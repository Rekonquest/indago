//! # Indago Breach Collector
//!
//! Mechanism-only, with a credential dependency. On an approved
//! [`Capability::BreachCheck`] request it asks the credential store for the
//! `hibp` API key ([`IndagoMessage::GetCredential`]), then queries
//! HaveIBeenPwned for the email and freezes the response as evidence.
//!
//! Without a key it does nothing (logs and skips) — the gate/credential layer
//! owns the policy of whether a key exists; this collector is pure mechanism.
//! Set the key via `INDAGO_HIBP_KEY` (seeded into the vault) or a
//! [`IndagoMessage::SetCredential`].

use std::collections::HashMap;

use indago_bus::Bus;
use indago_core::{Entity, EntityType, EvidenceType};
use indago_protocol::{BusEnvelope, Capability, CaseId, IndagoMessage, RequestId};
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};

const COLLECTOR: &str = "indago-collect-breach";

/// Start the breach collector subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        // Requests awaiting their credential, keyed by request id.
        let mut pending: HashMap<RequestId, (CaseId, String)> = HashMap::new();

        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionApproved {
                    request_id,
                    case_id,
                    capability: Capability::BreachCheck,
                    target,
                    ..
                }) => {
                    // Ask the vault for the HIBP key; act on the reply.
                    pending.insert(request_id, (case_id, target));
                    bus.send(IndagoMessage::GetCredential {
                        request_id,
                        case_id,
                        name: "hibp".into(),
                        envelope: BusEnvelope::fresh(),
                    });
                }
                Ok(IndagoMessage::CredentialResult {
                    request_id,
                    secret,
                    ..
                }) => {
                    if let Some((case_id, email)) = pending.remove(&request_id) {
                        match secret {
                            Some(key) => {
                                let bus = bus.clone();
                                tokio::spawn(async move {
                                    run(bus, request_id, case_id, email, key).await;
                                });
                            }
                            None => warn!(
                                %email,
                                "breach: no HIBP credential available; set INDAGO_HIBP_KEY \
                                 or SetCredential. Skipping."
                            ),
                        }
                    }
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "breach collector fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

async fn run(bus: Bus, request_id: RequestId, case_id: CaseId, email: String, key: String) {
    let raw = match query_hibp(&email, &key).await {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(error = %e, %email, "breach: HIBP query failed");
            return;
        }
    };
    info!(%email, bytes = raw.len(), "breach: HIBP response captured");

    bus.send(IndagoMessage::CollectionResult {
        request_id,
        case_id,
        capability: Capability::BreachCheck,
        target: email.clone(),
        title: format!("Breach check — {email}"),
        evidence_type: EvidenceType::JsonResponse,
        format: "JSON".into(),
        source_url: Some(format!("https://haveibeenpwned.com/api/v3/breachedaccount/{email}")),
        collector: COLLECTOR.into(),
        raw,
        envelope: BusEnvelope::fresh(),
    });

    bus.send(IndagoMessage::EntityCreated {
        entity: Entity::canonical(EntityType::Email, &email),
        envelope: BusEnvelope::fresh(),
    });
}

/// Query HIBP. A 404 (no breaches) is captured as an empty result rather than an
/// error, so "clean" is itself frozen evidence.
async fn query_hibp(email: &str, key: &str) -> reqwest::Result<Vec<u8>> {
    let url = format!(
        "https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    );
    let client = reqwest::Client::builder()
        .user_agent("indago/0.1")
        .build()?;
    let resp = client
        .get(&url)
        .header("hibp-api-key", key)
        .send()
        .await?;

    if resp.status().as_u16() == 404 {
        return Ok(br#"{"breaches":[]}"#.to_vec());
    }
    let resp = resp.error_for_status()?;
    Ok(resp.bytes().await?.to_vec())
}
