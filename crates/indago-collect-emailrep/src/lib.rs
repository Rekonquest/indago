//! # Indago Email-Reputation Collector
//!
//! Mechanism-only. On an approved [`Capability::EmailRep`] request it looks an
//! email up on emailrep.io (free, no key), freezes the JSON, and proposes the
//! linked platforms (where the email is registered) as entities with a
//! `registered_on` claim — a key step in a Person-of-Interest investigation.

use indago_bus::Bus;
use indago_core::{Claim, Entity, EntityType, EvidenceType, Predicate};
use indago_protocol::{BusEnvelope, Capability, CaseId, IndagoMessage, RequestId};
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};

const COLLECTOR: &str = "indago-collect-emailrep";

#[derive(Debug, Default, Deserialize)]
struct Resp {
    reputation: Option<String>,
    details: Option<Details>,
}

#[derive(Debug, Default, Deserialize)]
struct Details {
    #[serde(default)]
    profiles: Vec<String>,
}

/// Start the email-reputation collector subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionApproved {
                    request_id,
                    case_id,
                    capability: Capability::EmailRep,
                    target,
                    ..
                }) => {
                    let bus = bus.clone();
                    tokio::spawn(async move {
                        run(bus, request_id, case_id, target).await;
                    });
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "emailrep collector fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

async fn run(bus: Bus, request_id: RequestId, case_id: CaseId, target: String) {
    let raw = match fetch(&target).await {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(error = %e, %target, "emailrep query failed");
            return;
        }
    };
    let resp = serde_json::from_slice::<Resp>(&raw).unwrap_or_default();
    let profiles = resp.details.unwrap_or_default().profiles;
    info!(%target, reputation = ?resp.reputation, platforms = profiles.len(), "email reputation captured");

    bus.send(IndagoMessage::CollectionResult {
        request_id,
        case_id,
        capability: Capability::EmailRep,
        target: target.clone(),
        title: format!("Email reputation — {target}"),
        evidence_type: EvidenceType::JsonResponse,
        format: "JSON".into(),
        source_url: Some(format!("https://emailrep.io/{target}")),
        collector: COLLECTOR.into(),
        raw,
        envelope: BusEnvelope::fresh(),
    });

    let email = Entity::canonical(EntityType::Email, &target);
    bus.send(IndagoMessage::EntityCreated {
        entity: email.clone(),
        envelope: BusEnvelope::fresh(),
    });
    for platform in profiles {
        let platform_entity = Entity::canonical(EntityType::Other, format!("platform:{platform}"));
        bus.send(IndagoMessage::EntityCreated {
            entity: platform_entity.clone(),
            envelope: BusEnvelope::fresh(),
        });
        let mut claim = Claim::assert(
            email.id,
            Predicate::Other("registered_on".into()),
            platform_entity.id,
            COLLECTOR,
        );
        claim.confidence = 75;
        bus.send(IndagoMessage::ClaimProposed {
            claim,
            envelope: BusEnvelope::fresh(),
        });
    }
}

async fn fetch(email: &str) -> reqwest::Result<Vec<u8>> {
    let url = format!("https://emailrep.io/{email}");
    let client = reqwest::Client::builder()
        .user_agent("indago/0.1 (investigative-osint)")
        .build()?;
    Ok(client.get(&url).send().await?.bytes().await?.to_vec())
}
