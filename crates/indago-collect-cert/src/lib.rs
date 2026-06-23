//! # Indago Certificate-Transparency Collector
//!
//! Mechanism-only. On an approved [`Capability::CertTransparency`] request it
//! queries crt.sh for certificates mentioning the domain, freezes the JSON
//! response as evidence, and proposes each discovered subdomain as a Domain
//! entity plus a `subdomain_of` claim. It only *proposes* — the gate disposes.

use std::collections::BTreeSet;

use indago_bus::Bus;
use indago_core::{Claim, Entity, EntityType, EvidenceType, Predicate};
use indago_protocol::{BusEnvelope, Capability, CaseId, IndagoMessage, RequestId};
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};

const COLLECTOR: &str = "indago-collect-cert";
/// Cap on proposed subdomains per query, so a noisy domain can't flood the bus.
const MAX_SUBDOMAINS: usize = 500;

/// Start the certificate-transparency collector subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionApproved {
                    request_id,
                    case_id,
                    capability: Capability::CertTransparency,
                    target,
                    ..
                }) => {
                    let bus = bus.clone();
                    tokio::spawn(async move {
                        run(bus, request_id, case_id, target).await;
                    });
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "cert collector fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

async fn run(bus: Bus, request_id: RequestId, case_id: CaseId, target: String) {
    let raw = match fetch(&target).await {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(error = %e, %target, "crt.sh query failed");
            return;
        }
    };

    let subdomains = parse_subdomains(&raw, &target);
    info!(%target, found = subdomains.len(), "cert transparency captured");

    bus.send(IndagoMessage::CollectionResult {
        request_id,
        case_id,
        capability: Capability::CertTransparency,
        target: target.clone(),
        title: format!("Certificate transparency — {target}"),
        evidence_type: EvidenceType::JsonResponse,
        format: "JSON".into(),
        source_url: Some(format!("https://crt.sh/?q={target}&output=json")),
        collector: COLLECTOR.into(),
        raw,
        envelope: BusEnvelope::fresh(),
    });

    let domain = Entity::canonical(EntityType::Domain, &target);
    bus.send(IndagoMessage::EntityCreated {
        entity: domain.clone(),
        envelope: BusEnvelope::fresh(),
    });
    for sub in subdomains {
        let sub_entity = Entity::canonical(EntityType::Domain, &sub);
        bus.send(IndagoMessage::EntityCreated {
            entity: sub_entity.clone(),
            envelope: BusEnvelope::fresh(),
        });
        let mut claim = Claim::assert(
            sub_entity.id,
            Predicate::Other("subdomain_of".into()),
            domain.id,
            COLLECTOR,
        );
        claim.confidence = 80;
        bus.send(IndagoMessage::ClaimProposed {
            claim,
            envelope: BusEnvelope::fresh(),
        });
    }
}

async fn fetch(domain: &str) -> reqwest::Result<Vec<u8>> {
    let url = format!("https://crt.sh/?q={domain}&output=json");
    let client = reqwest::Client::builder()
        .user_agent("indago/0.1")
        .build()?;
    Ok(client.get(&url).send().await?.bytes().await?.to_vec())
}

/// Extract unique subdomains of `domain` from crt.sh JSON. Each record's
/// `name_value` may hold several newline-separated names and wildcards.
fn parse_subdomains(raw: &[u8], domain: &str) -> Vec<String> {
    let suffix = format!(".{}", domain.to_ascii_lowercase());
    let mut set: BTreeSet<String> = BTreeSet::new();
    if let Ok(entries) = serde_json::from_slice::<Vec<serde_json::Value>>(raw) {
        for entry in entries {
            let Some(name_value) = entry.get("name_value").and_then(|v| v.as_str()) else {
                continue;
            };
            for name in name_value.split('\n') {
                let n = name.trim().trim_start_matches("*.").to_ascii_lowercase();
                if n.ends_with(&suffix) && n != domain.to_ascii_lowercase() {
                    set.insert(n);
                }
                if set.len() >= MAX_SUBDOMAINS {
                    return set.into_iter().collect();
                }
            }
        }
    }
    set.into_iter().collect()
}
