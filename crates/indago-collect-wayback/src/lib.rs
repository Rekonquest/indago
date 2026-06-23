//! # Indago Wayback Collector
//!
//! Mechanism-only. On an approved [`Capability::Wayback`] request it queries the
//! Internet Archive CDX API for historical snapshots of a domain, freezes the
//! result, and proposes each archived URL as an entity with an `archived from`
//! claim back to the domain. Historical footprint — a classic OSINT pivot.

use std::collections::BTreeSet;

use indago_bus::Bus;
use indago_core::{Claim, Entity, EntityType, EvidenceType, Predicate};
use indago_protocol::{BusEnvelope, Capability, CaseId, IndagoMessage, RequestId};
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};

const COLLECTOR: &str = "indago-collect-wayback";
const MAX_URLS: usize = 200;

/// Start the Wayback collector subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionApproved {
                    request_id,
                    case_id,
                    capability: Capability::Wayback,
                    target,
                    ..
                }) => {
                    let bus = bus.clone();
                    tokio::spawn(async move {
                        run(bus, request_id, case_id, target).await;
                    });
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "wayback collector fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

async fn run(bus: Bus, request_id: RequestId, case_id: CaseId, target: String) {
    let raw = match fetch(&target).await {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(error = %e, %target, "wayback query failed");
            return;
        }
    };
    let urls = parse_urls(&raw);
    info!(%target, found = urls.len(), "wayback snapshots captured");

    bus.send(IndagoMessage::CollectionResult {
        request_id,
        case_id,
        capability: Capability::Wayback,
        target: target.clone(),
        title: format!("Wayback snapshots — {target}"),
        evidence_type: EvidenceType::JsonResponse,
        format: "JSON".into(),
        source_url: Some(format!("https://web.archive.org/cdx/search/cdx?url={target}*")),
        collector: COLLECTOR.into(),
        raw,
        envelope: BusEnvelope::fresh(),
    });

    let domain = Entity::canonical(EntityType::Domain, &target);
    bus.send(IndagoMessage::EntityCreated {
        entity: domain.clone(),
        envelope: BusEnvelope::fresh(),
    });
    for url in urls {
        let url_entity = Entity::canonical(EntityType::Url, &url);
        bus.send(IndagoMessage::EntityCreated {
            entity: url_entity.clone(),
            envelope: BusEnvelope::fresh(),
        });
        let mut claim = Claim::assert(url_entity.id, Predicate::ArchivedFrom, domain.id, COLLECTOR);
        claim.confidence = 90;
        bus.send(IndagoMessage::ClaimProposed {
            claim,
            envelope: BusEnvelope::fresh(),
        });
    }
}

async fn fetch(domain: &str) -> reqwest::Result<Vec<u8>> {
    let url = format!(
        "https://web.archive.org/cdx/search/cdx?url={domain}*&output=json&fl=original&collapse=urlkey&limit=300"
    );
    let client = reqwest::Client::builder().user_agent("indago/0.1").build()?;
    Ok(client.get(&url).send().await?.bytes().await?.to_vec())
}

/// CDX JSON is an array of rows; the first row is the header `["original"]`.
fn parse_urls(raw: &[u8]) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    if let Ok(rows) = serde_json::from_slice::<Vec<Vec<String>>>(raw) {
        for row in rows.into_iter().skip(1) {
            if let Some(original) = row.into_iter().next() {
                set.insert(original);
                if set.len() >= MAX_URLS {
                    break;
                }
            }
        }
    }
    set.into_iter().collect()
}
