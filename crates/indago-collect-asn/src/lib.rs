//! # Indago ASN Collector
//!
//! Mechanism-only. On an approved [`Capability::AsnPrefixes`] request it expands
//! an Autonomous System to its announced prefixes via RIPEstat, freezes the
//! JSON, and proposes each prefix as a Netblock entity with an `in asn` claim.
//! Completes the IP → ASN → netblocks pivot.

use indago_bus::Bus;
use indago_core::{Claim, Entity, EntityType, EvidenceType, Predicate};
use indago_protocol::{BusEnvelope, Capability, CaseId, IndagoMessage, RequestId};
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};

const COLLECTOR: &str = "indago-collect-asn";
const MAX_PREFIXES: usize = 150;

#[derive(Debug, Deserialize)]
struct Resp {
    data: Option<Data>,
}

#[derive(Debug, Default, Deserialize)]
struct Data {
    #[serde(default)]
    prefixes: Vec<Prefix>,
}

#[derive(Debug, Deserialize)]
struct Prefix {
    prefix: Option<String>,
}

/// Start the ASN collector subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionApproved {
                    request_id,
                    case_id,
                    capability: Capability::AsnPrefixes,
                    target,
                    ..
                }) => {
                    let bus = bus.clone();
                    tokio::spawn(async move {
                        run(bus, request_id, case_id, target).await;
                    });
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "asn collector fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

async fn run(bus: Bus, request_id: RequestId, case_id: CaseId, target: String) {
    // Accept "AS13335", "as13335", "13335", or "AS13335 Cloudflare, Inc.".
    let number: String = target.chars().take_while(|c| !c.is_whitespace()).filter(|c| c.is_ascii_digit()).collect();
    if number.is_empty() {
        warn!(%target, "asn: no AS number in target");
        return;
    }

    let raw = match fetch(&number).await {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(error = %e, %target, "bgpview query failed");
            return;
        }
    };
    let data = serde_json::from_slice::<Resp>(&raw)
        .ok()
        .and_then(|r| r.data)
        .unwrap_or_default();
    let prefixes: Vec<String> = data
        .prefixes
        .into_iter()
        .filter_map(|p| p.prefix)
        .filter(|p| !p.is_empty())
        .take(MAX_PREFIXES)
        .collect();
    info!(as_number = %number, prefixes = prefixes.len(), "asn prefixes captured");

    bus.send(IndagoMessage::CollectionResult {
        request_id,
        case_id,
        capability: Capability::AsnPrefixes,
        target: target.clone(),
        title: format!("ASN prefixes — AS{number}"),
        evidence_type: EvidenceType::JsonResponse,
        format: "JSON".into(),
        source_url: Some(format!(
            "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{number}"
        )),
        collector: COLLECTOR.into(),
        raw,
        envelope: BusEnvelope::fresh(),
    });

    let asn = Entity::canonical(EntityType::Asn, format!("AS{number}"));
    bus.send(IndagoMessage::EntityCreated {
        entity: asn.clone(),
        envelope: BusEnvelope::fresh(),
    });
    for prefix in prefixes {
        let netblock = Entity::canonical(EntityType::Netblock, &prefix);
        bus.send(IndagoMessage::EntityCreated {
            entity: netblock.clone(),
            envelope: BusEnvelope::fresh(),
        });
        let mut claim = Claim::assert(netblock.id, Predicate::InAsn, asn.id, COLLECTOR);
        claim.confidence = 95;
        bus.send(IndagoMessage::ClaimProposed {
            claim,
            envelope: BusEnvelope::fresh(),
        });
    }
}

async fn fetch(as_number: &str) -> reqwest::Result<Vec<u8>> {
    let url = format!(
        "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{as_number}"
    );
    let client = reqwest::Client::builder().user_agent("indago/0.1").build()?;
    Ok(client.get(&url).send().await?.bytes().await?.to_vec())
}
