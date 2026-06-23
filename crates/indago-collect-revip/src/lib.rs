//! # Indago Reverse-IP Collector
//!
//! Mechanism-only. On an approved [`Capability::ReverseIp`] request it asks
//! HackerTarget which domains are co-hosted on an IP, freezes the result, and
//! proposes each co-hosted domain with a `hosts` claim from the IP. This is the
//! classic "shared hosting" pivot — find every site behind one address.

use indago_bus::Bus;
use indago_core::{Claim, Entity, EntityType, EvidenceType, Predicate};
use indago_protocol::{BusEnvelope, Capability, CaseId, IndagoMessage, RequestId};
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};

const COLLECTOR: &str = "indago-collect-revip";
const MAX_DOMAINS: usize = 200;

/// Start the reverse-IP collector subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionApproved {
                    request_id,
                    case_id,
                    capability: Capability::ReverseIp,
                    target,
                    ..
                }) => {
                    let bus = bus.clone();
                    tokio::spawn(async move {
                        run(bus, request_id, case_id, target).await;
                    });
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "revip collector fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

async fn run(bus: Bus, request_id: RequestId, case_id: CaseId, target: String) {
    let raw = match fetch(&target).await {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(error = %e, %target, "reverse-IP query failed");
            return;
        }
    };
    let domains = parse_domains(&raw);
    info!(%target, found = domains.len(), "reverse-IP captured");

    bus.send(IndagoMessage::CollectionResult {
        request_id,
        case_id,
        capability: Capability::ReverseIp,
        target: target.clone(),
        title: format!("Reverse IP — {target}"),
        evidence_type: EvidenceType::Document,
        format: "TXT".into(),
        source_url: Some(format!("https://api.hackertarget.com/reverseiplookup/?q={target}")),
        collector: COLLECTOR.into(),
        raw,
        envelope: BusEnvelope::fresh(),
    });

    let ip = Entity::canonical(EntityType::IpAddress, &target);
    bus.send(IndagoMessage::EntityCreated {
        entity: ip.clone(),
        envelope: BusEnvelope::fresh(),
    });
    for domain in domains {
        let domain_entity = Entity::canonical(EntityType::Domain, &domain);
        bus.send(IndagoMessage::EntityCreated {
            entity: domain_entity.clone(),
            envelope: BusEnvelope::fresh(),
        });
        let mut claim = Claim::assert(ip.id, Predicate::Hosts, domain_entity.id, COLLECTOR);
        claim.confidence = 75;
        bus.send(IndagoMessage::ClaimProposed {
            claim,
            envelope: BusEnvelope::fresh(),
        });
    }
}

async fn fetch(ip: &str) -> reqwest::Result<Vec<u8>> {
    let url = format!("https://api.hackertarget.com/reverseiplookup/?q={ip}");
    let client = reqwest::Client::builder().user_agent("indago/0.1").build()?;
    Ok(client.get(&url).send().await?.bytes().await?.to_vec())
}

/// HackerTarget returns one host per line as plain text. Error responses ("API
/// count exceeded", "no records found") contain spaces / no dots and are
/// filtered out.
fn parse_domains(raw: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    for line in text.lines() {
        let host = line.trim().to_ascii_lowercase();
        if !host.is_empty() && host.contains('.') && !host.contains(' ') {
            out.push(host);
            if out.len() >= MAX_DOMAINS {
                break;
            }
        }
    }
    out.sort();
    out.dedup();
    out
}
