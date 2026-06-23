//! # Indago urlscan.io Collector
//!
//! Mechanism-only. On an approved [`Capability::UrlScan`] request it searches
//! urlscan.io for a domain (free search endpoint, no key), freezes the JSON, and
//! proposes the scanned URLs, the IPs they resolved to, and their ASNs — with
//! `hosts` (ip→domain) and `in asn` (ip→asn) claims.

use std::collections::HashSet;

use indago_bus::Bus;
use indago_core::{Claim, Entity, EntityType, EvidenceType, Predicate};
use indago_protocol::{BusEnvelope, Capability, CaseId, IndagoMessage, RequestId};
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};

const COLLECTOR: &str = "indago-collect-urlscan";
const MAX_RESULTS: usize = 100;

#[derive(Debug, Deserialize)]
struct SearchResp {
    #[serde(default)]
    results: Vec<ScanResult>,
}

#[derive(Debug, Deserialize)]
struct ScanResult {
    page: Option<Page>,
}

#[derive(Debug, Deserialize)]
struct Page {
    url: Option<String>,
    domain: Option<String>,
    ip: Option<String>,
    asn: Option<String>,
}

/// Start the urlscan collector subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionApproved {
                    request_id,
                    case_id,
                    capability: Capability::UrlScan,
                    target,
                    ..
                }) => {
                    let bus = bus.clone();
                    tokio::spawn(async move {
                        run(bus, request_id, case_id, target).await;
                    });
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "urlscan collector fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

async fn run(bus: Bus, request_id: RequestId, case_id: CaseId, target: String) {
    let raw = match fetch(&target).await {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(error = %e, %target, "urlscan query failed");
            return;
        }
    };
    let resp = serde_json::from_slice::<SearchResp>(&raw).unwrap_or(SearchResp { results: vec![] });
    info!(%target, results = resp.results.len(), "urlscan captured");

    bus.send(IndagoMessage::CollectionResult {
        request_id,
        case_id,
        capability: Capability::UrlScan,
        target: target.clone(),
        title: format!("urlscan.io — {target}"),
        evidence_type: EvidenceType::JsonResponse,
        format: "JSON".into(),
        source_url: Some(format!("https://urlscan.io/api/v1/search/?q=domain:{target}")),
        collector: COLLECTOR.into(),
        raw,
        envelope: BusEnvelope::fresh(),
    });

    // Dedup what we emit so a noisy domain doesn't flood the bus.
    let mut seen: HashSet<String> = HashSet::new();
    let mut emit_entity = |entity: &Entity| {
        if seen.insert(format!("{:?}:{}", entity.entity_type, entity.name)) {
            bus.send(IndagoMessage::EntityCreated {
                entity: entity.clone(),
                envelope: BusEnvelope::fresh(),
            });
        }
    };

    for result in resp.results.into_iter().take(MAX_RESULTS) {
        let Some(page) = result.page else { continue };

        if let Some(url) = page.url.filter(|s| !s.is_empty()) {
            emit_entity(&Entity::canonical(EntityType::Url, &url));
        }
        let ip = page.ip.filter(|s| !s.is_empty()).map(|ip| {
            let e = Entity::canonical(EntityType::IpAddress, &ip);
            emit_entity(&e);
            e
        });
        if let Some(domain) = page.domain.filter(|s| !s.is_empty()) {
            let d = Entity::canonical(EntityType::Domain, &domain);
            emit_entity(&d);
            if let Some(ip) = &ip {
                emit_claim(&bus, Claim::assert(ip.id, Predicate::Hosts, d.id, COLLECTOR));
            }
        }
        if let Some(asn) = page.asn.filter(|s| !s.is_empty()) {
            let a = Entity::canonical(EntityType::Asn, &asn);
            emit_entity(&a);
            if let Some(ip) = &ip {
                emit_claim(&bus, Claim::assert(ip.id, Predicate::InAsn, a.id, COLLECTOR));
            }
        }
    }
}

fn emit_claim(bus: &Bus, mut claim: Claim) {
    claim.confidence = 70;
    bus.send(IndagoMessage::ClaimProposed {
        claim,
        envelope: BusEnvelope::fresh(),
    });
}

async fn fetch(domain: &str) -> reqwest::Result<Vec<u8>> {
    let url = format!("https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100");
    let client = reqwest::Client::builder().user_agent("indago/0.1").build()?;
    Ok(client.get(&url).send().await?.bytes().await?.to_vec())
}
