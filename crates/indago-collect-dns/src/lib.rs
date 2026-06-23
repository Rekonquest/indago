//! # Indago DNS Collector
//!
//! A mechanism-only collection primitive. It subscribes to
//! [`IndagoMessage::CollectionApproved`] requests for [`Capability::Dns`],
//! resolves A/MX/NS/TXT/CNAME records, and:
//!
//! 1. freezes the records (as a JSON artifact) by emitting
//!    [`IndagoMessage::CollectionResult`] — the store hashes and persists it;
//! 2. proposes candidate entities ([`IndagoMessage::EntityCreated`]) and claims
//!    ([`IndagoMessage::ClaimProposed`]) extracted from the records.
//!
//! It makes **no policy decisions** — it acts only on already-approved requests
//! and only ever *proposes* claims; the gate and claim engine dispose.

use indago_bus::Bus;
use indago_core::{Claim, Entity, EntityType, EvidenceType, Predicate};
use indago_protocol::{BusEnvelope, Capability, CaseId, IndagoMessage, RequestId};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;
use serde::Serialize;
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};

const COLLECTOR: &str = "indago-collect-dns";

/// The frozen artifact: the resolved records for one domain.
#[derive(Debug, Serialize)]
struct DnsRecords {
    domain: String,
    a: Vec<String>,
    mx: Vec<String>,
    ns: Vec<String>,
    txt: Vec<String>,
    cname: Vec<String>,
}

/// Start the DNS collector subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionApproved {
                    request_id,
                    case_id,
                    capability: Capability::Dns,
                    target,
                    ..
                }) => {
                    // Spawn per request so one slow resolution doesn't stall the
                    // subscription loop.
                    let bus = bus.clone();
                    tokio::spawn(async move {
                        run(bus, request_id, case_id, target).await;
                    });
                }
                Ok(_) => { /* not ours */ }
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "dns collector fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

async fn run(bus: Bus, request_id: RequestId, case_id: CaseId, target: String) {
    let records = resolve(&target).await;

    // 1. Freeze the raw capture as evidence.
    let raw = serde_json::to_vec_pretty(&records).unwrap_or_default();
    info!(%target, a = records.a.len(), mx = records.mx.len(), "dns resolved");
    bus.send(IndagoMessage::CollectionResult {
        request_id,
        case_id,
        capability: Capability::Dns,
        target: target.clone(),
        title: format!("DNS records — {target}"),
        evidence_type: EvidenceType::JsonResponse,
        format: "JSON".into(),
        source_url: Some(format!("dns://{target}")),
        collector: COLLECTOR.into(),
        raw,
        envelope: BusEnvelope::fresh(),
    });

    // 2. Propose entities + claims from the A records: each resolved IP
    //    "hosts" the domain. Entities are minted fresh here; dedup/merge is the
    //    claim engine's job (Phase 3).
    let domain = Entity::canonical(EntityType::Domain, &target);
    bus.send(IndagoMessage::EntityCreated {
        entity: domain.clone(),
        envelope: BusEnvelope::fresh(),
    });
    for ip in &records.a {
        let ip_entity = Entity::canonical(EntityType::IpAddress, ip);
        bus.send(IndagoMessage::EntityCreated {
            entity: ip_entity.clone(),
            envelope: BusEnvelope::fresh(),
        });
        let mut claim = Claim::assert(ip_entity.id, Predicate::Hosts, domain.id, COLLECTOR);
        claim.confidence = 90;
        bus.send(IndagoMessage::ClaimProposed {
            claim,
            envelope: BusEnvelope::fresh(),
        });
    }
}

/// Resolve the standard record set for `target`. Missing record types resolve
/// to empty vectors rather than failing the whole capture, so resolution is
/// infallible from the caller's perspective.
async fn resolve(target: &str) -> DnsRecords {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    DnsRecords {
        domain: target.to_string(),
        a: lookup(&resolver, target, RecordType::A).await,
        mx: lookup(&resolver, target, RecordType::MX).await,
        ns: lookup(&resolver, target, RecordType::NS).await,
        txt: lookup(&resolver, target, RecordType::TXT).await,
        cname: lookup(&resolver, target, RecordType::CNAME).await,
    }
}

/// Look up one record type and render each record to its display string. A
/// resolution error (NXDOMAIN, no records, timeout) yields an empty vector.
async fn lookup(resolver: &TokioAsyncResolver, target: &str, rt: RecordType) -> Vec<String> {
    match resolver.lookup(target, rt).await {
        Ok(l) => l.iter().map(|rdata| rdata.to_string()).collect(),
        Err(_) => Vec::new(),
    }
}
