//! # Indago Subdomain Collector
//!
//! Mechanism-only. On an approved [`Capability::SubdomainEnum`] request it
//! brute-forces a built-in wordlist of common labels against the domain,
//! concurrently, keeping those that resolve. Resolved hosts are frozen as a JSON
//! artifact and proposed as Domain entities plus `subdomain_of` claims.
//!
//! This is the *active* counterpart to the passive certificate-transparency
//! collector; in practice both feed the same subdomain picture.

use indago_bus::Bus;
use indago_core::{Claim, Entity, EntityType, EvidenceType, Predicate};
use indago_protocol::{BusEnvelope, Capability, CaseId, IndagoMessage, RequestId};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use serde::Serialize;
use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinSet;
use tracing::{info, warn};

const COLLECTOR: &str = "indago-collect-subdomain";

/// Common subdomain labels to probe. Deliberately small; a real wordlist can be
/// loaded later without changing the collector's shape.
const WORDLIST: &[&str] = &[
    "www", "mail", "smtp", "imap", "pop", "webmail", "ns1", "ns2", "dns", "ftp",
    "api", "dev", "staging", "test", "admin", "portal", "vpn", "remote", "gateway",
    "app", "apps", "cdn", "static", "assets", "img", "images", "blog", "shop",
    "store", "secure", "login", "auth", "git", "gitlab", "jenkins", "ci",
    "docs", "support", "help", "status", "m", "mobile", "beta", "demo",
];

#[derive(Debug, Serialize)]
struct SubdomainHit {
    host: String,
    addresses: Vec<String>,
}

/// Start the subdomain collector subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionApproved {
                    request_id,
                    case_id,
                    capability: Capability::SubdomainEnum,
                    target,
                    ..
                }) => {
                    let bus = bus.clone();
                    tokio::spawn(async move {
                        run(bus, request_id, case_id, target).await;
                    });
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "subdomain collector fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

async fn run(bus: Bus, request_id: RequestId, case_id: CaseId, target: String) {
    let hits = brute(&target).await;
    info!(%target, found = hits.len(), "subdomain brute complete");

    let raw = serde_json::to_vec_pretty(&hits).unwrap_or_default();
    bus.send(IndagoMessage::CollectionResult {
        request_id,
        case_id,
        capability: Capability::SubdomainEnum,
        target: target.clone(),
        title: format!("Subdomain brute-force — {target}"),
        evidence_type: EvidenceType::JsonResponse,
        format: "JSON".into(),
        source_url: Some(format!("subdomain-brute://{target}")),
        collector: COLLECTOR.into(),
        raw,
        envelope: BusEnvelope::fresh(),
    });

    let domain = Entity::canonical(EntityType::Domain, &target);
    bus.send(IndagoMessage::EntityCreated {
        entity: domain.clone(),
        envelope: BusEnvelope::fresh(),
    });
    for hit in hits {
        let sub = Entity::canonical(EntityType::Domain, &hit.host);
        bus.send(IndagoMessage::EntityCreated {
            entity: sub.clone(),
            envelope: BusEnvelope::fresh(),
        });
        let mut claim = Claim::assert(
            sub.id,
            Predicate::Other("subdomain_of".into()),
            domain.id,
            COLLECTOR,
        );
        claim.confidence = 95; // it resolved, so it's a strong assertion
        bus.send(IndagoMessage::ClaimProposed {
            claim,
            envelope: BusEnvelope::fresh(),
        });
    }
}

/// Resolve every `{word}.{domain}` candidate concurrently; keep the ones that
/// return at least one address.
async fn brute(domain: &str) -> Vec<SubdomainHit> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let mut set: JoinSet<Option<SubdomainHit>> = JoinSet::new();
    for word in WORDLIST {
        let host = format!("{word}.{domain}");
        let resolver = resolver.clone();
        set.spawn(async move {
            match resolver.lookup_ip(host.clone()).await {
                Ok(ips) => {
                    let addresses: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                    if addresses.is_empty() {
                        None
                    } else {
                        Some(SubdomainHit { host, addresses })
                    }
                }
                Err(_) => None,
            }
        });
    }

    let mut hits = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(hit)) = joined {
            hits.push(hit);
        }
    }
    hits.sort_by(|a, b| a.host.cmp(&b.host));
    hits
}
