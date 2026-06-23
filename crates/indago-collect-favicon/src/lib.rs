//! # Indago Favicon Collector
//!
//! Mechanism-only. On an approved [`Capability::FaviconHash`] request it fetches
//! the site's favicon, computes the **Shodan-style mmh3 hash** (mmh3 of the
//! base64-encoded favicon), freezes the favicon, and proposes a content-
//! addressed `favicon-hash:<h>` entity with a `favicon_hash` claim. Two hosts
//! sharing a favicon resolve to the *same* hash entity — instant pivot in the
//! graph (the classic "find related infrastructure by favicon" move).

use std::io::Cursor;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use indago_bus::Bus;
use indago_core::{Claim, Entity, EntityType, EvidenceType, Predicate};
use indago_protocol::{BusEnvelope, Capability, CaseId, IndagoMessage, RequestId};
use murmur3::murmur3_32;
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};

const COLLECTOR: &str = "indago-collect-favicon";

/// Start the favicon collector subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionApproved {
                    request_id,
                    case_id,
                    capability: Capability::FaviconHash,
                    target,
                    ..
                }) => {
                    let bus = bus.clone();
                    tokio::spawn(async move {
                        run(bus, request_id, case_id, target).await;
                    });
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "favicon collector fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

async fn run(bus: Bus, request_id: RequestId, case_id: CaseId, target: String) {
    let url = favicon_url(&target);
    let bytes = match fetch(&url).await {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => {
            warn!(%target, "favicon was empty");
            return;
        }
        Err(e) => {
            warn!(error = %e, %target, "favicon fetch failed");
            return;
        }
    };
    let hash = shodan_favicon_hash(&bytes);
    info!(%target, hash, "favicon hashed");

    bus.send(IndagoMessage::CollectionResult {
        request_id,
        case_id,
        capability: Capability::FaviconHash,
        target: target.clone(),
        title: format!("Favicon — {target} (mmh3 {hash})"),
        evidence_type: EvidenceType::Other,
        format: "ICO".into(),
        source_url: Some(url),
        collector: COLLECTOR.into(),
        raw: bytes,
        envelope: BusEnvelope::fresh(),
    });

    let domain = Entity::canonical(EntityType::Domain, host_of(&target));
    bus.send(IndagoMessage::EntityCreated {
        entity: domain.clone(),
        envelope: BusEnvelope::fresh(),
    });
    // Content-addressed hash entity: same favicon → same id → graph pivot.
    let hash_entity = Entity::canonical(EntityType::Other, format!("favicon-hash:{hash}"));
    bus.send(IndagoMessage::EntityCreated {
        entity: hash_entity.clone(),
        envelope: BusEnvelope::fresh(),
    });
    let mut claim = Claim::assert(
        domain.id,
        Predicate::Other("favicon_hash".into()),
        hash_entity.id,
        COLLECTOR,
    );
    claim.confidence = 100;
    bus.send(IndagoMessage::ClaimProposed {
        claim,
        envelope: BusEnvelope::fresh(),
    });
}

/// Shodan's favicon hash: mmh3_32 (seed 0, signed) of the base64-encoded favicon
/// laid out like Python's `base64.encodebytes` (76-char lines, trailing `\n`).
fn shodan_favicon_hash(bytes: &[u8]) -> i32 {
    let b64 = STANDARD.encode(bytes);
    let mut buf = String::with_capacity(b64.len() + b64.len() / 76 + 1);
    for chunk in b64.as_bytes().chunks(76) {
        buf.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        buf.push('\n');
    }
    murmur3_32(&mut Cursor::new(buf.as_bytes()), 0).unwrap_or(0) as i32
}

fn favicon_url(target: &str) -> String {
    if let Ok(u) = reqwest::Url::parse(target) {
        if let Some(host) = u.host_str() {
            return format!("{}://{}/favicon.ico", u.scheme(), host);
        }
    }
    format!("http://{target}/favicon.ico")
}

fn host_of(target: &str) -> String {
    reqwest::Url::parse(target)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_else(|| target.to_string())
}

async fn fetch(url: &str) -> reqwest::Result<Vec<u8>> {
    let client = reqwest::Client::builder().user_agent("indago/0.1").build()?;
    Ok(client.get(url).send().await?.error_for_status()?.bytes().await?.to_vec())
}
