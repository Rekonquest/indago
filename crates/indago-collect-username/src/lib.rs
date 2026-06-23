//! # Indago Username Collector
//!
//! Mechanism-only. On an approved [`Capability::UsernameEnum`] request it checks
//! a curated set of social sites for the presence of the username
//! (Sherlock-style HTTP presence checks) and freezes the result set as a JSON
//! artifact.
//!
//! The presence test here is deliberately simple (HTTP success vs. not). It is a
//! first-cut mechanism; per-site negative-signal heuristics (Sherlock's site
//! database) are a refinement, not a change in shape.

use std::time::Duration;

use indago_bus::Bus;
use indago_core::{Claim, Entity, EntityType, EvidenceType, Predicate};
use indago_protocol::{BusEnvelope, Capability, CaseId, IndagoMessage, RequestId};
use serde::Serialize;
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};

const COLLECTOR: &str = "indago-collect-username";

/// (display name, URL template with `{}` for the username).
const SITES: &[(&str, &str)] = &[
    ("GitHub", "https://github.com/{}"),
    ("GitLab", "https://gitlab.com/{}"),
    ("Reddit", "https://www.reddit.com/user/{}"),
    ("Instagram", "https://www.instagram.com/{}"),
    ("X", "https://x.com/{}"),
    ("Telegram", "https://t.me/{}"),
    ("Keybase", "https://keybase.io/{}"),
    ("Medium", "https://medium.com/@{}"),
];

#[derive(Debug, Serialize)]
struct SiteResult {
    site: String,
    url: String,
    exists: bool,
    status: u16,
}

/// Start the username collector subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionApproved {
                    request_id,
                    case_id,
                    capability: Capability::UsernameEnum,
                    target,
                    ..
                }) => {
                    let bus = bus.clone();
                    tokio::spawn(async move {
                        run(bus, request_id, case_id, target).await;
                    });
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "username collector fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

async fn run(bus: Bus, request_id: RequestId, case_id: CaseId, target: String) {
    let results = check(&target).await;
    let found = results.iter().filter(|r| r.exists).count();
    info!(username = %target, found, of = results.len(), "username enumeration complete");

    let raw = serde_json::to_vec_pretty(&results).unwrap_or_default();
    bus.send(IndagoMessage::CollectionResult {
        request_id,
        case_id,
        capability: Capability::UsernameEnum,
        target: target.clone(),
        title: format!("Username enumeration — {target}"),
        evidence_type: EvidenceType::JsonResponse,
        format: "JSON".into(),
        source_url: None,
        collector: COLLECTOR.into(),
        raw,
        envelope: BusEnvelope::fresh(),
    });

    // Propose the username entity and each found profile URL, so a
    // Person-of-Interest strategy can chain off them.
    let username = Entity::canonical(EntityType::Username, &target);
    bus.send(IndagoMessage::EntityCreated {
        entity: username.clone(),
        envelope: BusEnvelope::fresh(),
    });
    for result in results.iter().filter(|r| r.exists) {
        let profile = Entity::canonical(EntityType::Url, &result.url);
        bus.send(IndagoMessage::EntityCreated {
            entity: profile.clone(),
            envelope: BusEnvelope::fresh(),
        });
        // 200-vs-404 presence is noisy, so confidence is modest.
        let mut claim =
            Claim::assert(username.id, Predicate::Other("has_profile".into()), profile.id, COLLECTOR);
        claim.confidence = 60;
        bus.send(IndagoMessage::ClaimProposed {
            claim,
            envelope: BusEnvelope::fresh(),
        });
    }
}

async fn check(username: &str) -> Vec<SiteResult> {
    let client = match reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (compatible; indago/0.1)")
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::with_capacity(SITES.len());
    for (site, template) in SITES {
        let url = template.replace("{}", username);
        let (exists, status) = match client.get(&url).send().await {
            Ok(resp) => {
                let s = resp.status();
                (s.is_success(), s.as_u16())
            }
            Err(_) => (false, 0),
        };
        out.push(SiteResult {
            site: (*site).to_string(),
            url,
            exists,
            status,
        });
    }
    out
}
