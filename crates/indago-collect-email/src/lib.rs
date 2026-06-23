//! # Indago Email Collector
//!
//! Mechanism-only. On an approved [`Capability::EmailScrape`] request it fetches
//! the target URL, extracts candidate email addresses, validates them (RFC 5322
//! via `email_address`), freezes the result set as evidence, and proposes each
//! address as an Email entity linked to the page's host.
//!
//! (It fetches its own copy for now; once the store exposes a read interface it
//! will mine already-frozen evidence instead of re-fetching.)

use std::collections::BTreeSet;
use std::sync::OnceLock;

use email_address::EmailAddress;
use indago_bus::Bus;
use indago_core::{Claim, Entity, EntityType, EvidenceType, Predicate};
use indago_protocol::{BusEnvelope, Capability, CaseId, IndagoMessage, RequestId};
use regex::Regex;
use serde::Serialize;
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};

const COLLECTOR: &str = "indago-collect-email";

#[derive(Debug, Serialize)]
struct EmailFindings {
    source: String,
    emails: Vec<String>,
}

/// Start the email collector subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionApproved {
                    request_id,
                    case_id,
                    capability: Capability::EmailScrape,
                    target,
                    ..
                }) => {
                    let bus = bus.clone();
                    tokio::spawn(async move {
                        run(bus, request_id, case_id, target).await;
                    });
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "email collector fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

async fn run(bus: Bus, request_id: RequestId, case_id: CaseId, target: String) {
    let body = match fetch(&target).await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, %target, "email scrape fetch failed");
            return;
        }
    };
    let emails = extract_emails(&body);
    info!(%target, found = emails.len(), "email scrape complete");

    let findings = EmailFindings {
        source: target.clone(),
        emails: emails.clone(),
    };
    let raw = serde_json::to_vec_pretty(&findings).unwrap_or_default();
    bus.send(IndagoMessage::CollectionResult {
        request_id,
        case_id,
        capability: Capability::EmailScrape,
        target: target.clone(),
        title: format!("Emails — {target}"),
        evidence_type: EvidenceType::JsonResponse,
        format: "JSON".into(),
        source_url: Some(target.clone()),
        collector: COLLECTOR.into(),
        raw,
        envelope: BusEnvelope::fresh(),
    });

    // Propose the page host and each email, with an email -> host link.
    let host = reqwest::Url::parse(&target)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned));
    let host_entity = host.map(|h| {
        let e = Entity::canonical(EntityType::Domain, h);
        bus.send(IndagoMessage::EntityCreated {
            entity: e.clone(),
            envelope: BusEnvelope::fresh(),
        });
        e
    });
    for addr in emails {
        let email_entity = Entity::canonical(EntityType::Email, &addr);
        bus.send(IndagoMessage::EntityCreated {
            entity: email_entity.clone(),
            envelope: BusEnvelope::fresh(),
        });
        if let Some(ref host_entity) = host_entity {
            let claim =
                Claim::assert(email_entity.id, Predicate::LinkedTo, host_entity.id, COLLECTOR);
            bus.send(IndagoMessage::ClaimProposed {
                claim,
                envelope: BusEnvelope::fresh(),
            });
        }
    }
}

async fn fetch(url: &str) -> reqwest::Result<String> {
    let client = reqwest::Client::builder()
        .user_agent("indago/0.1")
        .build()?;
    client.get(url).send().await?.text().await
}

/// Extract unique, RFC-5322-valid email addresses from arbitrary text.
fn extract_emails(text: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
            .expect("static email regex is valid")
    });
    let mut set: BTreeSet<String> = BTreeSet::new();
    for m in re.find_iter(text) {
        let candidate = m.as_str().trim_end_matches('.').to_ascii_lowercase();
        if EmailAddress::is_valid(&candidate) {
            set.insert(candidate);
        }
    }
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_and_validates_emails() {
        let text = "contact jane.doe@example.com or sales@example.co.uk — not bad@@x";
        let found = extract_emails(text);
        assert!(found.contains(&"jane.doe@example.com".to_string()));
        assert!(found.contains(&"sales@example.co.uk".to_string()));
        assert_eq!(found.len(), 2);
    }
}
