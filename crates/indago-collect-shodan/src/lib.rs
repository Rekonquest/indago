//! # Indago Shodan Collector
//!
//! Mechanism-only, credential-gated. On an approved [`Capability::ShodanHost`]
//! request it asks the credential store for the `shodan` API key, queries the
//! Shodan host API for an IP, freezes the JSON, and proposes Service (open
//! port), Domain (hostname), and Company (org) entities with claims.
//!
//! Without a key it logs and skips. Set the key via `INDAGO_SHODAN_KEY` or a
//! [`IndagoMessage::SetCredential`] with name `shodan`.

use std::collections::HashMap;

use indago_bus::Bus;
use indago_core::{Claim, Entity, EntityType, EvidenceType, Predicate};
use indago_protocol::{BusEnvelope, Capability, CaseId, IndagoMessage, RequestId};
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};

const COLLECTOR: &str = "indago-collect-shodan";

#[derive(Debug, Default, Deserialize)]
struct ShodanHost {
    #[serde(default)]
    ports: Vec<u32>,
    #[serde(default)]
    hostnames: Vec<String>,
    org: Option<String>,
}

/// Start the Shodan collector subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        let mut pending: HashMap<RequestId, (CaseId, String)> = HashMap::new();
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionApproved {
                    request_id,
                    case_id,
                    capability: Capability::ShodanHost,
                    target,
                    ..
                }) => {
                    pending.insert(request_id, (case_id, target));
                    bus.send(IndagoMessage::GetCredential {
                        request_id,
                        case_id,
                        name: "shodan".into(),
                        envelope: BusEnvelope::fresh(),
                    });
                }
                Ok(IndagoMessage::CredentialResult { request_id, secret, .. }) => {
                    if let Some((case_id, ip)) = pending.remove(&request_id) {
                        match secret {
                            Some(key) => {
                                let bus = bus.clone();
                                tokio::spawn(async move {
                                    run(bus, request_id, case_id, ip, key).await;
                                });
                            }
                            None => warn!(
                                %ip,
                                "shodan: no API key (set INDAGO_SHODAN_KEY or SetCredential). Skipping."
                            ),
                        }
                    }
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "shodan collector fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

async fn run(bus: Bus, request_id: RequestId, case_id: CaseId, ip: String, key: String) {
    let raw = match fetch(&ip, &key).await {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(error = %e, %ip, "shodan query failed");
            return;
        }
    };
    let host = serde_json::from_slice::<ShodanHost>(&raw).unwrap_or_default();
    info!(%ip, ports = host.ports.len(), "shodan host captured");

    bus.send(IndagoMessage::CollectionResult {
        request_id,
        case_id,
        capability: Capability::ShodanHost,
        target: ip.clone(),
        title: format!("Shodan host — {ip}"),
        evidence_type: EvidenceType::JsonResponse,
        format: "JSON".into(),
        source_url: Some(format!("https://api.shodan.io/shodan/host/{ip}")),
        collector: COLLECTOR.into(),
        raw,
        envelope: BusEnvelope::fresh(),
    });

    let ip_entity = Entity::canonical(EntityType::IpAddress, &ip);
    emit(&bus, &ip_entity);
    for port in host.ports {
        let svc = Entity::canonical(EntityType::Service, &format!("{ip}:{port}"));
        emit(&bus, &svc);
        let mut claim = Claim::assert(ip_entity.id, Predicate::RunsService, svc.id, COLLECTOR);
        claim.confidence = 90;
        bus.send(IndagoMessage::ClaimProposed { claim, envelope: BusEnvelope::fresh() });
    }
    for hostname in host.hostnames {
        emit(&bus, &Entity::canonical(EntityType::Domain, &hostname));
    }
    if let Some(org) = host.org.filter(|s| !s.is_empty()) {
        emit(&bus, &Entity::canonical(EntityType::Company, &org));
    }
}

fn emit(bus: &Bus, entity: &Entity) {
    bus.send(IndagoMessage::EntityCreated {
        entity: entity.clone(),
        envelope: BusEnvelope::fresh(),
    });
}

async fn fetch(ip: &str, key: &str) -> reqwest::Result<Vec<u8>> {
    let url = format!("https://api.shodan.io/shodan/host/{ip}?key={key}");
    let client = reqwest::Client::builder().user_agent("indago/0.1").build()?;
    Ok(client.get(&url).send().await?.bytes().await?.to_vec())
}
