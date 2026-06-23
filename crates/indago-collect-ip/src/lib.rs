//! # Indago IP-Intelligence Collector
//!
//! Mechanism-only. On an approved [`Capability::IpIntel`] request it enriches an
//! IP address via ip-api.com — geolocation, ASN, ISP, and reverse DNS — freezes
//! the JSON, and proposes Location / ASN / Domain entities plus `located in`,
//! `in asn`, and `resolves to` claims. A Maltego-style IP transform.

use indago_bus::Bus;
use indago_core::{Claim, Entity, EntityType, EvidenceType, Predicate};
use indago_protocol::{BusEnvelope, Capability, CaseId, IndagoMessage, RequestId};
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};

const COLLECTOR: &str = "indago-collect-ip";

#[derive(Debug, Deserialize)]
struct IpApi {
    country: Option<String>,
    #[serde(rename = "regionName")]
    region: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    #[serde(rename = "as")]
    asn: Option<String>,
    reverse: Option<String>,
}

/// Start the IP-intel collector subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionApproved {
                    request_id,
                    case_id,
                    capability: Capability::IpIntel,
                    target,
                    ..
                }) => {
                    let bus = bus.clone();
                    tokio::spawn(async move {
                        run(bus, request_id, case_id, target).await;
                    });
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "ip collector fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

async fn run(bus: Bus, request_id: RequestId, case_id: CaseId, target: String) {
    let raw = match fetch(&target).await {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(error = %e, %target, "ip-api query failed");
            return;
        }
    };
    let info = serde_json::from_slice::<IpApi>(&raw).ok();
    info!(%target, "ip intel captured");

    bus.send(IndagoMessage::CollectionResult {
        request_id,
        case_id,
        capability: Capability::IpIntel,
        target: target.clone(),
        title: format!("IP intel — {target}"),
        evidence_type: EvidenceType::JsonResponse,
        format: "JSON".into(),
        source_url: Some(format!("http://ip-api.com/json/{target}")),
        collector: COLLECTOR.into(),
        raw,
        envelope: BusEnvelope::fresh(),
    });

    let ip = Entity::canonical(EntityType::IpAddress, &target);
    emit_entity(&bus, &ip);
    let Some(info) = info else { return };

    if let Some(loc) = location_label(&info) {
        let location = Entity::canonical(EntityType::Location, &loc);
        emit_entity(&bus, &location);
        emit_claim(&bus, Claim::assert(ip.id, Predicate::LocatedIn, location.id, COLLECTOR));
    }
    if let Some(asn) = info.asn.filter(|s| !s.is_empty()) {
        let asn_entity = Entity::canonical(EntityType::Asn, &asn);
        emit_entity(&bus, &asn_entity);
        emit_claim(&bus, Claim::assert(ip.id, Predicate::InAsn, asn_entity.id, COLLECTOR));
    }
    if let Some(isp) = info.isp.filter(|s| !s.is_empty()) {
        emit_entity(&bus, &Entity::canonical(EntityType::Company, &isp));
    }
    if let Some(rev) = info.reverse.filter(|s| !s.is_empty()) {
        let host = Entity::canonical(EntityType::Domain, &rev);
        emit_entity(&bus, &host);
        emit_claim(&bus, Claim::assert(host.id, Predicate::ResolvesTo, ip.id, COLLECTOR));
    }
}

fn location_label(info: &IpApi) -> Option<String> {
    let parts: Vec<&str> = [&info.city, &info.region, &info.country]
        .into_iter()
        .filter_map(|o| o.as_deref())
        .filter(|s| !s.is_empty())
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

fn emit_entity(bus: &Bus, entity: &Entity) {
    bus.send(IndagoMessage::EntityCreated {
        entity: entity.clone(),
        envelope: BusEnvelope::fresh(),
    });
}

fn emit_claim(bus: &Bus, mut claim: Claim) {
    claim.confidence = 85;
    bus.send(IndagoMessage::ClaimProposed {
        claim,
        envelope: BusEnvelope::fresh(),
    });
}

async fn fetch(ip: &str) -> reqwest::Result<Vec<u8>> {
    // ip-api.com free tier is HTTP-only; rustls still does plain HTTP fine.
    let url = format!(
        "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,as,asname,reverse,query"
    );
    let client = reqwest::Client::builder().user_agent("indago/0.1").build()?;
    Ok(client.get(&url).send().await?.bytes().await?.to_vec())
}
