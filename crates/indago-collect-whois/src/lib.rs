//! # Indago WHOIS Collector
//!
//! Mechanism-only. On an approved [`Capability::Whois`] request it performs a
//! raw-socket WHOIS query (port 43) following the IANA referral chain — query
//! `whois.iana.org`, read the `refer:` line, then query the authoritative
//! registry server — and freezes the combined response as evidence.
//!
//! No external WHOIS crate or vendored server list is needed; the referral
//! chain is the protocol's own discovery mechanism. (`whois-rust` can be
//! swapped in later if a bundled server map is preferred.)

use indago_bus::Bus;
use indago_core::{Entity, EntityType, EvidenceType};
use indago_protocol::{BusEnvelope, Capability, CaseId, IndagoMessage, RequestId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};

const COLLECTOR: &str = "indago-collect-whois";
const IANA_WHOIS: &str = "whois.iana.org";

/// Start the WHOIS collector subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionApproved {
                    request_id,
                    case_id,
                    capability: Capability::Whois,
                    target,
                    ..
                }) => {
                    let bus = bus.clone();
                    tokio::spawn(async move {
                        run(bus, request_id, case_id, target).await;
                    });
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "whois collector fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

async fn run(bus: Bus, request_id: RequestId, case_id: CaseId, target: String) {
    let text = match whois(&target).await {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, %target, "whois lookup failed");
            return;
        }
    };
    info!(%target, bytes = text.len(), "whois captured");

    bus.send(IndagoMessage::CollectionResult {
        request_id,
        case_id,
        capability: Capability::Whois,
        target: target.clone(),
        title: format!("WHOIS — {target}"),
        evidence_type: EvidenceType::Document,
        format: "TXT".into(),
        source_url: Some(format!("whois://{target}")),
        collector: COLLECTOR.into(),
        raw: text.into_bytes(),
        envelope: BusEnvelope::fresh(),
    });

    bus.send(IndagoMessage::EntityCreated {
        entity: Entity::canonical(EntityType::Domain, &target),
        envelope: BusEnvelope::fresh(),
    });
}

/// Query IANA, follow the `refer:` referral, and return both responses.
async fn whois(domain: &str) -> std::io::Result<String> {
    let iana = query(IANA_WHOIS, domain).await?;
    let refer = iana.lines().find_map(|l| {
        l.trim()
            .strip_prefix("refer:")
            .map(|s| s.trim().to_string())
    });
    match refer {
        Some(server) if !server.is_empty() => {
            let detail = query(&server, domain).await.unwrap_or_default();
            Ok(format!(
                "=== {IANA_WHOIS} ===\n{iana}\n=== {server} ===\n{detail}"
            ))
        }
        _ => Ok(iana),
    }
}

/// One raw WHOIS exchange: connect to `server:43`, send the query, read all.
async fn query(server: &str, query: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect((server, 43)).await?;
    stream.write_all(format!("{query}\r\n").as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}
