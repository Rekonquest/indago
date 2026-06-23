//! # Indago Web Collector
//!
//! Mechanism-only. On an approved [`Capability::WebFetch`] request it fetches
//! the URL with `reqwest` and **freezes the response** as a minimal but valid
//! WARC/1.0 `response` record — embodying the "capture, don't query" rule: the
//! raw HTTP response (status line + headers + body) is preserved verbatim, then
//! all downstream work runs from the frozen copy.

use chrono::Utc;
use indago_bus::Bus;
use indago_core::{Entity, EntityType, EvidenceType};
use indago_protocol::{BusEnvelope, Capability, CaseId, IndagoMessage, RequestId};
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};
use uuid::Uuid;

const COLLECTOR: &str = "indago-collect-web";

/// Start the web collector subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionApproved {
                    request_id,
                    case_id,
                    capability: Capability::WebFetch,
                    target,
                    ..
                }) => {
                    let bus = bus.clone();
                    tokio::spawn(async move {
                        run(bus, request_id, case_id, target).await;
                    });
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "web collector fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

async fn run(bus: Bus, request_id: RequestId, case_id: CaseId, target: String) {
    let warc = match fetch_warc(&target).await {
        Ok(w) => w,
        Err(e) => {
            warn!(error = %e, %target, "web fetch failed");
            return;
        }
    };
    info!(%target, bytes = warc.len(), "web capture frozen");

    bus.send(IndagoMessage::CollectionResult {
        request_id,
        case_id,
        capability: Capability::WebFetch,
        target: target.clone(),
        title: format!("Web capture — {target}"),
        evidence_type: EvidenceType::Warc,
        format: "WARC".into(),
        source_url: Some(target.clone()),
        collector: COLLECTOR.into(),
        raw: warc,
        envelope: BusEnvelope::fresh(),
    });

    // Propose the host as a Domain entity.
    if let Some(host) = reqwest::Url::parse(&target)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
    {
        bus.send(IndagoMessage::EntityCreated {
            entity: Entity::canonical(EntityType::Domain, host),
            envelope: BusEnvelope::fresh(),
        });
    }
}

/// Fetch `url` and wrap the response in a WARC/1.0 `response` record.
async fn fetch_warc(url: &str) -> reqwest::Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .user_agent("indago/0.1 (+evidence-capture)")
        .build()?;
    let resp = client.get(url).send().await?;
    let final_url = resp.url().to_string();
    let status = resp.status();
    let version = format!("{:?}", resp.version());
    let headers = resp.headers().clone();
    let body = resp.bytes().await?;

    // Reconstruct the HTTP response block that the WARC payload wraps.
    let reason = status.canonical_reason().unwrap_or("");
    let mut http = format!("{version} {} {reason}\r\n", status.as_u16());
    for (name, value) in headers.iter() {
        http.push_str(name.as_str());
        http.push_str(": ");
        http.push_str(value.to_str().unwrap_or(""));
        http.push_str("\r\n");
    }
    http.push_str("\r\n");
    let mut http_block = http.into_bytes();
    http_block.extend_from_slice(&body);

    // WARC envelope around the HTTP block.
    let header = format!(
        "WARC/1.0\r\n\
         WARC-Type: response\r\n\
         WARC-Target-URI: {final_url}\r\n\
         WARC-Date: {}\r\n\
         WARC-Record-ID: <urn:uuid:{}>\r\n\
         Content-Type: application/http; msgtype=response\r\n\
         Content-Length: {}\r\n\r\n",
        Utc::now().to_rfc3339(),
        Uuid::new_v4(),
        http_block.len(),
    );
    let mut warc = header.into_bytes();
    warc.extend_from_slice(&http_block);
    warc.extend_from_slice(b"\r\n\r\n");
    Ok(warc)
}
