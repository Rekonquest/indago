//! # Indago Extractor — the one LLM leaf
//!
//! This is the **only** place an LLM appears in Indago. On each
//! [`IndagoMessage::EvidenceStored`] it reads the frozen artifact **through the
//! store's message interface** (a [`StoreQueryKind::ReadBlob`] query — never a
//! direct cross-crate call), asks a local Ollama model to extract structured
//! facts, and emits proposed entities and claims.
//!
//! It is a leaf *generator*: it never routes, never accepts its own claims, and
//! never decides collection. The gate and claim engine dispose. If Ollama is
//! unreachable or returns unparseable output, extraction is skipped silently —
//! the frozen evidence and collector-proposed claims are unaffected.
//!
//! Config: `INDAGO_OLLAMA` (default `http://localhost:11434`),
//! `INDAGO_EXTRACTOR_MODEL` (default `qwen35-4b-instruct-q8-chat:latest`).

use std::collections::HashMap;

use indago_bus::Bus;
use indago_core::{Claim, Entity, EntityType, EvidenceType, Predicate};
use indago_protocol::{BusEnvelope, IndagoMessage, StoreQueryKind, StoreResultData};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::error::RecvError;
use tracing::{debug, info, warn};
use uuid::Uuid;

const AUTHOR: &str = "indago-extractor";
const DEFAULT_MODEL: &str = "qwen35-4b-instruct-q8-chat:latest";
const DEFAULT_HOST: &str = "http://localhost:11434";
/// Cap artifact text sent to the model (keeps the prompt within a small model's
/// comfortable window).
const MAX_TEXT: usize = 6000;

/// What the extractor remembers about an artifact while it awaits the blob.
#[derive(Clone)]
struct PendingBlob {
    source_url: Option<String>,
    evidence_type: EvidenceType,
}

/// Start the extractor subsystem.
pub fn start(bus: Bus) {
    let host = std::env::var("INDAGO_OLLAMA").unwrap_or_else(|_| DEFAULT_HOST.to_string());
    let model = std::env::var("INDAGO_EXTRACTOR_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string());
    info!(%host, %model, "extractor: using local Ollama model");

    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        // Artifacts awaiting their blob, keyed by the ReadBlob query id.
        let mut pending: HashMap<Uuid, PendingBlob> = HashMap::new();

        loop {
            match rx.recv().await {
                Ok(IndagoMessage::EvidenceStored {
                    evidence_id,
                    evidence_type,
                    source_url,
                    ..
                }) => {
                    if !is_textual(evidence_type) {
                        continue; // can't extract claims from a screenshot
                    }
                    let query_id = Uuid::new_v4();
                    pending.insert(
                        query_id,
                        PendingBlob {
                            source_url,
                            evidence_type,
                        },
                    );
                    bus.send(IndagoMessage::StoreQuery {
                        query_id,
                        query: StoreQueryKind::ReadBlob { evidence_id },
                        envelope: BusEnvelope::fresh(),
                    });
                }
                Ok(IndagoMessage::StoreResult { query_id, result, .. }) => {
                    let Some(ctx) = pending.remove(&query_id) else {
                        continue; // not our query (e.g. the gate's dedup reply)
                    };
                    if let StoreResultData::Blob(Some(bytes)) = result {
                        let bus = bus.clone();
                        let host = host.clone();
                        let model = model.clone();
                        tokio::spawn(async move {
                            extract(bus, host, model, ctx, bytes).await;
                        });
                    }
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "extractor fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

/// Only text-bearing artifacts are worth sending to the model.
fn is_textual(t: EvidenceType) -> bool {
    matches!(
        t,
        EvidenceType::JsonResponse
            | EvidenceType::Document
            | EvidenceType::RawHtml
            | EvidenceType::Warc
            | EvidenceType::Other
    )
}

async fn extract(bus: Bus, host: String, model: String, ctx: PendingBlob, bytes: Vec<u8>) {
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if text.len() > MAX_TEXT {
        text.truncate(MAX_TEXT);
    }
    let source = ctx.source_url.clone().unwrap_or_default();
    let prompt = build_prompt(&source, ctx.evidence_type, &text);

    let raw = match ollama_generate(&host, &model, prompt).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "extractor: Ollama request failed");
            return;
        }
    };

    let extraction = match serde_json::from_str::<Extraction>(&raw) {
        Ok(e) => e,
        Err(e) => {
            debug!(error = %e, raw = %raw, "extractor: model output was not parseable JSON");
            return;
        }
    };

    let (entities, claims) = extraction.into_graph();
    info!(
        source = %source,
        entities = entities.len(),
        claims = claims.len(),
        "extractor: proposing"
    );
    for entity in entities {
        bus.send(IndagoMessage::EntityCreated {
            entity,
            envelope: BusEnvelope::fresh(),
        });
    }
    for claim in claims {
        bus.send(IndagoMessage::ClaimProposed {
            claim,
            envelope: BusEnvelope::fresh(),
        });
    }
}

fn build_prompt(source: &str, etype: EvidenceType, text: &str) -> String {
    format!(
        "You are an OSINT analyst extracting structured facts from a captured artifact.\n\
         Source: {source}\n\
         Artifact type: {etype:?}\n\
         Return ONLY a JSON object, no prose, with exactly this shape:\n\
         {{\"entities\":[{{\"type\":\"Domain|Person|Company|IpAddress|Email|Phone|Address|Document|Other\",\"name\":\"string\"}}],\
         \"claims\":[{{\"subject\":\"entity name\",\"predicate\":\"short verb phrase\",\"object\":\"entity name\",\"confidence\":0}}]}}\n\
         Only include facts explicitly supported by the artifact. Use entity names exactly as they appear. \
         If nothing can be extracted, return empty arrays.\n\n\
         Artifact:\n{text}"
    )
}

// ── Ollama HTTP (drive the sealed engine through its exposed surface) ────────

#[derive(Serialize)]
struct GenRequest<'a> {
    model: &'a str,
    prompt: String,
    stream: bool,
    /// Constrain the model to emit a JSON object.
    format: &'a str,
}

#[derive(Deserialize)]
struct GenResponse {
    response: String,
}

async fn ollama_generate(host: &str, model: &str, prompt: String) -> reqwest::Result<String> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{host}/api/generate"))
        .json(&GenRequest {
            model,
            prompt,
            stream: false,
            format: "json",
        })
        .send()
        .await?
        .error_for_status()?
        .json::<GenResponse>()
        .await?;
    Ok(resp.response)
}

// ── Model output schema → entities + claims ─────────────────────────────────

#[derive(Debug, Deserialize)]
struct Extraction {
    #[serde(default)]
    entities: Vec<EntityEntry>,
    #[serde(default)]
    claims: Vec<ClaimEntry>,
}

#[derive(Debug, Deserialize)]
struct EntityEntry {
    #[serde(rename = "type", default)]
    entity_type: String,
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize)]
struct ClaimEntry {
    #[serde(default)]
    subject: String,
    #[serde(default)]
    predicate: String,
    #[serde(default)]
    object: String,
    /// Models return this as either a 0-1 float or a 0-100 number; normalized
    /// in [`Extraction::into_graph`].
    #[serde(default)]
    confidence: Option<f64>,
}

impl Extraction {
    /// Resolve the model's name-based output into content-addressed entities and
    /// claims. Entities referenced by a claim but not listed are created as
    /// `Other`.
    fn into_graph(self) -> (Vec<Entity>, Vec<Claim>) {
        let mut by_name: HashMap<String, Entity> = HashMap::new();

        let mut intern = |name: &str, ty: EntityType| -> Option<Entity> {
            let key = name.trim().to_lowercase();
            if key.is_empty() {
                return None;
            }
            Some(
                by_name
                    .entry(key)
                    .or_insert_with(|| Entity::canonical(ty, name.trim()))
                    .clone(),
            )
        };

        for e in &self.entities {
            let _ = intern(&e.name, map_type(&e.entity_type));
        }

        let mut claims = Vec::new();
        for c in &self.claims {
            let (Some(subject), Some(object)) =
                (intern(&c.subject, EntityType::Other), intern(&c.object, EntityType::Other))
            else {
                continue;
            };
            if c.predicate.trim().is_empty() {
                continue;
            }
            let mut claim = Claim::assert(
                subject.id,
                Predicate::Other(c.predicate.trim().to_string()),
                object.id,
                AUTHOR,
            );
            if let Some(conf) = c.confidence {
                // Accept both 0-1 and 0-100 scales.
                let pct = if conf <= 1.0 { conf * 100.0 } else { conf };
                claim.confidence = pct.round().clamp(0.0, 100.0) as u8;
            }
            claims.push(claim);
        }

        let entities = by_name.into_values().collect();
        (entities, claims)
    }
}

fn map_type(s: &str) -> EntityType {
    match s.trim().to_ascii_lowercase().as_str() {
        "person" => EntityType::Person,
        "company" | "organization" | "org" => EntityType::Company,
        "domain" => EntityType::Domain,
        "ipaddress" | "ip" | "ip_address" => EntityType::IpAddress,
        "email" => EntityType::Email,
        "phone" => EntityType::Phone,
        "address" => EntityType::Address,
        "document" => EntityType::Document,
        _ => EntityType::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_model_json_into_entities_and_claims() {
        let json = r#"{
            "entities": [
                {"type":"Domain","name":"example.com"},
                {"type":"IpAddress","name":"93.184.216.34"}
            ],
            "claims": [
                {"subject":"93.184.216.34","predicate":"hosts","object":"example.com","confidence":85},
                {"subject":"example.com","predicate":"registered by","object":"IANA","confidence":0.95}
            ]
        }"#;
        let extraction: Extraction = serde_json::from_str(json).unwrap();
        let (entities, claims) = extraction.into_graph();
        // "IANA" is referenced by a claim but not listed -> created as Other.
        assert_eq!(entities.len(), 3);
        assert_eq!(claims.len(), 2);
        // 0-100 scale passes through; 0-1 float scales up.
        assert_eq!(claims[0].confidence, 85);
        assert_eq!(claims[1].confidence, 95);
        assert_eq!(claims[0].author, AUTHOR);
    }

    #[test]
    fn empty_extraction_yields_nothing() {
        let extraction: Extraction =
            serde_json::from_str(r#"{"entities":[],"claims":[]}"#).unwrap();
        let (entities, claims) = extraction.into_graph();
        assert!(entities.is_empty());
        assert!(claims.is_empty());
    }
}
