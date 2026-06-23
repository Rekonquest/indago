//! # indago — runtime entrypoint
//!
//! Builds the bus, opens the store, starts every subsystem, and idles until
//! Ctrl-C. `main` contains no business logic — the wiring is the subscriptions
//! each subsystem declares.
//!
//! ## Modes
//!
//! - **default** — start subsystems, print a banner, idle until Ctrl-C.
//! - **`INDAGO_SMOKE=1`** — emit one `CollectionResult` and verify it flows
//!   end-to-end (store freezes it → emits `EvidenceStored`), then exit 0. This
//!   is the Phase-1 "one message wired end to end" check.
//! - **`INDAGO_SMOKE=<capability>[:<target>]`** — emit a real `CollectionRequest`
//!   and verify the full vertical slice: gate approves → collector captures →
//!   store freezes evidence (and proposes entities/claims). Requires network.
//!   Examples: `dns`, `whois:example.com`, `cert:example.com`,
//!   `web:https://example.com`, `username:torvalds`. Exits 0 on success.
//!
//! ## Environment
//!
//! - `INDAGO_DATA` — store root directory (default `indago-data`).
//! - `INDAGO_SMOKE=1` — store-only end-to-end check; or `<capability>[:target]`.
//! - `INDAGO_GATE=require` — make the gate require approval (default: auto).
//! - `RUST_LOG` — tracing-subscriber env filter.

use std::process::ExitCode;
use std::time::Duration;

use indago_bus::Bus;
use indago_core::EvidenceType;
use indago_protocol::{
    BusEnvelope, Capability, IndagoMessage, ModeKind, StoreQueryKind, StoreResultData,
};
use tokio::runtime::Builder;
use tokio::signal;
use uuid::Uuid;

fn main() -> ExitCode {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .try_init();

    let rt = match Builder::new_multi_thread().worker_threads(4).enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("indago: tokio runtime build failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(async_main())
}

async fn async_main() -> ExitCode {
    let bus = Bus::new(indago_bus::DEFAULT_CAPACITY);

    let root = std::env::var("INDAGO_DATA").unwrap_or_else(|_| "indago-data".to_string());

    // Start every subsystem on the bus (wiring lives in indago-runtime).
    if let Err(e) = indago_runtime::start_subsystems(&bus, &root) {
        eprintln!("indago: startup failed: {e}");
        return ExitCode::FAILURE;
    }

    // Yield so subsystems subscribe before we emit anything or count receivers.
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }

    print_banner(&bus, &root);

    match std::env::var("INDAGO_SMOKE").ok().as_deref() {
        Some("1") => return run_smoke(&bus).await,
        Some("dedup") => return run_dedup_smoke(&bus).await,
        Some("extract") => return run_extract_smoke(&bus).await,
        Some("mode") => {
            return run_mode_smoke(&bus, ModeKind::DomainFootprint, "example.com").await
        }
        Some("poi") => {
            return run_mode_smoke(&bus, ModeKind::PersonOfInterest, "torvalds").await
        }
        Some("audit") => return run_audit_smoke(&bus, &root).await,
        Some("report") => return run_report_smoke(&bus, &root).await,
        Some(spec) if !spec.is_empty() => {
            let (cap_str, target) = spec.split_once(':').unwrap_or((spec, ""));
            match parse_capability(cap_str) {
                Some(cap) => {
                    let target = if target.is_empty() {
                        default_target(cap)
                    } else {
                        target.to_string()
                    };
                    return run_collect_smoke(&bus, cap, target).await;
                }
                None => {
                    eprintln!("indago: unknown smoke spec '{spec}' (use 1, or <capability>[:target])");
                    return ExitCode::FAILURE;
                }
            }
        }
        _ => {}
    }

    println!("indago: online — press Ctrl-C to stop");
    match signal::ctrl_c().await {
        Ok(()) => {
            println!("indago: shutdown signal received");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("indago: ctrl_c failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_banner(bus: &Bus, root: &str) {
    println!("indago: online");
    println!("data root: {root}");
    println!("bus receivers: {}", bus.receiver_count());
}

/// Phase-1 end-to-end check: emit a `CollectionResult`, expect the store to
/// freeze it and emit `EvidenceStored`. Returns success only if the round trip
/// completes within the timeout.
async fn run_smoke(bus: &Bus) -> ExitCode {
    println!("indago: INDAGO_SMOKE=1 — verifying one message end-to-end");
    let mut rx = bus.subscribe();

    let request_id = Uuid::new_v4();
    let case_id = Uuid::new_v4();
    bus.send(IndagoMessage::CollectionResult {
        request_id,
        case_id,
        capability: Capability::WebFetch,
        target: "smoke".into(),
        title: "smoke test artifact".into(),
        evidence_type: EvidenceType::JsonResponse,
        format: "JSON".into(),
        source_url: Some("https://example.com/".into()),
        collector: "smoke".into(),
        raw: br#"{"hello":"indago"}"#.to_vec(),
        envelope: BusEnvelope::fresh(),
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Ok(IndagoMessage::EvidenceStored {
                evidence_id,
                request_id: rid,
                ..
            })) if rid == request_id => {
                println!("indago smoke: OK — EvidenceStored id={evidence_id}");
                return ExitCode::SUCCESS;
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => {
                eprintln!("indago smoke: FAILED — bus closed before EvidenceStored");
                return ExitCode::FAILURE;
            }
            Err(_) => {
                eprintln!("indago smoke: FAILED — timed out waiting for EvidenceStored");
                return ExitCode::FAILURE;
            }
        }
    }
}

/// Demonstrate gate dedup against the store: run the same request twice in one
/// process. The first freezes evidence; the second is denied (already collected).
async fn run_dedup_smoke(bus: &Bus) -> ExitCode {
    println!("indago: INDAGO_SMOKE=dedup — first request collects, second is deduped");
    let mut rx = bus.subscribe();
    let case_id = Uuid::new_v4();
    let target = "example.com".to_string();

    // First request: expect evidence.
    let req1 = Uuid::new_v4();
    bus.send(IndagoMessage::CollectionRequest {
        request_id: req1,
        case_id,
        capability: Capability::Dns,
        target: target.clone(),
        envelope: BusEnvelope::fresh(),
    });

    let deadline1 = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut first_collected = false;
    while let Ok(Ok(msg)) = tokio::time::timeout_at(deadline1, rx.recv()).await {
        if let IndagoMessage::EvidenceStored { request_id: rid, .. } = msg {
            if rid == req1 {
                println!("  first request: evidence frozen");
                first_collected = true;
                break;
            }
        }
    }
    if !first_collected {
        eprintln!("indago dedup: FAILED — first request never produced evidence");
        return ExitCode::FAILURE;
    }

    // Give the store a beat to record the collection, then repeat the request.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let req2 = Uuid::new_v4();
    bus.send(IndagoMessage::CollectionRequest {
        request_id: req2,
        case_id,
        capability: Capability::Dns,
        target,
        envelope: BusEnvelope::fresh(),
    });

    let deadline2 = tokio::time::Instant::now() + Duration::from_secs(10);
    while let Ok(Ok(msg)) = tokio::time::timeout_at(deadline2, rx.recv()).await {
        match msg {
            IndagoMessage::CollectionDenied { request_id: rid, reason, .. } if rid == req2 => {
                println!("  second request: DENIED — {reason}");
                println!("indago dedup: OK — gate deduped the repeat collection");
                return ExitCode::SUCCESS;
            }
            IndagoMessage::EvidenceStored { request_id: rid, .. } if rid == req2 => {
                eprintln!("indago dedup: FAILED — second request was collected again, not deduped");
                return ExitCode::FAILURE;
            }
            _ => {}
        }
    }
    eprintln!("indago dedup: FAILED — no decision on the second request");
    ExitCode::FAILURE
}

/// Run a quick investigation, then generate a legally-defensible case report
/// from the store (entities + claims + evidence queried over the bus).
async fn run_report_smoke(bus: &Bus, root: &str) -> ExitCode {
    println!("indago: INDAGO_SMOKE=report — investigate example.com, then generate a case report");
    let case_id = Uuid::new_v4();
    bus.send(IndagoMessage::StartMode {
        case_id,
        mode: ModeKind::DomainFootprint,
        seed: "example.com".into(),
        envelope: BusEnvelope::fresh(),
    });
    // Let the cascade settle before snapshotting.
    tokio::time::sleep(Duration::from_secs(12)).await;

    let entities = match store_query(bus, StoreQueryKind::ListEntities).await {
        Some(StoreResultData::Entities(v)) => v,
        _ => Vec::new(),
    };
    let claims = match store_query(bus, StoreQueryKind::ListClaims).await {
        Some(StoreResultData::Claims(v)) => v,
        _ => Vec::new(),
    };
    let evidence = match store_query(bus, StoreQueryKind::ListEvidence).await {
        Some(StoreResultData::Evidence(v)) => v,
        _ => Vec::new(),
    };

    let markdown = indago_report::render_markdown(&entities, &claims, &evidence);
    let path = format!("{root}/report.md");
    if let Err(e) = std::fs::write(&path, &markdown) {
        eprintln!("indago report: FAILED — could not write {path}: {e}");
        return ExitCode::FAILURE;
    }

    println!(
        "indago report: OK — {} entities / {} claims / {} evidence → {path}",
        entities.len(),
        claims.len(),
        evidence.len()
    );
    println!("───────── report preview ─────────");
    for line in markdown.lines().take(24) {
        println!("  {line}");
    }
    ExitCode::SUCCESS
}

/// Send a store query and await its correlated result.
async fn store_query(bus: &Bus, query: StoreQueryKind) -> Option<StoreResultData> {
    let mut rx = bus.subscribe();
    let query_id = Uuid::new_v4();
    bus.send(IndagoMessage::StoreQuery {
        query_id,
        query,
        envelope: BusEnvelope::fresh(),
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Ok(IndagoMessage::StoreResult { query_id: qid, result, .. })) if qid == query_id => {
                return Some(result)
            }
            Ok(Ok(_)) => continue,
            _ => return None,
        }
    }
}

/// Collect one artifact, then verify the tamper-evident audit chain on disk.
async fn run_audit_smoke(bus: &Bus, root: &str) -> ExitCode {
    println!("indago: INDAGO_SMOKE=audit — collect, then verify the tamper-evident log");
    let mut rx = bus.subscribe();
    let request_id = Uuid::new_v4();
    let case_id = Uuid::new_v4();
    bus.send(IndagoMessage::CollectionRequest {
        request_id,
        case_id,
        capability: Capability::Dns,
        target: "example.com".into(),
        envelope: BusEnvelope::fresh(),
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut got = false;
    while let Ok(Ok(msg)) = tokio::time::timeout_at(deadline, rx.recv()).await {
        if let IndagoMessage::EvidenceStored { request_id: rid, .. } = msg {
            if rid == request_id {
                got = true;
                break;
            }
        }
    }
    if !got {
        eprintln!("indago audit: FAILED — no evidence (network required)");
        return ExitCode::FAILURE;
    }

    // Let the audit watcher flush the trailing entries, then verify.
    tokio::time::sleep(Duration::from_millis(600)).await;
    match indago_audit::verify_log(root) {
        Ok(n) => {
            println!("indago audit: OK — verified {n} hash-chained, signed log entries");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("indago audit: FAILED — {e}");
            ExitCode::FAILURE
        }
    }
}

/// Run the DomainFootprint mode agent and watch it chain collectors into a
/// cascade: seed fan-out, then reactive DNS+WHOIS of discovered subdomains.
async fn run_mode_smoke(bus: &Bus, mode: ModeKind, seed: &str) -> ExitCode {
    println!("indago: smoke {mode:?} strategy chaining collectors — seed {seed}");
    let mut rx = bus.subscribe();
    let case_id = Uuid::new_v4();
    bus.send(IndagoMessage::StartMode {
        case_id,
        mode,
        seed: seed.to_string(),
        envelope: BusEnvelope::fresh(),
    });

    let overall = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut grace: Option<tokio::time::Instant> = None;
    let (mut statuses, mut approvals, mut denials, mut evidence, mut claims) = (0, 0, 0, 0, 0);

    loop {
        let until = grace.unwrap_or(overall);
        match tokio::time::timeout_at(until, rx.recv()).await {
            Ok(Ok(IndagoMessage::AgentStatusUpdate { agent, status, detail, .. })) => {
                statuses += 1;
                println!("  [{agent}] {status:?} — {detail}");
            }
            Ok(Ok(IndagoMessage::CollectionApproved { capability, target, .. })) => {
                approvals += 1;
                println!("  approved: {capability:?} {target}");
            }
            Ok(Ok(IndagoMessage::CollectionDenied { .. })) => denials += 1,
            Ok(Ok(IndagoMessage::EvidenceStored { .. })) => {
                evidence += 1;
                // keep draining until the cascade goes quiet
                grace = Some(tokio::time::Instant::now() + Duration::from_secs(6));
            }
            Ok(Ok(IndagoMessage::ClaimAccepted { .. })) => claims += 1,
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }

    println!(
        "indago mode: agent-statuses={statuses} approvals={approvals} denials={denials} \
         evidence={evidence} claims-accepted={claims}"
    );
    if statuses > 0 && evidence >= 2 {
        println!("indago mode: OK — strategy chained collectors into a cascade");
        ExitCode::SUCCESS
    } else {
        eprintln!("indago mode: FAILED — expected agent activity + multiple captures (network required)");
        ExitCode::FAILURE
    }
}

/// Collect an artifact, then let the LLM extractor mine it for claims. Shows the
/// one-LLM-leaf in action against the local Ollama model.
async fn run_extract_smoke(bus: &Bus) -> ExitCode {
    println!("indago: INDAGO_SMOKE=extract — collect WHOIS, then LLM-extract claims from it");
    let mut rx = bus.subscribe();
    let request_id = Uuid::new_v4();
    let case_id = Uuid::new_v4();
    bus.send(IndagoMessage::CollectionRequest {
        request_id,
        case_id,
        capability: Capability::Whois,
        target: "example.com".into(),
        envelope: BusEnvelope::fresh(),
    });

    let overall = tokio::time::Instant::now() + Duration::from_secs(90);
    let mut grace: Option<tokio::time::Instant> = None;
    let mut evidence = false;
    let mut collector_claims = 0usize;
    let mut extractor_claims = 0usize;

    loop {
        let until = grace.unwrap_or(overall);
        match tokio::time::timeout_at(until, rx.recv()).await {
            Ok(Ok(IndagoMessage::EvidenceStored { request_id: rid, .. })) if rid == request_id => {
                println!("  evidence frozen — waiting for the LLM extractor…");
                evidence = true;
            }
            Ok(Ok(IndagoMessage::ClaimProposed { claim, .. })) => {
                if claim.author == "indago-extractor" {
                    extractor_claims += 1;
                    println!("  [LLM] {:?} (confidence {})", claim.predicate, claim.confidence);
                    // once the model starts producing, finish shortly after it goes quiet
                    grace = Some(tokio::time::Instant::now() + Duration::from_secs(4));
                } else {
                    collector_claims += 1;
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => break,
            Err(_) => break, // overall or grace deadline
        }
    }

    if !evidence {
        eprintln!("indago extract: FAILED — no evidence (network required)");
        return ExitCode::FAILURE;
    }
    println!(
        "indago extract: OK — collector claims={collector_claims}, LLM-extracted claims={extractor_claims}"
    );
    if extractor_claims == 0 {
        println!("  (note: the model extracted no claims from this artifact — try a richer target)");
    }
    ExitCode::SUCCESS
}

/// Map a capability label to its enum. Used by the smoke harness.
fn parse_capability(s: &str) -> Option<Capability> {
    Some(match s {
        "dns" => Capability::Dns,
        "whois" => Capability::Whois,
        "web" => Capability::WebFetch,
        "screenshot" => Capability::Screenshot,
        "cert" => Capability::CertTransparency,
        "username" => Capability::UsernameEnum,
        "email" => Capability::EmailScrape,
        "subdomain" => Capability::SubdomainEnum,
        "breach" => Capability::BreachCheck,
        "ip" | "ipintel" => Capability::IpIntel,
        "revip" | "reverseip" => Capability::ReverseIp,
        "wayback" => Capability::Wayback,
        "shodan" => Capability::ShodanHost,
        "favicon" => Capability::FaviconHash,
        "urlscan" => Capability::UrlScan,
        "asn" => Capability::AsnPrefixes,
        "emailrep" => Capability::EmailRep,
        _ => return None,
    })
}

/// A sensible default target per capability when the smoke spec omits one.
fn default_target(capability: Capability) -> String {
    match capability {
        Capability::WebFetch | Capability::EmailScrape => "https://example.com".into(),
        Capability::UsernameEnum => "torvalds".into(),
        Capability::BreachCheck | Capability::EmailRep => "test@example.com".into(),
        Capability::IpIntel | Capability::ReverseIp | Capability::ShodanHost => "1.1.1.1".into(),
        Capability::FaviconHash => "https://github.com".into(),
        Capability::AsnPrefixes => "13335".into(),
        _ => "example.com".into(),
    }
}

/// Full vertical-slice check for any capability: emit a `CollectionRequest`,
/// then observe gate approval → capture → evidence frozen (and any proposed
/// entities/claims). Succeeds on `EvidenceStored` for the request.
async fn run_collect_smoke(bus: &Bus, capability: Capability, target: String) -> ExitCode {
    println!("indago: smoke {capability:?} target={target}");
    let mut rx = bus.subscribe();

    let request_id = Uuid::new_v4();
    let case_id = Uuid::new_v4();
    bus.send(IndagoMessage::CollectionRequest {
        request_id,
        case_id,
        capability,
        target,
        envelope: BusEnvelope::fresh(),
    });

    // Drain until the overall deadline, but stop early once evidence has been
    // frozen and the downstream entity/claim traffic has gone quiet.
    let overall = tokio::time::Instant::now() + Duration::from_secs(40);
    let mut evidence: Option<String> = None;
    let mut grace: Option<tokio::time::Instant> = None;
    loop {
        let until = grace.unwrap_or(overall);
        match tokio::time::timeout_at(until, rx.recv()).await {
            Ok(Ok(IndagoMessage::CollectionApproved { target, .. })) => {
                println!("  gate: approved {target}");
            }
            Ok(Ok(IndagoMessage::EntityCreated { entity, .. })) => {
                println!("  entity: {:?} {}", entity.entity_type, entity.name);
            }
            Ok(Ok(IndagoMessage::ClaimProposed { claim, .. })) => {
                println!(
                    "  claim proposed: {:?} (confidence {})",
                    claim.predicate, claim.confidence
                );
            }
            Ok(Ok(IndagoMessage::ClaimAccepted { claim, .. })) => {
                println!(
                    "  claim accepted: {:?} sources={} confidence={}",
                    claim.status, claim.source_count, claim.confidence
                );
            }
            Ok(Ok(IndagoMessage::CollectionDenied { reason, .. })) => {
                println!("  gate: DENIED — {reason}");
            }
            Ok(Ok(IndagoMessage::EvidenceStored {
                evidence_id,
                request_id: rid,
                ..
            })) if rid == request_id => {
                println!("  store: evidence frozen id={evidence_id}");
                evidence = Some(evidence_id);
                // give downstream claim traffic a moment to flush, then finish
                grace = Some(tokio::time::Instant::now() + Duration::from_millis(1500));
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => break,
            Err(_) => break, // overall deadline or grace window elapsed
        }
    }

    match evidence {
        Some(id) => {
            println!("indago smoke: OK — full flow verified (evidence {id})");
            ExitCode::SUCCESS
        }
        None => {
            eprintln!("indago smoke: FAILED — no evidence (network required for live collection)");
            ExitCode::FAILURE
        }
    }
}
