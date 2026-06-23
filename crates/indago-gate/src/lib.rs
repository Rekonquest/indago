//! # Indago Gate
//!
//! The deterministic policy gate. **Every [`IndagoMessage::CollectionRequest`]
//! passes through here before any collector executes.** Agents propose; the gate
//! disposes. No LLM, no heuristics — every decision is a pure function of the
//! request and the gate's state.
//!
//! ## Flow (two-phase)
//!
//! 1. On a request, the gate asks the store whether `(case, capability, target)`
//!    was **already collected** ([`StoreQueryKind::AlreadyCollected`]).
//! 2. On the store's reply:
//!    - already collected → [`IndagoMessage::CollectionDenied`] (dedup).
//!    - otherwise → dispose per [`Policy`]: approve immediately, or request
//!      human approval and wait for [`IndagoMessage::GateApprovalResponse`].
//!
//! Still TODO for a full gate (Phase 3): per-case scope rules, rate budget, and
//! credential availability. Dedup against the evidence store is now real.

use std::collections::HashMap;

use indago_bus::Bus;
use indago_protocol::{
    BusEnvelope, Capability, CaseId, IndagoMessage, RequestId, StoreQueryKind, StoreResultData,
};
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};
use uuid::Uuid;

/// How the gate disposes of requests that pass dedup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Approve every (in-scope, not-yet-collected) request immediately.
    AutoApprove,
    /// Route live actions through a human-in-the-loop approval.
    RequireApproval,
}

impl Policy {
    /// Read the policy from `INDAGO_GATE` (`require` → RequireApproval, else
    /// AutoApprove).
    pub fn from_env() -> Self {
        match std::env::var("INDAGO_GATE").ok().as_deref() {
            Some("require") => Policy::RequireApproval,
            _ => Policy::AutoApprove,
        }
    }
}

/// A request awaiting its dedup answer or human approval.
#[derive(Clone)]
struct Pending {
    request_id: RequestId,
    case_id: CaseId,
    capability: Capability,
    target: String,
}

/// Start the gate with the policy from the environment.
pub fn start(bus: Bus) {
    start_with_policy(bus, Policy::from_env());
}

/// Start the gate with an explicit policy.
pub fn start_with_policy(bus: Bus, policy: Policy) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        // Requests awaiting a dedup reply, keyed by the store query id.
        let mut pending_dedup: HashMap<Uuid, Pending> = HashMap::new();
        // Requests awaiting human approval, keyed by request id.
        let mut pending_approval: HashMap<RequestId, Pending> = HashMap::new();

        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionRequest {
                    request_id,
                    case_id,
                    capability,
                    target,
                    ..
                }) => {
                    // Phase 1: ask the store whether this was already collected.
                    let query_id = Uuid::new_v4();
                    pending_dedup.insert(
                        query_id,
                        Pending {
                            request_id,
                            case_id,
                            capability,
                            target: target.clone(),
                        },
                    );
                    bus.send(IndagoMessage::StoreQuery {
                        query_id,
                        query: StoreQueryKind::AlreadyCollected {
                            case_id,
                            capability,
                            target,
                        },
                        envelope: BusEnvelope::fresh(),
                    });
                }
                Ok(IndagoMessage::StoreResult { query_id, result, .. }) => {
                    let Some(req) = pending_dedup.remove(&query_id) else {
                        continue; // not our query
                    };
                    if matches!(result, StoreResultData::Bool(true)) {
                        info!(request_id = %req.request_id, target = %req.target, "gate: denied (already collected)");
                        bus.send(IndagoMessage::CollectionDenied {
                            request_id: req.request_id,
                            reason: format!(
                                "already collected {:?} for {} in this case",
                                req.capability, req.target
                            ),
                            envelope: BusEnvelope::fresh(),
                        });
                    } else {
                        dispose(&bus, policy, req, &mut pending_approval);
                    }
                }
                Ok(IndagoMessage::GateApprovalResponse {
                    request_id,
                    approved,
                    ..
                }) => {
                    if let Some(req) = pending_approval.remove(&request_id) {
                        if approved {
                            info!(request_id = %request_id, "gate: approved by responder");
                            emit_approved(&bus, &req);
                        } else {
                            info!(request_id = %request_id, "gate: denied by responder");
                            bus.send(IndagoMessage::CollectionDenied {
                                request_id,
                                reason: "denied by approver".into(),
                                envelope: BusEnvelope::fresh(),
                            });
                        }
                    }
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "gate fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

/// Dispose of a deduped request per policy.
fn dispose(bus: &Bus, policy: Policy, req: Pending, pending_approval: &mut HashMap<RequestId, Pending>) {
    match policy {
        Policy::AutoApprove => {
            info!(request_id = %req.request_id, capability = ?req.capability, target = %req.target, "gate: auto-approved");
            emit_approved(bus, &req);
        }
        Policy::RequireApproval => {
            let risk = format!("Live external query ({:?}) against {}", req.capability, req.target);
            info!(request_id = %req.request_id, capability = ?req.capability, target = %req.target, "gate: approval requested");
            bus.send(IndagoMessage::GateApprovalRequest {
                request_id: req.request_id,
                case_id: req.case_id,
                capability: req.capability,
                target: req.target.clone(),
                risk,
                envelope: BusEnvelope::fresh(),
            });
            pending_approval.insert(req.request_id, req);
        }
    }
}

fn emit_approved(bus: &Bus, req: &Pending) {
    bus.send(IndagoMessage::CollectionApproved {
        request_id: req.request_id,
        case_id: req.case_id,
        capability: req.capability,
        target: req.target.clone(),
        envelope: BusEnvelope::fresh(),
    });
}
