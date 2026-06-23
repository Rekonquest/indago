//! # Indago Claim Engine
//!
//! The deterministic claim lifecycle. It consumes [`IndagoMessage::ClaimProposed`]
//! and maintains a ledger keyed by `(subject, predicate, object)`. Proposals for
//! the same triple from **distinct sources** (authors) accumulate independent
//! source classes; when the count reaches [`CORROBORATION_THRESHOLD`] the claim
//! auto-promotes Asserted → Corroborated. Each observation emits an updated
//! [`IndagoMessage::ClaimAccepted`] (which `indago-store` persists).
//!
//! No LLM, no heuristics — promotion is the pure rule in [`indago_core`]. The
//! pure ledger logic lives in [`ClaimLedger`] and is unit-tested without the bus.

use std::collections::{HashMap, HashSet};

use indago_bus::Bus;
use indago_core::{Claim, EntityId, EvidenceId, Predicate};
use indago_protocol::{BusEnvelope, IndagoMessage};
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};

/// Identity of a claim independent of who proposed it: the asserted triple.
type ClaimKey = (EntityId, Predicate, EntityId);

struct LedgerEntry {
    /// The canonical claim (keeps the first proposal's id; status/counts evolve).
    claim: Claim,
    /// Distinct source classes (collector/agent authors) backing the triple.
    sources: HashSet<String>,
    /// Union of evidence backing the triple.
    evidence: HashSet<EvidenceId>,
}

/// The pure, testable claim ledger. Feed it proposals; it returns the canonical
/// accepted claim to emit after each.
#[derive(Default)]
pub struct ClaimLedger {
    claims: HashMap<ClaimKey, LedgerEntry>,
}

impl ClaimLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe a proposed claim and return the canonical accepted form. Idempotent
    /// per source: re-proposing from the same author does not inflate the count.
    pub fn observe(&mut self, proposed: Claim) -> Claim {
        let key = (proposed.subject, proposed.predicate.clone(), proposed.object);
        let entry = self.claims.entry(key).or_insert_with(|| LedgerEntry {
            claim: proposed.clone(),
            sources: HashSet::new(),
            evidence: HashSet::new(),
        });

        entry.sources.insert(proposed.author.clone());
        for e in &proposed.evidence {
            entry.evidence.insert(e.clone());
        }

        entry.claim.source_count = entry.sources.len().min(u8::MAX as usize) as u8;
        entry.claim.evidence = entry.evidence.iter().cloned().collect();
        entry.claim.confidence = entry.claim.confidence.max(proposed.confidence);
        // Deterministic promotion lives in indago-core.
        entry.claim.status = entry.claim.promoted_status();
        entry.claim.updated = proposed.updated;
        entry.claim.clone()
    }
}

/// Start the claim-engine subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        let mut ledger = ClaimLedger::new();
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::ClaimProposed { claim, .. }) => {
                    let accepted = ledger.observe(claim);
                    info!(
                        subject = %accepted.subject,
                        status = ?accepted.status,
                        sources = accepted.source_count,
                        "claim accepted"
                    );
                    bus.send(IndagoMessage::ClaimAccepted {
                        claim: accepted,
                        envelope: BusEnvelope::fresh(),
                    });
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "claim engine fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use indago_core::ClaimStatus;
    use uuid::Uuid;

    #[test]
    fn two_distinct_sources_corroborate() {
        let mut ledger = ClaimLedger::new();
        let (s, o) = (Uuid::new_v4(), Uuid::new_v4());

        let first = ledger.observe(Claim::assert(s, Predicate::Hosts, o, "indago-collect-dns"));
        assert_eq!(first.source_count, 1);
        assert_eq!(first.status, ClaimStatus::Asserted);

        // Same triple, different source class -> corroborated.
        let second = ledger.observe(Claim::assert(s, Predicate::Hosts, o, "indago-collect-whois"));
        assert_eq!(second.source_count, 2);
        assert_eq!(second.status, ClaimStatus::Corroborated);
        // Canonical identity is preserved across sources.
        assert_eq!(first.id, second.id);
    }

    #[test]
    fn same_source_does_not_inflate_count() {
        let mut ledger = ClaimLedger::new();
        let (s, o) = (Uuid::new_v4(), Uuid::new_v4());
        ledger.observe(Claim::assert(s, Predicate::Hosts, o, "indago-collect-dns"));
        let again = ledger.observe(Claim::assert(s, Predicate::Hosts, o, "indago-collect-dns"));
        assert_eq!(again.source_count, 1);
        assert_eq!(again.status, ClaimStatus::Asserted);
    }
}
