//! # Indago Audit
//!
//! A passive watcher that makes the action log **tamper-evident**. It subscribes
//! to the bus and appends every meaningful action to an append-only JSONL log,
//! where each entry is:
//!
//! - **hash-chained** — `hash = SHA-256(seq, ts, kind, summary, prev_hash)`, so
//!   altering or removing any entry breaks every entry after it; and
//! - **signed** — ed25519 over the entry hash, so entries can't be forged
//!   without the signing key.
//!
//! [`verify_log`] re-checks the whole chain and every signature offline. The
//! audit never modifies or deletes; it only appends. Secrets are never logged
//! (credential *names* only).
//!
//! Layout under the data root: `audit/audit.log`, `audit/signing.key` (32-byte
//! seed), `audit/verifying.key` (hex public key for offline verification).

use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;

use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use indago_bus::Bus;
use indago_protocol::IndagoMessage;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast::error::RecvError;
use tracing::{error, info, warn};

const GENESIS: &str = "genesis";

/// One tamper-evident log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts: String,
    pub kind: String,
    pub summary: String,
    pub prev_hash: String,
    pub hash: String,
    pub signature: String,
}

/// The pure hash-chain + signing core (no IO), so the logic is unit-testable.
pub struct AuditChain {
    sk: SigningKey,
    seq: u64,
    prev_hash: String,
}

impl AuditChain {
    pub fn new(sk: SigningKey, seq: u64, prev_hash: String) -> Self {
        Self { sk, seq, prev_hash }
    }

    /// Append an entry, advancing the chain. Pure: returns the entry; the caller
    /// persists it.
    pub fn append(&mut self, ts: String, kind: &str, summary: &str) -> AuditEntry {
        let seq = self.seq;
        let hash = entry_hash(seq, &ts, kind, summary, &self.prev_hash);
        let signature = hex(&self.sk.sign(hash.as_bytes()).to_bytes());
        let entry = AuditEntry {
            seq,
            ts,
            kind: kind.to_string(),
            summary: summary.to_string(),
            prev_hash: std::mem::replace(&mut self.prev_hash, hash.clone()),
            hash,
            signature,
        };
        self.seq += 1;
        entry
    }
}

/// Start the audit subsystem. Synchronously loads/creates the signing key and
/// resumes the chain, then spawns the watcher.
pub fn start(bus: Bus, root: impl AsRef<Path>) -> anyhow::Result<()> {
    let dir = root.as_ref().join("audit");
    fs::create_dir_all(&dir)?;
    let sk = load_or_create_key(&dir)?;
    fs::write(dir.join("verifying.key"), hex(sk.verifying_key().as_bytes()))?;

    let log_path = dir.join("audit.log");
    let (seq, prev_hash) = resume(&log_path);
    let mut chain = AuditChain::new(sk, seq, prev_hash);

    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(msg) => {
                    if let Some((kind, summary)) = summarize(&msg) {
                        let entry = chain.append(Utc::now().to_rfc3339(), kind, &summary);
                        if let Err(e) = append_line(&log_path, &entry) {
                            error!(error = %e, "audit append failed");
                        }
                    }
                }
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "audit fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
    info!("audit: tamper-evident log started");
    Ok(())
}

/// Verify an on-disk audit log: chain continuity, recomputed hashes, and every
/// signature. Returns the number of valid entries, or an error at the first
/// inconsistency.
pub fn verify_log(root: impl AsRef<Path>) -> anyhow::Result<usize> {
    let dir = root.as_ref().join("audit");
    let vk = verifying_key_from_hex(fs::read_to_string(dir.join("verifying.key"))?.trim())?;
    let content = fs::read_to_string(dir.join("audit.log")).unwrap_or_default();

    let mut prev = GENESIS.to_string();
    let mut count: u64 = 0;
    for line in content.lines().filter(|l| !l.trim().is_empty()) {
        let entry: AuditEntry = serde_json::from_str(line)?;
        if entry.seq != count {
            anyhow::bail!("audit: sequence gap at entry {}", entry.seq);
        }
        if entry.prev_hash != prev {
            anyhow::bail!("audit: chain break at seq {}", entry.seq);
        }
        let expected = entry_hash(entry.seq, &entry.ts, &entry.kind, &entry.summary, &entry.prev_hash);
        if expected != entry.hash {
            anyhow::bail!("audit: hash mismatch at seq {} (tampered)", entry.seq);
        }
        let sig = signature_from_hex(&entry.signature)?;
        vk.verify(entry.hash.as_bytes(), &sig)
            .map_err(|_| anyhow::anyhow!("audit: bad signature at seq {}", entry.seq))?;
        prev = entry.hash;
        count += 1;
    }
    Ok(count as usize)
}

// ── auditable-message summarization ─────────────────────────

/// Which messages to record, and how. Returns `None` for noise (raw captures,
/// internal queries) and for secret-bearing messages.
fn summarize(msg: &IndagoMessage) -> Option<(&'static str, String)> {
    use IndagoMessage::*;
    Some(match msg {
        CollectionRequest { capability, target, .. } => {
            ("collection_request", format!("{capability:?} {target}"))
        }
        CollectionApproved { capability, target, .. } => {
            ("collection_approved", format!("{capability:?} {target}"))
        }
        CollectionDenied { reason, .. } => ("collection_denied", reason.clone()),
        GateApprovalRequest { capability, target, .. } => {
            ("approval_request", format!("{capability:?} {target}"))
        }
        GateApprovalResponse { approved, .. } => {
            ("approval_response", format!("approved={approved}"))
        }
        EvidenceStored { evidence_id, source_url, .. } => (
            "evidence_stored",
            format!("{evidence_id} {}", source_url.clone().unwrap_or_default()),
        ),
        ClaimAccepted { claim, .. } => (
            "claim_accepted",
            format!("{:?} conf={} sources={}", claim.status, claim.confidence, claim.source_count),
        ),
        EntityCreated { entity, .. } => {
            ("entity_created", format!("{:?} {}", entity.entity_type, entity.name))
        }
        StartMode { mode, seed, .. } => ("start_mode", format!("{mode:?} {seed}")),
        AgentStatusUpdate { agent, status, detail, .. } => {
            ("agent_status", format!("{agent} {status:?} {detail}"))
        }
        SetCredential { name, .. } => ("credential_set", name.clone()),
        // Not audited: raw CollectionResult, ClaimProposed, StoreQuery/StoreResult,
        // GetCredential/CredentialResult (secret-bearing).
        _ => return None,
    })
}

// ── helpers ─────────────────────────────────────────────────

fn entry_hash(seq: u64, ts: &str, kind: &str, summary: &str, prev_hash: &str) -> String {
    let mut h = Sha256::new();
    h.update(format!("{seq}\n{ts}\n{kind}\n{summary}\n{prev_hash}").as_bytes());
    hex(&h.finalize())
}

fn load_or_create_key(dir: &Path) -> anyhow::Result<SigningKey> {
    let key_path = dir.join("signing.key");
    let seed: [u8; 32] = if key_path.exists() {
        let bytes = fs::read(&key_path)?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("audit: corrupt signing key"))?
    } else {
        let mut s = [0u8; 32];
        getrandom::getrandom(&mut s).map_err(|e| anyhow::anyhow!("audit: getrandom: {e}"))?;
        fs::write(&key_path, s)?;
        s
    };
    Ok(SigningKey::from_bytes(&seed))
}

fn resume(log_path: &Path) -> (u64, String) {
    if let Ok(content) = fs::read_to_string(log_path) {
        if let Some(last) = content.lines().filter(|l| !l.trim().is_empty()).last() {
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(last) {
                return (entry.seq + 1, entry.hash);
            }
        }
    }
    (0, GENESIS.to_string())
}

fn append_line(path: &Path, entry: &AuditEntry) -> anyhow::Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "{}", serde_json::to_string(entry)?)?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn hex_to_vec(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        anyhow::bail!("odd hex length");
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| anyhow::anyhow!("hex: {e}")))
        .collect()
}

fn signature_from_hex(s: &str) -> anyhow::Result<Signature> {
    let arr: [u8; 64] = hex_to_vec(s)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature length"))?;
    Ok(Signature::from_bytes(&arr))
}

fn verifying_key_from_hex(s: &str) -> anyhow::Result<VerifyingKey> {
    let arr: [u8; 32] = hex_to_vec(s)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("verifying key length"))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| anyhow::anyhow!("verifying key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_links_signs_and_detects_tampering() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let mut chain = AuditChain::new(sk, 0, GENESIS.to_string());

        let e0 = chain.append("t0".into(), "evidence_stored", "abc123");
        let e1 = chain.append("t1".into(), "claim_accepted", "Corroborated");

        // Chain links.
        assert_eq!(e0.seq, 0);
        assert_eq!(e0.prev_hash, GENESIS);
        assert_eq!(e1.seq, 1);
        assert_eq!(e1.prev_hash, e0.hash);

        // Hashes recompute and signatures verify.
        for e in [&e0, &e1] {
            assert_eq!(e.hash, entry_hash(e.seq, &e.ts, &e.kind, &e.summary, &e.prev_hash));
            let sig = signature_from_hex(&e.signature).unwrap();
            assert!(vk.verify(e.hash.as_bytes(), &sig).is_ok());
        }

        // Tampering with the summary changes the hash → detectable.
        let tampered = entry_hash(e0.seq, &e0.ts, &e0.kind, "TAMPERED", &e0.prev_hash);
        assert_ne!(tampered, e0.hash);
    }
}
