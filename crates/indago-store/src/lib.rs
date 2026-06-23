//! # Indago Store
//!
//! Two storage layers behind one message-driven subsystem:
//!
//! 1. **Content-addressed blob store** — raw artifacts written **write-once**
//!    as `{sha256_hex}.{ext}` in a flat directory. Never modified, never
//!    deleted (append-only evidence).
//! 2. **SQLite index** — metadata for evidence, entities, claims, and timeline
//!    events. Migrations run forward via `PRAGMA user_version`.
//!
//! The store is the **sole writer** of persistence. Collectors emit
//! [`IndagoMessage::CollectionResult`] carrying raw bytes; the store hashes,
//! freezes, indexes, and emits [`IndagoMessage::EvidenceStored`]. No other
//! crate opens the database or writes blobs.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use indago_bus::Bus;
use indago_core::{
    Claim, ClaimStatus, Entity, EntityType, Evidence, EvidenceId, EvidenceType, Predicate,
};
use indago_protocol::{BusEnvelope, IndagoMessage, StoreQueryKind, StoreResultData};
use parking_lot::Mutex;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use tokio::sync::broadcast::error::RecvError;
use tracing::{error, info, warn};

/// Forward-only schema migrations. Index = applied `user_version`.
const MIGRATIONS: &[&str] = &[SCHEMA_V1, SCHEMA_V2];

/// v2: a collection index so the gate can dedup `(case, capability, target)`
/// against work already done.
const SCHEMA_V2: &str = "
CREATE TABLE collections (
    case_id      TEXT NOT NULL,
    capability   TEXT NOT NULL,
    target       TEXT NOT NULL,
    evidence_id  TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    PRIMARY KEY (case_id, capability, target)
);
";

const SCHEMA_V1: &str = "
CREATE TABLE evidence (
    id            TEXT PRIMARY KEY,
    title         TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    captured_at   TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    format        TEXT NOT NULL,
    source_url    TEXT,
    collector     TEXT NOT NULL,
    blob_file     TEXT NOT NULL
);
CREATE TABLE entities (
    id          TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    name        TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    metadata    TEXT NOT NULL,
    flags       TEXT NOT NULL,
    notes       TEXT NOT NULL
);
CREATE TABLE claims (
    id           TEXT PRIMARY KEY,
    subject      TEXT NOT NULL,
    predicate    TEXT NOT NULL,
    object       TEXT NOT NULL,
    status       TEXT NOT NULL,
    confidence   INTEGER NOT NULL,
    source_count INTEGER NOT NULL,
    author       TEXT NOT NULL,
    created      TEXT NOT NULL,
    updated      TEXT NOT NULL
);
CREATE TABLE claim_evidence (
    claim_id    TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    PRIMARY KEY (claim_id, evidence_id)
);
CREATE TABLE timeline_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    date       TEXT NOT NULL,
    label      TEXT NOT NULL,
    event_type TEXT NOT NULL,
    entity_id  TEXT NOT NULL,
    claim_id   TEXT
);
";

/// The persistence layer: a blob directory plus a SQLite index connection.
pub struct Store {
    blobs: PathBuf,
    conn: Mutex<Connection>,
}

impl Store {
    /// Open (or create) a store rooted at `root`, applying any pending
    /// migrations. Creates `root/blobs/` and `root/index.sqlite`.
    pub fn open(root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let root = root.as_ref();
        let blobs = root.join("blobs");
        fs::create_dir_all(&blobs)?;
        let mut conn = Connection::open(root.join("index.sqlite"))?;
        run_migrations(&mut conn)?;
        Ok(Self {
            blobs,
            conn: Mutex::new(conn),
        })
    }

    /// Freeze raw bytes into the content-addressed store and index the
    /// metadata. The blob is written write-once; re-freezing identical bytes is
    /// idempotent and returns the same [`EvidenceId`].
    pub fn freeze(
        &self,
        raw: &[u8],
        title: impl Into<String>,
        evidence_type: EvidenceType,
        format: impl Into<String>,
        source_url: Option<String>,
        collector: impl Into<String>,
    ) -> anyhow::Result<Evidence> {
        let format = format.into();

        // Content address: SHA-256 of the raw artifact.
        let mut hasher = Sha256::new();
        hasher.update(raw);
        let digest = hasher.finalize();
        let mut content_hash = [0u8; 32];
        content_hash.copy_from_slice(&digest);
        let hex = hex_encode(&content_hash);

        // Write-once blob: `{hash}.{ext}`, written atomically via temp+rename.
        let blob_file = format!("{hex}.{}", ext_for(&format));
        let path = self.blobs.join(&blob_file);
        if !path.exists() {
            let tmp = self.blobs.join(format!("{blob_file}.tmp"));
            fs::write(&tmp, raw)?;
            fs::rename(&tmp, &path)?;
        }

        let evidence = Evidence {
            id: hex,
            title: title.into(),
            evidence_type,
            captured_at: Utc::now(),
            content_hash,
            size_bytes: raw.len() as u64,
            format,
            source_url,
            collector: collector.into(),
        };

        // Index (idempotent: same id replaces the row but blob is unchanged).
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO evidence \
             (id, title, evidence_type, captured_at, size_bytes, format, source_url, collector, blob_file) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                evidence.id,
                evidence.title,
                format!("{:?}", evidence.evidence_type),
                evidence.captured_at.to_rfc3339(),
                evidence.size_bytes as i64,
                evidence.format,
                evidence.source_url,
                evidence.collector,
                blob_file,
            ],
        )?;
        Ok(evidence)
    }

    /// Read a frozen blob back by its evidence id (content hash).
    pub fn read_blob(&self, id: &EvidenceId) -> anyhow::Result<Vec<u8>> {
        let blob_file: String = {
            let conn = self.conn.lock();
            conn.query_row(
                "SELECT blob_file FROM evidence WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )?
        };
        Ok(fs::read(self.blobs.join(blob_file))?)
    }

    /// Persist an entity (upsert by id).
    pub fn put_entity(&self, e: &Entity) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO entities \
             (id, entity_type, name, first_seen, metadata, flags, notes) \
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                e.id.to_string(),
                format!("{:?}", e.entity_type),
                e.name,
                e.first_seen.to_rfc3339(),
                serde_json::to_string(&e.metadata)?,
                serde_json::to_string(&e.flags)?,
                e.notes,
            ],
        )?;
        Ok(())
    }

    /// Persist a claim and its evidence links (upsert by id).
    pub fn put_claim(&self, c: &Claim) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO claims \
             (id, subject, predicate, object, status, confidence, source_count, author, created, updated) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                c.id.to_string(),
                c.subject.to_string(),
                serde_json::to_string(&c.predicate)?,
                c.object.to_string(),
                format!("{:?}", c.status),
                c.confidence,
                c.source_count,
                c.author,
                c.created.to_rfc3339(),
                c.updated.to_rfc3339(),
            ],
        )?;
        for ev in &c.evidence {
            conn.execute(
                "INSERT OR IGNORE INTO claim_evidence (claim_id, evidence_id) VALUES (?1,?2)",
                params![c.id.to_string(), ev],
            )?;
        }
        Ok(())
    }

    /// Record that `(case, capability, target)` was collected, pointing at the
    /// frozen evidence. Lets the gate dedup repeat collection.
    pub fn record_collection(
        &self,
        case_id: &str,
        capability: &str,
        target: &str,
        evidence_id: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO collections \
             (case_id, capability, target, evidence_id, collected_at) VALUES (?1,?2,?3,?4,?5)",
            params![case_id, capability, target, evidence_id, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Whether `(case, capability, target)` has already been collected.
    pub fn already_collected(&self, case_id: &str, capability: &str, target: &str) -> bool {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT 1 FROM collections WHERE case_id=?1 AND capability=?2 AND target=?3 LIMIT 1",
            params![case_id, capability, target],
            |_| Ok(()),
        )
        .is_ok()
    }

    /// All frozen evidence, most-recent first. Reconstructs [`Evidence`] from the
    /// index (the content hash is recovered from the hex id).
    pub fn list_evidence(&self) -> anyhow::Result<Vec<Evidence>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, title, evidence_type, captured_at, size_bytes, format, source_url, collector \
             FROM evidence ORDER BY captured_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Evidence {
                id: row.get::<_, String>(0)?,
                title: row.get(1)?,
                evidence_type: parse_evidence_type(&row.get::<_, String>(2)?),
                captured_at: parse_rfc3339(&row.get::<_, String>(3)?),
                content_hash: hex_decode(&row.get::<_, String>(0)?),
                size_bytes: row.get::<_, i64>(4)? as u64,
                format: row.get(5)?,
                source_url: row.get(6)?,
                collector: row.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// All entities in the index (alphabetical by name).
    pub fn list_entities(&self) -> anyhow::Result<Vec<Entity>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, entity_type, name, first_seen, metadata, flags, notes \
             FROM entities ORDER BY name",
        )?;
        let rows: Vec<(String, String, String, String, String, String, String)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(rows
            .into_iter()
            .map(|(id, etype, name, first_seen, metadata, flags, notes)| Entity {
                id: parse_uuid(&id),
                entity_type: parse_entity_type(&etype),
                name,
                first_seen: parse_rfc3339(&first_seen),
                metadata: serde_json::from_str(&metadata).unwrap_or_default(),
                flags: serde_json::from_str(&flags).unwrap_or_default(),
                notes,
            })
            .collect())
    }

    /// All persisted (accepted) claims, with their evidence links.
    pub fn list_claims(&self) -> anyhow::Result<Vec<Claim>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, subject, predicate, object, status, confidence, source_count, author, created, updated \
             FROM claims ORDER BY created",
        )?;
        type Row = (String, String, String, String, String, i64, i64, String, String, String);
        let rows: Vec<Row> = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut claims = Vec::with_capacity(rows.len());
        for (id, subject, predicate, object, status, confidence, source_count, author, created, updated) in rows {
            let evidence: Vec<EvidenceId> = {
                let mut ev =
                    conn.prepare("SELECT evidence_id FROM claim_evidence WHERE claim_id = ?1")?;
                let links = ev
                    .query_map(params![id], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                links
            };
            claims.push(Claim {
                id: parse_uuid(&id),
                subject: parse_uuid(&subject),
                predicate: serde_json::from_str(&predicate)
                    .unwrap_or_else(|_| Predicate::Other(predicate.clone())),
                object: parse_uuid(&object),
                status: parse_claim_status(&status),
                confidence: confidence as u8,
                evidence,
                source_count: source_count as u8,
                author,
                created: parse_rfc3339(&created),
                updated: parse_rfc3339(&updated),
            });
        }
        Ok(claims)
    }
}

/// Start the store subsystem: subscribe to the bus, freeze captures, persist
/// entities and accepted claims. Spawns a long-lived task.
pub fn start(bus: Bus, store: std::sync::Arc<Store>) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::CollectionResult {
                    request_id,
                    case_id,
                    capability,
                    target,
                    title,
                    evidence_type,
                    format,
                    source_url,
                    collector,
                    raw,
                    ..
                }) => match store.freeze(&raw, title, evidence_type, format, source_url, collector) {
                    Ok(ev) => {
                        if let Err(e) = store.record_collection(
                            &case_id.to_string(),
                            &format!("{capability:?}"),
                            &target,
                            &ev.id,
                        ) {
                            error!(error = %e, "record_collection failed");
                        }
                        info!(evidence_id = %ev.id, size = ev.size_bytes, "evidence frozen");
                        bus.send(IndagoMessage::EvidenceStored {
                            evidence_id: ev.id,
                            request_id,
                            case_id,
                            evidence_type: ev.evidence_type,
                            source_url: ev.source_url.clone(),
                            envelope: BusEnvelope::fresh(),
                        });
                    }
                    Err(e) => error!(error = %e, "freeze failed"),
                },
                Ok(IndagoMessage::StoreQuery { query_id, query, .. }) => {
                    let result = match query {
                        StoreQueryKind::AlreadyCollected {
                            case_id,
                            capability,
                            target,
                        } => StoreResultData::Bool(store.already_collected(
                            &case_id.to_string(),
                            &format!("{capability:?}"),
                            &target,
                        )),
                        StoreQueryKind::ListEvidence => {
                            StoreResultData::Evidence(store.list_evidence().unwrap_or_default())
                        }
                        StoreQueryKind::ListEntities => {
                            StoreResultData::Entities(store.list_entities().unwrap_or_default())
                        }
                        StoreQueryKind::ListClaims => {
                            StoreResultData::Claims(store.list_claims().unwrap_or_default())
                        }
                        StoreQueryKind::ReadBlob { evidence_id } => {
                            StoreResultData::Blob(store.read_blob(&evidence_id).ok())
                        }
                    };
                    bus.send(IndagoMessage::StoreResult {
                        query_id,
                        result,
                        envelope: BusEnvelope::fresh(),
                    });
                }
                Ok(IndagoMessage::EntityCreated { entity, .. }) => {
                    if let Err(e) = store.put_entity(&entity) {
                        error!(error = %e, "put_entity failed");
                    }
                }
                Ok(IndagoMessage::ClaimAccepted { claim, .. }) => {
                    if let Err(e) = store.put_claim(&claim) {
                        error!(error = %e, "put_claim failed");
                    }
                }
                Ok(_) => { /* not ours */ }
                Err(RecvError::Lagged(n)) => {
                    warn!(skipped = n, "store fell behind; dropped messages");
                }
                Err(RecvError::Closed) => break,
            }
        }
    });
}

// ── helpers ─────────────────────────────────────────────────

fn run_migrations(conn: &mut Connection) -> anyhow::Result<()> {
    let applied: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(applied as usize) {
        conn.execute_batch(sql)?;
        // user_version takes a literal, not a bound parameter.
        conn.execute_batch(&format!("PRAGMA user_version = {}", i + 1))?;
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Decode a 64-char hex SHA-256 back into bytes. Best-effort: malformed input
/// yields zeros (the canonical id remains the source of truth).
fn hex_decode(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let Some(pair) = bytes.get(i * 2..i * 2 + 2) else {
            break;
        };
        if let Ok(s) = std::str::from_utf8(pair) {
            if let Ok(b) = u8::from_str_radix(s, 16) {
                *slot = b;
            }
        }
    }
    out
}

fn parse_rfc3339(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn parse_uuid(s: &str) -> Uuid {
    Uuid::parse_str(s).unwrap_or(Uuid::nil())
}

/// Inverse of the `{:?}` rendering used when indexing entities.
fn parse_entity_type(s: &str) -> EntityType {
    match s {
        "Person" => EntityType::Person,
        "Company" => EntityType::Company,
        "Domain" => EntityType::Domain,
        "IpAddress" => EntityType::IpAddress,
        "Email" => EntityType::Email,
        "Phone" => EntityType::Phone,
        "Address" => EntityType::Address,
        "Document" => EntityType::Document,
        "Asn" => EntityType::Asn,
        "Netblock" => EntityType::Netblock,
        "Location" => EntityType::Location,
        "Url" => EntityType::Url,
        "Username" => EntityType::Username,
        "Service" => EntityType::Service,
        _ => EntityType::Other,
    }
}

fn parse_claim_status(s: &str) -> ClaimStatus {
    match s {
        "Corroborated" => ClaimStatus::Corroborated,
        "Disputed" => ClaimStatus::Disputed,
        "Retracted" => ClaimStatus::Retracted,
        _ => ClaimStatus::Asserted,
    }
}

/// Inverse of the `{:?}` rendering used when indexing evidence.
fn parse_evidence_type(s: &str) -> EvidenceType {
    match s {
        "Warc" => EvidenceType::Warc,
        "Screenshot" => EvidenceType::Screenshot,
        "JsonResponse" => EvidenceType::JsonResponse,
        "Document" => EvidenceType::Document,
        "RawHtml" => EvidenceType::RawHtml,
        _ => EvidenceType::Other,
    }
}

/// Map a format label (e.g. "WARC", "PNG", "JSON") to a lowercase file
/// extension, falling back to "bin" for anything unrecognized.
fn ext_for(format: &str) -> String {
    let cleaned: String = format
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if cleaned.is_empty() {
        "bin".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!("indago-store-test-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn freeze_then_read_roundtrips_by_hash() {
        let root = temp_root();
        let store = Store::open(&root).unwrap();

        let raw = b"hello indago evidence";
        let ev = store
            .freeze(
                raw,
                "smoke artifact",
                EvidenceType::RawHtml,
                "HTML",
                Some("https://example.com/".into()),
                "test",
            )
            .unwrap();

        // id is a 64-char hex SHA-256.
        assert_eq!(ev.id.len(), 64);
        assert_eq!(ev.size_bytes, raw.len() as u64);

        // Blob is on disk and reads back byte-identical.
        let back = store.read_blob(&ev.id).unwrap();
        assert_eq!(back, raw);

        // Re-freezing identical bytes is idempotent (same content address).
        let ev2 = store
            .freeze(raw, "again", EvidenceType::RawHtml, "HTML", None, "test")
            .unwrap();
        assert_eq!(ev.id, ev2.id);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn collection_dedup_index_roundtrips() {
        let root = temp_root();
        let store = Store::open(&root).unwrap();

        assert!(!store.already_collected("case1", "Dns", "example.com"));
        store
            .record_collection("case1", "Dns", "example.com", "abc123")
            .unwrap();
        assert!(store.already_collected("case1", "Dns", "example.com"));
        // Scoped by case and capability and target.
        assert!(!store.already_collected("case2", "Dns", "example.com"));
        assert!(!store.already_collected("case1", "Whois", "example.com"));
        assert!(!store.already_collected("case1", "Dns", "other.com"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn list_evidence_returns_frozen_items() {
        let root = temp_root();
        let store = Store::open(&root).unwrap();
        let ev = store
            .freeze(b"abc", "t", EvidenceType::JsonResponse, "JSON", None, "test")
            .unwrap();
        let listed = store.list_evidence().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, ev.id);
        assert_eq!(listed[0].evidence_type, EvidenceType::JsonResponse);
        assert_eq!(listed[0].content_hash, ev.content_hash);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn open_is_idempotent_across_reopen() {
        let root = temp_root();
        {
            let store = Store::open(&root).unwrap();
            store
                .freeze(b"x", "t", EvidenceType::Other, "BIN", None, "test")
                .unwrap();
        }
        // Reopening runs migrations again as a no-op and preserves data.
        let store = Store::open(&root).unwrap();
        let raw = b"x";
        let mut hasher = Sha256::new();
        hasher.update(raw);
        let id = hex_encode(&hasher.finalize());
        assert_eq!(store.read_blob(&id).unwrap(), raw);
        let _ = fs::remove_dir_all(&root);
    }
}
