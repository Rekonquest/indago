//! # Indago Core — domain types and pure logic
//!
//! The atomic units of the investigative model:
//! - [`Entity`]   — a person, company, domain, etc. (the unit of identity)
//! - [`Claim`]    — a structured assertion with provenance (the unit of knowledge)
//! - [`Evidence`] — a frozen, content-addressed artifact (the unit of proof)
//! - [`TimelineEvent`] — a derived chronological marker
//!
//! This crate is **pure**: no IO, no bus, no SQLite. It holds types and the
//! deterministic rules that operate on them (claim promotion, confidence).
//! Persistence lives in `indago-store`; messaging lives in `indago-protocol`.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Identifiers ─────────────────────────────────────────────

/// Identity of an entity. UUID v4 today; may become content-addressed later.
pub type EntityId = Uuid;

/// Identity of a claim.
pub type ClaimId = Uuid;

/// Identity of an evidence artifact: the lowercase-hex SHA-256 of the raw
/// bytes. Evidence is content-addressed, so its id *is* its hash.
pub type EvidenceId = String;

// ── Entity ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityType {
    Person,
    Company,
    Domain,
    IpAddress,
    Email,
    Phone,
    Address,
    Document,
    /// Autonomous System (e.g. "AS13335").
    Asn,
    /// IP network block / CIDR.
    Netblock,
    /// Geographic location (city/region/country).
    Location,
    /// A URL / archived web resource.
    Url,
    /// A username / social handle.
    Username,
    /// A network service / open port.
    Service,
    Other,
}

/// Investigative salience of an entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityFlag {
    /// The subject of the investigation.
    Subject,
    /// A pivotal entity (shared address, key document, etc.).
    Key,
    /// Context only.
    Peripheral,
}

/// The atomic unit of identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entity {
    pub id: EntityId,
    pub entity_type: EntityType,
    pub name: String,
    pub first_seen: DateTime<Utc>,
    /// Type-specific flexible fields (e.g. WHOIS registrar, ASN).
    pub metadata: HashMap<String, serde_json::Value>,
    pub flags: Vec<EntityFlag>,
    pub notes: String,
}

/// Namespace for content-addressed entity ids (UUID v5). Stable forever — do
/// not change, or existing entity identities shift.
const ENTITY_NAMESPACE: Uuid = Uuid::from_u128(0x1dda_9000_4e1d_4b0e_9c3a_05a17e9b0c01);

impl Entity {
    /// Construct a fresh entity with a random id and `first_seen = now`. Use for
    /// genuinely new entities (e.g. user-created in the UI).
    pub fn new(entity_type: EntityType, name: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            entity_type,
            name: name.into(),
            first_seen: Utc::now(),
            metadata: HashMap::new(),
            flags: Vec::new(),
            notes: String::new(),
        }
    }

    /// Construct a **content-addressed** entity: the id is a UUID v5 derived
    /// from `(entity_type, normalized name)`. The same identity from any
    /// collector or run yields the same id, so duplicates unify automatically
    /// and claims referencing it corroborate across sources. Collectors should
    /// use this.
    pub fn canonical(entity_type: EntityType, name: impl Into<String>) -> Self {
        let name = name.into();
        let key = format!("{entity_type:?}:{}", name.trim().to_lowercase());
        Self {
            id: Uuid::new_v5(&ENTITY_NAMESPACE, key.as_bytes()),
            entity_type,
            name,
            first_seen: Utc::now(),
            metadata: HashMap::new(),
            flags: Vec::new(),
            notes: String::new(),
        }
    }
}

// ── Claim ───────────────────────────────────────────────────

/// The relationship asserted by a claim. Extensible: unrecognized
/// predicates ride in [`Predicate::Other`] until promoted to a variant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Predicate {
    IsDirectorOf,
    RegisteredAt,
    SharesAddressWith,
    IsSecretaryOf,
    RegisteredBy,
    PreviouslyEmployedAt,
    LinkedTo,
    Hosts,
    /// A domain resolves to an IP.
    ResolvesTo,
    /// An IP/entity is located in a place.
    LocatedIn,
    /// An IP belongs to an Autonomous System.
    InAsn,
    /// A domain appears in another host's TLS certificate (SAN).
    SanOf,
    /// A URL is an archived snapshot of a domain.
    ArchivedFrom,
    /// An IP exposes a service/port.
    RunsService,
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClaimStatus {
    Asserted,
    Corroborated,
    Disputed,
    Retracted,
}

/// The atomic unit of knowledge: a structured assertion backed by evidence.
/// This is **not** a graph edge — the graph is a projection of accepted claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub id: ClaimId,
    pub subject: EntityId,
    pub predicate: Predicate,
    pub object: EntityId,
    pub status: ClaimStatus,
    /// 0-100.
    pub confidence: u8,
    /// Evidence artifacts backing this claim.
    pub evidence: Vec<EvidenceId>,
    /// Number of independent source classes that back this claim.
    pub source_count: u8,
    /// Which agent or user created this claim.
    pub author: String,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

/// Independent source classes required to auto-promote Asserted -> Corroborated.
/// Deterministic; the rule is pure here and enforced by the gate / claim engine.
pub const CORROBORATION_THRESHOLD: u8 = 2;

impl Claim {
    /// Construct a freshly-asserted claim (confidence/sources default to a
    /// single-source assertion).
    pub fn assert(
        subject: EntityId,
        predicate: Predicate,
        object: EntityId,
        author: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            subject,
            predicate,
            object,
            status: ClaimStatus::Asserted,
            confidence: 50,
            evidence: Vec::new(),
            source_count: 1,
            author: author.into(),
            created: now,
            updated: now,
        }
    }

    /// The status this claim *should* hold given its independent source count.
    /// Pure and deterministic. Disputed/Retracted are terminal and never
    /// auto-promoted.
    pub fn promoted_status(&self) -> ClaimStatus {
        match self.status {
            ClaimStatus::Disputed | ClaimStatus::Retracted => self.status,
            _ if self.source_count >= CORROBORATION_THRESHOLD => ClaimStatus::Corroborated,
            _ => ClaimStatus::Asserted,
        }
    }
}

// ── Evidence ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceType {
    Warc,
    Screenshot,
    JsonResponse,
    Document,
    RawHtml,
    Other,
}

/// The atomic unit of proof: a frozen artifact captured at a point in time.
/// Append-only — never modified, never deleted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Content hash (hex SHA-256) — also the blob's identity.
    pub id: EvidenceId,
    pub title: String,
    pub evidence_type: EvidenceType,
    pub captured_at: DateTime<Utc>,
    pub content_hash: [u8; 32],
    pub size_bytes: u64,
    pub format: String,
    pub source_url: Option<String>,
    pub collector: String,
}

// ── Timeline ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimelineEventType {
    Event,
    Capture,
    Discovery,
}

/// A derived chronological marker, projected from entities and claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub date: DateTime<Utc>,
    pub label: String,
    pub event_type: TimelineEventType,
    pub entity_id: EntityId,
    pub claim_id: Option<ClaimId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_source_claim_stays_asserted() {
        let c = Claim::assert(Uuid::new_v4(), Predicate::Hosts, Uuid::new_v4(), "test");
        assert_eq!(c.source_count, 1);
        assert_eq!(c.promoted_status(), ClaimStatus::Asserted);
    }

    #[test]
    fn two_independent_sources_promote_to_corroborated() {
        let mut c = Claim::assert(Uuid::new_v4(), Predicate::Hosts, Uuid::new_v4(), "test");
        c.source_count = CORROBORATION_THRESHOLD;
        assert_eq!(c.promoted_status(), ClaimStatus::Corroborated);
    }

    #[test]
    fn canonical_entities_are_content_addressed() {
        // Same type + name (case/space-insensitive) → same id.
        let a = Entity::canonical(EntityType::Domain, "Example.com");
        let b = Entity::canonical(EntityType::Domain, "  example.com ");
        assert_eq!(a.id, b.id);
        // Different type → different id.
        let c = Entity::canonical(EntityType::Email, "example.com");
        assert_ne!(a.id, c.id);
        // Fresh entities are not content-addressed.
        assert_ne!(
            Entity::new(EntityType::Domain, "example.com").id,
            Entity::new(EntityType::Domain, "example.com").id
        );
    }

    #[test]
    fn disputed_never_auto_promotes() {
        let mut c = Claim::assert(Uuid::new_v4(), Predicate::Hosts, Uuid::new_v4(), "test");
        c.status = ClaimStatus::Disputed;
        c.source_count = 9;
        assert_eq!(c.promoted_status(), ClaimStatus::Disputed);
    }
}
