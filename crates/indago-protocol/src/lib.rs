//! # Indago Protocol — The Constitution
//!
//! Single source of truth for the bus protocol that connects every Indago
//! subsystem. **Every message that travels on the bus is one variant of
//! [`IndagoMessage`].** Adding a field or a variant is a deliberate amendment.
//! No crate defines message types anywhere else.
//!
//! ## Doc-comment convention
//!
//! Every [`IndagoMessage`] variant carries `/// EMITTED BY:` and
//! `/// CONSUMED BY:` lines so the contract is visible at the definition, not
//! buried in a subsystem.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use indago_core::{Claim, Entity, Evidence, EvidenceId, EvidenceType};

// ── Identifiers ─────────────────────────────────────────────

/// Correlates a collection request with its results and downstream events.
pub type RequestId = Uuid;

/// Identifies the investigation a message belongs to.
pub type CaseId = Uuid;

// ── Bus envelope ────────────────────────────────────────────

/// Correlation metadata carried by every message. Mirrors the Aedes runtime's
/// `BusEnvelope` so the two runtimes share one convention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BusEnvelope {
    pub correlation_id: Uuid,
    pub emitted_at: DateTime<Utc>,
}

impl BusEnvelope {
    /// A fresh envelope with a new correlation id and `emitted_at = now`.
    pub fn fresh() -> Self {
        Self {
            correlation_id: Uuid::new_v4(),
            emitted_at: Utc::now(),
        }
    }

    /// An envelope that continues an existing correlation chain.
    pub fn with_correlation(correlation_id: Uuid) -> Self {
        Self {
            correlation_id,
            emitted_at: Utc::now(),
        }
    }
}

impl Default for BusEnvelope {
    fn default() -> Self {
        Self::fresh()
    }
}

// ── Capabilities ────────────────────────────────────────────

/// The collection capability a request targets. One collector crate services
/// each capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    Dns,
    Whois,
    WebFetch,
    Screenshot,
    CertTransparency,
    UsernameEnum,
    EmailScrape,
    SubdomainEnum,
    BreachCheck,
    /// IP intelligence: geolocation, ASN, ISP, reverse DNS.
    IpIntel,
    /// Reverse-IP: domains co-hosted on the same IP address.
    ReverseIp,
    /// Wayback Machine historical snapshots.
    Wayback,
    /// Shodan host lookup (open ports, services, vulns).
    ShodanHost,
    /// Favicon hash (Shodan-style mmh3) for cross-host pivoting.
    FaviconHash,
    /// urlscan.io search: pages, IPs, and infrastructure for a domain.
    UrlScan,
    /// ASN → announced network prefixes (BGPView).
    AsnPrefixes,
    /// Email reputation + linked platforms (emailrep.io).
    EmailRep,
}

// ── The protocol ────────────────────────────────────────────

/// Every message on the Indago bus. Add variants here only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IndagoMessage {
    /// EMITTED BY: mode/tool agents, the UI, or `indago-main` (manual/smoke).
    /// CONSUMED BY: `indago-gate`.
    /// A request to perform a collection action against a target.
    CollectionRequest {
        request_id: RequestId,
        case_id: CaseId,
        capability: Capability,
        /// The thing to collect against (domain, email, username, URL, …).
        target: String,
        envelope: BusEnvelope,
    },

    /// EMITTED BY: `indago-gate`.
    /// CONSUMED BY: collectors (`indago-collect-*`).
    /// A request that has passed the gate and is cleared to execute. Collectors
    /// act on this, never on the raw [`IndagoMessage::CollectionRequest`] — the
    /// gate is the only path to execution.
    CollectionApproved {
        request_id: RequestId,
        case_id: CaseId,
        capability: Capability,
        target: String,
        envelope: BusEnvelope,
    },

    /// EMITTED BY: `indago-gate`.
    /// CONSUMED BY: the UI, `indago-audit`.
    /// A request the gate refused (out of scope, already-run, denied, …).
    CollectionDenied {
        request_id: RequestId,
        reason: String,
        envelope: BusEnvelope,
    },

    /// EMITTED BY: `indago-gate`.
    /// CONSUMED BY: the UI (human-in-the-loop), or a headless auto-approver.
    /// A live external action awaiting sign-off before it may execute.
    GateApprovalRequest {
        request_id: RequestId,
        case_id: CaseId,
        capability: Capability,
        target: String,
        risk: String,
        envelope: BusEnvelope,
    },

    /// EMITTED BY: the UI / a headless approver.
    /// CONSUMED BY: `indago-gate`.
    /// The decision on a pending [`IndagoMessage::GateApprovalRequest`].
    GateApprovalResponse {
        request_id: RequestId,
        approved: bool,
        envelope: BusEnvelope,
    },

    /// EMITTED BY: collectors (`indago-collect-*`).
    /// CONSUMED BY: `indago-store`.
    /// A completed capture carrying the raw artifact bytes to be frozen.
    /// The store is the sole writer: it hashes `raw`, freezes the blob,
    /// indexes the metadata, and emits [`IndagoMessage::EvidenceStored`].
    CollectionResult {
        request_id: RequestId,
        case_id: CaseId,
        capability: Capability,
        /// The original request target — recorded by the store for dedup.
        target: String,
        title: String,
        evidence_type: EvidenceType,
        format: String,
        source_url: Option<String>,
        collector: String,
        raw: Vec<u8>,
        envelope: BusEnvelope,
    },

    /// EMITTED BY: `indago-store`.
    /// CONSUMED BY: `indago-extractor`, `indago-claim-engine`, the UI.
    /// An artifact has been frozen into the content-addressed store. Carries
    /// enough context for the extractor to fetch and interpret the blob.
    EvidenceStored {
        evidence_id: EvidenceId,
        request_id: RequestId,
        case_id: CaseId,
        evidence_type: EvidenceType,
        source_url: Option<String>,
        envelope: BusEnvelope,
    },

    /// EMITTED BY: collectors, `indago-extractor`.
    /// CONSUMED BY: `indago-gate` / `indago-claim-engine`.
    /// A candidate claim awaiting disposition. Agents propose; gates dispose.
    ClaimProposed { claim: Claim, envelope: BusEnvelope },

    /// EMITTED BY: `indago-claim-engine` / `indago-gate`.
    /// CONSUMED BY: `indago-store`, the UI.
    /// A claim that has been accepted into the case record.
    ClaimAccepted { claim: Claim, envelope: BusEnvelope },

    /// EMITTED BY: collectors, agents, the UI.
    /// CONSUMED BY: `indago-store`, the UI, mode agents (reactive expansion).
    EntityCreated { entity: Entity, envelope: BusEnvelope },

    /// EMITTED BY: the UI / `indago-main`.
    /// CONSUMED BY: `indago-mode-agents`.
    /// Kick off an investigation strategy from a seed.
    StartMode {
        case_id: CaseId,
        mode: ModeKind,
        seed: String,
        envelope: BusEnvelope,
    },

    /// EMITTED BY: tool agents, mode agents.
    /// CONSUMED BY: the UI, `indago-audit`.
    /// Agent lifecycle reporting.
    AgentStatusUpdate {
        agent: String,
        status: AgentStatus,
        detail: String,
        envelope: BusEnvelope,
    },

    /// EMITTED BY: the UI, `indago-main` (env seed).
    /// CONSUMED BY: `indago-credential-store`.
    /// Store an API key / secret, scoped to a case (use the nil case for global).
    SetCredential {
        case_id: CaseId,
        name: String,
        secret: String,
        envelope: BusEnvelope,
    },

    /// EMITTED BY: collectors needing a key (e.g. breach), the gate.
    /// CONSUMED BY: `indago-credential-store`.
    GetCredential {
        request_id: RequestId,
        case_id: CaseId,
        name: String,
        envelope: BusEnvelope,
    },

    /// EMITTED BY: `indago-credential-store`.
    /// CONSUMED BY: the requester (correlate by `request_id`).
    CredentialResult {
        request_id: RequestId,
        name: String,
        secret: Option<String>,
        envelope: BusEnvelope,
    },

    /// EMITTED BY: `indago-gate` (dedup), the UI (read models).
    /// CONSUMED BY: `indago-store`.
    /// A read request against the store; answered with a correlated
    /// [`IndagoMessage::StoreResult`].
    StoreQuery {
        query_id: Uuid,
        query: StoreQueryKind,
        envelope: BusEnvelope,
    },

    /// EMITTED BY: `indago-store`.
    /// CONSUMED BY: the querier (correlate by `query_id`).
    StoreResult {
        query_id: Uuid,
        result: StoreResultData,
        envelope: BusEnvelope,
    },
}

/// What a [`IndagoMessage::StoreQuery`] asks for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StoreQueryKind {
    /// Has `(case, capability, target)` already been collected? Used by the gate
    /// to dedup live collection against the evidence store.
    AlreadyCollected {
        case_id: CaseId,
        capability: Capability,
        target: String,
    },
    /// All frozen evidence (most-recent first). For read models / the UI.
    ListEvidence,
    /// All entities in the index. For read models / reporting.
    ListEntities,
    /// All persisted (accepted) claims. For read models / reporting.
    ListClaims,
    /// The raw bytes of one frozen artifact, by evidence id. Used by the
    /// extractor to work from frozen evidence rather than re-fetching.
    ReadBlob { evidence_id: EvidenceId },
}

/// Lifecycle state of a tool or mode agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    Idle,
    Queued,
    Running,
    Completed,
    Failed,
}

/// An investigation strategy a mode agent can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModeKind {
    /// Seed = domain. Fan out DNS/WHOIS/cert/subdomain, then DNS+WHOIS every
    /// discovered subdomain.
    DomainFootprint,
    /// Seed = company/registrant name (web presence). Currently a domain-shaped
    /// footprint over the seed treated as a domain.
    CorporateStructure,
    /// Seed = username. Enumerate social presence.
    PersonOfInterest,
}

/// The answer to a [`IndagoMessage::StoreQuery`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StoreResultData {
    Bool(bool),
    Evidence(Vec<Evidence>),
    Entities(Vec<Entity>),
    Claims(Vec<Claim>),
    /// Raw artifact bytes (`None` if the blob is missing).
    Blob(Option<Vec<u8>>),
}
