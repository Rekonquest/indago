//! # Indago Report
//!
//! Pure rendering of a case into a legally-defensible Markdown report. Given the
//! case's entities, claims, and evidence, it produces a document where every
//! claim shows its status, confidence, independent-source count, and the content
//! hashes of the evidence backing it — the provenance chain a journalist ships.
//!
//! No IO, no bus: the caller gathers the data (via the store query interface)
//! and hands it here. That keeps this crate trivially unit-testable.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use chrono::Utc;
use indago_core::{Claim, ClaimStatus, Entity, EntityId, Evidence, Predicate};

/// Render a full case report as Markdown.
pub fn render_markdown(entities: &[Entity], claims: &[Claim], evidence: &[Evidence]) -> String {
    let name_of: HashMap<EntityId, &str> =
        entities.iter().map(|e| (e.id, e.name.as_str())).collect();
    let mut out = String::new();

    let _ = writeln!(out, "# Indago Investigation Report");
    let _ = writeln!(out);
    let _ = writeln!(out, "_Generated {} UTC_", Utc::now().format("%Y-%m-%d %H:%M:%S"));
    let _ = writeln!(out);

    // ── Summary ──────────────────────────────────────────────
    let mut status_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for c in claims {
        *status_counts.entry(status_label(c.status)).or_default() += 1;
    }
    let mut type_counts: BTreeMap<String, usize> = BTreeMap::new();
    for e in entities {
        *type_counts.entry(format!("{:?}", e.entity_type)).or_default() += 1;
    }

    let _ = writeln!(out, "## Summary");
    let _ = writeln!(out);
    let _ = writeln!(out, "- **{}** entities", entities.len());
    let _ = writeln!(out, "- **{}** claims ({})", claims.len(), join_counts(&status_counts));
    let _ = writeln!(out, "- **{}** frozen evidence artifacts", evidence.len());
    let _ = writeln!(out);

    // ── Entities ─────────────────────────────────────────────
    let _ = writeln!(out, "## Entities");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Type | Name |");
    let _ = writeln!(out, "|---|---|");
    for e in entities {
        let _ = writeln!(out, "| {:?} | {} |", e.entity_type, md_escape(&e.name));
    }
    let _ = writeln!(out);

    // ── Claims (with provenance) ─────────────────────────────
    let _ = writeln!(out, "## Claims");
    let _ = writeln!(out);
    if claims.is_empty() {
        let _ = writeln!(out, "_No accepted claims._");
    }
    for c in claims {
        let subject = name_of.get(&c.subject).copied().unwrap_or("?");
        let object = name_of.get(&c.object).copied().unwrap_or("?");
        let _ = writeln!(
            out,
            "- **{}** {} **{}** — _{}_, confidence {}%, {} source{}, by `{}`",
            md_escape(subject),
            predicate_label(&c.predicate),
            md_escape(object),
            status_label(c.status),
            c.confidence,
            c.source_count,
            if c.source_count == 1 { "" } else { "s" },
            c.author,
        );
        if !c.evidence.is_empty() {
            let hashes: Vec<String> = c.evidence.iter().map(|h| short_hash(h)).collect();
            let _ = writeln!(out, "  - evidence: {}", hashes.join(", "));
        }
    }
    let _ = writeln!(out);

    // ── Evidence vault ───────────────────────────────────────
    let _ = writeln!(out, "## Evidence Vault");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Content hash | Title | Format | Collector | Captured (UTC) |");
    let _ = writeln!(out, "|---|---|---|---|---|");
    for e in evidence {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {} |",
            short_hash(&e.id),
            md_escape(&e.title),
            e.format,
            e.collector,
            e.captured_at.format("%Y-%m-%d %H:%M:%S"),
        );
    }
    let _ = writeln!(out);

    // ── Provenance ───────────────────────────────────────────
    let _ = writeln!(out, "## Provenance & integrity");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Every artifact above is **content-addressed** (its id is the SHA-256 of the raw bytes) and \
         stored write-once. Every collection action and accepted claim is recorded in an \
         append-only, hash-chained, ed25519-signed **audit log** — altering or removing any entry \
         breaks the chain and is detectable. Claims are corroborated only when independent source \
         classes agree; the gate logged and (where required) approved every live collection action."
    );

    out
}

fn join_counts(counts: &BTreeMap<&str, usize>) -> String {
    if counts.is_empty() {
        return "none".into();
    }
    counts
        .iter()
        .map(|(k, v)| format!("{v} {k}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn status_label(s: ClaimStatus) -> &'static str {
    match s {
        ClaimStatus::Asserted => "asserted",
        ClaimStatus::Corroborated => "corroborated",
        ClaimStatus::Disputed => "disputed",
        ClaimStatus::Retracted => "retracted",
    }
}

fn predicate_label(p: &Predicate) -> String {
    match p {
        Predicate::IsDirectorOf => "is director of".into(),
        Predicate::RegisteredAt => "registered at".into(),
        Predicate::SharesAddressWith => "shares address with".into(),
        Predicate::IsSecretaryOf => "is secretary of".into(),
        Predicate::RegisteredBy => "registered by".into(),
        Predicate::PreviouslyEmployedAt => "previously employed at".into(),
        Predicate::LinkedTo => "linked to".into(),
        Predicate::Hosts => "hosts".into(),
        Predicate::ResolvesTo => "resolves to".into(),
        Predicate::LocatedIn => "located in".into(),
        Predicate::InAsn => "in ASN".into(),
        Predicate::SanOf => "TLS SAN of".into(),
        Predicate::ArchivedFrom => "archived from".into(),
        Predicate::RunsService => "runs service".into(),
        Predicate::Other(s) => s.replace('_', " "),
    }
}

fn short_hash(h: &str) -> String {
    if h.len() > 16 {
        format!("{}…", &h[..16])
    } else {
        h.to_string()
    }
}

/// Escape the characters that would break a Markdown table cell / emphasis.
fn md_escape(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use indago_core::{Entity, EntityType, EvidenceType};
    use indago_core::Evidence as Ev;

    #[test]
    fn renders_sections_and_resolves_names() {
        let ip = Entity::canonical(EntityType::IpAddress, "185.234.10.20");
        let domain = Entity::canonical(EntityType::Domain, "meridian-group.biz");
        let mut claim = Claim::assert(ip.id, Predicate::Hosts, domain.id, "indago-collect-dns");
        claim.status = ClaimStatus::Corroborated;
        claim.confidence = 95;
        claim.source_count = 2;
        claim.evidence = vec!["a3f2c8d19c01e4b7deadbeef".to_string()];

        let evidence = vec![Ev {
            id: "a3f2c8d19c01e4b7deadbeef".to_string(),
            title: "DNS records — meridian-group.biz".to_string(),
            evidence_type: EvidenceType::JsonResponse,
            captured_at: chrono::Utc::now(),
            content_hash: [0u8; 32],
            size_bytes: 100,
            format: "JSON".to_string(),
            source_url: None,
            collector: "indago-collect-dns".to_string(),
        }];

        let md = render_markdown(&[ip, domain], &[claim], &evidence);
        assert!(md.contains("# Indago Investigation Report"));
        assert!(md.contains("## Claims"));
        assert!(md.contains("185.234.10.20"));
        assert!(md.contains("hosts"));
        assert!(md.contains("meridian-group.biz"));
        assert!(md.contains("corroborated"));
        assert!(md.contains("Evidence Vault"));
        assert!(md.contains("Provenance"));
    }
}
