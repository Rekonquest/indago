//! # Indago Mode Agents
//!
//! Investigation strategies — the orchestration layer of the spiderweb bus. A
//! mode agent emits a *sequence* of [`IndagoMessage::CollectionRequest`] and
//! **reacts** to what surfaces, chaining the dumb collector primitives into a
//! workflow. It only proposes collection; the gate disposes (and dedups), so a
//! mode agent cannot loop or over-collect.
//!
//! ## Strategies
//!
//! - **DomainFootprint** / **CorporateStructure** (seed = domain): fan out
//!   DNS + WHOIS + cert + subdomain + Wayback; then DNS + WHOIS discovered
//!   subdomains and IP-intel + reverse-IP discovered IPs.
//! - **PersonOfInterest** (seed = username or email): enumerate social presence;
//!   for an email seed also pull reputation + breaches. Reactively enrich
//!   discovered emails (reputation + breach) and capture discovered profile URLs.
//!
//! Reactive expansion keys off discovered [`IndagoMessage::EntityCreated`]; the
//! investigation's mode + the entity's type decide the next transform. Every
//! step is budgeted and deduped (and re-deduped by the gate), so it terminates.

use std::collections::HashSet;

use indago_agent_framework::Reporter;
use indago_bus::Bus;
use indago_core::{Entity, EntityType};
use indago_protocol::{BusEnvelope, Capability, CaseId, IndagoMessage, ModeKind};
use tokio::sync::broadcast::error::RecvError;
use tracing::warn;
use uuid::Uuid;

/// Follow-up transform budget per investigation (bounds reactive expansion).
const BUDGET: usize = 30;

/// A live investigation tracking what it has already expanded.
struct Investigation {
    mode: ModeKind,
    case_id: CaseId,
    seed: String,
    expanded: HashSet<String>,
    budget: usize,
    reporter: Reporter,
}

/// Start the mode-agents subsystem.
pub fn start(bus: Bus) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        let mut investigations: Vec<Investigation> = Vec::new();
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::StartMode { case_id, mode, seed, .. }) => {
                    handle_start(&bus, &mut investigations, case_id, mode, seed)
                }
                Ok(IndagoMessage::EntityCreated { entity, .. }) => {
                    expand(&bus, &mut investigations, &entity)
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "mode agents fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
}

fn handle_start(
    bus: &Bus,
    investigations: &mut Vec<Investigation>,
    case_id: CaseId,
    mode: ModeKind,
    seed: String,
) {
    let seed = seed.trim().to_lowercase();
    if seed.is_empty() {
        return;
    }
    let reporter = Reporter::new(bus.clone(), format!("mode:{mode:?}"));
    let mut expanded = HashSet::new();
    expanded.insert(seed.clone());

    match mode {
        ModeKind::DomainFootprint | ModeKind::CorporateStructure => {
            reporter.running(format!("seeding footprint for {seed}"));
            for capability in [
                Capability::Dns,
                Capability::Whois,
                Capability::CertTransparency,
                Capability::SubdomainEnum,
                Capability::Wayback,
            ] {
                request(bus, case_id, capability, &seed);
            }
        }
        ModeKind::PersonOfInterest => {
            if let Some((local, _)) = seed.split_once('@') {
                reporter.running(format!("profiling email {seed}"));
                request(bus, case_id, Capability::EmailRep, &seed);
                request(bus, case_id, Capability::BreachCheck, &seed);
                request(bus, case_id, Capability::UsernameEnum, local);
            } else {
                reporter.running(format!("profiling username {seed}"));
                request(bus, case_id, Capability::UsernameEnum, &seed);
            }
        }
    }

    investigations.push(Investigation {
        mode,
        case_id,
        seed,
        expanded,
        budget: BUDGET,
        reporter,
    });
}

/// React to a discovered entity per each active investigation's strategy.
fn expand(bus: &Bus, investigations: &mut Vec<Investigation>, entity: &Entity) {
    let name = entity.name.trim().to_lowercase();
    for inv in investigations.iter_mut() {
        if inv.budget == 0 || inv.expanded.contains(&name) {
            continue;
        }
        let next = next_transforms(inv, entity, &name);
        if next.is_empty() {
            continue;
        }
        inv.expanded.insert(name.clone());
        inv.budget = inv.budget.saturating_sub(next.len());
        inv.reporter.running(reaction_label(entity.entity_type, &name));
        for capability in next {
            request(bus, inv.case_id, capability, &name);
        }
    }
}

/// The transforms to run for `(investigation mode, discovered entity type)`.
fn next_transforms(inv: &Investigation, entity: &Entity, name: &str) -> Vec<Capability> {
    use Capability::*;
    use EntityType::*;
    use ModeKind::*;
    match (inv.mode, entity.entity_type) {
        (DomainFootprint | CorporateStructure, Domain) => {
            // Only expand sub-names of the seed (its own subdomains).
            if name != inv.seed && name.ends_with(&format!(".{}", inv.seed)) {
                vec![Dns, Whois]
            } else {
                vec![]
            }
        }
        (DomainFootprint | CorporateStructure, IpAddress) => vec![IpIntel, ReverseIp],
        (PersonOfInterest, Email) => vec![EmailRep, BreachCheck],
        (PersonOfInterest, EntityType::Url) => vec![WebFetch],
        _ => vec![],
    }
}

fn reaction_label(entity_type: EntityType, name: &str) -> String {
    match entity_type {
        EntityType::Domain => format!("expanding subdomain {name}"),
        EntityType::IpAddress => format!("enriching IP {name}"),
        EntityType::Email => format!("enriching email {name}"),
        EntityType::Url => format!("capturing profile {name}"),
        _ => format!("expanding {name}"),
    }
}

fn request(bus: &Bus, case_id: CaseId, capability: Capability, target: &str) {
    bus.send(IndagoMessage::CollectionRequest {
        request_id: Uuid::new_v4(),
        case_id,
        capability,
        target: target.to_string(),
        envelope: BusEnvelope::fresh(),
    });
}
