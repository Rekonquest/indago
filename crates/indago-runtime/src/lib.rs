//! # Indago Runtime
//!
//! One place that wires the whole runtime: open the store and start every
//! subsystem on the bus. Both the headless `indago` binary and the Servo UI
//! binary call [`start_subsystems`] so the wiring is never duplicated.
//!
//! Must be called from within a Tokio runtime context (each subsystem's
//! `start` spawns a task). Start order creates no dependencies — subsystems
//! coordinate purely through bus messages.

use std::sync::Arc;

use indago_bus::Bus;
use indago_store::Store;

/// Open the store at `root` and start every subsystem on `bus`.
pub fn start_subsystems(bus: &Bus, root: &str) -> anyhow::Result<()> {
    let store = Arc::new(Store::open(root)?);
    indago_store::start(bus.clone(), store);

    if let Err(e) = indago_audit::start(bus.clone(), root) {
        tracing::error!(error = %e, "audit start failed");
    }
    if let Err(e) = indago_credential_store::start(bus.clone(), root) {
        tracing::error!(error = %e, "credential-store start failed");
    }

    indago_gate::start(bus.clone());
    indago_claim_engine::start(bus.clone());
    indago_extractor::start(bus.clone());
    indago_mode_agents::start(bus.clone());

    indago_collect_dns::start(bus.clone());
    indago_collect_whois::start(bus.clone());
    indago_collect_web::start(bus.clone());
    indago_collect_cert::start(bus.clone());
    indago_collect_username::start(bus.clone());
    indago_collect_subdomain::start(bus.clone());
    indago_collect_email::start(bus.clone());
    indago_collect_breach::start(bus.clone());
    indago_collect_ip::start(bus.clone());
    indago_collect_wayback::start(bus.clone());
    indago_collect_revip::start(bus.clone());
    indago_collect_shodan::start(bus.clone());
    indago_collect_favicon::start(bus.clone());
    indago_collect_urlscan::start(bus.clone());
    indago_collect_asn::start(bus.clone());
    indago_collect_emailrep::start(bus.clone());

    Ok(())
}
