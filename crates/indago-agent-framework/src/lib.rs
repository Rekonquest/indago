//! # Indago Agent Framework
//!
//! Shared plumbing for tool and mode agents. For now that is status reporting:
//! a [`Reporter`] that emits [`IndagoMessage::AgentStatusUpdate`] under a stable
//! agent name, so the UI and audit log can track agent lifecycle uniformly.

pub use indago_protocol::AgentStatus;

use indago_bus::Bus;
use indago_protocol::{BusEnvelope, IndagoMessage};

/// Emits agent status updates under a fixed agent name.
#[derive(Clone)]
pub struct Reporter {
    bus: Bus,
    name: String,
}

impl Reporter {
    pub fn new(bus: Bus, name: impl Into<String>) -> Self {
        Self {
            bus,
            name: name.into(),
        }
    }

    /// Emit a status update with detail text.
    pub fn report(&self, status: AgentStatus, detail: impl Into<String>) {
        self.bus.send(IndagoMessage::AgentStatusUpdate {
            agent: self.name.clone(),
            status,
            detail: detail.into(),
            envelope: BusEnvelope::fresh(),
        });
    }

    pub fn queued(&self, detail: impl Into<String>) {
        self.report(AgentStatus::Queued, detail);
    }

    pub fn running(&self, detail: impl Into<String>) {
        self.report(AgentStatus::Running, detail);
    }

    pub fn completed(&self, detail: impl Into<String>) {
        self.report(AgentStatus::Completed, detail);
    }
}
