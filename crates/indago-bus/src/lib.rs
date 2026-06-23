//! # Indago Bus
//!
//! Thin wrapper over [`tokio::sync::broadcast`]. Every subsystem gets a clone
//! of [`Bus`] and communicates exclusively through typed
//! [`indago_protocol::IndagoMessage`] variants. No other channel exists.
//!
//! The bus is clone-cheap (the underlying sender is `Arc`-backed) and is meant
//! to be cloned freely — store, collectors, gate, extractor, agents, and the UI
//! each hold their own handle.

use indago_protocol::{BusEnvelope, IndagoMessage};
use tokio::sync::broadcast;
use tracing::{debug, warn};

/// Default channel capacity. 4096 messages comfortably absorbs burst load.
pub const DEFAULT_CAPACITY: usize = 4096;

/// The central message bus.
#[derive(Clone)]
pub struct Bus {
    tx: broadcast::Sender<IndagoMessage>,
}

impl Bus {
    /// Construct a new bus with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Subscribe to all messages. Each subscriber sees every message published
    /// from the moment of subscription onward.
    pub fn subscribe(&self) -> broadcast::Receiver<IndagoMessage> {
        self.tx.subscribe()
    }

    /// Emit a message to every subscriber. Never blocks the sender; if there
    /// are no subscribers the send is a no-op (logged at warn).
    pub fn send(&self, msg: IndagoMessage) {
        match self.tx.send(msg) {
            Ok(n) => debug!(receivers = n, "bus message sent"),
            Err(_) => warn!("bus send failed: no active receivers"),
        }
    }

    /// Current number of active receivers.
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for Bus {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

/// Convenience constructor for a fresh [`BusEnvelope`], readable as a bus helper.
pub fn envelope() -> BusEnvelope {
    BusEnvelope::fresh()
}
