//! # indago-ui binary
//!
//! Launches the full Indago runtime **in one process** and hands the main
//! thread to the Servo renderer. The bus and every subsystem run on the Tokio
//! worker threads; the UI is just another crate on that bus.
//!
//! Build/run the real UI (heavy — pulls Servo):
//!   `cargo run -p indago-ui --features servo-engine`
//! Without the feature it starts the runtime headless and prints guidance.
//!
//! Env: `INDAGO_DATA` (store root), `INDAGO_OLLAMA` / `INDAGO_EXTRACTOR_MODEL`,
//! `INDAGO_GATE`, `RUST_LOG`.

use std::process::ExitCode;

use indago_bus::Bus;
use tokio::runtime::Builder;

fn main() -> ExitCode {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .try_init();

    let rt = match Builder::new_multi_thread().worker_threads(4).enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("indago-ui: tokio runtime build failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let bus = Bus::new(indago_bus::DEFAULT_CAPACITY);
    let root = std::env::var("INDAGO_DATA").unwrap_or_else(|_| "indago-data".to_string());

    // Establish the runtime as current so subsystem `start` calls can spawn.
    // The runtime's worker threads keep them alive while the UI owns the main
    // thread below.
    let _guard = rt.enter();
    if let Err(e) = indago_runtime::start_subsystems(&bus, &root) {
        eprintln!("indago-ui: startup failed: {e}");
        return ExitCode::FAILURE;
    }
    println!("indago-ui: runtime online (data root: {root})");

    // Run the renderer on the main thread. With `servo-engine` this opens the
    // Servo window and blocks until it closes; otherwise it returns immediately.
    indago_ui::run(bus);
    ExitCode::SUCCESS
}
