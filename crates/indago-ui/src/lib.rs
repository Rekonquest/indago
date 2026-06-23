//! # Indago UI
//!
//! The UI is **the Servo engine embedded in-process** as a self-renderer — a
//! crate on the bus, not a webview, not Tauri, not a separate process. The app
//! is authored as static HTML/CSS/JS (`ui/index.html`, no build step) and
//! rendered by Servo; live state flows in as bus messages translated to
//! `window.indago.apply({...})` calls.
//!
//! Servo's dependency tree is enormous, so the renderer is gated behind the
//! `servo-engine` feature (and this crate is its own workspace, isolated from
//! the fast main workspace). Without the feature, [`run`] is a stub that prints
//! how to launch the real UI.
//!
//! The bus→page translation ([`message_to_ui_json`]) is always compiled and
//! unit-tested, independent of Servo.

use indago_core::Predicate;
use indago_protocol::IndagoMessage;

/// The self-contained UI app, embedded at build time. Servo renders this.
pub const INDEX_HTML: &str = include_str!("../ui/index.html");

/// Translate a bus message into the JSON the page's `window.indago.apply`
/// expects, or `None` for messages the UI doesn't surface (raw captures,
/// internal queries, secrets).
pub fn message_to_ui_json(msg: &IndagoMessage) -> Option<String> {
    use serde_json::json;
    let value = match msg {
        IndagoMessage::CollectionRequest { capability, target, .. } => json!({
            "kind": "collection_request",
            "capability": format!("{capability:?}"),
            "target": target,
        }),
        IndagoMessage::CollectionApproved { capability, target, .. } => json!({
            "kind": "collection_approved",
            "capability": format!("{capability:?}"),
            "target": target,
        }),
        IndagoMessage::CollectionDenied { reason, .. } => json!({
            "kind": "collection_denied",
            "reason": reason,
        }),
        IndagoMessage::GateApprovalRequest { request_id, capability, target, risk, .. } => json!({
            "kind": "approval_request",
            "request_id": request_id.to_string(),
            "capability": format!("{capability:?}"),
            "target": target,
            "risk": risk,
        }),
        IndagoMessage::GateApprovalResponse { request_id, .. } => json!({
            "kind": "approval_response",
            "request_id": request_id.to_string(),
        }),
        IndagoMessage::EvidenceStored { evidence_id, evidence_type, source_url, .. } => json!({
            "kind": "evidence_stored",
            "id": evidence_id,
            "format": evidence_format(format!("{evidence_type:?}").as_str()),
            "title": source_url.clone().unwrap_or_else(|| format!("{evidence_type:?}")),
        }),
        IndagoMessage::ClaimAccepted { claim, .. } => json!({
            "kind": "claim_accepted",
            "id": claim.id.to_string(),
            "subject": claim.subject.to_string(),
            "predicate": predicate_label(&claim.predicate),
            "object": claim.object.to_string(),
            "status": format!("{:?}", claim.status),
            "confidence": claim.confidence,
            "sources": claim.source_count,
            "author": claim.author,
        }),
        IndagoMessage::EntityCreated { entity, .. } => json!({
            "kind": "entity_created",
            "id": entity.id.to_string(),
            "name": entity.name,
            "type": format!("{:?}", entity.entity_type),
        }),
        IndagoMessage::StartMode { mode, seed, .. } => json!({
            "kind": "start_mode",
            "mode": format!("{mode:?}"),
            "seed": seed,
        }),
        IndagoMessage::AgentStatusUpdate { agent, status, detail, .. } => json!({
            "kind": "agent_status",
            "name": agent,
            "status": format!("{status:?}"),
            "detail": detail,
        }),
        _ => return None,
    };
    Some(value.to_string())
}

/// Human-readable predicate label (so `Other("subdomain_of")` reads cleanly).
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
        Predicate::Other(s) => s.clone(),
    }
}

/// Map an `EvidenceType` debug name to the short format label the UI shows.
fn evidence_format(debug_name: &str) -> &'static str {
    match debug_name {
        "Warc" => "WARC",
        "JsonResponse" => "JSON",
        "Document" => "TXT",
        "RawHtml" => "HTML",
        "Screenshot" => "PNG",
        _ => "BIN",
    }
}

// ── Stub entrypoint (default build: no Servo) ───────────────────────────────

#[cfg(not(feature = "servo-engine"))]
/// Without the `servo-engine` feature this is a no-op that explains how to run
/// the real UI. Returns immediately so the runtime continues headless.
pub fn run(_bus: indago_bus::Bus) {
    tracing::info!(
        "indago-ui: built without the Servo renderer. Launch the UI with: \
         cargo run -p indago-main --features ui  (first build is heavy — pulls Servo)"
    );
}

// ── Servo renderer (feature `servo-engine`) ─────────────────────────────────

#[cfg(feature = "servo-engine")]
pub use renderer::run;

#[cfg(feature = "servo-engine")]
mod renderer {
    use std::cell::RefCell;
    use std::rc::Rc;

    use anyhow::Context;
    use euclid::Scale;
    use indago_bus::Bus;
    use indago_protocol::IndagoMessage;
    use servo::{
        LoadStatus, RenderingContext, Servo, ServoBuilder, WebView, WebViewBuilder,
        WebViewDelegate, WindowRenderingContext,
    };
    use tokio::sync::broadcast::error::RecvError;
    use tracing::warn;
    use url::Url;
    use winit::application::ApplicationHandler;
    use winit::dpi::PhysicalSize;
    use winit::event::WindowEvent;
    use winit::event_loop::{EventLoop, EventLoopProxy};
    use winit::raw_window_handle::{HasDisplayHandle, HasWindowHandle};
    use winit::window::Window;

    use crate::{message_to_ui_json, INDEX_HTML};

    /// Events delivered to the winit loop: Servo wants to spin, or a bus
    /// message arrived that should be pushed into the page.
    enum UiEvent {
        Wake,
        Bus(Box<IndagoMessage>),
    }

    /// Blocks the calling thread running the Servo window. MUST be called on the
    /// process main thread (winit requirement). The runtime's other subsystems
    /// run on the Tokio worker threads meanwhile.
    pub fn run(bus: Bus) {
        if let Err(e) = run_inner(bus) {
            tracing::error!(error = %e, "indago-ui: Servo renderer exited with error");
        }
    }

    fn run_inner(bus: Bus) -> anyhow::Result<()> {
        // Write the embedded app to disk and load it as a file:// URL.
        let dir = std::env::temp_dir().join("indago-ui");
        std::fs::create_dir_all(&dir)?;
        let html_path = dir.join("index.html");
        std::fs::write(&html_path, INDEX_HTML)?;
        let url = Url::from_file_path(&html_path)
            .map_err(|_| anyhow::anyhow!("could not build file:// URL for the UI"))?;

        let event_loop = EventLoop::<UiEvent>::with_user_event()
            .build()
            .context("creating Servo/winit event loop")?;

        // Forward bus messages into the winit loop from a background thread that
        // drives a blocking receiver. (The Tokio runtime keeps running on its
        // own threads; this is just a relay.)
        spawn_bus_relay(bus.clone(), event_loop.create_proxy());

        let mut app = App::Initial {
            proxy: event_loop.create_proxy(),
            url,
        };
        event_loop
            .run_app(&mut app)
            .context("running Servo window event loop")?;
        Ok(())
    }

    fn spawn_bus_relay(bus: Bus, proxy: EventLoopProxy<UiEvent>) {
        std::thread::spawn(move || {
            let mut rx = bus.subscribe();
            // A tiny current-thread runtime to await bus messages.
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    warn!(error = %e, "indago-ui: bus relay runtime failed");
                    return;
                }
            };
            rt.block_on(async move {
                loop {
                    match rx.recv().await {
                        Ok(msg) => {
                            if proxy.send_event(UiEvent::Bus(Box::new(msg))).is_err() {
                                break; // window closed
                            }
                        }
                        Err(RecvError::Lagged(_)) => continue,
                        Err(RecvError::Closed) => break,
                    }
                }
            });
        });
    }

    struct AppState {
        window: Window,
        servo: Servo,
        rendering_context: Rc<WindowRenderingContext>,
        webview: WebView,
    }

    impl WebViewDelegate for AppState {
        fn notify_new_frame_ready(&self, _webview: WebView) {
            self.window.request_redraw();
        }
        fn notify_load_status_changed(&self, webview: WebView, status: LoadStatus) {
            if matches!(status, LoadStatus::Complete) {
                // Clear the browser-preview demo seed; live bus events populate it.
                webview.evaluate_javascript("window.indago && window.indago.reset()", |_| {});
                self.window.request_redraw();
            }
        }
    }

    enum App {
        Initial {
            proxy: EventLoopProxy<UiEvent>,
            url: Url,
        },
        Running(Rc<AppState>),
    }

    impl ApplicationHandler<UiEvent> for App {
        fn resumed(&mut self, event_loop: &winit::event_loop::ActiveEventLoop) {
            let App::Initial { proxy, url } = self else { return };

            let display_handle = event_loop.display_handle().expect("display handle");
            let window = event_loop
                .create_window(
                    Window::default_attributes()
                        .with_title("Indago")
                        .with_inner_size(PhysicalSize::new(1280, 820)),
                )
                .expect("create Indago window");
            let window_handle = window.window_handle().expect("window handle");

            let rendering_context = Rc::new(
                WindowRenderingContext::new(display_handle, window_handle, window.inner_size())
                    .expect("Servo WindowRenderingContext"),
            );
            let _ = rendering_context.make_current();

            let servo = ServoBuilder::default()
                .event_loop_waker(Box::new(Waker(proxy.clone())))
                .build();
            servo.setup_logging();

            let state = Rc::new_cyclic(|_weak| {
                let webview = WebViewBuilder::new(&servo, rendering_context.clone())
                    .url(url.clone())
                    .hidpi_scale_factor(Scale::new(window.scale_factor() as f32))
                    .build();
                AppState {
                    window,
                    servo,
                    rendering_context,
                    webview,
                }
            });
            state
                .webview
                .set_delegate(state.clone() as Rc<dyn WebViewDelegate>);
            state.window.request_redraw();
            *self = App::Running(state);
        }

        fn user_event(&mut self, _el: &winit::event_loop::ActiveEventLoop, event: UiEvent) {
            let App::Running(state) = self else { return };
            match event {
                UiEvent::Wake => state.servo.spin_event_loop(),
                UiEvent::Bus(msg) => {
                    if let Some(json) = message_to_ui_json(&msg) {
                        let script = format!("window.indago && window.indago.apply({json})");
                        state.webview.evaluate_javascript(script, |_| {});
                    }
                    state.servo.spin_event_loop();
                }
            }
        }

        fn window_event(
            &mut self,
            event_loop: &winit::event_loop::ActiveEventLoop,
            _id: winit::window::WindowId,
            event: WindowEvent,
        ) {
            let App::Running(state) = self else { return };
            state.servo.spin_event_loop();
            match event {
                WindowEvent::CloseRequested => event_loop.exit(),
                WindowEvent::RedrawRequested => {
                    state.webview.paint();
                    state.rendering_context.present();
                }
                WindowEvent::Resized(size) => {
                    state.webview.resize(size);
                    state.window.request_redraw();
                }
                _ => {}
            }
        }
    }

    #[derive(Clone)]
    struct Waker(EventLoopProxy<UiEvent>);

    impl embedder_traits::EventLoopWaker for Waker {
        fn clone_box(&self) -> Box<dyn embedder_traits::EventLoopWaker> {
            Box::new(self.clone())
        }
        fn wake(&self) {
            let _ = self.0.send_event(UiEvent::Wake);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indago_core::{Claim, Entity, EntityType, EvidenceType};
    use indago_protocol::BusEnvelope;
    use uuid::Uuid;

    #[test]
    fn claim_accepted_maps_to_ui_json_with_label() {
        let mut claim = Claim::assert(Uuid::new_v4(), Predicate::Other("subdomain_of".into()), Uuid::new_v4(), "indago-collect-cert");
        claim.confidence = 80;
        let json = message_to_ui_json(&IndagoMessage::ClaimAccepted {
            claim,
            envelope: BusEnvelope::fresh(),
        })
        .unwrap();
        assert!(json.contains("\"kind\":\"claim_accepted\""));
        assert!(json.contains("\"predicate\":\"subdomain_of\""));
        assert!(json.contains("\"confidence\":80"));
    }

    #[test]
    fn evidence_stored_maps_format() {
        let json = message_to_ui_json(&IndagoMessage::EvidenceStored {
            evidence_id: "abc".into(),
            request_id: Uuid::new_v4(),
            case_id: Uuid::new_v4(),
            evidence_type: EvidenceType::Warc,
            source_url: Some("https://example.com".into()),
            envelope: BusEnvelope::fresh(),
        })
        .unwrap();
        assert!(json.contains("\"format\":\"WARC\""));
        assert!(json.contains("https://example.com"));
    }

    #[test]
    fn entity_created_carries_id_name_type() {
        let json = message_to_ui_json(&IndagoMessage::EntityCreated {
            entity: Entity::canonical(EntityType::Domain, "example.com"),
            envelope: BusEnvelope::fresh(),
        })
        .unwrap();
        assert!(json.contains("\"kind\":\"entity_created\""));
        assert!(json.contains("\"type\":\"Domain\""));
        assert!(json.contains("example.com"));
    }

    #[test]
    fn internal_messages_are_not_surfaced() {
        assert!(message_to_ui_json(&IndagoMessage::CredentialResult {
            request_id: Uuid::new_v4(),
            name: "hibp".into(),
            secret: Some("super-secret".into()),
            envelope: BusEnvelope::fresh(),
        })
        .is_none());
    }
}
