//! cdylib sync bridge — adapts the async [`SoapBackendPlugin`]
//! ([`mcpg_plugin_protocol::BackendPlugin`]) onto the sync FFI trait the
//! cdylib vtable expects ([`SyncBackendPlugin`]).
//!
//! Structure mirrors the http / grpc / graphql bridges: a private
//! multi-thread runtime + `block_on` for the async methods, and the
//! make-time [`HostHandle`] wrapped as an `Arc<dyn BackendHost>` (via
//! [`HostHandleBackendHost`]) for `register_profile` while also installed
//! on the inner plugin for per-call observability.
//!
//! Unlike the http / LLM bridges, SOAP is request/reply — it does NOT
//! override `execute_streaming`, so it inherits the SDK default (the
//! buffered `execute` result emitted as a single `BackendChunk::Done`)
//! and carries none of the stream-cancel machinery.

use std::sync::Arc;

use mcpg_plugin_protocol::{
    BackendError, BackendPlugin, BackendRequest, BackendResponse, PluginManifest,
};
use mcpg_plugin_sdk::ffi::SyncBackendPlugin;
use mcpg_plugin_sdk::{HostHandle, HostHandleBackendHost};

use crate::SoapBackendPlugin;

/// Build the private multi-thread runtime the bridge uses to `block_on`
/// the async inner plugin. Two workers + `enable_all`, matching the
/// http / nats / sql bridges.
fn build_bridge_runtime(thread_name: &str) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name(thread_name.to_owned())
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("soap cdylib: tokio runtime init failed: {e}"))
}

/// `SyncBackendPlugin` bridge over [`SoapBackendPlugin`].
pub struct SoapBackendCdylib {
    inner: SoapBackendPlugin,
    host: Arc<dyn mcpg_plugin_protocol::BackendHost>,
    rt: tokio::runtime::Runtime,
}

impl SoapBackendCdylib {
    /// Infallible cdylib factory. `config_json` is ignored — SOAP carries
    /// no plugin-level config (per-binding endpoint / action / templates
    /// arrive via `register_profile`). Installs the host handle on the
    /// inner plugin for observability and wraps it as the `BackendHost`
    /// `register_profile` consumes.
    pub fn from_host_config(_config_json: &str, host: HostHandle) -> Self {
        let inner = SoapBackendPlugin::new();
        let _installed = inner.set_host_handle(host.clone());
        Self {
            inner,
            host: Arc::new(HostHandleBackendHost::new(host)),
            rt: build_bridge_runtime("mcpg-backend-soap"),
        }
    }
}

impl SyncBackendPlugin for SoapBackendCdylib {
    fn manifest(&self) -> &PluginManifest {
        BackendPlugin::manifest(&self.inner)
    }

    fn kind(&self) -> &str {
        BackendPlugin::kind(&self.inner)
    }

    fn register_profile(
        &self,
        profile_name: &str,
        spec: &serde_json::Value,
    ) -> Result<(), BackendError> {
        self.rt.block_on(BackendPlugin::register_profile(
            &self.inner,
            profile_name,
            spec,
            Arc::clone(&self.host),
        ))
    }

    fn execute(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        self.rt
            .block_on(BackendPlugin::execute(&self.inner, profile_name, request))
    }

    fn audit_metadata(&self, profile_name: &str) -> serde_json::Map<String, serde_json::Value> {
        BackendPlugin::audit_metadata(&self.inner, profile_name)
    }
}

// cdylib export — one `backend` entity under `dev.mcpg.backend.soap`.
mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.backend.soap",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[::mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    // Residual per-kind facts the gateway reads back by kind. SOAP is an
    // HTTP/1.1 transport (the plugin POSTs the envelope to `endpoint`), so
    // the generic prober issues an HTTP GET against the bare base URL
    // (empty path) — matching the old typed `probe_http(endpoint)`, same as
    // http/graphql. It may appear as a backend pipeline step. label = kind
    // ("soap"), no dynamic tool list. `cred://` only resolves in the
    // endpoint + HTTP headers; the SOAPAction + body/header templates are
    // rendered without credential resolution, so they are transport-only —
    // the gateway's generic spec-walk asserts no `cred://` lands there
    // (mirroring the old config-load reject; `register_profile` also
    // enforces it).
    backend_profile: ::mcpg_plugin_protocol::manifest::BackendProfile {
        health_probe: ::mcpg_plugin_protocol::manifest::HealthProbeDecl::Http {
            path: ::std::string::String::new(),
        },
        pipeline_capable: true,
        transport_only_fields: ::std::vec![
            "/soap_action".to_owned(),
            "/body_template".to_owned(),
            "/header_template".to_owned(),
        ],
        ..::core::default::Default::default()
    },
    entities: [
        backend as binding {
            inner_name: "",
            plugin_type: SoapBackendCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                SoapBackendCdylib::from_host_config(cfg, host),
        },
    ],
}
