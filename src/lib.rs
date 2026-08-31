//! SOAP backend binding plugin for mcpg.
//!
//! Implements [`SoapBackendPlugin`] — `BackendPlugin` for `kind: "soap"`.
//! Dispatches tool calls as SOAP 1.1 / 1.2 envelopes over outbound HTTP:
//! each binding declares an endpoint, a SOAPAction, and an XML
//! `body_template`; per call the tool arguments are CEL-interpolated
//! (and XML-escaped) into `<soap:Body>`, the envelope is POSTed, and the
//! response is parsed for a `<soap:Fault>` before being projected back
//! as MCP structured content.
//!
//! ## Reuse
//!
//! SOAP is XML-over-HTTP, so the transport layer is the shared
//! `net-core` [`NetworkProfileRuntime`]: per-credential `reqwest::Client`
//! caching, the DNS-rebinding / SSRF guard, body-limit truncation, CEL
//! templating of the endpoint + headers, and per-caller `cred://`
//! resolution all come from there unchanged (exactly as http / grpc /
//! graphql use it). This crate adds only the SOAP envelope construction
//! ([`xml`]), Fault parsing, and the response envelope ([`envelope`]).
//!
//! ## v1 scope
//!
//! Operations are declared explicitly (one binding = one operation =
//! one MCP tool). WSDL-driven auto-generation of tools is deferred — see
//! `DEFERRED.md`; it would layer over the same per-operation structures
//! via `expand_capabilities` without disturbing the declarative path.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use mcpg_expr::DynamicValue;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{
    BackendError, BackendHost, BackendPlugin, BackendRequest, BackendResponse, PluginManifest,
    firstparty_manifest,
};
use mcpg_plugin_sdk::{HostHandle, SpanGuard};
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tracing::debug;

use mcpg_plugin_backend_net_core::exec;
use mcpg_plugin_backend_net_core::runtime::{NetworkProfileRuntime, build_expr_context};
use mcpg_plugin_backend_net_core::types::{
    HttpBackendMethod, HttpRequestProfile, HttpResponseSummary, RetrySafetyContext,
};

/// cdylib sync bridge.
pub mod cdylib;
mod envelope;
mod types;
mod xml;

use envelope::{
    DownstreamHttpError, build_result_envelope, soap_fault_downstream_error,
    transport_downstream_error, validate_expected_status_codes,
};
pub use types::{SoapBackendSpec, SoapVersion};
use xml::SoapFault;

/// Embedded plugin descriptor — passed to
/// [`mcpg_plugin_host::FirstPartyRegistrar::register`] at gateway
/// startup (and to the in-tree gateway test registration).
pub const BINDING_DESCRIPTOR_YAML: &str = include_str!("../plugin.yaml");

// ---------------------------------------------------------------------------
// Observability helpers (HostHandle triad) — mirror the http
// backend's bounded outcome-label + audit-action sets, SOAP-flavoured.
// ---------------------------------------------------------------------------

/// Bounded outcome label for the host metric pair. The set MUST stay
/// closed so the host metrics recorder doesn't blow up on cardinality.
/// 4xx/5xx roll up by status class; `soap_fault` is its own bucket.
fn host_outcome_label_for_status(status: u16) -> &'static str {
    match status {
        200..=299 => "ok",
        400..=499 => "http_4xx",
        500..=599 => "http_5xx",
        _ => "ok",
    }
}

/// Outcome label for the transport-error path (no HTTP status). The
/// resolution layer flattens to `String`, so timeout is sniffed from the
/// message (reqwest's canonical "operation timed out").
fn host_outcome_label_for_transport_error(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        "timeout"
    } else {
        "transport"
    }
}

/// Bounded set of dotted audit-event action names emitted on notable
/// failures. `None` for success + 4xx (4xx is normal traffic). SOAP
/// Faults always audit — they are the SOAP error channel and are
/// forensically interesting.
fn audit_action_for_outcome(label: &str) -> Option<&'static str> {
    match label {
        "timeout" => Some("dev.mcpg.backend.soap.request_timeout"),
        "transport" => Some("dev.mcpg.backend.soap.request_failed"),
        "http_5xx" => Some("dev.mcpg.backend.soap.upstream_5xx"),
        "soap_fault" => Some("dev.mcpg.backend.soap.fault"),
        "invalid_spec" => Some("dev.mcpg.backend.soap.request_failed"),
        _ => None,
    }
}

/// Best-effort RFC 3339 timestamp for audit `occurred_at`.
fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Synthetic identity for audit events on requests with no caller
/// attribution (system-initiated paths). Mirrors the http/sql shape so
/// cross-plugin audit search treats system traffic uniformly.
fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some("dev.mcpg.backend.soap".into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

/// Per-call effective headers surfaced in the response envelope for
/// operator visibility (resolved auth headers + the SOAP Content-Type +
/// SOAPAction the plugin set per call).
fn build_display_headers(
    resolved_headers: &BTreeMap<String, String>,
    content_type: &str,
    soap_action_header: Option<&str>,
) -> BTreeMap<String, String> {
    let mut out = resolved_headers.clone();
    out.insert("Content-Type".to_owned(), content_type.to_owned());
    if let Some(action) = soap_action_header {
        out.insert("SOAPAction".to_owned(), action.to_owned());
    }
    out
}

/// Send one SOAP envelope on the resolved (per-cred, DNS-pinned) client
/// and read the response under the body-limit cap. The client already
/// carries the baked auth headers + timeout + SSRF pinning; per call we
/// add only Content-Type, SOAPAction (1.1), trace headers, and the XML
/// body.
async fn send_soap_request(
    client: &reqwest::Client,
    resolved_url: &str,
    content_type: &str,
    soap_action_header: Option<&str>,
    trace_headers: &[(String, String)],
    body: String,
    max_response_bytes: usize,
) -> Result<HttpResponseSummary, String> {
    let started = Instant::now();
    let mut req = client
        .post(resolved_url)
        .header(reqwest::header::CONTENT_TYPE, content_type)
        .header(
            reqwest::header::ACCEPT,
            "text/xml, application/soap+xml, application/xml, */*",
        )
        .body(body);
    if let Some(action) = soap_action_header {
        req = req.header("SOAPAction", action);
    }
    for (name, value) in trace_headers {
        let lower = name.to_ascii_lowercase();
        if lower == "traceparent" || lower == "tracestate" {
            req = req.header(name.as_str(), value.as_str());
        }
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("SOAP request failed: {e}"))?;
    let status = resp.status().as_u16();
    let content_type_resp = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let retry_after_ms = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|secs| secs.saturating_mul(1_000));

    let (bytes, truncated) = exec::read_response_with_limit(resp, max_response_bytes).await?;
    Ok(HttpResponseSummary {
        status_code: status,
        content_type: content_type_resp,
        retry_after_ms,
        body: String::from_utf8_lossy(&bytes).into_owned(),
        body_truncated: truncated,
        duration_ms: started.elapsed().as_millis(),
    })
}

/// Classification of a completed SOAP response: Fault vs. unexpected
/// status vs. ok, plus the best-effort XML→JSON projection.
struct Classified {
    fault: Option<SoapFault>,
    response_json: Option<Value>,
    json_parse_error: Option<String>,
    downstream_errors: Vec<DownstreamHttpError>,
    primary: Option<DownstreamHttpError>,
    outcome_label: &'static str,
}

/// Classify a completed response. A `<soap:Fault>` takes precedence over
/// status-code checking (SOAP returns faults as HTTP 500 / 400), so a
/// fault is always reported as `soap_fault` rather than an unexpected
/// status.
fn classify(profile: &SoapProfile, summary: &HttpResponseSummary) -> Classified {
    let body_present = !summary.body.trim().is_empty();
    let fault = if body_present {
        xml::parse_fault(&summary.body, profile.version)
    } else {
        None
    };
    let (response_json, json_parse_error) = if body_present {
        match xml::xml_to_json(&summary.body) {
            Ok(v) => (Some(v), None),
            Err(e) => (None, Some(e)),
        }
    } else {
        (None, None)
    };

    let mut downstream_errors: Vec<DownstreamHttpError> = Vec::new();
    let outcome_label: &'static str = if let Some(fault) = &fault {
        downstream_errors.push(soap_fault_downstream_error(fault, summary.status_code));
        "soap_fault"
    } else if let Some(err) = validate_expected_status_codes(
        &profile.net.profile().expected_status_codes,
        summary.status_code,
        summary.retry_after_ms,
        RetrySafetyContext::PotentiallyNonIdempotentJsonCall,
    ) {
        downstream_errors.push(err);
        host_outcome_label_for_status(summary.status_code)
    } else {
        "ok"
    };
    let primary = downstream_errors.first().cloned();

    Classified {
        fault,
        response_json,
        json_parse_error,
        downstream_errors,
        primary,
        outcome_label,
    }
}

/// Serialize the response envelope into the `BackendResponse.payload`.
fn finalize_payload(envelope: Value) -> Result<BackendResponse, BackendError> {
    let payload = serde_json::to_vec(&envelope).map_err(|e| BackendError::Transport {
        message: format!("SOAP plugin envelope serialization failed: {e}"),
    })?;
    Ok(BackendResponse {
        payload,
        truncated: false,
    })
}

/// Per-binding SOAP runtime: the shared net-core transport runtime plus
/// the SOAP-specific compiled templates. Cheap to clone (every field is
/// `Arc`-backed or `Copy`); the dispatch path clones it out of the
/// profile map so the read lock isn't held across the upstream call.
#[derive(Clone)]
struct SoapProfile {
    net: NetworkProfileRuntime,
    version: SoapVersion,
    /// CEL-compiled SOAPAction (no `cred://`). `None` = empty action.
    compiled_action: Option<Arc<DynamicValue<String>>>,
    /// CEL-compiled `<soap:Body>` template (rendered against XML-escaped
    /// arguments).
    compiled_body: Arc<DynamicValue<String>>,
    /// CEL-compiled `<soap:Header>` template, if configured.
    compiled_header: Option<Arc<DynamicValue<String>>>,
}

/// `BackendPlugin` implementation for `kind: "soap"`.
pub struct SoapBackendPlugin {
    manifest: PluginManifest,
    profiles: RwLock<BTreeMap<String, SoapProfile>>,
    /// Unified host surface (per-call span / metric / audit).
    /// Installed once at boot via [`SoapBackendPlugin::set_host_handle`];
    /// `None` in test harnesses short-circuits the triad to no-ops.
    host_handle: OnceLock<HostHandle>,
}

impl Default for SoapBackendPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl SoapBackendPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.soap",
                name: "SOAP Binding",
                class: Backend,
            },
            profiles: RwLock::new(BTreeMap::new()),
            host_handle: OnceLock::new(),
        }
    }

    /// Install the unified [`HostHandle`] for per-call observability.
    /// Idempotent; returns whether the slot was installed (`true`) or
    /// already occupied (`false`).
    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.host_handle.set(host).is_ok()
    }

    fn host_handle(&self) -> Option<&HostHandle> {
        self.host_handle.get()
    }

    /// Emit the per-call observability triad (latency histogram + call
    /// counter + optional audit event) through the installed
    /// [`HostHandle`]. No-op when no handle is installed (test paths).
    /// Audit emission flows through `spawn_blocking` because
    /// `HostHandle::audit_event` is sync (mirrors the http backend).
    #[allow(clippy::too_many_arguments)]
    async fn emit_host_observability(
        &self,
        backend_name: &str,
        outcome_label: &'static str,
        status_code: Option<u16>,
        reason: Option<&str>,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        duration: Duration,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        host.histogram(
            "mcpg_soap_backend_latency_seconds",
            duration.as_secs_f64(),
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_soap_backend_calls_total",
            1,
            &[("outcome", outcome_label)],
        );

        if let Some(action) = audit_action_for_outcome(outcome_label) {
            let actor = identity.cloned().unwrap_or_else(synthetic_system_identity);
            let mut details = json!({
                "backend": backend_name,
                "duration_ms": duration.as_millis() as u64,
                "outcome": outcome_label,
                "alias": host.alias(),
            });
            let object = details.as_object_mut().expect("json object");
            if let Some(status) = status_code {
                object.insert("status_code".into(), Value::from(status));
            }
            if let Some(reason) = reason {
                object.insert("reason".into(), Value::String(reason.to_owned()));
            }
            let event = AuditEvent {
                event_id: format!("soap-{}-{}", request_id, duration.as_nanos()),
                occurred_at: rfc3339_now(),
                actor,
                action: action.to_owned(),
                resource: Some(format!("soap-binding://{backend_name}")),
                outcome: AuditOutcome::Failure,
                request_id: Some(request_id.to_owned()),
                upstream_request_id: None,
                node_id: None,
                details,
                prev_event_hash: None,
            };
            let host_for_audit = host.clone();
            if let Err(join_err) = tokio::task::spawn_blocking(move || {
                let _ = host_for_audit.audit_event(event);
            })
            .await
            {
                debug!(
                    target: "mcpg::soap::host_handle",
                    error = %join_err,
                    "host_handle.audit_event spawn_blocking failed"
                );
            }
        }
    }

    /// Build a transport-style error envelope (CEL/render/resolution
    /// failures), emit the triad, and return it as a normal payload so
    /// callers always receive structured `downstreamError` content
    /// rather than an opaque `Err` — matching the http backend.
    #[allow(clippy::too_many_arguments)]
    async fn finish_error(
        &self,
        profile: &SoapProfile,
        backend_name: &str,
        tool_name: &str,
        soap_action: Option<&str>,
        request_xml: Option<&str>,
        message: &str,
        label: &'static str,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        started: Instant,
        host_span: Option<SpanGuard>,
    ) -> Result<BackendResponse, BackendError> {
        let downstream = transport_downstream_error(
            message,
            RetrySafetyContext::PotentiallyNonIdempotentJsonCall,
        );
        let endpoint = profile.net.profile().url.clone();
        let display_headers = profile.net.profile().headers.clone();
        let envelope = build_result_envelope(
            tool_name,
            backend_name,
            profile.version,
            soap_action,
            &endpoint,
            request_xml.unwrap_or(""),
            &display_headers,
            None,
            None,
            None,
            None,
            Some(&downstream),
            std::slice::from_ref(&downstream),
            Some(message),
        );
        self.emit_host_observability(
            backend_name,
            label,
            None,
            Some(message),
            identity,
            request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }
}

impl std::fmt::Debug for SoapBackendPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoapBackendPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

#[async_trait]
impl BackendPlugin for SoapBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "soap"
    }

    async fn register_profile(
        &self,
        backend_name: &str,
        spec: &Value,
        host: Arc<dyn BackendHost>,
    ) -> Result<(), BackendError> {
        let parsed: SoapBackendSpec =
            serde_json::from_value(spec.clone()).map_err(|e| BackendError::InvalidSpec {
                message: format!("SOAP binding spec: {e}"),
            })?;

        if parsed.endpoint.trim().is_empty() {
            return Err(BackendError::InvalidSpec {
                message: "endpoint must not be empty".into(),
            });
        }
        if !parsed.endpoint.starts_with("http://") && !parsed.endpoint.starts_with("https://") {
            return Err(BackendError::InvalidSpec {
                message: format!(
                    "endpoint must start with http:// or https://, got '{}'",
                    parsed.endpoint
                ),
            });
        }
        if parsed.body_template.trim().is_empty() {
            return Err(BackendError::InvalidSpec {
                message: "body_template must not be empty".into(),
            });
        }
        if parsed.timeout_ms == 0 {
            return Err(BackendError::InvalidSpec {
                message: "timeout_ms must be greater than 0".into(),
            });
        }
        if parsed.max_response_bytes == 0 {
            return Err(BackendError::InvalidSpec {
                message: "max_response_bytes must be greater than 0".into(),
            });
        }
        for code in &parsed.expected_status_codes {
            if !(100..=599).contains(code) {
                return Err(BackendError::InvalidSpec {
                    message: format!(
                        "expected_status_codes entries must be valid HTTP status codes \
                         (100-599), got {code}"
                    ),
                });
            }
        }
        // `cred://` only resolves in the endpoint + HTTP headers (via the
        // net-core runtime). The SOAP action + body/header templates are
        // rendered without credential resolution, so reject `cred://`
        // there with a clear message rather than silently emitting an
        // unresolved literal into the wire envelope.
        for (label, text) in [
            ("soap_action", parsed.soap_action.as_deref()),
            ("body_template", Some(parsed.body_template.as_str())),
            ("header_template", parsed.header_template.as_deref()),
        ] {
            if text.is_some_and(|t| t.contains("cred://")) {
                return Err(BackendError::InvalidSpec {
                    message: format!(
                        "{label} must not contain cred:// — put transport credentials in an \
                         HTTP header (e.g. Authorization) instead"
                    ),
                });
            }
        }

        let compiled_action = match parsed.soap_action.as_deref() {
            Some(action) => Some(Arc::new(DynamicValue::<String>::parse(action).map_err(
                |e| BackendError::InvalidSpec {
                    message: format!("soap_action expression: {e}"),
                },
            )?)),
            None => None,
        };
        let compiled_body = Arc::new(
            DynamicValue::<String>::parse(&parsed.body_template).map_err(|e| {
                BackendError::InvalidSpec {
                    message: format!("body_template expression: {e}"),
                }
            })?,
        );
        let compiled_header = match parsed.header_template.as_deref() {
            Some(header) => Some(Arc::new(DynamicValue::<String>::parse(header).map_err(
                |e| BackendError::InvalidSpec {
                    message: format!("header_template expression: {e}"),
                },
            )?)),
            None => None,
        };

        // Secret rotation hint the gateway injects post-resolution.
        let secret_refs: Vec<String> = spec
            .get("__mcpg_secret_refs")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();

        debug!(
            backend = %backend_name,
            endpoint = %parsed.endpoint,
            soap_version = parsed.soap_version.as_str(),
            timeout_ms = parsed.timeout_ms,
            "registered SOAP binding profile"
        );

        let profile = HttpRequestProfile {
            url: parsed.endpoint.clone(),
            method: HttpBackendMethod::Post,
            headers: parsed.headers.clone(),
            expected_status_codes: parsed.expected_status_codes.clone(),
            require_json_response: false,
            max_response_bytes: parsed.max_response_bytes,
            timeout: Duration::from_millis(parsed.timeout_ms),
            allow_private_backends: parsed.allow_private_backends,
        };

        let net = NetworkProfileRuntime::register(
            backend_name,
            parsed.endpoint,
            parsed.headers,
            profile,
            host,
            secret_refs,
        )
        .map_err(|e| BackendError::InvalidSpec {
            message: format!("SOAP binding spec: {e}"),
        })?;

        self.profiles.write().await.insert(
            backend_name.to_owned(),
            SoapProfile {
                net,
                version: parsed.soap_version,
                compiled_action,
                compiled_body,
                compiled_header,
            },
        );
        Ok(())
    }

    async fn execute(
        &self,
        backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        let started = Instant::now();
        let request_id = request.request_id.clone();
        let identity = request.identity.clone();
        let host_span = self.host_handle().map(|h| {
            h.span(
                "soap_backend.execute",
                json!({ "backend": backend_name, "request_id": request_id }),
            )
        });

        // 1. Profile lookup (cloned out so the lock isn't held across IO).
        let profile = {
            let guard = self.profiles.read().await;
            match guard.get(backend_name).cloned() {
                Some(p) => p,
                None => {
                    let err = BackendError::ProfileNotFound {
                        backend_name: backend_name.to_owned(),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "profile_not_found",
                        None,
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        // 2. Parse tool arguments (hard error — never reaches the wire).
        let arguments: Value = if request.payload.is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(&request.payload) {
                Ok(v) => v,
                Err(e) => {
                    let err = BackendError::InvalidSpec {
                        message: format!("SOAP plugin payload is not valid JSON: {e}"),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "invalid_spec",
                        None,
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        let tool_name = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("mcpg-tool-name"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| backend_name.to_owned());
        let trace_headers: Vec<(String, String)> = request
            .headers
            .iter()
            .filter(|(k, _)| {
                let lower = k.to_ascii_lowercase();
                lower == "traceparent" || lower == "tracestate"
            })
            .cloned()
            .collect();

        // Two CEL contexts: raw args for the endpoint / headers / action
        // (which net-core validates as HTTP-header-safe), and XML-escaped
        // args for the body / header XML templates.
        let expr_ctx = build_expr_context(&arguments, &tool_name, &request);
        let escaped_args = xml::escape_arguments(&arguments);
        let body_ctx = build_expr_context(&escaped_args, &tool_name, &request);
        let nil_cred = |_uri: &str| None::<String>;

        // 3. Render the request envelope (no client needed yet).
        let resolved_action = match &profile.compiled_action {
            Some(dv) => match dv.resolve_with_credentials(&expr_ctx, nil_cred) {
                Ok(s) => Some(s),
                Err(e) => {
                    return self
                        .finish_error(
                            &profile,
                            backend_name,
                            &tool_name,
                            None,
                            None,
                            &format!("evaluating soap_action: {e}"),
                            "invalid_spec",
                            identity.as_ref(),
                            &request_id,
                            started,
                            host_span,
                        )
                        .await;
                }
            },
            None => None,
        };
        if let Some(action) = resolved_action.as_deref()
            && let Err(e) = mcpg_expr::validate_header_value("SOAPAction", action)
        {
            return self
                .finish_error(
                    &profile,
                    backend_name,
                    &tool_name,
                    resolved_action.as_deref(),
                    None,
                    &format!("soap_action: {e}"),
                    "invalid_spec",
                    identity.as_ref(),
                    &request_id,
                    started,
                    host_span,
                )
                .await;
        }
        let body_xml = match profile
            .compiled_body
            .resolve_with_credentials(&body_ctx, nil_cred)
        {
            Ok(s) => s,
            Err(e) => {
                return self
                    .finish_error(
                        &profile,
                        backend_name,
                        &tool_name,
                        resolved_action.as_deref(),
                        None,
                        &format!("evaluating body_template: {e}"),
                        "invalid_spec",
                        identity.as_ref(),
                        &request_id,
                        started,
                        host_span,
                    )
                    .await;
            }
        };
        let header_xml = match &profile.compiled_header {
            Some(dv) => match dv.resolve_with_credentials(&body_ctx, nil_cred) {
                Ok(s) => Some(s),
                Err(e) => {
                    return self
                        .finish_error(
                            &profile,
                            backend_name,
                            &tool_name,
                            resolved_action.as_deref(),
                            None,
                            &format!("evaluating header_template: {e}"),
                            "invalid_spec",
                            identity.as_ref(),
                            &request_id,
                            started,
                            host_span,
                        )
                        .await;
                }
            },
            None => None,
        };

        let request_xml = xml::build_envelope(profile.version, header_xml.as_deref(), &body_xml);
        let content_type = profile.version.content_type(resolved_action.as_deref());
        let soap_action_header = profile
            .version
            .soap_action_header(resolved_action.as_deref());

        // 4. Resolve the per-cred, DNS-pinned client (endpoint + auth
        // headers CEL/cred resolution) from the shared net-core runtime.
        let resolved = match profile
            .net
            .resolve_client(&expr_ctx, &request, backend_name)
            .await
        {
            Ok(r) => r,
            Err(res_err) => {
                return self
                    .finish_error(
                        &profile,
                        backend_name,
                        &tool_name,
                        resolved_action.as_deref(),
                        Some(&request_xml),
                        &res_err,
                        host_outcome_label_for_transport_error(&res_err),
                        identity.as_ref(),
                        &request_id,
                        started,
                        host_span,
                    )
                    .await;
            }
        };

        // 5. Send.
        let display_headers = build_display_headers(
            &resolved.resolved_headers,
            &content_type,
            soap_action_header.as_deref(),
        );
        let send = send_soap_request(
            &resolved.client,
            &resolved.resolved_url,
            &content_type,
            soap_action_header.as_deref(),
            &trace_headers,
            request_xml.clone(),
            profile.net.profile().max_response_bytes,
        )
        .await;

        let summary = match send {
            Ok(summary) => summary,
            Err(error) => {
                let label = host_outcome_label_for_transport_error(&error);
                let downstream = transport_downstream_error(
                    &error,
                    RetrySafetyContext::PotentiallyNonIdempotentJsonCall,
                );
                let envelope = build_result_envelope(
                    &tool_name,
                    backend_name,
                    profile.version,
                    resolved_action.as_deref(),
                    &resolved.resolved_url,
                    &request_xml,
                    &display_headers,
                    None,
                    None,
                    None,
                    None,
                    Some(&downstream),
                    std::slice::from_ref(&downstream),
                    Some(&error),
                );
                self.emit_host_observability(
                    backend_name,
                    label,
                    None,
                    Some(&error),
                    identity.as_ref(),
                    &request_id,
                    started.elapsed(),
                )
                .await;
                drop(host_span);
                return finalize_payload(envelope);
            }
        };

        // 6. Classify (Fault > status) + build the response envelope.
        let classified = classify(&profile, &summary);
        let audit_reason = classified.primary.as_ref().map(|e| e.message.clone());
        let envelope = build_result_envelope(
            &tool_name,
            backend_name,
            profile.version,
            resolved_action.as_deref(),
            &resolved.resolved_url,
            &request_xml,
            &display_headers,
            Some(&summary),
            classified.response_json.as_ref(),
            classified.json_parse_error.as_deref(),
            classified.fault.as_ref(),
            classified.primary.as_ref(),
            &classified.downstream_errors,
            None,
        );
        self.emit_host_observability(
            backend_name,
            classified.outcome_label,
            Some(summary.status_code),
            audit_reason.as_deref(),
            identity.as_ref(),
            &request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }

    fn audit_metadata(&self, _backend_name: &str) -> serde_json::Map<String, Value> {
        let mut map = serde_json::Map::new();
        map.insert("soap.transport".to_owned(), json!("plugin"));
        map
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn no_op_host() -> Arc<dyn BackendHost> {
        Arc::new(NoOpHost) as Arc<dyn BackendHost>
    }

    fn minimal_spec() -> Value {
        json!({
            "endpoint": "https://soap.example.com/svc",
            "soap_action": "urn:GetWeather",
            "body_template": "<tns:GetWeather xmlns:tns=\"urn:w\"><City>${arguments.city}</City></tns:GetWeather>",
        })
    }

    #[test]
    fn kind_is_soap() {
        assert_eq!(SoapBackendPlugin::new().kind(), "soap");
    }

    #[test]
    fn manifest_advertises_first_party_id() {
        assert_eq!(
            SoapBackendPlugin::new().manifest().id,
            "dev.mcpg.backend.soap"
        );
    }

    #[tokio::test]
    async fn register_accepts_minimal_spec() {
        let plugin = SoapBackendPlugin::new();
        plugin
            .register_profile("weather", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("weather").expect("profile");
        assert_eq!(p.version, SoapVersion::V11);
        assert_eq!(p.net.profile().url, "https://soap.example.com/svc");
        assert!(p.compiled_action.is_some());
    }

    #[tokio::test]
    async fn register_detects_cred_refs_in_headers() {
        let plugin = SoapBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["headers"] = json!({ "Authorization": "Bearer cred://oauth/api" });
        plugin
            .register_profile("weather", &spec, no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        assert!(profiles.get("weather").unwrap().net.has_cred_refs());
    }

    #[tokio::test]
    async fn register_rejects_cred_in_body_template() {
        let plugin = SoapBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["body_template"] = json!("<x>cred://oauth/api</x>");
        let err = plugin
            .register_profile("weather", &spec, no_op_host())
            .await
            .expect_err("cred in body");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_empty_endpoint() {
        let plugin = SoapBackendPlugin::new();
        let spec = json!({ "endpoint": "", "body_template": "<x/>" });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("empty endpoint");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_non_http_endpoint() {
        let plugin = SoapBackendPlugin::new();
        let spec = json!({ "endpoint": "ftp://x/", "body_template": "<x/>" });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("non-http");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_empty_body_template() {
        let plugin = SoapBackendPlugin::new();
        let spec = json!({ "endpoint": "https://x/", "body_template": "   " });
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("empty body");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn execute_unknown_profile_returns_profile_not_found() {
        let plugin = SoapBackendPlugin::new();
        let req = BackendRequest {
            payload: vec![],
            headers: vec![],
            request_id: "rq-1".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let err = plugin.execute("missing", req).await.expect_err("missing");
        assert!(matches!(err, BackendError::ProfileNotFound { .. }));
    }

    #[tokio::test]
    async fn execute_rejects_non_json_payload() {
        let plugin = SoapBackendPlugin::new();
        plugin
            .register_profile("weather", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let req = BackendRequest {
            payload: b"not json".to_vec(),
            headers: vec![],
            request_id: "rq-1".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let err = plugin
            .execute("weather", req)
            .await
            .expect_err("invalid json");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    // --- Stage 2B conformance: register_profile is the single source of
    // truth for the soap spec. Omitting each defaulted field resolves to
    // the same value the gateway's `dynamic_register_spec` used to apply; a
    // bad value fails as `InvalidSpec`; a bare `cred://` in a transport-only
    // (non-credential-resolving) field fails as `InvalidSpec`. ---

    #[tokio::test]
    async fn omitted_defaults_resolve_to_gateway_values() {
        // A spec carrying only the two required fields; every defaulted
        // field is absent and must resolve to the gateway's default.
        let spec = json!({
            "endpoint": "https://soap.example.com/svc",
            "body_template": "<tns:Ping/>",
        });
        let plugin = SoapBackendPlugin::new();
        plugin
            .register_profile("p", &spec, no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("p").expect("profile");
        // soap_version default = 1.1
        assert_eq!(p.version, SoapVersion::V11);
        let net = p.net.profile();
        // expected_status_codes default = [200]
        assert_eq!(net.expected_status_codes, vec![200]);
        // max_response_bytes default = 1 MiB
        assert_eq!(net.max_response_bytes, 1_048_576);
        // timeout_ms default = 30_000 ms
        assert_eq!(net.timeout, Duration::from_millis(30_000));
        // soap_action / header_template default to absent
        assert!(p.compiled_action.is_none());
        assert!(p.compiled_header.is_none());
    }

    #[tokio::test]
    async fn register_rejects_zero_timeout() {
        let plugin = SoapBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["timeout_ms"] = json!(0);
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("zero timeout");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_zero_max_response_bytes() {
        let plugin = SoapBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["max_response_bytes"] = json!(0);
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("zero byte cap");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_out_of_range_status_code() {
        let plugin = SoapBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["expected_status_codes"] = json!([99]);
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("bad status");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_unknown_soap_version() {
        let plugin = SoapBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["soap_version"] = json!("1.3");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("bad version");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_cred_in_soap_action() {
        let plugin = SoapBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["soap_action"] = json!("cred://oauth/api");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("cred in soap_action");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_cred_in_header_template() {
        let plugin = SoapBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["header_template"] = json!("<wsa:To>cred://oauth/api</wsa:To>");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("cred in header_template");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    /// Minimal `BackendHost` for tests — NotImplemented for every call.
    struct NoOpHost;

    #[async_trait]
    impl BackendHost for NoOpHost {
        async fn invoke_tool(
            &self,
            _ctx: &mcpg_plugin_protocol::BackendInvocationContext,
            _tool_name: &str,
            _args: &serde_json::Value,
        ) -> Result<serde_json::Value, mcpg_plugin_protocol::BackendHostError> {
            Err(mcpg_plugin_protocol::BackendHostError::NotImplemented)
        }
    }
}
