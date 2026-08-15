//! Operator-facing spec for the SOAP backend plugin.
//!
//! One binding = one SOAP operation = one MCP tool, mirroring the http
//! backend's one-profile-per-binding shape. The runtime request profile
//! (timeout / SSRF / body-limit knobs) is the shared `net-core`
//! [`HttpRequestProfile`]; SOAP layers its envelope-construction config
//! (version, action, body/header templates) on top.

use std::collections::BTreeMap;

use serde::Deserialize;

pub use mcpg_plugin_backend_net_core::types::HttpResponseSummary;

/// SOAP protocol version. Drives the envelope namespace, the request
/// `Content-Type`, and where the action travels (a `SOAPAction` HTTP
/// header in 1.1 vs. an `action=` Content-Type parameter in 1.2).
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
pub enum SoapVersion {
    /// SOAP 1.1 — `text/xml`, `SOAPAction` header, envelope namespace
    /// `http://schemas.xmlsoap.org/soap/envelope/`.
    #[serde(rename = "1.1")]
    #[default]
    V11,
    /// SOAP 1.2 — `application/soap+xml`, action as a Content-Type
    /// parameter, envelope namespace `http://www.w3.org/2003/05/soap-envelope`.
    #[serde(rename = "1.2")]
    V12,
}

impl SoapVersion {
    /// The `soap:Envelope` namespace URI for this version.
    pub fn envelope_namespace(self) -> &'static str {
        match self {
            SoapVersion::V11 => "http://schemas.xmlsoap.org/soap/envelope/",
            SoapVersion::V12 => "http://www.w3.org/2003/05/soap-envelope",
        }
    }

    /// Human label used in the response envelope + audit metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            SoapVersion::V11 => "1.1",
            SoapVersion::V12 => "1.2",
        }
    }

    /// The request `Content-Type`. For 1.2 the SOAPAction (when present)
    /// rides as an `action="…"` media-type parameter; 1.1 carries it in
    /// a separate `SOAPAction` header instead (see
    /// [`SoapVersion::soap_action_header`]).
    pub fn content_type(self, action: Option<&str>) -> String {
        match self {
            SoapVersion::V11 => "text/xml; charset=utf-8".to_owned(),
            SoapVersion::V12 => match action {
                Some(a) if !a.is_empty() => {
                    format!("application/soap+xml; charset=utf-8; action=\"{a}\"")
                }
                _ => "application/soap+xml; charset=utf-8".to_owned(),
            },
        }
    }

    /// The `SOAPAction` HTTP header value for 1.1 (always sent, quoted,
    /// empty string when no action is configured per the SOAP 1.1
    /// binding). Returns `None` for 1.2, which carries the action in the
    /// Content-Type instead.
    pub fn soap_action_header(self, action: Option<&str>) -> Option<String> {
        match self {
            SoapVersion::V11 => Some(format!("\"{}\"", action.unwrap_or(""))),
            SoapVersion::V12 => None,
        }
    }
}

/// Operator-facing spec the gateway serializes when calling
/// `register_profile`. Mirrors `SoapBackendConfig` in the gateway crate.
#[derive(Debug, Clone, Deserialize)]
pub struct SoapBackendSpec {
    /// Absolute `http(s)://` endpoint the SOAP envelope is POSTed to.
    /// CEL `${…}` templating + per-caller `cred://` resolution apply.
    pub endpoint: String,

    /// SOAP protocol version (default 1.1).
    #[serde(default)]
    pub soap_version: SoapVersion,

    /// The SOAPAction URI for this operation. CEL-templatable but does
    /// NOT resolve `cred://` (use an HTTP `Authorization` header for
    /// transport auth). `None` sends an empty action.
    #[serde(default)]
    pub soap_action: Option<String>,

    /// XML for the contents of `<soap:Body>`. CEL `${arguments.*}`
    /// placeholders are interpolated per call; interpolated string
    /// values are XML-escaped to keep the envelope well-formed. The
    /// operator owns the service-specific element namespaces.
    pub body_template: String,

    /// Optional XML for the contents of `<soap:Header>` (WS-Addressing,
    /// routing hints, …). Same CEL + escaping rules as `body_template`.
    #[serde(default)]
    pub header_template: Option<String>,

    /// Extra outbound HTTP headers. CEL-templatable; `cred://` resolves
    /// per caller (this is where transport auth — `Authorization`,
    /// `X-API-Key` — belongs).
    #[serde(default)]
    pub headers: BTreeMap<String, String>,

    /// HTTP status codes treated as a non-fault response. A response
    /// carrying a `<soap:Fault>` is always classified as a fault first,
    /// regardless of status (SOAP returns faults as HTTP 500 / 400), so
    /// this only gates fault-free responses.
    #[serde(default = "default_expected_status_codes")]
    pub expected_status_codes: Vec<u16>,

    /// Response body cap (bytes). XML responses run larger than JSON, so
    /// the default is 1 MiB vs. the http backend's 64 KiB.
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,

    /// Per-call timeout (ms). SOAP services tend to be slower than REST,
    /// so the default is 30 s vs. the http backend's 5 s.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Opt in to reaching private/loopback resolved addresses (disables
    /// the DNS-rebinding guard for this binding only).
    #[serde(default)]
    pub allow_private_backends: bool,
}

fn default_expected_status_codes() -> Vec<u16> {
    vec![200]
}
fn default_max_response_bytes() -> usize {
    1_048_576
}
fn default_timeout_ms() -> u64 {
    30_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_defaults_to_11() {
        assert_eq!(SoapVersion::default(), SoapVersion::V11);
    }

    #[test]
    fn version_deserializes_from_dotted_string() {
        let v: SoapVersion = serde_json::from_value(serde_json::json!("1.2")).unwrap();
        assert_eq!(v, SoapVersion::V12);
    }

    #[test]
    fn content_type_carries_action_only_for_12() {
        assert_eq!(
            SoapVersion::V11.content_type(Some("urn:Foo")),
            "text/xml; charset=utf-8"
        );
        assert_eq!(
            SoapVersion::V12.content_type(Some("urn:Foo")),
            "application/soap+xml; charset=utf-8; action=\"urn:Foo\""
        );
        assert_eq!(
            SoapVersion::V12.content_type(None),
            "application/soap+xml; charset=utf-8"
        );
    }

    #[test]
    fn soap_action_header_only_for_11() {
        assert_eq!(
            SoapVersion::V11.soap_action_header(Some("urn:Foo")),
            Some("\"urn:Foo\"".to_owned())
        );
        assert_eq!(
            SoapVersion::V11.soap_action_header(None),
            Some("\"\"".to_owned())
        );
        assert_eq!(SoapVersion::V12.soap_action_header(Some("urn:Foo")), None);
    }

    #[test]
    fn spec_applies_soap_defaults() {
        let spec: SoapBackendSpec = serde_json::from_value(serde_json::json!({
            "endpoint": "https://example.com/svc",
            "body_template": "<tns:Ping/>",
        }))
        .unwrap();
        assert_eq!(spec.soap_version, SoapVersion::V11);
        assert_eq!(spec.expected_status_codes, vec![200]);
        assert_eq!(spec.max_response_bytes, 1_048_576);
        assert_eq!(spec.timeout_ms, 30_000);
        assert!(!spec.allow_private_backends);
        assert!(spec.soap_action.is_none());
    }
}
