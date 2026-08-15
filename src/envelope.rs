//! SOAP-family structured response envelope.
//!
//! The status-code / transport downstream-error classification + the
//! retry-guidance fields are shared with http/grpc/graphql and live in
//! `net-core`'s `retry` module; they are re-exported here. This module
//! owns the SOAP-specific structured-content layout the gateway projects
//! onto `tools/call` (via `execute_envelope_plugin`), plus the
//! Fault → [`DownstreamHttpError`] mapping.
//!
//! The `BackendResponse.payload` the plugin returns is this UTF-8 JSON
//! document. The gateway parses it as `structured_content`, stringifies
//! it as the text content, and treats a non-null `downstreamError` slot
//! as the `is_error` signal — identical to the http backend's contract.

use std::collections::BTreeMap;

use serde_json::{Value, json};

pub use mcpg_plugin_backend_net_core::retry::{
    DownstreamHttpError, transport_downstream_error, validate_expected_status_codes,
};

use crate::types::{HttpResponseSummary, SoapVersion};
use crate::xml::SoapFault;

const DEFAULT_BACKOFF_BASE_MS: u64 = 1_000;

/// Map a parsed [`SoapFault`] onto the shared [`DownstreamHttpError`]
/// envelope slot so the gateway flags the call `is_error` and clients
/// get consistent retry guidance. Receiver/Server faults are retryable
/// (transient server condition); Sender/Client faults are not (caller
/// contract violation).
pub fn soap_fault_downstream_error(fault: &SoapFault, status_code: u16) -> DownstreamHttpError {
    let retryable = fault.is_retryable();
    let (
        retry_class,
        backoff_strategy,
        minimum_backoff_ms,
        caller_retry_decision,
        retry_safety,
        suggested_action,
    ) = if retryable {
        (
            "with_backoff",
            "exponential_backoff",
            Some(DEFAULT_BACKOFF_BASE_MS),
            "confirm_idempotency_then_retry_with_backoff",
            "review_idempotency_before_retry",
            "review_idempotency_then_retry_with_backoff",
        )
    } else {
        (
            "do_not_retry",
            "no_retry",
            None,
            "do_not_retry",
            "do_not_retry",
            "inspect_soap_fault_detail",
        )
    };

    let message = if fault.reason.trim().is_empty() {
        format!("SOAP Fault: {}", fault.code)
    } else {
        fault.reason.clone()
    };

    DownstreamHttpError {
        kind: "soap_fault".to_owned(),
        code: "mcpg.downstream_soap.fault".to_owned(),
        message,
        retryable,
        retry_class: retry_class.to_owned(),
        retry_after_ms: None,
        // SOAP requests are POST envelopes — non-idempotent by default.
        idempotency_hint: "potentially_non_idempotent".to_owned(),
        caller_retry_decision: caller_retry_decision.to_owned(),
        retry_safety: retry_safety.to_owned(),
        backoff_strategy: backoff_strategy.to_owned(),
        minimum_backoff_ms,
        suggested_action: suggested_action.to_owned(),
        status_code: Some(status_code),
        details: json!({
            "faultCode": fault.code,
            "faultReason": fault.reason,
            "faultNode": fault.node,
            "faultRole": fault.role,
            "faultSubcodes": fault.subcodes,
            "faultDetail": fault.detail,
        }),
    }
}

fn fault_to_json(fault: &SoapFault) -> Value {
    json!({
        "code": fault.code,
        "reason": fault.reason,
        "node": fault.node,
        "role": fault.role,
        "detail": fault.detail,
        "subcodes": fault.subcodes,
    })
}

/// Build the SOAP structured-content envelope returned as the
/// `BackendResponse.payload`. `request_xml` is the rendered request
/// envelope; `request_headers` carries the per-call effective headers
/// (incl. the resolved Content-Type / SOAPAction) for operator
/// visibility. A non-null `downstream_error` drives `is_error` at the
/// gateway.
#[allow(clippy::too_many_arguments)]
pub fn build_result_envelope(
    tool_name: &str,
    profile_name: &str,
    version: SoapVersion,
    soap_action: Option<&str>,
    endpoint: &str,
    request_xml: &str,
    request_headers: &BTreeMap<String, String>,
    response: Option<&HttpResponseSummary>,
    response_json: Option<&Value>,
    response_json_parse_error: Option<&str>,
    fault: Option<&SoapFault>,
    downstream_error: Option<&DownstreamHttpError>,
    downstream_errors: &[DownstreamHttpError],
    error: Option<&str>,
) -> Value {
    json!({
        "toolName": tool_name,
        "profile": profile_name,
        "soapVersion": version.as_str(),
        "soapAction": soap_action,
        "request": {
            "endpoint": endpoint,
            "xml": request_xml,
            "headers": request_headers,
        },
        "response": response.map(|r| json!({
            "durationMs": r.duration_ms,
            "statusCode": r.status_code,
            "contentType": r.content_type,
            "xml": r.body,
            "bodyTruncated": r.body_truncated,
            "json": response_json,
            "jsonParseError": response_json_parse_error,
        })),
        "fault": fault.map(fault_to_json),
        "downstreamError": downstream_error
            .map(|e| serde_json::to_value(e).expect("DownstreamHttpError is serializable")),
        "downstreamErrors": downstream_errors,
        "error": error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::SoapFault;

    fn sample_fault(code: &str) -> SoapFault {
        SoapFault {
            code: code.to_owned(),
            reason: "boom".to_owned(),
            node: None,
            role: None,
            detail: Some("<e>x</e>".to_owned()),
            subcodes: vec![],
        }
    }

    #[test]
    fn receiver_fault_is_retryable() {
        let err = soap_fault_downstream_error(&sample_fault("env:Receiver"), 500);
        assert_eq!(err.kind, "soap_fault");
        assert!(err.retryable);
        assert_eq!(err.status_code, Some(500));
        assert_eq!(err.message, "boom");
    }

    #[test]
    fn sender_fault_is_not_retryable() {
        let err = soap_fault_downstream_error(&sample_fault("soap:Client"), 500);
        assert!(!err.retryable);
        assert_eq!(err.suggested_action, "inspect_soap_fault_detail");
    }

    #[test]
    fn envelope_surfaces_downstream_error_for_fault() {
        let fault = sample_fault("soap:Server");
        let dse = soap_fault_downstream_error(&fault, 500);
        let env = build_result_envelope(
            "GetWeather",
            "weather",
            SoapVersion::V11,
            Some("urn:GetWeather"),
            "https://svc/weather",
            "<soap:Envelope/>",
            &BTreeMap::new(),
            None,
            None,
            None,
            Some(&fault),
            Some(&dse),
            std::slice::from_ref(&dse),
            None,
        );
        assert_eq!(env["soapVersion"], json!("1.1"));
        assert_eq!(env["fault"]["code"], json!("soap:Server"));
        assert!(!env["downstreamError"].is_null());
        assert_eq!(env["downstreamError"]["kind"], json!("soap_fault"));
    }
}
