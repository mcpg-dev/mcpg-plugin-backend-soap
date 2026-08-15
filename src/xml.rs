//! SOAP envelope construction + response / Fault parsing.
//!
//! This is the only SOAP-specific machinery the plugin adds over the
//! shared `net-core` HTTP transport:
//!
//! - [`escape_arguments`] — XML-escapes the string leaves of the
//!   tool-call arguments so CEL `${arguments.*}` interpolation into the
//!   body template stays well-formed (defends against XML injection).
//! - [`build_envelope`] — wraps the rendered `<soap:Body>` (and optional
//!   `<soap:Header>`) in a version-appropriate `<soap:Envelope>`.
//! - [`parse_fault`] — detects a `<soap:Fault>` in the response and
//!   extracts its code / reason / detail for both SOAP 1.1 and 1.2.
//! - [`xml_to_json`] — best-effort generic XML → JSON so the gateway can
//!   surface the response as MCP structured content.

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::QName;
use serde_json::{Map, Value};

use crate::types::SoapVersion;

/// Local name of a `QName`, namespace prefix stripped, as an owned
/// `String`. Used for both element matching (Fault detection) and JSON
/// key derivation (so `tns:GetWeatherResponse` keys as
/// `GetWeatherResponse`).
fn qname_local(name: QName<'_>) -> String {
    String::from_utf8_lossy(name.local_name().as_ref()).into_owned()
}

/// Recursively XML-escape every string leaf of a JSON value, leaving
/// numbers / bools / null untouched. The result feeds a *separate* CEL
/// context used only for body / header template rendering, so headers
/// and the endpoint URL (which need the raw, un-escaped values) are
/// unaffected. Interpolating an escaped value into XML text or an
/// attribute keeps the envelope well-formed even when an argument
/// carries `<`, `&`, or quotes.
pub fn escape_arguments(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(quick_xml::escape::escape(s).into_owned()),
        Value::Array(items) => Value::Array(items.iter().map(escape_arguments).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), escape_arguments(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Assemble the full SOAP request envelope. `body_xml` is the rendered
/// (CEL-evaluated, arg-escaped) contents of `<soap:Body>`; `header_xml`
/// is the optional rendered contents of `<soap:Header>`. The operator
/// owns the service-specific element namespaces inside these fragments;
/// this only adds the standard envelope wrapper with the
/// version-appropriate namespace.
pub fn build_envelope(version: SoapVersion, header_xml: Option<&str>, body_xml: &str) -> String {
    let ns = version.envelope_namespace();
    let mut out = String::with_capacity(body_xml.len() + 256);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    out.push_str("<soap:Envelope xmlns:soap=\"");
    out.push_str(ns);
    out.push_str("\">");
    if let Some(header) = header_xml {
        let trimmed = header.trim();
        if !trimmed.is_empty() {
            out.push_str("<soap:Header>");
            out.push_str(trimmed);
            out.push_str("</soap:Header>");
        }
    }
    out.push_str("<soap:Body>");
    out.push_str(body_xml.trim());
    out.push_str("</soap:Body>");
    out.push_str("</soap:Envelope>");
    out
}

/// A parsed SOAP Fault. Field names are normalised across SOAP 1.1
/// (`faultcode` / `faultstring` / `faultactor`) and 1.2 (`Code/Value` /
/// `Reason/Text` / `Node` / `Role` / `Subcode`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoapFault {
    /// `faultcode` (1.1) or the top `Code/Value` (1.2), verbatim
    /// (namespace prefix retained, e.g. `soap:Server` / `env:Receiver`).
    pub code: String,
    /// `faultstring` (1.1) or `Reason/Text` (1.2).
    pub reason: String,
    /// `faultactor` (1.1) or `Node` (1.2).
    pub node: Option<String>,
    /// `Role` (1.2 only).
    pub role: Option<String>,
    /// Concatenated text content of `<detail>` / `<Detail>` (best
    /// effort — nested element structure is flattened; the full
    /// response XML is always preserved separately in the envelope).
    pub detail: Option<String>,
    /// Nested `Subcode/Value` chain (1.2 only).
    pub subcodes: Vec<String>,
}

impl SoapFault {
    /// SOAP faults split into caller-fault (1.1 `Client`, 1.2 `Sender`)
    /// vs. receiver-fault (1.1 `Server`, 1.2 `Receiver`). Receiver
    /// faults are transient server-side conditions and so retryable;
    /// sender faults are caller contract violations and are not.
    /// Unknown codes default to non-retryable (conservative).
    pub fn is_retryable(&self) -> bool {
        let code = self.code.to_ascii_lowercase();
        code.contains("server") || code.contains("receiver")
    }
}

/// Scan a response body for a `<soap:Fault>` and extract it. Matches the
/// `Fault` element by local name (namespace-agnostic) so it tolerates
/// any envelope prefix. Returns `None` when no Fault is present or the
/// body is not parseable as XML.
pub fn parse_fault(body: &str, _version: SoapVersion) -> Option<SoapFault> {
    let mut reader = Reader::from_str(body);
    let mut path: Vec<String> = Vec::new();
    let mut fault_depth: Option<usize> = None;
    let mut code = String::new();
    let mut reason = String::new();
    let mut node: Option<String> = None;
    let mut role: Option<String> = None;
    let mut detail: Option<String> = None;
    let mut subcodes: Vec<String> = Vec::new();
    let mut code_value_captured = false;
    let mut in_detail = false;
    let mut detail_buf = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let local = qname_local(e.name());
                path.push(local.clone());
                if local == "Fault" && fault_depth.is_none() {
                    fault_depth = Some(path.len());
                }
                if fault_depth.is_some() && !in_detail && (local == "detail" || local == "Detail") {
                    in_detail = true;
                    detail_buf.clear();
                }
            }
            Ok(Event::Text(t)) => {
                if let Some(depth) = fault_depth {
                    let text = t.xml_content().map(|c| c.into_owned()).unwrap_or_default();
                    if in_detail {
                        detail_buf.push_str(&text);
                    } else if !text.trim().is_empty() {
                        assign_fault_field(
                            &path,
                            depth,
                            text.trim(),
                            &mut code,
                            &mut reason,
                            &mut node,
                            &mut role,
                            &mut subcodes,
                            &mut code_value_captured,
                        );
                    }
                }
            }
            Ok(Event::End(e)) => {
                let local = qname_local(e.name());
                if in_detail && (local == "detail" || local == "Detail") {
                    in_detail = false;
                    let trimmed = detail_buf.trim();
                    if !trimmed.is_empty() {
                        detail = Some(trimmed.to_owned());
                    }
                }
                let closing_fault =
                    matches!(fault_depth, Some(depth) if path.len() == depth && local == "Fault");
                path.pop();
                if closing_fault {
                    break;
                }
            }
            Ok(Event::Eof) => break,
            // Malformed XML: report no fault and let the caller fall back
            // to status-code classification + the raw response XML.
            Err(_) => return None,
            _ => {}
        }
    }

    fault_depth.map(|_| SoapFault {
        code,
        reason,
        node,
        role,
        detail,
        subcodes,
    })
}

/// Route a text node to the right [`SoapFault`] field based on its
/// element path within the Fault. Handles both the flat SOAP 1.1 child
/// elements and the nested SOAP 1.2 `Code/Value`, `Reason/Text`, and
/// `Subcode/Value` shapes.
#[allow(clippy::too_many_arguments)]
fn assign_fault_field(
    path: &[String],
    fault_depth: usize,
    text: &str,
    code: &mut String,
    reason: &mut String,
    node: &mut Option<String>,
    role: &mut Option<String>,
    subcodes: &mut Vec<String>,
    code_value_captured: &mut bool,
) {
    let parent = path.last().map(String::as_str).unwrap_or("");
    let grandparent = if path.len() >= 2 {
        path[path.len() - 2].as_str()
    } else {
        ""
    };
    match parent {
        // SOAP 1.1
        "faultcode" => *code = text.to_owned(),
        "faultstring" => *reason = text.to_owned(),
        "faultactor" => *node = Some(text.to_owned()),
        // SOAP 1.2
        "Value" if grandparent == "Code" => {
            if !*code_value_captured {
                *code = text.to_owned();
                *code_value_captured = true;
            }
        }
        "Value" if grandparent == "Subcode" => subcodes.push(text.to_owned()),
        "Text" if grandparent == "Reason" => *reason = text.to_owned(),
        "Node" => *node = Some(text.to_owned()),
        "Role" => *role = Some(text.to_owned()),
        _ => {
            // Inside Fault but not a recognised slot. Ignore — the full
            // response XML is preserved in the envelope regardless.
            let _ = fault_depth;
        }
    }
}

/// Best-effort generic XML → JSON conversion of a response body, so the
/// gateway can project the SOAP response as MCP structured content.
///
/// Mapping: each element becomes an object keyed by child local-names
/// (namespace prefixes stripped); repeated child names collapse to an
/// array; attributes become `@name` keys; leaf text becomes a string
/// (or `#text` alongside attributes/children). This is intentionally
/// lossy (mixed content, ordering, namespaces) — the verbatim response
/// XML is always available separately in the envelope's `response.xml`.
pub fn xml_to_json(body: &str) -> Result<Value, String> {
    let mut reader = Reader::from_str(body);
    loop {
        match reader.read_event().map_err(|e| e.to_string())? {
            Event::Start(e) => {
                let name = qname_local(e.name());
                let value = read_element(&mut reader, &e)?;
                let mut root = Map::new();
                root.insert(name, value);
                return Ok(Value::Object(root));
            }
            Event::Empty(e) => {
                let name = qname_local(e.name());
                let value = empty_element_value(&e)?;
                let mut root = Map::new();
                root.insert(name, value);
                return Ok(Value::Object(root));
            }
            Event::Eof => return Err("no root element in XML".to_owned()),
            _ => {}
        }
    }
}

/// Read one element (its `Start` already consumed) to its matching
/// `End`, returning the JSON value for its subtree.
fn read_element(reader: &mut Reader<&[u8]>, start: &BytesStart<'_>) -> Result<Value, String> {
    let mut obj = Map::new();
    let mut has_attr = false;
    for attr in start.attributes() {
        let attr = attr.map_err(|e| e.to_string())?;
        let key = qname_local(attr.key);
        let val = attr
            .unescape_value()
            .map_err(|e| e.to_string())?
            .into_owned();
        obj.insert(format!("@{key}"), Value::String(val));
        has_attr = true;
    }

    let mut text = String::new();
    let mut children: Vec<(String, Value)> = Vec::new();
    loop {
        match reader.read_event().map_err(|e| e.to_string())? {
            Event::Start(e) => {
                let name = qname_local(e.name());
                let child = read_element(reader, &e)?;
                children.push((name, child));
            }
            Event::Empty(e) => {
                let name = qname_local(e.name());
                let child = empty_element_value(&e)?;
                children.push((name, child));
            }
            Event::Text(t) => {
                let chunk = t.xml_content().map_err(|e| e.to_string())?;
                text.push_str(chunk.as_ref());
            }
            Event::CData(t) => {
                text.push_str(t.decode().map_err(|e| e.to_string())?.as_ref());
            }
            Event::End(_) => break,
            Event::Eof => return Err("unexpected EOF inside XML element".to_owned()),
            _ => {}
        }
    }

    if children.is_empty() && !has_attr {
        return Ok(Value::String(text.trim().to_owned()));
    }
    for (name, val) in children {
        if let Some(existing) = obj.get_mut(&name) {
            if let Value::Array(arr) = existing {
                arr.push(val);
            } else {
                let old = std::mem::replace(existing, Value::Null);
                *existing = Value::Array(vec![old, val]);
            }
        } else {
            obj.insert(name, val);
        }
    }
    let trimmed = text.trim();
    if !trimmed.is_empty() {
        obj.insert("#text".to_owned(), Value::String(trimmed.to_owned()));
    }
    Ok(Value::Object(obj))
}

/// Value for a self-closing element: its attributes as `@name` keys, or
/// the empty string when it has none.
fn empty_element_value(e: &BytesStart<'_>) -> Result<Value, String> {
    let mut obj = Map::new();
    for attr in e.attributes() {
        let attr = attr.map_err(|x| x.to_string())?;
        let key = qname_local(attr.key);
        let val = attr
            .unescape_value()
            .map_err(|x| x.to_string())?
            .into_owned();
        obj.insert(format!("@{key}"), Value::String(val));
    }
    if obj.is_empty() {
        Ok(Value::String(String::new()))
    } else {
        Ok(Value::Object(obj))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn escapes_string_leaves_only() {
        let escaped = escape_arguments(&json!({
            "name": "a<b>&\"c\"",
            "count": 7,
            "nested": { "x": "<y>" },
            "list": ["<a>", 2]
        }));
        assert_eq!(escaped["name"], json!("a&lt;b&gt;&amp;&quot;c&quot;"));
        assert_eq!(escaped["count"], json!(7));
        assert_eq!(escaped["nested"]["x"], json!("&lt;y&gt;"));
        assert_eq!(escaped["list"][0], json!("&lt;a&gt;"));
        assert_eq!(escaped["list"][1], json!(2));
    }

    #[test]
    fn builds_11_envelope_with_header() {
        let env = build_envelope(
            SoapVersion::V11,
            Some("<wsa:To>urn:x</wsa:To>"),
            "<tns:Ping/>",
        );
        assert!(env.contains("xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\""));
        assert!(env.contains("<soap:Header><wsa:To>urn:x</wsa:To></soap:Header>"));
        assert!(env.contains("<soap:Body><tns:Ping/></soap:Body>"));
    }

    #[test]
    fn builds_12_envelope_without_empty_header() {
        let env = build_envelope(SoapVersion::V12, Some("   "), "<tns:Ping/>");
        assert!(env.contains("xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\""));
        assert!(!env.contains("<soap:Header>"));
    }

    #[test]
    fn parses_soap_11_fault() {
        let body = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Body>
            <soap:Fault>
              <faultcode>soap:Server</faultcode>
              <faultstring>Backend exploded</faultstring>
              <faultactor>http://svc/actor</faultactor>
              <detail><e:Err xmlns:e="urn:e">boom</e:Err></detail>
            </soap:Fault>
          </soap:Body>
        </soap:Envelope>"#;
        let fault = parse_fault(body, SoapVersion::V11).expect("fault");
        assert_eq!(fault.code, "soap:Server");
        assert_eq!(fault.reason, "Backend exploded");
        assert_eq!(fault.node.as_deref(), Some("http://svc/actor"));
        assert!(fault.detail.as_deref().unwrap().contains("boom"));
        assert!(fault.is_retryable());
    }

    #[test]
    fn parses_soap_12_fault() {
        let body = r#"<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
          <env:Body>
            <env:Fault>
              <env:Code>
                <env:Value>env:Sender</env:Value>
                <env:Subcode><env:Value>rpc:BadArguments</env:Value></env:Subcode>
              </env:Code>
              <env:Reason><env:Text xml:lang="en">Bad arguments</env:Text></env:Reason>
              <env:Node>http://svc/node</env:Node>
              <env:Role>http://svc/role</env:Role>
            </env:Fault>
          </env:Body>
        </env:Envelope>"#;
        let fault = parse_fault(body, SoapVersion::V12).expect("fault");
        assert_eq!(fault.code, "env:Sender");
        assert_eq!(fault.reason, "Bad arguments");
        assert_eq!(fault.node.as_deref(), Some("http://svc/node"));
        assert_eq!(fault.role.as_deref(), Some("http://svc/role"));
        assert_eq!(fault.subcodes, vec!["rpc:BadArguments".to_owned()]);
        assert!(!fault.is_retryable());
    }

    #[test]
    fn no_fault_returns_none() {
        let body = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Body><tns:Ok xmlns:tns="urn:t">fine</tns:Ok></soap:Body>
        </soap:Envelope>"#;
        assert!(parse_fault(body, SoapVersion::V11).is_none());
    }

    #[test]
    fn malformed_xml_returns_none() {
        assert!(parse_fault("<not<xml", SoapVersion::V11).is_none());
    }

    #[test]
    fn xml_to_json_maps_nested_and_repeated() {
        let body = r#"<tns:Resp xmlns:tns="urn:t" total="2">
          <Item id="1">a</Item>
          <Item id="2">b</Item>
          <Note>hi</Note>
        </tns:Resp>"#;
        let json = xml_to_json(body).expect("json");
        let resp = &json["Resp"];
        assert_eq!(resp["@total"], json!("2"));
        assert!(resp["Item"].is_array());
        assert_eq!(resp["Item"][0]["@id"], json!("1"));
        assert_eq!(resp["Item"][0]["#text"], json!("a"));
        assert_eq!(resp["Note"], json!("hi"));
    }
}
