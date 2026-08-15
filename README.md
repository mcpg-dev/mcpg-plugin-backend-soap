# `mcpg-plugin-backend-soap`

SOAP backend binding plugin for mcpg (`kind: soap`). Dispatches tool
calls as **SOAP 1.1 / 1.2** envelopes over outbound HTTP, so legacy SOAP
web services can be surfaced as MCP **tools**, **resources**, and
**pipeline steps**.

It is a runtime-loaded cdylib (like `http` / `grpc` / `graphql`) and
reuses the shared `net-core` HTTP-over-reqwest core — per-credential
`reqwest::Client` caching, the DNS-rebinding / SSRF guard, body-limit
truncation, CEL templating of the endpoint + headers, and per-caller
`cred://` resolution — unchanged. SOAP adds only XML **envelope
construction**, **Fault parsing**, and the structured response envelope.

## How it works

One binding = one SOAP operation = one MCP tool. Per call:

1. Tool arguments are CEL-interpolated into `body_template` (and
   `header_template`); interpolated **string values are XML-escaped** so
   the envelope stays well-formed (defends against XML injection).
2. The fragment is wrapped in a version-appropriate `<soap:Envelope>`.
3. The envelope is POSTed to `endpoint` with the right `Content-Type`,
   the `SOAPAction` header (1.1) or `action=` Content-Type parameter
   (1.2), and W3C trace headers.
4. The response is read under `max_response_bytes`, scanned for a
   `<soap:Fault>`, and projected into a structured JSON envelope (with a
   best-effort XML→JSON view for MCP structured content).

A `<soap:Fault>` (HTTP 500 carrying a fault body, 1.1 — or 500/400, 1.2)
is classified as an **application fault**, not a transport error: it
populates `fault` + `downstreamError` (which the gateway reads to set
`isError: true`), so callers get a clean error with retry guidance
rather than an opaque 500.

## Configuration

| Field | Type | Default | Notes |
|---|---|---|---|
| `endpoint` | string (required) | — | `http(s)://` URL. CEL + `cred://` apply. |
| `soap_version` | `"1.1"` \| `"1.2"` | `"1.1"` | Drives namespace, Content-Type, action placement. |
| `soap_action` | string | — | SOAPAction URI. CEL ok; **no `cred://`**. |
| `body_template` | string (required) | — | XML for `<soap:Body>`. CEL `${arguments.*}`, values XML-escaped. |
| `header_template` | string | — | XML for `<soap:Header>` (WS-Addressing, …). |
| `headers` | map | `{}` | Extra HTTP headers. CEL + `cred://` (put transport auth here). |
| `expected_status_codes` | `[u16]` | `[200]` | Fault-free responses outside this set are flagged. Faults are detected regardless of status. |
| `max_response_bytes` | int | `1048576` | Response cap (XML > JSON; 1 MiB vs the http backend's 64 KiB). |
| `timeout_ms` | int | `30000` | SOAP services are slower than REST; 30 s default. |

### As a tool

```yaml
mcp:
  capabilities:
    tools:
      - name: GetWeather
        description: Current weather for a city via the legacy SOAP service.
        input_schema:
          type: object
          properties: { city: { type: string } }
          required: [city]
        backend:
          kind: soap
          endpoint: https://weather.example.com/ws/WeatherService
          soap_version: "1.1"
          soap_action: "http://weather.example.com/GetWeather"
          body_template: |
            <wsx:GetWeather xmlns:wsx="http://weather.example.com/">
              <City>${arguments.city}</City>
            </wsx:GetWeather>
          headers:
            Authorization: "Bearer ${cred://oauth/weather}"
```

### As a resource

A read-only operation can be exposed under `mcp.capabilities.resources[]` /
`mcp.capabilities.resource_templates[]`; a `resources/read` routes through the same
`execute` path:

```yaml
mcp:
  capabilities:
    resources:
      - uri: "soap://weather/berlin"
        mime_type: application/json
        backend:
          kind: soap
          endpoint: https://weather.example.com/ws/WeatherService
          soap_action: "http://weather.example.com/GetWeather"
          body_template: '<wsx:GetWeather xmlns:wsx="http://weather.example.com/"><City>Berlin</City></wsx:GetWeather>'
```

### As a pipeline step

```yaml
backend:
  kind: pipeline
  steps:
    - kind: soap
      id: lookup
      endpoint: https://legacy.example.com/ws/Orders
      soap_action: "urn:GetOrder"
      body_template: '<o:GetOrder xmlns:o="urn:orders"><Id>${arguments.id}</Id></o:GetOrder>'
    - kind: transform
      id: shape
      expression: "{ status: steps.lookup.output.response.json }"
```

Later steps read this step's structured output via
`steps.<id>.output` (the response envelope described below).

## Response envelope

`tools/call` structured content (the `BackendResponse.payload`):

```jsonc
{
  "toolName": "GetWeather",
  "profile": "GetWeather",
  "soapVersion": "1.1",
  "soapAction": "http://weather.example.com/GetWeather",
  "request":  { "endpoint": "...", "xml": "<soap:Envelope>…", "headers": { … } },
  "response": { "statusCode": 200, "contentType": "text/xml", "xml": "…",
                "bodyTruncated": false, "json": { … }, "jsonParseError": null },
  "fault": null,                 // or { code, reason, node, role, detail, subcodes }
  "downstreamError": null,       // non-null ⇒ isError:true (soap_fault / unexpected_status_code / transport_error)
  "downstreamErrors": [],
  "error": null
}
```

## Security

- **`cred://` boundary.** `cred://` resolves only in `endpoint` and HTTP
  `headers` (per-caller, via the net-core ClientRegistry). It is
  **rejected** in `soap_action` / `body_template` / `header_template` —
  put transport credentials in an `Authorization` header. (In-body
  WS-Security secret injection is deferred — see `DEFERRED.md`.)
- **SSRF / DNS rebinding.** The shared guard rejects endpoints that
  resolve to private/loopback addresses unless `allow_private_backends`
  is set for the binding; the resolved address is pinned per cached
  client.
- **XML injection.** Argument string values are XML-escaped before
  interpolation into the body/header templates.

## Build / test

```bash
nx build mcpg-plugin-backend-soap          # cdylib + rlib
nx test  mcpg-plugin-backend-soap          # unit tests
nx integration mcpg-plugin-backend-soap    # wiremock end-to-end tests
nx lint  mcpg-plugin-backend-soap          # clippy -D warnings
```

## Scope

v1 declares operations explicitly. WSDL-driven auto-generation of tools
is deferred (it would layer over the same per-operation structures via
`expand_capabilities`).
