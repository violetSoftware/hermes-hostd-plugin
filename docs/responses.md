# Response validation and resource boundary

The bundled client requires an object with `id` (string) and `approved` (actual
JSON boolean). Optional `exit_code` is an integer excluding booleans, or null;
`stdout`/`stderr` are strings; `error`/`log_id` are strings or null;
`output_truncated` and an additive `persistent_intent` are strict booleans.
Absent optional fields retain their documented defaults for older daemons.
Duplicate JSON keys, non-JSON constants, malformed/deep JSON and invalid UTF-8
are rejected. The response ID must equal the sent request ID exactly.

Compatible unknown metadata is retained and reserialized, never interpreted as
authority. Known fields cannot be overridden by additive metadata. Log IDs and
truncation indicators now survive the actual tool response. Persistent intent
remains request/approval metadata, not supervision or a cleanup exemption; if a
future result includes it, it is retained only with the correct boolean type.

`max_response_bytes` is a positive integer in public plugin settings or the flat
compatibility file (file wins), or in the library constructors/factory. The
default is 1,048,576 bytes (1 MiB), including whitespace and the VSOCK terminating
newline. There is no unlimited value. It accommodates both current 16 KiB daemon
output tails even with worst-case JSON escaping and replacement characters,
plus ordinary error/ID/log metadata. An unusually large server error or future
metadata can still exceed the limit and will fail closed; an operator may select
a different finite ceiling. This is not a new job timeout policy.

Both HTTP and VSOCK request at most 4,096 bytes per read, and at most the remaining
budget plus a one-byte oversize probe. At most the ceiling is accumulated before
UTF-8 decoding/JSON parsing. Oversize replies close the transport without parsing
or echoing the body. Underlying HTTP/socket buffering has its own fixed protocol
buffers; this bounds application body accumulation, not total process RSS.
HTTP errors/redirects are closed without reading their bodies. Timeouts, proxy/TLS
handling and no-redirect behavior remain unchanged.

Local validation failures return `approved: false`, the sent ID and a fixed,
bounded diagnostic; raw response data and arbitrary exception strings are not
echoed. Server-supplied valid stdout/stderr/error/metadata remain untrusted data
and may themselves contain secrets: this is not output-content redaction.
Validation establishes schema/correlation/resource bounds, not honest execution,
server identity, channel encryption or authenticated human approval. A malicious
peer can copy an ID and fabricate a well-typed result. Do not retry an uncertain
execution automatically.
