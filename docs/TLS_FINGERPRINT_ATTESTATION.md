# Trusted TLS fingerprint attestation

JA3 and JA4 affect identity, detection, or audit provenance only after a
service proves that the values came from infrastructure which observed the
client TLS handshake. Syntax validation alone is not provenance.

## First trust hop

For direct Envoy termination, enable the TLS inspector's JA3 and JA4 options.
The sample Envoy configuration deletes visitor-supplied `X-ASD-TLS-*` headers
and overwrites them with `%TLS_JA3_FINGERPRINT%`, `%TLS_JA4_FINGERPRINT%`, and
source `envoy`. Configure only the Envoy workload CIDR in
`SECURITY_TRUSTED_PROXY_CIDRS` and prevent public access to the origin.

Cloudflare JA3/JA4 values require Enterprise Bot Management and are available
to Workers as `request.cf.botManagement.ja3Hash` and `.ja4`; they are not
automatic origin headers. A Worker must delete visitor-supplied copies and set
`cf-ja3-hash`/`cf-ja4` from those fields. Restrict the origin with an
account-scoped Authenticated Origin Pull certificate, a Cloudflare Tunnel, or
validated Cloudflare CIDRs in `SECURITY_CDN_TRUSTED_PROXY_CIDRS`. Missing Bot
Management fields simply produce no verified fingerprint and never fail
startup.

## Service binding

`cloud-proxy` accepts fingerprints only from a configured immediate proxy,
resolves the originating client IP from that same trust boundary, and signs
the normalized values before MCP forwarding. `escalation-engine` and the MCP
adapter discard caller-asserted verification state and recompute it.

The token is `v1:<unix-seconds>:<lowercase hex HMAC-SHA256>`. Its UTF-8 message
is eight newline-separated fields in this exact order: `v1`, decimal issued-at
seconds, lowercase client IP, uppercase method, exact path, normalized JA3 or
empty, normalized JA4 or empty, and lowercase source. Newline, carriage-return,
and NUL bytes are rejected. Verification recomputes the HMAC from the live
request context, compares in constant time, and enforces
`TLS_FINGERPRINT_ATTESTATION_MAX_AGE_SECONDS` (default 60). Thus a valid `GET /`
token cannot be replayed on `POST /admin`.

Set the same random key of at least 32 bytes as
`TLS_FINGERPRINT_ATTESTATION_KEY` on producers and consumers. For a rolling
rotation, deploy the new current key and the old value as
`TLS_FINGERPRINT_ATTESTATION_PREVIOUS_KEY` to downstream consumers, MCP before
escalation. Only after every consumer accepts both should upstream producers
switch. Producers sign only with current, while consumers accept either. Remove
the previous key after all producers have rolled and at least the maximum token
lifetime has elapsed.

References: [Envoy TLS inspector](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/listener/tls_inspector/v3/tls_inspector.proto.html),
[Envoy substitution formatter](https://www.envoyproxy.io/docs/envoy/latest/configuration/advanced/substitution_formatter.html),
[Cloudflare Bot Management variables](https://developers.cloudflare.com/bots/reference/bot-management-variables/), and
[Cloudflare Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/).
