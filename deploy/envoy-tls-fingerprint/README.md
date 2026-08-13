# Trusted TLS fingerprint collector

This sample terminates direct client TLS in Envoy, computes JA3 and JA4 from
the ClientHello, overwrites any client-supplied fingerprint headers, and sends
the validated values to the defense origin.

- Mount the certificate and key at `/etc/envoy/tls/tls.crt` and
  `/etc/envoy/tls/tls.key`.
- Resolve `defense-origin` to the protected service or change that cluster
  address.
- Configure the origin to trust only the Envoy address/CIDR as a proxy.
- Do not expose the origin directly, because direct clients must not be able to
  assert `X-ASD-TLS-JA3` or `X-ASD-TLS-JA4`.

When Cloudflare terminates client TLS, the origin cannot recreate the original
fingerprint. JA3 and JA4 are Enterprise Bot Management fields, not automatic
origin headers. A Worker must delete visitor-supplied copies and populate
`cf-ja3-hash` and `cf-ja4` from `request.cf.botManagement`; the origin must also
be isolated with account-scoped Authenticated Origin Pulls, a Tunnel, or
validated Cloudflare CIDRs. Missing Bot Management values remain unverified and
do not fail startup. See [the full attestation design](../../docs/TLS_FINGERPRINT_ATTESTATION.md).
