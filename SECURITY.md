# Security

This repository is experimental and has not received an independent security
audit. Report security issues privately through GitHub's private vulnerability
reporting when available; otherwise use Appwrite's published security reporting
channel. Do not include production keys or subscription secrets in public issues.

## Trust boundaries

- Records contain sensitive callback signing secrets. Do not log plaintext,
  envelopes, Authorization headers, or decrypted errors with payloads.
- Use dedicated, random 256-bit encryption keys from a secret manager. Public
  fixture keys are intentionally insecure and must never be deployed.
- Expected envelope context must come from trusted server configuration and
  authenticated adapter routing. A token cannot establish its own tenant scope.
- A decrypted subscription does not prove present authorization or revocation
  status. Adapters must implement those checks and callback verification.
- Validate callback addresses at connection time, block internal destinations,
  preserve TLS hostname verification, and do not follow redirects. This library
  validates URL syntax only; it does not resolve DNS or perform outbound HTTP.
- Expiry limits validity; it does not prevent replay before expiry. Concurrent
  writes and stale cleanup require storage-level coordination.
- No-expiry subscriptions need durable revocation and key migration mechanisms.

The decoder limits token size, rejects duplicate keys/non-finite numbers, uses
an algorithm allowlist, and never fetches keys referenced by an envelope.
