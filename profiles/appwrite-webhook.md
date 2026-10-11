# Appwrite webhook storage profile — draft mapping

This profile illustrates storing an encrypted subscription in an upstream
webhook. It is documentation only; this repository has no live Appwrite adapter.

| Appwrite field | Proposed mapping |
| --- | --- |
| Webhook ID | Record `id`, constrained to Appwrite's identifier rules |
| `url` | Server ingress URL for that webhook |
| `events` | Narrow Appwrite patterns derived from event arguments |
| `enabled`, `tls` | `true` |
| `authUsername` | Fixed nonempty value, e.g. `mcp-events` |
| `authPassword` | Full JWE Compact envelope |
| `secret` | Independently managed Appwrite-to-ingress signing key |
| `name` | Human-readable label; any cleanup metadata needs concurrency protection |

Envelope context binds the configured server identity, project ID as `tenant`,
and webhook ID as `resource`. Expected tenant/resource must come from an
adapter-authenticated request, not unverified caller input. The ingress must
verify Appwrite's webhook signature as well as opening the envelope.

Appwrite sends `authUsername:authPassword` in HTTP Basic auth on webhook delivery;
the body remains the ordinary Appwrite event body. Basic auth base64 is encoding,
not encryption; HTTPS is required. The receiving server opens the envelope and
uses the recovered callback configuration to send an MCP notification.

## Constraints to resolve before implementing

- `authPassword` is write-only. It cannot be used as a general read/update store.
- Measure every supported record and JWE against the deployed API/database
  password limits. The core's 64 KiB bound is not an Appwrite compatibility claim.
  [Appwrite #14293](https://github.com/appwrite/appwrite/issues/14293) tracks
  password storage limitations relevant to the existing MCP implementation.
- Updating webhook configuration and its signing secret can require separate
  writes. Coordinate refreshes, use an atomic API if available, or decouple the
  signing key from envelope-key rotation with a separate key lifecycle. Do not
  assume successful sequential writes are safe under concurrent replicas.
- An expired label from an earlier list result is insufficient authority to
  delete. Re-reading reduces the window but is not atomic protection; use
  conditional deletion or equivalent coordination with refreshes.
- Existing `v1.<kid>.<payload>` MCP envelopes are not JWE. Migration needs explicit
  dual readers and a writer cutover, with retirement based on actual leases.
- Ordinary JSON Schema validation does not prove OAuth access or ownership.

[Example configuration](../examples/appwrite-webhook.json) is illustrative and
uses synthetic secrets. No Appwrite network calls are made by the reference
implementation or tests.
