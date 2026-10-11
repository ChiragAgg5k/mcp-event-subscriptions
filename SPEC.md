# Subscription Record v1 — experimental draft

This document defines an optional persistence representation for webhook
subscriptions. It is independent of the MCP wire protocol. MUST, SHOULD, and
MAY express requirements for implementations claiming this draft profile; they
are not additional requirements imposed on all MCP servers.

## Record

A record MUST be a JSON object conforming to
[`subscription-v1.schema.json`](schemas/subscription-v1.schema.json) and the
semantic rules below. Unknown fields MUST be rejected outside `extensions`.
JSON parsers MUST reject duplicate object keys and non-finite numbers.

| Field | Meaning |
| --- | --- |
| `version` | Integer `1`; unsupported versions MUST be rejected. |
| `id` | Nonempty, opaque subscription identifier scoped to its issuing server. |
| `principal` | Nonempty, opaque canonical owner identifier. It MUST NOT contain bearer or refresh tokens. |
| `event.name` | Event type advertised by the issuing server. |
| `event.arguments` | JSON object; the adapter MUST validate it against that event's published input schema. |
| `delivery.mode` | `webhook` in v1. |
| `delivery.url` | Absolute HTTPS callback URL without user information or fragment. |
| `delivery.secret` | `whsec_` followed by canonical padded standard base64 for 24–64 decoded bytes. |
| `lease.expiresAt` | Actual expiry, or `null` for an explicitly granted no-expiry subscription. |
| `lease.refreshBefore` | Suggested refresh deadline, or `null` together with `expiresAt`. |
| `extensions` | Optional object with namespaced keys such as `io.appwrite.source`. |

Timestamps MUST be UTC RFC 3339 strings using `Z`, with seconds and optionally
1–6 fractional digits. A finite `refreshBefore` MUST be at or before `expiresAt`.
At the expiry instant the subscription is expired. No-expiry records MUST have
both lease fields set to `null`; granting them requires durable storage and an
explicit no-expiry request at the protocol layer. The schema permits this
representation; it does not grant such a lease by itself.

Record validation is separate from activation. A stored record may be expired;
a consumer MUST check expiry before using it for delivery. The reference
`open_envelope` checks expiry by default.

The record MUST contain JSON values only. The reference implementation limits
encoded records and envelopes to 64 KiB each; adapters MAY impose lower limits.
This draft has no compression profile.

## Identity and authorization

The adapter MUST preserve MCP's logical identity based on principal, callback,
event name, and arguments. This draft does not prescribe a hash algorithm or
identifier syntax. Importing a record MUST NOT grant access: the receiving
server MUST establish tenant/resource ownership and current authorization.
Principal identifiers are server-scoped; cross-server migration requires an
explicit identity mapping and reauthorization, not merely copying JSON.

## Extensions

An extension key MUST have a reverse-domain namespace followed by a name,
for example `io.appwrite.source`. Core consumers MAY preserve extensions they
do not understand, but MUST NOT depend on them to establish security. A future
required extension needs a new profile or version with explicit negotiation.

## Storage and lifecycle

This record is a snapshot. It is not proof that a subscription remains live.
The storage adapter MUST define:

1. An atomic upsert or coordination mechanism for concurrent refreshes.
2. Conditional expiry cleanup, so a stale snapshot cannot delete a renewed lease.
3. Revocation semantics and the treatment of deliveries already in flight.
4. How callback secret changes coexist with retries signed using an old secret.
5. Lease durability and recovery guarantees.

A generation number alone provides no protection without compare-and-swap or
equivalent enforcement. Version 1 deliberately has no unenforced revision field.
The encrypted profile authenticates a snapshot but cannot prove its freshness.

## Versioning

Adding required fields, changing field meaning, or changing validation rules
requires a new record version. Readers MUST reject unsupported versions rather
than guessing. This experimental draft may change before a stable release.

## Related work

- [MCP Events design sketch](https://github.com/modelcontextprotocol/experimental-ext-triggers-events/blob/main/docs/design-sketch-proposal.md)
- [SEP-3415 discussion](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3415)
- [JSON Schema](https://json-schema.org/draft/2020-12)

The proposal's value is a reusable persistence representation and test suite;
it does not claim that internal database schemas must be standardized for MCP
clients and servers to interoperate.
