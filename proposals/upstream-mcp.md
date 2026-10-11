# Discussion draft: optional subscription persistence profile

Status: independent discussion draft; not submitted upstream.

## Problem

MCP Events defines interoperable subscribe/unsubscribe and delivery behavior.
Implementers still need a subscription representation, secret storage, lease
validation, and migration rules. Repeating that work makes reusable storage
adapters and cross-language implementations harder to build.

## Proposed contribution

Publish an optional webhook subscription JSON Schema with explicit field
semantics, and a separate JWE profile for deployments that store sensitive
subscription records outside their own database. Include examples and shared
accept/reject and encryption vectors. Existing servers can continue using their
own schemas; adoption is not required for protocol interoperability.

## Evidence and limits

The Appwrite MCP implementation stores encrypted subscription state in each
project webhook's write-only authentication password. This is one motivating
use case, not evidence that every provider needs encrypted envelopes. A second
independent implementation should exercise the schema before stabilization.

The profile does not make tenant identities portable without mapping, make
storage APIs atomic, supply durable delivery, or solve authorization revocation.
It must not be described as fixing all persistence or lifecycle problems.

## Open questions

1. Should the record schema and encrypted profile be separate projects?
2. Should the secret be inline, a secret-store reference, or two explicit profiles?
3. Is the restricted UTC timestamp representation useful across languages?
4. What migration/export use case would justify requiring more identity fields?
5. Which adapter lifecycle guarantees deserve protocol-level clarification?
6. Should a future version model a replay cursor or overlapping secret rotation?
7. Can another provider use the record unchanged with a different storage adapter?

## Adoption path

Exercise the Python implementation and vectors, add an independent language or
provider implementation, document incompatible assumptions, and then open an
upstream discussion. Do not claim adoption before that review.
