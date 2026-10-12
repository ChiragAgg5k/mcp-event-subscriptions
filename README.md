# MCP Event Subscriptions

An experimental, portable subscription record for MCP Events, with an optional
[JWE](https://www.rfc-editor.org/rfc/rfc7516) encrypted envelope.

Store the same record in a database, a key-value store, or an upstream webhook
configuration. This repository defines its fields, encrypted encoding, and
validation rules, with a Python reference implementation and conformance vectors.

**Independent proposal. This is not an adopted MCP specification or an IETF RFC.**
The format may change before a stable release. It does not change MCP event
requests or notification payloads.

## What is here

- [Record specification](SPEC.md) and [JSON Schema](schemas/subscription-v1.schema.json).
- [Encrypted envelope profile](profiles/encrypted-envelope.md): JWE Compact,
  `dir` + `A256GCM`, with explicit server/tenant/resource binding.
- [Appwrite webhook profile](profiles/appwrite-webhook.md): proposed storage
  mapping and the limits of write-only upstream state.
- [Examples](examples/) and [conformance vectors](test-vectors/README.md).
- [Python reference implementation](packages/python/README.md).
- [Upstream discussion draft](proposals/upstream-mcp.md).

## Install the alpha release

Available on [PyPI](https://pypi.org/project/mcp-event-subscriptions/0.1.0a1/) for Python 3.12 or newer:

```sh
pip install mcp-event-subscriptions==0.1.0a1
```

See [RELEASING.md](RELEASING.md) for the Trusted Publishing setup and release process.

## Quick start

Python 3.12 or newer and [uv](https://docs.astral.sh/uv/):

```sh
uv sync --group dev
uv run python examples/roundtrip.py
uv run python -m unittest discover -s tests -v
```

```python
import json
import secrets
from mcp_event_subscriptions import seal, open_envelope

record = json.load(open("examples/subscription.json"))
context = {
    "server": "https://mcp.example.com",
    "tenant": "project_demo",
    "resource": record["id"],
}
keys = {"k1": secrets.token_bytes(32)}
token = seal(record, keys, active_key="k1", context=context)
restored = open_envelope(token, keys, expected_context=context)
assert restored == record
```

The sample subscription expires in 2030. Examples and vectors use synthetic
principals and secrets. Fixed test-vector keys are public fixtures, never
production keys.

## Scope

Version 1 describes webhook and push subscription state and optional encrypted
storage.
It does not specify a SQL layout, implement a delivery queue, establish current
caller authorization, or make refresh/delete operations atomic. Adapters must
provide their own coordination and revocation checks. Encryption cannot detect
replay of an older, still-valid envelope without current state.

The Appwrite profile is documentation, not a working Appwrite adapter. It is not
wire-compatible with the existing `v1.<kid>.<ciphertext>` envelope in
[appwrite/mcp PR #132](https://github.com/appwrite/mcp/pull/132).

## Discussing the proposal

Start with the [open questions](proposals/upstream-mcp.md#open-questions): which
fields should be common, whether an encrypted profile belongs alongside the
schema, and what lifecycle guarantees adapters must expose. No proposal has
been submitted upstream by this repository.

## Development

```sh
uv run --group dev ruff check .
uv run --group dev black --check .
uv run python -m unittest discover -s tests -v
uv build
```

Licensed under the MIT License. See [SECURITY.md](SECURITY.md) before using the
reference implementation with real secrets.
