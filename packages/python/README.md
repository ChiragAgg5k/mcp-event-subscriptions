# Python reference implementation

The root `pyproject.toml` packages `packages/python/src/mcp_event_subscriptions`.
Install locally with `uv sync` or `pip install .` from the repository root.

```python
validate_subscription(record)  # structural and semantic checks; returns a copy
seal(record, keys, active_key="k1", context=context)
open_envelope(token, keys, expected_context=context)  # also rejects expiry
```

`keys` maps key IDs to dedicated 32-byte keys. `context` contains exactly
`server`, `tenant`, and `resource`. Opening uses the `kid` named in the protected
header. Missing keys, tampering, invalid records and context mismatches raise
`EnvelopeError`; expired records raise `ExpiredSubscription`. Invalid direct
record input raises `RecordError`. Keys must be generated randomly by the caller.

`open_envelope(..., now=datetime(..., tzinfo=UTC))` permits a supplied clock for
fixtures; normal consumers should use the default current clock. The function
does not contact the callback or check current upstream revocation state.
