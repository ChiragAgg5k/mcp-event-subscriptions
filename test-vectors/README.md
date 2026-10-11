# Conformance fixtures

All keys, IVs, and secrets here are public synthetic fixtures. Fixed IVs are for
reproducible vectors only; the production sealing function generates random IVs.

`encryption/jwe-v1.json` contains a fixed key, IV, protected header, context,
plaintext, and resulting token generated independently using AES-GCM. Any
implementation of the profile should recover exactly the supplied record.
Tests additionally decrypt reference-library output with the independent
cryptography AES-GCM API to check JWE framing and authenticated data.

`valid/` and `invalid/` contain record-validation cases. Structural cases are
covered by JSON Schema; semantic cases (e.g. lease ordering) require the rules
in SPEC.md. The packaged schema must equal the root schema. The `$id` is a
schema identifier; no deployed GitHub Pages resolver is required.
