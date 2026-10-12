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
in SPEC.md. `valid/push.json` is a push record, which carries no callback or
secret. The packaged schema must equal the root schema. The `$id` is a
schema identifier; no deployed GitHub Pages resolver is required.

## Secret-scanning classification

The callback fixture `whsec_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=`
is the `whsec_` prefix followed by standard base64 of the 32 sequential bytes
`00 01 02 ... 1f`. It was constructed for these conformance tests and was never
issued by Stripe or registered with a live service. The prefix overlaps with
Stripe webhook signing secrets, so secret scanners may flag it. Classify that
exact fixture as **used in tests**; never deploy it or broadly suppress scanning
of `whsec_` values. Other detected values still need individual review.
