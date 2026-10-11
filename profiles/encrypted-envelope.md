# Encrypted Subscription Envelope v1 — experimental draft

This profile uses [JWE Compact Serialization, RFC 7516](https://www.rfc-editor.org/rfc/rfc7516)
and [JWA, RFC 7518](https://www.rfc-editor.org/rfc/rfc7518).
It introduces an application payload profile, not a new cryptographic primitive.

## Protected header

Exactly these protected fields are permitted:

```json
{"alg":"dir","enc":"A256GCM","kid":"k1","typ":"mcp-subscription+jwe","cty":"application/json"}
```

`mcp-subscription+jwe` is a draft application identifier, not a registered media
type. `kid` MUST be 1–128 ASCII letters, digits, `_`, or `-`. Consumers MUST
require this exact algorithm pair, type and content type; reject extra headers,
including `zip`, remote key URLs and embedded keys; and select keys only from a
locally supplied keyring. The compact encrypted-key segment MUST be empty for
`dir`. Encryption keys MUST be 32 random bytes dedicated to this purpose.

## Plaintext

```json
{
  "profile": "mcp-subscription-envelope-v1",
  "context": {
    "server": "https://mcp.example.com",
    "tenant": "project_demo",
    "resource": "sub_example"
  },
  "subscription": {"...": "Subscription Record v1"}
}
```

The three wrapper fields are required and no others are allowed. Each context
value is a nonempty string. The context has exactly the three shown fields.
`resource` MUST equal the subscription `id`. `server` is a stable deployment
identifier, not an inbound Host header. `tenant` is the adapter's tenant scope.
The context is encrypted and authenticated as part of the JWE plaintext.

The consumer MUST supply expected context from trusted routing/configuration
and compare all three values exactly after decryption. It MUST NOT take expected
context from the token itself. A mismatched context is rejected.

## Encoding and limits

The payload is UTF-8 JSON. Object ordering and whitespace do not affect record
meaning. No custom canonicalization is required for encryption: JWE authenticates
the exact encoded bytes. The implementation emits compact, sorted JSON for
repeatable examples; other valid JSON encodings MUST be accepted.

The compact format is:

```text
base64url(protected-header)..base64url(iv).base64url(ciphertext).base64url(tag)
```

Base64url is unpadded and canonical. The IV is 12 bytes generated randomly for
each encryption; the authentication tag is 16 bytes. The protected-header segment
is the JWE additional authenticated data, exactly as RFC 7516 specifies. Do not
append custom AAD to a compact JWE.

Encoded records and tokens MUST each fit in 64 KiB in this profile. An adapter
MAY impose a lower limit. Duplicate JSON keys and non-finite numbers MUST be
rejected in the protected header and plaintext.

## Reading and rotation

Readers MUST authenticate before using plaintext, validate the wrapper and
record, check context, and enforce expiry before delivering. Unsupported or
unknown keys are errors, not fallback attempts with every available key.

Writers use the configured active key; readers may retain previous keys. Refresh
reseals using the active key. Keep a retired key while accepted records or
in-flight work still need it, or explicitly revoke them. No-expiry records
require explicit re-encryption or retention; waiting a maximum TTL cannot retire
those keys safely.

Possession of a valid older envelope is not proof of a current lease. Revocation
and rollback protection require current adapter state or a documented bounded
lease policy. This format does not store access tokens and does not authorize a
callback or bypass callback verification.
