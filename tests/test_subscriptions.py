"""Profile conformance, tampering, tenant binding and independent JWE checks."""

import base64
import copy
import json
import secrets
import unittest
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jsonschema import Draft202012Validator
from mcp_event_subscriptions import (
    EnvelopeError,
    ExpiredSubscription,
    RecordError,
    open_envelope,
    seal,
    validate_subscription,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2029, 1, 1, tzinfo=UTC)


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.vector = json.loads(
            (ROOT / "test-vectors/encryption/jwe-v1.json").read_text()
        )
        self.record = self.vector["plaintext"]["subscription"]
        self.context = self.vector["context"]
        self.keys = {"fixture-k1": bytes.fromhex(self.vector["keyHex"])}

    def seal(self, record=None):
        return seal(
            self.record if record is None else record,
            self.keys,
            active_key="fixture-k1",
            context=self.context,
        )

    def open(self, token, **kwargs):
        return open_envelope(
            token, self.keys, expected_context=self.context, now=NOW, **kwargs
        )

    def raw_token(self, plaintext, header=None):
        header = header or self.vector["protected"]
        protected = b64(json.dumps(header, separators=(",", ":")).encode())
        iv = secrets.token_bytes(12)
        encrypted = AESGCM(self.keys["fixture-k1"]).encrypt(
            iv, plaintext, protected.encode()
        )
        return ".".join(
            [protected, "", b64(iv), b64(encrypted[:-16]), b64(encrypted[-16:])]
        )

    def test_schema_is_valid_and_packaged_copy_matches(self):
        schema = json.loads((ROOT / "schemas/subscription-v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        packaged = json.loads(
            files("mcp_event_subscriptions")
            .joinpath("subscription-v1.schema.json")
            .read_text()
        )
        self.assertEqual(schema, packaged)

    def test_valid_record_vectors(self):
        for path in (ROOT / "test-vectors/valid").glob("*.json"):
            with self.subTest(path=path.name):
                record = json.loads(path.read_text())
                self.assertEqual(validate_subscription(record), record)
                self.assertEqual(self.open(self.seal(record)), record)

    def test_invalid_record_vectors(self):
        for path in (ROOT / "test-vectors/invalid").glob("*.json"):
            with self.subTest(path=path.name):
                with self.assertRaises(RecordError):
                    validate_subscription(json.loads(path.read_text()))

    def test_external_known_answer_vector(self):
        self.assertEqual(self.open(self.vector["token"]), self.record)

    def test_reference_output_decrypts_independently(self):
        token = self.seal()
        protected, encrypted_key, iv, ciphertext, tag = token.split(".")
        self.assertEqual(encrypted_key, "")
        decrypted = AESGCM(self.keys["fixture-k1"]).decrypt(
            unb64(iv), unb64(ciphertext) + unb64(tag), protected.encode()
        )
        self.assertEqual(json.loads(decrypted), self.vector["plaintext"])

    def test_sealing_uses_fresh_iv(self):
        self.assertNotEqual(self.seal(), self.seal())

    def test_each_segment_tampering_is_rejected(self):
        for index in (0, 2, 3, 4):
            parts = self.vector["token"].split(".")
            raw = bytearray(unb64(parts[index]))
            raw[0] ^= 1
            parts[index] = b64(raw)
            with self.subTest(segment=index), self.assertRaises(EnvelopeError):
                self.open(".".join(parts))

    def test_every_context_dimension_is_bound(self):
        for field in self.context:
            context = {**self.context, field: "other"}
            with self.subTest(field=field), self.assertRaises(EnvelopeError):
                open_envelope(
                    self.vector["token"], self.keys, expected_context=context, now=NOW
                )

    def test_rotation_and_retired_key(self):
        rotated = {**self.keys, "k2": secrets.token_bytes(32)}
        self.assertEqual(
            open_envelope(
                self.vector["token"], rotated, expected_context=self.context, now=NOW
            ),
            self.record,
        )
        token = seal(self.record, rotated, active_key="k2", context=self.context)
        self.assertEqual(
            open_envelope(
                token, {"k2": rotated["k2"]}, expected_context=self.context, now=NOW
            ),
            self.record,
        )
        with self.assertRaises(EnvelopeError):
            open_envelope(
                self.vector["token"],
                {"k2": rotated["k2"]},
                expected_context=self.context,
                now=NOW,
            )

    def test_expiry_at_exact_boundary(self):
        expiry = datetime(2030, 1, 1, 1, tzinfo=UTC)
        with self.assertRaises(ExpiredSubscription):
            open_envelope(
                self.vector["token"],
                self.keys,
                expected_context=self.context,
                now=expiry,
            )

    def test_unsupported_headers_and_algorithms(self):
        for change in (
            {"alg": "A256KW"},
            {"enc": "A128GCM"},
            {"zip": "DEF"},
            {"typ": "JWT"},
            {"jku": "https://keys.example.com"},
        ):
            token = self.raw_token(
                json.dumps(self.vector["plaintext"]).encode(),
                {**self.vector["protected"], **change},
            )
            with self.subTest(change=change), self.assertRaises(EnvelopeError):
                self.open(token)

    def test_authenticated_malformed_payloads(self):
        valid = self.vector["plaintext"]
        for value in (
            {**valid, "profile": "unknown"},
            {**valid, "extra": True},
            {**valid, "subscription": {}},
        ):
            with self.subTest(value=value.keys()), self.assertRaises(EnvelopeError):
                self.open(self.raw_token(json.dumps(value).encode()))

    def test_duplicate_keys_and_nonfinite_json(self):
        payload = json.dumps(self.vector["plaintext"])
        invalid = [
            payload.replace('"profile":', '"profile":"duplicate","profile":', 1),
            payload.replace('"version": 1', '"version": NaN'),
        ]
        for text in invalid:
            with self.subTest(text=text[:30]), self.assertRaises(EnvelopeError):
                self.open(self.raw_token(text.encode()))

    def test_bad_framing_size_and_keys(self):
        for token in ("", "a.b.c", "x" * 65537, self.vector["token"] + "=", "é"):
            with self.subTest(token=token[:10]), self.assertRaises(EnvelopeError):
                self.open(token)
        for keys in ({}, {"fixture-k1": b"short"}):
            with self.assertRaises(EnvelopeError):
                open_envelope(
                    self.vector["token"], keys, expected_context=self.context, now=NOW
                )
        with self.assertRaises(EnvelopeError):
            seal(self.record, self.keys, active_key="missing", context=self.context)

    def test_non_json_input_and_record_size(self):
        for value in (float("nan"), {1: "non-string key"}, ("tuple",)):
            record = copy.deepcopy(self.record)
            record["event"]["arguments"]["bad"] = value
            with self.subTest(value=type(value)), self.assertRaises(RecordError):
                validate_subscription(record)
        record = copy.deepcopy(self.record)
        record["event"]["arguments"]["huge"] = "x" * 65536
        with self.assertRaises(RecordError):
            validate_subscription(record)

    def test_naive_clock_rejected(self):
        with self.assertRaises(EnvelopeError):
            open_envelope(
                self.vector["token"],
                self.keys,
                expected_context=self.context,
                now=datetime(2029, 1, 1),
            )


if __name__ == "__main__":
    unittest.main()
