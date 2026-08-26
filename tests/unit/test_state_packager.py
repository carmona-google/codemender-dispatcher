"""Unit tests for Cryptographic StatePackager and HMAC verification."""

import tempfile
import unittest
from pathlib import Path

from src.core.state_packager import StatePackager


class TestStatePackager(unittest.TestCase):
    """Verifies state compression, HMAC signing, extraction, and anti-tampering."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.source_state = self.base_path / "source_state"
        self.target_state = self.base_path / "target_state"
        self.archive_path = self.base_path / "packages" / "state_bundle.tar.gz"

        self.source_state.mkdir(parents=True, exist_ok=True)
        (self.source_state / "session_memory.json").write_text('{"turn": 3, "status": "active"}', encoding="utf-8")
        (self.source_state / "keys.db").write_text("ENCRYPTED_SESSION_KEY_BLOB", encoding="utf-8")

        self.packager = StatePackager(signing_secret="test-crypto-signing-secret")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_package_and_unpackage_success(self):
        meta = self.packager.package_state(self.source_state, self.archive_path)
        self.assertTrue(self.archive_path.exists())
        self.assertIn("hmac_sha256", meta)
        self.assertEqual(len(meta["hmac_sha256"]), 64)

        # Unpackage with valid signature
        success = self.packager.unpackage_state(
            self.archive_path,
            self.target_state,
            expected_signature=meta["hmac_sha256"],
        )
        self.assertTrue(success)
        self.assertTrue((self.target_state / "session_memory.json").exists())
        self.assertEqual(
            (self.target_state / "keys.db").read_text(encoding="utf-8"),
            "ENCRYPTED_SESSION_KEY_BLOB",
        )

    def test_tampered_archive_rejection(self):
        meta = self.packager.package_state(self.source_state, self.archive_path)

        # Corrupt the archive payload
        with open(self.archive_path, "ab") as f:
            f.write(b"\x00\xffMALICIOUS_TAMPER_BYTES")

        # Expect HMAC mismatch
        with self.assertRaises(ValueError) as ctx:
            self.packager.unpackage_state(
                self.archive_path,
                self.target_state,
                expected_signature=meta["hmac_sha256"],
            )
        self.assertIn("HMAC signature mismatch", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
