"""Cryptographic State Packaging and HMAC Signing for Multi-Turn Continuity."""

import hmac
import hashlib
import json
import os
import tarfile
from pathlib import Path
from typing import Optional, Dict, Any


class StatePackager:
    """Packages and cryptographically signs ~/.codemender state across distributed runs."""

    def __init__(self, signing_secret: str = "codemender-default-state-key-change-in-prod"):
        self.signing_secret = signing_secret

    def package_state(self, state_dir: Path, output_archive_path: Path) -> Dict[str, Any]:
        """Compresses state directory into a tar.gz archive and produces an HMAC signature."""
        state_dir = Path(state_dir)
        output_archive_path = Path(output_archive_path)
        output_archive_path.parent.mkdir(parents=True, exist_ok=True)

        with tarfile.open(output_archive_path, "w:gz") as tar:
            for item in state_dir.iterdir():
                tar.add(item, arcname=item.name)

        archive_bytes = output_archive_path.read_bytes()
        signature = hmac.new(
            self.signing_secret.encode("utf-8"),
            msg=archive_bytes,
            digestmod=hashlib.sha256,
        ).hexdigest()

        metadata = {
            "archive_path": str(output_archive_path),
            "size_bytes": len(archive_bytes),
            "hmac_sha256": signature,
        }

        # Save checksum file alongside archive
        checksum_file = output_archive_path.with_suffix(".sig")
        checksum_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

        return metadata

    def unpackage_state(self, archive_path: Path, target_state_dir: Path, expected_signature: Optional[str] = None) -> bool:
        """Verifies signature and unpackages state into target directory safely."""
        archive_path = Path(archive_path)
        target_state_dir = Path(target_state_dir)
        target_state_dir.mkdir(parents=True, exist_ok=True)

        if not archive_path.exists():
            return False

        archive_bytes = archive_path.read_bytes()
        computed_sig = hmac.new(
            self.signing_secret.encode("utf-8"),
            msg=archive_bytes,
            digestmod=hashlib.sha256,
        ).hexdigest()

        if expected_signature and not hmac.compare_digest(computed_sig, expected_signature):
            raise ValueError("State package integrity error: HMAC signature mismatch!")

        # Unpack safely
        with tarfile.open(archive_path, "r:gz") as tar:
            for member in tar.getmembers():
                dest_path = (target_state_dir / member.name).resolve()
                if not str(dest_path).startswith(str(target_state_dir.resolve())):
                    raise ValueError(f"Malicious archive entry detected: {member.name}")
            try:
                tar.extractall(target_state_dir, filter="data")
            except TypeError:
                tar.extractall(target_state_dir)

        return True
