"""Persistence and state hydration manager for CodeMender sessions."""

import json
import os
import shutil
import zipfile
from pathlib import Path
from typing import Optional, Dict, Any


class PersistenceManager:
    """Manages local storage, state hydration, and artifact extraction for scans."""

    def __init__(self, base_storage_dir: Path):
        self.base_storage_dir = Path(base_storage_dir)
        self.base_storage_dir.mkdir(parents=True, exist_ok=True)

    def get_session_dir(self, session_id: str) -> Path:
        return self.base_storage_dir / session_id

    def setup_session(self, session_id: str, zip_file_path: Optional[Path] = None) -> Dict[str, Path]:
        """Prepares session directories and unpacks source files safely."""
        session_dir = self.get_session_dir(session_id)
        source_dir = session_dir / "source"
        state_dir = session_dir / "state"
        config_dir = session_dir / "config"
        output_dir = session_dir / "output"
        patches_dir = output_dir / "patches"

        for directory in (source_dir, state_dir, config_dir, output_dir, patches_dir):
            directory.mkdir(parents=True, exist_ok=True)

        # Generate default read-only config.yaml
        config_file = config_dir / "config.yaml"
        if not config_file.exists():
            model_name = os.environ.get("CODEMENDER_MODEL", "gemini-3.7-flash")
            config_content = (
                f"model: {model_name}\n"
                "confirm_writes: false\n"
                "human_confirmation: false\n"
                "telemetry:\n"
                "  ast_pre_filter: true\n"
                "  redact_secrets: true\n"
            )
            config_file.write_text(config_content, encoding="utf-8")

        if zip_file_path and zip_file_path.exists():
            self._safe_extract_zip(zip_file_path, source_dir)

        return {
            "session_dir": session_dir,
            "source_dir": source_dir,
            "state_dir": state_dir,
            "config_dir": config_dir,
            "output_dir": output_dir,
            "patches_dir": patches_dir,
        }

    def _safe_extract_zip(self, zip_file_path: Path, target_dir: Path):
        """Extracts a zip archive safely preventing directory traversal (Zip-Slip)."""
        target_dir = target_dir.resolve()
        with zipfile.ZipFile(zip_file_path, "r") as zf:
            for member in zf.infolist():
                member_path = (target_dir / member.filename).resolve()
                if not str(member_path).startswith(str(target_dir)):
                    raise ValueError(f"Malicious zip entry detected: {member.filename}")
            zf.extractall(target_dir)

    def load_report(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Reads report.json if available."""
        report_file = self.get_session_dir(session_id) / "output" / "report.json"
        if report_file.exists():
            try:
                with open(report_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    def load_log(self, session_id: str) -> str:
        """Reads LOG.md execution log."""
        log_file = self.get_session_dir(session_id) / "output" / "LOG.md"
        if log_file.exists():
            return log_file.read_text(encoding="utf-8")
        return "No execution logs available."

    def list_patches(self, session_id: str) -> Dict[str, str]:
        """Lists generated .diff patch contents."""
        patches_dir = self.get_session_dir(session_id) / "output" / "patches"
        patches = {}
        if patches_dir.exists():
            for patch_file in patches_dir.glob("*.diff"):
                patches[patch_file.name] = patch_file.read_text(encoding="utf-8")
        return patches

    def cleanup_session(self, session_id: str):
        """Removes the entire session folder."""
        session_dir = self.get_session_dir(session_id)
        if session_dir.exists():
            shutil.rmtree(session_dir, ignore_errors=True)
