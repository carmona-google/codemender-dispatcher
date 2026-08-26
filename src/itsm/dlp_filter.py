"""Local DLP & AST Pre-Sanitizer with Shannon Entropy Secret Detection."""

import re
import math
from typing import Dict, Any, List


class DLPFilter:
    """Pre-sanitizes outbound event payloads and prompts to prevent code, secret, and diff leakage."""

    DIFF_PATTERNS = [
        re.compile(r"^diff\s+--git", re.MULTILINE),
        re.compile(r"^@@\s+-\d+,\d+\s+\+\d+,\d+\s+@@", re.MULTILINE),
        re.compile(r"^[+-][^+-]", re.MULTILINE),
    ]

    KNOWN_SECRET_PATTERNS = [
        re.compile(r"-----BEGIN\s+(?:RSA|OPENSSH|EC)?\s*PRIVATE\s+KEY-----", re.IGNORECASE),
        re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}", re.IGNORECASE),
        re.compile(r"AIza[0-9A-Za-z\-_]{35}", re.IGNORECASE),
        re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
        re.compile(r"(?:Bearer|Basic)\s+[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE),
    ]

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Calculates the Shannon entropy of a string."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        for count in freq.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        return entropy

    @classmethod
    def contains_diff_or_source_code(cls, text: str) -> bool:
        """Checks if a string contains unified diff syntax."""
        if not isinstance(text, str):
            return False
        for pattern in cls.DIFF_PATTERNS:
            if pattern.search(text):
                return True
        return False

    @classmethod
    def contains_secrets(cls, text: str) -> bool:
        """Checks if a string contains known secret patterns or high-entropy tokens."""
        if not isinstance(text, str):
            return False
        for pattern in cls.KNOWN_SECRET_PATTERNS:
            if pattern.search(text):
                return True

        # Check individual tokens for high Shannon entropy (> 4.5 for length >= 16)
        tokens = re.split(r"[\s=:\"',;]+", text)
        for token in tokens:
            if len(token) >= 16 and not token.startswith("http"):
                if cls.calculate_shannon_entropy(token) > 4.5:
                    return True
        return False

    @classmethod
    def sanitize_event_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively validates and sanitizes event metadata dictionaries."""
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                if cls.contains_secrets(value):
                    raise ValueError(f"DLP Violation: High-entropy secret detected in field '{key}'")
                if cls.contains_diff_or_source_code(value):
                    raise ValueError(f"DLP Violation: Source code / diff syntax detected in field '{key}'")
                sanitized[key] = value
            elif isinstance(value, dict):
                sanitized[key] = cls.sanitize_event_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    cls.sanitize_event_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        return sanitized
