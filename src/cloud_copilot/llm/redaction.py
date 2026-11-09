"""
Reversible pseudonymisation of sensitive identifiers before text leaves the platform for an LLM provider.

    acct 111122223333 -> AWS_ACCOUNT_1
    203.0.113.7       -> IP_1
    AKIA....          -> ACCESS_KEY_1

The mapping is kept in memory for one request so the model's answer can be restored for the user.
"""

from __future__ import annotations

import re

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{12,20}\b")),
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
    ("SUBSCRIPTION", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)),
    ("AWS_ACCOUNT", re.compile(r"(?<![\d.])\d{12}(?![\d.])")),
    ("IP", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
]
# Never pseudonymise these: they carry meaning for the model.
KEEP = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}  # nosec B104


class Redactor:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._forward: dict[str, str] = {}
        self._reverse: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def _token(self, kind: str, value: str) -> str:
        if value in KEEP:
            return value
        if value not in self._forward:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            token = f"{kind}_{self._counters[kind]}"
            self._forward[value] = token
            self._reverse[token] = value
        return self._forward[value]

    def redact(self, text: str) -> str:
        if not self.enabled:
            return text
        for kind, pattern in PATTERNS:

            def repl(m: re.Match[str], k: str = kind) -> str:
                return self._token(k, m.group(0))

            text = pattern.sub(repl, text)
        return text

    def restore(self, text: str) -> str:
        if not self.enabled or not self._reverse:
            return text
        # longest tokens first so IP_12 isn't partially replaced by IP_1
        for token in sorted(self._reverse, key=len, reverse=True):
            text = text.replace(token, self._reverse[token])
        return text

    @property
    def mapping_size(self) -> int:
        return len(self._forward)
