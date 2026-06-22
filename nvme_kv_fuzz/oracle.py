from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Verdict(StrEnum):
    PASS_VALID = "PASS_VALID"
    PASS_REJECTED = "PASS_REJECTED"
    PASS_RECOVERED = "PASS_RECOVERED"
    FAIL_SAFETY = "FAIL_SAFETY"
    FAIL_HANG = "FAIL_HANG"
    FAIL_CLEANUP = "FAIL_CLEANUP"
    FAIL_ORACLE = "FAIL_ORACLE"
    FAIL_INFRA = "FAIL_INFRA"


@dataclass(frozen=True)
class OracleResult:
    verdict: Verdict
    reason: str
    nvme_status: str | None = None
    errno: str | None = None


class OracleAnalyzer:
    SAFETY_PATTERNS = (
        "KASAN",
        "KCSAN",
        "KMSAN",
        "BUG:",
        "Oops",
        "panic",
        "use-after-free",
        "NULL pointer",
        "controller fatal",
        "fatal status",
    )
    HANG_PATTERNS = ("hung task", "blocked for more than", "I/O timeout", "queue timeout")

    def analyze(
        self,
        *,
        dmesg: str = "",
        nvme_before: dict[str, Any] | None = None,
        nvme_after: dict[str, Any] | None = None,
        timed_out: bool = False,
        infra_error: str | None = None,
        semantic_error: str | None = None,
        expected_allowed: tuple[str, ...] = ("PASS_VALID", "PASS_REJECTED", "PASS_RECOVERED"),
        command_returncode: int | None = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> OracleResult:
        if infra_error:
            return OracleResult(Verdict.FAIL_INFRA, infra_error)
        safety = self._first_pattern(dmesg + "\n" + stderr, self.SAFETY_PATTERNS)
        if safety:
            return OracleResult(Verdict.FAIL_SAFETY, safety)
        hang = self._first_pattern(dmesg + "\n" + stderr, self.HANG_PATTERNS)
        if timed_out or hang:
            return OracleResult(Verdict.FAIL_HANG, hang or "case timed out")
        if self._controller_leaked(nvme_before or {}, nvme_after or {}):
            return OracleResult(Verdict.FAIL_CLEANUP, "NVMe controller or namespace state changed after cleanup")
        if semantic_error:
            return OracleResult(Verdict.FAIL_ORACLE, semantic_error, nvme_status=_extract_status(stdout, stderr))
        if command_returncode is None:
            return OracleResult(Verdict.FAIL_INFRA, "command did not produce a return code")
        if command_returncode == 0:
            verdict = Verdict.PASS_VALID if "PASS_VALID" in expected_allowed else Verdict.FAIL_ORACLE
            reason = "command completed" if verdict == Verdict.PASS_VALID else "unexpected silent success"
            return OracleResult(verdict, reason, nvme_status=_extract_status(stdout, stderr) or "0x0")
        if _looks_like_reconnect(dmesg + "\n" + stderr):
            return OracleResult(Verdict.PASS_RECOVERED, f"target rejected or reconnected cleanly: rc={command_returncode}")
        return OracleResult(Verdict.PASS_REJECTED, f"command rejected cleanly: rc={command_returncode}")

    def _first_pattern(self, text: str, patterns: tuple[str, ...]) -> str | None:
        lower = text.lower()
        for pattern in patterns:
            if pattern.lower() in lower:
                return pattern
        return None

    def _controller_leaked(self, before: dict[str, Any], after: dict[str, Any]) -> bool:
        before_names = _controller_names(before)
        after_names = _controller_names(after)
        return bool(after_names - before_names)


def _controller_names(data: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for key in ("Controllers", "controllers", "Devices", "devices"):
        for item in data.get(key, []) or []:
            if isinstance(item, dict):
                name = item.get("Name") or item.get("DevicePath") or item.get("name")
                if name:
                    names.add(str(name))
    return names


def _extract_status(stdout: str, stderr: str) -> str | None:
    text = f"{stdout}\n{stderr}".lower()
    for marker in ("status:", "nvme status:", "status code:"):
        if marker in text:
            tail = text.split(marker, 1)[1].strip().split()[0]
            return tail.rstrip(",;")
    return None


def _looks_like_reconnect(text: str) -> bool:
    lower = text.lower()
    return "reconnect" in lower or "reset controller" in lower or "disconnect" in lower
