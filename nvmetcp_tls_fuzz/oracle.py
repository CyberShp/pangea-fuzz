from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Verdict(StrEnum):
    PASS_VALID = "PASS_VALID"
    PASS_REJECTED = "PASS_REJECTED"
    PASS_DISCONNECTED = "PASS_DISCONNECTED"
    FAIL_SAFETY = "FAIL_SAFETY"
    FAIL_HANG = "FAIL_HANG"
    FAIL_CLEANUP = "FAIL_CLEANUP"
    FAIL_ORACLE = "FAIL_ORACLE"
    FAIL_INFRA = "FAIL_INFRA"


@dataclass(frozen=True)
class OracleResult:
    verdict: Verdict
    reasons: tuple[str, ...]


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
    )
    HANG_PATTERNS = (
        "hung task",
        "blocked for more than",
    )

    def analyze(
        self,
        *,
        dmesg: str = "",
        fio_json: dict[str, Any] | None = None,
        nvme_before: dict[str, Any] | None = None,
        nvme_after: dict[str, Any] | None = None,
        timed_out: bool = False,
        infra_error: str | None = None,
    ) -> OracleResult:
        if infra_error:
            return OracleResult(Verdict.FAIL_INFRA, (infra_error,))
        safety = self._first_pattern(dmesg, self.SAFETY_PATTERNS)
        if safety:
            return OracleResult(Verdict.FAIL_SAFETY, (safety,))
        hang = self._first_pattern(dmesg, self.HANG_PATTERNS)
        if timed_out or hang:
            return OracleResult(Verdict.FAIL_HANG, (hang or "phase timed out",))
        if self._has_verify_mismatch(fio_json):
            return OracleResult(Verdict.FAIL_ORACLE, ("fio verify mismatch or silent data corruption",))
        if self._controller_leaked(nvme_before or {}, nvme_after or {}):
            return OracleResult(Verdict.FAIL_CLEANUP, ("NVMe controller remained after cleanup",))
        if self._has_io_error(fio_json) or "I/O timeout" in dmesg or "queue" in dmesg and "timeout" in dmesg:
            return OracleResult(Verdict.PASS_REJECTED, ("command failed cleanly",))
        if "disconnect" in dmesg.lower() or "reset controller" in dmesg:
            return OracleResult(Verdict.PASS_DISCONNECTED, ("controller disconnected or reset cleanly",))
        return OracleResult(Verdict.PASS_VALID, ("no oracle violations detected",))

    def _first_pattern(self, text: str, patterns: tuple[str, ...]) -> str | None:
        for pattern in patterns:
            if pattern in text:
                return pattern
        return None

    def _has_io_error(self, fio_json: dict[str, Any] | None) -> bool:
        if not fio_json:
            return False
        return any(int(job.get("error", 0) or 0) != 0 for job in fio_json.get("jobs", []))

    def _has_verify_mismatch(self, fio_json: dict[str, Any] | None) -> bool:
        if not fio_json:
            return False
        return any(int(job.get("verify_errors", 0) or 0) > 0 for job in fio_json.get("jobs", []))

    def _controller_leaked(self, before: dict[str, Any], after: dict[str, Any]) -> bool:
        before_names = {item.get("Name") for item in before.get("Controllers", [])}
        after_names = {item.get("Name") for item in after.get("Controllers", [])}
        return bool(after_names - before_names)
