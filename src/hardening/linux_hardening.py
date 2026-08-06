"""
Linux hardening module: deterministic CIS-Benchmark-style checks against a
lab Linux container (via LabOrchestrator.exec_in_container), covering the
SEPE curriculum topic "Endurecimiento de sistemas Linux".

Each check returns a HardeningResult with a pass/fail verdict and the exact
command output used as evidence — no heuristic scoring, just direct
inspection of configuration state.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from src.core.lab_orchestrator import LabOrchestrator


class CheckStatus(str, Enum):
    PASS = "pass"  # nosec B105 - enum member name, not a credential
    FAIL = "fail"
    ERROR = "error"  # command could not be executed (e.g. container offline)


@dataclass(frozen=True)
class HardeningResult:
    """Outcome of a single hardening check, with raw evidence attached."""

    check_id: str
    title: str
    status: CheckStatus
    evidence: str
    remediation: str


class LinuxHardeningAuditor:
    """Runs CIS-style hardening checks against a Linux lab container."""

    def __init__(self, orchestrator: LabOrchestrator | None = None) -> None:
        self._orchestrator = orchestrator or LabOrchestrator()

    def _run(self, container: str, command: list[str]) -> tuple[int, str]:
        return self._orchestrator.exec_in_container(container, command)

    # ------------------------------------------------------------------ #
    # SSH hardening (CIS 5.2.x equivalents)
    # ------------------------------------------------------------------ #

    def check_ssh_root_login_disabled(self, container: str) -> HardeningResult:
        """CIS 5.2.10 — PermitRootLogin must not be 'yes'."""
        exit_code, output = self._run(
            container, ["sh", "-c", "grep -i '^PermitRootLogin' /etc/ssh/sshd_config"]
        )
        passed = exit_code == 0 and "yes" not in output.lower()
        return HardeningResult(
            check_id="cis_5.2.10",
            title="SSH root login disabled",
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            evidence=output.strip() or "(directive not found — insecure default applies)",
            remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd.",
        )

    def check_ssh_password_auth_disabled(self, container: str) -> HardeningResult:
        """CIS 5.2.11 — PasswordAuthentication should be 'no' (key-based only)."""
        exit_code, output = self._run(
            container, ["sh", "-c", "grep -i '^PasswordAuthentication' /etc/ssh/sshd_config"]
        )
        passed = exit_code == 0 and "no" in output.lower()
        return HardeningResult(
            check_id="cis_5.2.11",
            title="SSH password authentication disabled",
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            evidence=output.strip() or "(directive not found — insecure default applies)",
            remediation="Set 'PasswordAuthentication no' and enforce key-based auth.",
        )

    def check_ssh_protocol_version(self, container: str) -> HardeningResult:
        """CIS 5.2.4 — Only SSH protocol 2 should be permitted (implicit in modern OpenSSH,
        but explicit misconfiguration to '1' or '1,2' must be flagged)."""
        exit_code, output = self._run(
            container, ["sh", "-c", "grep -i '^Protocol' /etc/ssh/sshd_config"]
        )
        insecure = exit_code == 0 and "1" in output
        return HardeningResult(
            check_id="cis_5.2.4",
            title="SSH protocol 1 not enabled",
            status=CheckStatus.FAIL if insecure else CheckStatus.PASS,
            evidence=output.strip() or "(no explicit Protocol directive — OpenSSH defaults to v2)",
            remediation="Remove any 'Protocol 1' directive; OpenSSH >= 7.6 defaults to v2 only.",
        )

    # ------------------------------------------------------------------ #
    # File permission hardening (CIS 6.1.x equivalents)
    # ------------------------------------------------------------------ #

    def check_passwd_permissions(self, container: str) -> HardeningResult:
        """CIS 6.1.2 — /etc/passwd must be world-readable only, never world-writable."""
        exit_code, output = self._run(container, ["stat", "-c", "%a", "/etc/passwd"])
        mode = output.strip()
        passed = exit_code == 0 and mode in {"644", "444"}
        return HardeningResult(
            check_id="cis_6.1.2",
            title="/etc/passwd permissions",
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            evidence=f"mode={mode}" if exit_code == 0 else output,
            remediation="Run: chmod 644 /etc/passwd",
        )

    def check_shadow_permissions(self, container: str) -> HardeningResult:
        """CIS 6.1.3 — /etc/shadow must not be readable outside root."""
        exit_code, output = self._run(container, ["stat", "-c", "%a", "/etc/shadow"])
        mode = output.strip()
        passed = exit_code == 0 and mode in {"640", "600", "000"}
        return HardeningResult(
            check_id="cis_6.1.3",
            title="/etc/shadow permissions",
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            evidence=f"mode={mode}" if exit_code == 0 else output,
            remediation="Run: chmod 640 /etc/shadow (or 600 depending on distro convention).",
        )

    def check_world_writable_files(self, container: str) -> HardeningResult:
        """CIS 6.1.10 — No world-writable files should exist outside expected paths."""
        exit_code, output = self._run(
            container,
            ["find", "/etc", "/usr", "/opt", "-xdev", "-type", "f", "-perm", "-0002"],
        )
        offenders = [line for line in output.strip().splitlines() if line]
        passed = exit_code == 0 and not offenders
        return HardeningResult(
            check_id="cis_6.1.10",
            title="No world-writable files under /etc, /usr, /opt",
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            evidence=f"{len(offenders)} offending file(s): {offenders[:5]}",
            remediation="Run: chmod o-w <file> for each offending file.",
        )

    # ------------------------------------------------------------------ #
    # Patch status (CIS 1.9 equivalent)
    # ------------------------------------------------------------------ #

    def check_pending_security_updates(self, container: str) -> HardeningResult:
        """Flags systems with pending apt security updates (Debian/Ubuntu-family)."""
        exit_code, output = self._run(
            container, ["sh", "-c", "apt list --upgradable 2>/dev/null | grep -i security | wc -l"]
        )
        try:
            pending_count = int(output.strip())
        except ValueError:
            pending_count = -1

        if pending_count < 0:
            status = CheckStatus.ERROR
        else:
            status = CheckStatus.PASS if pending_count == 0 else CheckStatus.FAIL

        return HardeningResult(
            check_id="patch_status",
            title="No pending security updates",
            status=status,
            evidence=f"{pending_count} pending security update(s)" if pending_count >= 0 else output,
            remediation="Run: apt update && apt upgrade -y (test in a maintenance window first).",
        )

    # ------------------------------------------------------------------ #
    # Aggregate
    # ------------------------------------------------------------------ #

    def run_all(self, container: str) -> list[HardeningResult]:
        """Run every check against `container` and return all results."""
        return [
            self.check_ssh_root_login_disabled(container),
            self.check_ssh_password_auth_disabled(container),
            self.check_ssh_protocol_version(container),
            self.check_passwd_permissions(container),
            self.check_shadow_permissions(container),
            self.check_world_writable_files(container),
            self.check_pending_security_updates(container),
        ]
