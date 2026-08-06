"""
Windows hardening module (simulated).

Per the confirmed architecture, "windows-workstation" is a Linux container
running xrdp (RDP simulation) + Samba (SMB simulation) — no native Windows
kernel is involved. Checks here inspect xrdp.ini/smb.conf equivalents of
real Windows hardening controls (Network Level Authentication, SMB signing,
guest access), covering the SEPE curriculum topic "Endurecimiento de
sistemas Windows" within the project's container-only constraint.
"""

from __future__ import annotations

from src.core.lab_orchestrator import LabOrchestrator
from src.hardening.linux_hardening import CheckStatus, HardeningResult


class WindowsHardeningAuditor:
    """Runs hardening checks against the simulated Windows workstation container."""

    def __init__(self, orchestrator: LabOrchestrator | None = None) -> None:
        self._orchestrator = orchestrator or LabOrchestrator()

    def _run(self, container: str, command: list[str]) -> tuple[int, str]:
        return self._orchestrator.exec_in_container(container, command)

    def check_rdp_nla_enabled(self, container: str) -> HardeningResult:
        """Network Level Authentication equivalent: xrdp's security_layer must
        not be 'rdp' (legacy, pre-auth), should be 'negotiate' or 'tls'."""
        exit_code, output = self._run(
            container, ["sh", "-c", "grep -i '^security_layer' /etc/xrdp/xrdp.ini"]
        )
        insecure = exit_code == 0 and "rdp" in output.lower() and "tls" not in output.lower()
        return HardeningResult(
            check_id="win_nla",
            title="RDP Network Level Authentication (NLA) equivalent enabled",
            status=CheckStatus.FAIL if insecure else CheckStatus.PASS,
            evidence=output.strip() or "(directive not found)",
            remediation="Set security_layer=negotiate or tls in /etc/xrdp/xrdp.ini.",
        )

    def check_rdp_encryption_level(self, container: str) -> HardeningResult:
        """crypt_level should be 'high', not 'low' or 'none'."""
        exit_code, output = self._run(
            container, ["sh", "-c", "grep -i '^crypt_level' /etc/xrdp/xrdp.ini"]
        )
        passed = exit_code == 0 and "high" in output.lower()
        return HardeningResult(
            check_id="win_rdp_encryption",
            title="RDP encryption level set to high",
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            evidence=output.strip() or "(directive not found — insecure default may apply)",
            remediation="Set crypt_level=high in /etc/xrdp/xrdp.ini.",
        )

    def check_smb_signing_required(self, container: str) -> HardeningResult:
        """SMB signing must be required, not merely optional, to prevent
        SMB relay attacks — the container-world equivalent of a well-known
        real Windows/Samba hardening control."""
        exit_code, output = self._run(
            container, ["sh", "-c", "grep -i 'server signing' /etc/samba/smb.conf"]
        )
        passed = exit_code == 0 and "mandatory" in output.lower()
        return HardeningResult(
            check_id="win_smb_signing",
            title="SMB signing required (mandatory)",
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            evidence=output.strip() or "(directive not found — signing likely optional/disabled)",
            remediation="Set 'server signing = mandatory' in the [global] section of smb.conf.",
        )

    def check_guest_access_disabled(self, container: str) -> HardeningResult:
        """Samba 'map to guest' must not allow anonymous/guest access to shares."""
        exit_code, output = self._run(
            container, ["sh", "-c", "grep -i 'map to guest' /etc/samba/smb.conf"]
        )
        insecure = exit_code == 0 and "bad user" in output.lower()
        return HardeningResult(
            check_id="win_guest_access",
            title="Guest/anonymous SMB access disabled",
            status=CheckStatus.FAIL if insecure else CheckStatus.PASS,
            evidence=output.strip() or "(directive not found — default is typically 'Never', which passes)",
            remediation="Set 'map to guest = Never' in the [global] section of smb.conf.",
        )

    def run_all(self, container: str) -> list[HardeningResult]:
        """Run every Windows-simulated hardening check against `container`."""
        return [
            self.check_rdp_nla_enabled(container),
            self.check_rdp_encryption_level(container),
            self.check_smb_signing_required(container),
            self.check_guest_access_disabled(container),
        ]
