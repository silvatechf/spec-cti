"""
Wireless audit simulator: evaluates simulated access-point configuration
profiles (encryption type, WPS status, PSK strength) against known-weak
patterns — covering the SEPE curriculum topic "Auditorías de seguridad
inalámbrica" WITHOUT requiring real RF hardware, a real access point, or
any actual over-the-air capture.

Safety design (same pattern as the ransomware simulator): all "handshake"
and "AP profile" data is a local, seeded fixture (data/wordlists/), and the
PSK check is a simple offline dictionary lookup against that fixture —
never a real WPA handshake capture or an attack against a live network.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from src.core.config import get_settings

settings = get_settings()


class EncryptionType(str, Enum):
    OPEN = "open"
    WEP = "wep"
    WPA_TKIP = "wpa_tkip"
    WPA2_PSK = "wpa2_psk"
    WPA3_SAE = "wpa3_sae"


@dataclass(frozen=True)
class AccessPointProfile:
    """A simulated AP configuration — seeded fixture data, never a live scan."""

    ssid: str
    encryption: EncryptionType
    wps_enabled: bool
    hidden_ssid: bool
    psk_sha256: str | None = None  # hash of the PSK, for offline dictionary comparison only


class WirelessCheckSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    INFO = "info"


@dataclass(frozen=True)
class WirelessFinding:
    check_id: str
    title: str
    severity: WirelessCheckSeverity
    evidence: str
    remediation: str


class WirelessAuditSimulator:
    """Deterministic, offline evaluation of a simulated AP profile."""

    def __init__(self, wordlist_path: Path | None = None) -> None:
        self._wordlist_path = wordlist_path or (settings.wordlists_dir / "passwords.txt")

    def audit(self, profile: AccessPointProfile) -> list[WirelessFinding]:
        """Run every wireless check against a single AP profile."""
        findings: list[WirelessFinding] = []

        findings.append(self._check_encryption_strength(profile))
        findings.append(self._check_wps(profile))
        findings.append(self._check_ssid_disclosure(profile))

        psk_finding = self._check_psk_dictionary(profile)
        if psk_finding is not None:
            findings.append(psk_finding)

        return findings

    @staticmethod
    def _check_encryption_strength(profile: AccessPointProfile) -> WirelessFinding:
        weak = {EncryptionType.OPEN, EncryptionType.WEP, EncryptionType.WPA_TKIP}
        if profile.encryption in weak:
            return WirelessFinding(
                check_id="wireless_encryption",
                title="Weak or absent wireless encryption",
                severity=WirelessCheckSeverity.CRITICAL,
                evidence=f"SSID '{profile.ssid}' uses {profile.encryption.value}",
                remediation="Migrate to WPA2-PSK (AES/CCMP) at minimum; prefer WPA3-SAE.",
            )
        return WirelessFinding(
            check_id="wireless_encryption",
            title="Wireless encryption strength acceptable",
            severity=WirelessCheckSeverity.INFO,
            evidence=f"SSID '{profile.ssid}' uses {profile.encryption.value}",
            remediation="No action required.",
        )

    @staticmethod
    def _check_wps(profile: AccessPointProfile) -> WirelessFinding:
        if profile.wps_enabled:
            return WirelessFinding(
                check_id="wireless_wps",
                title="WPS enabled — vulnerable to PIN brute-force",
                severity=WirelessCheckSeverity.HIGH,
                evidence=f"SSID '{profile.ssid}' has WPS enabled",
                remediation="Disable WPS on the access point.",
            )
        return WirelessFinding(
            check_id="wireless_wps",
            title="WPS disabled",
            severity=WirelessCheckSeverity.INFO,
            evidence=f"SSID '{profile.ssid}' has WPS disabled",
            remediation="No action required.",
        )

    @staticmethod
    def _check_ssid_disclosure(profile: AccessPointProfile) -> WirelessFinding:
        """Hidden SSID is a weak control (not real security) but its absence
        combined with weak encryption compounds risk — flagged as informational."""
        if not profile.hidden_ssid:
            return WirelessFinding(
                check_id="wireless_ssid_broadcast",
                title="SSID broadcast enabled",
                severity=WirelessCheckSeverity.INFO,
                evidence=f"SSID '{profile.ssid}' is broadcast",
                remediation=(
                    "Optional hardening only — hidden SSID is not a substitute for strong "
                    "encryption and should not be relied upon alone."
                ),
            )
        return WirelessFinding(
            check_id="wireless_ssid_broadcast",
            title="SSID hidden",
            severity=WirelessCheckSeverity.INFO,
            evidence=f"SSID '{profile.ssid}' is not broadcast",
            remediation="No action required.",
        )

    def _check_psk_dictionary(self, profile: AccessPointProfile) -> WirelessFinding | None:
        """Offline dictionary check: does the PSK hash match any seeded
        wordlist entry? Entirely local comparison against a fixture file —
        no live handshake capture or real-network interaction involved.
        """
        if profile.psk_sha256 is None or not self._wordlist_path.exists():
            return None

        with open(self._wordlist_path, "r", encoding="utf-8") as fh:
            candidates = [line.strip() for line in fh if line.strip()]

        for candidate in candidates:
            candidate_hash = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
            if candidate_hash == profile.psk_sha256:
                return WirelessFinding(
                    check_id="wireless_psk_strength",
                    title="Pre-shared key found in common wordlist",
                    severity=WirelessCheckSeverity.CRITICAL,
                    evidence=f"SSID '{profile.ssid}' PSK matches a dictionary entry",
                    remediation="Set a PSK of 16+ random characters not present in any wordlist.",
                )

        return WirelessFinding(
            check_id="wireless_psk_strength",
            title="Pre-shared key not found in seeded wordlist",
            severity=WirelessCheckSeverity.INFO,
            evidence=f"SSID '{profile.ssid}' PSK did not match the {len(candidates)}-entry wordlist",
            remediation="No action required from this check alone (does not guarantee overall strength).",
        )
