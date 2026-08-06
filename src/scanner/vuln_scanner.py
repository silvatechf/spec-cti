"""
Vulnerability scanner: correlates discovered services/accounts against a
local CVE lookup table, assigns simulated CVSS v3.1 scores, and applies
false-positive validation logic before findings are persisted.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.core.config import get_settings
from src.core.database import Severity

logger = logging.getLogger(__name__)
settings = get_settings()


@dataclass
class VulnFinding:
    """A single vulnerability finding prior to DB persistence."""

    title: str
    description: str
    cve_id: Optional[str]
    cvss_score: float
    severity: Severity
    is_confirmed_exploitable: bool
    is_false_positive: bool = False


def _score_to_severity(score: float) -> Severity:
    """Map a CVSS v3.1 base score to a qualitative severity bucket."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


class CVELookup:
    """Loads and queries the local, simplified CVE database (JSON)."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or settings.cve_lookup_path
        self._data: dict[str, dict] = self._load()

    def _load(self) -> dict[str, dict]:
        if not self.path.exists():
            logger.warning("CVE lookup file not found at %s; using empty table", self.path)
            return {}
        with open(self.path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def find_by_product(self, product: str, version: Optional[str] = None) -> list[dict]:
        """Return all CVE entries whose `product` matches (case-insensitive)."""
        product_lower = product.lower()
        matches = []
        for cve_id, entry in self._data.items():
            if entry.get("product", "").lower() != product_lower:
                continue
            if version and entry.get("affected_versions"):
                if version not in entry["affected_versions"]:
                    continue
            matches.append({"cve_id": cve_id, **entry})
        return matches


class VulnScanner:
    """Correlates recon data against known weaknesses and CVEs."""

    def __init__(self, cve_lookup: Optional[CVELookup] = None) -> None:
        self.cve_lookup = cve_lookup or CVELookup()

    # ------------------------------------------------------------------ #
    # Service-based CVE correlation
    # ------------------------------------------------------------------ #

    def check_service(self, product: str, version: Optional[str]) -> list[VulnFinding]:
        """Look up a fingerprinted service/version against the local CVE table."""
        findings: list[VulnFinding] = []
        for entry in self.cve_lookup.find_by_product(product, version):
            score = float(entry.get("cvss_score", 0.0))
            findings.append(
                VulnFinding(
                    title=f"{product} {version or ''} — {entry.get('title', entry['cve_id'])}".strip(),
                    description=entry.get("description", ""),
                    cve_id=entry["cve_id"],
                    cvss_score=score,
                    severity=_score_to_severity(score),
                    is_confirmed_exploitable=entry.get("known_exploitable", False),
                )
            )
        return findings

    # ------------------------------------------------------------------ #
    # Heuristic / configuration-based checks (non-CVE)
    # ------------------------------------------------------------------ #

    def check_weak_password_accounts(self, accounts: list[dict]) -> list[VulnFinding]:
        """Flag accounts with reused or dictionary-weak passwords.

        `accounts` is a list of dicts like {"username": ..., "reused_password": bool}.
        """
        findings = []
        for acct in accounts:
            if acct.get("reused_password"):
                findings.append(
                    VulnFinding(
                        title=f"Password reuse detected: {acct['username']}",
                        description=(
                            "Account uses a password shared with at least one other "
                            "account, significantly increasing credential-stuffing risk."
                        ),
                        cve_id=None,
                        cvss_score=6.5,
                        severity=_score_to_severity(6.5),
                        is_confirmed_exploitable=True,
                    )
                )
        return findings

    def check_inactive_accounts(self, accounts: list[dict]) -> list[VulnFinding]:
        """Flag former-employee accounts that remain active/enabled."""
        findings = []
        for acct in accounts:
            if acct.get("is_former_employee") and acct.get("is_active"):
                findings.append(
                    VulnFinding(
                        title=f"Former employee account still active: {acct['username']}",
                        description=(
                            "Account belongs to a former employee but has not been "
                            "disabled, representing an unauthorized-access risk."
                        ),
                        cve_id=None,
                        cvss_score=7.5,
                        severity=_score_to_severity(7.5),
                        is_confirmed_exploitable=True,
                    )
                )
        return findings

    def check_exposed_rdp(self, open_ports: list[int]) -> list[VulnFinding]:
        """Flag RDP (3389) reachable without additional network controls."""
        if 3389 not in open_ports:
            return []
        return [
            VulnFinding(
                title="RDP exposed without network restriction",
                description=(
                    "Port 3389 is reachable directly, without VPN/bastion/allow-listing, "
                    "making the host a prime target for brute-force and known RDP CVEs."
                ),
                cve_id=None,
                cvss_score=8.1,
                severity=_score_to_severity(8.1),
                is_confirmed_exploitable=True,
            )
        ]

    def check_missing_mfa(self, accounts: list[dict]) -> list[VulnFinding]:
        """Flag accounts without MFA enabled."""
        findings = []
        for acct in accounts:
            if not acct.get("mfa_enabled", False):
                findings.append(
                    VulnFinding(
                        title=f"MFA not enabled: {acct['username']}",
                        description="Account authentication relies on password only.",
                        cve_id=None,
                        cvss_score=5.3,
                        severity=_score_to_severity(5.3),
                        is_confirmed_exploitable=False,
                    )
                )
        return findings

    # ------------------------------------------------------------------ #
    # False-positive validation
    # ------------------------------------------------------------------ #

    def validate_finding(self, finding: VulnFinding, live_probe_success: bool) -> VulnFinding:
        """Mark a finding as a false positive if a live exploit probe failed.

        `live_probe_success` should come from an actual (sandboxed) attempt
        by the exploit_simulator module — e.g. a brute-force module reporting
        whether a weak-password account was genuinely reachable and login-able.
        """
        if finding.is_confirmed_exploitable and not live_probe_success:
            finding.is_false_positive = True
            logger.info("Finding '%s' marked as false positive after live probe", finding.title)
        return finding
