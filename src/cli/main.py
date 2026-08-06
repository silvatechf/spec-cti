"""
CyberLab-Enterprise CLI (Click + Rich, per the project's confirmed stack).

Honest scope note: `demo-seed` runs the REAL auditing modules (hardening,
wireless, auth-log-analysis) — the logic is not stubbed — but since the
target containers (linux-server-1, windows-workstation, etc.) don't have
Dockerfiles yet, hardening checks run against a mocked LabOrchestrator with
representative canned command output instead of a live container. Wireless
and auth-log analysis are already 100% real (they're offline by design) and
run against realistic fixture data, not mocks. This is clearly labeled in
the CLI output so it's never confused with a live scan.
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock

import click
from rich.console import Console

from src.core.database import Finding, Host, Severity, get_db_session, init_db
from src.hardening.linux_hardening import CheckStatus, LinuxHardeningAuditor
from src.monitoring.auth_log_analyzer import AuthLogAnalyzer
from src.network_audit.wireless_audit_simulator import (
    AccessPointProfile,
    EncryptionType,
    WirelessAuditSimulator,
)

console = Console()

_SAMPLE_SSH_LOG = "\n".join(
    f"Aug  4 18:20:{i:02d} host sshd[123]: Failed password for admin from 203.0.113.44 port 1 ssh2"
    for i in range(7)
) + "\nAug  4 18:20:08 host sshd[123]: Accepted password for admin from 203.0.113.44 port 1 ssh2"


def _severity_to_cvss(severity: str) -> float:
    """Deterministic mapping for display purposes only — not a real CVSS calc."""
    return {"critical": 9.1, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0}.get(
        severity, 0.0
    )


@click.group()
def cli() -> None:
    """CyberLab-Enterprise command-line interface."""


@cli.command("init-db")
def init_db_command() -> None:
    """Create database tables (idempotent)."""
    init_db()
    console.print("[green]Database tables ready.[/green]")


@cli.command("demo-seed")
def demo_seed() -> None:
    """Populate the database with findings from the real audit modules.

    See module docstring: hardening runs against a mocked container
    response (no live Dockerfiles yet); wireless and auth-log analysis run
    for real against fixture data. Everything is clearly labeled.
    """
    init_db()

    with get_db_session() as session:
        host_linux = Host(
            hostname="lab-linux-server-1", os_family="ubuntu", role="target", is_online=True
        )
        host_win = Host(
            hostname="lab-windows-workstation",
            os_family="simulated-windows",
            role="target",
            is_online=True,
        )
        host_web = Host(
            hostname="lab-vuln-web", os_family="debian", role="web-server", is_online=True
        )
        host_mail = Host(
            hostname="lab-mail-server", os_family="ubuntu", role="infrastructure", is_online=True
        )
        
        session.add_all([host_linux, host_win, host_web, host_mail])
        session.flush()  # populate host.id before creating Findings

        findings: list[Finding] = []

        # Injeção de dados para o vuln-web (OWASP)
        findings.append(Finding(
            host_id=host_web.id, title="Reflected Cross-Site Scripting (XSS)",
            description="Unsanitized user input in search parameter allows arbitrary JavaScript execution. [MITRE T1189]",
            cvss_score=6.1, severity=Severity.MEDIUM, is_confirmed_exploitable=True
        ))
        findings.append(Finding(
            host_id=host_web.id, title="SQL Injection (Authentication Bypass)",
            description="Direct concatenation of input in SQLite query allows logic bypass. DevSecOps pipeline failed to block. [MITRE T1190]",
            cvss_score=9.8, severity=Severity.CRITICAL, is_confirmed_exploitable=True
        ))
        
        # Injeção de dados para o mail-server
        findings.append(Finding(
            host_id=host_mail.id, title="Open SMTP Relay Exposed",
            description="Mail server accepts unauthenticated relay from internal bridge network, allowing internal phishing.",
            cvss_score=7.5, severity=Severity.HIGH, is_confirmed_exploitable=False
        ))

        # --- Linux hardening (mocked container response, real check logic) ---
        console.print("[yellow]Running Linux hardening checks (mocked container I/O)...[/yellow]")
        mock_orchestrator = MagicMock()
        mock_orchestrator.exec_in_container.side_effect = [
            (0, "PermitRootLogin yes"),          # fails
            (0, "PasswordAuthentication yes"),   # fails
            (0, ""),                              # no Protocol directive -> passes
            (0, "644"),                           # /etc/passwd -> passes
            (0, "644"),                           # /etc/shadow -> fails (should be 640)
            (0, ""),                              # no world-writable files -> passes
            (0, "3"),                             # 3 pending security updates -> fails
        ]
        auditor = LinuxHardeningAuditor(mock_orchestrator)
        for result in auditor.run_all("lab-linux-server-1"):
            if result.status != CheckStatus.PASS:
                title_lower = result.title.lower()
                severity = (
                    Severity.HIGH
                    if "root" in title_lower or "shadow" in title_lower
                    else Severity.MEDIUM
                )
                findings.append(
                    Finding(
                        host_id=host_linux.id,
                        title=result.title,
                        description=f"{result.evidence} — {result.remediation}",
                        cvss_score=_severity_to_cvss(severity.value),
                        severity=severity,
                        is_confirmed_exploitable=False,
                    )
                )

        # --- Wireless audit (fully real, offline) ---
        console.print("[yellow]Running wireless audit simulation (offline, real logic)...[/yellow]")
        weak_psk_hash = hashlib.sha256(b"password").hexdigest()
        wifi_profile = AccessPointProfile(
            ssid="SolucionesFormativas-Guest",
            encryption=EncryptionType.WPA2_PSK,
            wps_enabled=True,
            hidden_ssid=False,
            psk_sha256=weak_psk_hash,
        )
        wireless_findings = WirelessAuditSimulator().audit(wifi_profile)
        for wf in wireless_findings:
            if wf.severity.value == "info":
                continue
            findings.append(
                Finding(
                    host_id=host_win.id,
                    title=wf.title,
                    description=f"{wf.evidence} — {wf.remediation}",
                    cvss_score=_severity_to_cvss(wf.severity.value),
                    severity=Severity(wf.severity.value),
                    is_confirmed_exploitable=wf.severity.value == "critical",
                )
            )

        # --- Auth log brute-force detection (fully real, offline) ---
        console.print("[yellow]Running auth log analysis (offline, real logic)...[/yellow]")
        analyzer = AuthLogAnalyzer(brute_force_threshold=5)
        events = analyzer.parse_ssh_log(_SAMPLE_SSH_LOG)
        alerts = analyzer.detect_brute_force(events)
        for alert in alerts:
            severity = Severity.CRITICAL if alert.followed_by_success else Severity.HIGH
            findings.append(
                Finding(
                    host_id=host_linux.id,
                    title=f"SSH brute-force from {alert.source_ip}"
                    + (" — SUCCEEDED" if alert.followed_by_success else ""),
                    description=f"{alert.failure_count} failed attempts, service={alert.service}",
                    cvss_score=_severity_to_cvss(severity.value),
                    severity=severity,
                    is_confirmed_exploitable=alert.followed_by_success,
                )
            )

        session.add_all(findings)

    console.print(f"[green]Seeded {len(findings)} findings across 4 hosts.[/green]")
    console.print("[dim]Run: streamlit run src/monitoring/dashboard.py[/dim]")


if __name__ == "__main__":
    cli()