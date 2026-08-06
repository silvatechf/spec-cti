"""
Network perimeter auditor: checks the lab's simulated "internet-facing"
boundary — which services are reachable from outside the segmented network,
and router/gateway configuration weaknesses — covering the SEPE curriculum
topic "Auditorías de perímetro y routers".

Builds on PortScanner (src/scanner/port_scanner.py) rather than duplicating
scanning logic; this module adds the perimeter-specific interpretation
layer (which open ports constitute a perimeter exposure) and router
configuration checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from src.core.lab_orchestrator import LabOrchestrator
from src.scanner.port_scanner import PortScanner, ScanResult

# Ports that should never be reachable directly from the "internet" side of
# a perimeter without a VPN/bastion in front of them.
_HIGH_RISK_PERIMETER_PORTS: dict[int, str] = {
    3389: "RDP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
}


class ExposureSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    INFO = "info"


@dataclass(frozen=True)
class PerimeterExposure:
    """A single perimeter finding: a port reachable that shouldn't be."""

    host: str
    port: int
    service_guess: str
    severity: ExposureSeverity
    recommendation: str


class PerimeterAuditor:
    """Audits which lab-network services are exposed on the "perimeter"
    (i.e., reachable without going through a bastion/VPN boundary)."""

    def __init__(self, port_scanner: PortScanner | None = None) -> None:
        self._scanner = port_scanner or PortScanner()

    def audit_host(self, host: str) -> list[PerimeterExposure]:
        """Scan `host` and flag any high-risk perimeter port found open."""
        scan_result: ScanResult = self._scanner.scan_tcp(host, ports="1-10000")
        exposures: list[PerimeterExposure] = []

        for port_result in scan_result.ports:
            if port_result.state != "open":
                continue
            if port_result.port not in _HIGH_RISK_PERIMETER_PORTS:
                continue

            service_name = _HIGH_RISK_PERIMETER_PORTS[port_result.port]
            severity = (
                ExposureSeverity.CRITICAL
                if port_result.port in {3389, 23, 3306, 5432, 6379, 9200}
                else ExposureSeverity.HIGH
            )
            exposures.append(
                PerimeterExposure(
                    host=host,
                    port=port_result.port,
                    service_guess=service_name,
                    severity=severity,
                    recommendation=(
                        f"Restrict {service_name} (port {port_result.port}) to a VPN/bastion "
                        "allow-list; never expose directly to an untrusted network."
                    ),
                )
            )

        return exposures

    def audit_fleet(self, hosts: list[str]) -> dict[str, list[PerimeterExposure]]:
        """Audit multiple hosts and return exposures keyed by host."""
        return {host: self.audit_host(host) for host in hosts}


# --------------------------------------------------------------------------
# Router / gateway configuration checks
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class RouterCheckResult:
    check_id: str
    title: str
    passed: bool
    evidence: str
    remediation: str


class RouterAuditor:
    """Checks a simulated router/gateway container's configuration.

    In this lab, the 'router' role is played by whichever container exposes
    a gateway-style config (e.g. iptables rules) — the orchestrator is used
    to inspect that config directly, consistent with the rest of the project's
    Docker-exec-based approach (no real router hardware involved).
    """

    def __init__(self, orchestrator: LabOrchestrator | None = None) -> None:
        self._orchestrator = orchestrator or LabOrchestrator()

    def check_default_deny_policy(self, container: str) -> RouterCheckResult:
        """iptables INPUT chain should default to DROP/REJECT, not ACCEPT."""
        exit_code, output = self._orchestrator.exec_in_container(
            container, ["sh", "-c", "iptables -L INPUT | head -1"]
        )
        passed = exit_code == 0 and ("DROP" in output or "REJECT" in output)
        return RouterCheckResult(
            check_id="router_default_deny",
            title="Default-deny policy on INPUT chain",
            passed=passed,
            evidence=output.strip(),
            remediation="Set default INPUT policy to DROP and explicitly allow required ports.",
        )

    def check_no_management_interface_on_wan(self, container: str) -> RouterCheckResult:
        """Router admin/management ports (e.g. 80/443/22 for admin UI) must
        not be bound on a WAN-facing interface — checked via iptables rule
        inspection for explicit WAN-interface allow rules on those ports."""
        exit_code, output = self._orchestrator.exec_in_container(
            container, ["sh", "-c", "iptables -L INPUT -v -n | grep -E '(80|443|22)\\s'"]
        )
        wan_exposed = exit_code == 0 and "eth0" in output  # convention: eth0 = WAN in this lab
        return RouterCheckResult(
            check_id="router_no_wan_admin",
            title="Management interface not exposed on WAN",
            passed=not wan_exposed,
            evidence=output.strip() or "(no matching rule found)",
            remediation="Restrict admin ports to the LAN-facing interface only.",
        )

    def run_all(self, container: str) -> list[RouterCheckResult]:
        return [
            self.check_default_deny_policy(container),
            self.check_no_management_interface_on_wan(container),
        ]
