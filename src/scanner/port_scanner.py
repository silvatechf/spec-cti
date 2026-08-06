"""
Port and service scanner for lab targets.

Wraps `python-nmap` behind a typed, testable interface. Scans are restricted
to hosts on the isolated lab network by convention (the CLI/API only ever
passes container hostnames/IPs resolved from LabOrchestrator).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

import nmap

logger = logging.getLogger(__name__)


@dataclass
class PortResult:
    """A single discovered open port with its detected service."""

    port: int
    protocol: str  # "tcp" or "udp"
    state: str
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


@dataclass
class ScanResult:
    """Aggregate scan result for one host."""

    host: str
    is_up: bool
    ports: list[PortResult] = field(default_factory=list)
    os_guess: Optional[str] = None


class PortScanner:
    """TCP/UDP port scanning with service/version detection."""

    def __init__(self, nm: Optional[nmap.PortScanner] = None) -> None:
        """Accept an injectable nmap.PortScanner instance for testability."""
        self._nm = nm or nmap.PortScanner()

    def scan_tcp(
        self,
        target: str,
        ports: str = "1-1024",
        service_detection: bool = True,
    ) -> ScanResult:
        """Run a TCP SYN/connect scan against `target` for the given port range.

        Args:
            target: Hostname or IP of a lab container (never a public host).
            ports: nmap-style port range, e.g. "1-1024" or "22,80,443".
            service_detection: If True, adds `-sV` for version detection.

        Returns:
            ScanResult with all discovered open TCP ports.
        """
        arguments = "-sT -Pn"
        if service_detection:
            arguments += " -sV"

        logger.info("Starting TCP scan on %s ports=%s", target, ports)
        self._nm.scan(hosts=target, ports=ports, arguments=arguments)
        return self._parse_result(target, protocol="tcp")

    def scan_udp(self, target: str, ports: str = "53,67,123,161") -> ScanResult:
        """Run a UDP scan against common UDP services on `target`."""
        logger.info("Starting UDP scan on %s ports=%s", target, ports)
        self._nm.scan(hosts=target, ports=ports, arguments="-sU -Pn")
        return self._parse_result(target, protocol="udp")

    def _parse_result(self, target: str, protocol: str) -> ScanResult:
        """Convert raw python-nmap output into a ScanResult dataclass."""
        all_hosts = self._nm.all_hosts()
        if target not in all_hosts:
            return ScanResult(host=target, is_up=False)

        host_data = self._nm[target]
        is_up = host_data.state() == "up"
        ports: list[PortResult] = []

        if protocol in host_data.all_protocols():
            for port in sorted(host_data[protocol].keys()):
                port_info = host_data[protocol][port]
                ports.append(
                    PortResult(
                        port=port,
                        protocol=protocol,
                        state=port_info.get("state", "unknown"),
                        service=port_info.get("name"),
                        product=port_info.get("product") or None,
                        version=port_info.get("version") or None,
                    )
                )

        os_guess = None
        if "osmatch" in host_data and host_data["osmatch"]:
            os_guess = host_data["osmatch"][0].get("name")

        return ScanResult(host=target, is_up=is_up, ports=ports, os_guess=os_guess)

    def scan_lab_range(self, targets: list[str], ports: str = "1-1024") -> list[ScanResult]:
        """Convenience helper to scan multiple lab hosts sequentially."""
        return [self.scan_tcp(t, ports=ports) for t in targets]
