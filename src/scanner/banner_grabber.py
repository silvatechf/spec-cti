"""
Banner grabber: connects to open TCP ports on lab hosts and captures the
service banner (SSH version strings, HTTP Server headers, SMTP greetings,
etc.) for manual and automated fingerprinting.
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Protocols that expect the client to speak first before a banner appears.
_CLIENT_FIRST_PROBES: dict[int, bytes] = {
    80: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    443: b"",  # TLS handshake required; left as a raw-connect attempt only
}


@dataclass
class BannerResult:
    """Result of a single banner-grab attempt."""

    host: str
    port: int
    banner: Optional[str]
    success: bool
    error: Optional[str] = None


class BannerGrabber:
    """Grabs service banners over raw TCP sockets."""

    def __init__(self, timeout: float = 3.0) -> None:
        self.timeout = timeout

    def grab(self, host: str, port: int) -> BannerResult:
        """Connect to host:port and attempt to read a service banner.

        Args:
            host: Target hostname/IP (lab network only).
            port: TCP port to connect to.

        Returns:
            BannerResult containing the raw banner text, if any.
        """
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)

                probe = _CLIENT_FIRST_PROBES.get(port)
                if probe:
                    sock.sendall(probe)

                data = sock.recv(1024)
                banner = data.decode("utf-8", errors="replace").strip()
                logger.info("Grabbed banner from %s:%s -> %s", host, port, banner[:60])
                return BannerResult(host=host, port=port, banner=banner, success=True)

        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            logger.debug("Banner grab failed for %s:%s -> %s", host, port, exc)
            return BannerResult(host=host, port=port, banner=None, success=False, error=str(exc))

    def grab_many(self, host: str, ports: list[int]) -> list[BannerResult]:
        """Grab banners for multiple ports on the same host."""
        return [self.grab(host, port) for port in ports]

    @staticmethod
    def fingerprint_banner(banner: str) -> dict[str, Optional[str]]:
        """Very lightweight heuristic fingerprinting of a raw banner string.

        Not a replacement for `-sV` in nmap — this is meant for the OSINT/
        recon module to produce human-readable hints for CTF "recon" flags.
        """
        lowered = banner.lower()
        product = None
        version = None

        if "openssh" in lowered:
            product = "OpenSSH"
            parts = banner.split("OpenSSH_")
            if len(parts) > 1:
                version = parts[1].split(" ")[0].split(",")[0]
        elif "apache" in lowered:
            product = "Apache"
            if "apache/" in lowered:
                version = lowered.split("apache/")[1].split(" ")[0]
        elif "nginx" in lowered:
            product = "nginx"
            if "nginx/" in lowered:
                version = lowered.split("nginx/")[1].split(" ")[0]
        elif "postfix" in lowered:
            product = "Postfix"

        return {"product": product, "version": version}
