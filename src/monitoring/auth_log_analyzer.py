"""
Auth log analyzer: parses SSH (auth.log/syslog format) and simulated RDP
(xrdp.log) authentication events, detecting brute-force patterns and
successful logins following a burst of failures — the SEPE curriculum
topic "Análisis de eventos de autenticación".

Parsing is line-based and regex-driven (no log-shipping infra required for
the lab), deliberately narrow to the two log formats the lab containers
actually produce.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class AuthEventType(str, Enum):
    LOGIN_FAILURE = "login_failure"
    LOGIN_SUCCESS = "login_success"


@dataclass(frozen=True)
class AuthEvent:
    """A single parsed authentication event."""

    event_type: AuthEventType
    username: str
    source_ip: str
    timestamp_raw: str
    service: str  # "ssh" or "rdp"


@dataclass(frozen=True)
class BruteForceAlert:
    """A detected brute-force pattern: N+ failures from one IP within a window,
    optionally followed by a success (which escalates severity)."""

    source_ip: str
    username_attempts: list[str]
    failure_count: int
    followed_by_success: bool
    service: str


# --- SSH (auth.log / syslog format) --------------------------------------
# Example line:
# Aug  4 18:20:11 host sshd[1234]: Failed password for admin from 10.0.0.5 port 51422 ssh2
_SSH_FAILURE_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+Failed password for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
_SSH_SUCCESS_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+Accepted password for "
    r"(?P<user>\S+) from (?P<ip>[\d.]+)"
)

# --- Simulated RDP (xrdp.log format) --------------------------------------
# Example line:
# [20260804-18:20:11] [ERROR] Login failed for user 'admin' from 10.0.0.5
# [20260804-18:20:15] [INFO]  Login successful for user 'admin' from 10.0.0.5
_RDP_FAILURE_RE = re.compile(
    r"\[(?P<ts>[\d\-:]+)\]\s+\[ERROR\]\s+Login failed for user '(?P<user>[^']+)' "
    r"from (?P<ip>[\d.]+)"
)
_RDP_SUCCESS_RE = re.compile(
    r"\[(?P<ts>[\d\-:]+)\]\s+\[INFO\]\s+Login successful for user '(?P<user>[^']+)' "
    r"from (?P<ip>[\d.]+)"
)

_MAX_LINE_LENGTH = 2000  # ReDoS guard, consistent with NHI Shield's approach


class AuthLogAnalyzer:
    """Parses auth log text into AuthEvents and detects brute-force patterns."""

    def __init__(self, brute_force_threshold: int = 5) -> None:
        self.brute_force_threshold = brute_force_threshold

    def parse_ssh_log(self, log_text: str) -> list[AuthEvent]:
        """Parse SSH auth.log-format text into AuthEvent objects."""
        events: list[AuthEvent] = []
        for line in log_text.splitlines():
            safe_line = line[:_MAX_LINE_LENGTH]

            failure = _SSH_FAILURE_RE.search(safe_line)
            if failure:
                events.append(
                    AuthEvent(
                        event_type=AuthEventType.LOGIN_FAILURE,
                        username=failure.group("user"),
                        source_ip=failure.group("ip"),
                        timestamp_raw=failure.group("ts"),
                        service="ssh",
                    )
                )
                continue

            success = _SSH_SUCCESS_RE.search(safe_line)
            if success:
                events.append(
                    AuthEvent(
                        event_type=AuthEventType.LOGIN_SUCCESS,
                        username=success.group("user"),
                        source_ip=success.group("ip"),
                        timestamp_raw=success.group("ts"),
                        service="ssh",
                    )
                )
        return events

    def parse_rdp_log(self, log_text: str) -> list[AuthEvent]:
        """Parse simulated xrdp.log-format text into AuthEvent objects."""
        events: list[AuthEvent] = []
        for line in log_text.splitlines():
            safe_line = line[:_MAX_LINE_LENGTH]

            failure = _RDP_FAILURE_RE.search(safe_line)
            if failure:
                events.append(
                    AuthEvent(
                        event_type=AuthEventType.LOGIN_FAILURE,
                        username=failure.group("user"),
                        source_ip=failure.group("ip"),
                        timestamp_raw=failure.group("ts"),
                        service="rdp",
                    )
                )
                continue

            success = _RDP_SUCCESS_RE.search(safe_line)
            if success:
                events.append(
                    AuthEvent(
                        event_type=AuthEventType.LOGIN_SUCCESS,
                        username=success.group("user"),
                        source_ip=success.group("ip"),
                        timestamp_raw=success.group("ts"),
                        service="rdp",
                    )
                )
        return events

    def detect_brute_force(self, events: list[AuthEvent]) -> list[BruteForceAlert]:
        """Group events by (source_ip, service) and flag IPs whose failure
        count meets or exceeds the threshold. Order-preserving, deterministic.
        """
        by_source: dict[tuple[str, str], list[AuthEvent]] = defaultdict(list)
        for event in events:
            by_source[(event.source_ip, event.service)].append(event)

        alerts: list[BruteForceAlert] = []
        for (source_ip, service), ip_events in by_source.items():
            failures = [e for e in ip_events if e.event_type == AuthEventType.LOGIN_FAILURE]
            if len(failures) < self.brute_force_threshold:
                continue

            followed_by_success = any(
                e.event_type == AuthEventType.LOGIN_SUCCESS for e in ip_events
            )
            alerts.append(
                BruteForceAlert(
                    source_ip=source_ip,
                    username_attempts=[e.username for e in failures],
                    failure_count=len(failures),
                    followed_by_success=followed_by_success,
                    service=service,
                )
            )

        return alerts
