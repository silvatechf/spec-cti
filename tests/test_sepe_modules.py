"""
Consolidated test suite for the SEPE-curriculum modules: hardening,
auth log analysis, network/wireless audit, and controlled brute force.

Kept in fewer files deliberately, grouped by module under test, to keep
the suite easy to navigate without proliferating near-empty test files.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.exploit_simulator.brute_force import BruteForceSimulator, UnsafeBruteForceTargetError
from src.hardening.linux_hardening import CheckStatus, LinuxHardeningAuditor
from src.hardening.windows_hardening import WindowsHardeningAuditor
from src.monitoring.auth_log_analyzer import AuthEventType, AuthLogAnalyzer
from src.network_audit.wireless_audit_simulator import (
    AccessPointProfile,
    EncryptionType,
    WirelessAuditSimulator,
    WirelessCheckSeverity,
)

# --------------------------------------------------------------------------
# LinuxHardeningAuditor
# --------------------------------------------------------------------------


class TestLinuxHardening:
    def test_ssh_root_login_check_passes_when_disabled(self) -> None:
        orchestrator = MagicMock()
        orchestrator.exec_in_container.return_value = (0, "PermitRootLogin no")
        auditor = LinuxHardeningAuditor(orchestrator)

        result = auditor.check_ssh_root_login_disabled("lab-linux-server-1")

        assert result.status == CheckStatus.PASS

    def test_ssh_root_login_check_fails_when_enabled(self) -> None:
        orchestrator = MagicMock()
        orchestrator.exec_in_container.return_value = (0, "PermitRootLogin yes")
        auditor = LinuxHardeningAuditor(orchestrator)

        result = auditor.check_ssh_root_login_disabled("lab-linux-server-1")

        assert result.status == CheckStatus.FAIL

    def test_shadow_permissions_pass_for_secure_mode(self) -> None:
        orchestrator = MagicMock()
        orchestrator.exec_in_container.return_value = (0, "640")
        auditor = LinuxHardeningAuditor(orchestrator)

        result = auditor.check_shadow_permissions("lab-linux-server-1")

        assert result.status == CheckStatus.PASS

    def test_shadow_permissions_fail_for_world_readable(self) -> None:
        orchestrator = MagicMock()
        orchestrator.exec_in_container.return_value = (0, "644")
        auditor = LinuxHardeningAuditor(orchestrator)

        result = auditor.check_shadow_permissions("lab-linux-server-1")

        assert result.status == CheckStatus.FAIL

    def test_run_all_returns_seven_checks(self) -> None:
        orchestrator = MagicMock()
        orchestrator.exec_in_container.return_value = (0, "0")
        auditor = LinuxHardeningAuditor(orchestrator)

        results = auditor.run_all("lab-linux-server-1")

        assert len(results) == 7


# --------------------------------------------------------------------------
# WindowsHardeningAuditor (simulated via xrdp/Samba)
# --------------------------------------------------------------------------


class TestWindowsHardening:
    def test_rdp_nla_fails_for_legacy_rdp_security(self) -> None:
        orchestrator = MagicMock()
        orchestrator.exec_in_container.return_value = (0, "security_layer=rdp")
        auditor = WindowsHardeningAuditor(orchestrator)

        result = auditor.check_rdp_nla_enabled("lab-windows-workstation")

        assert result.status == CheckStatus.FAIL

    def test_rdp_nla_passes_for_negotiate(self) -> None:
        orchestrator = MagicMock()
        orchestrator.exec_in_container.return_value = (0, "security_layer=negotiate")
        auditor = WindowsHardeningAuditor(orchestrator)

        result = auditor.check_rdp_nla_enabled("lab-windows-workstation")

        assert result.status == CheckStatus.PASS

    def test_smb_signing_mandatory_passes(self) -> None:
        orchestrator = MagicMock()
        orchestrator.exec_in_container.return_value = (0, "server signing = mandatory")
        auditor = WindowsHardeningAuditor(orchestrator)

        result = auditor.check_smb_signing_required("lab-windows-workstation")

        assert result.status == CheckStatus.PASS

    def test_guest_access_enabled_fails(self) -> None:
        orchestrator = MagicMock()
        orchestrator.exec_in_container.return_value = (0, "map to guest = Bad User")
        auditor = WindowsHardeningAuditor(orchestrator)

        result = auditor.check_guest_access_disabled("lab-windows-workstation")

        assert result.status == CheckStatus.FAIL


# --------------------------------------------------------------------------
# AuthLogAnalyzer
# --------------------------------------------------------------------------


class TestAuthLogAnalyzer:
    def test_parses_ssh_failure_line(self) -> None:
        analyzer = AuthLogAnalyzer()
        log = "Aug  4 18:20:11 host sshd[1234]: Failed password for admin from 10.0.0.5 port 51422 ssh2"

        events = analyzer.parse_ssh_log(log)

        assert len(events) == 1
        assert events[0].event_type == AuthEventType.LOGIN_FAILURE
        assert events[0].username == "admin"
        assert events[0].source_ip == "10.0.0.5"

    def test_parses_ssh_success_line(self) -> None:
        analyzer = AuthLogAnalyzer()
        log = "Aug  4 18:22:00 host sshd[1234]: Accepted password for admin from 10.0.0.5 port 51422 ssh2"

        events = analyzer.parse_ssh_log(log)

        assert events[0].event_type == AuthEventType.LOGIN_SUCCESS

    def test_parses_rdp_failure_line(self) -> None:
        analyzer = AuthLogAnalyzer()
        log = "[20260804-18:20:11] [ERROR] Login failed for user 'administrator' from 10.0.0.9"

        events = analyzer.parse_rdp_log(log)

        assert len(events) == 1
        assert events[0].service == "rdp"
        assert events[0].event_type == AuthEventType.LOGIN_FAILURE

    def test_detects_brute_force_above_threshold(self) -> None:
        analyzer = AuthLogAnalyzer(brute_force_threshold=3)
        log = "\n".join(
            f"Aug  4 18:20:{i:02d} host sshd[123]: Failed password for admin from 10.0.0.5 port 1 ssh2"
            for i in range(5)
        )
        events = analyzer.parse_ssh_log(log)

        alerts = analyzer.detect_brute_force(events)

        assert len(alerts) == 1
        assert alerts[0].failure_count == 5
        assert alerts[0].followed_by_success is False

    def test_no_alert_below_threshold(self) -> None:
        analyzer = AuthLogAnalyzer(brute_force_threshold=10)
        log = "Aug  4 18:20:00 host sshd[123]: Failed password for admin from 10.0.0.5 port 1 ssh2"
        events = analyzer.parse_ssh_log(log)

        alerts = analyzer.detect_brute_force(events)

        assert alerts == []

    def test_brute_force_followed_by_success_is_flagged(self) -> None:
        analyzer = AuthLogAnalyzer(brute_force_threshold=2)
        log = (
            "Aug  4 18:20:00 host sshd[123]: Failed password for admin from 10.0.0.5 port 1 ssh2\n"
            "Aug  4 18:20:01 host sshd[123]: Failed password for admin from 10.0.0.5 port 1 ssh2\n"
            "Aug  4 18:20:02 host sshd[123]: Accepted password for admin from 10.0.0.5 port 1 ssh2"
        )
        events = analyzer.parse_ssh_log(log)

        alerts = analyzer.detect_brute_force(events)

        assert alerts[0].followed_by_success is True


# --------------------------------------------------------------------------
# WirelessAuditSimulator (fully offline, no real RF)
# --------------------------------------------------------------------------


class TestWirelessAuditSimulator:
    def test_flags_open_encryption_as_critical(self) -> None:
        simulator = WirelessAuditSimulator(wordlist_path=None)
        profile = AccessPointProfile(
            ssid="LabAP", encryption=EncryptionType.OPEN, wps_enabled=False, hidden_ssid=False
        )

        findings = simulator.audit(profile)

        encryption_finding = next(f for f in findings if f.check_id == "wireless_encryption")
        assert encryption_finding.severity == WirelessCheckSeverity.CRITICAL

    def test_wpa3_encryption_is_informational_only(self) -> None:
        simulator = WirelessAuditSimulator(wordlist_path=None)
        profile = AccessPointProfile(
            ssid="LabAP", encryption=EncryptionType.WPA3_SAE, wps_enabled=False, hidden_ssid=False
        )

        findings = simulator.audit(profile)

        encryption_finding = next(f for f in findings if f.check_id == "wireless_encryption")
        assert encryption_finding.severity == WirelessCheckSeverity.INFO

    def test_wps_enabled_flagged_high(self) -> None:
        simulator = WirelessAuditSimulator(wordlist_path=None)
        profile = AccessPointProfile(
            ssid="LabAP", encryption=EncryptionType.WPA2_PSK, wps_enabled=True, hidden_ssid=False
        )

        findings = simulator.audit(profile)

        wps_finding = next(f for f in findings if f.check_id == "wireless_wps")
        assert wps_finding.severity == WirelessCheckSeverity.HIGH

    def test_psk_dictionary_match_flagged_critical(self, tmp_path) -> None:  # noqa: ANN001
        import hashlib

        wordlist = tmp_path / "passwords.txt"
        wordlist.write_text("password\n123456\n")

        weak_psk_hash = hashlib.sha256(b"password").hexdigest()
        simulator = WirelessAuditSimulator(wordlist_path=wordlist)
        profile = AccessPointProfile(
            ssid="LabAP",
            encryption=EncryptionType.WPA2_PSK,
            wps_enabled=False,
            hidden_ssid=False,
            psk_sha256=weak_psk_hash,
        )

        findings = simulator.audit(profile)

        psk_finding = next(f for f in findings if f.check_id == "wireless_psk_strength")
        assert psk_finding.severity == WirelessCheckSeverity.CRITICAL

    def test_psk_not_in_wordlist_is_informational(self, tmp_path) -> None:  # noqa: ANN001
        import hashlib

        wordlist = tmp_path / "passwords.txt"
        wordlist.write_text("password\n123456\n")

        strong_psk_hash = hashlib.sha256(b"Xk9$mQ2vLp7#nR4z").hexdigest()
        simulator = WirelessAuditSimulator(wordlist_path=wordlist)
        profile = AccessPointProfile(
            ssid="LabAP",
            encryption=EncryptionType.WPA2_PSK,
            wps_enabled=False,
            hidden_ssid=False,
            psk_sha256=strong_psk_hash,
        )

        findings = simulator.audit(profile)

        psk_finding = next(f for f in findings if f.check_id == "wireless_psk_strength")
        assert psk_finding.severity == WirelessCheckSeverity.INFO


# --------------------------------------------------------------------------
# BruteForceSimulator — safety-boundary tests are the priority here
# --------------------------------------------------------------------------


class TestBruteForceSimulatorSafety:
    def test_rejects_target_without_lab_prefix(self) -> None:
        orchestrator = MagicMock()
        simulator = BruteForceSimulator(orchestrator)

        with pytest.raises(UnsafeBruteForceTargetError, match="lab-"):
            simulator.run_ssh("production-server", "10.0.0.5")

    def test_rejects_target_not_in_known_containers(self) -> None:
        orchestrator = MagicMock()
        fake_container = MagicMock()
        fake_container.name = "lab-linux-server-1"
        orchestrator.list_lab_containers.return_value = [fake_container]
        simulator = BruteForceSimulator(orchestrator)

        with pytest.raises(UnsafeBruteForceTargetError, match="not a running lab container"):
            simulator.run_ssh("lab-nonexistent", "10.0.0.5")

    def test_accepts_known_lab_container(self, tmp_path) -> None:  # noqa: ANN001
        (tmp_path / "users.txt").write_text("svc_backup\n")
        (tmp_path / "passwords.txt").write_text("wrongpass\n")

        orchestrator = MagicMock()
        fake_container = MagicMock()
        fake_container.name = "lab-linux-server-1"
        orchestrator.list_lab_containers.return_value = [fake_container]

        simulator = BruteForceSimulator(orchestrator, wordlist_dir=tmp_path)
        # host_ip deliberately unreachable in the test sandbox — this proves
        # the safety validation passes and execution proceeds to the (failing)
        # connection attempt, rather than raising UnsafeBruteForceTargetError.
        result = simulator.run_ssh("lab-linux-server-1", "127.0.0.1", port=1)

        assert result.target == "lab-linux-server-1"
        assert result.successful_credentials is None

    def test_attempt_count_is_bounded(self, tmp_path) -> None:  # noqa: ANN001
        (tmp_path / "users.txt").write_text("\n".join(f"user{i}" for i in range(50)))
        (tmp_path / "passwords.txt").write_text("\n".join(f"pass{i}" for i in range(50)))

        orchestrator = MagicMock()
        orchestrator.list_lab_containers.return_value = []
        simulator = BruteForceSimulator(orchestrator, wordlist_dir=tmp_path)

        result = simulator.run_ssh("lab-linux-server-1", "127.0.0.1", port=1)

        assert result.total_attempts <= 200
