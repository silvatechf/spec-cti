"""
LabOrchestrator: the single entry point for controlling the lab's lifecycle
(bring-up, teardown, containment actions, health checks) via the Docker SDK.

Keeping all `docker` SDK calls behind this one class means every other
module (IR containment, CLI, API) talks to a narrow, testable interface
instead of the Docker API directly — which also makes it trivial to mock
in tests without a real Docker daemon.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import docker
from docker.errors import DockerException, NotFound
from docker.models.containers import Container
from docker.models.networks import Network

from src.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

LAB_CONTAINER_PREFIX = "lab-"


@dataclass
class HostStatus:
    """Lightweight snapshot of a lab container's runtime state."""

    name: str
    status: str
    is_online: bool
    ip_address: Optional[str] = None
    networks: Optional[list[str]] = None


class LabOrchestrator:
    """Wraps the Docker SDK to manage lab target containers and networks."""

    def __init__(self, docker_client: Optional[docker.DockerClient] = None) -> None:
        """Initialize with an injectable Docker client (for testing/mocking)."""
        try:
            self._client = docker_client or docker.from_env()
        except DockerException as exc:  # pragma: no cover - environment-dependent
            logger.warning("Docker daemon unavailable: %s", exc)
            self._client = None

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #

    def list_lab_containers(self) -> list[Container]:
        """Return all containers whose name starts with the lab prefix."""
        if self._client is None:
            return []
        return [
            c
            for c in self._client.containers.list(all=True)
            if c.name.startswith(LAB_CONTAINER_PREFIX)
        ]

    def get_host_status(self, container_name: str) -> HostStatus:
        """Return a HostStatus snapshot for a single lab container."""
        if self._client is None:
            return HostStatus(name=container_name, status="unknown", is_online=False)

        try:
            container = self._client.containers.get(container_name)
        except NotFound:
            return HostStatus(name=container_name, status="not_found", is_online=False)

        container.reload()
        networks = list(container.attrs["NetworkSettings"]["Networks"].keys())
        ip_address = None
        for net_name, net_data in container.attrs["NetworkSettings"]["Networks"].items():
            if net_data.get("IPAddress"):
                ip_address = net_data["IPAddress"]
                break

        return HostStatus(
            name=container.name,
            status=container.status,
            is_online=container.status == "running",
            ip_address=ip_address,
            networks=networks,
        )

    def health_check_all(self) -> list[HostStatus]:
        """Return HostStatus for every lab container — used by `make health`."""
        return [self.get_host_status(c.name) for c in self.list_lab_containers()]

    # ------------------------------------------------------------------ #
    # Containment (used by incident_response.containment)
    # ------------------------------------------------------------------ #

    def isolate_container(self, container_name: str) -> bool:
        """Disconnect a container from the lab network to contain an incident.

        This is the automation behind the "Containment" phase of IR: it
        does NOT stop the container (preserving forensic state in memory)
        but severs its network connectivity.
        """
        if self._client is None:
            logger.error("Cannot isolate %s: Docker client unavailable", container_name)
            return False

        try:
            container = self._client.containers.get(container_name)
            network: Network = self._client.networks.get(settings.lab_network_name)
            network.disconnect(container, force=True)
            logger.info("Isolated container %s from %s", container_name, settings.lab_network_name)
            return True
        except (NotFound, DockerException) as exc:
            logger.error("Failed to isolate %s: %s", container_name, exc)
            return False

    def reconnect_container(self, container_name: str) -> bool:
        """Reconnect a previously isolated container — used during Recovery."""
        if self._client is None:
            return False
        try:
            container = self._client.containers.get(container_name)
            network: Network = self._client.networks.get(settings.lab_network_name)
            network.connect(container)
            logger.info("Reconnected container %s to %s", container_name, settings.lab_network_name)
            return True
        except (NotFound, DockerException) as exc:
            logger.error("Failed to reconnect %s: %s", container_name, exc)
            return False

    # ------------------------------------------------------------------ #
    # Lifecycle helpers
    # ------------------------------------------------------------------ #

    def restart_container(self, container_name: str) -> bool:
        """Restart a container — used by eradication after killing persistence."""
        if self._client is None:
            return False
        try:
            container = self._client.containers.get(container_name)
            container.restart(timeout=10)
            return True
        except (NotFound, DockerException) as exc:
            logger.error("Failed to restart %s: %s", container_name, exc)
            return False

    def exec_in_container(self, container_name: str, command: list[str]) -> tuple[int, str]:
        """Run a command inside a lab container and return (exit_code, output).

        Used by exploit simulator and IR modules to perform in-container
        actions (e.g., planting/removing a persistence script).
        """
        if self._client is None:
            return 1, "docker client unavailable"
        try:
            container = self._client.containers.get(container_name)
            result = container.exec_run(command)
            return result.exit_code, result.output.decode("utf-8", errors="replace")
        except (NotFound, DockerException) as exc:
            logger.error("exec_run failed on %s: %s", container_name, exc)
            return 1, str(exc)
