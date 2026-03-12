"""Device model built from Attack Surface Discovery and Vulnerable Devices data."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

try:
    from .vulnerability import Vulnerability
except ImportError:  # pragma: no cover - allows direct script execution.
    from vulnerability import Vulnerability


@dataclass(slots=True)
class Device:
    # These fields mirror `/v3.0/asrm/attackSurfaceDevices`.
    deviceName: str
    id: str
    latestRiskScore: int | float
    criticality: str
    osName: str
    osPlatform: str
    ip: list[str]
    lastUser: str
    cveCount: int
    installedAgents: list[str]
    discoveredBy: list[str]
    firstSeenDateTime: str
    lastDetectDateTime: str
    assetCustomTags: list[dict[str, Any]]
    # These fields are added from `/v3.0/asrm/vulnerableDevices`.
    lastScannedDateTime: str | None = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    @classmethod
    def from_attack_surface_data(cls, data: dict[str, Any]) -> "Device":
        """Build a device from one attack surface device record."""
        return cls(
            deviceName=data["deviceName"],
            id=data["id"],
            latestRiskScore=data["latestRiskScore"],
            criticality=data["criticality"],
            osName=data["osName"],
            osPlatform=data["osPlatform"],
            ip=data.get("ip", []),
            lastUser=data["lastUser"],
            cveCount=data["cveCount"],
            installedAgents=data.get("installedAgents", []),
            discoveredBy=data.get("discoveredBy", []),
            firstSeenDateTime=data["firstSeenDateTime"],
            lastDetectDateTime=data["lastDetectDateTime"],
            assetCustomTags=data.get("assetCustomTags", []),
        )

    def apply_vulnerability_data(self, data: dict[str, Any]) -> None:
        """Attach the vulnerability scan output to an existing device."""
        self.lastScannedDateTime = data.get("lastScannedDateTime")
        self.vulnerabilities = [
            Vulnerability.from_api_data(record) for record in data.get("cveRecords", [])
        ]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable version of the device."""
        return asdict(self)
