"""Environment model built from `/v3.0/asrm/securityPosture` plus devices."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

try:
    from .device import Device
except ImportError:  # pragma: no cover - allows direct script execution.
    from device import Device


@dataclass(slots=True)
class Environment:
    # These fields mirror `/v3.0/asrm/securityPosture`.
    schemaVersion: str
    companyId: str
    companyName: str
    createdDateTime: str
    riskIndex: int | float | None
    riskCategoryLevel: dict[str, Any]
    highImpactRiskEvents: list[dict[str, Any]]
    vulnerabilityAssessmentCoverageRate: int | float
    cveManagementMetrics: dict[str, Any]
    exposureStatus: dict[str, Any]
    securityConfigurationStatus: dict[str, Any]
    # The environment also owns the device inventory.
    devices: list[Device]

    @classmethod
    def from_security_posture_data(
        cls, data: dict[str, Any], devices: list[Device]
    ) -> "Environment":
        """Build the parent object from posture data and merged devices."""
        return cls(
            schemaVersion=data["schemaVersion"],
            companyId=data["companyId"],
            companyName=data["companyName"],
            createdDateTime=data["createdDateTime"],
            riskIndex=data.get("riskIndex"),
            riskCategoryLevel=data["riskCategoryLevel"],
            highImpactRiskEvents=data.get("highImpactRiskEvents", []),
            vulnerabilityAssessmentCoverageRate=data["vulnerabilityAssessmentCoverageRate"],
            cveManagementMetrics=data["cveManagementMetrics"],
            exposureStatus=data["exposureStatus"],
            securityConfigurationStatus=data["securityConfigurationStatus"],
            devices=devices,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable version of the environment."""
        return asdict(self)
