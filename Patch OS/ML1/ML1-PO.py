import json
import os
import sys
import copy
from datetime import datetime, timezone
from typing import Any

PATCH_OS_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CODING_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

for path in (PATCH_OS_ROOT, CODING_ROOT):
    if path not in sys.path:
        sys.path.append(path)

from asrm_environment import Environment, build_environment


def _get_asset_tag_values(device: Any) -> list[str]:
    tags = device.assetCustomTags or []
    values: list[str] = []
    for tag in tags:
        if isinstance(tag, str):
            values.append(tag)
        elif isinstance(tag, dict):
            for key in ("name", "value", "tagName"):
                value = tag.get(key)
                if isinstance(value, str):
                    values.append(value)
    return values


def _parse_iso8601(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_exploit_available(vulnerability: Any) -> bool:
    level = (vulnerability.globalExploitActivityLevel or "").strip().lower()
    return level in {"high", "medium", "critical", "very high", "very_high"}


def ML1_PO_01(environment: Environment) -> tuple[bool, str]:
    total = len(environment.devices)
    beingScannedByNetworkDiscovery = 0

    for device in environment.devices:
        discovery_tools = device.discoveredBy or []
        beingScannedByNetworkDiscovery += sum(
            1
            for discovery_tool in discovery_tools
            if "network sensor" in discovery_tool.lower()
        )

    return (
        beingScannedByNetworkDiscovery == total,
        str(beingScannedByNetworkDiscovery)
        + "/"
        + str(total)
        + " devices discovered with asset discovery tool.",
    )

def ML1_PO_03(environment: Environment) -> tuple[bool, str]:
    total = 0
    compliantN = 0
    for device in environment.devices:
        tags = [tag.lower() for tag in _get_asset_tag_values(device)]
        if "internet-facing" in tags:
            total += 1
            installedAgents = device.installedAgents or []
            if "Trend Vision One Endpoint Sensor" in installedAgents:
                compliantN += 1
    return (
        compliantN == total,
        str(compliantN)
        + "/"
        + str(total)
        + " internet-facing services with daily vulnerability detection.",
    )
            
def ML1_PO_04(environment: Environment) -> tuple[bool, str]:
    total = 0
    compliantN = 0
    for device in environment.devices:
        total += 1
        installedAgents = device.installedAgents or []
        if "Trend Vision One Endpoint Sensor" in installedAgents:
            compliantN += 1
    return (
        compliantN == total,
        str(compliantN)
        + "/"
        + str(total)
        + " operating systems with fortnightly vulnerability detection.",
    )

def ML1_PO_05(environment: Environment) -> tuple[bool, str]:
    for device in environment.devices:
        last_scanned = _parse_iso8601(device.lastScannedDateTime)
        if not last_scanned:
            continue

        for vulnerability in device.vulnerabilities:
            published = _parse_iso8601(vulnerability.publishedDateTime)
            mitigation_status = vulnerability.mitigationStatus.lower()
            if not published:
                continue
            if "patch" not in mitigation_status and "mitigat" not in mitigation_status:
                continue

            hours_to_scan = (last_scanned - published).total_seconds() / 3600
            if 0 <= hours_to_scan <= 48:
                return (
                    True,
                    f"{device.deviceName} has {vulnerability.id} marked as "
                    f"'{vulnerability.mitigationStatus}' within 48 hours of publication.",
                )

    return (
        False,
        "No vulnerability was found with mitigation status indicating patched or mitigated "
        "within 48 hours of publication.",
    )


def ML1_PO_06(environment: Environment) -> tuple[bool, str]:
    total_internet_facing = 0
    non_compliant = 0

    for device in environment.devices:
        tags = [tag.lower() for tag in _get_asset_tag_values(device)]
        if "internet-facing" not in tags:
            continue

        total_internet_facing += 1

        has_old_exploited_vulnerability = False
        for vulnerability in device.vulnerabilities:
            published = _parse_iso8601(vulnerability.publishedDateTime)
            if not published or not _is_exploit_available(vulnerability):
                continue

            age_hours = (datetime.now(timezone.utc) - published).total_seconds() / 3600
            if age_hours > 48:
                has_old_exploited_vulnerability = True
                break

        if has_old_exploited_vulnerability:
            non_compliant += 1

    return (
        non_compliant == 0,
        f"{non_compliant}/{total_internet_facing} internet-facing operating systems "
        "with critical or actively exploited vulnerabilities older than 48 hours",
    )


def ML1_PO_07(environment: Environment) -> tuple[bool, str]:
    total_internet_facing = 0
    non_compliant = 0

    for device in environment.devices:
        tags = [tag.lower() for tag in _get_asset_tag_values(device)]
        if "internet-facing" not in tags:
            continue

        total_internet_facing += 1

        has_old_vulnerability = False
        for vulnerability in device.vulnerabilities:
            published = _parse_iso8601(vulnerability.publishedDateTime)
            if not published:
                continue

            age_days = (datetime.now(timezone.utc) - published).total_seconds() / 86400
            if age_days > 14:
                has_old_vulnerability = True
                break

        if has_old_vulnerability:
            non_compliant += 1

    return (
        non_compliant == 0,
        f"{non_compliant}/{total_internet_facing} internet-facing operating systems "
        "with vulnerabilities older than 2 weeks",
    )


def ML1_PO_09(environment: Environment) -> tuple[bool, str]:
    total_devices = len(environment.devices)
    non_compliant = 0

    for device in environment.devices:
        has_old_vulnerability = False
        for vulnerability in device.vulnerabilities:
            published = _parse_iso8601(vulnerability.publishedDateTime)
            if not published:
                continue

            age_days = (datetime.now(timezone.utc) - published).total_seconds() / 86400
            if age_days > 30:
                has_old_vulnerability = True
                break

        if has_old_vulnerability:
            non_compliant += 1

    return (
        non_compliant == 0,
        f"{non_compliant}/{total_devices} operating systems with vulnerabilities older than 1 month",
    )

def ML1_PO_10(environment: Environment) -> tuple[bool, str]:
    legacy_devices = environment.cveManagementMetrics.get("legacyOSEndpointCount", 0)
    if not isinstance(legacy_devices, (int, float)):
        legacy_devices = 0

    return (
        legacy_devices == 0,
        f"{int(legacy_devices)} legacy devices detected",
    )


def read_json_file(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def build_maturity_level_one_report(
    test_results: dict[str, tuple[bool, str]],
    template_path: str = os.path.join(PATCH_OS_ROOT, "patch_os_template.json"),
) -> dict[str, Any]:
    template = read_json_file(template_path)
    maturity_level_one = copy.deepcopy(template["Maturity Level 1"])
    maturity_level_one["generatedAt"] = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )

    for control in maturity_level_one.get("controls", []):
        for test in control.get("tests", []):
            test_id = test.get("testId")
            function_name = test_id.replace("-", "_") if isinstance(test_id, str) else None
            if not function_name or function_name not in test_results:
                continue

            fulfilled, logic = test_results[function_name]
            technical_control = test.setdefault("technicalControl", {})
            technical_control["technicalControlFulfilled"] = fulfilled
            technical_control["technicalControlLogic"] = logic

    return {
        "Mitigation Strategy": template.get("Mitigation Strategy", "6. Patch OS"),
        "Maturity Level 1": maturity_level_one,
    }


def write_report_file(
    report: dict[str, Any],
    output_dir: str = os.path.join(PATCH_OS_ROOT, "Reports"),
) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"patch_os_{timestamp}.json")

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)
        file.write("\n")

    return output_path



def main() -> None:
    environment = build_environment()
    tests = [
        ("ML1_PO_01", ML1_PO_01),
        ("ML1_PO_03", ML1_PO_03),
        ("ML1_PO_04", ML1_PO_04),
        ("ML1_PO_05", ML1_PO_05),
        ("ML1_PO_06", ML1_PO_06),
        ("ML1_PO_07", ML1_PO_07),
        ("ML1_PO_09", ML1_PO_09),
        ("ML1_PO_10", ML1_PO_10),
    ]

    test_results = {test_name: test_func(environment) for test_name, test_func in tests}
    report = build_maturity_level_one_report(test_results)
    output_path = write_report_file(report)
    print(f"Generated report: {output_path}")


if __name__ == "__main__":
    main()
