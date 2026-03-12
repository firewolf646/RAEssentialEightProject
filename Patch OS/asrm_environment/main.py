"""Fetch Trend Vision One ASRM data and build one Environment object."""

from __future__ import annotations

import json
import os
import sys
from typing import Any
from urllib.parse import urljoin

import requests

if __package__ in {None, ""}:
    # Allow `python3 main.py` by making sibling modules importable.
    sys.path.append(os.path.dirname(__file__))
    from device import Device
    from environment import Environment
else:
    from .device import Device
    from .environment import Environment


ATTACK_SURFACE_PATH = "/v3.0/asrm/attackSurfaceDevices"
SECURITY_POSTURE_PATH = "/v3.0/asrm/securityPosture"
VULNERABLE_DEVICES_PATH = "/v3.0/asrm/vulnerableDevices"


def require_env(name: str) -> str:
    """Fail fast when a required environment variable is missing."""
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def build_headers(token: str, tmv1_filter: str | None = None) -> dict[str, str]:
    """Build the headers required by Trend APIs."""
    headers = {"Authorization": f"Bearer {token}"}
    if tmv1_filter:
        headers["TMV1-Filter"] = tmv1_filter
    return headers


def get_json(
    session: requests.Session,
    url: str,
    *,
    headers: dict[str, str],
    params: dict[str, Any] | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Make one GET request and return the decoded JSON body."""
    response = session.get(url, headers=headers, params=params, timeout=timeout)
    response.raise_for_status()
    return response.json()


def get_all_items(
    session: requests.Session,
    *,
    base_url: str,
    path: str,
    headers: dict[str, str],
    params: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Follow `nextLink` until every page has been collected."""
    items: list[dict[str, Any]] = []
    page = get_json(session, urljoin(base_url, path.lstrip("/")), headers=headers, params=params)

    while True:
        items.extend(page.get("items", []))
        next_link = page.get("nextLink")
        if not next_link:
            return items
        page = get_json(session, next_link, headers=headers)


def build_environment() -> Environment:
    """
    Build one Environment object from:
      1. security posture
      2. attack surface devices
      3. vulnerable devices
    """
    base_url = require_env("V1_BASE_URL").rstrip("/") + "/"
    token = require_env("V1_TOKEN")
    attack_surface_filter = os.getenv("V1_ATTACK_SURFACE_FILTER")
    vulnerable_devices_filter = os.getenv("V1_VULNERABLE_DEVICES_FILTER")

    with requests.Session() as session:
        # Security posture is a single object, so no pagination is needed.
        posture = get_json(
            session,
            urljoin(base_url, SECURITY_POSTURE_PATH.lstrip("/")),
            headers=build_headers(token),
        )

        # Pull the device inventory first so it becomes the source of truth.
        devices = [
            Device.from_attack_surface_data(item)
            for item in get_all_items(
                session,
                base_url=base_url,
                path=ATTACK_SURFACE_PATH,
                headers=build_headers(token, attack_surface_filter),
                params={"top": 1000},
            )
        ]

        # Ask for `any` so devices without detected CVEs still get scan metadata when available.
        vulnerable_devices = get_all_items(
            session,
            base_url=base_url,
            path=VULNERABLE_DEVICES_PATH,
            headers=build_headers(token, vulnerable_devices_filter),
            params={"top": 200, "cveDetectionStatus": "any"},
        )

    devices_by_id = {device.id: device for device in devices}
    devices_by_name = {device.deviceName: device for device in devices}

    # Merge vulnerability data onto the matching attack surface device.
    for item in vulnerable_devices:
        device = devices_by_id.get(item["id"]) or devices_by_name.get(item["deviceName"])
        if device:
            device.apply_vulnerability_data(item)

    return Environment.from_security_posture_data(posture, devices)


def main() -> None:
    """Build the environment and print it as formatted JSON."""
    print(json.dumps(build_environment().to_dict(), indent=2))


if __name__ == "__main__":
    main()
