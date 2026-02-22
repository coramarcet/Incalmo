"""Attack graph resources — subscribe for live attack-path data."""

from __future__ import annotations

import json

from ..serializers import host_by_ip, serialize_attack_path
from ..server import get_services, mcp_server


@mcp_server.resource(
    "incalmo://attack-graph/executed-paths",
    name="Executed Attack Paths",
    description=(
        "All attack paths that have already been executed in this engagement. "
        "Each entry shows the attacking host, target host, and technique used "
        "(credential-based SSH or port/service exploit). Subscribe to avoid "
        "planning redundant re-attacks."
    ),
    mime_type="application/json",
)
def resource_executed_paths() -> str:
    _, graph = get_services()
    return json.dumps(
        [serialize_attack_path(p) for p in graph.executed_attack_paths], indent=2
    )


@mcp_server.resource(
    "incalmo://attack-graph/from/{host_ip}",
    name="Attack Paths From Host",
    description=(
        "All attack paths that can be launched from the compromised host "
        "identified by {host_ip}. Each path specifies a reachable target host "
        "and the technique to use: an SSH credential or a vulnerable port/service "
        "exploit. Subscribe to a specific host's URI to track its options as new "
        "hosts and credentials are discovered."
    ),
    mime_type="application/json",
)
def resource_attack_paths_from(host_ip: str) -> str:
    _, graph = get_services()
    host = host_by_ip(host_ip)
    paths = graph.get_possible_targets_from_host(host)
    return json.dumps([serialize_attack_path(p) for p in paths], indent=2)


@mcp_server.resource(
    "incalmo://attack-graph/to/{host_ip}",
    name="Attack Paths To Host",
    description=(
        "All attack paths from any currently-compromised host toward the target "
        "host identified by {host_ip}. Useful when you know which host to attack "
        "next and want to find the best launching point and technique. Subscribe "
        "to be notified as new compromised hosts that can reach this target appear."
    ),
    mime_type="application/json",
)
def resource_attack_paths_to(host_ip: str) -> str:
    _, graph = get_services()
    host = host_by_ip(host_ip)
    paths = graph.get_attack_paths_to_target(host)
    return json.dumps([serialize_attack_path(p) for p in paths], indent=2)


@mcp_server.resource(
    "incalmo://attack-graph/exfiltration/{host_ip}",
    name="Exfiltration Path",
    description=(
        "The chain of hosts that can relay data from the host identified by "
        "{host_ip} to an HTTP-reachable exfiltration point accessible by the "
        "attacker. Returns null when no exfiltration path currently exists. "
        "Subscribe to be notified when a path becomes available as the network "
        "is further compromised."
    ),
    mime_type="application/json",
)
def resource_exfiltration_path(host_ip: str) -> str:
    _, graph = get_services()
    host = host_by_ip(host_ip)
    path = graph.find_exfiltration_path(host)
    if path is None:
        return json.dumps(None)
    return json.dumps(
        [{"hostname": h.hostname, "ip_addresses": h.ip_addresses} for h in path],
        indent=2,
    )
