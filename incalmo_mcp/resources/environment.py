"""Environment state resources — subscribe for live network and agent data."""

from __future__ import annotations

import json

from ..serializers import serialize_agent, serialize_host, serialize_subnet
from ..server import get_services, mcp_server


@mcp_server.resource(
    "incalmo://environment/network",
    name="Network State",
    description=(
        "The current full network topology: every known subnet with its hosts, "
        "each host's IP addresses, hostname, infection status, active C2 agents, "
        "open ports and their services/CVEs, discovered SSH credentials, and any "
        "critical data files found on that host. Subscribe to receive updates "
        "whenever the environment state changes."
    ),
    mime_type="application/json",
)
def resource_network_state() -> str:
    env, _ = get_services()
    payload = {
        "subnets": [serialize_subnet(s) for s in env.network.subnets],
        "summary": {
            "total_hosts_discovered": len(env.network.get_all_hosts()),
            "compromised_hosts": len(env.get_hosts_with_agents()),
            "uncompromised_hosts": len(env.get_hosts_without_agents()),
            "exfiltrated_files": len(env.exfiltrated_data),
        },
    }
    return json.dumps(payload, indent=2)


@mcp_server.resource(
    "incalmo://environment/agents",
    name="Active Agents",
    description=(
        "All active C2 agents currently deployed across the network. Each entry "
        "includes the agent's paw identifier, username, privilege level "
        "(user or root), host IPs, hostname, and last-beacon timestamp. "
        "Subscribe to detect newly-compromised hosts."
    ),
    mime_type="application/json",
)
def resource_agents() -> str:
    env, _ = get_services()
    return json.dumps([serialize_agent(a) for a in env.get_agents()], indent=2)


@mcp_server.resource(
    "incalmo://environment/hosts/compromised",
    name="Compromised Hosts",
    description=(
        "Hosts that have at least one active C2 agent running on them. "
        "Includes full host details: IPs, open ports, discovered credentials, "
        "and critical data files. Subscribe to track lateral-movement progress."
    ),
    mime_type="application/json",
)
def resource_compromised_hosts() -> str:
    env, _ = get_services()
    return json.dumps(
        [serialize_host(h) for h in env.get_hosts_with_agents()], indent=2
    )


@mcp_server.resource(
    "incalmo://environment/hosts/uncompromised",
    name="Uncompromised Hosts",
    description=(
        "Discovered hosts that do not yet have an active C2 agent — targets "
        "that have been seen in scans but are not yet compromised. Includes "
        "IPs, hostname, and open ports/services. Subscribe to track remaining targets."
    ),
    mime_type="application/json",
)
def resource_uncompromised_hosts() -> str:
    env, _ = get_services()
    return json.dumps(
        [serialize_host(h) for h in env.get_hosts_without_agents()], indent=2
    )


@mcp_server.resource(
    "incalmo://environment/exfiltrated-data",
    name="Exfiltrated Data",
    description=(
        "Files that have been successfully exfiltrated from target hosts during "
        "this engagement, along with their MD5 hashes. Subscribe to monitor "
        "data-exfiltration progress."
    ),
    mime_type="application/json",
)
def resource_exfiltrated_data() -> str:
    env, _ = get_services()
    return json.dumps(
        [{"file": e.file, "md5_hash": e.hash} for e in env.exfiltrated_data],
        indent=2,
    )
