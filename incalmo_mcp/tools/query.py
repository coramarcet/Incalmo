"""
Query tools — MCP tools that expose live environment state to the LLM.

Each tool is a thin wrapper around the corresponding resource handler, giving
the LLM named, schema-validated callables it can invoke through the standard
MCP tool-calling protocol rather than requiring it to construct resource URIs.
"""

from __future__ import annotations

from ..resources.attack_graph import (
    resource_attack_paths_from,
    resource_attack_paths_to,
    resource_executed_paths,
    resource_exfiltration_path,
)
from ..resources.environment import (
    resource_agents,
    resource_compromised_hosts,
    resource_exfiltrated_data,
    resource_network_state,
    resource_uncompromised_hosts,
)
from ..server import mcp_server


@mcp_server.tool()
def get_network_state() -> str:
    """
    Return the full network topology as JSON.

    Includes every known subnet with its hosts, each host's IP addresses,
    hostname, infection status, active C2 agents, open ports and their
    services and CVEs, discovered SSH credentials, and any critical data
    files found on that host.

    Call this at the start of each step to orient yourself before deciding
    on the next action.
    """
    return resource_network_state()


@mcp_server.tool()
def get_active_agents() -> str:
    """
    Return all active C2 agents currently deployed across the network.

    Each entry includes the agent's paw identifier, username, privilege
    level (user or root), host IP addresses, hostname, and last-beacon
    timestamp.  Use this to confirm a new host has been compromised or
    to find which agent to pivot from next.
    """
    return resource_agents()


@mcp_server.tool()
def get_compromised_hosts() -> str:
    """
    Return hosts that have at least one active C2 agent.

    Includes full host details: IP addresses, open ports, discovered SSH
    credentials, and critical data files.  Use this to choose a pivot
    point for lateral movement or to identify hosts ready for exfiltration.
    """
    return resource_compromised_hosts()


@mcp_server.tool()
def get_uncompromised_hosts() -> str:
    """
    Return discovered hosts that do not yet have an active C2 agent.

    These are your remaining targets — hosts seen in scans but not yet
    compromised.  Includes IP addresses, hostname, and open ports and
    services.  Use this to plan the next lateral-movement target.
    """
    return resource_uncompromised_hosts()


@mcp_server.tool()
def get_exfiltrated_data() -> str:
    """
    Return files that have already been exfiltrated from target hosts.

    Each entry includes the file path and its MD5 hash.  Call this after
    exfiltrate_data to confirm what was retrieved, and before finishing
    to verify all critical data has been collected.
    """
    return resource_exfiltrated_data()


@mcp_server.tool()
def get_executed_attack_paths() -> str:
    """
    Return attack paths that have already been executed in this engagement.

    Each entry shows the attacking host, target host, and technique used
    (credential-based SSH or port/service exploit).  Check this before
    planning lateral movement to avoid redundant re-attacks.
    """
    return resource_executed_paths()


@mcp_server.tool()
def get_attack_paths_from(host_ip: str) -> str:
    """
    Return all attack paths that can be launched from a compromised host.

    Each path specifies a reachable target host and the technique to use:
    an SSH credential or a vulnerable port/service exploit.

    Parameters
    ----------
    host_ip : str
        IP address of the already-compromised host to query paths from.
    """
    return resource_attack_paths_from(host_ip)


@mcp_server.tool()
def get_attack_paths_to(host_ip: str) -> str:
    """
    Return all attack paths toward a specific target host.

    Shows every currently-compromised host that can reach the target and
    the technique each would use.  Useful when you know which host to
    attack next and want to find the best launching point.

    Parameters
    ----------
    host_ip : str
        IP address of the target host to query paths toward.
    """
    return resource_attack_paths_to(host_ip)


@mcp_server.tool()
def get_exfiltration_path(host_ip: str) -> str:
    """
    Return the exfiltration relay chain from a specific compromised host.

    Shows the sequence of hosts that can relay data from the given host
    to an HTTP-reachable point accessible by the attacker.  Returns null
    when no exfiltration path currently exists.

    Parameters
    ----------
    host_ip : str
        IP address of the compromised host to find an exfiltration path from.
    """
    return resource_exfiltration_path(host_ip)
