"""
Execution tools — MCP tools that actually run high-level Incalmo actions.

Each tool maps directly to one HighLevelAction class.  Parameters use plain
JSON-serialisable types (strings, lists of strings, bools) so the LLM can
supply them without knowing Incalmo's internal domain model.

All tools return a JSON string describing the events produced by the action.
"""

from __future__ import annotations

import json

from ..server import get_orchestrator, get_services, mcp_server
from ..serializers import host_by_ip

from incalmo.core.actions.HighLevel import (
    EscelatePrivledge,
    ExfiltrateData,
    FindInformationOnAHost,
    LateralMoveToHost,
    Scan,
)
from incalmo.core.actions.HighLevel.attack_path_lateral_move import AttackPathLateralMove


def _events_to_json(events) -> str:
    """Serialise a list of events to a JSON array of their string representations."""
    return json.dumps([str(e) for e in events], indent=2)


def _find_subnet_by_cidr(env, cidr: str):
    """Return the Subnet whose ip_mask matches cidr, or None."""
    for subnet in env.network.subnets:
        if subnet.ip_mask == cidr:
            return subnet
    return None


@mcp_server.tool()
async def scan(host_ip: str, subnet_cidrs: list[str]) -> str:
    """
    Scan one or more subnets from a compromised host to discover new hosts,
    open ports, running services, and HTTP vulnerabilities (Nikto / CVE-2017-5638).

    Parameters
    ----------
    host_ip : str
        IP address of the already-compromised host to scan from.
        Must have at least one active C2 agent.
    subnet_cidrs : list[str]
        CIDR masks of the subnets to scan (e.g. ["10.0.1.0/24", "10.0.2.0/24"]).
        Read subnet CIDRs from the incalmo://environment/network resource
        (the ip_mask field of each subnet).  Pass an empty list to scan all
        known subnets.

    Returns
    -------
    JSON array of event strings produced by the scan.
    """
    env, _ = get_services()
    orch = get_orchestrator()
    scan_host = host_by_ip(host_ip)

    if subnet_cidrs:
        subnets = [_find_subnet_by_cidr(env, c) for c in subnet_cidrs]
        subnets = [s for s in subnets if s is not None]
        if not subnets:
            return json.dumps({"error": f"None of the requested subnet CIDRs were found: {subnet_cidrs}"})
    else:
        subnets = env.network.get_all_subnets()

    events = await orch.run_action(Scan(scan_host=scan_host, subnets_to_scan=subnets))
    return _events_to_json(events)


@mcp_server.tool()
async def find_information(host_ip: str, username: str | None = None) -> str:
    """
    Search a compromised host for SSH credentials and critical data files.

    Discovered SSH credentials enable lateral movement via attack_path_lateral_move
    or lateral_move_to_host.  Discovered critical data files can later be
    retrieved with exfiltrate_data.

    Parameters
    ----------
    host_ip : str
        IP address of the compromised host to search.
    username : str or null
        Restrict the search to one user's context.  Pass null to query all
        agents on the host.

    Returns
    -------
    JSON array of event strings (SSHCredentialFound, CriticalDataFound).
    """
    orch = get_orchestrator()
    host = host_by_ip(host_ip)
    events = await orch.run_action(FindInformationOnAHost(host=host, user=username))
    return _events_to_json(events)


@mcp_server.tool()
async def lateral_move_to_host(
    target_ip: str,
    attacker_ip: str,
    stop_after_success: bool = True,
) -> str:
    """
    Attempt to compromise a target host from an already-compromised host.

    Tries known SSH credentials first, then service exploits
    (CVE-2017-5638 Apache Struts, netcat backdoor on port 4444).

    Parameters
    ----------
    target_ip : str
        IP address of the host to compromise.
    attacker_ip : str
        IP address of the already-compromised host to attack from.
    stop_after_success : bool
        If true (default), stop after the first successful technique.

    Returns
    -------
    JSON array of event strings (InfectedNewHost, RootAccessOnHost).
    """
    orch = get_orchestrator()
    target = host_by_ip(target_ip)
    attacker = host_by_ip(attacker_ip)
    events = await orch.run_action(
        LateralMoveToHost(
            host_to_attack=target,
            attacking_host=attacker,
            stop_after_success=stop_after_success,
        )
    )
    return _events_to_json(events)


@mcp_server.tool()
async def attack_path_lateral_move(
    attacker_ip: str,
    target_ip: str,
    skip_if_already_executed: bool = True,
) -> str:
    """
    Execute a pre-computed attack path from the attack graph.

    Use the incalmo://attack-graph/from/{host_ip} resource to find available
    paths first.  This tool looks up the first available path between the two
    hosts and executes it.  The path is marked as executed so that repeated
    calls with the same pair are skipped (when skip_if_already_executed is true).

    Parameters
    ----------
    attacker_ip : str
        IP address of the already-compromised attacking host.
    target_ip : str
        IP address of the target host to compromise.
    skip_if_already_executed : bool
        If true (default), skip if an equivalent path has already been run.

    Returns
    -------
    JSON array of event strings, or an error object if no path is found.
    """
    _, graph = get_services()
    orch = get_orchestrator()
    attacker = host_by_ip(attacker_ip)
    target = host_by_ip(target_ip)

    paths = graph.get_possible_targets_from_host(attacker)
    matching = [p for p in paths if target_ip in p.target_host.ip_addresses]
    if not matching:
        return json.dumps({
            "error": (
                f"No attack path found from {attacker_ip} to {target_ip}. "
                "Read incalmo://attack-graph/from/{host_ip} to see available paths."
            )
        })

    events = await orch.run_action(
        AttackPathLateralMove(
            attack_path=matching[0],
            skip_if_already_executed=skip_if_already_executed,
        )
    )
    return _events_to_json(events)


@mcp_server.tool()
async def escalate_privilege(host_ip: str) -> str:
    """
    Attempt privilege escalation on a compromised host to gain root access.

    Tries (1) a writeable /etc/passwd exploit, then (2) sudo Baron Samedit
    (CVE-2021-3156) when sudo < 1.8.30.  Skips hosts that already have a
    root-level agent.

    Parameters
    ----------
    host_ip : str
        IP address of the compromised host to escalate privileges on.

    Returns
    -------
    JSON array of event strings (RootAccessOnHost), or empty if not applicable.
    """
    orch = get_orchestrator()
    host = host_by_ip(host_ip)
    events = await orch.run_action(EscelatePrivledge(host=host))
    return _events_to_json(events)


@mcp_server.tool()
async def exfiltrate_data(target_ip: str) -> str:
    """
    Exfiltrate critical data files from a compromised host back to the attacker.

    Requires that critical data files have already been discovered via
    find_information.  Prefers indirect HTTP exfiltration when a compromised
    HTTP server exists; falls back to direct SSH/SCP otherwise.

    Parameters
    ----------
    target_ip : str
        IP address of the compromised host with critical data to exfiltrate.

    Returns
    -------
    JSON array of event strings (ExfiltratedData), or empty if no data is ready.
    """
    orch = get_orchestrator()
    target = host_by_ip(target_ip)
    events = await orch.run_action(ExfiltrateData(target_host=target))
    return _events_to_json(events)
