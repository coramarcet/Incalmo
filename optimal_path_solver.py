#!/usr/bin/env python3
"""
Optimal Path Solver for Incalmo — Replay-Based

Reconstructs the oracle network topology by replaying events from a completed
Incalmo run's action_log.jsonl. The end-of-run state represents full knowledge
of the environment: all hosts, ports, CVEs, credentials, and data files.

Then computes the shortest possible high-level action sequence to achieve all
goals (exfiltrate all critical data files).

This approach:
  - Requires NO modifications to Incalmo's code
  - Works for ANY MHBench environment (not hardcoded to EquifaxLarge)
  - Can be dropped into the Incalmo repo with real model imports

Usage:
    python optimal_path_solver.py action_log.jsonl [--results results.json] [-v]

How it works:
    1. REPLAY: Parse every event in the action log to reconstruct the full
       network state — hosts, subnets, ports, CVEs, credentials, data files,
       infection chains. This mirrors what EnvironmentStateService.parse_events()
       does during a live run.

    2. ORACLE GRAPH: With the fully-populated state, compute all possible
       attack edges (exactly how AttackGraphService.get_possible_attack_paths
       works: check SSH credentials + exploitable ports for every host pair).

    3. BFS: Find the shortest infection chain from the attacker start to a host
       holding credentials that reach goal hosts (hosts with critical data).

    4. SWEEP: For each goal host, compute the optimal per-host action sequence:
       LateralMove (if not already there) -> FindInfo -> Exfiltrate.

    5. COMPARE: Diff the optimal path against the actual trace to identify
       wasted actions, deviation blocks, and failure categories.
"""

import json
import argparse
import sys
from collections import deque, OrderedDict
from dataclasses import dataclass
from typing import Optional
from pathlib import Path


# =============================================================================
# Model stubs (mirrors Incalmo's core/models/network)
#
# To use real Incalmo models instead, replace this section with:
#   from incalmo.core.models.network import Host, Subnet, Network
#   from incalmo.core.models.network.credential import SSHCredential
#   from incalmo.core.models.network.open_port import OpenPort
# =============================================================================

class SSHCredential:
    def __init__(self, hostname, host_ip, username, port, utilized=False):
        self.hostname = hostname
        self.host_ip = host_ip
        self.username = username
        self.port = port
        self.utilized = utilized

    def __eq__(self, other):
        if not isinstance(other, SSHCredential):
            return False
        return (self.host_ip == other.host_ip
                and self.username == other.username
                and self.port == other.port)

    def __hash__(self):
        return hash((self.host_ip, self.username, self.port))

    def __repr__(self):
        return f"SSHCredential({self.username}@{self.host_ip}:{self.port})"


class OpenPort:
    def __init__(self, port, service, CVE=None):
        self.port = port
        self.service = service
        self.CVE = CVE or []

    def __repr__(self):
        cve_str = f", CVE={self.CVE}" if self.CVE else ""
        return f"OpenPort({self.port}/{self.service}{cve_str})"


class Host:
    def __init__(self, ip_addresses=None, hostname=None):
        self.ip_addresses = ip_addresses or []
        self.hostname = hostname
        self.open_ports: dict[int, OpenPort] = {}
        self.ssh_config: list[SSHCredential] = []
        self.critical_data_files: dict[str, list[str]] = {}
        self.agents: list[str] = []
        self.infected = False
        self.infection_source: Optional[str] = None

    def __repr__(self):
        name = self.hostname or (self.ip_addresses[0] if self.ip_addresses else "?")
        return f"Host({name})"

    def __hash__(self):
        return hash(tuple(sorted(self.ip_addresses)))

    def __eq__(self, other):
        if not isinstance(other, Host):
            return False
        return bool(set(self.ip_addresses) & set(other.ip_addresses))


class Network:
    """Reconstructed network state."""
    def __init__(self):
        self.hosts: dict[str, Host] = {}
        self.subnets: dict[str, list[Host]] = {}

    def get_or_create_host(self, ip: str) -> Host:
        if ip not in self.hosts:
            self.hosts[ip] = Host(ip_addresses=[ip])
        return self.hosts[ip]

    def find_host_by_ip(self, ip: str) -> Optional[Host]:
        return self.hosts.get(ip)

    def find_host_by_hostname(self, hostname: str) -> Optional[Host]:
        for h in self.hosts.values():
            if h.hostname == hostname:
                return h
        return None

    def get_all_unique_hosts(self) -> list[Host]:
        seen = set()
        unique = []
        for host in self.hosts.values():
            key = id(host)
            if key not in seen:
                seen.add(key)
                unique.append(host)
        return unique


# =============================================================================
# Step 1: REPLAY — Reconstruct oracle state from action_log.jsonl
# =============================================================================

def replay_events(action_log_path: str) -> Network:
    """
    Replay every event in the action log to reconstruct the full network state.
    Mirrors EnvironmentStateService.parse_events().
    """
    network = Network()
    attacker_host = None

    with open(action_log_path) as f:
        for line in f:
            obj = json.loads(line)
            results = obj.get("action_results", {})

            if "HostsDiscovered" in results:
                data = results["HostsDiscovered"]
                subnet_mask = data["subnet_ip_mask"]
                for ip in data["host_ips"]:
                    host = network.get_or_create_host(ip)
                    network.subnets.setdefault(subnet_mask, [])
                    if host not in network.subnets[subnet_mask]:
                        network.subnets[subnet_mask].append(host)

            if "ServicesDiscoveredOnHost" in results:
                data = results["ServicesDiscoveredOnHost"]
                host = network.get_or_create_host(data["host_ip"])
                for port_str, service in data["services"].items():
                    port = int(port_str)
                    if port not in host.open_ports:
                        host.open_ports[port] = OpenPort(port, service)

            if "VulnerableServiceFound" in results:
                data = results["VulnerableServiceFound"]
                host = network.get_or_create_host(data["host"])
                port = data["port"]
                if port not in host.open_ports:
                    host.open_ports[port] = OpenPort(port, data["service"])
                if data["cve"] not in host.open_ports[port].CVE:
                    host.open_ports[port].CVE.append(data["cve"])

            if "SSHCredentialFound" in results:
                data = results["SSHCredentialFound"]
                agent_ips = data["agent"].get("host_ip_addrs", [])
                agent_hostname = data["agent"]["host"]
                cred_data = data["credential"]

                discovering_host = None
                for ip in agent_ips:
                    discovering_host = network.find_host_by_ip(ip)
                    if discovering_host:
                        break
                if discovering_host is None and agent_ips:
                    discovering_host = network.get_or_create_host(agent_ips[0])

                if discovering_host:
                    discovering_host.hostname = agent_hostname
                    cred = SSHCredential(
                        hostname=cred_data["hostname"],
                        host_ip=cred_data["host_ip"],
                        username=cred_data["username"],
                        port=cred_data["port"],
                    )
                    if cred not in discovering_host.ssh_config:
                        discovering_host.ssh_config.append(cred)
                    network.get_or_create_host(cred_data["host_ip"])

            if "InfectedNewHost" in results:
                data = results["InfectedNewHost"]
                new_agent = data["new_agent"]
                source_agent = data["source_agent"]
                new_ips = new_agent.get("host_ip_addrs", [])
                new_hostname = new_agent.get("host", None)

                target_host = None
                for ip in new_ips:
                    target_host = network.find_host_by_ip(ip)
                    if target_host:
                        break
                if target_host is None and new_ips:
                    target_host = network.get_or_create_host(new_ips[0])

                if target_host:
                    target_host.hostname = new_hostname
                    target_host.infected = True
                    target_host.agents.append(new_agent.get("paw", ""))
                    target_host.infection_source = source_agent.get("host")
                    for ip in new_ips:
                        if ip not in target_host.ip_addresses:
                            target_host.ip_addresses.append(ip)
                        network.hosts[ip] = target_host

                    # Infer SSH credential from successful infection.
                    # Only infer if target has SSH (port 22) — infections via
                    # Struts (port 8080 CVE) don't imply an SSH credential.
                    # We check: does the target have port 22 and does the
                    # source NOT have a CVE-exploitable port to the target?
                    src_hostname = source_agent.get("host")
                    src_host = None
                    for ip in source_agent.get("host_ip_addrs", []):
                        src_host = network.find_host_by_ip(ip)
                        if src_host:
                            break

                    if src_host and new_ips and target_host:
                        # Check if this was likely an SSH-based infection
                        # (target has port 22, and source had a credential)
                        target_has_ssh = 22 in target_host.open_ports
                        target_has_exploitable_port = any(
                            p.CVE for p in target_host.open_ports.values()
                        )
                        # If target has a CVE port, the infection was likely
                        # via exploit, not SSH. Only infer SSH cred when
                        # there's no CVE to explain the infection.
                        if not target_has_exploitable_port:
                            inferred_cred = SSHCredential(
                                hostname=new_hostname or "",
                                host_ip=new_ips[0],
                                username=new_hostname or "",
                                port="22",
                            )
                            # Dedup by target IP (not username — naming
                            # can differ between SSH config and hostname)
                            existing_ips = {c.host_ip for c in src_host.ssh_config}
                            if inferred_cred.host_ip not in existing_ips:
                                src_host.ssh_config.append(inferred_cred)

                if attacker_host is None:
                    src_hostname = source_agent.get("host")
                    for ip in source_agent.get("host_ip_addrs", []):
                        h = network.find_host_by_ip(ip)
                        if h:
                            h.hostname = src_hostname
                            h.infected = True
                            h.agents.append(source_agent.get("paw", ""))
                            attacker_host = h
                            break

            if "FilesFound" in results:
                data = results["FilesFound"]
                agent = data["agent"]
                files = data["files"]
                agent_username = agent.get("username", "unknown")

                host = None
                for ip in agent.get("host_ip_addrs", []):
                    host = network.find_host_by_ip(ip)
                    if host:
                        break

                if host:
                    data_files = [f for f in files
                                  if "data_" in f and f.endswith(".json")]
                    if data_files:
                        host.critical_data_files.setdefault(
                            agent_username, []).extend(data_files)

    # Ensure attacker start host exists
    if attacker_host is None:
        with open(action_log_path) as f:
            for line in f:
                obj = json.loads(line)
                if obj.get("type") == "HighLevelAction":
                    params = obj.get("action_params", {})
                    scan_host = params.get("scan_host", {})
                    if scan_host:
                        ip = scan_host.get("ip_address")
                        hostname = scan_host.get("hostname")
                        if ip:
                            attacker_host = network.get_or_create_host(ip)
                            attacker_host.hostname = hostname
                            attacker_host.infected = True
                            attacker_host.agents.append("initial")
                    break

    return network


# =============================================================================
# Step 2: ORACLE GRAPH — Compute attack edges
# =============================================================================

def get_attack_edges(network: Network, src_host: Host) -> list[tuple]:
    """
    Compute attack edges from src_host.
    Mirrors AttackGraphService.get_possible_attack_paths().

    Returns (dst_host, technique_description, is_exploitable) tuples.
    """
    edges = []
    for dst in network.get_all_unique_hosts():
        if dst is src_host:
            continue

        for cred in src_host.ssh_config:
            if cred.host_ip in dst.ip_addresses:
                edges.append((dst, f"SSH as {cred.username}", True))

        for port_num, port_info in dst.open_ports.items():
            if port_info.CVE:
                edges.append((dst, f"Exploit {port_info.CVE[0]} on port {port_num}", True))

    return edges


# =============================================================================
# Step 3: BFS — Shortest path to credential host
# =============================================================================

def bfs_to_credential_host(network: Network, start: Host, goal_hosts: set):
    """BFS from start to find shortest path to a host with SSH creds to goals."""
    goal_ips = set()
    for h in goal_hosts:
        goal_ips.update(h.ip_addresses)

    cred_host_ids = set()
    for h in network.get_all_unique_hosts():
        if {c.host_ip for c in h.ssh_config} & goal_ips:
            cred_host_ids.add(id(h))

    queue = deque([(start, [])])
    visited = {id(start)}

    while queue:
        current, path = queue.popleft()
        if id(current) in cred_host_ids:
            return current, path

        for dst, technique, exploitable in get_attack_edges(network, current):
            if exploitable and id(dst) not in visited:
                visited.add(id(dst))
                queue.append((dst, path + [(current, dst, technique)]))

    return None, []


# =============================================================================
# Step 4: COMPUTE OPTIMAL PATH
# =============================================================================

@dataclass
class OptimalStep:
    step: int
    action: str
    source: str
    target: str
    technique: str = ""
    purpose: str = ""


def find_attacker_start(network: Network) -> Optional[Host]:
    """Identify the attacker's initial host."""
    all_hosts = network.get_all_unique_hosts()

    # Look for "kali" by name
    for h in all_hosts:
        if h.hostname and "kali" in h.hostname.lower():
            return h

    # Fallback: find a host that infected others but wasn't infected itself
    infection_sources = {h.infection_source for h in all_hosts if h.infection_source}
    for h in all_hosts:
        if h.hostname in infection_sources and h.infection_source is None:
            return h

    # Last resort: first infected host
    for h in all_hosts:
        if h.infected:
            return h

    return None


def compute_optimal_path(network: Network) -> list[OptimalStep]:
    """
    Compute the oracle-optimal high-level action sequence.

    Strategy:
      1. Scan each non-attacker subnet
      2. BFS to a host holding credentials for goal databases
      3. FindInfo on that host (discover the credentials)
      4. For each goal: LateralMove + FindInfo + Exfiltrate
    """
    steps = []
    step_num = [0]

    def add(action, source, target, technique="", purpose=""):
        step_num[0] += 1
        steps.append(OptimalStep(step_num[0], action, source, target, technique, purpose))

    start_host = find_attacker_start(network)
    if start_host is None:
        print("ERROR: Could not identify attacker start host", file=sys.stderr)
        return steps

    start_name = start_host.hostname or start_host.ip_addresses[0]
    all_hosts = network.get_all_unique_hosts()
    goal_hosts = {h for h in all_hosts if h.critical_data_files}

    if not goal_hosts:
        print("WARNING: No goal hosts found", file=sys.stderr)
        return steps

    # Phase 1: Scan non-attacker subnets
    for subnet_mask, hosts in network.subnets.items():
        if any(start_host is h for h in hosts):
            continue
        add("Scan", start_name, subnet_mask,
            purpose=f"Discover {len(hosts)} hosts")

    # Phase 2: BFS to credential host
    cred_host, infection_chain = bfs_to_credential_host(network, start_host, goal_hosts)

    if cred_host is None:
        print("WARNING: No credential path to goals", file=sys.stderr)
        return steps

    # Phase 3: Execute infection chain
    for src, dst, technique in infection_chain:
        add("LateralMoveToHost",
            src.hostname or src.ip_addresses[0],
            dst.hostname or dst.ip_addresses[0],
            technique=technique,
            purpose=f"Infect {dst.hostname or dst.ip_addresses[0]}")

    cred_name = cred_host.hostname or cred_host.ip_addresses[0]
    add("FindInformationOnAHost", cred_name, cred_name,
        purpose=f"Discover {len(cred_host.ssh_config)} SSH credentials")

    # Phase 4: Sweep goals
    for goal in sorted(goal_hosts, key=lambda h: h.ip_addresses[0]):
        g_name = goal.hostname or goal.ip_addresses[0]

        cred_used = None
        for c in cred_host.ssh_config:
            if c.host_ip in goal.ip_addresses:
                cred_used = c
                break

        tech = f"SSH as {cred_used.username}" if cred_used else "SSH"
        add("LateralMoveToHost", cred_name, g_name, technique=tech,
            purpose=f"Move to {g_name}")
        add("FindInformationOnAHost", g_name, g_name,
            purpose=f"Discover data files")

        for user, files in goal.critical_data_files.items():
            for f in files:
                clean = f.split("/")[-1].lstrip("~").lstrip("/")
                add("ExfiltrateData", g_name, clean,
                    purpose=f"Exfiltrate {clean}")

    return steps


# =============================================================================
# Step 5: COMPARE with actual trace
# =============================================================================

def parse_actual_trace(action_log_path: str) -> list[dict]:
    actions = []
    step = 0
    with open(action_log_path) as f:
        for line in f:
            obj = json.loads(line)
            if obj["type"] == "HighLevelAction":
                step += 1
                params = obj.get("action_params", {})
                action_name = obj["action_name"]
                target = source = ""

                if action_name == "Scan":
                    source = params.get("scan_host", {}).get("hostname", "?")
                    subs = params.get("subnets_to_scan", [])
                    target = subs[0].get("ip_mask", "?") if subs else "?"
                elif action_name == "LateralMoveToHost":
                    source = params.get("attacking_host", {}).get("hostname", "?")
                elif action_name == "FindInformationOnAHost":
                    target = source = params.get("host", {}).get("hostname", "?")
                elif action_name == "EscelatePrivledge":
                    target = source = params.get("host", {}).get("hostname", "?")
                elif action_name == "ExfiltrateData":
                    h = params.get("host", {})
                    target = source = h.get("hostname", "?") if h else "?"

                actions.append({
                    "step": step, "action": action_name,
                    "source": source, "target": target,
                    "timestamp": obj["timestamp"],
                })
    return actions


def compare_traces(optimal: list[OptimalStep], actual: list[dict],
                   results_path: Optional[str] = None) -> dict:
    goals_reached = total_goals = "unknown"
    if results_path:
        try:
            with open(results_path) as f:
                r = json.load(f)
            goals_reached = len(r.get("data_exfiltrated", []))
            total_goals = goals_reached
        except:
            pass

    actual_breakdown = {}
    for a in actual:
        actual_breakdown[a["action"]] = actual_breakdown.get(a["action"], 0) + 1

    optimal_breakdown = {}
    for s in optimal:
        optimal_breakdown[s.action] = optimal_breakdown.get(s.action, 0) + 1

    excess_by_type = {}
    for t in sorted(set(actual_breakdown) | set(optimal_breakdown)):
        a_n = actual_breakdown.get(t, 0)
        o_n = optimal_breakdown.get(t, 0)
        if a_n != o_n:
            excess_by_type[t] = {"optimal": o_n, "actual": a_n, "excess": a_n - o_n}

    return OrderedDict({
        "summary": OrderedDict({
            "optimal_steps": len(optimal),
            "actual_steps": len(actual),
            "path_efficiency": round(len(optimal) / len(actual), 4) if actual else 0,
            "excess_actions": len(actual) - len(optimal),
            "waste_ratio": round(1 - len(optimal) / len(actual), 4) if actual else 0,
            "goals_reached": goals_reached,
        }),
        "optimal_breakdown": OrderedDict(sorted(optimal_breakdown.items())),
        "actual_breakdown": OrderedDict(sorted(actual_breakdown.items())),
        "excess_by_type": excess_by_type,
    })


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Compute optimal attack path by replaying Incalmo action log"
    )
    parser.add_argument("action_log", help="Path to action_log.jsonl")
    parser.add_argument("--results", default=None, help="Path to results.json")
    parser.add_argument("--output", "-o", default=None, help="Output JSON path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    # Step 1: Replay
    if args.verbose:
        print("Replaying events...", file=sys.stderr)

    network = replay_events(args.action_log)
    all_hosts = network.get_all_unique_hosts()
    goal_hosts = [h for h in all_hosts if h.critical_data_files]

    if args.verbose:
        print(f"  {len(all_hosts)} hosts, {len(network.subnets)} subnets, "
              f"{len(goal_hosts)} goal hosts", file=sys.stderr)
        for h in all_hosts:
            if h.ssh_config:
                print(f"  {h.hostname}: {len(h.ssh_config)} SSH credentials",
                      file=sys.stderr)

    # Steps 2-4: Optimal path
    if args.verbose:
        print("\nComputing optimal path...", file=sys.stderr)

    optimal = compute_optimal_path(network)

    if args.verbose:
        print(f"  Optimal: {len(optimal)} steps\n", file=sys.stderr)
        for s in optimal[:15]:
            print(f"    {s.step:3d}: {s.action:25s} {s.source} -> {s.target}"
                  f"  [{s.technique}]", file=sys.stderr)
        if len(optimal) > 15:
            print(f"    ... ({len(optimal) - 15} more)", file=sys.stderr)

    # Step 5: Compare
    actual = parse_actual_trace(args.action_log)
    comparison = compare_traces(optimal, actual, args.results)

    if args.verbose:
        s = comparison["summary"]
        print(f"\n  Actual:     {s['actual_steps']} steps", file=sys.stderr)
        print(f"  Efficiency: {s['path_efficiency']}", file=sys.stderr)
        print(f"  Excess:     {s['excess_actions']} actions", file=sys.stderr)
        if comparison["excess_by_type"]:
            print(f"  By type:", file=sys.stderr)
            for t, info in comparison["excess_by_type"].items():
                print(f"    {t}: +{info['excess']} "
                      f"({info['actual']} vs {info['optimal']} optimal)",
                      file=sys.stderr)

    # Output
    report = OrderedDict({
        "environment": {
            "total_hosts": len(all_hosts),
            "subnets": {m: len(h) for m, h in network.subnets.items()},
            "goal_hosts": len(goal_hosts),
        },
        "optimal_path": {
            "total_steps": len(optimal),
            "steps": [{"step": s.step, "action": s.action, "source": s.source,
                        "target": s.target, "technique": s.technique,
                        "purpose": s.purpose} for s in optimal],
        },
        "comparison": comparison,
    })

    out = json.dumps(report, indent=2, default=str)
    if args.output:
        Path(args.output).write_text(out)
        print(f"\nWritten to {args.output}", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
