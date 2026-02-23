"""
Hardcoded MCP test strategy — exercises every query and execution tool on the
MCP server without any LLM involvement.

This strategy is meant to verify that the MCP server wiring is correct end-to-end
against the standard docker environment:

  attacker (external subnet)
      └─► scan → discovers webserver subnet
  webserver (Apache Struts CVE-2017-5638)
      └─► lateral_move_to_host (Struts exploit)
      └─► find_information → SSH credentials
      └─► escalate_privilege (optional)
  database container
      └─► lateral_move (credential-based SSH)
      └─► find_information → critical data files
      └─► exfiltrate_data

All interactions go through the live MCP server at MCP_URL so that the tool
schemas, argument serialisation, and result parsing are all exercised under
realistic conditions.
"""

from __future__ import annotations

import asyncio
import json
import logging

from langchain_core.tools.base import ToolException
from langchain_mcp_adapters.client import MultiServerMCPClient

from incalmo.core.strategies.incalmo_strategy import IncalmoStrategy

MCP_URL = "http://localhost:8765/sse"

# Seconds to wait for the MCP SSE server to bind after it is started as an
# asyncio task in incalmo_runner.py (before strategy.initialize() is called).
_MCP_STARTUP_WAIT = 2.0

log = logging.getLogger("incalmo.mcp_test")


class MCPTestStrategy(IncalmoStrategy, name="mcp_test"):
    """
    Hardcoded attack sequence driven entirely through MCP tool calls.

    Each call to step() runs the full engagement and returns True when done.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._done = False
        

    async def step(self) -> bool:
        if self._done:
            return True

        # Give the MCP SSE server a moment to start up.
        await asyncio.sleep(_MCP_STARTUP_WAIT)

        client = MultiServerMCPClient(
            {"incalmo": {"url": MCP_URL, "transport": "sse"}}
        )
        
        tools = {t.name: t for t in await client.get_tools()}
        log.info(f"[mcp_test] Connected. Available tools: {list(tools)}")

        async def call(name: str, **kwargs):
            """Invoke an MCP tool and return the parsed result.

            ToolException is caught and returned as {"error": "..."} so a
            single bad call doesn't abort the whole engagement.
            """
            log.info(f"[mcp_test] -> {name}({kwargs})")
            try:
                raw = await tools[name].ainvoke(kwargs)
            except ToolException as exc:
                log.warning(f"[mcp_test] !! {name} failed: {exc}")
                return {"error": str(exc)}
            try:
                result = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                result = raw
            preview = str(result)[:400]
            log.info(f"[mcp_test] <- {name}: {preview}")
            return result

        # ------------------------------------------------------------------
        # Phase 1: orient — survey the live environment
        # ------------------------------------------------------------------
        network = await call("get_network_state")
        _print_section("NETWORK STATE", network)

        agents = await call("get_active_agents")
        _print_section("ACTIVE AGENTS", agents)

        compromised = await call("get_compromised_hosts")
        _print_section("COMPROMISED HOSTS", compromised)

        if not compromised:
            log.error(
                "[mcp_test] No compromised hosts — ensure the initial "
                "C2 agent is running before starting the strategy."
            )
            self._done = True
            return True

        # The only host compromised at the start is the attacker itself.
        # Derive a /24 CIDR for every IP the attacker has so the scan covers
        # all of its network interfaces (mirrors equifax_test.py's explicit
        # two-subnet scan).
        attacker_ips = compromised[0]["ip_addresses"]
        attacker_ip = attacker_ips[0]
        log.info(f"[mcp_test] Attacker IPs: {attacker_ips}")

        subnet_cidrs = list(dict.fromkeys(
            _ip_to_slash24(ip) for ip in attacker_ips
        ))
        log.info(f"[mcp_test] Scanning subnets derived from attacker IPs: {subnet_cidrs}")

        # ------------------------------------------------------------------
        # Phase 2: scan — discover webserver and db subnets from the attacker
        # ------------------------------------------------------------------
        scan_events = await call(
            "scan", host_ip=attacker_ip, subnet_cidrs=subnet_cidrs
        )
        _print_section("SCAN EVENTS", scan_events)

        uncompromised = await call("get_uncompromised_hosts")
        _print_section("UNCOMPROMISED HOSTS (after scan)", uncompromised)

        if not uncompromised:
            log.info("[mcp_test] No uncompromised hosts found after scan.")
            self._done = True
            return True

        # ------------------------------------------------------------------
        # Phase 3: compromise the webserver (Struts exploit)
        # Modelled after equifax_test.py: attacker pivots via 192.168.200.10
        # to reach webserver at 192.168.200.20.
        # ------------------------------------------------------------------
        # Pick the attacker IP that shares a subnet with the webserver.
        attacker_ip_web = _pick_ip_in_subnet(attacker_ips, "192.168.200")
        webserver_ip = "192.168.200.20"
        log.info(f"[mcp_test] Lateral move: {attacker_ip_web} → webserver {webserver_ip}")

        paths_to_web = await call("get_attack_paths_to", host_ip=webserver_ip)
        _print_section(f"ATTACK PATHS TO {webserver_ip}", paths_to_web)

        move_events = await call(
            "lateral_move_to_host",
            target_ip=webserver_ip,
            attacker_ip=attacker_ip_web or attacker_ip,
        )
        _print_section(f"LATERAL MOVE → {webserver_ip}", move_events)

        # ------------------------------------------------------------------
        # Phase 4: find credentials on the webserver (both its IPs)
        # 192.168.201.20 is the webserver's db-network interface; it may not
        # be visible in the model until after a scan of 192.168.201.0/24.
        # The ToolException handler in call() means a miss is non-fatal.
        # ------------------------------------------------------------------
        for ws_ip in [webserver_ip, "192.168.201.20"]:
            info_events = await call("find_information", host_ip=ws_ip)
            _print_section(f"FIND INFORMATION on {ws_ip}", info_events)

        priv_events = await call("escalate_privilege", host_ip=webserver_ip)
        _print_section(f"ESCALATE PRIVILEGE on {webserver_ip}", priv_events)

        executed = await call("get_executed_attack_paths")
        _print_section("EXECUTED ATTACK PATHS", executed)

        # ------------------------------------------------------------------
        # Phase 5: lateral move to the database container
        # Webserver at 192.168.201.20 can reach database at 192.168.201.100.
        # ------------------------------------------------------------------
        database_ip = "192.168.201.100"
        pivot_ip = "192.168.201.20"   # webserver's db-network IP
        log.info(f"[mcp_test] Lateral move: {pivot_ip} → database {database_ip}")

        paths_from_web = await call("get_attack_paths_from", host_ip=webserver_ip)
        _print_section(f"ATTACK PATHS FROM {webserver_ip}", paths_from_web)

        if paths_from_web:
            db_move_events = await call(
                "attack_path_lateral_move",
                attacker_ip=webserver_ip,
                target_ip=database_ip,
            )
        else:
            db_move_events = await call(
                "lateral_move_to_host",
                target_ip=database_ip,
                attacker_ip=pivot_ip,
            )
        _print_section(f"LATERAL MOVE → {database_ip}", db_move_events)

        exfil_path = await call("get_exfiltration_path", host_ip=database_ip)
        _print_section(f"EXFILTRATION PATH from {database_ip}", exfil_path)

        # ------------------------------------------------------------------
        # Phase 6: find critical data and exfiltrate from the database
        # ------------------------------------------------------------------
        db_info_events = await call("find_information", host_ip=database_ip)
        _print_section(f"FIND INFORMATION on {database_ip}", db_info_events)

        exfil_events = await call("exfiltrate_data", target_ip=database_ip)
        _print_section(f"EXFILTRATE DATA from {database_ip}", exfil_events)

        # ------------------------------------------------------------------
        # Phase 9: final summary via query tools
        # ------------------------------------------------------------------
        exfiltrated = await call("get_exfiltrated_data")
        _print_section("EXFILTRATED DATA", exfiltrated)

        compromised_final = await call("get_compromised_hosts")
        _print_section("FINAL COMPROMISED HOSTS", compromised_final)

        log.info(
            f"[mcp_test] Engagement complete. "
            f"Compromised: {len(compromised_final)} host(s), "
            f"Exfiltrated files: {len(exfiltrated)}"
        )

        self._done = True
        return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pick_http_host(hosts: list[dict]) -> dict | None:
    """Return the first host that has an HTTP/HTTPS-related port open."""
    http_ports = {80, 443, 8080, 8443}
    for host in hosts:
        open_ports = {int(p) for p in host.get("open_ports", {}).keys()}
        if open_ports & http_ports:
            return host
    return None

def _print_section(title: str, data) -> None:
    """Pretty-print a labelled section to stdout."""
    border = "=" * 60
    body = json.dumps(data, indent=2) if not isinstance(data, str) else data
    print(f"\n{border}\n  {title}\n{border}\n{body}\n")
    
def _pick_ip_in_subnet(ip_list, subnet_prefix):
    """Return the first IP in ip_list that starts with subnet_prefix."""
    for ip in ip_list:
        if ip.startswith(subnet_prefix):
            return ip
    return None
  
def _ip_to_slash24(ip):
        parts = ip.split('.')
        if len(parts) != 4:
            raise ValueError(f"Invalid IP address: {ip}")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
