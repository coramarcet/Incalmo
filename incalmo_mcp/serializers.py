"""
Serialization helpers that convert Incalmo domain objects to JSON-safe dicts.

All public functions take a single domain object and return a plain dict.
`host_by_ip` is a lookup helper included here because it is used by the
resource modules and depends on the live env service.
"""

from __future__ import annotations

from .server import get_services


def serialize_agent(agent) -> dict:
    return {
        "paw": agent.paw,
        "username": agent.username,
        "privilege": agent.privilege,
        "pid": agent.pid,
        "hostname": agent.hostname,
        "host_ips": agent.host_ip_addrs,
        "last_beacon": agent.last_beacon.isoformat() if agent.last_beacon else None,
    }


def serialize_credential(cred) -> dict:
    return {
        "hostname": cred.hostname,
        "host_ip": cred.host_ip,
        "username": cred.username,
        "port": str(cred.port),
        "utilized": cred.utilized,
        "discovered_by_agent": (
            cred.agent_discovered.paw if cred.agent_discovered else None
        ),
    }


def serialize_open_port(port_num: int, open_port) -> dict:
    return {"port": port_num, "service": open_port.service, "cves": open_port.CVE}


def serialize_host(host) -> dict:
    return {
        "hostname": host.hostname,
        "ip_addresses": host.ip_addresses,
        "infected": host.infected,
        "agents": [serialize_agent(a) for a in host.agents],
        "open_ports": {
            str(p): serialize_open_port(p, op) for p, op in host.open_ports.items()
        },
        "ssh_credentials": [serialize_credential(c) for c in host.ssh_config],
        "critical_data_files": host.critical_data_files,
        "infected_by_agent": (
            host.infection_source_agent.paw if host.infection_source_agent else None
        ),
    }


def serialize_subnet(subnet) -> dict:
    return {
        "ip_mask": subnet.ip_mask,
        "attacker_subnet": subnet.attacker_subnet,
        "hosts": [serialize_host(h) for h in subnet.hosts],
    }


def serialize_attack_path(path) -> dict:
    technique = path.attack_technique
    return {
        "attack_host": {
            "hostname": path.attack_host.hostname,
            "ip_addresses": path.attack_host.ip_addresses,
        },
        "target_host": {
            "hostname": path.target_host.hostname,
            "ip_addresses": path.target_host.ip_addresses,
        },
        "technique": {
            "type": "credential" if technique.CredentialToUse else "port_exploit",
            "credential": (
                serialize_credential(technique.CredentialToUse)
                if technique.CredentialToUse
                else None
            ),
            "port_to_attack": technique.PortToAttack,
        },
    }


def host_by_ip(host_ip: str):
    """Look up a host by IP address; raise ValueError if not found."""
    env, _ = get_services()
    host = env.network.find_host_by_ip(host_ip)
    if host is None:
        raise ValueError(f"No host found with IP address '{host_ip}'")
    return host
