"""Load and save trapsnmp configuration in one INI file."""

from __future__ import annotations

import configparser
import json
import logging
import os

from trapsnmp.agent import COMPARISONS
from trapsnmp.paths import DATA_DIR

log = logging.getLogger("trapsnmp.settings")

INI_PATH = DATA_DIR / "trapsnmp.ini"
_JSON_PATH = DATA_DIR / "ge-master.json"

_REMOTE_FIELDS = (
    "ifIndex",
    "mac",
    "key",
    "index",
    "ip",
    "address",
    "name",
    "version",
    "allIp",
    "gateway",
    "link",
    "ttl",
    "nicId",
    "rssi",
    "downRssi",
    "evm",
    "downEvm",
    "mod",
    "downMod",
    "temp",
    "alarmed",
    "oid",
    "txPackets",
    "txBytes",
    "rxPackets",
    "rxBytes",
    "txError",
    "rxError",
    "txDrop",
    "rxDrop",
)
_REMOTE_INTS = {
    "ifIndex",
    "ttl",
    "nicId",
    "rssi",
    "downRssi",
    "evm",
    "downEvm",
    "temp",
    "txPackets",
    "txBytes",
    "rxPackets",
    "rxBytes",
    "txError",
    "rxError",
    "txDrop",
    "rxDrop",
}


def _parser() -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    return parser


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(value: str | None, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def load(service) -> None:
    service._loading = True
    try:
        if not INI_PATH.exists():
            _migrate_master(service)
            return
        parser = _parser()
        parser.read(INI_PATH, encoding="utf-8")
        _apply(service, parser)
    finally:
        service._loading = False
    if not INI_PATH.exists():
        try:
            save(service)
        except OSError:
            # Keep running with defaults; the console shows the next save error.
            log.exception("Could not create %s", INI_PATH)


def save(service) -> None:
    if getattr(service, "_loading", False):
        return
    parser = _parser()
    parser["snmp"] = {"communities": ", ".join(service.snmp.communities)}
    for user in service.snmp.users:
        parser[f"v3.{user['name']}"] = {
            "level": user.get("level", ""),
            "auth": user.get("auth", ""),
            "auth_key": user.get("authKey", ""),
            "priv": user.get("priv", ""),
            "priv_key": user.get("privKey", ""),
        }
    master = service.radios
    parser["master"] = {
        "host": master.host,
        "community": master.community,
        "port": str(master.port),
        "interval": str(master.interval),
        "enabled": "true" if master.enabled else "false",
    }
    parser["tags"] = {
        "community": service.tags.community,
        "device_ip": service.tags.device_ip,
    }
    upstream = service.opc.upstream
    parser["upstream"] = {
        "enabled": "true" if upstream.get("enabled") else "false",
        "endpoint": upstream.get("endpoint") or "",
        "node_id": upstream.get("nodeId") or "",
    }
    agent = service.agent
    parser["agent"] = {
        "enabled": "true" if agent.enabled else "false",
        "accept_all": "true" if agent.accept_all else "false",
        "comparison": agent.comparison,
        "threshold": str(agent.threshold),
        "description": agent.description,
        "contact": agent.contact,
        "name": agent.name,
        "location": agent.location,
        "hosts": ", ".join(agent.hosts),
    }
    for item in agent.communities:
        parser[f"agent.community.{item['name']}"] = {"rights": item.get("rights", "read-only")}
    for index, dest in enumerate(agent.destinations, start=1):
        parser[f"agent.destination.{index}"] = {
            "address": dest.get("address", ""),
            "port": str(dest.get("port", 162)),
            "community": dest.get("community", "public"),
            "version": dest.get("version", "2c"),
        }
    parser["sine"] = {"enabled": "true" if service._sine_on else "false"}
    for name, password in service.opc.users.passwords.items():
        parser[f"opc.user.{name}"] = {"password": password}
    for index, row in enumerate(service.radios.remotes, start=1):
        section = {}
        for key in _REMOTE_FIELDS:
            value = row.get(key)
            if value is None or value == "":
                continue
            if key == "alarmed":
                section[key] = "true" if value else "false"
            else:
                section[key] = str(value)
        if section:
            parser[f"remote.{index}"] = section
    INI_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Write a temporary file and swap it in, so a crash or power loss mid-write
    # never leaves a truncated settings file behind.
    temp = INI_PATH.with_name(INI_PATH.name + ".tmp")
    with temp.open("w", encoding="utf-8") as handle:
        handle.write("; trapsnmp settings. Loaded automatically on the next start.\n")
        parser.write(handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, INI_PATH)


def _migrate_master(service) -> None:
    try:
        saved = json.loads(_JSON_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(saved, dict):
        return
    _apply_master(service.radios, {key: str(value) for key, value in saved.items() if value is not None})
    if "enabled" in saved:
        service.radios.enabled = bool(saved.get("enabled"))


def _apply(service, parser: configparser.ConfigParser) -> None:
    if parser.has_section("snmp"):
        names = [item.strip() for item in parser["snmp"].get("communities", "").split(",") if item.strip()]
        if names:
            service.snmp.communities = names
    users = []
    for section in parser.sections():
        if not section.startswith("v3."):
            continue
        item = parser[section]
        users.append(
            {
                "name": section.split(".", 1)[1],
                "level": item.get("level", "authPriv"),
                "auth": item.get("auth", "SHA"),
                "authKey": item.get("auth_key", ""),
                "priv": item.get("priv", "AES"),
                "privKey": item.get("priv_key", ""),
            }
        )
    if users:
        service.snmp.users = users
    if parser.has_section("master"):
        _apply_master(service.radios, parser["master"])
    if parser.has_section("tags"):
        service.tags.community = parser["tags"].get("community", "")
        service.tags.device_ip = parser["tags"].get("device_ip", "")
    if parser.has_section("upstream"):
        item = parser["upstream"]
        service.opc.upstream["enabled"] = _bool(item.get("enabled"))
        service.opc.upstream["endpoint"] = item.get("endpoint", "")
        service.opc.upstream["nodeId"] = item.get("node_id", "")
        service.opc.upstream["status"] = "Armed" if service.opc.upstream["enabled"] else "Not forwarding"
    if parser.has_section("agent"):
        item = parser["agent"]
        agent = service.agent
        agent.enabled = _bool(item.get("enabled"), True)
        agent.accept_all = _bool(item.get("accept_all"), True)
        agent._store["enabled"] = agent.enabled
        comparison = item.get("comparison", agent.comparison)
        if comparison in COMPARISONS:
            agent.comparison = comparison
        elif comparison:
            log.warning("Ignoring unknown agent comparison %r in %s", comparison, INI_PATH)
        agent.threshold = _int(item.get("threshold"), agent.threshold)
        agent.description = item.get("description", agent.description)
        agent.contact = item.get("contact", "")
        agent.name = item.get("name", agent.name)
        agent.location = item.get("location", "")
        agent.hosts = [host.strip() for host in item.get("hosts", "").split(",") if host.strip()]
        agent._reset_values()
    communities = []
    for section in parser.sections():
        if section.startswith("agent.community."):
            communities.append(
                {
                    "name": section.split(".", 2)[2],
                    "rights": parser[section].get("rights", "read-only"),
                }
            )
    if communities:
        service.agent.communities = communities
    destinations = []
    numbered = []
    for section in parser.sections():
        if section.startswith("agent.destination."):
            try:
                numbered.append((int(section.rsplit(".", 1)[1]), section))
            except ValueError:
                continue
    for _index, section in sorted(numbered):
        item = parser[section]
        destinations.append(
            {
                "address": item.get("address", ""),
                "port": _int(item.get("port"), 162),
                "community": item.get("community", "public"),
                "version": item.get("version", "2c"),
            }
        )
    if numbered:
        service.agent.destinations = destinations
    if parser.has_section("sine"):
        service._sine_on = _bool(parser["sine"].get("enabled"))
    opc_users: dict[str, str] = {}
    for section in parser.sections():
        if section.startswith("opc.user."):
            password = parser[section].get("password", "")
            if password:
                opc_users[section[len("opc.user.") :]] = password
    if opc_users:
        service.opc.users.passwords = opc_users
    remotes = []
    slots = []
    for section in parser.sections():
        if not section.startswith("remote."):
            continue
        try:
            slots.append((int(section.split(".", 1)[1]), section))
        except ValueError:
            continue
    for _index, section in sorted(slots):
        item = parser[section]
        row = {}
        for key in _REMOTE_FIELDS:
            if key not in item:
                continue
            raw = item.get(key, "")
            if key == "alarmed":
                row[key] = _bool(raw)
            elif key in _REMOTE_INTS:
                row[key] = _int(raw, 0)
            else:
                row[key] = raw
        if row:
            remotes.append(row)
    if remotes:
        service.radios.remotes = remotes
        for index, row in enumerate(remotes, start=1):
            stats = {}
            for key in ("txPackets", "txBytes", "rxPackets", "rxBytes", "txError", "rxError", "txDrop", "rxDrop"):
                if key in row:
                    stats[key] = int(row[key])
            if stats:
                service._sine_stats[index] = stats


def _apply_master(master, item) -> None:
    host = str(item.get("host") or "").strip()
    community = str(item.get("community") or "").strip()
    if host:
        master.host = host
    if community:
        master.community = community
    port = _int(item.get("port"), master.port)
    interval = _int(item.get("interval"), master.interval)
    if 1 <= port <= 65535:
        master.port = port
    if 5 <= interval <= 300:
        master.interval = interval
    if "enabled" in item:
        master.enabled = _bool(str(item.get("enabled")))
