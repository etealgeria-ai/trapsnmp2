"""SNMP agent shaped like the SNMP Agent Plug-In (v1 and v2c over UDP).

Object layout, from the plug-in manual:

- system objects at 1.3.6.1.4.1.30144.12.<sub>.1.<n>.0 and the RFC 1213 twins
- item mappings at 1.3.6.1.4.1.30144.12.<sub>.2.<group>.<item>.0
- outbound notifications at 1.3.6.1.4.1.30144.12.<sub>.3.<group>.0.<specific>
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    getCmd,
    sendNotification,
)
from pysnmp.proto.rfc1902 import Integer32, ObjectIdentifier, OctetString, TimeTicks
from pysnmp.proto.rfc1905 import noSuchObject
from pysnmp.smi import error as smi_error

log = logging.getLogger("trapsnmp.agent")

ENTERPRISE = (1, 3, 6, 1, 4, 1, 30144, 12)
SUB_ID = 1
ITEM_GROUP = 1
TRAP_GROUP = 1
TRAP_SPECIFIC = 1

SYSTEM_OBJECTS = (
    ("sysDescr", 1, "The description of the agent"),
    ("sysObjectID", 2, "The agent node's fully-qualified object identifier"),
    ("sysUpTime", 3, "Hundredths of a second since the agent started"),
    ("sysContact", 4, "Contact for the person maintaining the agent"),
    ("sysName", 5, "Administratively-assigned name"),
    ("sysLocation", 6, "Physical location of this node"),
    ("lastTrapDescr", 7, "Description of the last trap sent or received"),
)

ITEM_MAPPINGS = (
    ("trapName", 1, "string", "Name of the latest trap"),
    ("trapOid", 2, "oid", "OID of the latest trap"),
    ("source", 3, "string", "Source address of the latest trap"),
    ("severityCode", 4, "integer", "Severity code of the latest trap"),
    ("message", 5, "string", "Message of the latest trap"),
    ("version", 6, "string", "SNMP version of the latest trap"),
)

RFC1213 = {
    "sysDescr": (1, 3, 6, 1, 2, 1, 1, 1, 0),
    "sysObjectID": (1, 3, 6, 1, 2, 1, 1, 2, 0),
    "sysUpTime": (1, 3, 6, 1, 2, 1, 1, 3, 0),
    "sysContact": (1, 3, 6, 1, 2, 1, 1, 4, 0),
    "sysName": (1, 3, 6, 1, 2, 1, 1, 5, 0),
    "sysLocation": (1, 3, 6, 1, 2, 1, 1, 6, 0),
}

COMPARISONS = (
    "Source > Threshold",
    "Source >= Threshold",
    "Source < Threshold",
    "Source <= Threshold",
    "Source == Threshold",
    "Source != Threshold",
)


def _dotted(parts: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in parts)


def _syntax(kind: str):
    if kind == "integer":
        return Integer32(0)
    if kind == "oid":
        return ObjectIdentifier("0.0")
    if kind == "timeticks":
        return TimeTicks(0)
    return OctetString("")


class _LiveScalar:
    """Filled in after pysnmp classes are imported inside start()."""


def _make_scalar_type(mib_scalar_instance):
    class LiveScalar(mib_scalar_instance):
        def __init__(self, type_name, inst_id, syntax, store, key):
            super().__init__(type_name, inst_id, syntax)
            self._store = store
            self._key = key

        def _hidden(self) -> bool:
            return not self._store.get("enabled", True)

        def readTest(self, name, val, idx, ac_info):
            if self._hidden():
                raise smi_error.NoSuchInstanceError(idx=idx, name=name)
            return super().readTest(name, val, idx, ac_info)

        def readTestNext(self, name, val, idx, ac_info, o_name=None):
            if self._hidden():
                raise smi_error.NoSuchInstanceError(idx=idx, name=name)
            return super().readTestNext(name, val, idx, ac_info, o_name)

        def readGet(self, name, val, idx, ac_info):
            if self._hidden():
                return name, noSuchObject
            return super().readGet(name, val, idx, ac_info)

        def getValue(self, name, idx):
            if self._key == "sysUpTime":
                ticks = int((time.monotonic() - self._store["booted"]) * 100) % 4_294_967_295
                return self.syntax.clone(ticks)
            raw = self._store["values"].get(self._key, "")
            if isinstance(self.syntax, Integer32):
                raw = int(raw or 0)
            elif isinstance(self.syntax, ObjectIdentifier):
                raw = raw or "0.0"
            return self.syntax.clone(raw)

        def writeTest(self, name, val, idx, ac_info):
            raise smi_error.NotWritableError(idx=idx, name=name)

    return LiveScalar


class SnmpAgent:
    def __init__(self) -> None:
        self.port: int | None = None
        self.note = ""
        self.listening = False
        self.error: str | None = None
        self.enabled = True
        self.accept_all = True
        self.hosts: list[str] = []
        self.communities: list[dict] = [
            {"name": "public", "rights": "read-only"},
            {"name": "private", "rights": "read-write"},
        ]
        self.destinations: list[dict] = []
        self.comparison = "Source > Threshold"
        self.threshold = 0
        self.description = "trapsnmp"
        self.contact = ""
        self.name = "trapsnmp"
        self.location = ""
        self.sub_id = SUB_ID
        self.last_notify = ""
        self.notify_error: str | None = None
        self._engine = None
        self._sender: SnmpEngine | None = None
        self._send_lock = asyncio.Lock()
        self._store: dict = {
            "enabled": True,
            "booted": time.monotonic(),
            "values": {},
        }
        self._reset_values()

    def object_id(self) -> str:
        return _dotted(ENTERPRISE + (self.sub_id,))

    def trap_oid(self) -> str:
        return _dotted(ENTERPRISE + (self.sub_id, 3, TRAP_GROUP, 0, TRAP_SPECIFIC))

    def _reset_values(self) -> None:
        self._store["values"] = {
            "sysDescr": self.description,
            "sysObjectID": self.object_id(),
            "sysContact": self.contact,
            "sysName": self.name,
            "sysLocation": self.location,
            "lastTrapDescr": "",
            "trapName": "",
            "trapOid": "0.0",
            "source": "",
            "severityCode": 0,
            "message": "",
            "version": "",
        }

    def local_oid(self, name: str) -> str:
        for label, sub, _detail in SYSTEM_OBJECTS:
            if label == name:
                return _dotted(ENTERPRISE + (self.sub_id, 1, sub, 0))
        raise KeyError(name)

    def item_oid(self, sub: int) -> str:
        return _dotted(ENTERPRISE + (self.sub_id, 2, ITEM_GROUP, sub, 0))

    async def start(self, ports: tuple[int, ...] = (161, 1161)) -> None:
        try:
            port = _pick_udp_port(ports)
        except OSError as exc:
            self.error = f"Could not bind a UDP socket ({exc})."
            log.error(self.error)
            return
        self.port = port
        if port != 161:
            self.note = "UDP 161 is not available, so the agent answers on UDP 1161."
        try:
            snmp_engine = engine.SnmpEngine()
            transport = udp.UdpTransport().openServerMode(("0.0.0.0", port))
            config.addTransport(snmp_engine, udp.domainName, transport)
            for item in self.communities:
                self._register_community(snmp_engine, item)
            self._install_mib(snmp_engine)
            self._arm_host_filter(snmp_engine)
            snmp_context = context.SnmpContext(snmp_engine)
            cmdrsp.GetCommandResponder(snmp_engine, snmp_context)
            cmdrsp.NextCommandResponder(snmp_engine, snmp_context)
            cmdrsp.BulkCommandResponder(snmp_engine, snmp_context)
            cmdrsp.SetCommandResponder(snmp_engine, snmp_context)
            if getattr(transport, "_lport", None) is not None:
                await transport._lport
            self._engine = snmp_engine
            self.listening = True
            self.error = None
            log.info("SNMP agent on UDP %s", port)
        except Exception as exc:
            self.error = str(exc)
            self.listening = False
            log.exception("SNMP agent failed")

    def _install_mib(self, snmp_engine) -> None:
        builder = snmp_engine.getMibBuilder()
        (mib_scalar_instance,) = builder.importSymbols("SNMPv2-SMI", "MibScalarInstance")
        (mib_scalar,) = builder.importSymbols("SNMPv2-SMI", "MibScalar")
        live = _make_scalar_type(mib_scalar_instance)
        symbols = []
        seen: set[tuple[int, ...]] = set()

        def add(oid: tuple[int, ...], kind: str, key: str) -> None:
            base, inst = oid[:-1], (oid[-1],)
            if base not in seen:
                symbols.append(mib_scalar(base, _syntax(kind)).setMaxAccess("read-only"))
                seen.add(base)
            symbols.append(live(base, inst, _syntax(kind), self._store, key))

        for label, sub, _detail in SYSTEM_OBJECTS:
            kind = {"sysObjectID": "oid", "sysUpTime": "timeticks"}.get(label, "string")
            add(ENTERPRISE + (self.sub_id, 1, sub, 0), kind, label)
            rfc = RFC1213.get(label)
            if rfc:
                add(rfc, kind, label)
        for label, sub, kind, _detail in ITEM_MAPPINGS:
            add(ENTERPRISE + (self.sub_id, 2, ITEM_GROUP, sub, 0), kind, label)
        builder.exportSymbols("TRAPSNMP-MIB", *symbols)

    def _register_community(self, snmp_engine, item: dict) -> None:
        name = item["name"]
        config.addV1System(snmp_engine, name, name)
        read_tree = (1, 3, 6, 1)
        write_tree = read_tree if item["rights"] == "read-write" else ()
        for model in (1, 2):
            config.addVacmUser(
                snmp_engine,
                model,
                name,
                "noAuthNoPriv",
                read_tree,
                write_tree,
            )

    def _unregister_community(self, item: dict) -> None:
        if self._engine is None:
            return
        name = item["name"]
        read_tree = (1, 3, 6, 1)
        write_tree = read_tree if item.get("rights") == "read-write" else ()
        try:
            config.delV1System(self._engine, name)
        except Exception:
            log.warning("could not remove community %s from the agent", name, exc_info=True)
        for model in (1, 2):
            try:
                config.delVacmUser(
                    self._engine,
                    model,
                    name,
                    "noAuthNoPriv",
                    read_tree,
                    write_tree,
                )
            except Exception:
                log.warning("could not remove access for community %s", name, exc_info=True)

    def _arm_host_filter(self, snmp_engine) -> None:
        original = snmp_engine.msgAndPduDsp.receiveMessage

        def wrapped(engine_arg, transport_domain, transport_address, whole_msg):
            if not self._allowed(transport_address):
                return None
            return original(engine_arg, transport_domain, transport_address, whole_msg)

        snmp_engine.msgAndPduDsp.receiveMessage = wrapped

    def _allowed(self, address) -> bool:
        if self.accept_all:
            return True
        host = ""
        if isinstance(address, tuple) and address:
            host = str(address[0])
        return host in self.hosts

    def configure(self, body: dict) -> None:
        if "description" in body:
            self.description = _text(body.get("description"), 255)
            self._store["values"]["sysDescr"] = self.description
        if "contact" in body:
            self.contact = _text(body.get("contact"), 255)
            self._store["values"]["sysContact"] = self.contact
        if "name" in body:
            self.name = _text(body.get("name"), 255)
            self._store["values"]["sysName"] = self.name
        if "location" in body:
            self.location = _text(body.get("location"), 255)
            self._store["values"]["sysLocation"] = self.location
        if "enabled" in body:
            self.enabled = bool(body.get("enabled"))
            self._store["enabled"] = self.enabled
        if "acceptAll" in body:
            self.accept_all = bool(body.get("acceptAll"))
        if "comparison" in body:
            comparison = str(body.get("comparison") or "")
            if comparison not in COMPARISONS:
                raise ValueError("Comparison is not one of the trigger operators.")
            self.comparison = comparison
        if "threshold" in body:
            try:
                self.threshold = int(body.get("threshold"))
            except (TypeError, ValueError) as exc:
                raise ValueError("Threshold must be an integer.") from exc

    def add_community(self, name: str, rights: str) -> None:
        name = name.strip()
        rights = rights.strip().lower().replace(" ", "-").replace("_", "-")
        if rights in ("readonly", "read-only"):
            rights = "read-only"
        elif rights in ("readwrite", "read-write"):
            rights = "read-write"
        else:
            raise ValueError("Community rights must be Read Only or Read/Write.")
        if not name or len(name) > 64:
            raise ValueError("Community must be 1–64 characters.")
        if any(item["name"] == name for item in self.communities):
            raise ValueError(f"The community {name} has already been added.")
        item = {"name": name, "rights": rights}
        if self._engine is not None:
            self._register_community(self._engine, item)
        self.communities.append(item)

    def add_host(self, address: str) -> None:
        address = _ipv4(address)
        if address in self.hosts:
            raise ValueError(f"The host IP {address} has already been added.")
        self.hosts.append(address)

    def add_destination(self, address: str, port: int, community: str, version: str) -> None:
        address = _ipv4(address)
        if not 1 <= int(port) <= 65535:
            raise ValueError("Port must be from 1 to 65535.")
        community = community.strip() or "public"
        version = version.strip()
        if version not in ("1", "2c"):
            raise ValueError("SNMP version must be V1 or V2c.")
        row = {
            "address": address,
            "port": int(port),
            "community": community,
            "version": version,
        }
        if any(
            item["address"] == row["address"]
            and item["port"] == row["port"]
            and item["community"] == row["community"]
            and item["version"] == row["version"]
            for item in self.destinations
        ):
            raise ValueError(
                "The trap recipient has already been added. "
                "Select a different IP, port, community, or version."
            )
        self.destinations.append(row)

    def remove(self, kind: str, key: str) -> None:
        if kind == "host":
            self.hosts = [item for item in self.hosts if item != key]
            return
        if kind == "community":
            if key in ("public", "private"):
                raise ValueError("The built-in communities stay in the list.")
            current = next((item for item in self.communities if item["name"] == key), None)
            if current is not None:
                self._unregister_community(current)
            self.communities = [item for item in self.communities if item["name"] != key]
            return
        if kind == "destination":
            self.destinations = [
                item for item in self.destinations if _dest_key(item) != key
            ]
            return
        raise ValueError("Unknown remove target.")

    def observe(self, record: dict) -> None:
        oid = str(record.get("trapOid") or "")
        if self._own_trap(oid):
            return
        values = self._store["values"]
        message = record.get("message") or record.get("trapName") or ""
        values["lastTrapDescr"] = message
        values["trapName"] = record.get("trapName") or ""
        values["trapOid"] = oid or "0.0"
        values["source"] = record.get("source") or ""
        values["severityCode"] = int(record.get("severityCode") or 0)
        values["message"] = message
        values["version"] = record.get("version") or ""

    def _own_trap(self, oid: str) -> bool:
        root = self.object_id()
        return oid == root or oid.startswith(root + ".")

    def triggered(self, severity: int) -> bool:
        threshold = self.threshold
        rules = {
            "Source > Threshold": severity > threshold,
            "Source >= Threshold": severity >= threshold,
            "Source < Threshold": severity < threshold,
            "Source <= Threshold": severity <= threshold,
            "Source == Threshold": severity == threshold,
            "Source != Threshold": severity != threshold,
        }
        rule = rules.get(self.comparison)
        if rule is None:
            self.last_notify = "Trigger comparison is not recognized"
            return False
        return rule

    async def maybe_notify(self, record: dict) -> None:
        oid = str(record.get("trapOid") or "")
        if self._own_trap(oid) or not self.enabled:
            return
        if not self.destinations:
            return
        severity = int(record.get("severityCode") or 0)
        if not self.triggered(severity):
            self.last_notify = "Trigger condition was not met"
            return
        description = record.get("message") or record.get("trapName") or ""
        self._store["values"]["lastTrapDescr"] = description
        errors = []
        for dest in list(self.destinations):
            try:
                await self._send(dest, description)
            except Exception as exc:
                errors.append(f"{dest['address']}:{dest['port']} {exc}")
                log.warning("trap notify failed: %s", exc)
        if errors:
            self.notify_error = "; ".join(errors)
            self.last_notify = "Notify failed"
        else:
            self.notify_error = None
            self.last_notify = f"Sent {self.trap_oid()} to {len(self.destinations)} recipient(s)"

    async def _send(self, dest: dict, description: str) -> None:
        uptime = int((time.monotonic() - self._store["booted"]) * 100) % 4_294_967_295
        varbinds = [
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.3.0"), TimeTicks(uptime)),
            ObjectType(ObjectIdentity("1.3.6.1.6.3.1.1.4.1.0"), ObjectIdentifier(self.trap_oid())),
            ObjectType(ObjectIdentity(self.local_oid("lastTrapDescr")), OctetString(description)),
        ]
        mp_model = 0 if dest["version"] == "1" else 1
        async with self._send_lock:
            if self._sender is None:
                self._sender = SnmpEngine()
            error_indication, error_status, _index, _binds = await sendNotification(
                self._sender,
                CommunityData(dest["community"], mpModel=mp_model),
                UdpTransportTarget((dest["address"], dest["port"])),
                ContextData(),
                "trap",
                varbinds,
                lookupMib=False,
            )
        if error_indication:
            raise RuntimeError(str(error_indication))
        if error_status:
            raise RuntimeError(str(error_status))

    async def read_object(self, oid: str, community: str = "public") -> str:
        if not self.listening or self.port is None:
            raise RuntimeError(self.error or "The agent is not listening.")
        if self._sender is None:
            self._sender = SnmpEngine()
        error_indication, error_status, _index, var_binds = await getCmd(
            self._sender,
            CommunityData(community, mpModel=1),
            UdpTransportTarget(("127.0.0.1", self.port)),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lookupMib=False,
        )
        if error_indication:
            raise RuntimeError(str(error_indication))
        if error_status:
            raise RuntimeError(str(error_status))
        value = var_binds[0][1]
        return value.prettyPrint() if hasattr(value, "prettyPrint") else str(value)

    def snapshot(self) -> dict:
        values = self._store["values"]
        ticks = int((time.monotonic() - self._store["booted"]) * 100) % 4_294_967_295
        system = []
        for label, sub, detail in SYSTEM_OBJECTS:
            local = self.local_oid(label)
            rfc = RFC1213.get(label)
            shown = str(ticks) if label == "sysUpTime" else str(values.get(label, ""))
            system.append(
                {
                    "name": label,
                    "description": detail,
                    "access": "read-only",
                    "localOid": local,
                    "rfcOid": _dotted(rfc) if rfc else "",
                    "value": shown,
                }
            )
        items = []
        for label, sub, kind, detail in ITEM_MAPPINGS:
            items.append(
                {
                    "name": label,
                    "description": detail,
                    "type": kind,
                    "access": "read-only",
                    "oid": self.item_oid(sub),
                    "value": str(values.get(label, "")),
                }
            )
        return {
            "listening": self.listening,
            "port": self.port,
            "note": self.note,
            "error": self.error,
            "enabled": self.enabled,
            "version": "V1, V2c",
            "protocol": "UDP",
            "objectId": self.object_id(),
            "subId": self.sub_id,
            "description": self.description,
            "contact": self.contact,
            "name": self.name,
            "location": self.location,
            "acceptAll": self.accept_all,
            "hosts": list(self.hosts),
            "communities": [dict(item) for item in self.communities],
            "destinations": [{**item, "id": _dest_key(item)} for item in self.destinations],
            "comparison": self.comparison,
            "threshold": self.threshold,
            "trapOid": self.trap_oid(),
            "lastNotify": self.last_notify,
            "notifyError": self.notify_error,
            "system": system,
            "items": items,
            "comparisons": list(COMPARISONS),
        }


def _dest_key(item: dict) -> str:
    return f"{item['address']}:{item['port']}:{item['community']}:{item['version']}"


def _text(value, limit: int) -> str:
    text = str(value or "")
    if len(text) > limit:
        raise ValueError(f"Text must be at most {limit} characters.")
    return text


def _ipv4(value: str) -> str:
    text = str(value or "").strip()
    parts = text.split(".")
    if len(parts) != 4:
        raise ValueError("Enter a valid IPv4 address in quad-dotted notation.")
    try:
        numbers = [int(part) for part in parts]
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 address in quad-dotted notation.") from exc
    if any(number < 0 or number > 255 or str(number) != part for number, part in zip(numbers, parts)):
        raise ValueError("Enter a valid IPv4 address in quad-dotted notation.")
    return text


def _pick_udp_port(candidates: tuple[int, ...]) -> int:
    last_error = "no candidate"
    for port in candidates:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind(("0.0.0.0", port))
        except OSError as exc:
            last_error = str(exc)
            continue
        else:
            return port
        finally:
            probe.close()
    raise OSError(last_error)
