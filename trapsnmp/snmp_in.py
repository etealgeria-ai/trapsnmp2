"""SNMPv1, SNMPv2c, and SNMPv3 trap receiver, plus a bench sender."""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from collections import OrderedDict
from typing import Awaitable, Callable

from pyasn1.codec.ber import decoder
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    Counter32,
    Gauge32,
    Integer,
    IpAddress,
    ObjectIdentifier,
    ObjectIdentity,
    ObjectType,
    OctetString,
    SnmpEngine,
    TimeTicks,
    UdpTransportTarget,
    Unsigned32,
    UsmUserData,
    sendNotification,
)
from pysnmp.proto.api import v2c
from pysnmp.proto.mpmod.rfc3412 import SNMPv3Message
from pysnmp.proto.secmod.rfc3414.service import UsmSecurityParameters
from pysnmp.smi.error import NoSuchInstanceError

from trapsnmp.tasks import spawn

log = logging.getLogger("trapsnmp.snmp")

_MAX_IN_FLIGHT = 64
# Each SNMPv3 sender engine ID gets its own copy of a user. The user name is
# not secret, so without a cap any host could grow this table forever.
_MAX_V3_CLONES = 1024

# pysnmp counts messages it rejects before they become traps.
_REJECT_COUNTERS = (
    ("__SNMPv2-MIB", "snmpInBadCommunityNames", "badCommunity"),
    ("__SNMP-USER-BASED-SM-MIB", "usmStatsUnknownUserNames", "unknownUser"),
    ("__SNMP-USER-BASED-SM-MIB", "usmStatsWrongDigests", "wrongAuth"),
    ("__SNMP-USER-BASED-SM-MIB", "usmStatsDecryptionErrors", "wrongPriv"),
    ("__SNMP-USER-BASED-SM-MIB", "usmStatsUnsupportedSecLevels", "wrongLevel"),
)

OnTrap = Callable[[dict, list[tuple[str, str, str]]], Awaitable[None]]

VALUE_TYPES = {
    "integer": lambda raw: Integer(int(raw)),
    "string": lambda raw: OctetString(raw),
    "oid": lambda raw: ObjectIdentifier(raw),
    "timeticks": lambda raw: TimeTicks(int(raw)),
    "gauge": lambda raw: Gauge32(int(raw)),
    "counter": lambda raw: Counter32(int(raw)),
    "unsigned": lambda raw: Unsigned32(int(raw)),
    "ip": lambda raw: IpAddress(raw),
}

AUTH_PROTOCOLS = {
    "MD5": config.usmHMACMD5AuthProtocol,
    "SHA": config.usmHMACSHAAuthProtocol,
    "SHA-256": config.usmHMAC192SHA256AuthProtocol,
}
PRIV_PROTOCOLS = {
    "DES": config.usmDESPrivProtocol,
    "AES": config.usmAesCfb128Protocol,
}
LEVELS = {1: "noAuthNoPriv", 2: "authNoPriv", 3: "authPriv"}

DEFAULT_USER = {
    "name": "trapsnmp",
    "level": "authPriv",
    "auth": "SHA",
    "authKey": "trapsnmp-auth",
    "priv": "AES",
    "privKey": "trapsnmp-priv",
}


def _text(value) -> str:
    if value is None:
        return ""
    if hasattr(value, "prettyPrint"):
        return str(value.prettyPrint())
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return str(value)


def _pick_udp_port(candidates: tuple[int, ...]) -> int:
    last_error = "no candidate"
    for port in candidates:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError as exc:
            last_error = str(exc)
            continue
        else:
            return port
        finally:
            sock.close()
    raise OSError(last_error)


class SnmpTrapIn:
    def __init__(self, on_trap: OnTrap) -> None:
        self._on_trap = on_trap
        self.port: int | None = None
        self.note = ""
        self.communities: list[str] = ["public", "private"]
        self.users: list[dict] = [dict(DEFAULT_USER)]
        self.listening = False
        self.error: str | None = None
        self._engine: engine.SnmpEngine | None = None
        self._sender: SnmpEngine | None = None
        self._sink: dict = {}
        self._send_lock = asyncio.Lock()
        self._inflight = 0
        self.dropped = 0
        self._clones: OrderedDict[tuple[bytes, bytes], None] = OrderedDict()

    async def start(self, ports: tuple[int, ...] = (162, 1162)) -> None:
        try:
            port = _pick_udp_port(ports)
        except OSError as exc:
            self.error = f"Could not bind a UDP socket ({exc})."
            log.error(self.error)
            return
        self.port = port
        if port != 162:
            self.note = "UDP 162 is not available in this environment, so traps are accepted on UDP 1162."
        try:
            snmp_engine = engine.SnmpEngine()
            transport = udp.UdpTransport().openServerMode(("0.0.0.0", port))
            config.addTransport(snmp_engine, udp.domainName, transport)
            for name in self.communities:
                self._add_community(snmp_engine, name)
            for profile in self.users:
                self._add_v3_user(snmp_engine, profile)
            self._arm_v3_clone(snmp_engine)
            snmp_engine.observer.registerObserver(
                self._on_community, "rfc2576.processIncomingMsg", cbCtx=self._sink
            )
            snmp_engine.observer.registerObserver(
                self._on_request, "rfc3412.receiveMessage:request", cbCtx=self._sink
            )
            ntfrcv.NotificationReceiver(snmp_engine, self._on_pdu, cbCtx=self._sink)
            if getattr(transport, "_lport", None) is not None:
                await transport._lport
            self._engine = snmp_engine
            self.listening = True
            self.error = None
            log.info("SNMP trap receiver on UDP %s", port)
        except Exception as exc:
            self.error = str(exc)
            self.listening = False
            log.exception("SNMP receiver failed")

    def allow(self, community: str) -> None:
        community = community.strip()
        if not community or community in self.communities:
            return
        if self._engine is not None:
            self._add_community(self._engine, community)
        self.communities.append(community)

    def add_user(self, profile: dict) -> dict:
        cleaned = _clean_user(profile)
        if any(item["name"] == cleaned["name"] for item in self.users):
            raise ValueError(f"User '{cleaned['name']}' is already configured.")
        if self._engine is not None:
            self._add_v3_user(self._engine, cleaned)
        self.users.append(cleaned)
        return cleaned

    def user_named(self, name: str) -> dict | None:
        for item in self.users:
            if item["name"] == name:
                return item
        return None

    async def send(
        self,
        *,
        community: str,
        version: str,
        trap_oid: str,
        varbinds: list[tuple[str, str, str]],
        user: str | None = None,
    ) -> None:
        if version == "3":
            profile = self.user_named(user or "") or (self.users[0] if self.users else None)
            if profile is None:
                raise RuntimeError("No SNMPv3 user is configured.")
            if user and profile["name"] != user:
                raise ValueError(f"Unknown SNMPv3 user '{user}'.")
            auth_data = _usm(profile)
        else:
            mp_model = 0 if version == "1" else 1
            auth_data = CommunityData(community, mpModel=mp_model)
        uptime = int(time.monotonic() * 100) % 4_294_967_295
        rows: list[tuple[str, str, str]] = [
            ("1.3.6.1.2.1.1.3.0", "timeticks", str(uptime)),
            ("1.3.6.1.6.3.1.1.4.1.0", "oid", trap_oid),
        ]
        seen = {oid for oid, _kind, _value in rows}
        for oid, kind, value in varbinds:
            if oid in seen:
                continue
            rows.append((oid, kind, value))
            seen.add(oid)
        built = []
        for oid, kind, value in rows:
            factory = VALUE_TYPES.get(kind)
            if factory is None:
                raise ValueError(f"Unsupported varbind type '{kind}'.")
            try:
                syntax = factory(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{oid}: {exc}") from exc
            built.append(ObjectType(ObjectIdentity(oid), syntax))
        if self.port is None:
            raise RuntimeError("The trap receiver is not listening.")
        async with self._send_lock:
            if self._sender is None:
                self._sender = SnmpEngine()
            error_indication, error_status, _error_index, _var_binds = await sendNotification(
                self._sender,
                auth_data,
                UdpTransportTarget(("127.0.0.1", self.port)),
                ContextData(),
                "trap",
                built,
                lookupMib=False,
            )
        if error_indication:
            raise RuntimeError(str(error_indication))
        if error_status:
            raise RuntimeError(str(error_status))

    def _add_community(self, snmp_engine: engine.SnmpEngine, name: str) -> None:
        config.addV1System(snmp_engine, name, name)

    def _add_v3_user(self, snmp_engine: engine.SnmpEngine, profile: dict) -> None:
        level = profile["level"]
        auth_protocol = config.usmNoAuthProtocol
        auth_key = None
        priv_protocol = config.usmNoPrivProtocol
        priv_key = None
        if level in ("authNoPriv", "authPriv"):
            auth_protocol = AUTH_PROTOCOLS[profile["auth"]]
            auth_key = profile["authKey"]
        if level == "authPriv":
            priv_protocol = PRIV_PROTOCOLS[profile["priv"]]
            priv_key = profile["privKey"]
        config.addV3User(
            snmp_engine,
            profile["name"],
            auth_protocol,
            auth_key,
            priv_protocol,
            priv_key,
        )

    def _arm_v3_clone(self, snmp_engine: engine.SnmpEngine) -> None:
        """Localize a known user onto the sender's engine ID before USM checks it."""
        original = snmp_engine.msgAndPduDsp.receiveMessage
        clones = self._clones

        def wrapped(engine_arg, transport_domain, transport_address, whole_msg):
            _clone_v3_user(engine_arg, whole_msg, clones)
            return original(engine_arg, transport_domain, transport_address, whole_msg)

        snmp_engine.msgAndPduDsp.receiveMessage = wrapped

    @staticmethod
    def _on_community(_snmp_engine, _execpoint, variables, sink) -> None:
        sink["community"] = _text(variables.get("communityName"))

    @staticmethod
    def _on_request(_snmp_engine, _execpoint, variables, sink) -> None:
        model = int(variables.get("messageProcessingModel", 1))
        sink["version"] = {0: "v1", 1: "v2c", 3: "v3"}.get(model, str(model))
        security_name = _text(variables.get("securityName"))
        level = LEVELS.get(int(variables.get("securityLevel") or 1), "")
        if model == 3:
            sink["user"] = security_name
            sink["community"] = ""
            sink["securityLevel"] = level
        else:
            sink["user"] = ""
            sink["securityLevel"] = "community"
        address = variables.get("transportAddress")
        if isinstance(address, tuple) and len(address) >= 2:
            sink["source"] = str(address[0])
            try:
                sink["sourcePort"] = int(address[1])
            except (TypeError, ValueError):
                sink["sourcePort"] = 0
        pdu = variables.get("pdu")
        if pdu is not None and pdu.tagSet == v2c.InformRequestPDU.tagSet:
            sink["kind"] = "inform"
        else:
            sink["kind"] = "trap"

    def _on_pdu(self, *args) -> None:
        var_binds = args[-2]
        sink = args[-1] if args else self._sink
        rows: list[tuple[str, str, str]] = []
        for name, val in var_binds:
            rows.append((_text(name), type(val).__name__, _text(val)))
        snap = {
            "version": sink.get("version", "v2c"),
            "kind": sink.get("kind", "trap"),
            "source": sink.get("source", ""),
            "sourcePort": int(sink.get("sourcePort") or 0),
            "community": sink.get("community", ""),
            "user": sink.get("user", ""),
            "securityLevel": sink.get("securityLevel", ""),
        }
        if self._inflight >= _MAX_IN_FLIGHT:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 100 == 0:
                log.warning("trap backlog is full; dropped %s", self.dropped)
            return
        self._inflight += 1
        try:
            task = spawn(self._dispatch(snap, rows), name="trap-dispatch")
        except RuntimeError:
            self._inflight -= 1
            self.dropped += 1
            log.exception("trap dropped; no running loop")
            return
        task.add_done_callback(self._release_trap)

    def _release_trap(self, _task: asyncio.Task) -> None:
        self._inflight = max(0, self._inflight - 1)

    @property
    def in_flight(self) -> int:
        return self._inflight

    @property
    def max_in_flight(self) -> int:
        return _MAX_IN_FLIGHT

    def rejected(self) -> dict[str, int]:
        """Messages refused for a bad community or SNMPv3 credentials."""
        counts: dict[str, int] = {}
        if self._engine is None:
            return counts
        try:
            builder = self._engine.getMibBuilder()
        except Exception:
            return counts
        for module, symbol, key in _REJECT_COUNTERS:
            try:
                (node,) = builder.importSymbols(module, symbol)
                counts[key] = int(node.syntax)
            except Exception:
                continue
        return counts

    async def _dispatch(self, snap: dict, rows: list[tuple[str, str, str]]) -> None:
        try:
            await self._on_trap(snap, rows)
        except Exception:
            log.exception("trap handler failed")


def _clone_v3_user(
    snmp_engine: engine.SnmpEngine,
    whole_msg: bytes,
    clones: OrderedDict | None = None,
) -> None:
    try:
        message = decoder.decode(whole_msg, asn1Spec=SNMPv3Message())[0]
    except Exception:
        return
    if int(message.getComponentByPosition(0)) != 3:
        return
    try:
        security = decoder.decode(
            bytes(message.getComponentByPosition(2)),
            asn1Spec=UsmSecurityParameters(),
        )[0]
    except Exception:
        log.debug("could not read USM parameters", exc_info=True)
        return
    engine_id = security.getComponentByPosition(0)
    user_name = security.getComponentByPosition(3)
    if not user_name:
        return
    usm = snmp_engine.securityModels[3]
    controller = snmp_engine.msgAndPduDsp.mibInstrumController
    key = (bytes(engine_id), bytes(user_name))
    try:
        usm._SnmpUSMSecurityModel__getUserInfo(controller, engine_id, user_name)
        if clones is not None and key in clones:
            clones.move_to_end(key)
        return
    except NoSuchInstanceError:
        pass
    try:
        usm._SnmpUSMSecurityModel__cloneUserInfo(controller, engine_id, user_name)
    except Exception:
        log.debug("USM user was not cloned for this engine", exc_info=True)
        return
    if clones is None:
        return
    clones[key] = None
    while len(clones) > _MAX_V3_CLONES:
        (old_engine, old_user), _ = clones.popitem(last=False)
        try:
            config.delV3User(
                snmp_engine,
                old_user.decode("utf-8", "replace"),
                securityEngineId=old_engine,
            )
        except Exception:
            log.debug("could not drop the oldest SNMPv3 user copy", exc_info=True)


def _usm(profile: dict) -> UsmUserData:
    level = profile["level"]
    if level == "noAuthNoPriv":
        return UsmUserData(profile["name"])
    auth_protocol = AUTH_PROTOCOLS[profile["auth"]]
    if level == "authNoPriv":
        return UsmUserData(profile["name"], profile["authKey"], authProtocol=auth_protocol)
    return UsmUserData(
        profile["name"],
        profile["authKey"],
        profile["privKey"],
        authProtocol=auth_protocol,
        privProtocol=PRIV_PROTOCOLS[profile["priv"]],
    )


def _clean_user(profile: dict) -> dict:
    name = str(profile.get("name", "")).strip()
    level = str(profile.get("level", "authPriv")).strip()
    auth = str(profile.get("auth", "SHA")).strip() or "SHA"
    priv = str(profile.get("priv", "AES")).strip() or "AES"
    auth_key = str(profile.get("authKey", ""))
    priv_key = str(profile.get("privKey", ""))
    if not name or len(name) > 32:
        raise ValueError("User name must be 1–32 characters.")
    if any(ord(ch) < 33 or ord(ch) > 126 for ch in name):
        raise ValueError("User name must be printable and cannot contain spaces.")
    if level not in ("noAuthNoPriv", "authNoPriv", "authPriv"):
        raise ValueError("Level must be noAuthNoPriv, authNoPriv, or authPriv.")
    if level != "noAuthNoPriv":
        if auth not in AUTH_PROTOCOLS:
            raise ValueError("Auth protocol must be MD5, SHA, or SHA-256.")
        if len(auth_key) < 8:
            raise ValueError("Auth passphrase must be at least 8 characters.")
    else:
        auth, auth_key = "NONE", ""
    if level == "authPriv":
        if priv not in PRIV_PROTOCOLS:
            raise ValueError("Privacy protocol must be DES or AES.")
        if len(priv_key) < 8:
            raise ValueError("Privacy passphrase must be at least 8 characters.")
    else:
        priv, priv_key = "NONE", ""
    return {
        "name": name,
        "level": level,
        "auth": auth,
        "authKey": auth_key,
        "priv": priv,
        "privKey": priv_key,
    }
