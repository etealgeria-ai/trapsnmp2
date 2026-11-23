"""Glue between the SNMP receiver, the OPC UA bridge, and the console."""

from __future__ import annotations

import asyncio
import json
import logging
import math
import random
import re
import time
from collections import deque
from datetime import datetime, timezone

from trapsnmp import __version__
from trapsnmp.agent import SnmpAgent
from trapsnmp.catalog import OID_RE, PRESETS, classify_trap, display_value, oid_name
from trapsnmp.radios import CONN_REM_COLUMNS, ENTRY, LINK_STATUS, MODULATION, OrbitMaster, slot_fields
from trapsnmp.trap_tags import TrapTags
from trapsnmp.opcua_out import NS_URI, REMOTE_TAG_COUNT, OpcuaBridge
from trapsnmp.settings import INI_PATH, load as load_settings
from trapsnmp.settings import save as save_settings
from trapsnmp.snmp_in import SnmpTrapIn
from trapsnmp.tasks import spawn

log = logging.getLogger("trapsnmp")


def _remote_varbinds(row: dict) -> list[tuple[str, str, str]]:
    index = row["index"]
    binds = []
    for column, key, _name, kind in CONN_REM_COLUMNS:
        value = row.get(key)
        if kind == "link":
            kind_name, text = "integer", str(_LINK_NUM.get(value, 4))
        elif kind == "mod":
            kind_name, text = "integer", str(_MOD_NUM.get(value, 0))
        elif kind == "bool":
            kind_name, text = "integer", "1" if value else "2"
        elif kind in ("int", "uint"):
            kind_name, text = "integer", "0" if value is None else str(int(value))
        else:
            kind_name, text = "string", "" if value is None else str(value)
        binds.append((f"{_REM}.{column}.{index}", kind_name, text))
    return binds

_OID = re.compile(OID_RE)
_MAX_BINDS = 32
_MAX_VALUE = 512
_SINE_CENTER = -75
_SINE_AMPLITUDE = 15
_SINE_PERIOD = 30.0
_SINE_EVERY = 10.0  # seconds between sine steps (one trap per remote)
_SINE_SPREAD = 8
_LINK_NUM = {name: number for number, name in LINK_STATUS.items()}
_MOD_NUM = {name: number for number, name in MODULATION.items()}
_MOD_NAMES = ("qpsk", "qam16", "qam64", "fsk9600")
_COUNTERS = (
    "txPackets",
    "txBytes",
    "rxPackets",
    "rxBytes",
    "txError",
    "rxError",
    "txDrop",
    "rxDrop",
)
_SINE_INDEX = "1.0.26.139.1.2.3"
_SINE_MAC = "00:1A:8B:01:02:03"
_SINE_IP = "10.1.2.3"
_REM = "1.3.6.1.4.1.4130.10.2.5.1.2.2.1"
# Remote values change every poll or sine step; save them at most this often
# instead of rewriting the whole settings file each time.
_SAVE_REMOTES_EVERY = 60.0
_INJECT_TIMEOUT = 5.0
_V2_GENERIC = tuple(f"1.3.6.1.6.3.1.1.5.{number}" for number in range(1, 7))
_WIRE_VERSION = {"1": "v1", "2c": "v2c", "3": "v3"}


def _received_trap_oid(trap_oid: str, version: str) -> str:
    """snmpTrapOID the receiver reports after a v1 round trip (RFC 3584).

    A v1 trap carries enterprise, generic, and specific. For an
    enterprise-specific trap the receiver rebuilds enterprise.0.specific,
    so 1.3.6.1.4.1.99999.1.1 comes back as 1.3.6.1.4.1.99999.1.0.1.
    """
    if version != "1" or trap_oid in _V2_GENERIC:
        return trap_oid
    parts = trap_oid.split(".")
    enterprise = parts[:-2] if len(parts) > 2 and parts[-2] == "0" else parts[:-1]
    return ".".join([*enterprise, "0", parts[-1]])


class Service:
    def __init__(self) -> None:
        self.snmp = SnmpTrapIn(self._ingest)
        self.opc = OpcuaBridge()
        self.tags = TrapTags()
        self.opc.bind_tag_store(self.tags)
        self.agent = SnmpAgent()
        self.radios = OrbitMaster(self._on_radios)
        self._radio_trace = ""
        self.traps: deque[dict] = deque(maxlen=50)
        self.trace: deque[str] = deque(maxlen=40)
        self.counts = {"traps": 0, "informs": 0}
        self._seq = 0
        self._inject_lock = asyncio.Lock()
        self._pending: asyncio.Future | None = None
        self._expect: tuple[str, str, frozenset[str]] | None = None
        self._save_handle: asyncio.TimerHandle | None = None
        self._sine_on = False
        self._sine_task: asyncio.Task | None = None
        self._sine_t0 = 0.0
        self._sine_rssi: int | None = None
        self._sine_down: int | None = None
        self._sine_stats: dict[int, dict[str, int]] = {}
        self._loading = False
        self._started = False
        self.started_at = datetime.now(timezone.utc)
        load_settings(self)
        self.radios.on_save = self.persist

    def persist(self) -> None:
        if self._save_handle is not None:
            self._save_handle.cancel()
            self._save_handle = None
        try:
            save_settings(self)
        except OSError as exc:
            log.exception("could not save settings")
            self._trace(f"Could not save settings to {INI_PATH}: {exc}")

    def persist_soon(self) -> None:
        """Save remote values later, at most once per _SAVE_REMOTES_EVERY."""
        if self._save_handle is not None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self.persist()
            return
        self._save_handle = loop.call_later(_SAVE_REMOTES_EVERY, self.persist)

    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        await self.snmp.start()
        await self.agent.start()
        await self.opc.start()
        await self.opc.set_listener(self.snmp.listening, self.snmp.port or 0)
        if self.snmp.listening:
            users = ", ".join(item["name"] for item in self.snmp.users)
            self._trace(
                "Receiver listening on UDP "
                + str(self.snmp.port)
                + ". Communities "
                + ", ".join(self.snmp.communities)
                + ". SNMPv3 users "
                + users
            )
        elif self.snmp.error:
            self._trace(f"Receiver failed: {self.snmp.error}")
        if self.opc.ready:
            self._trace(f"OPC UA server ready at {self.opc.endpoint}")
        elif self.opc.error:
            self._trace(f"OPC UA server failed: {self.opc.error}")
        if self.radios.remotes and self.opc.ready:
            await self.opc.write_rssi_wave(self.radios.remotes)
        if INI_PATH.exists():
            self._trace(f"Loaded settings from {INI_PATH}")
        if self._sine_on:
            self.set_sine(True)
        if self.agent.listening:
            self._trace(
                f"SNMP agent on UDP {self.agent.port} at {self.agent.object_id()}"
            )
        elif self.agent.error:
            self._trace(f"SNMP agent failed: {self.agent.error}")
        self.radios._ensure_loop()

    def radio_view(self) -> dict:
        snap = self.radios.snapshot()
        index = self.opc.namespace_index or 0
        slots = []
        remotes = snap["remotes"]
        for slot in range(1, REMOTE_TAG_COUNT + 1):
            row = remotes[slot - 1] if slot <= len(remotes) else None
            node = f"ns={index};s=Remote{slot}" if index else f"Remote{slot}"
            slots.append({"tag": f"Remote{slot}", "node": node, **slot_fields(row)})
        snap["slots"] = slots
        snap["capacity"] = REMOTE_TAG_COUNT
        # The console reads the slots. Sending the raw rows too doubled the
        # size of every /api/state response.
        snap.pop("remotes", None)
        return snap

    def sine_view(self) -> dict:
        return {
            "enabled": self._sine_on,
            "rssi": self._sine_rssi,
            "down": self._sine_down,
            "center": _SINE_CENTER,
            "amplitude": _SINE_AMPLITUDE,
            "period": int(_SINE_PERIOD),
            "spread": _SINE_SPREAD,
            "remotes": REMOTE_TAG_COUNT,
            "every": int(_SINE_EVERY),
        }

    def set_sine(self, enabled: bool) -> dict:
        enabled = bool(enabled)
        if enabled:
            self._sine_on = True
            if self._sine_t0 == 0.0:
                self._sine_t0 = time.monotonic()
            if self._sine_task is None or self._sine_task.done():
                self._sine_task = asyncio.create_task(self._sine_loop())
        else:
            self._sine_on = False
            if self._sine_task is not None:
                self._sine_task.cancel()
                self._sine_task = None
        self.persist()
        return self.sine_view()

    async def _sine_loop(self) -> None:
        loop = asyncio.get_running_loop()
        next_at = loop.time()
        try:
            while self._sine_on:
                try:
                    await self._sine_once()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    # Keep the wave running; without this one failed write
                    # stopped it while the console still showed it as on.
                    log.exception("RSSI sine step failed")
                    self._trace(f"RSSI sine step failed: {exc}")
                # Fixed rate: start a step every _SINE_EVERY seconds, however
                # long sending the traps took. If a step overran, start the
                # next one right away rather than trying to catch up.
                next_at = max(next_at + _SINE_EVERY, loop.time())
                await asyncio.sleep(next_at - loop.time())
        except asyncio.CancelledError:
            return

    async def _sine_once(self) -> None:
        elapsed = time.monotonic() - self._sine_t0
        angle = 2 * math.pi * (elapsed / _SINE_PERIOD)
        rssi = int(round(_SINE_CENTER + _SINE_AMPLITUDE * math.sin(angle)))
        down = int(round(_SINE_CENTER - 6 + _SINE_AMPLITUDE * math.sin(angle - 0.8)))
        self._sine_rssi = rssi
        self._sine_down = down
        rows = []
        for number in range(1, REMOTE_TAG_COUNT + 1):
            mac = f"00:1A:8B:00:{(number >> 8) & 0xFF:02X}:{number & 0xFF:02X}"
            index = "1." + ".".join(str(int(part, 16)) for part in mac.split(":"))
            ip = f"10.1.{(number - 1) // 254 + 2}.{(number - 1) % 254 + 1}"
            stats = self._sine_stats.setdefault(
                number,
                {key: random.randint(0, 500) for key in _COUNTERS},
            )
            for key in _COUNTERS:
                step = random.randint(0, 40 if key.endswith("Bytes") else 8)
                stats[key] = (stats[key] + step) % 1_000_000
            link = "associated" if random.random() > 0.08 else random.choice(("scanning", "negotiating", "disassociated"))
            rows.append(
                {
                    "ifIndex": 1,
                    "mac": mac,
                    "key": mac.replace(":", ""),
                    "index": index,
                    "ip": ip,
                    "address": mac,
                    "name": f"ORBIT-{number}",
                    "version": "4.6.1",
                    "allIp": ip,
                    "gateway": "00:1A:8B:FF:00:01",
                    "link": link,
                    "ttl": random.randint(30, 300),
                    "nicId": 1000 + number,
                    "rssi": max(-110, min(-40, rssi + random.randint(-_SINE_SPREAD, _SINE_SPREAD))),
                    "downRssi": max(-110, min(-40, down + random.randint(-_SINE_SPREAD, _SINE_SPREAD))),
                    "evm": random.randint(4, 35),
                    "downEvm": random.randint(4, 35),
                    "mod": random.choice(_MOD_NAMES),
                    "downMod": random.choice(_MOD_NAMES),
                    "temp": int(round(38 + 6 * math.sin(angle + number / 8) + random.randint(-2, 2))),
                    "alarmed": random.random() < 0.08,
                    "oid": f"{ENTRY}.6.{index}",
                    **stats,
                }
            )
        for row in rows:
            try:
                await self.snmp.send(
                    community="public",
                    version="2c",
                    trap_oid=f"{_REM}.6",
                    varbinds=_remote_varbinds(row),
                )
            except Exception as exc:
                self._trace(f"RSSI sine trap failed for {row['name']}: {exc}")
                break
        self.radios.remotes = rows
        self.radios.error = None
        self.radios.updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if self.opc.ready:
            await self.opc.write_rssi_wave(rows)
        self.persist_soon()

    async def _on_radios(self, snap: dict) -> None:
        note = snap.get("error") or f"{snap['host']}: {snap['count']} remote" + ("" if snap["count"] == 1 else "s")
        if note != self._radio_trace:
            self._radio_trace = note
            self._trace("Radio poll failed: " + snap["error"] if snap.get("error") else "Radio poll " + note)
        if self.opc.ready:
            await self.opc.publish_radios(snap)
        self.persist_soon()

    async def snapshot(self) -> dict:
        readback = await self.opc.readback()
        return {
            "snmp": {
                "listening": self.snmp.listening,
                "port": self.snmp.port,
                "note": self.snmp.note,
                "communities": list(self.snmp.communities),
                "users": [dict(item) for item in self.snmp.users],
                "error": self.snmp.error,
            },
            "opcua": {
                "ready": self.opc.ready,
                "endpoint": self.opc.endpoint,
                "namespace": NS_URI,
                "namespaceIndex": self.opc.namespace_index,
                "security": "None and current secure profiles",
                "identity": "anonymous",
                "certificate": self.opc.security_summary(),
                "eventType": "SnmpTrapEvent",
                "eventCount": self.opc.event_count,
                "error": self.opc.error,
                "nodes": {
                    "object": self.opc.node_ids.get("trapsnmp", "ns=2;s=trapsnmp"),
                    "trapOid": self.opc.node_ids.get("Latest.TrapOid", ""),
                    "message": self.opc.node_ids.get("Latest.Message", ""),
                    "varbinds": self.opc.node_ids.get("Latest.Varbinds", ""),
                    "count": self.opc.node_ids.get("Gateway.TrapCount", ""),
                    "inbox": self.opc.node_ids.get("Upstream.Inbox", ""),
                },
            },
            "upstream": dict(self.opc.upstream),
            "counts": {
                "traps": self.counts["traps"],
                "informs": self.counts["informs"],
                "events": self.opc.event_count,
            },
            "traps": list(self.traps),
            "readback": readback,
            "trace": list(self.trace),
            "presets": [
                {"id": item["id"], "label": item["label"], "detail": item["detail"]}
                for item in PRESETS
            ],
            "version": __version__,
            "startedAt": self.started_at.isoformat(timespec="seconds"),
            "agent": self.agent.snapshot(),
            "tags": self.tags.snapshot(),
            "radios": self.radio_view(),
            "sine": self.sine_view(),
        }

    async def diagnose(self) -> dict:
        started = datetime.now(timezone.utc)
        steps: list[dict] = []

        def step(name: str, ok: bool, detail: str) -> None:
            steps.append({"name": name, "ok": bool(ok), "detail": detail})

        step(
            "SNMP socket",
            self.snmp.listening,
            f"UDP {self.snmp.port}" if self.snmp.listening else (self.snmp.error or "Not listening"),
        )
        step(
            "OPC UA server",
            self.opc.ready,
            self.opc.endpoint if self.opc.ready else (self.opc.error or "Not ready"),
        )
        if self.snmp.listening and self.opc.ready:
            try:
                record = await self.inject_custom(
                    community=self.snmp.communities[0] if self.snmp.communities else "public",
                    version="2c",
                    trap_oid="1.3.6.1.6.3.1.1.5.2",
                    varbinds=[("1.3.6.1.2.1.1.5.0", "string", "trapsnmp-diag")],
                )
            except (ValueError, RuntimeError) as exc:
                step("Loopback trap", False, str(exc))
                record = None
            else:
                published = record.get("opcua") or {}
                step(
                    "Loopback trap",
                    True,
                    f"{record.get('trapName')} {record.get('version')} from {record.get('source')}",
                )
                step(
                    "OPC UA write",
                    not published.get("error") and int(published.get("written") or 0) > 0,
                    published.get("error")
                    or f"{published.get('written', 0)} nodes written",
                )
                step(
                    "Event",
                    bool(published.get("event")),
                    "SnmpTrapEvent fired" if published.get("event") else "No event",
                )
                readback = await self.opc.readback()
                matched = bool(readback.get("ok") and readback.get("trapOid") == record.get("trapOid"))
                step(
                    "Readback",
                    matched,
                    readback.get("trapName") or readback.get("error") or "Empty read",
                )
        if self.agent.listening:
            try:
                descr = await self.agent.read_object("1.3.6.1.2.1.1.1.0")
                last = await self.agent.read_object(self.agent.local_oid("lastTrapDescr"))
            except Exception as exc:
                step("SNMP agent", False, str(exc))
            else:
                step("SNMP agent", bool(descr), f"UDP {self.agent.port} · sysDescr {descr}")
                step(
                    "Trap mapping",
                    bool(last),
                    last or "lastTrapDescr is empty until a trap arrives",
                )
        else:
            step("SNMP agent", False, self.agent.error or "Not listening")
        if self.opc.ready:
            try:
                latched = await self.opc.read_tag("TRAP_V2C:.1.3.6.1.6.3.1.1.5.2")
                queued = await self.opc.read_tag("EVENTS_001")
            except Exception as exc:
                step("Trap tag", False, str(exc))
            else:
                step(
                    "Trap tag",
                    latched is True,
                    "TRAP_V2C warmStart latched" if latched is True else f"Boolean is {latched}",
                )
                text = queued if isinstance(queued, str) else ""
                step(
                    "Events queue",
                    "1.3.6.1.6.3.1.1.5" in text,
                    text[:140] or "EVENTS_001 is empty",
                )
        elapsed = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
        return {
            "ok": bool(steps) and all(item["ok"] for item in steps),
            "steps": steps,
            "ms": elapsed,
        }

    async def inject_preset(self, preset_id: str, community: str | None = None) -> dict:
        from trapsnmp.catalog import PRESET_BY_ID

        preset = PRESET_BY_ID.get(preset_id)
        if preset is None:
            raise ValueError("Unknown preset.")
        return await self._send_and_wait(
            community=(community or (self.snmp.communities[0] if self.snmp.communities else "public")),
            version=preset["version"],
            trap_oid=preset["trap_oid"],
            varbinds=list(preset["varbinds"]),
        )

    async def inject_custom(
        self,
        *,
        community: str,
        version: str,
        trap_oid: str,
        varbinds: list[tuple[str, str, str]],
        user: str | None = None,
    ) -> dict:
        self._validate(community, version, trap_oid, varbinds, user)
        return await self._send_and_wait(
            community=community,
            version=version,
            trap_oid=trap_oid,
            varbinds=varbinds,
            user=user,
        )

    def allow_community(self, community: str) -> None:
        community = community.strip()
        if not community or len(community) > 64:
            raise ValueError("Community must be 1–64 characters.")
        if any(ch in community for ch in "\r\n\x00"):
            raise ValueError("Community contains a control character.")
        if "," in community:
            # Communities are saved as a comma-separated list.
            raise ValueError("Community cannot contain a comma.")
        self.snmp.allow(community)
        self._trace(f"Community '{community}' is now accepted")

    def add_user(self, profile: dict) -> dict:
        created = self.snmp.add_user(profile)
        self._trace(f"SNMPv3 user '{created['name']}' ({created['level']}) is now accepted")
        return created

    def configure_upstream(self, *, enabled: bool, endpoint: str, node_id: str) -> None:
        self.opc.configure_upstream(enabled=enabled, endpoint=endpoint, node_id=node_id)
        if enabled:
            self._trace(f"Forwarding armed → {endpoint} {node_id}")
        else:
            self._trace("Forwarding stopped")

    async def _send_and_wait(
        self,
        *,
        community: str,
        version: str,
        trap_oid: str,
        varbinds: list[tuple[str, str, str]],
        user: str | None = None,
    ) -> dict:
        async with self._inject_lock:
            loop = asyncio.get_running_loop()
            fut: asyncio.Future = loop.create_future()
            self._pending = fut
            # Match on what the receiver will report, not only the trap OID:
            # a sine trap or a real device can share the same trap OID.
            self._expect = (
                _received_trap_oid(trap_oid, version),
                _WIRE_VERSION.get(version, version),
                frozenset(oid for oid, _kind, _value in varbinds),
            )
            try:
                await self.snmp.send(
                    community=community,
                    version=version,
                    trap_oid=trap_oid,
                    varbinds=varbinds,
                    user=user,
                )
                return await asyncio.wait_for(fut, _INJECT_TIMEOUT)
            except asyncio.TimeoutError as exc:
                raise RuntimeError(
                    "The trap was sent, but the receiver did not accept it. "
                    "Check the community or the SNMPv3 user."
                ) from exc
            finally:
                if self._pending is fut:
                    self._pending = None
                    self._expect = None

    async def _ingest(self, snap: dict, rows: list[tuple[str, str, str]]) -> None:
        trap_oid = ""
        sys_up = 0
        varbinds = []
        for oid, syntax, value in rows:
            if oid == "1.3.6.1.6.3.1.1.4.1.0":
                trap_oid = value
            elif oid == "1.3.6.1.2.1.1.3.0" and value.isdigit():
                sys_up = int(value)
            varbinds.append(
                {
                    "oid": oid,
                    "name": oid_name(oid),
                    "type": syntax,
                    "value": value,
                    "display": display_value(oid, syntax, value),
                }
            )
        level, code, name = classify_trap(trap_oid or "0.0")
        now = datetime.now(timezone.utc)
        self._seq += 1
        if snap.get("kind") == "inform":
            self.counts["informs"] += 1
        else:
            self.counts["traps"] += 1
        record = {
            "id": self._seq,
            "receivedAt": now.isoformat(timespec="seconds"),
            "received": now,
            "source": snap.get("source") or "",
            "sourcePort": int(snap.get("sourcePort") or 0),
            "community": snap.get("community") or "",
            "user": snap.get("user") or "",
            "securityLevel": snap.get("securityLevel") or "",
            "version": snap.get("version") or "",
            "kind": snap.get("kind") or "trap",
            "trapOid": trap_oid,
            "trapName": name,
            "severity": level,
            "severityCode": code,
            "sysUpTime": sys_up,
            "message": f"{name} from {snap.get('source') or 'unknown'}",
            "varbinds": varbinds,
            "varbindsJson": json.dumps(varbinds, separators=(",", ":")),
        }
        history = [record, *list(self.traps)]
        published = await self.opc.publish(record, history, self.counts)
        public = {key: value for key, value in record.items() if key != "received"}
        public["opcua"] = published
        self.traps.appendleft(public)
        upstream = published.get("upstream")
        extra = ""
        if upstream == "ok":
            extra = ", forwarded"
        elif upstream == "failed":
            extra = ", forward failed"
        if published.get("error"):
            extra += f", OPC UA error: {published['error']}"
        if self.tags.accept(public):
            try:
                written = await self.opc.write_tags(self.tags.apply(public))
                published["written"] = int(published.get("written") or 0) + written
            except Exception:
                log.exception("trap tag update failed")
        else:
            extra += ", kept off the trap tags"
        who = public["user"] if public["version"] == "v3" else (public["community"] or "—")
        how = f" {public['securityLevel']}" if public["version"] == "v3" else ""
        self._trace(
            f"{public['version']} {public['kind']} {public['trapName']} "
            f"from {public['source']} as {who}{how} "
            f"→ {published.get('written', 0)} node writes"
            f"{', event' if published.get('event') else ''}{extra}"
        )
        try:
            self.agent.observe(public)
            spawn(self.agent.maybe_notify(public), name="agent-notify")
        except Exception:
            log.exception("agent update failed")
        pending = self._pending
        if pending is not None and not pending.done() and self._is_expected(public):
            pending.set_result(public)

    def _is_expected(self, record: dict) -> bool:
        if self._expect is None:
            return False
        trap_oid, version, oids = self._expect
        if record["trapOid"] != trap_oid or record["version"] != version:
            return False
        received = {item["oid"] for item in record["varbinds"]}
        return oids <= received

    def _trace(self, line: str) -> None:
        stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.trace.appendleft(f"{stamp}  {line}")

    def _validate(
        self,
        community: str,
        version: str,
        trap_oid: str,
        varbinds: list[tuple[str, str, str]],
        user: str | None,
    ) -> None:
        if version not in ("1", "2c", "3"):
            raise ValueError("Version must be 1, 2c, or 3.")
        if version == "3":
            if not user or self.snmp.user_named(user) is None:
                raise ValueError("Choose a configured SNMPv3 user.")
        elif not community.strip():
            raise ValueError("Community is required.")
        if not _OID.match(trap_oid):
            raise ValueError("Trap OID must be numeric, like 1.3.6.1.6.3.1.1.5.3.")
        if len(varbinds) > _MAX_BINDS:
            raise ValueError(f"At most {_MAX_BINDS} extra varbinds.")
        for oid, kind, value in varbinds:
            if not _OID.match(oid):
                raise ValueError(f"Bad varbind OID: {oid}")
            if kind not in {
                "integer",
                "string",
                "oid",
                "timeticks",
                "gauge",
                "counter",
                "unsigned",
                "ip",
            }:
                raise ValueError(f"Unsupported type '{kind}'.")
            if len(value) > _MAX_VALUE:
                raise ValueError("Varbind value is too long.")
            if kind == "oid" and not _OID.match(value):
                raise ValueError(f"Value for {oid} is not an OID.")
