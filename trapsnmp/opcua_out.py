"""OPC UA server for trap state, plus an optional client that forwards each trap."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone

from asyncua import Client, Server, ua

from trapsnmp.opc_users import USER_POLICY, PasswordUsers
from trapsnmp.pki import PROFILES, Pki
from trapsnmp.radios import OPC_TAGS, remote_opc_values
from trapsnmp.trap_tags import startup_nodes

log = logging.getLogger("trapsnmp.opcua")

_TAG_TYPES = {
    "bool": ua.VariantType.Boolean,
    "string": ua.VariantType.String,
    "int": ua.VariantType.Int32,
    "uint": ua.VariantType.UInt32,
}
_TAG_INITIAL = {"bool": False, "string": "", "int": 0, "uint": 0}

NS_URI = "urn:trapsnmp:snmp"
SLOT_COUNT = 8
REMOTE_TAG_COUNT = 255

LATEST_FIELDS = (
    ("Source", ua.VariantType.String, ""),
    ("SourcePort", ua.VariantType.UInt16, 0),
    ("Community", ua.VariantType.String, ""),
    ("User", ua.VariantType.String, ""),
    ("SecurityLevel", ua.VariantType.String, ""),
    ("Version", ua.VariantType.String, ""),
    ("Kind", ua.VariantType.String, ""),
    ("TrapOid", ua.VariantType.String, ""),
    ("TrapName", ua.VariantType.String, ""),
    ("Severity", ua.VariantType.String, ""),
    ("SeverityCode", ua.VariantType.UInt16, 0),
    ("SysUpTime", ua.VariantType.UInt32, 0),
    ("Message", ua.VariantType.String, ""),
    ("Varbinds", ua.VariantType.String, ""),
)


def _iso(value) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat(timespec="seconds")
    return "" if value is None else str(value)


def _opc_text(value) -> tuple[str, str]:
    if isinstance(value, bool):
        return "Boolean", "true" if value else "false"
    if isinstance(value, int):
        return "Int32", str(value)
    if isinstance(value, datetime):
        return "DateTime", _iso(value)
    if value is None:
        return "Null", ""
    return "String", str(value)


class OpcuaBridge:
    def __init__(self) -> None:
        self.ready = False
        self.error: str | None = None
        self.endpoint = "opc.tcp://127.0.0.1:4840/trapsnmp/"
        self.namespace_index = 0
        self.event_count = 0
        self.pki: Pki | None = None
        self.users = PasswordUsers()
        self.nodes: dict = {}
        self.node_ids: dict[str, str] = {}
        self._server: Server | None = None
        self._events = None
        self._reader: Client | None = None
        self._forwarder: Client | None = None
        self._forward_url = ""
        self._forward_lock = asyncio.Lock()
        self._forward_pause_until = 0.0
        self._forward_pause_reason = ""
        self._read_lock = asyncio.Lock()
        self._tag_store = None
        self._tags_parent = None
        self._radios_parent = None
        self._radio_folders: dict = {}
        self._radio_keys: set[str] = set()
        self._radio_slots = 0
        self._ns = 0
        self.upstream = {
            "enabled": False,
            "endpoint": "",
            "nodeId": "",
            "status": "Not forwarding",
            "forwarded": 0,
            "failed": 0,
        }

    async def start(self) -> None:
        server = Server(user_manager=self.users)
        await server.init()
        await server.set_application_uri("urn:trapsnmp:gateway")
        server.product_uri = "urn:trapsnmp:snmp-opcua"
        server.manufacturer_name = "trapsnmp"
        server.set_server_name("trapsnmp SNMP Gateway")
        server.set_endpoint(self.endpoint)
        server.socket_address = ("0.0.0.0", 4840)
        try:
            self.pki = await Pki.ensure()
            await server.load_certificate(self.pki.cert_file, "der")
            await server.load_private_key(self.pki.key_file)
            server.set_security_policy(list(PROFILES))
            server.set_identity_tokens([ua.AnonymousIdentityToken, ua.UserNameIdentityToken])
            server.set_certificate_validator(self.pki.validator)
        except Exception:
            log.exception("OPC UA certificate setup failed; staying open")
            self.pki = None
            server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
            server.set_identity_tokens([ua.AnonymousIdentityToken, ua.UserNameIdentityToken])
        try:
            idx = await server.register_namespace(NS_URI)
            objects = server.nodes.objects
            root = await objects.add_object(ua.NodeId("trapsnmp", idx), "trapsnmp")
            self.node_ids["trapsnmp"] = f"ns={idx};s=trapsnmp"
            gateway = await root.add_object(ua.NodeId("Gateway", idx), "Gateway")
            latest = await root.add_object(ua.NodeId("Latest", idx), "Latest")
            recent = await root.add_object(ua.NodeId("Recent", idx), "Recent")
            upstream = await root.add_object(ua.NodeId("Upstream", idx), "Upstream")

            async def add_var(parent, node_key: str, browse: str, value, variant):
                node = await parent.add_variable(
                    ua.NodeId(node_key, idx), browse, value, varianttype=variant
                )
                self.nodes[node_key] = node
                self.node_ids[node_key] = f"ns={idx};s={node_key}"

            await add_var(gateway, "Gateway.Listening", "Listening", False, ua.VariantType.Boolean)
            await add_var(gateway, "Gateway.UdpPort", "UdpPort", 0, ua.VariantType.UInt16)
            await add_var(gateway, "Gateway.TrapCount", "TrapCount", 0, ua.VariantType.UInt64)
            await add_var(gateway, "Gateway.InformCount", "InformCount", 0, ua.VariantType.UInt64)
            await add_var(gateway, "Gateway.LastError", "LastError", "", ua.VariantType.String)
            received = datetime(1970, 1, 1, tzinfo=timezone.utc)
            await add_var(latest, "Latest.ReceivedAt", "ReceivedAt", received, ua.VariantType.DateTime)
            for name, variant, initial in LATEST_FIELDS:
                await add_var(latest, f"Latest.{name}", name, initial, variant)
            for slot in range(1, SLOT_COUNT + 1):
                folder = await recent.add_object(ua.NodeId(f"Recent.{slot}", idx), f"Slot{slot}")
                for name in ("TrapOid", "TrapName", "Source", "Severity", "ReceivedAt"):
                    await add_var(
                        folder,
                        f"Recent.{slot}.{name}",
                        name,
                        "",
                        ua.VariantType.String,
                    )
            await add_var(upstream, "Upstream.Inbox", "Inbox", "", ua.VariantType.String)
            await self.nodes["Upstream.Inbox"].set_writable(True)
            await add_var(upstream, "Upstream.Status", "Status", "Not forwarding", ua.VariantType.String)
            await add_var(upstream, "Upstream.Forwarded", "Forwarded", 0, ua.VariantType.UInt64)

            tags = await root.add_object(ua.NodeId("Tags", idx), "Tags")
            self._tags_parent = tags
            self._ns = idx
            radios = await root.add_object(ua.NodeId("Radios", idx), "Radios")
            self._radios_parent = radios
            await add_var(radios, "Radios.Count", "Count", 0, ua.VariantType.UInt32)
            await add_var(radios, "Radios.Master", "Master", "", ua.VariantType.String)
            await add_var(radios, "Radios.Error", "Error", "", ua.VariantType.String)
            for number in range(1, REMOTE_TAG_COUNT + 1):
                folder = await radios.add_object(ua.NodeId(f"Remote{number}", idx), f"Remote{number}")
                for name, kind in OPC_TAGS:
                    await add_var(
                        folder,
                        f"Remote{number}.{name}",
                        name,
                        _TAG_INITIAL[kind],
                        _TAG_TYPES[kind],
                    )
            await self._install_tag_nodes()

            event_type = await server.create_custom_event_type(
                idx,
                "SnmpTrapEvent",
                ua.ObjectIds.BaseEventType,
                [
                    ("TrapOid", ua.VariantType.String),
                    ("SourceAddress", ua.VariantType.String),
                    ("Community", ua.VariantType.String),
                    ("SeverityName", ua.VariantType.String),
                    ("Varbinds", ua.VariantType.String),
                ],
            )
            self._events = await server.get_event_generator(event_type, root)
            await server.start()
            self._arm_tag_writes(server)
        except Exception as exc:
            self.error = str(exc)
            self.ready = False
            log.exception("OPC UA server failed")
            try:
                await server.stop()
            except Exception:
                pass
            return
        self._server = server
        self.namespace_index = idx
        self.ready = True
        self.error = None
        log.info("OPC UA server at %s (ns=%s)", self.endpoint, idx)
        try:
            await self._connect_reader()
        except Exception as exc:
            log.warning("OPC UA readback client not connected yet: %s", exc)

    async def set_listener(self, listening: bool, port: int) -> None:
        if not self.ready:
            return
        await self._write("Gateway.Listening", listening, ua.VariantType.Boolean)
        await self._write("Gateway.UdpPort", int(port or 0), ua.VariantType.UInt16)

    async def publish(self, trap: dict, history: list[dict], counts: dict) -> dict:
        result = {"event": False, "written": 0, "upstream": "skipped", "error": None}
        if not self.ready:
            result["error"] = self.error or "OPC UA server is not running"
            return result
        try:
            pairs = [
                ("Latest.Source", trap["source"], ua.VariantType.String),
                ("Latest.SourcePort", int(trap["sourcePort"]), ua.VariantType.UInt16),
                ("Latest.Community", trap["community"], ua.VariantType.String),
                ("Latest.User", trap.get("user", ""), ua.VariantType.String),
                ("Latest.SecurityLevel", trap.get("securityLevel", ""), ua.VariantType.String),
                ("Latest.Version", trap["version"], ua.VariantType.String),
                ("Latest.Kind", trap["kind"], ua.VariantType.String),
                ("Latest.TrapOid", trap["trapOid"], ua.VariantType.String),
                ("Latest.TrapName", trap["trapName"], ua.VariantType.String),
                ("Latest.Severity", trap["severity"], ua.VariantType.String),
                ("Latest.SeverityCode", int(trap["severityCode"]), ua.VariantType.UInt16),
                ("Latest.SysUpTime", int(trap["sysUpTime"]), ua.VariantType.UInt32),
                ("Latest.Message", trap["message"], ua.VariantType.String),
                ("Latest.Varbinds", trap["varbindsJson"], ua.VariantType.String),
                ("Latest.ReceivedAt", trap["received"], ua.VariantType.DateTime),
                ("Gateway.TrapCount", int(counts["traps"]), ua.VariantType.UInt64),
                ("Gateway.InformCount", int(counts["informs"]), ua.VariantType.UInt64),
                ("Gateway.LastError", "", ua.VariantType.String),
            ]
            for key, value, variant in pairs:
                await self._write(key, value, variant)
            for slot in range(1, SLOT_COUNT + 1):
                item = history[slot - 1] if slot - 1 < len(history) else None
                fields = {
                    "TrapOid": item["trapOid"] if item else "",
                    "TrapName": item["trapName"] if item else "",
                    "Source": item["source"] if item else "",
                    "Severity": item["severity"] if item else "",
                    "ReceivedAt": item["receivedAt"] if item else "",
                }
                for name, value in fields.items():
                    await self._write(f"Recent.{slot}.{name}", value, ua.VariantType.String)
            result["written"] = len(pairs) + SLOT_COUNT * 5
            self._events.event.TrapOid = trap["trapOid"]
            self._events.event.SourceAddress = trap["source"]
            self._events.event.Community = trap["community"]
            self._events.event.SeverityName = trap["severity"]
            self._events.event.Varbinds = trap["varbindsJson"][:4000]
            self._events.event.Severity = int(trap["severityCode"])
            await self._events.trigger(message=trap["message"])
            self.event_count += 1
            result["event"] = True
        except Exception as exc:
            result["error"] = str(exc)
            log.exception("OPC UA publish failed")
            try:
                await self._write("Gateway.LastError", str(exc)[:400], ua.VariantType.String)
            except Exception:
                pass
            return result
        if self.upstream["enabled"]:
            result["upstream"] = await self._forward(trap)
        return result

    async def readback(self) -> dict:
        if not self.ready:
            return {"ok": False, "error": self.error or "OPC UA server is not running"}
        async with self._read_lock:
            return await self._readback()

    async def _readback(self) -> dict:
        keys = (
            "Latest.TrapOid",
            "Latest.TrapName",
            "Latest.Source",
            "Latest.Community",
            "Latest.User",
            "Latest.SecurityLevel",
            "Latest.Version",
            "Latest.Kind",
            "Latest.Severity",
            "Latest.SeverityCode",
            "Latest.Message",
            "Latest.SysUpTime",
            "Gateway.TrapCount",
            "Gateway.InformCount",
            "Gateway.UdpPort",
            "Upstream.Inbox",
            "Upstream.Status",
        )
        try:
            values = await self._read_keys(keys)
        except Exception as exc:
            await self._drop_reader()
            try:
                values = await self._read_keys(keys)
            except Exception as again:
                return {"ok": False, "error": str(again or exc)}
        received = ""
        try:
            if self._reader is not None:
                when = await self._reader.get_node(self.node_ids["Latest.ReceivedAt"]).read_value()
                received = _iso(when)
        except Exception:
            received = ""
        return {
            "ok": True,
            "error": None,
            "trapOid": values["Latest.TrapOid"],
            "trapName": values["Latest.TrapName"],
            "source": values["Latest.Source"],
            "community": values["Latest.Community"],
            "user": values["Latest.User"],
            "securityLevel": values["Latest.SecurityLevel"],
            "version": values["Latest.Version"],
            "kind": values["Latest.Kind"],
            "severity": values["Latest.Severity"],
            "severityCode": values["Latest.SeverityCode"],
            "message": values["Latest.Message"],
            "sysUpTime": values["Latest.SysUpTime"],
            "trapCount": values["Gateway.TrapCount"],
            "informCount": values["Gateway.InformCount"],
            "udpPort": values["Gateway.UdpPort"],
            "receivedAt": received,
            "inbox": values["Upstream.Inbox"],
            "upstreamStatus": values["Upstream.Status"],
        }

    async def browse(self, folder: str, query: str = "") -> dict:
        if not self.ready:
            return {
                "ok": False,
                "error": self.error or "OPC UA server is not running",
                "folders": [],
                "items": [],
            }
        folder = (folder or "Latest").strip() or "Latest"
        query = query.strip().lower()
        ns = self.namespace_index or 2
        folders: list[str] = []
        if folder == "trapsnmp":
            folders = ["Latest", "Gateway", "Upstream", "Recent", "Radios", "Tags"]
            keys: list[str] = []
        elif folder == "Radios":
            folders = [f"Remote{number}" for number in range(1, REMOTE_TAG_COUNT + 1)]
            keys = [key for key in self.nodes if key.startswith("Radios.")]
        elif folder.startswith("Remote") and folder[6:].isdigit() and 1 <= int(folder[6:]) <= REMOTE_TAG_COUNT:
            keys = [key for key in self.nodes if key.startswith(folder + ".")]
        elif folder in ("Latest", "Gateway", "Upstream", "Recent"):
            keys = [key for key in self.nodes if key.startswith(folder + ".")]
        elif folder == "Tags":
            keys = [
                key
                for key in self.nodes
                if not key.startswith(("Latest.", "Gateway.", "Upstream.", "Recent.", "Radios.", "Remote"))
            ]
        else:
            return {"ok": False, "error": "Unknown folder.", "folders": [], "items": []}
        if query:
            keys = [key for key in keys if query in key.lower()]
        keys.sort()
        truncated = len(keys) > 300
        items = []
        for key in keys[:300]:
            try:
                raw = await self.nodes[key].read_value()
            except Exception:
                raw = None
            kind, text = _opc_text(raw)
            items.append(
                {
                    "name": key.split(".")[-1] if "." in key else key,
                    "nodeId": f"ns={ns};s={key}",
                    "value": text,
                    "type": kind,
                }
            )
        return {
            "ok": True,
            "folder": folder,
            "endpoint": self.endpoint,
            "namespace": NS_URI,
            "namespaceIndex": ns,
            "folders": folders,
            "items": items,
            "truncated": truncated,
        }

    def security_summary(self) -> dict:
        summary = {
            "policies": ["NoSecurity"],
            "subject": "",
            "expires": "",
            "thumbprint": "",
            "uri": "",
            "trusted": [],
            "rejected": [],
        }
        if self.pki is not None:
            summary.update(self.pki.summary())
        summary["users"] = self.users.names()
        summary["userPolicy"] = USER_POLICY
        return summary

    def configure_upstream(self, *, enabled: bool, endpoint: str, node_id: str) -> None:
        endpoint = endpoint.strip()
        node_id = node_id.strip()
        if enabled:
            if not endpoint.startswith("opc.tcp://"):
                raise ValueError("Endpoint must start with opc.tcp://")
            if not node_id.startswith("ns="):
                raise ValueError("Node id looks like ns=2;s=Upstream.Inbox")
        self.upstream["enabled"] = enabled
        self.upstream["endpoint"] = endpoint
        self.upstream["nodeId"] = node_id
        if not enabled:
            self.upstream["status"] = "Not forwarding"
        else:
            self.upstream["status"] = "Armed"
        self._forward_url = ""
        self._forward_pause_until = 0.0
        self._forward_pause_reason = ""

    def _forward_failed(self, reason: str) -> str:
        text = (reason or "Upstream did not answer").strip() or "Upstream did not answer"
        self.upstream["failed"] += 1
        self.upstream["status"] = text
        return "failed"

    async def _forward(self, trap: dict) -> str:
        payload = {
            "source": trap["source"],
            "sourcePort": trap["sourcePort"],
            "community": trap["community"],
            "user": trap.get("user", ""),
            "securityLevel": trap.get("securityLevel", ""),
            "version": trap["version"],
            "kind": trap["kind"],
            "trapOid": trap["trapOid"],
            "trapName": trap["trapName"],
            "severity": trap["severity"],
            "severityCode": trap["severityCode"],
            "message": trap["message"],
            "receivedAt": trap["receivedAt"],
            "varbinds": trap["varbinds"],
        }
        encoded = json.dumps(payload, separators=(",", ":"))
        if time.monotonic() < self._forward_pause_until:
            return self._forward_failed(self._forward_pause_reason)
        try:
            async with self._forward_lock:
                if time.monotonic() < self._forward_pause_until:
                    return self._forward_failed(self._forward_pause_reason)
                client = await asyncio.wait_for(self._forward_client(), 4.0)
                node = client.get_node(self.upstream["nodeId"])
                await asyncio.wait_for(node.write_value(encoded, ua.VariantType.String), 4.0)
        except Exception as exc:
            reason = str(exc).strip() or "Upstream did not answer"
            self._forward_pause_until = time.monotonic() + 10
            self._forward_pause_reason = reason
            try:
                async with self._forward_lock:
                    await self._drop_forwarder()
            except Exception:
                log.exception("could not close the upstream client")
            log.warning("upstream write failed: %s", reason)
            return self._forward_failed(reason)
        self.upstream["forwarded"] += 1
        self.upstream["status"] = "Last write succeeded"
        try:
            await self._write("Upstream.Status", self.upstream["status"], ua.VariantType.String)
            await self._write(
                "Upstream.Forwarded", self.upstream["forwarded"], ua.VariantType.UInt64
            )
        except Exception:
            log.exception("could not mirror upstream status")
        return "ok"

    def bind_tag_store(self, store) -> None:
        self._tag_store = store

    async def _install_tag_nodes(self) -> None:
        for address, kind in startup_nodes():
            await self._ensure_tag(address, kind)

    async def _ensure_tag(self, address: str, kind: str):
        if address in self.nodes or self._tags_parent is None:
            return self.nodes.get(address)
        variant = _TAG_TYPES[kind]
        initial = _TAG_INITIAL[kind]
        node = await self._tags_parent.add_variable(
            ua.NodeId(address, self._ns),
            ua.QualifiedName(address, self._ns),
            initial,
            varianttype=variant,
        )
        self.nodes[address] = node
        self.node_ids[address] = f"ns={self._ns};s={address}"
        writable = address == "EVENTS_COUNT" or (kind == "bool" and "[" not in address)
        if writable:
            await node.set_writable(True)
        return node

    def _arm_tag_writes(self, server: Server) -> None:
        bridge = self

        def setter(node, _attr, value):
            node.attributes[_attr].value = value
            ident = node.nodeid.Identifier
            if bridge._tag_store is None or not isinstance(ident, str):
                return
            raw = None if value.Value is None else value.Value.Value
            if ident == "EVENTS_COUNT" or ident in bridge._tag_store.bits or ident.endswith("(T)") or ident.startswith("TRAP_"):
                bridge._tag_store.note_write(ident, raw)

        for address, node in list(self.nodes.items()):
            if address == "EVENTS_COUNT" or address.endswith("(T)") or address.startswith("TRAP_"):
                if "[" in address:
                    continue
                server.set_attribute_value_setter(node.nodeid, setter)

    async def write_tags(self, updates: list[dict]) -> int:
        if not self.ready:
            return 0
        written = 0
        for item in updates:
            address = item["address"]
            kind = item["variant"]
            try:
                if address not in self.nodes:
                    await self._ensure_tag(address, kind)
                    if self._server is not None and kind == "bool":
                        self._arm_one(address)
                await self._write(address, item["value"], _TAG_TYPES[kind])
                written += 1
            except Exception:
                log.exception("tag write failed for %s", address)
        return written

    async def write_rssi_wave(self, rows: list[dict]) -> None:
        if not self.ready:
            return
        try:
            await self._write("Radios.Count", min(len(rows), REMOTE_TAG_COUNT), ua.VariantType.UInt32)
        except Exception:
            log.exception("radio count write failed")
        for number, row in enumerate(rows[:REMOTE_TAG_COUNT], start=1):
            for name, value, kind in remote_opc_values(row):
                try:
                    await self._write(f"Remote{number}.{name}", value, _TAG_TYPES[kind])
                except Exception:
                    log.exception("rssi wave write failed for Remote%s.%s", number, name)

    async def publish_radios(self, snap: dict) -> int:
        if not self.ready:
            return 0
        written = 0
        master = f"{snap.get('host', '')}:{snap.get('port', '')}"
        try:
            await self._write("Radios.Count", int(snap.get("count") or 0), ua.VariantType.UInt32)
            await self._write("Radios.Master", master, ua.VariantType.String)
            await self._write("Radios.Error", str(snap.get("error") or ""), ua.VariantType.String)
            written += 3
        except Exception:
            log.exception("radio summary write failed")
        current = set()
        for remote in snap.get("remotes") or []:
            key = remote["key"]
            current.add(key)
            rssi = remote.get("rssi")
            down = remote.get("downRssi")
            fields = [
                ("Present", True, "bool"),
                ("Mac", remote["mac"], "string"),
                ("Ip", remote.get("ip") or "", "string"),
                ("Name", remote.get("name") or "", "string"),
                ("Link", remote.get("link") or "", "string"),
                ("IfIndex", int(remote.get("ifIndex") or 0), "uint"),
            ]
            if rssi is not None:
                fields.append(("Rssi", int(rssi), "int"))
            if down is not None:
                fields.append(("DownRssi", int(down), "int"))
            for name, value, kind in fields:
                written += await self._put_radio(key, f"Radios.{key}.{name}", name, value, kind)
        remotes = list(snap.get("remotes") or [])
        for number in range(1, REMOTE_TAG_COUNT + 1):
            remote = remotes[number - 1] if number <= len(remotes) else None
            for name, value, kind in remote_opc_values(remote):
                try:
                    await self._write(f"Remote{number}.{name}", value, _TAG_TYPES[kind])
                    written += 1
                except Exception:
                    log.exception("remote tag write failed for Remote%s.%s", number, name)
        for key in list(self._radio_keys):
            if key in current:
                continue
            written += await self._put_radio(key, f"Radios.{key}.Present", "Present", False, "bool")
        self._radio_keys = current
        return written

    async def _put_radio(self, key: str, address: str, browse: str, value, kind: str) -> int:
        try:
            await self._ensure_radio(key, address, browse, kind)
            await self._write(address, value, _TAG_TYPES[kind])
        except Exception:
            log.exception("radio write failed for %s", address)
            return 0
        return 1

    async def _ensure_radio(self, key: str, address: str, browse: str, kind: str):
        if address in self.nodes or self._radios_parent is None:
            return self.nodes.get(address)
        folder = self._radio_folders.get(key)
        if folder is None:
            folder = await self._radios_parent.add_object(
                ua.NodeId(f"Radios.{key}", self._ns),
                key,
            )
            self._radio_folders[key] = folder
        node = await folder.add_variable(
            ua.NodeId(address, self._ns),
            ua.QualifiedName(browse, self._ns),
            _TAG_INITIAL[kind],
            varianttype=_TAG_TYPES[kind],
        )
        self.nodes[address] = node
        self.node_ids[address] = f"ns={self._ns};s={address}"
        return node

    def _arm_one(self, address: str) -> None:
        node = self.nodes.get(address)
        if node is None or self._server is None:
            return

        bridge = self

        def setter(ndata, attr, value):
            ndata.attributes[attr].value = value
            if bridge._tag_store is not None:
                raw = None if value.Value is None else value.Value.Value
                bridge._tag_store.note_write(address, raw)

        self._server.set_attribute_value_setter(node.nodeid, setter)

    async def read_tag(self, address: str):
        if not self.ready or address not in self.node_ids:
            return None
        async with self._read_lock:
            if self._reader is None:
                await self._connect_reader()
            node = self._reader.get_node(self.node_ids[address])
            return await node.read_value()

    async def _write(self, key: str, value, variant: ua.VariantType) -> None:
        await self.nodes[key].write_value(value, variant)

    async def _connect_reader(self) -> None:
        client = Client(self.endpoint)
        client.session_timeout = 600_000
        await client.connect()
        self._reader = client

    async def _drop_reader(self) -> None:
        client = self._reader
        self._reader = None
        if client is not None:
            try:
                await client.disconnect()
            except Exception:
                pass

    async def _read_keys(self, keys: tuple[str, ...]) -> dict:
        if self._reader is None:
            await self._connect_reader()
        assert self._reader is not None
        out = {}
        for key in keys:
            value = await self._reader.get_node(self.node_ids[key]).read_value()
            out[key] = _iso(value) if isinstance(value, datetime) else value
        return out

    async def _forward_client(self) -> Client:
        url = self.upstream["endpoint"]
        if self._forwarder is not None and self._forward_url == url:
            return self._forwarder
        await self._drop_forwarder()
        client = Client(url)
        client.session_timeout = 10_000
        try:
            await client.connect()
        except BaseException:
            try:
                await client.disconnect()
            except Exception:
                pass
            raise
        self._forwarder = client
        self._forward_url = url
        return client

    async def _drop_forwarder(self) -> None:
        client = self._forwarder
        self._forwarder = None
        self._forward_url = ""
        if client is not None:
            try:
                await client.disconnect()
            except Exception:
                pass
