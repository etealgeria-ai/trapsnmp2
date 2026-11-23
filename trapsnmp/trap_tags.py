"""Trap-tag driver.

A received trap sets a Boolean at TRAP_V1 or TRAP_V2C and fills that tag's
virtual table. The same message is pushed to EVENTS_001. Clients reset a
Boolean by writing false, and reset EVENTS_COUNT by writing a new value.
"""

from __future__ import annotations

import logging

log = logging.getLogger("trapsnmp.tags")

SYS_UP = "1.3.6.1.2.1.1.3.0"
TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
IF_INDEX = "1.3.6.1.2.1.2.2.1.1."
V1_GENERIC_ENTERPRISE = "1.3.6.1.2.1.11"
V2_TRAPS = "1.3.6.1.6.3.1.1.5"

# Ethernet switch / other-device profile: coldStart, warmStart, linkDown, linkUp.
V2_AUTO = (
    f"{V2_TRAPS}.1",
    f"{V2_TRAPS}.2",
    f"{V2_TRAPS}.3",
    f"{V2_TRAPS}.4",
)
V1_AUTO = (0, 1, 2, 3)

EVENT_SLOTS = 10
# Each new trap OID or port adds about 21 OPC UA nodes that are never removed.
# Past this many extra addresses, traps still reach Latest, Recent, the event,
# and EVENTS_001..010, but get no new TRAP_ tags.
MAX_TRAP_TAGS = 2000
_UINT32 = 2**32
FIELD_SLOTS = 20
TABLE_ROWS = 20


def _tail_int(oid: str) -> int | None:
    piece = oid.rsplit(".", 1)[-1]
    if piece.isdigit():
        return int(piece)
    return None


def v1_identity(oid: str) -> tuple[int, int, str]:
    """Return generic type, specific type, and enterprise OID for a v1 trap."""
    number = _tail_int(oid)
    if oid.startswith(V2_TRAPS + ".") and number is not None and 1 <= number <= 6:
        return number - 1, 0, V1_GENERIC_ENTERPRISE
    parts = oid.split(".")
    if len(parts) >= 3 and parts[-2] == "0" and parts[-1].isdigit():
        return 6, int(parts[-1]), ".".join(parts[:-2])
    return 6, 0, oid


def v2_identity(oid: str) -> tuple[int, int, str]:
    number = _tail_int(oid)
    if oid.startswith(V2_TRAPS + ".") and number is not None and 1 <= number <= 6:
        return number - 1, 0, V2_TRAPS
    return 6, 0, oid


def _port(varbinds: list[dict]) -> int | None:
    for item in varbinds:
        oid = str(item.get("oid") or "")
        if oid.startswith(IF_INDEX):
            port = _tail_int(oid)
            if port:
                return port
    return None


def _payload(varbinds: list[dict]) -> list[dict]:
    rows = []
    for item in varbinds:
        oid = str(item.get("oid") or "")
        if oid in (SYS_UP, TRAP_OID):
            continue
        rows.append(item)
    return rows


def virtual_fields(record: dict, enterprise: str, generic: int, specific: int) -> list[str]:
    binds = _payload(record.get("varbinds") or [])
    stamp = str(record.get("receivedAt") or "").replace("T", " ")
    if stamp.endswith("+00:00"):
        stamp = stamp[:-6]
    fields = [
        stamp,
        enterprise,
        str(generic),
        str(specific),
        str(int(record.get("sysUpTime") or 0)),
        str(len(binds)),
    ]
    for item in binds:
        fields.append(str(item.get("oid") or ""))
        fields.append(str(item.get("value") or ""))
    return fields


def addresses_for(record: dict) -> list[str]:
    oid = str(record.get("trapOid") or "").lstrip(".")
    if not oid:
        return []
    port = _port(_payload(record.get("varbinds") or []))
    version = record.get("version") or "v2c"
    found: list[str] = []
    if version == "v1":
        generic, specific, enterprise = v1_identity(oid)
        base = f"TRAP_V1:.{enterprise}:G{generic}"
        if generic == 6:
            base += f":S{specific}"
        found.append(base)
        if port and generic in (2, 3, 6):
            found.append(f"{base}:P{port}")
    else:
        found.append(f"TRAP_V2C:.{oid}")
        if port and (oid in (f"{V2_TRAPS}.3", f"{V2_TRAPS}.4") or v2_identity(oid)[0] == 6):
            found.append(f"TRAP_V2C:.{oid}:P{port}")
        found.append(f"{oid}(T)")
    return found


def table_variant(row: int) -> str:
    if row in (3, 4, 6):
        return "int"
    if row == 5:
        return "uint"
    return "string"


def standard_addresses() -> list[str]:
    rows = [f"TRAP_V1:.{V1_GENERIC_ENTERPRISE}:G{generic}" for generic in V1_AUTO]
    rows.extend(f"TRAP_V2C:.{oid}" for oid in V2_AUTO)
    rows.extend(f"{oid}(T)" for oid in V2_AUTO)
    return rows


def startup_nodes() -> list[tuple[str, str]]:
    nodes = [("EVENTS_COUNT", "uint")]
    for slot in range(1, EVENT_SLOTS + 1):
        prefix = f"EVENTS_{slot:03d}"
        nodes.append((prefix, "string"))
        nodes.append((f"{prefix}_FLDCNT", "uint"))
        for index in range(1, FIELD_SLOTS + 1):
            nodes.append((f"{prefix}_{index:03d}", "string"))
    for address in standard_addresses():
        nodes.append((address, "bool"))
        if address.endswith("(T)"):
            continue
        for index in range(1, TABLE_ROWS + 1):
            nodes.append((f"{address}[{index}]", table_variant(index)))
    return nodes


class TrapTags:
    def __init__(self) -> None:
        self.event_slots = EVENT_SLOTS
        self.field_slots = FIELD_SLOTS
        self.count = 0
        self.community = ""
        self.device_ip = ""
        self.bits: dict[str, bool] = {addr: False for addr in standard_addresses()}
        self._standard = len(self.bits)
        self.limit_hits = 0
        self.limited_last = False
        self.queue: list[list[str]] = []

    def configure(self, *, community: str | None = None, device_ip: str | None = None) -> None:
        if community is not None:
            self.community = community.strip()
        if device_ip is not None:
            self.device_ip = device_ip.strip()

    def accept(self, record: dict) -> bool:
        if self.device_ip and str(record.get("source") or "") != self.device_ip:
            return False
        if self.community and record.get("version") != "v3":
            if str(record.get("community") or "") != self.community:
                return False
        return True

    def note_write(self, address: str, value) -> None:
        if address == "EVENTS_COUNT":
            try:
                self.count = max(0, int(value)) % _UINT32
            except (TypeError, ValueError):
                return
            return
        if address in self.bits or address.startswith("TRAP_") or address.endswith("(T)"):
            self.bits[address] = bool(value)

    def apply(self, record: dict) -> list[dict]:
        oid = str(record.get("trapOid") or "").lstrip(".")
        if record.get("version") == "v1":
            generic, specific, enterprise = v1_identity(oid)
        else:
            generic, specific, enterprise = v2_identity(oid)
        fields = virtual_fields(record, enterprise, generic, specific)
        # EVENTS_COUNT is a UInt32; past 4,294,967,295 every write would fail.
        self.count = (self.count + 1) % _UINT32
        self.queue.insert(0, fields)
        del self.queue[self.event_slots :]
        updates: list[dict] = [
            {"address": "EVENTS_COUNT", "value": self.count, "variant": "uint"}
        ]
        for slot in range(1, self.event_slots + 1):
            row = self.queue[slot - 1] if slot - 1 < len(self.queue) else []
            prefix = f"EVENTS_{slot:03d}"
            updates.append(
                {
                    "address": prefix,
                    "value": ";".join(row),
                    "variant": "string",
                }
            )
            updates.append(
                {
                    "address": f"{prefix}_FLDCNT",
                    "value": len(row),
                    "variant": "uint",
                }
            )
            for index in range(1, self.field_slots + 1):
                value = row[index - 1] if index - 1 < len(row) else ""
                updates.append(
                    {
                        "address": f"{prefix}_{index:03d}",
                        "value": value,
                        "variant": "string",
                    }
                )
        self.limited_last = False
        for address in addresses_for(record):
            if address not in self.bits and len(self.bits) - self._standard >= MAX_TRAP_TAGS:
                self.limited_last = True
                self.limit_hits += 1
                if self.limit_hits == 1:
                    log.warning(
                        "Trap tag limit of %s reached; new trap OIDs and ports get no TRAP_ tags",
                        MAX_TRAP_TAGS,
                    )
                continue
            if not self.bits.get(address):
                self.bits[address] = True
                updates.append({"address": address, "value": True, "variant": "bool"})
            if address.endswith("(T)"):
                continue
            for index in range(1, TABLE_ROWS + 1):
                raw = fields[index - 1] if index - 1 < len(fields) else ""
                kind = table_variant(index)
                if kind == "int":
                    value = int(raw or 0)
                elif kind == "uint":
                    value = int(raw or 0)
                else:
                    value = raw
                updates.append(
                    {
                        "address": f"{address}[{index}]",
                        "value": value,
                        "variant": kind,
                    }
                )
        return updates

    def snapshot(self) -> dict:
        latest = self.queue[0] if self.queue else []
        shown = []
        for address in standard_addresses():
            if address.endswith("(T)"):
                continue
            shown.append({"address": address, "value": bool(self.bits.get(address))})
        extras = [
            {"address": address, "value": True}
            for address, value in self.bits.items()
            if value and address not in {item["address"] for item in shown} and not address.endswith("(T)")
        ]
        return {
            "count": self.count,
            "community": self.community,
            "deviceIp": self.device_ip,
            "eventSlots": self.event_slots,
            "fieldSlots": self.field_slots,
            "latest": ";".join(latest),
            "latestFields": latest[:8],
            "fieldCount": len(latest),
            "bits": shown + extras,
            "tagLimit": MAX_TRAP_TAGS,
            "tagsUsed": len(self.bits) - self._standard,
            "tagLimitHits": self.limit_hits,
        }
