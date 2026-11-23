"""Operator console served next to the gateway."""

from __future__ import annotations

import logging
from html import escape
from pathlib import Path

from aiohttp import web

from trapsnmp.catalog import PRESETS
from trapsnmp.service import Service

log = logging.getLogger("trapsnmp.web")

STATIC = Path(__file__).resolve().parent / "static"
INDEX = (STATIC / "index.html").read_text(encoding="utf-8")


def _preset_buttons(items) -> str:
    parts = []
    for item in items:
        parts.append(
            "<button type=\"button\" class=\"preset\" data-preset=\"{id}\">"
            "<span class=\"preset-name\">{label}</span>"
            "<span class=\"preset-detail\">{detail}</span>"
            "</button>".format(
                id=_esc(item["id"]),
                label=_esc(item["label"]),
                detail=_esc(item["detail"]),
            )
        )
    return "".join(parts)


def _esc(value: str) -> str:
    return escape(value, quote=True)


PAGE = INDEX.replace(
    "<!--PRESETS-->",
    _preset_buttons([item for item in PRESETS if item.get("group") != "ge-ln"]),
).replace(
    "<!--GE-PRESETS-->",
    _preset_buttons([item for item in PRESETS if item.get("group") == "ge-ln"]),
)


def _json_error(message: str, status: int = 400) -> web.Response:
    return web.json_response({"ok": False, "error": message}, status=status)


@web.middleware
async def _require_json(request: web.Request, handler):
    # A page on another site can POST text/plain without a CORS preflight,
    # and request.json() would still parse it. Requiring application/json
    # forces a preflight, which this server never approves.
    if request.method == "POST" and request.content_type != "application/json":
        return _json_error("Send JSON with Content-Type: application/json.", 415)
    return await handler(request)


async def handle_index(_request: web.Request) -> web.Response:
    return web.Response(
        text=PAGE,
        content_type="text/html",
        headers={"Cache-Control": "no-store"},
    )


async def handle_opc_user(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
    except Exception:
        return _json_error("Expected JSON.")
    if not isinstance(body, dict):
        return _json_error("Expected a JSON object.")
    try:
        if body.get("action") == "remove":
            service.opc.users.remove(str(body.get("name") or ""))
        else:
            service.opc.users.add(str(body.get("name") or ""), str(body.get("password") or ""))
    except ValueError as exc:
        return _json_error(str(exc))
    service.persist()
    return web.json_response({"ok": True, "users": service.opc.users.names()})


async def handle_pki(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    if service.opc.pki is None:
        return _json_error("The certificate store is not ready.", 503)
    try:
        body = await request.json()
    except Exception:
        return _json_error("Expected JSON.")
    if not isinstance(body, dict) or body.get("action") != "trust":
        return _json_error("Expected a trust action.")
    try:
        summary = service.opc.pki.trust(str(body.get("name") or ""))
    except ValueError as exc:
        return _json_error(str(exc))
    return web.json_response({"ok": True, "certificate": summary})


async def handle_opc(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    folder = request.query.get("folder", "Latest")
    query = request.query.get("q", "")
    return web.json_response(await service.opc.browse(folder, query))


async def handle_favicon(_request: web.Request) -> web.Response:
    body = (STATIC / "favicon.svg").read_bytes()
    return web.Response(body=body, content_type="image/svg+xml")


async def handle_state(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    return web.json_response(await service.snapshot())


async def handle_inject(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
    except Exception:
        return _json_error("Expected JSON.")
    if not isinstance(body, dict):
        return _json_error("Expected a JSON object.")
    try:
        preset = body.get("preset")
        if preset:
            record = await service.inject_preset(str(preset), _optional_str(body.get("community")))
        else:
            binds = []
            for item in body.get("varbinds") or []:
                if not isinstance(item, dict):
                    raise ValueError("Each varbind needs oid, type, and value.")
                binds.append(
                    (
                        str(item.get("oid", "")).strip(),
                        str(item.get("type", "string")).strip(),
                        str(item.get("value", "")),
                    )
                )
            record = await service.inject_custom(
                community=str(body.get("community") or "public"),
                version=str(body.get("version") or "2c"),
                trap_oid=str(body.get("trapOid") or "").strip(),
                varbinds=binds,
                user=_optional_str(body.get("user")),
            )
    except (ValueError, RuntimeError) as exc:
        return _json_error(str(exc))
    except Exception as exc:
        log.exception("inject failed")
        return _json_error(str(exc), 500)
    return web.json_response({"ok": True, "trap": record})


async def handle_community(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
        service.allow_community(str(body.get("community", "")))
    except (ValueError, TypeError, AttributeError) as exc:
        return _json_error(str(exc))
    except Exception:
        return _json_error("Expected JSON.", 400)
    service.persist()
    return web.json_response({"ok": True, "communities": service.snmp.communities})


async def handle_user(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
        created = service.add_user(body if isinstance(body, dict) else {})
    except (ValueError, TypeError, AttributeError) as exc:
        return _json_error(str(exc))
    except Exception:
        return _json_error("Expected JSON.", 400)
    service.persist()
    return web.json_response({"ok": True, "user": created, "users": service.snmp.users})


async def handle_diag(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        report = await service.diagnose()
    except Exception as exc:
        log.exception("diag failed")
        return _json_error(str(exc), 500)
    return web.json_response(report)


async def handle_agent(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
    except Exception:
        return _json_error("Expected JSON.")
    if not isinstance(body, dict):
        return _json_error("Expected a JSON object.")
    action = str(body.get("action") or "settings")
    try:
        if action == "settings":
            service.agent.configure(body)
        elif action == "community":
            service.agent.add_community(str(body.get("name") or ""), str(body.get("rights") or ""))
        elif action == "host":
            service.agent.add_host(str(body.get("address") or ""))
        elif action == "destination":
            service.agent.add_destination(
                str(body.get("address") or ""),
                int(body.get("port") or 162),
                str(body.get("community") or "public"),
                str(body.get("version") or "2c"),
            )
        elif action == "remove":
            service.agent.remove(str(body.get("kind") or ""), str(body.get("key") or ""))
        else:
            raise ValueError("Unknown agent action.")
    except (ValueError, TypeError) as exc:
        return _json_error(str(exc))
    except Exception as exc:
        log.exception("agent update failed")
        return _json_error(str(exc), 500)
    service.persist()
    return web.json_response({"ok": True, "agent": service.agent.snapshot()})


async def handle_radios(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
    except Exception:
        return _json_error("Expected JSON.")
    if not isinstance(body, dict):
        return _json_error("Expected a JSON object.")
    action = str(body.get("action") or "save")
    try:
        if action in ("save", "poll"):
            service.radios.configure(
                host=str(body.get("host") or ""),
                community=str(body.get("community") or "public"),
                port=int(body.get("port") or 161),
                interval=int(body.get("interval") or 15),
                enabled=bool(body.get("enabled")),
            )
        if action == "poll":
            await service.radios.poll()
    except (TypeError, ValueError) as exc:
        return _json_error(str(exc))
    except Exception as exc:
        log.exception("radio poll failed")
        return _json_error(str(exc), 500)
    return web.json_response({"ok": True, "radios": service.radio_view()})


async def handle_tags(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
    except Exception:
        return _json_error("Expected JSON.")
    if not isinstance(body, dict):
        return _json_error("Expected a JSON object.")
    try:
        service.tags.configure(
            community=str(body.get("community") or ""),
            device_ip=str(body.get("deviceIp") or ""),
        )
    except (TypeError, ValueError) as exc:
        return _json_error(str(exc))
    service.persist()
    return web.json_response({"ok": True, "tags": service.tags.snapshot()})


async def handle_sine(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
    except Exception:
        return _json_error("Expected JSON.")
    if not isinstance(body, dict):
        return _json_error("Expected a JSON object.")
    return web.json_response({"ok": True, "sine": service.set_sine(bool(body.get("enabled")))})


async def handle_upstream(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
        service.configure_upstream(
            enabled=bool(body.get("enabled")),
            endpoint=str(body.get("endpoint") or ""),
            node_id=str(body.get("nodeId") or ""),
        )
    except (ValueError, TypeError, AttributeError) as exc:
        return _json_error(str(exc))
    except Exception:
        return _json_error("Expected JSON.", 400)
    service.persist()
    return web.json_response({"ok": True, "upstream": service.opc.upstream})


def _optional_str(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


async def serve(service: Service) -> None:
    app = web.Application(client_max_size=1024 * 256, middlewares=[_require_json])
    app["service"] = service
    app.router.add_get("/", handle_index)
    app.router.add_get("/favicon.svg", handle_favicon)
    app.router.add_get("/api/state", handle_state)
    app.router.add_get("/api/opc", handle_opc)
    app.router.add_post("/api/pki", handle_pki)
    app.router.add_post("/api/opc-user", handle_opc_user)
    app.router.add_post("/api/inject", handle_inject)
    app.router.add_post("/api/community", handle_community)
    app.router.add_post("/api/user", handle_user)
    app.router.add_post("/api/diag", handle_diag)
    app.router.add_post("/api/agent", handle_agent)
    app.router.add_post("/api/tags", handle_tags)
    app.router.add_post("/api/radios", handle_radios)
    app.router.add_post("/api/sine", handle_sine)
    app.router.add_post("/api/upstream", handle_upstream)
    app.router.add_static("/static", STATIC, show_index=False)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", 8080)
    await site.start()
    log.info("console ready")
    await asyncio_forever()


async def asyncio_forever() -> None:
    import asyncio

    await asyncio.Event().wait()
