"""Run the trapsnmp gateway and its console."""

from __future__ import annotations

import asyncio
import logging

from trapsnmp.paths import DATA_DIR
from trapsnmp.service import Service
from trapsnmp.tasks import spawn
from trapsnmp.web import serve


async def _amain() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    service = Service()
    logging.getLogger("trapsnmp").info("Settings and certificates in %s", DATA_DIR)

    async def _start() -> None:
        try:
            await service.start()
        except Exception:
            logging.getLogger("trapsnmp").exception("gateway start failed")

    spawn(_start(), name="gateway-start")
    await serve(service)


def main() -> None:
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
