"""Avvio locale dell'interfaccia: ``python -m sentinella.web``.

Serve l'API e il frontend (cartella ``web/``) su http://127.0.0.1:8000.
Richiede uvicorn (``pip install -e ".[web,dev]"``).
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path


def main() -> None:
    p = argparse.ArgumentParser(prog="python -m sentinella.web", description="Avvia l'interfaccia web in locale.")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--porta", type=int, default=8000)
    args = p.parse_args()

    radice = Path(__file__).resolve().parents[2]
    os.environ.setdefault("SENTINELLA_FRONTEND", str(radice / "web"))
    os.environ.setdefault("SENTINELLA_DATABASE", str(radice / "sentinella.sqlite3"))
    os.environ.setdefault("SENTINELLA_DIETRO_PROXY", "0")

    import uvicorn

    from sentinella.web import crea_app

    uvicorn.run(crea_app(), host=args.host, port=args.porta)


if __name__ == "__main__":
    main()
