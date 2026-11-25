"""Front-end a riga di comando: legge gli argomenti, chiama ``analizza()``, passa il
``Report`` allo strato di rendering. Nessuna logica di analisi qui."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from rich.console import Console

from sentinella import __version__
from sentinella.core import analizza
from sentinella.core.models import Report
from sentinella.report import (
    render_html,
    render_json,
    render_pec,
    render_report_sindaco,
    render_report_tecnico,
    render_text,
)

# opzione CLI -> funzione di rendering
USCITE: dict[str, Callable[[Report], str]] = {
    "json": render_json,
    "html": render_html,
    "pec": render_pec,
    "report_tecnico": render_report_tecnico,
    "report_sindaco": render_report_sindaco,
}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinella",
        description="Verifica passiva della sicurezza di un sito della Pubblica Amministrazione.",
    )
    p.add_argument("url", help="indirizzo del sito, es. https://www.comune.example.it o solo il dominio")
    p.add_argument("--json", metavar="FILE", help="salva il report in JSON")
    p.add_argument("--html", metavar="FILE", help="salva il report HTML stampabile")
    p.add_argument("--pec", metavar="FILE", help="salva la bozza di PEC all'ente")
    p.add_argument("--report-tecnico", metavar="FILE", help="salva il report tecnico (Markdown)")
    p.add_argument("--report-sindaco", metavar="FILE", help="salva il report semplice per sindaco/RTD (Markdown)")
    p.add_argument("--timeout", type=float, default=10.0, help="timeout di rete in secondi (default 10)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    console = Console()
    errori = Console(stderr=True)

    try:
        with console.status(f"Analisi passiva di {args.url} in corso..."):
            report = analizza(args.url, timeout=args.timeout)
    except ValueError as exc:
        errori.print(f"[red]URL non valido:[/red] {exc}")
        return 2

    render_text(report, console)

    for nome, funzione in USCITE.items():
        destinazione = getattr(args, nome)
        if destinazione:
            Path(destinazione).write_text(funzione(report), encoding="utf-8")
            console.print(f"Salvato: {destinazione}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
