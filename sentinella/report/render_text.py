"""Riepilogo a terminale con ``rich``."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sentinella.core.models import Report, Status
from sentinella.report._jinja import DESCRIZIONE_VOTO, ETICHETTE_STATUS, data_leggibile

STILE_STATUS = {
    Status.OK: "green",
    Status.ATTENZIONE: "yellow",
    Status.PROBLEMA: "bold red",
    Status.ERRORE: "magenta",
    Status.INFO: "cyan",
}

STILE_VOTO = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "E": "bold red"}


def render_text(report: Report, console: Console | None = None) -> None:
    """Stampa il riepilogo sulla console indicata (o su stdout)."""
    console = console or Console()

    intestazione = Text()
    intestazione.append(f"{report.hostname}\n", style="bold")
    intestazione.append(f"URL finale: {report.final_url}\n")
    intestazione.append(f"Dominio: {report.dominio} · {data_leggibile(report.timestamp)}\n")
    intestazione.append("Punteggio: ")
    intestazione.append(f"{report.punteggio}/100  voto {report.voto}", style=STILE_VOTO[report.voto])
    intestazione.append(f"  — {DESCRIZIONE_VOTO[report.voto]}")
    if not report.completo:
        intestazione.append(
            f"\nVoto parziale: {report.non_verificabili} controlli non verificabili", style="magenta"
        )
    console.print(Panel(intestazione, title="Sentinella PA — verifica passiva", expand=False))

    tabella = Table(expand=True)
    tabella.add_column("Esito", no_wrap=True)
    tabella.add_column("Gravita'", no_wrap=True)
    tabella.add_column("Controllo", ratio=2)
    tabella.add_column("Dettaglio", ratio=5)
    for f in report.findings_ordinati():
        tabella.add_row(
            Text(ETICHETTE_STATUS[f.status], style=STILE_STATUS[f.status]),
            f.severita.value,
            f.titolo,
            f.dettaglio,
        )
    console.print(tabella)

    conteggi = report.conteggi()
    console.print(
        f"Problemi: {conteggi['problema']} · Attenzione: {conteggi['attenzione']} · "
        f"OK: {conteggi['ok']} · Non verificabili: {conteggi['errore']} · Info: {conteggi['info']}"
    )
    console.print(Text(report.generato_con, style="dim"))
