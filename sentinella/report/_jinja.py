"""Ambiente Jinja2 condiviso da tutti i template (CLI e futuro sito web)."""

from __future__ import annotations

from datetime import datetime
from functools import lru_cache

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from sentinella.core.checks import ETICHETTE
from sentinella.core.models import Finding, Report, Status
from sentinella.report.linguaggio import rischio, titolo_semplice

ETICHETTE_STATUS = {
    Status.OK: "OK",
    Status.ATTENZIONE: "Attenzione",
    Status.PROBLEMA: "Problema",
    Status.ERRORE: "Non verificabile",
    Status.INFO: "Info",
}

DESCRIZIONE_VOTO = {
    "A": "Configurazione molto buona",
    "B": "Configurazione buona, con alcuni miglioramenti possibili",
    "C": "Configurazione sufficiente, con interventi consigliati",
    "D": "Configurazione insufficiente, interventi necessari",
    "E": "Configurazione critica, interventi urgenti",
}


def data_leggibile(iso: str) -> str:
    """'2026-11-25T10:00:00+00:00' -> '25/11/2026 10:00 UTC'."""
    try:
        return datetime.fromisoformat(iso).strftime("%d/%m/%Y %H:%M UTC")
    except ValueError:
        return iso


def _gruppi(report: Report) -> list[tuple[str, list[Finding]]]:
    """Esiti raggruppati per controllo, nell'ordine del registro."""
    gruppi: dict[str, list[Finding]] = {}
    for f in report.findings:
        gruppi.setdefault(f.categoria, []).append(f)
    return [(ETICHETTE.get(nome, nome), lista) for nome, lista in gruppi.items()]


def _da_correggere(report: Report) -> list[Finding]:
    """Problemi e attenzioni, dal piu' grave."""
    return [
        f for f in report.findings_ordinati() if f.status in (Status.PROBLEMA, Status.ATTENZIONE)
    ]


@lru_cache(maxsize=1)
def ambiente() -> Environment:
    env = Environment(
        loader=PackageLoader("sentinella.report", "templates"),
        autoescape=select_autoescape(enabled_extensions=("html", "html.j2"), default=False),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        undefined=StrictUndefined,
    )
    env.filters["data"] = data_leggibile
    env.filters["etichetta_status"] = lambda s: ETICHETTE_STATUS[Status(s)]
    env.filters["titolo_semplice"] = titolo_semplice
    env.filters["rischio"] = rischio
    env.globals["gruppi"] = _gruppi
    env.globals["da_correggere"] = _da_correggere
    env.globals["descrizione_voto"] = DESCRIZIONE_VOTO
    env.globals["Status"] = Status
    return env


def render(nome_template: str, **variabili: object) -> str:
    return ambiente().get_template(nome_template).render(**variabili)
