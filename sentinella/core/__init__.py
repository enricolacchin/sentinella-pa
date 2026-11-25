"""Il motore di analisi di Sentinella PA.

API pubblica::

    from sentinella.core import analizza
    report = analizza("https://www.comune.example.it")
    report.to_dict()   # tutto serializzabile: pronto per JSON o database

Il motore non stampa nulla e non dipende da CLI o framework web: riceve un URL
e restituisce un ``Report``. Puo' quindi girare tale e quale in un job in
background (Fase 2: form web -> coda -> ``analizza()`` -> salvataggio).
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import requests

from sentinella import __version__
from sentinella.core.checks import REGISTRO
from sentinella.core.context import Context, DnsResolver, costruisci_contesto
from sentinella.core.models import Finding, Report, Severity, Status

__all__ = ["analizza", "analizza_contesto", "Report", "Finding", "Severity", "Status"]


def analizza_contesto(ctx: Context) -> list[Finding]:
    """Esegue tutti i controlli registrati su un ``Context`` gia' costruito.

    Un controllo che solleva un'eccezione non blocca gli altri: produce un
    esito "errore" con la descrizione del problema.
    """
    findings: list[Finding] = []
    for nome, controllo in REGISTRO:
        try:
            risultati = controllo(ctx)
        except Exception as exc:  # un bug in un controllo non deve fermare l'analisi
            risultati = [
                Finding(
                    id=f"{nome}.errore_interno",
                    titolo=f"Controllo {nome} non completato",
                    status=Status.ERRORE,
                    severita=Severity.INFORMATIVA,
                    dettaglio="Errore inatteso durante il controllo: esito non verificabile.",
                    evidenza=f"{exc.__class__.__name__}: {exc}",
                )
            ]
        for f in risultati:
            f.categoria = nome
        findings.extend(risultati)
    return findings


def analizza(
    url: str,
    timeout: float = 10.0,
    *,
    sessione: requests.Session | None = None,
    resolver: DnsResolver | None = None,
) -> Report:
    """Analizza in modo esclusivamente passivo il sito indicato.

    :param url: indirizzo del sito (anche solo il dominio).
    :param timeout: timeout in secondi per ciascuna operazione di rete.
    :param sessione: sessione HTTP alternativa (test, proxy, Fase 2).
    :param resolver: resolver DNS alternativo (test).
    :raises ValueError: se l'URL non e' formalmente valido.
    """
    inizio = time.monotonic()
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    ctx = costruisci_contesto(url, timeout=timeout, sessione=sessione, resolver=resolver)
    findings = analizza_contesto(ctx)
    return Report(
        target=ctx.url,
        final_url=ctx.final_url,
        hostname=ctx.hostname,
        dominio=ctx.dominio,
        timestamp=timestamp,
        findings=findings,
        durata_secondi=round(time.monotonic() - inizio, 2),
        versione=__version__,
    )
