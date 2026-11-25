"""security.txt (RFC 9116): l'ente indica come ricevere segnalazioni di sicurezza?"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from sentinella.core.context import Context
from sentinella.core.models import Finding, Severity, Status

RIF_SECTXT = "RFC 9116 (security.txt); https://securitytxt.org"


def _esempio(dominio: str) -> str:
    anno = datetime.now(timezone.utc).year + 1
    return (
        f"Contact: mailto:sicurezza@{dominio}\n"
        f"Expires: {anno}-12-31T23:00:00.000Z\n"
        "Preferred-Languages: it, en\n"
        f"Policy: https://{dominio}/divulgazione-responsabile"
    )


def _campi(testo: str) -> dict[str, list[str]]:
    campi: dict[str, list[str]] = {}
    for riga in testo.splitlines():
        riga = riga.strip()
        if not riga or riga.startswith("#") or ":" not in riga:
            continue
        nome, valore = riga.split(":", 1)
        campi.setdefault(nome.strip().lower(), []).append(valore.strip())
    return campi


def _data(valore: str) -> datetime | None:
    valore = valore.strip().replace("Z", "+00:00")
    try:
        data = datetime.fromisoformat(valore)
    except ValueError:
        m = re.match(r"\d{4}-\d{2}-\d{2}", valore)
        if not m:
            return None
        data = datetime.fromisoformat(m.group(0))
    return data if data.tzinfo else data.replace(tzinfo=timezone.utc)


def controlla(ctx: Context) -> list[Finding]:
    fetch = ctx.security_txt
    rimedio = (
        "Pubblicare un file di testo in /.well-known/security.txt con almeno i campi "
        "Contact ed Expires, ad esempio:\n" + _esempio(ctx.dominio)
    )
    base = dict(id="security_txt", titolo="File security.txt", riferimento=RIF_SECTXT)
    rimedi_server = dict(
        rimedio_nginx="location = /.well-known/security.txt {\n    default_type text/plain;\n}",
        rimedio_apache='<Files "security.txt">\n    ForceType text/plain\n</Files>',
        rimedio_wordpress="Caricare il file nella cartella .well-known della radice del sito (non tramite il CMS).",
    )

    # Errore di rete e anche la home non e' arrivata: non verificabile.
    if fetch.response is None and ctx.home is None:
        return [
            Finding(
                **base,
                status=Status.ERRORE,
                severita=Severity.BASSA,
                dettaglio="security.txt non verificabile.",
                evidenza=fetch.errore or "",
            )
        ]
    r = fetch.response
    valido = (
        r is not None
        and r.status_code == 200
        and r.content_type in ("text/plain", "")
        and "contact:" in r.text.lower()
    )
    if not valido:
        evidenza = (
            f"GET {fetch.url} -> {r.status_code} ({r.content_type or 'senza content-type'})"
            if r is not None
            else (fetch.errore or "")
        )
        return [
            Finding(
                **base,
                status=Status.PROBLEMA,
                severita=Severity.BASSA,
                dettaglio=(
                    "Manca un security.txt valido: chi individua un problema di sicurezza "
                    "non trova un canale ufficiale per segnalarlo all'ente."
                ),
                evidenza=evidenza,
                rimedio=rimedio,
                **rimedi_server,
            )
        ]

    assert r is not None
    campi = _campi(r.text)
    contatti = campi.get("contact", [])
    scadenze = campi.get("expires", [])
    evidenza = f"Contact: {', '.join(contatti)}" + (f" · Expires: {scadenze[0]}" if scadenze else "")
    if not scadenze:
        return [
            Finding(
                **base,
                status=Status.ATTENZIONE,
                severita=Severity.BASSA,
                dettaglio="security.txt presente ma senza il campo obbligatorio Expires.",
                evidenza=evidenza,
                rimedio=rimedio,
            )
        ]
    scadenza = _data(scadenze[0])
    if scadenza is None:
        return [
            Finding(
                **base,
                status=Status.ATTENZIONE,
                severita=Severity.BASSA,
                dettaglio="Il campo Expires di security.txt non e' una data ISO 8601 valida.",
                evidenza=evidenza,
                rimedio=rimedio,
            )
        ]
    if scadenza < datetime.now(timezone.utc):
        return [
            Finding(
                **base,
                status=Status.PROBLEMA,
                severita=Severity.BASSA,
                dettaglio="security.txt e' scaduto: i contatti indicati potrebbero non essere piu' validi.",
                evidenza=evidenza,
                rimedio="Verificare i contatti e aggiornare la data Expires (massimo un anno avanti).",
            )
        ]
    return [
        Finding(
            **base,
            status=Status.OK,
            severita=Severity.BASSA,
            dettaglio="security.txt presente, con contatto e scadenza validi.",
            evidenza=evidenza,
        )
    ]
