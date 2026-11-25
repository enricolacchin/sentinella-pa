"""Riconoscimento del CMS (WordPress, Joomla, Drupal) dalla sola home gia' scaricata.

Nessuna richiesta aggiuntiva: niente sondaggio di /wp-login.php, /administrator,
CHANGELOG o simili. Si leggono soltanto il meta "generator", gli header e i
percorsi delle risorse che la pagina stessa carica.
"""

from __future__ import annotations

import re

from sentinella.core.context import Context
from sentinella.core.models import Finding, Severity, Status

RIF_CMS = "OWASP Top 10 — A06 Vulnerable and Outdated Components"

_RE_GENERATOR = re.compile(r"<meta[^>]+name\s*=\s*[\"']generator[\"'][^>]*>", re.IGNORECASE)
_RE_CONTENT = re.compile(r"content\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE)

# Indizi nel codice HTML (percorsi delle risorse) per ciascun CMS.
_INDIZI: dict[str, tuple[str, ...]] = {
    "WordPress": ("/wp-content/", "/wp-includes/", "wp-json"),
    "Joomla": ("/media/jui/", "/media/system/js/", "/components/com_", "joomla"),
    "Drupal": ("/sites/default/files", "drupal-settings-json", "drupal.settings", "/core/misc/drupal"),
}

_RIMEDI_VERSIONE = {
    "WordPress": (
        "// functions.php del tema child: rimuove il meta generator\n"
        "remove_action('wp_head', 'wp_generator');\n"
        "add_filter('the_generator', '__return_empty_string');"
    ),
}


def _generator(html: str) -> str | None:
    for tag in _RE_GENERATOR.findall(html):
        m = _RE_CONTENT.search(tag)
        if m:
            return m.group(1).strip()
    return None


def controlla(ctx: Context) -> list[Finding]:
    home = ctx.home_valutabile
    if home is None:
        return [
            Finding(
                id="cms.rilevato",
                titolo="CMS in uso",
                status=Status.ERRORE,
                severita=Severity.INFORMATIVA,
                dettaglio=ctx.motivo_home_non_valutabile,
            )
        ]
    html_min = home.text.lower()
    generator = _generator(home.text) or home.header("x-generator") or ""

    cms: str | None = None
    indizi: list[str] = []
    # 1. Il meta generator (o l'header X-Generator) e' l'indizio piu' affidabile.
    for nome in _INDIZI:
        if nome.lower() in generator.lower():
            cms = nome
            indizi.append(f"generator: {generator}")
            break
    # 2. Altrimenti i percorsi tipici delle risorse caricate dalla pagina.
    if cms is None:
        for nome, marcatori in _INDIZI.items():
            trovati = [m for m in marcatori if m in html_min]
            if trovati:
                cms = nome
                indizi.extend(trovati)
                break
    if cms is None and home.header("x-drupal-cache"):
        cms, indizi = "Drupal", ["header X-Drupal-Cache"]

    if cms is None:
        return [
            Finding(
                id="cms.rilevato",
                titolo="CMS in uso",
                status=Status.INFO,
                severita=Severity.INFORMATIVA,
                dettaglio="Nessun CMS tra WordPress, Joomla e Drupal riconosciuto dalla home.",
                evidenza=f"generator: {generator}" if generator else "",
            )
        ]

    risultati = [
        Finding(
            id="cms.rilevato",
            titolo="CMS in uso",
            status=Status.INFO,
            severita=Severity.INFORMATIVA,
            dettaglio=f"Il sito sembra realizzato con {cms}. Va mantenuto aggiornato insieme a temi e plugin/estensioni.",
            evidenza="Indizi: " + ", ".join(indizi[:4]),
            riferimento=RIF_CMS,
        )
    ]
    versione = re.search(r"\d+(?:\.\d+)+", generator) if cms.lower() in generator.lower() else None
    if versione:
        risultati.append(
            Finding(
                id="cms.versione",
                titolo=f"Versione di {cms} esposta",
                status=Status.ATTENZIONE,
                severita=Severity.MEDIA,
                dettaglio=(
                    f"La pagina dichiara pubblicamente la versione {versione.group(0)} di {cms}. "
                    "Se non e' l'ultima, chiunque puo' cercare le vulnerabilita' note per "
                    "quella versione. Lo strumento non verifica se e' aggiornata."
                ),
                evidenza=f"generator: {generator}",
                rimedio=(
                    f"Aggiornare {cms} all'ultima versione supportata e rimuovere il meta "
                    "generator dalla pagina."
                ),
                rimedio_wordpress=_RIMEDI_VERSIONE.get(cms, ""),
                riferimento=RIF_CMS,
            )
        )
    return risultati
