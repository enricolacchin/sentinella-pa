"""Risorse di terze parti caricate dalla home (<script>, <iframe>) e contenuti misti."""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from sentinella.core.context import Context, dominio_registrabile
from sentinella.core.models import Finding, Severity, Status

RIF_TERZE = "Garante Privacy — trasferimenti di dati verso fornitori terzi; MDN — Subresource Integrity"
RIF_MISTI = "MDN Web Docs — Mixed content"


class _Raccoglitore(HTMLParser):
    """Raccoglie gli attributi src di <script> e <iframe> (senza eseguire nulla)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.risorse: list[tuple[str, str, bool]] = []  # (tag, src, ha_integrity)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in ("script", "iframe"):
            return
        attributi = {k.lower(): (v or "") for k, v in attrs}
        src = attributi.get("src", "").strip()
        if src:
            self.risorse.append((tag, src, "integrity" in attributi))


def estrai_risorse(html: str, base_url: str) -> list[tuple[str, str, bool]]:
    """Restituisce (tag, URL assoluto, ha_integrity) per ogni script/iframe con src."""
    parser = _Raccoglitore()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # HTML malformato: si usa quanto raccolto
        pass
    risultato = []
    for tag, src, integrity in parser.risorse:
        assoluto = urljoin(base_url, src)
        if urlsplit(assoluto).scheme in ("http", "https"):
            risultato.append((tag, assoluto, integrity))
    return risultato


def controlla(ctx: Context) -> list[Finding]:
    home = ctx.home_valutabile
    if home is None:
        return [
            Finding(
                id="terze_parti.origini",
                titolo="Risorse di terze parti",
                status=Status.ERRORE,
                severita=Severity.INFORMATIVA,
                dettaglio=ctx.motivo_home_non_valutabile,
            )
        ]
    risorse = estrai_risorse(home.text, home.url)
    dominio_sito = dominio_registrabile(urlsplit(home.url).hostname or ctx.hostname)

    esterne: dict[str, set[str]] = {}
    senza_sri = 0
    for tag, url, integrity in risorse:
        parti = urlsplit(url)
        host = parti.hostname or ""
        if dominio_registrabile(host) == dominio_sito:
            continue
        esterne.setdefault(f"{parti.scheme}://{host}", set()).add(tag)
        if tag == "script" and not integrity:
            senza_sri += 1

    risultati: list[Finding] = []
    if esterne:
        elenco = "\n".join(
            f"{origine} ({', '.join(sorted(tag))})" for origine, tag in sorted(esterne.items())
        )
        nota_sri = (
            f" {senza_sri} script esterni sono caricati senza controllo di integrita' (SRI)."
            if senza_sri
            else ""
        )
        risultati.append(
            Finding(
                id="terze_parti.origini",
                titolo="Risorse di terze parti",
                status=Status.INFO,
                severita=Severity.INFORMATIVA,
                dettaglio=(
                    f"La home carica script o frame da {len(esterne)} origini esterne. Ogni "
                    "fornitore riceve l'indirizzo IP dei visitatori e, se compromesso, puo' "
                    "modificare la pagina. Verificare che siano necessari e coperti da "
                    "nomina/informativa." + nota_sri
                ),
                evidenza=elenco,
                rimedio=(
                    "Ridurre le dipendenze esterne, ospitare localmente le librerie quando "
                    "possibile e aggiungere l'attributo integrity agli script da CDN."
                ),
                riferimento=RIF_TERZE,
            )
        )
    else:
        risultati.append(
            Finding(
                id="terze_parti.origini",
                titolo="Risorse di terze parti",
                status=Status.INFO,
                severita=Severity.INFORMATIVA,
                dettaglio="La home non carica script o frame da origini esterne.",
            )
        )

    if home.url.startswith("https://"):
        misti = sorted({url for _, url, _ in risorse if url.startswith("http://")})
        if misti:
            risultati.append(
                Finding(
                    id="terze_parti.contenuti_misti",
                    titolo="Contenuti misti (script/frame in HTTP)",
                    status=Status.PROBLEMA,
                    severita=Severity.MEDIA,
                    dettaglio=(
                        "La pagina HTTPS carica script o frame in chiaro: i browser li "
                        "bloccano (parti del sito non funzionano) o, se caricati, possono "
                        "essere alterati in transito."
                    ),
                    evidenza="\n".join(misti[:10]),
                    rimedio="Aggiornare i riferimenti a https:// (o percorsi relativi).",
                    rimedio_nginx='add_header Content-Security-Policy "upgrade-insecure-requests" always;',
                    rimedio_apache='Header always set Content-Security-Policy "upgrade-insecure-requests"',
                    rimedio_wordpress="Sostituire gli URL http:// nel database (es. con WP-CLI: wp search-replace 'http://' 'https://').",
                    riferimento=RIF_MISTI,
                )
            )
    return risultati
