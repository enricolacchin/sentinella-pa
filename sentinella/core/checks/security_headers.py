"""Header di sicurezza HTTP della pagina principale."""

from __future__ import annotations

import re

from sentinella.core.context import Context, HttpResponse
from sentinella.core.models import Finding, Severity, Status

RIF_OWASP = "OWASP Secure Headers Project; MDN Web Docs — HTTP headers"

# 180 giorni: durata minima consigliata per HSTS.
HSTS_MIN_SECONDI = 15_552_000


def _wp_header(nome: str, valore: str) -> str:
    """Snippet per functions.php (o plugin dedicato) che aggiunge un header."""
    return (
        "// functions.php del tema child, oppure un plugin di header di sicurezza\n"
        "add_action('send_headers', function () {\n"
        f"    header('{nome}: {valore}');\n"
        "});"
    )


def _rimedi(nome: str, valore: str) -> dict[str, str]:
    return dict(
        rimedio_nginx=f'add_header {nome} "{valore}" always;',
        rimedio_apache=f'Header always set {nome} "{valore}"',
        rimedio_wordpress=_wp_header(nome, valore),
    )


def controlla(ctx: Context) -> list[Finding]:
    home = ctx.home_valutabile
    if home is None:
        return [
            Finding(
                id="header.non_verificabili",
                titolo="Header di sicurezza",
                status=Status.ERRORE,
                severita=Severity.MEDIA,
                dettaglio=ctx.motivo_home_non_valutabile,
            )
        ]
    in_https = home.url.startswith("https://")
    risultati = [
        _hsts(home, in_https),
        _csp(home),
        _xcto(home),
        _frame(home),
        _referrer(home),
        _permissions(home),
    ]
    versioni = _versioni_esposte(home)
    if versioni is not None:
        risultati.append(versioni)
    return risultati


def _hsts(home: HttpResponse, in_https: bool) -> Finding:
    base = dict(
        id="header.hsts",
        titolo="Strict-Transport-Security (HSTS)",
        riferimento="RFC 6797; " + RIF_OWASP,
        **_rimedi("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    )
    rimedio = (
        "Inviare l'header Strict-Transport-Security con max-age di almeno un anno, "
        "dopo aver verificato che tutti i sottodomini funzionino in HTTPS."
    )
    if not in_https:
        return Finding(
            **base,
            status=Status.ERRORE,
            severita=Severity.MEDIA,
            dettaglio="Pagina non servita in HTTPS: HSTS non applicabile.",
        )
    valore = home.header("strict-transport-security")
    if not valore:
        return Finding(
            **base,
            status=Status.PROBLEMA,
            severita=Severity.MEDIA,
            dettaglio=(
                "Manca HSTS: il browser non e' istruito a usare sempre HTTPS, quindi il "
                "primo accesso in chiaro puo' essere intercettato (attacco di downgrade)."
            ),
            rimedio=rimedio,
        )
    m = re.search(r"max-age\s*=\s*\"?(\d+)", valore, re.IGNORECASE)
    max_age = int(m.group(1)) if m else 0
    if max_age < HSTS_MIN_SECONDI:
        return Finding(
            **base,
            status=Status.ATTENZIONE,
            severita=Severity.MEDIA,
            dettaglio=f"HSTS presente ma con durata breve (max-age={max_age} secondi, consigliati almeno 180 giorni).",
            evidenza=f"Strict-Transport-Security: {valore}",
            rimedio=rimedio,
        )
    return Finding(
        **base,
        status=Status.OK,
        severita=Severity.MEDIA,
        dettaglio="HSTS presente con durata adeguata.",
        evidenza=f"Strict-Transport-Security: {valore}",
    )


def _csp(home: HttpResponse) -> Finding:
    valore_tipo = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
    base = dict(
        id="header.csp",
        titolo="Content-Security-Policy (CSP)",
        riferimento="W3C Content Security Policy Level 3; " + RIF_OWASP,
        **_rimedi("Content-Security-Policy", valore_tipo),
    )
    rimedio = (
        "Definire una Content-Security-Policy che elenchi le origini consentite per "
        "script, stili e frame. Conviene partire in modalita' di sola osservazione "
        "(Content-Security-Policy-Report-Only) per non rompere il sito, poi attivarla."
    )
    valore = home.header("content-security-policy")
    if not valore:
        solo_report = home.header("content-security-policy-report-only")
        if solo_report:
            return Finding(
                **base,
                status=Status.ATTENZIONE,
                severita=Severity.MEDIA,
                dettaglio="CSP presente solo in modalita' di osservazione (Report-Only): non protegge ancora.",
                evidenza=f"Content-Security-Policy-Report-Only: {solo_report[:300]}",
                rimedio=rimedio,
            )
        return Finding(
            **base,
            status=Status.PROBLEMA,
            severita=Severity.MEDIA,
            dettaglio=(
                "Manca una Content-Security-Policy: in caso di vulnerabilita' XSS o di "
                "compromissione di uno script esterno, il browser non ha limiti su cosa eseguire."
            ),
            rimedio=rimedio,
        )
    # Le sorgenti degli script sono in script-src, o in default-src se manca.
    direttive: dict[str, list[str]] = {}
    for parte in valore.split(";"):
        token = parte.strip().lower().split()
        if token:
            direttive.setdefault(token[0], token[1:])
    sorgenti = direttive.get("script-src", direttive.get("default-src", []))
    # Con nonce/hash i browser moderni ignorano 'unsafe-inline'.
    con_nonce = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in sorgenti)
    debolezze = [
        token
        for token in ("'unsafe-inline'", "'unsafe-eval'")
        if token in sorgenti and not (token == "'unsafe-inline'" and con_nonce)
    ]
    if debolezze:
        return Finding(
            **base,
            status=Status.ATTENZIONE,
            severita=Severity.BASSA,
            dettaglio=(
                "CSP presente ma permissiva (" + ", ".join(debolezze) + "): "
                "riduce solo in parte il rischio di XSS."
            ),
            evidenza=f"Content-Security-Policy: {valore[:300]}",
            rimedio="Sostituire gli script inline con file esterni o nonce/hash, poi rimuovere 'unsafe-inline'/'unsafe-eval'.",
        )
    return Finding(
        **base,
        status=Status.OK,
        severita=Severity.MEDIA,
        dettaglio="Content-Security-Policy presente.",
        evidenza=f"Content-Security-Policy: {valore[:300]}",
    )


def _xcto(home: HttpResponse) -> Finding:
    base = dict(
        id="header.xcto",
        titolo="X-Content-Type-Options",
        riferimento=RIF_OWASP,
        **_rimedi("X-Content-Type-Options", "nosniff"),
    )
    valore = home.header("x-content-type-options")
    if valore and valore.strip().lower() == "nosniff":
        return Finding(
            **base,
            status=Status.OK,
            severita=Severity.BASSA,
            dettaglio="Il browser non tenta di indovinare il tipo dei file.",
            evidenza=f"X-Content-Type-Options: {valore}",
        )
    return Finding(
        **base,
        status=Status.PROBLEMA,
        severita=Severity.BASSA,
        dettaglio="Manca 'X-Content-Type-Options: nosniff': il browser puo' interpretare file caricati come script.",
        evidenza=f"X-Content-Type-Options: {valore}" if valore else "",
        rimedio="Inviare l'header X-Content-Type-Options: nosniff.",
    )


def _frame(home: HttpResponse) -> Finding:
    base = dict(
        id="header.frame",
        titolo="Protezione da clickjacking (X-Frame-Options / frame-ancestors)",
        riferimento=RIF_OWASP,
        **_rimedi("X-Frame-Options", "SAMEORIGIN"),
    )
    xfo = home.header("x-frame-options")
    csp = home.header("content-security-policy") or ""
    if "frame-ancestors" in csp.lower():
        direttiva = re.search(r"frame-ancestors[^;]*", csp, re.IGNORECASE)
        return Finding(
            **base,
            status=Status.OK,
            severita=Severity.MEDIA,
            dettaglio="La CSP limita chi puo' incorporare il sito in un frame.",
            evidenza=direttiva.group(0) if direttiva else "frame-ancestors",
        )
    # Un header duplicato arriva unito da virgole ("SAMEORIGIN, SAMEORIGIN"): i
    # browser lo applicano se tutti i valori sono DENY o SAMEORIGIN.
    valori_xfo = {v.strip().upper() for v in (xfo or "").split(",") if v.strip()}
    if valori_xfo and valori_xfo <= {"DENY", "SAMEORIGIN"}:
        return Finding(
            **base,
            status=Status.OK,
            severita=Severity.MEDIA,
            dettaglio="Il sito non puo' essere incorporato in frame di altri domini.",
            evidenza=f"X-Frame-Options: {xfo}",
        )
    return Finding(
        **base,
        status=Status.PROBLEMA,
        severita=Severity.MEDIA,
        dettaglio=(
            "Il sito puo' essere incorporato in pagine di terzi: un malintenzionato puo' "
            "sovrapporre elementi ingannevoli e indurre i cittadini a cliccare (clickjacking)."
        ),
        evidenza=f"X-Frame-Options: {xfo}" if xfo else "",
        rimedio="Inviare X-Frame-Options: SAMEORIGIN oppure la direttiva CSP frame-ancestors 'self'.",
    )


def _referrer(home: HttpResponse) -> Finding:
    base = dict(
        id="header.referrer",
        titolo="Referrer-Policy",
        riferimento=RIF_OWASP,
        **_rimedi("Referrer-Policy", "strict-origin-when-cross-origin"),
    )
    valore = home.header("referrer-policy")
    deboli = {"unsafe-url", "no-referrer-when-downgrade"}
    # Con piu' valori separati da virgola vale l'ultimo riconosciuto dal browser.
    if valore and valore.strip().lower().split(",")[-1].strip() not in deboli:
        return Finding(
            **base,
            status=Status.OK,
            severita=Severity.BASSA,
            dettaglio="Gli indirizzi delle pagine visitate non vengono passati per intero ai siti esterni.",
            evidenza=f"Referrer-Policy: {valore}",
        )
    return Finding(
        **base,
        status=Status.PROBLEMA,
        severita=Severity.BASSA,
        dettaglio=(
            "Referrer-Policy assente o permissiva: l'indirizzo completo delle pagine "
            "visitate (che puo' contenere parametri personali) viene inviato ai siti esterni."
        ),
        evidenza=f"Referrer-Policy: {valore}" if valore else "",
        rimedio="Inviare Referrer-Policy: strict-origin-when-cross-origin.",
    )


def _permissions(home: HttpResponse) -> Finding:
    base = dict(
        id="header.permissions",
        titolo="Permissions-Policy",
        riferimento="W3C Permissions Policy; " + RIF_OWASP,
        **_rimedi("Permissions-Policy", "geolocation=(), camera=(), microphone=()"),
    )
    valore = home.header("permissions-policy") or home.header("feature-policy")
    if valore:
        return Finding(
            **base,
            status=Status.OK,
            severita=Severity.BASSA,
            dettaglio="Il sito limita l'accesso a funzioni sensibili del browser.",
            evidenza=f"Permissions-Policy: {valore[:200]}",
        )
    return Finding(
        **base,
        status=Status.PROBLEMA,
        severita=Severity.BASSA,
        dettaglio=(
            "Manca Permissions-Policy: script di terze parti incorporati potrebbero "
            "richiedere fotocamera, microfono o posizione."
        ),
        rimedio="Inviare Permissions-Policy disabilitando le funzioni non usate (geolocation, camera, microphone...).",
    )


_RE_VERSIONE = re.compile(r"\d+\.\d+")


def _versioni_esposte(home: HttpResponse) -> Finding | None:
    esposti = []
    for nome in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        valore = home.header(nome)
        if valore and _RE_VERSIONE.search(valore):
            esposti.append(f"{nome}: {valore}")
    if not esposti:
        return None
    return Finding(
        id="header.versioni_esposte",
        titolo="Versioni del software esposte negli header",
        status=Status.ATTENZIONE,
        severita=Severity.BASSA,
        dettaglio=(
            "Gli header rivelano il software usato e la sua versione: facilita chi cerca "
            "installazioni non aggiornate a cui applicare vulnerabilita' note."
        ),
        evidenza="; ".join(esposti),
        rimedio="Nascondere la versione del server web e rimuovere X-Powered-By. Verificare che il software sia aggiornato.",
        rimedio_nginx="server_tokens off;\nfastcgi_hide_header X-Powered-By;  # o proxy_hide_header",
        rimedio_apache="ServerTokens Prod\nServerSignature Off\nHeader always unset X-Powered-By",
        rimedio_wordpress="In php.ini impostare expose_php = Off.",
        riferimento=RIF_OWASP,
    )
