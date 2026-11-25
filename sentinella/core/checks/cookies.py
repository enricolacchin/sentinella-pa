"""Cookie impostati dalla home al primo caricamento: flag di sicurezza e nota GDPR."""

from __future__ import annotations

import re
from dataclasses import dataclass

from sentinella.core.context import Context
from sentinella.core.models import Finding, Severity, Status

RIF_COOKIE = "RFC 6265bis; OWASP Session Management Cheat Sheet"
RIF_GARANTE = "Garante Privacy — Linee guida cookie e altri strumenti di tracciamento (10 giugno 2021)"

# Nomi tipici dei cookie di sessione: senza HttpOnly sono piu' esposti a furto via XSS.
_RE_SESSIONE = re.compile(
    r"^(phpsessid|jsessionid|asp\.net_sessionid|aspsessionid.*|sess.*|ssess.*|"
    r"wordpress_logged_in.*|wordpress_sec.*|connect\.sid|laravel_session|.*session.*)$",
    re.IGNORECASE,
)

_RIMEDI_FLAG = dict(
    rimedio_nginx="proxy_cookie_flags ~ secure httponly samesite=lax;  # nginx >= 1.19.3",
    rimedio_apache='Header always edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"',
    rimedio_wordpress=(
        "In php.ini o .user.ini:\n"
        "session.cookie_secure = 1\n"
        "session.cookie_httponly = 1\n"
        "session.cookie_samesite = Lax"
    ),
)


@dataclass
class Cookie:
    nome: str
    secure: bool
    httponly: bool
    samesite: str | None

    @property
    def di_sessione(self) -> bool:
        return bool(_RE_SESSIONE.match(self.nome))


def analizza_set_cookie(header: str) -> Cookie | None:
    """Legge un singolo header Set-Cookie (solo nome e attributi, mai il valore)."""
    parti = [p.strip() for p in header.split(";")]
    if not parti or "=" not in parti[0]:
        return None
    nome = parti[0].split("=", 1)[0].strip()
    attributi = {}
    for p in parti[1:]:
        k, _, v = p.partition("=")
        attributi[k.strip().lower()] = v.strip()
    return Cookie(
        nome=nome,
        secure="secure" in attributi,
        httponly="httponly" in attributi,
        samesite=attributi.get("samesite") or None,
    )


def controlla(ctx: Context) -> list[Finding]:
    home = ctx.home_valutabile
    if home is None:
        return [
            Finding(
                id="cookie.primo_caricamento",
                titolo="Cookie al primo caricamento",
                status=Status.ERRORE,
                severita=Severity.INFORMATIVA,
                dettaglio=ctx.motivo_home_non_valutabile,
            )
        ]
    cookie = [c for c in (analizza_set_cookie(h) for h in home.set_cookies) if c is not None]
    if not cookie:
        return [
            Finding(
                id="cookie.primo_caricamento",
                titolo="Cookie al primo caricamento",
                status=Status.OK,
                severita=Severity.INFORMATIVA,
                dettaglio="La home non imposta cookie lato server al primo caricamento.",
                evidenza="Nessun header Set-Cookie (i cookie impostati via JavaScript non sono osservati).",
            )
        ]

    nomi = ", ".join(sorted({c.nome for c in cookie}))
    risultati = [
        Finding(
            id="cookie.primo_caricamento",
            titolo="Cookie al primo caricamento",
            status=Status.INFO,
            severita=Severity.INFORMATIVA,
            dettaglio=(
                f"La home imposta {len(cookie)} cookie prima di qualsiasi interazione. "
                "Se tra questi ci sono cookie non tecnici (statistica, profilazione), "
                "va verificato che siano installati solo dopo il consenso. Lo strumento "
                "non valuta il banner ne' la natura dei cookie."
            ),
            evidenza=f"Cookie (header Set-Cookie): {nomi}",
            riferimento=RIF_GARANTE,
        )
    ]

    in_https = home.url.startswith("https://")
    senza_secure = [c for c in cookie if not c.secure]
    if in_https and senza_secure:
        risultati.append(
            Finding(
                id="cookie.secure",
                titolo="Cookie senza flag Secure",
                status=Status.PROBLEMA,
                severita=Severity.MEDIA if any(c.di_sessione for c in senza_secure) else Severity.BASSA,
                dettaglio="Alcuni cookie possono essere inviati anche su connessioni non cifrate.",
                evidenza=", ".join(c.nome for c in senza_secure),
                rimedio="Impostare il flag Secure su tutti i cookie di un sito servito in HTTPS.",
                riferimento=RIF_COOKIE,
                **_RIMEDI_FLAG,
            )
        )

    sessione_senza_httponly = [c.nome for c in cookie if c.di_sessione and not c.httponly]
    altri_senza_httponly = [c.nome for c in cookie if not c.di_sessione and not c.httponly]
    if sessione_senza_httponly:
        risultati.append(
            Finding(
                id="cookie.httponly",
                titolo="Cookie di sessione senza flag HttpOnly",
                status=Status.PROBLEMA,
                severita=Severity.MEDIA,
                dettaglio="Cookie di sessione leggibili da JavaScript: in caso di XSS possono essere rubati.",
                evidenza=", ".join(sessione_senza_httponly),
                rimedio="Impostare il flag HttpOnly sui cookie di sessione.",
                riferimento=RIF_COOKIE,
                **_RIMEDI_FLAG,
            )
        )
    elif altri_senza_httponly:
        risultati.append(
            Finding(
                id="cookie.httponly",
                titolo="Cookie senza flag HttpOnly",
                status=Status.ATTENZIONE,
                severita=Severity.BASSA,
                dettaglio="Alcuni cookie sono leggibili da JavaScript: e' corretto solo se lo script ne ha bisogno.",
                evidenza=", ".join(altri_senza_httponly),
                rimedio="Impostare HttpOnly su tutti i cookie che non devono essere letti dagli script.",
                riferimento=RIF_COOKIE,
            )
        )

    senza_samesite = [c.nome for c in cookie if not c.samesite]
    if senza_samesite:
        risultati.append(
            Finding(
                id="cookie.samesite",
                titolo="Cookie senza attributo SameSite",
                status=Status.ATTENZIONE,
                severita=Severity.BASSA,
                dettaglio=(
                    "Senza SameSite il comportamento dipende dal browser; dichiararlo "
                    "esplicitamente riduce il rischio di richieste forgiate (CSRF)."
                ),
                evidenza=", ".join(senza_samesite),
                rimedio="Impostare SameSite=Lax (o Strict) sui cookie.",
                riferimento=RIF_COOKIE,
            )
        )

    if len(risultati) == 1:  # nessun difetto sui flag
        risultati.append(
            Finding(
                id="cookie.flag",
                titolo="Flag di sicurezza dei cookie",
                status=Status.OK,
                severita=Severity.MEDIA,
                dettaglio="Tutti i cookie osservati hanno Secure, HttpOnly e SameSite.",
                evidenza=nomi,
            )
        )
    return risultati
