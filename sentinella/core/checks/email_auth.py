"""Autenticazione della posta del dominio: SPF, DMARC, DKIM (parziale).

Sono semplici query DNS pubbliche (record TXT), le stesse che fa qualsiasi
server di posta che riceve un messaggio dal dominio dell'ente.
"""

from __future__ import annotations

import re

from sentinella.core.context import Context, DnsError
from sentinella.core.models import Finding, Severity, Status

RIF_EMAIL = "RFC 7208 (SPF), RFC 7489 (DMARC), RFC 6376 (DKIM); AgID — Misure minime di sicurezza ICT per le PA"

# Selettori DKIM piu' diffusi (Microsoft 365, Google Workspace, default di molti MTA).
SELETTORI_DKIM = ("default", "selector1", "selector2", "google")


def controlla(ctx: Context) -> list[Finding]:
    dominio = ctx.dominio
    return [_spf(ctx, dominio), _dmarc(ctx, dominio), _dkim(ctx, dominio)]


def _ha_mx(ctx: Context, dominio: str) -> bool | None:
    try:
        return bool(ctx.dns.query(dominio, "MX"))
    except DnsError:
        return None


def _spf(ctx: Context, dominio: str) -> Finding:
    base = dict(id="email.spf", titolo=f"SPF del dominio {dominio}", riferimento=RIF_EMAIL)
    try:
        txt = ctx.dns.query(dominio, "TXT")
    except DnsError as exc:
        return Finding(
            **base,
            status=Status.ERRORE,
            severita=Severity.ALTA,
            dettaglio="Interrogazione DNS non riuscita: SPF non verificabile.",
            evidenza=str(exc),
        )
    record = [t for t in txt if t.strip().lower().startswith("v=spf1")]

    if not record:
        ha_mx = _ha_mx(ctx, dominio)
        record_suggerito = (
            "v=spf1 -all" if ha_mx is False else "v=spf1 include:<provider-di-posta> -all"
        )
        nota_mx = (
            " Il dominio non riceve posta (nessun MX): basta un record che vieti ogni invio."
            if ha_mx is False
            else ""
        )
        return Finding(
            **base,
            status=Status.PROBLEMA,
            severita=Severity.ALTA,
            dettaglio=(
                "Il dominio non pubblica un record SPF: chiunque puo' inviare email che "
                "sembrano provenire dall'ente (phishing verso i cittadini)." + nota_mx
            ),
            rimedio=(
                f"Pubblicare un record TXT su {dominio} che elenchi i server autorizzati "
                "all'invio. Record DNS di esempio:\n"
                f'{dominio}.  IN  TXT  "{record_suggerito}"'
            ),
        )
    if len(record) > 1:
        return Finding(
            **base,
            status=Status.PROBLEMA,
            severita=Severity.MEDIA,
            dettaglio=(
                "Sono pubblicati piu' record SPF: lo standard lo vieta e i server "
                "destinatari considerano la configurazione non valida."
            ),
            evidenza=" | ".join(record),
            rimedio="Unire i record in un unico TXT v=spf1 ... con un solo meccanismo finale.",
        )
    spf = record[0]
    termini = spf.lower().split()
    finale = next((t for t in termini if re.fullmatch(r"[+\-~?]?all", t)), None)
    ha_redirect = any(t.startswith("redirect=") for t in termini)

    if finale in ("all", "+all"):
        return Finding(
            **base,
            status=Status.PROBLEMA,
            severita=Severity.ALTA,
            dettaglio="Il record SPF termina con '+all': autorizza qualunque server del mondo a inviare posta per l'ente.",
            evidenza=spf,
            rimedio="Sostituire '+all' con '-all' (o '~all' durante la transizione).",
        )
    if finale == "?all":
        return Finding(
            **base,
            status=Status.ATTENZIONE,
            severita=Severity.MEDIA,
            dettaglio="Il record SPF termina con '?all' (neutro): non indica ai destinatari di rifiutare i mittenti falsi.",
            evidenza=spf,
            rimedio="Sostituire '?all' con '~all' o, meglio, '-all'.",
        )
    if finale is None and not ha_redirect:
        return Finding(
            **base,
            status=Status.ATTENZIONE,
            severita=Severity.MEDIA,
            dettaglio="Il record SPF non ha un meccanismo finale 'all': il trattamento dei mittenti non elencati resta indefinito.",
            evidenza=spf,
            rimedio="Aggiungere '-all' (o '~all') in fondo al record.",
        )
    return Finding(
        **base,
        status=Status.OK,
        severita=Severity.ALTA,
        dettaglio="Record SPF presente e restrittivo.",
        evidenza=spf,
    )


def _tag_dmarc(record: str) -> dict[str, str]:
    tag = {}
    for parte in record.split(";"):
        if "=" in parte:
            k, v = parte.split("=", 1)
            tag[k.strip().lower()] = v.strip()
    return tag


def _dmarc(ctx: Context, dominio: str) -> Finding:
    nome = f"_dmarc.{dominio}"
    base = dict(id="email.dmarc", titolo=f"DMARC del dominio {dominio}", riferimento=RIF_EMAIL)
    rimedio_record = f'{nome}.  IN  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@{dominio}"'
    try:
        txt = ctx.dns.query(nome, "TXT")
    except DnsError as exc:
        return Finding(
            **base,
            status=Status.ERRORE,
            severita=Severity.ALTA,
            dettaglio="Interrogazione DNS non riuscita: DMARC non verificabile.",
            evidenza=str(exc),
        )
    record = [t for t in txt if t.strip().lower().startswith("v=dmarc1")]
    if not record:
        return Finding(
            **base,
            status=Status.PROBLEMA,
            severita=Severity.ALTA,
            dettaglio=(
                "Il dominio non pubblica una policy DMARC: i server di posta non sanno "
                "come trattare le email false a nome dell'ente e l'ente non riceve "
                "segnalazioni sugli abusi."
            ),
            rimedio=(
                "Pubblicare un record DMARC iniziando con p=none e un indirizzo rua per "
                "raccogliere i report, poi passare a p=quarantine e infine p=reject. "
                "Record DNS di esempio:\n" + rimedio_record
            ),
        )
    tag = _tag_dmarc(record[0])
    policy = tag.get("p", "").lower()
    pct = tag.get("pct", "100")
    if policy not in ("quarantine", "reject"):
        return Finding(
            **base,
            status=Status.ATTENZIONE,
            severita=Severity.ALTA,
            dettaglio=(
                f"La policy DMARC e' '{policy or 'assente'}': le email false vengono solo "
                "monitorate, non bloccate."
            ),
            evidenza=record[0],
            rimedio=(
                "Dopo aver analizzato i report, portare la policy a p=quarantine e poi "
                "p=reject. Record DNS di esempio:\n" + rimedio_record
            ),
        )
    if pct != "100":
        return Finding(
            **base,
            status=Status.ATTENZIONE,
            severita=Severity.BASSA,
            dettaglio=f"Policy DMARC '{policy}' applicata solo al {pct}% dei messaggi.",
            evidenza=record[0],
            rimedio="Portare pct a 100 (o rimuovere il tag).",
        )
    return Finding(
        **base,
        status=Status.OK,
        severita=Severity.ALTA,
        dettaglio=f"Policy DMARC '{policy}' attiva.",
        evidenza=record[0],
    )


def _dkim(ctx: Context, dominio: str) -> Finding:
    base = dict(
        id="email.dkim",
        titolo=f"DKIM del dominio {dominio} (controllo parziale)",
        riferimento=RIF_EMAIL,
    )
    trovati: list[str] = []
    errori: list[str] = []
    for selettore in SELETTORI_DKIM:
        nome = f"{selettore}._domainkey.{dominio}"
        try:
            txt = ctx.dns.query(nome, "TXT")
        except DnsError as exc:
            errori.append(str(exc))
            continue
        if any("v=dkim1" in t.lower() or "p=" in t.lower() for t in txt):
            trovati.append(selettore)
    if trovati:
        return Finding(
            **base,
            status=Status.OK,
            severita=Severity.INFORMATIVA,
            dettaglio="Trovata almeno una chiave DKIM pubblicata.",
            evidenza="Selettori trovati: " + ", ".join(trovati),
        )
    if errori and len(errori) == len(SELETTORI_DKIM):
        return Finding(
            **base,
            status=Status.ERRORE,
            severita=Severity.INFORMATIVA,
            dettaglio="Interrogazioni DNS non riuscite: DKIM non verificabile.",
            evidenza="; ".join(errori[:2]),
        )
    return Finding(
        **base,
        status=Status.INFO,
        severita=Severity.INFORMATIVA,
        dettaglio=(
            "Nessuna chiave DKIM trovata tra i selettori piu' comuni ("
            + ", ".join(SELETTORI_DKIM)
            + "). Il nome del selettore non e' pubblico, quindi l'assenza non e' "
            "dimostrata: va verificato con chi gestisce la posta dell'ente."
        ),
        rimedio="Verificare che il servizio di posta firmi i messaggi con DKIM e che la chiave sia pubblicata nel DNS.",
    )
