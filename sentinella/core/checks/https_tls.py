"""HTTPS e TLS: disponibilita', redirect, certificato, versione del protocollo."""

from __future__ import annotations

from sentinella.core.context import Context
from sentinella.core.models import Finding, Severity, Status

RIF_AGID_TLS = (
    "AgID — Raccomandazioni in merito allo standard Transport Layer Security (TLS); "
    "Mozilla Server Side TLS"
)

# Codici OpenSSL X509_V_ERR_* rilevanti.
_SCADUTO = 10
_AUTOFIRMATO = (18, 19)
_CATENA_INCOMPLETA = (20, 21)
_HOSTNAME = 62


def controlla(ctx: Context) -> list[Finding]:
    return [
        _disponibilita_https(ctx),
        _redirect(ctx),
        _certificato(ctx),
        _versione_tls(ctx),
    ]


def _disponibilita_https(ctx: Context) -> Finding:
    base = dict(id="https.disponibile", titolo="Sito raggiungibile in HTTPS")
    if ctx.https.ok and not ctx.https.certificato_non_verificato:
        r = ctx.https.response
        assert r is not None
        dettaglio = "La pagina risponde correttamente su connessione cifrata."
        if r.status_code >= 400:
            dettaglio = (
                f"Il sito risponde su connessione cifrata, ma con codice HTTP {r.status_code}: "
                "i controlli sul contenuto della pagina non sono stati valutati."
            )
        return Finding(
            **base,
            status=Status.OK,
            severita=Severity.CRITICA,
            dettaglio=dettaglio,
            evidenza=f"GET {ctx.url} -> {r.status_code} ({r.url})",
        )
    if ctx.https.ok and ctx.https.certificato_non_verificato:
        return Finding(
            **base,
            status=Status.PROBLEMA,
            severita=Severity.ALTA,
            dettaglio=(
                "Il sito risponde in HTTPS ma il certificato non viene accettato: "
                "i browser mostrano un avviso di sicurezza ai cittadini."
            ),
            evidenza=ctx.https.errore or "",
            rimedio="Installare un certificato valido e la catena completa (vedi esito sul certificato).",
            riferimento=RIF_AGID_TLS,
        )
    if ctx.http.response is not None:
        return Finding(
            **base,
            status=Status.PROBLEMA,
            severita=Severity.CRITICA,
            dettaglio=(
                "Il sito e' raggiungibile solo in chiaro (HTTP): dati e moduli dei "
                "cittadini viaggiano senza cifratura e possono essere letti o alterati."
            ),
            evidenza=ctx.https.errore or "",
            rimedio=(
                "Attivare HTTPS con un certificato gratuito (es. Let's Encrypt) o fornito "
                "dal provider, poi reindirizzare tutto il traffico HTTP verso HTTPS."
            ),
            rimedio_nginx=f"sudo certbot --nginx -d {ctx.hostname}",
            rimedio_apache=f"sudo certbot --apache -d {ctx.hostname}",
            riferimento=RIF_AGID_TLS,
        )
    return Finding(
        **base,
        status=Status.ERRORE,
        severita=Severity.CRITICA,
        dettaglio="Non e' stato possibile raggiungere il sito ne' in HTTPS ne' in HTTP.",
        evidenza="; ".join(e for e in (ctx.https.errore, ctx.http.errore) if e),
    )


def _redirect(ctx: Context) -> Finding:
    base = dict(id="https.redirect", titolo="Reindirizzamento da HTTP a HTTPS")
    info = ctx.http
    catena = " -> ".join([f"{c} {u}" for c, u in info.catena] + [info.url_finale or "?"])
    if info.porta_a_https:
        return Finding(
            **base,
            status=Status.OK,
            severita=Severity.ALTA,
            dettaglio="Chi digita l'indirizzo senza https:// viene portato sulla versione cifrata.",
            evidenza=info.errore or catena,
        )
    if info.http_non_raggiungibile:
        if ctx.https.ok:
            return Finding(
                **base,
                status=Status.INFO,
                severita=Severity.BASSA,
                dettaglio=(
                    "La porta 80 (HTTP) non risponde: il sito e' servito solo in HTTPS. "
                    "E' una scelta sicura, ma chi digita l'indirizzo senza https:// "
                    "potrebbe non raggiungere il sito: valutare un redirect esplicito."
                ),
                evidenza=info.errore or "",
            )
        return Finding(
            **base,
            status=Status.ERRORE,
            severita=Severity.ALTA,
            dettaglio="Versione HTTP non raggiungibile: redirect non verificabile.",
            evidenza=info.errore or "",
        )
    if info.porta_a_https is False:
        return Finding(
            **base,
            status=Status.PROBLEMA,
            severita=Severity.ALTA,
            dettaglio=(
                "La versione in chiaro (http://) del sito non reindirizza a HTTPS: "
                "chi segue un vecchio link o digita l'indirizzo naviga senza cifratura."
            ),
            evidenza=catena,
            rimedio="Configurare un redirect permanente (301) di tutto il traffico HTTP verso HTTPS.",
            rimedio_nginx=(
                "server {\n"
                "    listen 80;\n"
                f"    server_name {ctx.hostname};\n"
                "    return 301 https://$host$request_uri;\n"
                "}"
            ),
            rimedio_apache=(
                "<VirtualHost *:80>\n"
                f"    ServerName {ctx.hostname}\n"
                f"    Redirect permanent / https://{ctx.hostname}/\n"
                "</VirtualHost>"
            ),
            rimedio_wordpress=(
                "Impostare 'Indirizzo WordPress' e 'Indirizzo sito' con https:// in "
                "Impostazioni > Generali, e aggiungere il redirect a livello di server web."
            ),
            riferimento=RIF_AGID_TLS,
        )
    return Finding(
        **base,
        status=Status.ERRORE,
        severita=Severity.ALTA,
        dettaglio="Redirect HTTP -> HTTPS non verificabile.",
        evidenza=info.errore or "",
    )


def _certificato(ctx: Context) -> Finding:
    tls = ctx.tls
    base = dict(id="tls.certificato", titolo="Certificato TLS")
    if tls.certificato_valido is None:
        return Finding(
            **base,
            status=Status.ERRORE,
            severita=Severity.CRITICA,
            dettaglio="Handshake TLS non riuscito: certificato non verificabile.",
            evidenza=tls.errore or "",
        )

    rimedio_rinnovo = dict(
        rimedio=(
            "Rinnovare il certificato e automatizzarne il rinnovo (es. ACME/Let's Encrypt "
            "con rinnovo automatico, oppure promemoria con il fornitore)."
        ),
        rimedio_nginx="sudo certbot renew --nginx && sudo systemctl reload nginx",
        rimedio_apache="sudo certbot renew --apache && sudo systemctl reload apache2",
        riferimento=RIF_AGID_TLS,
    )

    if tls.certificato_valido is False:
        codice = tls.codice_verifica
        evidenza = f"{tls.host}: {tls.errore_verifica} (codice {codice})"
        if codice == _HOSTNAME:
            return Finding(
                **base,
                status=Status.PROBLEMA,
                severita=Severity.CRITICA,
                dettaglio=(
                    f"Il certificato presentato non e' intestato a {tls.host}: i browser "
                    "bloccano la pagina con un avviso di sicurezza."
                ),
                evidenza=evidenza,
                rimedio=f"Emettere un certificato che includa {tls.host} tra i nomi (SAN).",
                riferimento=RIF_AGID_TLS,
            )
        if codice == _SCADUTO:
            return Finding(
                **base,
                status=Status.PROBLEMA,
                severita=Severity.CRITICA,
                dettaglio="Il certificato e' scaduto: i browser bloccano la pagina con un avviso.",
                evidenza=evidenza,
                **rimedio_rinnovo,
            )
        if codice in _CATENA_INCOMPLETA:
            return Finding(
                **base,
                status=Status.ATTENZIONE,
                severita=Severity.ALTA,
                dettaglio=(
                    "Il server non invia la catena completa dei certificati intermedi. "
                    "Alcuni browser la ricostruiscono da soli, ma molti client (app, "
                    "dispositivi, servizi automatici) falliscono la connessione."
                ),
                evidenza=evidenza,
                rimedio="Configurare il server per inviare il certificato insieme agli intermedi (fullchain).",
                rimedio_nginx="ssl_certificate /etc/letsencrypt/live/<dominio>/fullchain.pem;",
                rimedio_apache="SSLCertificateFile /etc/letsencrypt/live/<dominio>/fullchain.pem",
                riferimento=RIF_AGID_TLS,
            )
        dettaglio = (
            "Il certificato e' autofirmato o emesso da un'autorita' non riconosciuta."
            if codice in _AUTOFIRMATO
            else "Il certificato non supera la verifica dei browser."
        )
        return Finding(
            **base,
            status=Status.PROBLEMA,
            severita=Severity.ALTA,
            dettaglio=dettaglio + " I cittadini ricevono un avviso di sicurezza.",
            evidenza=evidenza,
            rimedio="Sostituirlo con un certificato emesso da un'autorita' riconosciuta.",
            riferimento=RIF_AGID_TLS,
        )

    giorni = tls.giorni_alla_scadenza
    evidenza = (
        f"Soggetto: {tls.soggetto or '?'} · Emittente: {tls.emittente or '?'} · "
        f"Scadenza: {tls.scadenza or '?'} ({giorni if giorni is not None else '?'} giorni)"
    )
    if giorni is not None and giorni < 0:
        return Finding(
            **base,
            status=Status.PROBLEMA,
            severita=Severity.CRITICA,
            dettaglio="Il certificato risulta scaduto.",
            evidenza=evidenza,
            **rimedio_rinnovo,
        )
    # Soglie proporzionate alla durata del certificato: un certificato da 6
    # giorni a 4 giorni dalla scadenza e' normale, uno da 1 anno no.
    durata = tls.durata_giorni or 398
    soglia_problema = min(14.0, durata / 4)
    soglia_attenzione = min(30.0, durata / 3)
    if giorni is not None and giorni < soglia_problema:
        return Finding(
            **base,
            status=Status.PROBLEMA,
            severita=Severity.ALTA,
            dettaglio=(
                f"Il certificato scade tra {giorni} giorni (validita' totale {durata} giorni): "
                "il rinnovo automatico potrebbe non funzionare."
            ),
            evidenza=evidenza,
            **rimedio_rinnovo,
        )
    if giorni is not None and giorni < soglia_attenzione:
        return Finding(
            **base,
            status=Status.ATTENZIONE,
            severita=Severity.MEDIA,
            dettaglio=f"Il certificato scade tra {giorni} giorni: verificare che il rinnovo sia pianificato.",
            evidenza=evidenza,
            **rimedio_rinnovo,
        )
    return Finding(
        **base,
        status=Status.OK,
        severita=Severity.CRITICA,
        dettaglio="Certificato valido, intestato correttamente e non in scadenza.",
        evidenza=evidenza,
    )


def _versione_tls(ctx: Context) -> Finding:
    tls = ctx.tls
    base = dict(id="tls.versione", titolo="Versione del protocollo TLS")
    if not tls.handshake_riuscito:
        errore = tls.errore or ""
        if "VERSION" in errore.upper() or "PROTOCOL" in errore.upper():
            return Finding(
                **base,
                status=Status.PROBLEMA,
                severita=Severity.ALTA,
                dettaglio=(
                    "L'handshake con le impostazioni di un client moderno fallisce: il "
                    "server potrebbe supportare solo versioni obsolete di TLS (1.0/1.1)."
                ),
                evidenza=errore,
                rimedio="Abilitare TLS 1.2 e TLS 1.3 e disabilitare SSLv3, TLS 1.0 e TLS 1.1.",
                rimedio_nginx="ssl_protocols TLSv1.2 TLSv1.3;",
                rimedio_apache="SSLProtocol -all +TLSv1.2 +TLSv1.3",
                riferimento=RIF_AGID_TLS,
            )
        return Finding(
            **base,
            status=Status.ERRORE,
            severita=Severity.ALTA,
            dettaglio="Versione TLS non verificabile.",
            evidenza=errore,
        )
    versione = tls.versione or ""
    evidenza = f"Negoziato {versione}" + (f" · cifrario {tls.cifrario}" if tls.cifrario else "")
    if versione in ("TLSv1.3", "TLSv1.2"):
        return Finding(
            **base,
            status=Status.OK,
            severita=Severity.ALTA,
            dettaglio=f"La connessione usa {versione}, versione considerata sicura.",
            evidenza=evidenza,
        )
    return Finding(
        **base,
        status=Status.PROBLEMA,
        severita=Severity.ALTA,
        dettaglio=f"La connessione usa {versione}, versione obsoleta e non piu' considerata sicura.",
        evidenza=evidenza,
        rimedio="Abilitare TLS 1.2 e TLS 1.3 e disabilitare le versioni precedenti.",
        rimedio_nginx="ssl_protocols TLSv1.2 TLSv1.3;",
        rimedio_apache="SSLProtocol -all +TLSv1.2 +TLSv1.3",
        riferimento=RIF_AGID_TLS,
    )
