"""Test dei controlli su Context finti (fixtures), senza rete."""

from __future__ import annotations

import pytest

from conftest import DNS_BUONO, DOMINIO, HEADER_BUONI, HOST, crea_contesto, leggi_fixture, risposta, tls_buono
from sentinella.core import analizza_contesto
from sentinella.core.checks import REGISTRO, cms, cookies, dnssec, email_auth, https_tls, security_headers, security_txt, third_party
from sentinella.core.context import RedirectInfo
from sentinella.core.models import Severity, Status


def per_id(findings, id_):
    trovati = [f for f in findings if f.id == id_]
    assert trovati, f"esito {id_} assente in {[f.id for f in findings]}"
    return trovati[0]


# ---------------------------------------------------------------- sito ben configurato


def test_sito_ben_configurato_ha_voto_a(ctx_buono):
    findings = analizza_contesto(ctx_buono)
    problemi = [f for f in findings if f.status in (Status.PROBLEMA, Status.ATTENZIONE)]
    assert problemi == []
    assert all(f.categoria for f in findings)


def test_ogni_controllo_registrato_produce_esiti(ctx_buono):
    for nome, controllo in REGISTRO:
        assert controllo(ctx_buono), nome


def test_un_controllo_che_esplode_non_blocca_gli_altri(ctx_buono, monkeypatch):
    def rotto(ctx):
        raise RuntimeError("bug")

    monkeypatch.setattr("sentinella.core.REGISTRO", [("rotto", rotto), REGISTRO[0]])
    findings = analizza_contesto(ctx_buono)
    assert findings[0].id == "rotto.errore_interno"
    assert findings[0].status == Status.ERRORE
    assert any(f.categoria == "https_tls" for f in findings)


# ---------------------------------------------------------------- https_tls


def test_https_irraggiungibile_ma_http_si():
    home_http = risposta(url=f"http://{HOST}/", headers={"content-type": "text/html"}, text="<html></html>")
    ctx = crea_contesto(
        https_errore="ConnectionError: refused",
        http=RedirectInfo(url_iniziale=f"http://{HOST}/", url_finale=f"http://{HOST}/", porta_a_https=False, response=home_http),
        tls=tls_buono(versione=None, certificato_valido=None, errore="Connessione alla porta 443 non riuscita"),
    )
    f = per_id(https_tls.controlla(ctx), "https.disponibile")
    assert (f.status, f.severita) == (Status.PROBLEMA, Severity.CRITICA)
    assert ctx.home is home_http  # i controlli sul contenuto usano la pagina in chiaro


def test_sito_del_tutto_irraggiungibile_e_non_verificabile():
    ctx = crea_contesto(
        https_errore="ConnectionError",
        http=RedirectInfo(url_iniziale=f"http://{HOST}/", http_non_raggiungibile=True, errore="ConnectionError"),
        tls=tls_buono(versione=None, certificato_valido=None, errore="rete"),
        security_txt_errore="ConnectionError",
    )
    findings = analizza_contesto(ctx)
    assert per_id(findings, "https.disponibile").status == Status.ERRORE
    assert per_id(findings, "tls.certificato").status == Status.ERRORE
    assert per_id(findings, "security_txt").status == Status.ERRORE
    assert per_id(findings, "header.non_verificabili").status == Status.ERRORE


def test_manca_redirect_http_https():
    ctx = crea_contesto(http=RedirectInfo(url_iniziale=f"http://{HOST}/", url_finale=f"http://{HOST}/", porta_a_https=False))
    f = per_id(https_tls.controlla(ctx), "https.redirect")
    assert (f.status, f.severita) == (Status.PROBLEMA, Severity.ALTA)
    assert "return 301" in f.rimedio_nginx


def test_porta_80_chiusa_e_solo_informativa():
    ctx = crea_contesto(http=RedirectInfo(url_iniziale=f"http://{HOST}/", http_non_raggiungibile=True))
    assert per_id(https_tls.controlla(ctx), "https.redirect").status == Status.INFO


@pytest.mark.parametrize(
    "codice, status, severita",
    [
        (62, Status.PROBLEMA, Severity.CRITICA),   # hostname errato
        (10, Status.PROBLEMA, Severity.CRITICA),   # scaduto
        (18, Status.PROBLEMA, Severity.ALTA),      # autofirmato
        (20, Status.ATTENZIONE, Severity.ALTA),    # catena incompleta
    ],
)
def test_certificato_non_valido(codice, status, severita):
    ctx = crea_contesto(
        certificato_non_verificato=True,
        tls=tls_buono(certificato_valido=False, codice_verifica=codice, errore_verifica="errore"),
    )
    f = per_id(https_tls.controlla(ctx), "tls.certificato")
    assert (f.status, f.severita) == (status, severita)


@pytest.mark.parametrize(
    "giorni, durata, status",
    [
        (5, 365, Status.PROBLEMA),
        (20, 365, Status.ATTENZIONE),
        (60, 365, Status.OK),
        (4, 6, Status.OK),          # certificato a vita breve: normale
        (1, 6, Status.PROBLEMA),
        (-1, 90, Status.PROBLEMA),
    ],
)
def test_scadenza_certificato_proporzionata(giorni, durata, status):
    ctx = crea_contesto(tls=tls_buono(giorni_alla_scadenza=giorni, durata_giorni=durata))
    assert per_id(https_tls.controlla(ctx), "tls.certificato").status == status


@pytest.mark.parametrize("versione, status", [("TLSv1.3", Status.OK), ("TLSv1.2", Status.OK), ("TLSv1.1", Status.PROBLEMA), ("TLSv1", Status.PROBLEMA)])
def test_versione_tls(versione, status):
    ctx = crea_contesto(tls=tls_buono(versione=versione))
    assert per_id(https_tls.controlla(ctx), "tls.versione").status == status


def test_handshake_fallito_per_protocollo_obsoleto():
    ctx = crea_contesto(tls=tls_buono(versione=None, certificato_valido=None, errore="Handshake TLS fallito: [SSL: UNSUPPORTED_PROTOCOL]"))
    assert per_id(https_tls.controlla(ctx), "tls.versione").status == Status.PROBLEMA


# ---------------------------------------------------------------- security_headers


def test_header_assenti():
    ctx = crea_contesto(home=risposta(headers={"content-type": "text/html"}))
    findings = security_headers.controlla(ctx)
    for id_ in ("header.hsts", "header.csp", "header.xcto", "header.frame", "header.referrer", "header.permissions"):
        assert per_id(findings, id_).status == Status.PROBLEMA, id_
    assert "add_header" in per_id(findings, "header.hsts").rimedio_nginx
    assert "Header always set" in per_id(findings, "header.hsts").rimedio_apache
    assert "send_headers" in per_id(findings, "header.hsts").rimedio_wordpress


def test_hsts_troppo_breve():
    ctx = crea_contesto(home=risposta(headers={**HEADER_BUONI, "strict-transport-security": "max-age=300"}))
    assert per_id(security_headers.controlla(ctx), "header.hsts").status == Status.ATTENZIONE


def test_csp_permissiva_e_nonce():
    debole = {**HEADER_BUONI, "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"}
    ctx = crea_contesto(home=risposta(headers=debole))
    assert per_id(security_headers.controlla(ctx), "header.csp").status == Status.ATTENZIONE

    con_nonce = {**HEADER_BUONI, "content-security-policy": "script-src 'nonce-abc' 'unsafe-inline'"}
    ctx = crea_contesto(home=risposta(headers=con_nonce))
    assert per_id(security_headers.controlla(ctx), "header.csp").status == Status.OK


def test_csp_solo_report_only():
    h = {k: v for k, v in HEADER_BUONI.items() if k != "content-security-policy"}
    h["content-security-policy-report-only"] = "default-src 'self'"
    ctx = crea_contesto(home=risposta(headers=h))
    assert per_id(security_headers.controlla(ctx), "header.csp").status == Status.ATTENZIONE


def test_frame_ancestors_sostituisce_x_frame_options():
    h = {k: v for k, v in HEADER_BUONI.items() if k != "x-frame-options"}
    ctx = crea_contesto(home=risposta(headers=h))
    assert per_id(security_headers.controlla(ctx), "header.frame").status == Status.OK


def test_versioni_esposte():
    h = {**HEADER_BUONI, "server": "Apache/2.4.29 (Ubuntu)", "x-powered-by": "PHP/7.2.24"}
    f = per_id(security_headers.controlla(crea_contesto(home=risposta(headers=h))), "header.versioni_esposte")
    assert f.status == Status.ATTENZIONE
    assert "Apache/2.4.29" in f.evidenza and "PHP/7.2.24" in f.evidenza


def test_server_senza_versione_non_segnalato(ctx_buono):
    assert not [f for f in security_headers.controlla(ctx_buono) if f.id == "header.versioni_esposte"]


# ---------------------------------------------------------------- email_auth


def test_spf_assente_senza_mx_suggerisce_meno_all():
    record = {k: v for k, v in DNS_BUONO.items() if k not in ((DOMINIO, "TXT"), (DOMINIO, "MX"))}
    f = per_id(email_auth.controlla(crea_contesto(dns=record)), "email.spf")
    assert (f.status, f.severita) == (Status.PROBLEMA, Severity.ALTA)
    assert '"v=spf1 -all"' in f.rimedio


@pytest.mark.parametrize(
    "spf, status",
    [
        ("v=spf1 +all", Status.PROBLEMA),
        ("v=spf1 a mx all", Status.PROBLEMA),
        ("v=spf1 mx ?all", Status.ATTENZIONE),
        ("v=spf1 mx", Status.ATTENZIONE),
        ("v=spf1 redirect=_spf.esempio.example", Status.OK),
        ("v=spf1 mx ~all", Status.OK),
        ("v=spf1 mx -all", Status.OK),
    ],
)
def test_varianti_spf(spf, status):
    record = {**DNS_BUONO, (DOMINIO, "TXT"): ["google-site-verification=abc", spf]}
    assert per_id(email_auth.controlla(crea_contesto(dns=record)), "email.spf").status == status


def test_spf_doppio():
    record = {**DNS_BUONO, (DOMINIO, "TXT"): ["v=spf1 mx -all", "v=spf1 a -all"]}
    assert per_id(email_auth.controlla(crea_contesto(dns=record)), "email.spf").status == Status.PROBLEMA


@pytest.mark.parametrize(
    "dmarc, status",
    [
        (None, Status.PROBLEMA),
        ("v=DMARC1; p=none; rua=mailto:x@esempio.example", Status.ATTENZIONE),
        ("v=DMARC1; p=quarantine; pct=50", Status.ATTENZIONE),
        ("v=DMARC1; p=quarantine", Status.OK),
        ("v=DMARC1;p=reject", Status.OK),
    ],
)
def test_varianti_dmarc(dmarc, status):
    record = dict(DNS_BUONO)
    if dmarc is None:
        record.pop((f"_dmarc.{DOMINIO}", "TXT"))
    else:
        record[(f"_dmarc.{DOMINIO}", "TXT")] = [dmarc]
    assert per_id(email_auth.controlla(crea_contesto(dns=record)), "email.dmarc").status == status


def test_dkim_non_trovato_e_solo_informativo():
    record = {k: v for k, v in DNS_BUONO.items() if "_domainkey" not in k[0]}
    f = per_id(email_auth.controlla(crea_contesto(dns=record)), "email.dkim")
    assert f.status == Status.INFO and f.peso == 0


def test_errori_dns_diventano_non_verificabili():
    guasti = {DOMINIO, f"_dmarc.{DOMINIO}"} | {f"{s}._domainkey.{DOMINIO}" for s in email_auth.SELETTORI_DKIM}
    findings = email_auth.controlla(crea_contesto(dns_guasti=guasti))
    assert {f.status for f in findings} == {Status.ERRORE}


def test_email_usa_il_dominio_registrabile(ctx_buono):
    email_auth.controlla(ctx_buono)
    nomi = {nome for nome, _ in ctx_buono.dns.interrogazioni}
    assert DOMINIO in nomi and f"_dmarc.{DOMINIO}" in nomi
    assert HOST not in nomi


# ---------------------------------------------------------------- dnssec


def test_dnssec_varianti():
    assert dnssec.controlla(crea_contesto())[0].status == Status.OK
    senza_ds = {k: v for k, v in DNS_BUONO.items() if k != (DOMINIO, "DS")}
    assert dnssec.controlla(crea_contesto(dns=senza_ds))[0].status == Status.ATTENZIONE
    assert dnssec.controlla(crea_contesto(dns={}))[0].status == Status.PROBLEMA
    assert dnssec.controlla(crea_contesto(dns_guasti={DOMINIO}))[0].status == Status.ERRORE


# ---------------------------------------------------------------- security_txt


def _sectxt(testo: str, status_code: int = 200, ct: str = "text/plain"):
    return risposta(url=f"https://{HOST}/.well-known/security.txt", status_code=status_code, headers={"content-type": ct}, text=testo)


def test_security_txt_valido(ctx_buono):
    f = security_txt.controlla(ctx_buono)[0]
    assert f.status == Status.OK
    assert "sicurezza@comune.esempio.example" in f.evidenza


@pytest.mark.parametrize(
    "fetch, status",
    [
        (lambda: _sectxt("Not found", status_code=404, ct="text/html"), Status.PROBLEMA),
        (lambda: _sectxt("<html>pagina del CMS</html>", ct="text/html"), Status.PROBLEMA),  # soft 404
        (lambda: _sectxt(leggi_fixture("security_scaduto.txt")), Status.PROBLEMA),
        (lambda: _sectxt("Contact: mailto:a@esempio.example\n"), Status.ATTENZIONE),
        (lambda: _sectxt("Contact: mailto:a@esempio.example\nExpires: domani\n"), Status.ATTENZIONE),
    ],
)
def test_security_txt_varianti(fetch, status):
    assert security_txt.controlla(crea_contesto(security_txt=fetch()))[0].status == status


def test_security_txt_errore_rete_con_home_presente():
    f = security_txt.controlla(crea_contesto(security_txt_errore="Timeout"))[0]
    assert f.status == Status.PROBLEMA


# ---------------------------------------------------------------- cms


def test_wordpress_con_versione():
    ctx = crea_contesto(home=risposta(text=leggi_fixture("home_wordpress.html")))
    findings = cms.controlla(ctx)
    assert "WordPress" in per_id(findings, "cms.rilevato").dettaglio
    versione = per_id(findings, "cms.versione")
    assert versione.status == Status.ATTENZIONE and "6.4.2" in versione.dettaglio
    assert "wp_generator" in versione.rimedio_wordpress


def test_drupal_da_generator_senza_versione_puntuale():
    ctx = crea_contesto(home=risposta(text=leggi_fixture("home_drupal.html")))
    findings = cms.controlla(ctx)
    assert "Drupal" in per_id(findings, "cms.rilevato").dettaglio
    # "Drupal 10" non contiene una versione x.y: nessuna segnalazione
    assert not [f for f in findings if f.id == "cms.versione"]


def test_joomla_da_percorsi():
    html = '<html><head><script src="/media/jui/js/jquery.min.js"></script></head></html>'
    assert "Joomla" in per_id(cms.controlla(crea_contesto(home=risposta(text=html))), "cms.rilevato").dettaglio


def test_nessun_cms(ctx_buono):
    f = per_id(cms.controlla(ctx_buono), "cms.rilevato")
    assert f.status == Status.INFO and "Nessun CMS" in f.dettaglio


# ---------------------------------------------------------------- cookies


def test_analizza_set_cookie():
    c = cookies.analizza_set_cookie("PHPSESSID=abc123; path=/; Secure; HttpOnly; SameSite=Lax")
    assert (c.nome, c.secure, c.httponly, c.samesite) == ("PHPSESSID", True, True, "Lax")
    assert c.di_sessione


def test_cookie_insicuri():
    ctx = crea_contesto(
        home=risposta(set_cookies=["PHPSESSID=abc; path=/", "preferenze=it; path=/; Secure; HttpOnly"])
    )
    findings = cookies.controlla(ctx)
    assert per_id(findings, "cookie.primo_caricamento").status == Status.INFO
    secure = per_id(findings, "cookie.secure")
    assert secure.status == Status.PROBLEMA and secure.severita == Severity.MEDIA
    assert secure.evidenza == "PHPSESSID"
    assert per_id(findings, "cookie.httponly").status == Status.PROBLEMA
    assert per_id(findings, "cookie.samesite").status == Status.ATTENZIONE
    # Il valore dei cookie non deve mai comparire negli esiti
    assert all("abc" not in f.evidenza for f in findings)


def test_cookie_corretti():
    ctx = crea_contesto(home=risposta(set_cookies=["sid=x; Secure; HttpOnly; SameSite=Strict"]))
    findings = cookies.controlla(ctx)
    assert per_id(findings, "cookie.flag").status == Status.OK


def test_nessun_cookie(ctx_buono):
    assert per_id(cookies.controlla(ctx_buono), "cookie.primo_caricamento").status == Status.OK


# ---------------------------------------------------------------- third_party


def test_terze_parti_e_contenuti_misti():
    ctx = crea_contesto(home=risposta(text=leggi_fixture("home_wordpress.html")))
    findings = third_party.controlla(ctx)
    origini = per_id(findings, "terze_parti.origini")
    assert origini.status == Status.INFO
    assert "https://www.googletagmanager.com (script)" in origini.evidenza
    assert "https://www.youtube-nocookie.com (iframe)" in origini.evidenza
    # sottodominio dello stesso ente: non e' terza parte
    assert "static.comune.esempio.example" not in origini.evidenza
    assert "senza controllo di integrita'" in origini.dettaglio
    misti = per_id(findings, "terze_parti.contenuti_misti")
    assert misti.status == Status.PROBLEMA and "http://widget.example-meteo.org/w.js" in misti.evidenza


def test_nessuna_terza_parte(ctx_buono):
    findings = third_party.controlla(ctx_buono)
    assert len(findings) == 1 and "non carica" in findings[0].dettaglio


def test_html_malformato_non_rompe():
    ctx = crea_contesto(home=risposta(text="<script src='https://a.example-terzo.org/x.js'><iframe src=<<<"))
    assert third_party.controlla(ctx)


# ---------------------------------------------------------------- passivita'


def test_i_controlli_non_fanno_io_di_rete(ctx_buono, monkeypatch):
    """I controlli leggono solo il Context: qualsiasi richiesta HTTP o socket fallisce il test."""
    import socket

    import requests

    def vietato(*a, **k):
        raise AssertionError("I/O di rete in un controllo")

    monkeypatch.setattr(requests.Session, "request", vietato)
    monkeypatch.setattr(socket, "create_connection", vietato)
    ctx = crea_contesto(home=risposta(text=leggi_fixture("home_wordpress.html"), set_cookies=["a=b"]))
    analizza_contesto(ctx)
    analizza_contesto(ctx_buono)



# ---------------------------------------------------------------- pagina bloccata (403/5xx)


@pytest.mark.parametrize("codice", [403, 503])
def test_pagina_bloccata_non_produce_falsi_positivi(codice):
    """Un WAF che blocca i client automatici risponde 403 senza header: non va giudicato."""
    bloccata = risposta(status_code=codice, headers={"content-type": "text/html"}, text="Access denied", set_cookies=["x=1"])
    findings = analizza_contesto(crea_contesto(home=bloccata))
    for id_ in ("header.non_verificabili", "cms.rilevato", "cookie.primo_caricamento", "terze_parti.origini"):
        f = per_id(findings, id_)
        assert f.status == Status.ERRORE and str(codice) in f.dettaglio, id_
    assert not [f for f in findings if f.id.startswith("header.") and f.status == Status.PROBLEMA]
    assert str(codice) in per_id(findings, "https.disponibile").dettaglio
