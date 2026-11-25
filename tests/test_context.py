"""Test della raccolta passiva con una sessione HTTP finta e un handshake TLS finto."""

from __future__ import annotations

import pytest
import requests

from conftest import DNS_BUONO, FakeResolver, tls_buono
from sentinella.core import analizza
from sentinella.core import context as modulo_context
from sentinella.core.context import dominio_registrabile, normalizza_url


@pytest.mark.parametrize(
    "ingresso, atteso",
    [
        ("www.comune.milano.it", "https://www.comune.milano.it/"),
        ("http://WWW.Comune.Milano.IT", "https://www.comune.milano.it/"),
        ("https://www.comune.milano.it/servizi?x=1#ancora", "https://www.comune.milano.it/servizi?x=1"),
        ("https://www.comune.milano.it:443/", "https://www.comune.milano.it/"),
        ("https://www.comune.milano.it:8443/", "https://www.comune.milano.it:8443/"),
        ("  agid.gov.it.  ", "https://agid.gov.it/"),
    ],
)
def test_normalizza_url(ingresso, atteso):
    assert normalizza_url(ingresso) == atteso


@pytest.mark.parametrize("ingresso", ["", "   ", "ftp://comune.milano.it", "https://"])
def test_normalizza_url_rifiuta_input_non_validi(ingresso):
    with pytest.raises(ValueError):
        normalizza_url(ingresso)


@pytest.mark.parametrize(
    "host, atteso",
    [
        ("www.comune.milano.it", "comune.milano.it"),
        ("servizi.comune.milano.it", "comune.milano.it"),
        ("www.agid.gov.it", "agid.gov.it"),
        ("www.regione.lombardia.it", "regione.lombardia.it"),
        ("www.comune.roma.it", "comune.roma.it"),
        ("192.0.2.10", "192.0.2.10"),
    ],
)
def test_dominio_registrabile(host, atteso):
    assert dominio_registrabile(host) == atteso


# ---------------------------------------------------------------- sessione finta


def _risposta(url: str, status: int = 200, headers: dict | None = None, corpo: bytes = b"", history=None):
    r = requests.Response()
    r.url = url
    r.status_code = status
    r.headers.update(headers or {"Content-Type": "text/html; charset=utf-8"})
    r._content = corpo
    r._content_consumed = True
    r.encoding = "utf-8"
    r.history = history or []
    return r


class _CM:
    """Rende una Response usabile come context manager (come con stream=True)."""

    def __init__(self, r):
        self.r = r

    def __enter__(self):
        return self.r

    def __exit__(self, *exc):
        return False


class SessioneFinta:
    def __init__(self, mappa: dict[str, object]):
        self.mappa = mappa
        self.richieste: list[tuple[str, dict]] = []
        self.headers: dict[str, str] = {}

    def get(self, url, **kwargs):
        self.richieste.append((url, kwargs))
        esito = self.mappa[url]
        if isinstance(esito, Exception):
            raise esito
        return _CM(esito)


HOME = "https://www.comune.esempio.example/"


def _mappa_base():
    redirect = _risposta("http://www.comune.esempio.example/", status=301)
    return {
        HOME: _risposta(
            HOME,
            headers={"Content-Type": "text/html", "Strict-Transport-Security": "max-age=63072000"},
            corpo=b"<html><head><meta name='generator' content='WordPress 6.4'></head></html>",
        ),
        "http://www.comune.esempio.example/": _risposta(HOME, history=[redirect]),
        "https://www.comune.esempio.example/.well-known/security.txt": _risposta(
            "https://www.comune.esempio.example/.well-known/security.txt", status=404
        ),
    }


def test_analizza_end_to_end_senza_rete(monkeypatch):
    monkeypatch.setattr(modulo_context, "handshake_tls", lambda host, porta=443, timeout=10: tls_buono(host=host))
    sessione = SessioneFinta(_mappa_base())
    report = analizza("www.comune.esempio.example", sessione=sessione, resolver=FakeResolver(DNS_BUONO))

    # Solo le tre richieste previste, nessuna enumerazione di percorsi.
    assert [u for u, _ in sessione.richieste] == [
        HOME,
        "http://www.comune.esempio.example/",
        "https://www.comune.esempio.example/.well-known/security.txt",
    ]
    assert all(k.get("timeout") for _, k in sessione.richieste)

    ids = {f.id: f for f in report.findings}
    assert ids["https.redirect"].status.value == "ok"
    assert ids["header.hsts"].status.value == "ok"
    assert ids["security_txt"].status.value == "problema"
    assert ids["cms.versione"].status.value == "attenzione"
    assert report.dominio == "esempio.example"
    assert report.to_dict()["generato_con"].startswith("Report generato con Sentinella PA")


def test_errori_di_rete_non_interrompono(monkeypatch):
    monkeypatch.setattr(
        modulo_context,
        "handshake_tls",
        lambda host, porta=443, timeout=10: modulo_context.TlsInfo(host=host, errore="rete giu'"),
    )
    errore = requests.exceptions.ConnectionError("rete giu'")
    sessione = SessioneFinta(
        {
            HOME: errore,
            "http://www.comune.esempio.example/": errore,
            "https://www.comune.esempio.example/.well-known/security.txt": errore,
        }
    )
    report = analizza("www.comune.esempio.example", sessione=sessione, resolver=FakeResolver(guasti={"esempio.example"}))
    assert report.findings  # nessuna eccezione, solo esiti "non verificabile"
    assert report.conteggi()["errore"] >= 3


def test_certificato_non_valido_rilegge_senza_verifica(monkeypatch):
    monkeypatch.setattr(modulo_context, "handshake_tls", lambda host, porta=443, timeout=10: tls_buono(host=host))
    chiamate = []

    class SessioneTls(SessioneFinta):
        def get(self, url, **kwargs):
            if url == HOME:
                chiamate.append(kwargs.get("verify", True))
                if kwargs.get("verify", True):
                    raise requests.exceptions.SSLError("certificate verify failed")
            return super().get(url, **kwargs)

    sessione = SessioneTls(_mappa_base())
    fetch = modulo_context.scarica(sessione, HOME, timeout=5)
    assert chiamate == [True, False]
    assert fetch.ok and fetch.certificato_non_verificato
    assert "Errore TLS" in fetch.errore


def test_set_cookie_multipli_restano_separati():
    r = _risposta(HOME)
    convertita = modulo_context._converti(r)
    assert convertita.set_cookies == []

    class RawFinto:
        class headers:
            @staticmethod
            def getlist(nome):
                return ["a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure", "b=2; HttpOnly"]

    r.raw = RawFinto()
    assert modulo_context._converti(r).set_cookies == [
        "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure",
        "b=2; HttpOnly",
    ]


def test_user_agent_trasparente():
    ua = modulo_context.nuova_sessione().headers["User-Agent"]
    assert ua.startswith("SentinellaPA/") and "controllo passivo" in ua
