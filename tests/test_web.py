"""Test dell'API web: validazione dei bersagli, anti-SSRF, limiti d'uso, job e documenti."""

from __future__ import annotations

import time

import pytest
import requests

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from conftest import crea_contesto, leggi_fixture, risposta  # noqa: E402
from sentinella.core import analizza_contesto  # noqa: E402
from sentinella.core.models import Report  # noqa: E402
from sentinella.web import crea_app  # noqa: E402
from sentinella.web.config import Impostazioni  # noqa: E402
from sentinella.web.sicurezza import (  # noqa: E402
    BersaglioNonConsentito,
    controlla_host,
    sessione_protetta,
    valida_bersaglio,
)

IP_PUBBLICO = "93.184.215.14"
DNS_FINTO = {
    "www.comune.esempio.it": [IP_PUBBLICO],
    "comune.esempio.it": [IP_PUBBLICO, "2606:2800:21f:cb07:6820:80da:af6b:8b2c"],
    "interno.esempio.it": ["10.0.0.5"],
    "locale.esempio.it": ["127.0.0.1"],
    "metadati.esempio.it": ["169.254.169.254"],
    "misto.esempio.it": [IP_PUBBLICO, "192.168.1.10"],
    "www.example.com": [IP_PUBBLICO],
}


def risolutore_finto(host: str) -> list[str]:
    if host not in DNS_FINTO:
        raise BersaglioNonConsentito(f"Il dominio {host} non esiste o non risolve")
    return DNS_FINTO[host]


# ---------------------------------------------------------------- validazione


@pytest.mark.parametrize("url", ["www.comune.esempio.it", "https://comune.esempio.it/servizi", "http://www.comune.esempio.it"])
def test_bersagli_validi(url):
    assert valida_bersaglio(url, ["it"], risolutore_finto).startswith("https://")


@pytest.mark.parametrize(
    "url, messaggio",
    [
        ("interno.esempio.it", "non pubblico"),
        ("locale.esempio.it", "non pubblico"),
        ("metadati.esempio.it", "non pubblico"),
        ("misto.esempio.it", "non pubblico"),
        ("https://93.184.215.14/", "non un indirizzo IP"),
        ("https://[::1]/", "non un indirizzo IP"),
        ("https://www.comune.esempio.it:8080/", "porte standard"),
        ("www.example.com", "solo domini .it"),
        ("localhost", "dominio completo"),
        ("ftp://www.comune.esempio.it", "Schema non supportato"),
        ("inesistente.esempio.it", "non esiste"),
    ],
)
def test_bersagli_rifiutati(url, messaggio):
    with pytest.raises(BersaglioNonConsentito, match=messaggio):
        valida_bersaglio(url, ["it"], risolutore_finto)


def test_senza_restrizione_di_dominio_accetta_altri_tld():
    assert valida_bersaglio("www.example.com", [], risolutore_finto) == "https://www.example.com/"


def test_controlla_host_rifiuta_ipv6_privati():
    with pytest.raises(BersaglioNonConsentito):
        controlla_host("v6.esempio.it", lambda h: ["fd00::1"])


def test_sessione_protetta_blocca_redirect_verso_rete_interna(monkeypatch):
    """Anche un redirect verso un host interno viene bloccato prima della connessione."""
    from requests.adapters import HTTPAdapter

    inviate = []

    def invio_finto(self, req, **kw):
        inviate.append(req.url)
        r = requests.Response()
        r.status_code, r.url, r.request = 200, req.url, req
        return r

    monkeypatch.setattr(HTTPAdapter, "send", invio_finto)
    sessione = sessione_protetta(risolutore_finto)
    with pytest.raises(requests.exceptions.InvalidURL, match="non consentita"):
        sessione.get("http://interno.esempio.it/")
    with pytest.raises(requests.exceptions.InvalidURL, match="Porta"):
        sessione.get("http://www.comune.esempio.it:2375/")
    assert inviate == []
    sessione.get("https://www.comune.esempio.it/")
    assert inviate == ["https://www.comune.esempio.it/"]


# ---------------------------------------------------------------- API


def _report_finto(url: str, timeout: float) -> Report:
    ctx = crea_contesto(home=risposta(headers={"content-type": "text/html"}, text=leggi_fixture("home_wordpress.html")), dns={})
    return Report(
        target=url,
        final_url=url,
        hostname="www.comune.esempio.it",
        dominio="comune.esempio.it",
        timestamp="2026-11-25T10:00:00+00:00",
        findings=analizza_contesto(ctx),
    )


@pytest.fixture
def client(tmp_path):
    chiamate: list[str] = []

    def analizzatore(url, timeout):
        chiamate.append(url)
        return _report_finto(url, timeout)

    imp = Impostazioni(
        database=tmp_path / "test.sqlite3",
        cors_origini=["https://enricolacchin.github.io"],
        limite_per_ora=3,
        riuso_minuti=10,
    )
    app = crea_app(imp, analizzatore=analizzatore, risolutore=risolutore_finto)
    with TestClient(app) as c:
        c.chiamate = chiamate
        yield c


def _attendi(client, id_, secondi=5.0):
    fine = time.time() + secondi
    while time.time() < fine:
        dati = client.get(f"/api/analisi/{id_}").json()
        if dati["stato"] != "in_corso":
            return dati
        time.sleep(0.02)
    raise AssertionError("job non completato")


def test_salute_e_configurazione(client):
    assert client.get("/api/salute").json()["stato"] == "ok"
    conf = client.get("/api/configurazione").json()
    assert conf["domini_consentiti"] == ["it"] and conf["limite_per_ora"] == 3
    assert conf["generato_con"].startswith("Report generato con Sentinella PA")


def test_ciclo_completo_di_un_analisi(client):
    avvio = client.post("/api/analisi", json={"url": "www.comune.esempio.it"})
    assert avvio.status_code == 202 and avvio.json()["riusata"] is False
    dati = _attendi(client, avvio.json()["id"])
    assert dati["stato"] == "completata"
    assert dati["report"]["voto"] in "ABCDE"
    documenti = dati["documenti"]
    assert set(documenti) == {"html", "tecnico", "sindaco", "pec"}
    for testo in documenti.values():
        assert "Report generato con Sentinella PA" in testo
    assert client.chiamate == ["https://www.comune.esempio.it/"]


def test_stesso_sito_entro_pochi_minuti_riusa_l_analisi(client):
    primo = client.post("/api/analisi", json={"url": "www.comune.esempio.it"}).json()
    _attendi(client, primo["id"])
    secondo = client.post("/api/analisi", json={"url": "https://www.comune.esempio.it/"}).json()
    assert secondo["riusata"] is True and secondo["id"] == primo["id"]
    assert len(client.chiamate) == 1  # il sito non e' stato contattato di nuovo


def test_bersaglio_rifiutato_restituisce_400(client):
    r = client.post("/api/analisi", json={"url": "interno.esempio.it"})
    assert r.status_code == 400 and "non pubblico" in r.json()["detail"]
    assert client.chiamate == []


def test_limite_di_richieste_per_ora(client):
    for _ in range(3):
        assert client.post("/api/analisi", json={"url": "www.comune.esempio.it"}).status_code == 202
    r = client.post("/api/analisi", json={"url": "www.comune.esempio.it"})
    assert r.status_code == 429 and "Limite" in r.json()["detail"]
    # un altro richiedente (dietro proxy) non e' bloccato
    r = client.post("/api/analisi", json={"url": "www.comune.esempio.it"}, headers={"X-Forwarded-For": "203.0.113.9"})
    assert r.status_code == 202


def test_url_troppo_lungo_o_mancante(client):
    assert client.post("/api/analisi", json={}).status_code == 422
    assert client.post("/api/analisi", json={"url": "a" * 400}).status_code == 422


def test_analisi_inesistente(client):
    assert client.get("/api/analisi/" + "0" * 32).status_code == 404
    assert client.get("/api/analisi/..%2F..%2Fetc").status_code == 404


def test_pec_personalizzata(client):
    id_ = client.post("/api/analisi", json={"url": "www.comune.esempio.it"}).json()["id"]
    _attendi(client, id_)
    r = client.post(f"/api/analisi/{id_}/pec", json={"ente": "Comune di Esempio", "mittente": "Mario Rossi"})
    testo = r.json()["testo"]
    assert "A: Comune di Esempio" in testo and "Mario Rossi" in testo
    assert "[PEC ISTITUZIONALE DELL'ENTE]" in testo  # campo non compilato: segnaposto


def test_errore_nell_analisi_non_lascia_il_job_appeso(tmp_path):
    def rotto(url, timeout):
        raise RuntimeError("guasto")

    app = crea_app(Impostazioni(database=tmp_path / "db.sqlite3"), analizzatore=rotto, risolutore=risolutore_finto)
    with TestClient(app) as c:
        id_ = c.post("/api/analisi", json={"url": "www.comune.esempio.it"}).json()["id"]
        dati = _attendi(c, id_)
    assert dati["stato"] == "errore" and "guasto" not in dati["errore"]


def test_cors_e_header_di_sicurezza(client):
    r = client.options(
        "/api/analisi",
        headers={"Origin": "https://enricolacchin.github.io", "Access-Control-Request-Method": "POST"},
    )
    assert r.headers["access-control-allow-origin"] == "https://enricolacchin.github.io"
    r = client.get("/api/salute", headers={"Origin": "https://sito-estraneo.example"})
    assert "access-control-allow-origin" not in r.headers
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_frontend_servito_con_csp(tmp_path):
    cartella = tmp_path / "web"
    cartella.mkdir()
    (cartella / "index.html").write_text("<!doctype html><title>ok</title>")
    app = crea_app(Impostazioni(database=tmp_path / "db.sqlite3", frontend=cartella), analizzatore=_report_finto, risolutore=risolutore_finto)
    with TestClient(app) as c:
        r = c.get("/")
    assert r.status_code == 200 and "<title>ok</title>" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]


def test_storico_per_il_follow_up(client):
    id_ = client.post("/api/analisi", json={"url": "www.comune.esempio.it"}).json()["id"]
    _attendi(client, id_)
    storico = client.app.state.archivio.storico("www.comune.esempio.it")
    assert storico[0]["id"] == id_ and storico[0]["voto"] in "ABCDE"


def test_ip_non_salvati_in_chiaro(client):
    client.post("/api/analisi", json={"url": "www.comune.esempio.it"}, headers={"X-Forwarded-For": "198.51.100.77"})
    contenuto = client.app.state.archivio.percorso.read_bytes()
    assert b"198.51.100.77" not in contenuto


def test_passenger_wsgi_espone_application(tmp_path, monkeypatch):
    pytest.importorskip("a2wsgi")
    import importlib.util
    from pathlib import Path

    monkeypatch.setenv("SENTINELLA_DATABASE", str(tmp_path / "p.sqlite3"))
    percorso = Path(__file__).resolve().parents[1] / "passenger_wsgi.py"
    spec = importlib.util.spec_from_file_location("passenger_wsgi", percorso)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    assert callable(modulo.application)
