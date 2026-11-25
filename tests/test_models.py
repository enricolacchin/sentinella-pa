"""Test del modello dati: punteggio, voto, ordinamento e serializzazione."""

from __future__ import annotations

import json

import pytest

from sentinella import __version__
from sentinella.branding import firma
from sentinella.core.models import (
    Finding,
    Report,
    Severity,
    Status,
    calcola_punteggio,
    calcola_voto,
)


def _f(status: Status, severita: Severity, id: str = "x") -> Finding:
    return Finding(id=id, titolo=id, status=status, severita=severita)


def test_punteggio_parte_da_100_senza_esiti():
    assert calcola_punteggio([]) == 100


@pytest.mark.parametrize(
    "severita, atteso",
    [
        (Severity.CRITICA, 75),
        (Severity.ALTA, 85),
        (Severity.MEDIA, 92),
        (Severity.BASSA, 97),
        (Severity.INFORMATIVA, 100),
    ],
)
def test_pesi_dei_problemi(severita, atteso):
    assert calcola_punteggio([_f(Status.PROBLEMA, severita)]) == atteso


def test_attenzione_pesa_la_meta():
    assert _f(Status.ATTENZIONE, Severity.ALTA).peso == 7.5
    assert _f(Status.ATTENZIONE, Severity.MEDIA).peso == 4


@pytest.mark.parametrize("status", [Status.OK, Status.INFO, Status.ERRORE])
def test_ok_info_errore_non_pesano(status):
    assert calcola_punteggio([_f(status, Severity.CRITICA)]) == 100


def test_punteggio_non_scende_sotto_zero():
    assert calcola_punteggio([_f(Status.PROBLEMA, Severity.CRITICA)] * 10) == 0


@pytest.mark.parametrize(
    "punteggio, voto",
    [(100, "A"), (90, "A"), (89, "B"), (75, "B"), (74, "C"), (60, "C"), (59, "D"), (40, "D"), (39, "E"), (0, "E")],
)
def test_soglie_voto(punteggio, voto):
    assert calcola_voto(punteggio) == voto


def _report() -> Report:
    return Report(
        target="https://www.comune.esempio.example/",
        final_url="https://www.comune.esempio.example/home",
        hostname="www.comune.esempio.example",
        dominio="esempio.example",
        timestamp="2026-11-25T10:00:00+00:00",
        findings=[
            _f(Status.OK, Severity.CRITICA, "a"),
            _f(Status.ATTENZIONE, Severity.MEDIA, "b"),
            _f(Status.PROBLEMA, Severity.BASSA, "c"),
            _f(Status.PROBLEMA, Severity.ALTA, "d"),
            _f(Status.INFO, Severity.INFORMATIVA, "e"),
            _f(Status.ERRORE, Severity.MEDIA, "f"),
        ],
    )


def test_report_punteggio_e_voto():
    r = _report()
    # 100 - 4 (attenzione media) - 3 (bassa) - 15 (alta) = 78
    assert r.punteggio == 78
    assert r.voto == "B"


def test_ordinamento_mette_prima_i_problemi_gravi():
    ids = [f.id for f in _report().findings_ordinati()]
    assert ids == ["d", "c", "b", "f", "a", "e"]


def test_da_segnalare_solo_media_e_superiori():
    assert [f.id for f in _report().da_segnalare()] == ["d", "b"]


def test_conteggi():
    assert _report().conteggi() == {"ok": 1, "attenzione": 1, "problema": 2, "errore": 1, "info": 1}


def test_to_dict_e_serializzabile_in_json_e_contiene_la_firma():
    dati = _report().to_dict()
    testo = json.dumps(dati)  # nessun tipo non JSON
    assert dati["generato_con"] == firma(__version__)
    assert dati["punteggio"] == 78 and dati["voto"] == "B"
    assert dati["findings"][0]["status"] == "ok"
    assert "Sentinella PA" in testo


def test_from_dict_ricostruisce_il_report():
    originale = _report()
    copia = Report.from_dict(json.loads(json.dumps(originale.to_dict())))
    assert copia.to_dict() == originale.to_dict()


def test_firma_contiene_nome_versione_e_url():
    riga = firma("9.9.9")
    assert riga.startswith("Report generato con Sentinella PA v9.9.9")
    assert "github.com/enricolacchin/sentinella-pa" in riga
