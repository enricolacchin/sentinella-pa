"""Test dello strato di rendering: tutti i formati contengono la firma e i dati attesi."""

from __future__ import annotations

import json
import re

from rich.console import Console

from conftest import crea_contesto, leggi_fixture, risposta
from sentinella import __version__
from sentinella.branding import firma
from sentinella.core import analizza_contesto
from sentinella.core.models import Report
from sentinella.report import (
    DatiPec,
    render_html,
    render_json,
    render_pec,
    render_report_sindaco,
    render_report_tecnico,
    render_text,
)

FIRMA = firma(__version__)


def _report(ctx=None) -> Report:
    ctx = ctx or crea_contesto(
        home=risposta(
            headers={"content-type": "text/html", "server": "Apache/2.4.29"},
            text=leggi_fixture("home_wordpress.html"),
            set_cookies=["PHPSESSID=abc; path=/"],
        ),
        dns={},
    )
    return Report(
        target=ctx.url,
        final_url=ctx.final_url,
        hostname=ctx.hostname,
        dominio=ctx.dominio,
        timestamp="2026-11-25T10:00:00+00:00",
        findings=analizza_contesto(ctx),
    )


def test_json():
    dati = json.loads(render_json(_report()))
    assert dati["generato_con"] == FIRMA
    assert dati["voto"] in "ABCDE"
    assert Report.from_dict(dati).punteggio == dati["punteggio"]


def test_testo_a_terminale_termina_con_la_firma():
    console = Console(record=True, width=160)
    render_text(_report(), console)
    testo = console.export_text().strip()
    assert testo.splitlines()[-1] == FIRMA
    assert "Strict-Transport-Security" in testo


def test_html_escape_e_firma():
    report = _report()
    report.findings[0].evidenza = "<script>alert(1)</script>"
    html = render_html(report)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert f"<footer>{FIRMA}</footer>" in html
    assert "Interventi consigliati" in html


def test_report_tecnico_contiene_rimedi_e_firma():
    md = render_report_tecnico(_report())
    assert md.rstrip().endswith(FIRMA)
    assert "```nginx" in md and "```apache" in md and "```php" in md
    assert "add_header Strict-Transport-Security" in md
    assert "{{" not in md and "{%" not in md


def test_report_sindaco_linguaggio_semplice():
    md = render_report_sindaco(_report())
    assert md.rstrip().endswith(FIRMA)
    assert "Cosa rischiano i cittadini" in md
    assert "Chiunque puo' inviare email che sembrano dell'ente" in md  # SPF assente
    assert "add_header" not in md  # nessun dettaglio tecnico


def test_pec_con_segnaposto_e_problemi():
    pec = render_pec(_report())
    assert "[DENOMINAZIONE ENTE]" in pec and "[PEC ISTITUZIONALE DELL'ENTE]" in pec
    assert "[NOME DEL RESPONSABILE PER LA TRANSIZIONE DIGITALE]" in pec
    assert "esclusivamente passiva" in pec and "CSIRT Italia" in pec and "AgID" in pec
    assert pec.rstrip().splitlines()[-1] == FIRMA
    # Solo problemi di gravita' media o superiore, numerati
    assert re.search(r"^1\. ", pec, re.MULTILINE)
    assert "Permissions-Policy" not in pec  # gravita' bassa: esclusa


def test_pec_compilata():
    pec = render_pec(_report(), DatiPec(ente="Comune di Esempio", pec_ente="protocollo@pec.esempio.example", mittente="Mario Rossi"))
    assert "A: Comune di Esempio" in pec and "PEC: protocollo@pec.esempio.example" in pec
    assert "Mario Rossi" in pec and "[DENOMINAZIONE ENTE]" not in pec


def test_sito_perfetto_rende_senza_interventi():
    report = _report(crea_contesto())
    assert "Nessun intervento necessario" in render_report_tecnico(report)
    assert "Nessun problema rilevante" in render_report_sindaco(report)
    assert "non ha evidenziato problemi" in render_pec(report)


def test_voto_parziale_segnalato_in_tutti_i_formati():
    bloccata = risposta(status_code=403, headers={"content-type": "text/html"}, text="Access denied")
    report = _report(crea_contesto(home=bloccata))
    assert not report.completo and report.non_verificabili == 4
    assert json.loads(render_json(report))["completo"] is False
    assert "Voto parziale" in render_html(report)
    assert "Voto parziale" in render_report_tecnico(report)
    assert "Il voto e' parziale" in render_report_sindaco(report)
    console = Console(record=True, width=160)
    render_text(report, console)
    assert "Voto parziale" in console.export_text()
