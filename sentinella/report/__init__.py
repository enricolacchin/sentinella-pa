"""Rendering condiviso: trasforma un ``Report`` nei vari formati. Non esegue analisi.

Usato dalla CLI e, nella Fase 2, dal sito web (``render_html``).
"""

from sentinella.report.pec_draft import DatiPec, render_pec
from sentinella.report.render_html import render_html
from sentinella.report.render_json import render_json
from sentinella.report.render_markdown import render_report_sindaco, render_report_tecnico
from sentinella.report.render_text import render_text

__all__ = [
    "DatiPec",
    "render_html",
    "render_json",
    "render_pec",
    "render_report_sindaco",
    "render_report_tecnico",
    "render_text",
]
