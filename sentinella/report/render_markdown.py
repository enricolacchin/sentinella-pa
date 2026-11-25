"""I due report Markdown in italiano: tecnico (sistemista) e semplice (sindaco/RTD)."""

from __future__ import annotations

from sentinella.core.models import Report
from sentinella.report._jinja import render


def render_report_tecnico(report: Report) -> str:
    """Report per il sistemista: ogni esito con evidenza e istruzioni di rimedio."""
    return render("report_tecnico.md.j2", report=report)


def render_report_sindaco(report: Report) -> str:
    """Report in linguaggio semplice: cosa rischia il cittadino e perche' intervenire."""
    return render("report_sindaco.md.j2", report=report)
