"""Report HTML autonomo e stampabile (lo stesso che mostrera' il futuro sito web)."""

from __future__ import annotations

from sentinella.core.models import Report
from sentinella.report._jinja import render


def render_html(report: Report) -> str:
    return render("report.html.j2", report=report)
