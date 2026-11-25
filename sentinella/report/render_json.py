"""Export JSON del Report (dal suo ``to_dict()``)."""

from __future__ import annotations

import json

from sentinella.core.models import Report


def render_json(report: Report, indent: int | None = 2) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=indent) + "\n"
