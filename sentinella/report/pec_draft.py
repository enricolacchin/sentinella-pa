"""Bozza di comunicazione PEC all'ente.

I dati del destinatario sono facoltativi: se mancano restano segnaposto da
completare a mano. Nella Fase 2 verranno compilati automaticamente
dall'Indice PA (PEC istituzionale, RTD) partendo dal dominio.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinella.core.models import Report
from sentinella.report._jinja import render


@dataclass
class DatiPec:
    """Dati di intestazione della PEC. I campi vuoti diventano segnaposto."""

    ente: str = ""
    pec_ente: str = ""
    rtd: str = ""
    mittente: str = ""
    contatto_mittente: str = ""

    def compilati(self) -> dict[str, str]:
        return {
            "ente": self.ente or "[DENOMINAZIONE ENTE]",
            "pec_ente": self.pec_ente or "[PEC ISTITUZIONALE DELL'ENTE]",
            "rtd": self.rtd or "[NOME DEL RESPONSABILE PER LA TRANSIZIONE DIGITALE]",
            "mittente": self.mittente or "[NOME E COGNOME DEL MITTENTE]",
            "contatto_mittente": self.contatto_mittente or "[RECAPITO DEL MITTENTE]",
        }


def render_pec(report: Report, dati: DatiPec | None = None) -> str:
    return render(
        "pec.txt.j2",
        report=report,
        problemi=report.da_segnalare(),
        **(dati or DatiPec()).compilati(),
    )
