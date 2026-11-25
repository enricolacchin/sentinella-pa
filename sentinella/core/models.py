"""Modello dati del motore: esiti dei controlli, report e calcolo del punteggio.

Tutto cio' che sta qui e' serializzabile in un ``dict`` di soli tipi JSON
(``str``, ``int``, ``float``, ``list``, ``dict``, ``None``): e' il requisito che
permettera' alla Fase 2 di salvare un'analisi su database con il solo
``Report.to_dict()`` e di ricostruirla con ``Report.from_dict()``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from sentinella import __version__
from sentinella.branding import firma


class Status(str, Enum):
    """Esito di un singolo controllo."""

    OK = "ok"                  # configurazione corretta
    ATTENZIONE = "attenzione"  # migliorabile: pesa la meta' nel punteggio
    PROBLEMA = "problema"      # da correggere
    ERRORE = "errore"          # non verificabile (errore di rete, DNS, ...)
    INFO = "info"              # puramente informativo, non pesa


class Severity(str, Enum):
    """Gravita' di un esito. Per gli esiti ``ok``/``info`` indica l'importanza del tema."""

    CRITICA = "critica"
    ALTA = "alta"
    MEDIA = "media"
    BASSA = "bassa"
    INFORMATIVA = "informativa"


# Pesi sottratti al punteggio (parte da 100) per ogni esito "problema".
# Gli esiti "attenzione" pesano la meta'.
PESI: dict[Severity, float] = {
    Severity.CRITICA: 25,
    Severity.ALTA: 15,
    Severity.MEDIA: 8,
    Severity.BASSA: 3,
    Severity.INFORMATIVA: 0,
}

# Ordine di gravita' (0 = piu' grave), utile per ordinare gli esiti.
ORDINE_SEVERITA: dict[Severity, int] = {s: i for i, s in enumerate(Severity)}

# Soglie del voto: punteggio minimo per ottenere la lettera.
SOGLIE_VOTO: list[tuple[int, str]] = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "E")]


@dataclass
class Finding:
    """Un esito di controllo: cosa si e' osservato e come rimediare."""

    id: str
    titolo: str
    status: Status
    severita: Severity
    dettaglio: str = ""
    evidenza: str = ""
    rimedio: str = ""
    rimedio_nginx: str = ""
    rimedio_apache: str = ""
    rimedio_wordpress: str = ""
    riferimento: str = ""
    # Nome del controllo che ha prodotto l'esito (impostato dal motore).
    categoria: str = ""

    @property
    def peso(self) -> float:
        """Punti sottratti al punteggio da questo esito."""
        if self.status == Status.PROBLEMA:
            return PESI[self.severita]
        if self.status == Status.ATTENZIONE:
            return PESI[self.severita] / 2
        return 0.0

    @property
    def da_segnalare(self) -> bool:
        """Vero se l'esito va riportato all'ente (gravita' media o superiore)."""
        return self.status in (Status.PROBLEMA, Status.ATTENZIONE) and self.severita in (
            Severity.CRITICA,
            Severity.ALTA,
            Severity.MEDIA,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "categoria": self.categoria,
            "titolo": self.titolo,
            "status": self.status.value,
            "severita": self.severita.value,
            "peso": self.peso,
            "dettaglio": self.dettaglio,
            "evidenza": self.evidenza,
            "rimedio": self.rimedio,
            "rimedio_nginx": self.rimedio_nginx,
            "rimedio_apache": self.rimedio_apache,
            "rimedio_wordpress": self.rimedio_wordpress,
            "riferimento": self.riferimento,
        }

    @classmethod
    def from_dict(cls, dati: dict[str, Any]) -> Finding:
        return cls(
            id=dati["id"],
            titolo=dati["titolo"],
            status=Status(dati["status"]),
            severita=Severity(dati["severita"]),
            dettaglio=dati.get("dettaglio", ""),
            evidenza=dati.get("evidenza", ""),
            rimedio=dati.get("rimedio", ""),
            rimedio_nginx=dati.get("rimedio_nginx", ""),
            rimedio_apache=dati.get("rimedio_apache", ""),
            rimedio_wordpress=dati.get("rimedio_wordpress", ""),
            riferimento=dati.get("riferimento", ""),
            categoria=dati.get("categoria", ""),
        )


def calcola_punteggio(findings: list[Finding]) -> int:
    """Parte da 100 e sottrae il peso di ogni esito; il minimo e' 0."""
    totale = 100.0 - sum(f.peso for f in findings)
    return max(0, round(totale))


def calcola_voto(punteggio: int) -> str:
    """Converte il punteggio 0–100 in un voto A–E."""
    for soglia, lettera in SOGLIE_VOTO:
        if punteggio >= soglia:
            return lettera
    return "E"


@dataclass
class Report:
    """Risultato completo di un'analisi. Unico oggetto restituito dal motore."""

    target: str
    final_url: str
    hostname: str
    timestamp: str  # ISO 8601 UTC
    findings: list[Finding] = field(default_factory=list)
    dominio: str = ""  # dominio registrabile (es. comune.milano.it)
    durata_secondi: float = 0.0
    versione: str = __version__

    @property
    def punteggio(self) -> int:
        return calcola_punteggio(self.findings)

    @property
    def voto(self) -> str:
        return calcola_voto(self.punteggio)

    @property
    def non_verificabili(self) -> int:
        """Numero di controlli che non e' stato possibile eseguire."""
        return sum(1 for f in self.findings if f.status == Status.ERRORE)

    @property
    def completo(self) -> bool:
        """Falso se qualche controllo non e' verificabile: il voto e' parziale."""
        return self.non_verificabili == 0

    @property
    def generato_con(self) -> str:
        return firma(self.versione)

    def findings_ordinati(self) -> list[Finding]:
        """Esiti ordinati: prima i problemi piu' gravi, poi attenzioni, poi il resto."""
        ordine_status = {
            Status.PROBLEMA: 0,
            Status.ATTENZIONE: 1,
            Status.ERRORE: 2,
            Status.OK: 3,
            Status.INFO: 4,
        }
        return sorted(
            self.findings,
            key=lambda f: (ordine_status[f.status], ORDINE_SEVERITA[f.severita]),
        )

    def da_segnalare(self) -> list[Finding]:
        """Esiti di gravita' media/alta/critica da comunicare all'ente."""
        return [f for f in self.findings_ordinati() if f.da_segnalare]

    def conteggi(self) -> dict[str, int]:
        """Numero di esiti per stato."""
        risultato = {s.value: 0 for s in Status}
        for f in self.findings:
            risultato[f.status.value] += 1
        return risultato

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "final_url": self.final_url,
            "hostname": self.hostname,
            "dominio": self.dominio,
            "timestamp": self.timestamp,
            "durata_secondi": self.durata_secondi,
            "versione": self.versione,
            "punteggio": self.punteggio,
            "voto": self.voto,
            "completo": self.completo,
            "conteggi": self.conteggi(),
            "findings": [f.to_dict() for f in self.findings],
            "generato_con": self.generato_con,
        }

    @classmethod
    def from_dict(cls, dati: dict[str, Any]) -> Report:
        """Ricostruisce un Report da ``to_dict()`` (es. letto da database).

        Punteggio, voto e conteggi non vengono letti: sono ricalcolati dagli esiti.
        """
        return cls(
            target=dati["target"],
            final_url=dati.get("final_url", ""),
            hostname=dati.get("hostname", ""),
            timestamp=dati["timestamp"],
            findings=[Finding.from_dict(f) for f in dati.get("findings", [])],
            dominio=dati.get("dominio", ""),
            durata_secondi=dati.get("durata_secondi", 0.0),
            versione=dati.get("versione", __version__),
        )
