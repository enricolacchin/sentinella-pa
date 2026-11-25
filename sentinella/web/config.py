"""Configurazione dell'API, letta dalle variabili d'ambiente.

Su cPanel le variabili si impostano nella pagina "Setup Python App".
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _lista(valore: str | None) -> list[str]:
    return [v.strip() for v in (valore or "").split(",") if v.strip()]


def _intero(nome: str, predefinito: int) -> int:
    try:
        return int(os.environ.get(nome, predefinito))
    except ValueError:
        return predefinito


@dataclass
class Impostazioni:
    # File SQLite con lo storico delle analisi. Su un hosting condiviso va
    # messo FUORI dalla cartella pubblica (public_html).
    database: Path = Path("sentinella.sqlite3")
    # Origini web autorizzate a chiamare l'API dal browser (CORS), ad esempio
    # "https://enricolacchin.github.io". Vuoto = solo stessa origine.
    cors_origini: list[str] = field(default_factory=list)
    # Suffissi di dominio analizzabili (es. "it"). Vuoto = qualsiasi dominio
    # pubblico. Limitare i bersagli riduce il rischio di abusi del servizio.
    domini_consentiti: list[str] = field(default_factory=lambda: ["it"])
    # Analisi consentite per indirizzo IP del richiedente in un'ora.
    limite_per_ora: int = 10
    # Entro questo intervallo (minuti) una nuova richiesta sullo stesso sito
    # restituisce l'analisi gia' fatta, senza contattare di nuovo il sito.
    riuso_minuti: int = 10
    # Analisi eseguite in parallelo da un singolo processo.
    analisi_parallele: int = 2
    # Timeout di rete di ciascuna operazione, in secondi.
    timeout: float = 10.0
    # Cartella del frontend statico da servire anche dall'API (facoltativo).
    frontend: Path | None = None
    # Fidarsi dell'header X-Forwarded-For (vero dietro il proxy di cPanel).
    dietro_proxy: bool = True

    @classmethod
    def da_ambiente(cls) -> Impostazioni:
        e = os.environ
        frontend = e.get("SENTINELLA_FRONTEND")
        domini = e.get("SENTINELLA_DOMINI_CONSENTITI")
        return cls(
            database=Path(e.get("SENTINELLA_DATABASE", "sentinella.sqlite3")),
            cors_origini=_lista(e.get("SENTINELLA_CORS_ORIGINI")),
            domini_consentiti=["it"] if domini is None else _lista(domini),
            limite_per_ora=_intero("SENTINELLA_LIMITE_ORA", 10),
            riuso_minuti=_intero("SENTINELLA_RIUSO_MINUTI", 10),
            analisi_parallele=_intero("SENTINELLA_ANALISI_PARALLELE", 2),
            timeout=float(e.get("SENTINELLA_TIMEOUT", "10")),
            frontend=Path(frontend) if frontend else None,
            dietro_proxy=e.get("SENTINELLA_DIETRO_PROXY", "1") != "0",
        )
