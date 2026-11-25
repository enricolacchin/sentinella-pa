"""Archivio delle analisi su SQLite: stato dei job, report salvati, limiti di uso.

Il report viene salvato cosi' com'e' restituito da ``Report.to_dict()``: e' la
base per lo storico e per il follow-up a 30/60/90 giorni. SQLite basta per
iniziare e funziona anche quando l'hosting avvia piu' processi (come
Passenger su cPanel), perche' lo stato dei job sta nel file e non in memoria.

Gli indirizzi IP dei richiedenti non vengono salvati in chiaro: si conserva
solo un'impronta (hash con sale) per contare le richieste dell'ultima ora, e
le righe piu' vecchie di un giorno vengono cancellate.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

# Un job "in corso" piu' vecchio di cosi' e' considerato interrotto (processo
# terminato dall'hosting, riavvio, ...).
SCADENZA_JOB_SECONDI = 180

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analisi (
    id          TEXT PRIMARY KEY,
    url         TEXT NOT NULL,
    hostname    TEXT NOT NULL,
    stato       TEXT NOT NULL,          -- in_corso | completata | errore
    creata      REAL NOT NULL,
    completata  REAL,
    report      TEXT,                   -- JSON di Report.to_dict()
    errore      TEXT
);
CREATE INDEX IF NOT EXISTS analisi_host ON analisi (hostname, creata);

CREATE TABLE IF NOT EXISTS richieste (
    impronta    TEXT NOT NULL,
    quando      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS richieste_impronta ON richieste (impronta, quando);

CREATE TABLE IF NOT EXISTS impostazioni (
    chiave      TEXT PRIMARY KEY,
    valore      TEXT NOT NULL
);
"""


class Archivio:
    def __init__(self, percorso: Path | str) -> None:
        self.percorso = Path(percorso)
        self.percorso.parent.mkdir(parents=True, exist_ok=True)
        with self._connessione() as db:
            db.executescript(_SCHEMA)
            riga = db.execute("SELECT valore FROM impostazioni WHERE chiave = 'sale'").fetchone()
            if riga is None:
                self._sale = secrets.token_hex(16)
                db.execute("INSERT INTO impostazioni VALUES ('sale', ?)", (self._sale,))
            else:
                self._sale = riga[0]

    @contextmanager
    def _connessione(self) -> Iterator[sqlite3.Connection]:
        # Una connessione per operazione: sicuro con thread e processi multipli.
        db = sqlite3.connect(self.percorso, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA journal_mode=WAL")
            yield db
        finally:
            db.close()

    # ------------------------------------------------------------------ job

    def crea(self, url: str, hostname: str) -> str:
        id_ = uuid.uuid4().hex
        with self._connessione() as db:
            db.execute(
                "INSERT INTO analisi (id, url, hostname, stato, creata) VALUES (?, ?, ?, 'in_corso', ?)",
                (id_, url, hostname, time.time()),
            )
        return id_

    def completa(self, id_: str, report: dict[str, Any]) -> None:
        with self._connessione() as db:
            db.execute(
                "UPDATE analisi SET stato = 'completata', completata = ?, report = ? WHERE id = ?",
                (time.time(), json.dumps(report, ensure_ascii=False), id_),
            )

    def fallisci(self, id_: str, messaggio: str) -> None:
        with self._connessione() as db:
            db.execute(
                "UPDATE analisi SET stato = 'errore', completata = ?, errore = ? WHERE id = ?",
                (time.time(), messaggio, id_),
            )

    def leggi(self, id_: str) -> dict[str, Any] | None:
        with self._connessione() as db:
            riga = db.execute("SELECT * FROM analisi WHERE id = ?", (id_,)).fetchone()
        if riga is None:
            return None
        dati = dict(riga)
        dati["report"] = json.loads(dati["report"]) if dati["report"] else None
        if dati["stato"] == "in_corso" and time.time() - dati["creata"] > SCADENZA_JOB_SECONDI:
            dati["stato"] = "errore"
            dati["errore"] = "Analisi interrotta: riprovare."
        return dati

    def recente(self, hostname: str, minuti: int) -> str | None:
        """Id di un'analisi recente (completata o ancora in corso) dello stesso sito."""
        if minuti <= 0:
            return None
        limite = time.time() - minuti * 60
        limite_job = time.time() - SCADENZA_JOB_SECONDI
        with self._connessione() as db:
            riga = db.execute(
                "SELECT id FROM analisi WHERE hostname = ? AND creata >= ? AND "
                "(stato = 'completata' OR (stato = 'in_corso' AND creata >= ?)) "
                "ORDER BY creata DESC LIMIT 1",
                (hostname, limite, limite_job),
            ).fetchone()
        return riga["id"] if riga else None

    def storico(self, hostname: str, limite: int = 20) -> list[dict[str, Any]]:
        """Analisi completate di un sito, dalla piu' recente (base per il follow-up)."""
        with self._connessione() as db:
            righe = db.execute(
                "SELECT id, creata, report FROM analisi WHERE hostname = ? AND stato = 'completata' "
                "ORDER BY creata DESC LIMIT ?",
                (hostname, limite),
            ).fetchall()
        risultato = []
        for r in righe:
            report = json.loads(r["report"])
            risultato.append(
                {"id": r["id"], "creata": r["creata"], "punteggio": report["punteggio"], "voto": report["voto"]}
            )
        return risultato

    # ------------------------------------------------------------ limiti d'uso

    def impronta(self, ip: str) -> str:
        return hashlib.sha256(f"{self._sale}:{ip}".encode()).hexdigest()[:32]

    def registra_richiesta(self, impronta: str) -> None:
        adesso = time.time()
        with self._connessione() as db:
            db.execute("INSERT INTO richieste VALUES (?, ?)", (impronta, adesso))
            db.execute("DELETE FROM richieste WHERE quando < ?", (adesso - 86400,))

    def richieste_recenti(self, impronta: str, secondi: int = 3600) -> int:
        with self._connessione() as db:
            riga = db.execute(
                "SELECT COUNT(*) FROM richieste WHERE impronta = ? AND quando >= ?",
                (impronta, time.time() - secondi),
            ).fetchone()
        return int(riga[0])
