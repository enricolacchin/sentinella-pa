"""Costante unica di firma/attribuzione, usata da tutti gli output.

Nessun template o modulo di rendering deve scrivere a mano la riga di firma:
deve sempre passare da :func:`firma`.
"""

# Nota di attribuzione protetta dalla licenza EUPL-1.2 (art. 5):
# non va rimossa dagli output ne' dalle versioni ridistribuite.
NOME = "Sentinella PA"
AUTORE = ""   # opzionale, es. "a cura di Enrico Lacchin" o "Arton Business"
URL = "https://github.com/enricolacchin/sentinella-pa"


def firma(versione: str) -> str:
    """Restituisce la riga di attribuzione da riportare in calce a ogni output."""
    base = f"Report generato con {NOME} v{versione} — {URL}"
    return f"{base} · {AUTORE}" if AUTORE else base


def user_agent(versione: str) -> str:
    """User-Agent trasparente e non ingannevole usato per tutte le richieste HTTP."""
    return f"SentinellaPA/{versione} (+controllo passivo sicurezza; {URL})"
