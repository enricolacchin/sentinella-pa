"""Sentinella PA — verifica passiva della sicurezza dei siti della Pubblica Amministrazione.

Il pacchetto e' diviso in tre strati indipendenti:

* ``sentinella.core``   — il motore di analisi (``analizza(url) -> Report``);
* ``sentinella.report`` — il rendering condiviso (testo, JSON, HTML, report, bozza PEC);
* ``sentinella.cli``    — il front-end a riga di comando, un sottile wrapper.

Questo modulo non deve importare nulla dagli strati sottostanti: contiene solo
la versione, cosi' che chiunque possa leggerla senza effetti collaterali.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
