"""Interfaccia web di Sentinella PA (API HTTP).

E' un altro "consumatore" del motore, come la CLI: riceve un URL, chiama
``sentinella.core.analizza`` in un job in background, salva il ``Report`` su
SQLite e restituisce i documenti prodotti da ``sentinella.report``. Nessuna
logica di analisi o di rendering e' duplicata qui.

Il frontend statico (cartella ``web/`` del repository) puo' essere pubblicato
su GitHub Pages e chiama questa API, ospitata su un hosting Python (es. cPanel
con Passenger, vedi ``passenger_wsgi.py``).
"""

from sentinella.web.app import crea_app

__all__ = ["crea_app"]
