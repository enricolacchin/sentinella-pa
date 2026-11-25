"""Punto di ingresso per cPanel ("Setup Python App", Phusion Passenger).

Passenger parla WSGI, FastAPI e' ASGI: ``a2wsgi`` fa da ponte. Nella pagina
"Setup Python App" di cPanel indicare:

* Application startup file: ``passenger_wsgi.py``
* Application Entry point:  ``application``

La configurazione si fa con le variabili d'ambiente SENTINELLA_* (vedi
``docs/pubblicazione.md``).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from a2wsgi import ASGIMiddleware  # noqa: E402

from sentinella.web import crea_app  # noqa: E402

application = ASGIMiddleware(crea_app())
