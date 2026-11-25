"""Registro dei controlli.

Ogni controllo e' una funzione ``controlla(ctx: Context) -> list[Finding]``
senza effetti di presentazione. Per aggiungerne uno basta scrivere il modulo e
registrarlo qui: il motore li esegue tutti, nell'ordine indicato.
"""

from __future__ import annotations

from collections.abc import Callable

from sentinella.core.context import Context
from sentinella.core.models import Finding

from . import cms, cookies, dnssec, email_auth, https_tls, security_headers, security_txt, third_party

Controllo = Callable[[Context], list[Finding]]

# (nome del controllo, funzione). Il nome finisce nel campo ``categoria``.
REGISTRO: list[tuple[str, Controllo]] = [
    ("https_tls", https_tls.controlla),
    ("security_headers", security_headers.controlla),
    ("email_auth", email_auth.controlla),
    ("dnssec", dnssec.controlla),
    ("security_txt", security_txt.controlla),
    ("cms", cms.controlla),
    ("cookies", cookies.controlla),
    ("third_party", third_party.controlla),
]

# Etichette leggibili per i report.
ETICHETTE: dict[str, str] = {
    "https_tls": "HTTPS e certificato",
    "security_headers": "Header di sicurezza",
    "email_auth": "Protezione della posta (SPF, DMARC, DKIM)",
    "dnssec": "DNSSEC",
    "security_txt": "Canale per le segnalazioni (security.txt)",
    "cms": "CMS",
    "cookies": "Cookie",
    "third_party": "Risorse di terze parti",
}

__all__ = ["REGISTRO", "ETICHETTE", "Controllo"]
