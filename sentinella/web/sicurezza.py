"""Protezioni del servizio pubblico: validazione del bersaglio e anti-SSRF.

Un servizio che contatta URL scelti da chiunque puo' essere usato per
raggiungere indirizzi interni del server che lo ospita (SSRF: 127.0.0.1,
reti private, metadati del cloud). Per questo:

* il bersaglio deve essere un nome di dominio pubblico, su porta 80/443,
  con un suffisso consentito dalla configurazione;
* ogni indirizzo IP a cui il nome risolve deve essere pubblico;
* la sessione HTTP ripete il controllo a OGNI richiesta, compresi i redirect,
  cosi' un sito non puo' reindirizzare l'analisi verso la rete interna.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter

from sentinella.core.context import normalizza_url, nuova_sessione


class BersaglioNonConsentito(ValueError):
    """Il sito richiesto non puo' essere analizzato da questo servizio."""


Risolutore = Callable[[str], list[str]]


def risolvi(host: str) -> list[str]:
    """Indirizzi IP del nome (A e AAAA) tramite il resolver di sistema."""
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
    except socket.gaierror as exc:
        raise BersaglioNonConsentito(f"Il dominio {host} non esiste o non risolve") from exc


def controlla_host(host: str, risolutore: Risolutore = risolvi) -> None:
    """Solleva BersaglioNonConsentito se l'host risolve verso indirizzi non pubblici."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass  # e' un nome di dominio, come previsto
    else:
        raise BersaglioNonConsentito("Indicare un nome di dominio, non un indirizzo IP")
    indirizzi = risolutore(host)
    if not indirizzi:
        raise BersaglioNonConsentito(f"Il dominio {host} non risolve")
    for ip in indirizzi:
        if not ipaddress.ip_address(ip.split("%")[0]).is_global:
            raise BersaglioNonConsentito(f"Il dominio {host} punta a un indirizzo non pubblico")


def valida_bersaglio(
    url: str,
    domini_consentiti: list[str],
    risolutore: Risolutore = risolvi,
) -> str:
    """Normalizza e valida l'URL richiesto; restituisce l'URL normalizzato."""
    try:
        normalizzato = normalizza_url(url)
    except ValueError as exc:
        raise BersaglioNonConsentito(str(exc)) from exc
    parti = urlsplit(normalizzato)
    host = parti.hostname or ""
    if parti.port not in (None, 80, 443):  # porta gia' validata da normalizza_url
        raise BersaglioNonConsentito("Sono analizzabili solo siti sulle porte standard 80 e 443")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise BersaglioNonConsentito("Indicare un nome di dominio, non un indirizzo IP")
    if "." not in host:
        raise BersaglioNonConsentito("Indicare un nome di dominio completo (es. www.comune.esempio.it)")
    if domini_consentiti and not any(
        host == s or host.endswith("." + s) for s in (d.lower().lstrip(".") for d in domini_consentiti)
    ):
        elenco = ", ".join("." + d.lstrip(".") for d in domini_consentiti)
        raise BersaglioNonConsentito(f"Questo servizio analizza solo domini {elenco}")
    controlla_host(host, risolutore)
    return normalizzato


class _AdapterProtetto(HTTPAdapter):
    """Adapter che verifica l'host prima di ogni richiesta (redirect compresi)."""

    def __init__(self, risolutore: Risolutore, **kwargs) -> None:
        self._risolutore = risolutore
        super().__init__(**kwargs)

    def send(self, request: requests.PreparedRequest, **kwargs):  # type: ignore[override]
        parti = urlsplit(request.url or "")
        if parti.port not in (None, 80, 443):
            raise requests.exceptions.InvalidURL(f"Porta non consentita: {parti.port}")
        try:
            controlla_host(parti.hostname or "", self._risolutore)
        except BersaglioNonConsentito as exc:
            raise requests.exceptions.InvalidURL(f"Destinazione non consentita: {exc}") from exc
        return super().send(request, **kwargs)


def sessione_protetta(risolutore: Risolutore = risolvi) -> requests.Session:
    """La normale sessione del motore, con il controllo anti-SSRF su ogni richiesta."""
    sessione = nuova_sessione()
    adapter = _AdapterProtetto(risolutore)
    sessione.mount("http://", adapter)
    sessione.mount("https://", adapter)
    return sessione
