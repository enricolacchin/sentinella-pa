"""Raccolta passiva dei dati: HTTP/HTTPS, handshake TLS, DNS, ``/.well-known/``.

Qui si fa TUTTO l'I/O di rete del motore (tranne le interrogazioni DNS, che i
controlli eseguono tramite il resolver contenuto nel ``Context``). Le regole:

* solo cio' che farebbe un normale browser o un normale resolver DNS:
  GET della pagina richiesta (versione https e http), un handshake TLS sulla
  porta 443, GET di ``/.well-known/security.txt``, query DNS pubbliche;
* nessuna scansione di porte, nessuna enumerazione di percorsi, nessun payload;
* nessun errore di rete interrompe l'esecuzione: viene registrato nel
  ``Context`` e i controlli lo traducono in un esito "non verificabile".

Le strutture dati sono semplici dataclass, cosi' i test possono costruire un
``Context`` finto senza toccare la rete.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import time
import warnings
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

import requests
import tldextract

from sentinella import __version__
from sentinella.branding import user_agent

# Dimensione massima del corpo scaricato (la home di un sito PA sta ben sotto).
MAX_BYTES = 3 * 1024 * 1024
MAX_REDIRECT = 10

# Estrattore del dominio registrabile che usa SOLO la Public Suffix List
# inclusa nel pacchetto: nessuna richiesta di rete verso publicsuffix.org e
# risultati deterministici (essenziale per domini come comune.milano.it).
_ESTRATTORE = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


# ---------------------------------------------------------------------------
# Strutture dati
# ---------------------------------------------------------------------------


@dataclass
class HttpResponse:
    """Risposta HTTP ridotta all'essenziale, indipendente da ``requests``."""

    url: str                                   # URL finale dopo i redirect
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)  # chiavi in minuscolo
    set_cookies: list[str] = field(default_factory=list)   # header Set-Cookie grezzi
    text: str = ""
    # Catena dei redirect seguiti: (codice, URL) di ogni risposta intermedia.
    history: list[tuple[int, str]] = field(default_factory=list)

    def header(self, nome: str) -> str | None:
        return self.headers.get(nome.lower())

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").split(";")[0].strip().lower()


@dataclass
class Fetch:
    """Esito di una richiesta HTTP: una risposta oppure un errore."""

    url: str
    response: HttpResponse | None = None
    errore: str | None = None
    # Vero se il certificato non era valido e la pagina e' stata letta
    # comunque senza verifica, solo per poterne analizzare gli header.
    certificato_non_verificato: bool = False

    @property
    def ok(self) -> bool:
        return self.response is not None


@dataclass
class RedirectInfo:
    """Esito della visita in chiaro (http://) della stessa pagina."""

    url_iniziale: str
    url_finale: str | None = None
    porta_a_https: bool | None = None  # None = non verificabile
    catena: list[tuple[int, str]] = field(default_factory=list)
    errore: str | None = None
    http_non_raggiungibile: bool = False
    # Pagina servita in chiaro, conservata solo se NON c'e' redirect verso
    # HTTPS (serve come ripiego per i controlli sul contenuto).
    response: HttpResponse | None = None


@dataclass
class TlsInfo:
    """Dati ricavati da un singolo handshake TLS (come quello di un browser)."""

    host: str
    versione: str | None = None          # es. "TLSv1.3"
    cifrario: str | None = None
    certificato_valido: bool | None = None
    errore_verifica: str | None = None    # messaggio OpenSSL se non valido
    codice_verifica: int | None = None    # codice X509_V_ERR_*
    hostname_corrisponde: bool | None = None
    scadenza: str | None = None           # notAfter in ISO 8601
    giorni_alla_scadenza: int | None = None
    durata_giorni: int | None = None      # validita' totale (notAfter - notBefore)
    soggetto: str | None = None
    emittente: str | None = None
    san: list[str] = field(default_factory=list)
    errore: str | None = None             # handshake fallito / rete

    @property
    def handshake_riuscito(self) -> bool:
        return self.versione is not None


class DnsError(Exception):
    """Interrogazione DNS non riuscita (timeout, server non raggiungibili, ...)."""


class DnsResolver(Protocol):
    """Interfaccia minima del resolver usato dai controlli.

    ``query`` restituisce i record come stringhe; una lista vuota se il nome
    non esiste o non ha record di quel tipo; solleva ``DnsError`` se la
    risposta non e' ottenibile.
    """

    def query(self, nome: str, tipo: str) -> list[str]: ...


class DnsPythonResolver:
    """Resolver reale basato su dnspython (usa i resolver configurati nel sistema)."""

    def __init__(self, timeout: float = 5.0) -> None:
        import dns.flags
        import dns.resolver

        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout
        self._resolver.timeout = timeout
        # Chiede esplicitamente le informazioni DNSSEC (flag DO), come farebbe
        # un resolver validante: e' una normale query pubblica.
        self._resolver.use_edns(0, dns.flags.DO, 1232)

    def query(self, nome: str, tipo: str) -> list[str]:
        import dns.exception
        import dns.resolver

        try:
            risposta = self._resolver.resolve(nome, tipo, raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            raise DnsError(f"{tipo} {nome}: {exc.__class__.__name__}") from exc
        except dns.exception.DNSException as exc:
            raise DnsError(f"{tipo} {nome}: {exc}") from exc
        if risposta.rrset is None:
            return []
        valori: list[str] = []
        for rdata in risposta.rrset:
            if tipo.upper() == "TXT":
                valori.append(b"".join(rdata.strings).decode("utf-8", errors="replace"))
            else:
                valori.append(rdata.to_text())
        return valori


@dataclass
class Context:
    """Tutto cio' che i controlli possono leggere. Nessun controllo fa altro I/O
    se non le query DNS tramite ``dns``."""

    input_url: str
    url: str                      # URL normalizzato (https)
    hostname: str                 # host richiesto
    dominio: str                  # dominio registrabile (per SPF/DMARC/DNSSEC)
    https: Fetch
    http: RedirectInfo
    tls: TlsInfo
    security_txt: Fetch
    dns: DnsResolver
    timeout: float = 10.0
    errori: list[str] = field(default_factory=list)

    @property
    def home(self) -> HttpResponse | None:
        """La pagina scaricata: preferibilmente in HTTPS, altrimenti in chiaro."""
        if self.https.response is not None:
            return self.https.response
        return self.http.response

    @property
    def home_valutabile(self) -> HttpResponse | None:
        """La pagina, solo se e' quella vista dai cittadini (codice HTTP < 400).

        Molti siti rispondono 403 ai client che non si dichiarano browser, o 5xx
        per un guasto: giudicare header, cookie o CMS di quella risposta
        produrrebbe falsi positivi, quindi i controlli sul contenuto si fermano.
        """
        home = self.home
        if home is None or home.status_code >= 400:
            return None
        return home

    @property
    def motivo_home_non_valutabile(self) -> str:
        home = self.home
        if home is None:
            return "Pagina non scaricata: " + ("; ".join(self.errori) or "errore di rete")
        return (
            f"Il sito ha risposto HTTP {home.status_code} a questa verifica (probabile blocco "
            "dei client automatici o errore del server): la pagina ricevuta non e' quella "
            "vista dai cittadini, quindi questo aspetto non e' stato valutato."
        )

    @property
    def final_url(self) -> str:
        if self.https.response is not None:
            return self.https.response.url
        if self.http.url_finale:
            return self.http.url_finale
        return self.url

    @property
    def final_hostname(self) -> str:
        return urlsplit(self.final_url).hostname or self.hostname


# ---------------------------------------------------------------------------
# Utilita' sugli URL
# ---------------------------------------------------------------------------


def normalizza_url(url: str) -> str:
    """Restituisce l'URL in forma ``https://host[:porta]/percorso``.

    Accetta anche un semplice nome di dominio. Solleva ``ValueError`` per input
    non validi o schemi diversi da http/https.
    """
    url = (url or "").strip()
    if not url:
        raise ValueError("URL vuoto")
    if "://" not in url:
        url = "https://" + url
    parti = urlsplit(url)
    if parti.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Schema non supportato: {parti.scheme}")
    host = (parti.hostname or "").rstrip(".").lower()
    if not host or " " in host:
        raise ValueError(f"Hostname non valido in: {url}")
    try:
        porta = parti.port
    except ValueError as exc:
        raise ValueError(f"Porta non valida in: {url}") from exc
    if ":" in host:  # indirizzo IPv6: nell'URL va tra parentesi quadre
        host = f"[{host}]"
    netloc = host if porta in (None, 80, 443) else f"{host}:{porta}"
    percorso = parti.path or "/"
    return urlunsplit(("https", netloc, percorso, parti.query, ""))


def dominio_registrabile(hostname: str) -> str:
    """Dominio registrabile secondo la Public Suffix List.

    ``www.comune.milano.it`` -> ``comune.milano.it`` (perche' ``milano.it`` e'
    un suffisso pubblico), ``www.agid.gov.it`` -> ``agid.gov.it``.
    """
    try:
        ipaddress.ip_address(hostname)
        return hostname  # indirizzo IP: nessun dominio
    except ValueError:
        pass
    risultato = _ESTRATTORE(hostname)
    dominio = getattr(risultato, "top_domain_under_public_suffix", None)
    if dominio is None:  # versioni di tldextract precedenti alla 5.3
        dominio = risultato.registered_domain
    if not dominio:
        # TLD non presente nella Public Suffix List (es. domini di test):
        # si usano le ultime due etichette.
        dominio = ".".join(hostname.split(".")[-2:])
    return dominio


def _con_schema(url_https: str, schema: str) -> str:
    parti = urlsplit(url_https)
    return urlunsplit((schema, parti.netloc, parti.path, parti.query, ""))


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


def nuova_sessione() -> requests.Session:
    """Sessione HTTP con User-Agent trasparente."""
    sessione = requests.Session()
    sessione.max_redirects = MAX_REDIRECT
    sessione.headers.update(
        {
            "User-Agent": user_agent(__version__),
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
            "Accept-Language": "it-IT,it;q=0.9",
        }
    )
    return sessione


def _set_cookie_grezzi(risposta: requests.Response) -> list[str]:
    """Estrae gli header Set-Cookie uno per uno (requests li unirebbe con virgole)."""
    raw_headers = getattr(getattr(risposta, "raw", None), "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        return list(raw_headers.getlist("Set-Cookie"))
    valore = risposta.headers.get("Set-Cookie")
    return [valore] if valore else []


def _leggi_corpo(risposta: requests.Response) -> str:
    """Legge il corpo fino a MAX_BYTES e lo decodifica in modo tollerante."""
    blocchi: list[bytes] = []
    letti = 0
    for blocco in risposta.iter_content(chunk_size=65536):
        blocchi.append(blocco)
        letti += len(blocco)
        if letti >= MAX_BYTES:
            break
    contenuto = b"".join(blocchi)[:MAX_BYTES]
    codifica = risposta.encoding or "utf-8"
    try:
        return contenuto.decode(codifica, errors="replace")
    except LookupError:
        return contenuto.decode("utf-8", errors="replace")


def _converti(risposta: requests.Response, leggi_corpo: bool = True) -> HttpResponse:
    cookie: list[str] = []
    for intermedia in risposta.history:
        cookie.extend(_set_cookie_grezzi(intermedia))
    cookie.extend(_set_cookie_grezzi(risposta))
    return HttpResponse(
        url=risposta.url,
        status_code=risposta.status_code,
        headers={k.lower(): v for k, v in risposta.headers.items()},
        set_cookies=cookie,
        text=_leggi_corpo(risposta) if leggi_corpo else "",
        history=[(r.status_code, r.url) for r in risposta.history],
    )


def scarica(sessione: requests.Session, url: str, timeout: float) -> Fetch:
    """GET passivo di un URL, seguendo i redirect come un browser.

    Se il certificato non e' valido, la pagina viene riletta senza verifica
    unicamente per poterne analizzare header e contenuto: l'anomalia del
    certificato viene comunque segnalata dal controllo TLS.
    """
    esito = Fetch(url=url)
    try:
        with sessione.get(url, timeout=timeout, allow_redirects=True, stream=True) as r:
            esito.response = _converti(r)
        return esito
    except requests.exceptions.SSLError as exc:
        esito.errore = f"Errore TLS: {_breve(exc)}"
    except requests.exceptions.RequestException as exc:
        esito.errore = f"{exc.__class__.__name__}: {_breve(exc)}"
        return esito

    # Secondo tentativo senza verifica del certificato (solo dopo SSLError).
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with sessione.get(
                url, timeout=timeout, allow_redirects=True, stream=True, verify=False
            ) as r:
                esito.response = _converti(r)
                esito.certificato_non_verificato = True
    except requests.exceptions.RequestException:
        pass  # resta l'errore TLS originale
    return esito


def verifica_redirect(sessione: requests.Session, url_http: str, timeout: float) -> RedirectInfo:
    """Visita la versione in chiaro e osserva dove portano i redirect."""
    info = RedirectInfo(url_iniziale=url_http)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with sessione.get(url_http, timeout=timeout, allow_redirects=True, stream=True) as r:
                info.url_finale = r.url
                info.catena = [(h.status_code, h.url) for h in r.history]
                info.porta_a_https = urlsplit(r.url).scheme == "https"
                if not info.porta_a_https:
                    info.response = _converti(r)
    except requests.exceptions.SSLError:
        # Una richiesta partita in http:// che fallisce sul TLS e' stata per
        # forza reindirizzata verso https: il redirect esiste.
        info.porta_a_https = True
        info.errore = "Redirect verso HTTPS presente, ma la connessione HTTPS non e' valida"
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
        info.http_non_raggiungibile = True
        info.errore = f"{exc.__class__.__name__}: {_breve(exc)}"
    except requests.exceptions.RequestException as exc:
        info.errore = f"{exc.__class__.__name__}: {_breve(exc)}"
    return info


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------


def _contesto_ssl_verificante() -> ssl.SSLContext:
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:  # pragma: no cover - certifi arriva con requests
        return ssl.create_default_context()


def _nome_da_rdn(rdn: tuple) -> str:
    campi = {k: v for gruppo in rdn for (k, v) in gruppo}
    return campi.get("commonName") or campi.get("organizationName") or ""


def handshake_tls(host: str, porta: int = 443, timeout: float = 10.0) -> TlsInfo:
    """Un singolo handshake TLS, come quello che apre un browser.

    Se la verifica del certificato fallisce, ripete l'handshake senza verifica
    solo per conoscere la versione di protocollo negoziata.
    """
    info = TlsInfo(host=host)
    contesto = _contesto_ssl_verificante()
    try:
        with socket.create_connection((host, porta), timeout=timeout) as sock:
            with contesto.wrap_socket(sock, server_hostname=host) as tls:
                info.versione = tls.version()
                cifrario = tls.cipher()
                info.cifrario = cifrario[0] if cifrario else None
                cert = tls.getpeercert() or {}
        info.certificato_valido = True
        info.hostname_corrisponde = True
        _leggi_certificato(info, cert)
        return info
    except ssl.SSLCertVerificationError as exc:
        info.certificato_valido = False
        info.codice_verifica = getattr(exc, "verify_code", None)
        info.errore_verifica = getattr(exc, "verify_message", None) or _breve(exc)
        # 62 = X509_V_ERR_HOSTNAME_MISMATCH
        info.hostname_corrisponde = info.codice_verifica != 62
    except ssl.SSLError as exc:
        info.errore = f"Handshake TLS fallito: {_breve(exc)}"
        return info
    except OSError as exc:
        info.errore = f"Connessione alla porta {porta} non riuscita: {_breve(exc)}"
        return info

    # Certificato non valido: secondo handshake senza verifica, solo per la versione.
    contesto_libero = ssl.create_default_context()
    contesto_libero.check_hostname = False
    contesto_libero.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, porta), timeout=timeout) as sock:
            with contesto_libero.wrap_socket(sock, server_hostname=host) as tls:
                info.versione = tls.version()
                cifrario = tls.cipher()
                info.cifrario = cifrario[0] if cifrario else None
    except (ssl.SSLError, OSError) as exc:
        info.errore = f"Handshake TLS non verificato fallito: {_breve(exc)}"
    return info


def _leggi_certificato(info: TlsInfo, cert: dict) -> None:
    not_after = cert.get("notAfter")
    if not_after:
        try:
            secondi = ssl.cert_time_to_seconds(not_after)
            info.scadenza = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(secondi))
            info.giorni_alla_scadenza = int((secondi - time.time()) // 86400)
            not_before = cert.get("notBefore")
            if not_before:
                inizio = ssl.cert_time_to_seconds(not_before)
                info.durata_giorni = int((secondi - inizio) // 86400)
        except ValueError:
            pass
    if cert.get("subject"):
        info.soggetto = _nome_da_rdn(cert["subject"])
    if cert.get("issuer"):
        info.emittente = _nome_da_rdn(cert["issuer"])
    info.san = [v for (k, v) in cert.get("subjectAltName", ()) if k == "DNS"]


# ---------------------------------------------------------------------------
# Costruzione del contesto
# ---------------------------------------------------------------------------


def _breve(exc: BaseException, lunghezza: int = 200) -> str:
    testo = str(exc) or exc.__class__.__name__
    return testo if len(testo) <= lunghezza else testo[: lunghezza - 1] + "…"


def costruisci_contesto(
    url: str,
    timeout: float = 10.0,
    sessione: requests.Session | None = None,
    resolver: DnsResolver | None = None,
) -> Context:
    """Esegue tutte le raccolte passive e restituisce il ``Context``.

    Solleva ``ValueError`` solo se l'URL e' formalmente non valido; qualsiasi
    errore di rete viene invece registrato nel contesto.
    """
    url_norm = normalizza_url(url)
    host = urlsplit(url_norm).hostname or ""
    sessione = sessione or nuova_sessione()
    resolver = resolver or DnsPythonResolver(timeout=min(timeout, 8.0))
    errori: list[str] = []

    # 1. La pagina in HTTPS (seguendo i redirect).
    https = scarica(sessione, url_norm, timeout)
    if https.errore:
        errori.append(f"HTTPS: {https.errore}")

    # 2. La stessa pagina in chiaro, per verificare il redirect verso HTTPS.
    http = verifica_redirect(sessione, _con_schema(url_norm, "http"), timeout)
    if http.errore:
        errori.append(f"HTTP: {http.errore}")

    # 3. Handshake TLS sull'host effettivamente servito all'utente.
    host_tls = host
    if https.response is not None:
        host_tls = urlsplit(https.response.url).hostname or host
    porta = urlsplit(url_norm).port or 443
    tls = handshake_tls(host_tls, porta=porta, timeout=timeout)
    if tls.errore:
        errori.append(f"TLS: {tls.errore}")

    # 4. security.txt nella posizione standard (RFC 9116).
    base = https.response.url if https.response is not None else url_norm
    parti = urlsplit(base)
    url_sec = urlunsplit(("https", parti.netloc, "/.well-known/security.txt", "", ""))
    security_txt = scarica(sessione, url_sec, timeout)

    return Context(
        input_url=url,
        url=url_norm,
        hostname=host,
        dominio=dominio_registrabile(host),
        https=https,
        http=http,
        tls=tls,
        security_txt=security_txt,
        dns=resolver,
        timeout=timeout,
        errori=errori,
    )
