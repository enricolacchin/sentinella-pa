"""Strumenti comuni ai test: un resolver DNS finto e un costruttore di Context.

Nessun test usa la rete: le risposte HTTP, l'esito TLS e il DNS sono tutti finti.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinella.core.context import (
    Context,
    DnsError,
    Fetch,
    HttpResponse,
    RedirectInfo,
    TlsInfo,
)

FIXTURES = Path(__file__).parent / "fixtures"

HOST = "www.comune.esempio.example"
DOMINIO = "esempio.example"
URL = f"https://{HOST}/"


def leggi_fixture(nome: str) -> str:
    return (FIXTURES / nome).read_text(encoding="utf-8")


class FakeResolver:
    """Resolver DNS finto: ``record[(nome, tipo)] = [valori]``; i nomi in
    ``guasti`` sollevano DnsError (come un timeout)."""

    def __init__(
        self,
        record: dict[tuple[str, str], list[str]] | None = None,
        guasti: set[str] | None = None,
    ) -> None:
        self.record = record or {}
        self.guasti = guasti or set()
        self.interrogazioni: list[tuple[str, str]] = []

    def query(self, nome: str, tipo: str) -> list[str]:
        self.interrogazioni.append((nome, tipo))
        if nome in self.guasti:
            raise DnsError(f"{tipo} {nome}: Timeout")
        return list(self.record.get((nome, tipo.upper()), []))


# Header di una configurazione ben fatta.
HEADER_BUONI = {
    "content-type": "text/html; charset=utf-8",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "SAMEORIGIN",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=(), camera=()",
    "server": "nginx",
}

DNS_BUONO = {
    (DOMINIO, "TXT"): ["v=spf1 include:_spf.esempio.example -all"],
    (DOMINIO, "MX"): ["10 mx.esempio.example."],
    (f"_dmarc.{DOMINIO}", "TXT"): ["v=DMARC1; p=reject; rua=mailto:dmarc@esempio.example"],
    (f"selector1._domainkey.{DOMINIO}", "TXT"): ["v=DKIM1; k=rsa; p=MIIBIjANBg"],
    (DOMINIO, "DNSKEY"): ["257 3 13 abc"],
    (DOMINIO, "DS"): ["12345 13 2 abcdef"],
}


def risposta(
    url: str = URL,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    text: str = "",
    set_cookies: list[str] | None = None,
) -> HttpResponse:
    return HttpResponse(
        url=url,
        status_code=status_code,
        headers={k.lower(): v for k, v in (headers if headers is not None else HEADER_BUONI).items()},
        set_cookies=set_cookies or [],
        text=text,
    )


def tls_buono(**modifiche: object) -> TlsInfo:
    tls = TlsInfo(
        host=HOST,
        versione="TLSv1.3",
        cifrario="TLS_AES_256_GCM_SHA384",
        certificato_valido=True,
        hostname_corrisponde=True,
        scadenza="2027-06-01T00:00:00Z",
        giorni_alla_scadenza=180,
        durata_giorni=365,
        soggetto=HOST,
        emittente="CA di Esempio",
    )
    for k, v in modifiche.items():
        setattr(tls, k, v)
    return tls


def crea_contesto(
    *,
    home: HttpResponse | None = None,
    https_errore: str | None = None,
    certificato_non_verificato: bool = False,
    http: RedirectInfo | None = None,
    tls: TlsInfo | None = None,
    security_txt: HttpResponse | None = None,
    security_txt_errore: str | None = None,
    dns: dict[tuple[str, str], list[str]] | None = None,
    dns_guasti: set[str] | None = None,
) -> Context:
    """Context finto: per default rappresenta un sito configurato bene."""
    if home is None and https_errore is None:
        home = risposta(text=leggi_fixture("home_semplice.html"))
    if http is None:
        http = RedirectInfo(
            url_iniziale=f"http://{HOST}/",
            url_finale=URL,
            porta_a_https=True,
            catena=[(301, f"http://{HOST}/")],
        )
    if security_txt is None and security_txt_errore is None:
        security_txt = risposta(
            url=f"https://{HOST}/.well-known/security.txt",
            headers={"content-type": "text/plain; charset=utf-8"},
            text=leggi_fixture("security_valido.txt"),
        )
    return Context(
        input_url=HOST,
        url=URL,
        hostname=HOST,
        dominio=DOMINIO,
        https=Fetch(
            url=URL,
            response=home,
            errore=https_errore,
            certificato_non_verificato=certificato_non_verificato,
        ),
        http=http,
        tls=tls or tls_buono(),
        security_txt=Fetch(
            url=f"https://{HOST}/.well-known/security.txt",
            response=security_txt,
            errore=security_txt_errore,
        ),
        dns=FakeResolver(DNS_BUONO if dns is None else dns, dns_guasti),
    )


@pytest.fixture
def ctx_buono() -> Context:
    return crea_contesto()
