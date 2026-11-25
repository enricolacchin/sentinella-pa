"""API HTTP di Sentinella PA (FastAPI).

Flusso: ``POST /api/analisi`` con l'URL -> risposta immediata con l'id del job
-> il browser interroga ``GET /api/analisi/{id}`` finche' lo stato non e'
"completata" -> riceve il report e i documenti gia' pronti (HTML, report
tecnico, report per il sindaco, bozza PEC), prodotti da ``sentinella.report``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from sentinella import __version__
from sentinella.branding import firma
from sentinella.core import analizza
from sentinella.core.models import Report
from sentinella.report import (
    DatiPec,
    render_html,
    render_pec,
    render_report_sindaco,
    render_report_tecnico,
)
from sentinella.web.archivio import Archivio
from sentinella.web.config import Impostazioni
from sentinella.web.sicurezza import BersaglioNonConsentito, Risolutore, risolvi, sessione_protetta, valida_bersaglio

log = logging.getLogger("sentinella.web")

# Funzione che esegue l'analisi: (url, timeout) -> Report. Sostituibile nei test.
Analizzatore = Callable[[str, float], Report]

# Header di sicurezza applicati a ogni risposta: lo strumento deve rispettare
# per primo le buone pratiche che verifica.
HEADER_SICUREZZA = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}
CSP_FRONTEND = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; frame-src 'self' blob:; object-src 'none'; "
    "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)


class RichiestaAnalisi(BaseModel):
    url: str = Field(min_length=3, max_length=300)


class RichiestaPec(BaseModel):
    ente: str = Field("", max_length=200)
    pec_ente: str = Field("", max_length=200)
    rtd: str = Field("", max_length=200)
    mittente: str = Field("", max_length=200)
    contatto_mittente: str = Field("", max_length=300)


def _documenti(report: Report) -> dict[str, str]:
    return {
        "html": render_html(report),
        "tecnico": render_report_tecnico(report),
        "sindaco": render_report_sindaco(report),
        "pec": render_pec(report),
    }


def crea_app(
    impostazioni: Impostazioni | None = None,
    *,
    analizzatore: Analizzatore | None = None,
    risolutore: Risolutore = risolvi,
) -> FastAPI:
    imp = impostazioni or Impostazioni.da_ambiente()
    archivio = Archivio(imp.database)
    esecutore = ThreadPoolExecutor(max_workers=max(1, imp.analisi_parallele), thread_name_prefix="analisi")

    def analisi_predefinita(url: str, timeout: float) -> Report:
        return analizza(url, timeout=timeout, sessione=sessione_protetta(risolutore))

    esegui = analizzatore or analisi_predefinita

    app = FastAPI(
        title="Sentinella PA",
        version=__version__,
        description="Verifica passiva della sicurezza dei siti della Pubblica Amministrazione.",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        redoc_url=None,
    )
    app.state.archivio = archivio
    app.state.impostazioni = imp

    if imp.cors_origini:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=imp.cors_origini,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type"],
            max_age=3600,
        )

    @app.middleware("http")
    async def header_sicurezza(request: Request, call_next):
        risposta = await call_next(request)
        for nome, valore in HEADER_SICUREZZA.items():
            risposta.headers.setdefault(nome, valore)
        if request.url.path.startswith("/api/"):
            risposta.headers["Cache-Control"] = "no-store"
        else:
            risposta.headers.setdefault("Content-Security-Policy", CSP_FRONTEND)
        if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
            risposta.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        return risposta

    def ip_richiedente(request: Request) -> str:
        if imp.dietro_proxy:
            inoltrato = request.headers.get("x-forwarded-for", "")
            if inoltrato:
                return inoltrato.split(",")[0].strip()
        return request.client.host if request.client else "sconosciuto"

    def lavoro(id_: str, url: str) -> None:
        try:
            report = esegui(url, imp.timeout)
            archivio.completa(id_, report.to_dict())
        except Exception:  # un errore imprevisto non deve lasciare il job appeso
            log.exception("Analisi %s di %s non riuscita", id_, url)
            archivio.fallisci(id_, "Errore interno durante l'analisi.")

    # -------------------------------------------------------------- endpoint

    @app.get("/api/salute")
    def salute() -> dict[str, Any]:
        return {"stato": "ok", "versione": __version__, "generato_con": firma(__version__)}

    @app.get("/api/configurazione")
    def configurazione() -> dict[str, Any]:
        return {
            "versione": __version__,
            "domini_consentiti": imp.domini_consentiti,
            "limite_per_ora": imp.limite_per_ora,
            "generato_con": firma(__version__),
        }

    @app.post("/api/analisi", status_code=202)
    def avvia(richiesta: RichiestaAnalisi, request: Request) -> JSONResponse:
        impronta = archivio.impronta(ip_richiedente(request))
        if imp.limite_per_ora and archivio.richieste_recenti(impronta) >= imp.limite_per_ora:
            raise HTTPException(
                status_code=429,
                detail=f"Limite di {imp.limite_per_ora} analisi l'ora raggiunto. Riprova piu' tardi.",
            )
        try:
            url = valida_bersaglio(richiesta.url, imp.domini_consentiti, risolutore)
        except BersaglioNonConsentito as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        archivio.registra_richiesta(impronta)

        hostname = urlsplit(url).hostname or ""
        esistente = archivio.recente(hostname, imp.riuso_minuti)
        if esistente:
            dati = archivio.leggi(esistente)
            stato = dati["stato"] if dati else "in_corso"
            return JSONResponse({"id": esistente, "stato": stato, "riusata": True}, status_code=202)

        id_ = archivio.crea(url, hostname)
        esecutore.submit(lavoro, id_, url)
        return JSONResponse({"id": id_, "stato": "in_corso", "riusata": False}, status_code=202)

    def _carica(id_: str) -> dict[str, Any]:
        if not id_.isalnum() or len(id_) > 64:
            raise HTTPException(status_code=404, detail="Analisi non trovata")
        dati = archivio.leggi(id_)
        if dati is None:
            raise HTTPException(status_code=404, detail="Analisi non trovata")
        return dati

    @app.get("/api/analisi/{id_}")
    def stato(id_: str) -> dict[str, Any]:
        dati = _carica(id_)
        risposta: dict[str, Any] = {
            "id": dati["id"],
            "url": dati["url"],
            "stato": dati["stato"],
            "errore": dati["errore"],
        }
        if dati["stato"] == "completata" and dati["report"]:
            report = Report.from_dict(dati["report"])
            risposta["report"] = report.to_dict()
            risposta["documenti"] = _documenti(report)
        return risposta

    @app.post("/api/analisi/{id_}/pec")
    def pec(id_: str, richiesta: RichiestaPec) -> dict[str, str]:
        dati = _carica(id_)
        if dati["stato"] != "completata" or not dati["report"]:
            raise HTTPException(status_code=409, detail="Analisi non ancora completata")
        report = Report.from_dict(dati["report"])
        return {"testo": render_pec(report, DatiPec(**richiesta.model_dump()))}

    # Frontend statico (facoltativo): utile in locale o per pubblicare tutto
    # sullo stesso dominio. Su GitHub Pages il frontend vive separatamente.
    if imp.frontend and imp.frontend.is_dir():
        app.mount("/", StaticFiles(directory=imp.frontend, html=True), name="frontend")

    return app
