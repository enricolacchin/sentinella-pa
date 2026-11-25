"""DNSSEC: il dominio firma le proprie risposte DNS?

Si interrogano due record pubblici: DNSKEY (le chiavi pubblicate dalla zona)
e DS (l'impronta della chiave depositata presso il registro del TLD, che
chiude la catena di fiducia).
"""

from __future__ import annotations

from sentinella.core.context import Context, DnsError
from sentinella.core.models import Finding, Severity, Status

RIF_DNSSEC = "RFC 4033-4035 (DNSSEC); Registro .it — documentazione DNSSEC"


def controlla(ctx: Context) -> list[Finding]:
    dominio = ctx.dominio
    base = dict(id="dnssec", titolo=f"DNSSEC sul dominio {dominio}", riferimento=RIF_DNSSEC)
    try:
        dnskey = ctx.dns.query(dominio, "DNSKEY")
        ds = ctx.dns.query(dominio, "DS")
    except DnsError as exc:
        return [
            Finding(
                **base,
                status=Status.ERRORE,
                severita=Severity.MEDIA,
                dettaglio="Interrogazione DNS non riuscita: DNSSEC non verificabile.",
                evidenza=str(exc),
            )
        ]
    evidenza = f"DNSKEY: {len(dnskey)} record · DS presso il registro: {len(ds)} record"
    if dnskey and ds:
        return [
            Finding(
                **base,
                status=Status.OK,
                severita=Severity.MEDIA,
                dettaglio="Il dominio e' firmato con DNSSEC e la catena di fiducia e' completa.",
                evidenza=evidenza,
            )
        ]
    if dnskey and not ds:
        return [
            Finding(
                **base,
                status=Status.ATTENZIONE,
                severita=Severity.MEDIA,
                dettaglio=(
                    "La zona pubblica chiavi DNSSEC ma il record DS non e' depositato presso "
                    "il registro: la firma non viene verificata dai resolver."
                ),
                evidenza=evidenza,
                rimedio="Chiedere al registrar/maintainer di pubblicare il record DS presso il registro del TLD.",
            )
        ]
    return [
        Finding(
            **base,
            status=Status.PROBLEMA,
            severita=Severity.BASSA,
            dettaglio=(
                "DNSSEC non e' attivo: le risposte DNS del dominio non sono firmate, quindi "
                "un attaccante in posizione favorevole potrebbe dirottare i visitatori verso "
                "un server falso (DNS spoofing)."
            ),
            evidenza=evidenza,
            rimedio=(
                "Attivare DNSSEC presso il provider DNS (molti lo offrono con un clic) e "
                "far pubblicare il record DS dal registrar."
            ),
        )
    ]
