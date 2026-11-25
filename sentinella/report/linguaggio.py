"""Spiegazioni in linguaggio semplice degli esiti, per sindaco/RTD e per la PEC.

Sono testi di presentazione, quindi stanno nello strato di rendering e non nel
motore. Le chiavi sono gli ``id`` dei Finding.
"""

from __future__ import annotations

from sentinella.core.models import Finding

# id -> (titolo semplice, cosa rischia il cittadino / l'ente)
SPIEGAZIONI: dict[str, tuple[str, str]] = {
    "https.disponibile": (
        "Il sito non offre una connessione cifrata affidabile",
        "Le informazioni che i cittadini consultano o inviano (moduli, ricerche, dati "
        "personali) possono essere lette o modificate da chi controlla la rete, ad "
        "esempio un Wi-Fi pubblico.",
    ),
    "https.redirect": (
        "Chi apre il sito senza 'https://' naviga senza cifratura",
        "Molti cittadini arrivano da vecchi link o digitano solo il nome del sito: in "
        "quel caso la navigazione avviene in chiaro e puo' essere intercettata.",
    ),
    "tls.certificato": (
        "Il certificato di sicurezza del sito ha un problema",
        "Il browser puo' mostrare un avviso di pericolo: i cittadini si abituano a "
        "ignorare gli avvisi, oppure non riescono ad accedere ai servizi.",
    ),
    "tls.versione": (
        "Il sito usa una tecnologia di cifratura superata",
        "Le versioni vecchie del protocollo hanno debolezze note e i browser moderni le "
        "stanno abbandonando: il sito rischia di diventare irraggiungibile.",
    ),
    "header.hsts": (
        "Il browser non viene obbligato a usare sempre la connessione sicura",
        "Il primo accesso puo' avvenire in chiaro ed essere dirottato da chi controlla "
        "la rete.",
    ),
    "header.csp": (
        "Manca una regola che limiti cosa puo' essere eseguito nella pagina",
        "Se un malintenzionato riuscisse a inserire codice nel sito, ad esempio tramite un "
        "componente esterno, potrebbe mostrare contenuti falsi o rubare dati inseriti dai "
        "cittadini.",
    ),
    "header.frame": (
        "Il sito puo' essere 'incorniciato' in pagine di altri",
        "Una pagina truffaldina puo' mostrare il sito dell'ente sotto elementi invisibili e "
        "indurre i cittadini a cliccare dove non vorrebbero.",
    ),
    "email.spf": (
        "Chiunque puo' inviare email che sembrano dell'ente",
        "Senza questa protezione e' facile mandare ai cittadini email false a nome del "
        "Comune (falsi avvisi di pagamento, multe, rimborsi): e' la base del phishing.",
    ),
    "email.dmarc": (
        "Le email false a nome dell'ente non vengono bloccate",
        "I servizi di posta dei cittadini non ricevono istruzioni per scartare i messaggi "
        "contraffatti, e l'ente non viene avvisato quando qualcuno usa il suo nome.",
    ),
    "dnssec": (
        "L'indirizzo del sito non e' protetto da falsificazioni",
        "In casi particolari un attaccante potrebbe indirizzare chi digita l'indirizzo "
        "corretto verso un sito falso identico all'originale.",
    ),
    "security_txt": (
        "Non c'e' un canale ufficiale per segnalare problemi di sicurezza",
        "Chi scopre una vulnerabilita' non sa a chi scrivere: la segnalazione rischia di "
        "perdersi o di arrivare troppo tardi.",
    ),
    "cms.versione": (
        "Il sito dichiara pubblicamente la versione del software usato",
        "Se il software non e' aggiornato, chiunque puo' cercare in rete come attaccare "
        "proprio quella versione.",
    ),
    "cookie.secure": (
        "Alcuni cookie possono viaggiare senza cifratura",
        "Su reti non sicure le informazioni contenute nei cookie, comprese quelle di "
        "accesso ai servizi, possono essere intercettate.",
    ),
    "cookie.httponly": (
        "I cookie di accesso sono leggibili dagli script della pagina",
        "In caso di attacco alla pagina, la sessione del cittadino puo' essere rubata.",
    ),
    "terze_parti.contenuti_misti": (
        "La pagina sicura carica parti non cifrate",
        "Quelle parti possono essere modificate durante il tragitto e alterare la pagina "
        "che il cittadino vede.",
    ),
}


def titolo_semplice(f: Finding) -> str:
    return SPIEGAZIONI.get(f.id, (f.titolo, ""))[0]


def rischio(f: Finding) -> str:
    """Cosa rischia il cittadino; in mancanza di un testo dedicato, il dettaglio tecnico."""
    return SPIEGAZIONI.get(f.id, ("", f.dettaglio))[1] or f.dettaglio
