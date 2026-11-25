# Sentinella PA

Verifica **esclusivamente passiva** della sicurezza dei siti della Pubblica
Amministrazione italiana. Produce un riepilogo a terminale, un report tecnico per il
sistemista, un report in linguaggio semplice per sindaco e RTD, un report HTML
stampabile, un export JSON e una bozza di PEC da inviare all'ente.

Lo scopo e' la **divulgazione responsabile**: aiutare un ente a migliorare la propria
configurazione, segnalandogli con garbo cio' che chiunque puo' gia' vedere.

## Cosa controlla

| Area | Cosa osserva |
|---|---|
| HTTPS e TLS | risposta in HTTPS, redirect da HTTP, validita' e scadenza del certificato, corrispondenza del nome, versione TLS negoziata |
| Header di sicurezza | HSTS, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options / frame-ancestors, Referrer-Policy, Permissions-Policy, versioni esposte in `Server` / `X-Powered-By` |
| Posta elettronica | SPF (assenza, `+all`, `?all`), DMARC su `_dmarc.<dominio>` (assente o `p=none`), DKIM sui selettori piu' comuni (controllo parziale) |
| DNSSEC | presenza di DNSKEY nella zona e di DS presso il registro |
| security.txt | presenza di `/.well-known/security.txt` con i campi `Contact` ed `Expires` |
| CMS | WordPress, Joomla, Drupal riconosciuti dalla sola home; segnala la versione se esposta |
| Cookie | flag `Secure`, `HttpOnly`, `SameSite`; cookie impostati al primo caricamento (nota GDPR, senza giudizio sul consenso) |
| Terze parti | origini esterne di `<script>` e `<iframe>`, contenuti misti |

Posta e DNSSEC si verificano sul **dominio registrabile**, calcolato con la Public
Suffix List inclusa nel pacchetto (es. `www.comune.milano.it` → `comune.milano.it`).

### Punteggio

Si parte da 100 e si sottrae, per ogni problema: critica 25, alta 15, media 8,
bassa 3 punti. Gli esiti "attenzione" pesano la meta'; quelli non verificabili e
informativi non pesano. Voto: **A** ≥ 90, **B** ≥ 75, **C** ≥ 60, **D** ≥ 40, **E** < 40.

## Installazione

Serve Python 3.11 o superiore.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Per sviluppare ed eseguire i test (che non usano la rete):

```bash
pip install -e ".[dev]"
pytest
```

## Uso

```bash
sentinella www.comune.example.it
```

```text
sentinella <url> [--json FILE] [--html FILE] [--pec FILE]
                 [--report-tecnico FILE] [--report-sindaco FILE]
                 [--timeout SECONDI]
```

Il riepilogo a terminale viene stampato sempre; le opzioni salvano gli altri formati:

```bash
sentinella https://www.comune.example.it --json analisi.json --html analisi.html --report-tecnico tecnico.md --report-sindaco sindaco.md --pec pec.txt
```

La bozza PEC contiene segnaposto (`[DENOMINAZIONE ENTE]`, `[PEC ISTITUZIONALE DELL'ENTE]`,
`[NOME DEL RESPONSABILE PER LA TRANSIZIONE DIGITALE]`, firma del mittente) da completare
prima dell'invio. Va sempre riletta: lo strumento puo' sbagliare.

Un esempio di output JSON, generato su un sito fittizio, e' in
[`esempi/report_esempio.json`](esempi/report_esempio.json).

### Uso come libreria

```python
from sentinella.core import analizza
from sentinella.report import DatiPec, render_html, render_pec

report = analizza("www.comune.example.it", timeout=10)
print(report.punteggio, report.voto)
dati = report.to_dict()        # solo tipi JSON: pronto per un database
html = render_html(report)
pec = render_pec(report, DatiPec(ente="Comune di Esempio", pec_ente="protocollo@pec.example.it"))
```

## Interfaccia web

Oltre alla riga di comando c'e' un'interfaccia web: si incolla l'indirizzo del sito,
si attende qualche secondo e si ottengono riepilogo, report completo, report tecnico,
report per il sindaco e bozza PEC personalizzabile, tutti scaricabili.

- **Frontend** statico in `web/`, pubblicabile su GitHub Pages.
- **API** in `sentinella/web/` (FastAPI), da ospitare su un hosting con Python,
  ad esempio cPanel con "Setup Python App" (`passenger_wsgi.py`).

Per provarla in locale:

```bash
pip install -e ".[web,dev]"
```

```bash
python -m sentinella.web
```

e apri <http://127.0.0.1:8000>. La guida passo per passo per cPanel e GitHub Pages
e' in [`docs/pubblicazione.md`](docs/pubblicazione.md).

L'API e' pensata per essere esposta al pubblico: accetta solo domini pubblici
(per default `.it`), blocca indirizzi interni anche dopo i redirect, limita le
analisi per ora e non ricontatta lo stesso sito entro pochi minuti.

## Architettura

```text
sentinella/
├── core/      il motore: analizza(url) -> Report. Nessuna stampa, nessuna dipendenza da CLI o web
│   ├── context.py   unico punto di I/O di rete (HTTP, handshake TLS, security.txt, resolver DNS)
│   ├── models.py    Finding, Report, Status, Severity, punteggio. Tutto serializzabile
│   └── checks/      un modulo per area; ognuno riceve il Context e restituisce list[Finding]
├── report/    rendering condiviso: testo, JSON, HTML, report tecnico, report semplice, PEC
├── web/       API FastAPI: job in background, storico su SQLite, protezioni anti-abuso
└── cli.py     wrapper sottile: argomenti -> analizza() -> report/
web/           frontend statico (GitHub Pages) che chiama l'API
passenger_wsgi.py   punto di ingresso per cPanel
```

Per aggiungere un controllo basta scrivere una funzione `controlla(ctx) -> list[Finding]`
in `core/checks/` e registrarla in `core/checks/__init__.py`. Un controllo che va in
errore non blocca gli altri: produce un esito "non verificabile".

CLI e interfaccia web sono due consumatori dello stesso motore: l'API chiama
`analizza()` in un job in background, salva `Report.to_dict()` su SQLite (base per lo
storico e il follow-up a 30/60/90 giorni) e restituisce i documenti prodotti da
`sentinella.report`, senza duplicare logica.

## Cosa fa e cosa NON fa

Lo strumento esegue soltanto cio' che fa un normale browser o un normale resolver DNS:

- una richiesta GET alla pagina indicata, in HTTPS e in HTTP, seguendo i redirect;
- un handshake TLS sulla porta 443 (ripetuto una volta senza verifica, solo per leggere
  la versione del protocollo, se il certificato non e' valido);
- una richiesta GET a `/.well-known/security.txt`;
- interrogazioni DNS pubbliche (TXT, MX, DNSKEY, DS).

**Non** esegue scansioni di porte, enumerazione di directory o file, tentativi di
login, fuzzing, invio di payload o qualsiasi test attivo di vulnerabilita'. Si
presenta con uno User-Agent trasparente:
`SentinellaPA/<versione> (+controllo passivo sicurezza; https://github.com/enricolacchin/sentinella-pa)`.

Se il sito risponde con un errore (es. 403 perche' blocca i client che non si dichiarano
browser, o 5xx), header, cookie, CMS e risorse esterne vengono marcati "non
verificabili" invece di essere giudicati sulla pagina di errore: lo User-Agent resta
trasparente e non si tenta di aggirare il blocco.

Limiti noti: i cookie impostati via JavaScript e i contenuti caricati dinamicamente non
sono osservati; il controllo DKIM prova solo selettori comuni; la versione del CMS
viene segnalata se esposta, ma non viene confrontata con un elenco di vulnerabilita'.

## Inquadramento legale

Questa sezione e' informativa e non costituisce consulenza legale.

- **Lo strumento e' passivo.** Le informazioni raccolte sono le stesse che il sito e il
  DNS forniscono a qualsiasi visitatore: equivalgono a cio' che vede un browser
  aprendo la pagina. Non si accede ad aree riservate e non si aggirano misure di
  protezione.
- **Divulgazione coordinata.** In Italia la divulgazione coordinata delle
  vulnerabilita' segue la procedura del CSIRT Italia, secondo la policy di Coordinated
  Vulnerability Disclosure dell'Agenzia per la Cybersicurezza Nazionale (ACN, ottobre
  2026). La bozza PEC generata segue lo stesso spirito: segnalazione riservata all'ente,
  nessuna pubblicazione dei dettagli, disponibilita' al confronto e possibile
  coinvolgimento del CSIRT Italia.
- **Test attivi.** L'art. 615-ter c.p. (accesso abusivo a un sistema informatico o
  telematico) resta applicabile ai test attivi non autorizzati. Per questo lo strumento
  e' volutamente passivo, e ogni estensione futura deve restarlo: nessun controllo che
  vada oltre cio' che un browser richiede normalmente.
- **Uso responsabile.** Chi usa lo strumento ne risponde: le segnalazioni vanno inviate
  all'ente interessato, con tono collaborativo, senza diffonderne i contenuti.

## Licenza e attribuzione

Il codice e' software libero, distribuito sotto la
[European Union Public Licence v. 1.2](LICENSE) (EUPL-1.2): puoi usarlo, studiarlo,
modificarlo e ridistribuirlo alle condizioni della licenza.

- **Riga di attribuzione.** Ogni output (terminale, JSON, HTML, report, PEC) riporta la
  riga generata da `sentinella/branding.py`. L'art. 5 dell'EUPL impone di mantenere
  intatte le note di attribuzione dell'opera: chi usa o ridistribuisce lo strumento,
  anche modificato, deve mantenere questa riga negli output e indicare in modo evidente
  le modifiche apportate.
- **Nome del progetto.** La licenza non concede il diritto di usare il nome del progetto
  o del licenziante (art. 5, "Legal Protection"), salvo per descriverne l'origine. Una
  versione derivata non puo' presentarsi come "Sentinella PA".
