# Pubblicare l'interfaccia web

L'interfaccia ha due parti:

| Parte | Cosa fa | Dove va |
|---|---|---|
| **Frontend** (`web/`) | Pagina statica: modulo, risultati, download | GitHub Pages |
| **API** (`sentinella/web/`) | Esegue l'analisi con il motore e salva lo storico | Hosting con Python (cPanel) |

GitHub Pages pubblica solo file statici: l'analisi deve girare su un server,
perche' un browser non puo' leggere header e certificato TLS di un altro sito.

Ordine consigliato: prima l'API su cPanel, poi il frontend su GitHub Pages.

---

## 1. API su cPanel

Servono: la voce **Setup Python App** nel pannello (Python 3.11 o superiore) e un
sottodominio con certificato HTTPS, ad esempio `api.tuodominio.it`.

### 1.1 Sottodominio e certificato

1. cPanel → **Domini** (o **Sottodomini**): crea `api.tuodominio.it`.
2. cPanel → **SSL/TLS Status**: verifica che AutoSSL abbia emesso il certificato
   per il sottodominio (puo' servire qualche minuto).

### 1.2 Codice sul server

Il modo piu' comodo e' **Git Version Control** di cPanel:

1. cPanel → **Git Version Control** → **Create**.
2. Clone URL: `https://github.com/enricolacchin/sentinella-pa.git`
3. Repository Path: ad esempio `sentinella-pa` (cioe' `/home/UTENTE/sentinella-pa`),
   **fuori** da `public_html`.

In alternativa carica i file con il File Manager nella stessa cartella.

### 1.3 Applicazione Python

cPanel → **Setup Python App** → **Create Application**:

| Campo | Valore |
|---|---|
| Python version | 3.11 o superiore (la piu' recente disponibile) |
| Application root | `sentinella-pa` |
| Application URL | `api.tuodominio.it` |
| Application startup file | `passenger_wsgi.py` |
| Application Entry point | `application` |

Nella stessa pagina, sezione **Environment variables**, aggiungi:

| Variabile | Valore | Note |
|---|---|---|
| `SENTINELLA_CORS_ORIGINI` | `https://enricolacchin.github.io` | Origine del frontend su Pages (senza percorso) |
| `SENTINELLA_DATABASE` | `/home/UTENTE/sentinella-dati/sentinella.sqlite3` | Fuori da `public_html` |
| `SENTINELLA_DOMINI_CONSENTITI` | `it` | Suffissi analizzabili; vuoto = qualsiasi dominio pubblico |
| `SENTINELLA_LIMITE_ORA` | `10` | Analisi per ora per ogni richiedente |
| `SENTINELLA_RIUSO_MINUTI` | `10` | Entro questo tempo lo stesso sito non viene ricontattato |

Salva, poi installa le dipendenze. Nella pagina dell'app c'e' il campo
**Configuration files**: aggiungi `requirements-web.txt` e premi **Run Pip Install**.
In alternativa, dal **Terminale** di cPanel (il comando esatto per attivare
l'ambiente e' mostrato in cima alla pagina dell'app):

```bash
source /home/UTENTE/virtualenv/sentinella-pa/3.11/bin/activate && cd ~/sentinella-pa && pip install -r requirements-web.txt
```

Infine premi **Restart**.

### 1.4 Verifica

Apri `https://api.tuodominio.it/api/salute`: deve rispondere con
`{"stato": "ok", ...}`. La documentazione interattiva dell'API e' su
`https://api.tuodominio.it/api/docs`.

Se non risponde, guarda il file `stderr.log` nella cartella dell'app.

### Limiti tipici degli hosting condivisi

- **Connessioni in uscita**: l'analisi deve poter contattare i siti sulle porte
  80 e 443 e interrogare il DNS. Quasi tutti gli hosting lo permettono; se ogni
  analisi finisce con "non verificabile", chiedi al supporto se le connessioni in
  uscita sono bloccate.
- **Processi**: Passenger puo' fermare l'app quando e' inattiva. Un'analisi
  rimasta "in corso" per piu' di 3 minuti viene segnata come interrotta e si
  puo' ripetere.
- **Versione di Python**: serve la 3.11 o superiore.

---

## 2. Frontend su GitHub Pages

1. Repository su GitHub → **Settings** → **Pages** → **Source**: *GitHub Actions*.
2. **Settings** → **Secrets and variables** → **Actions** → scheda **Variables** →
   **New repository variable**:
   - Name: `SENTINELLA_API_URL`
   - Value: `https://api.tuodominio.it` (senza barra finale)
3. **Actions** → workflow **Pubblica su GitHub Pages** → **Run workflow**
   (parte da solo anche a ogni push che modifica `web/`).

Il sito sara' su `https://enricolacchin.github.io/sentinella-pa/`.

Il workflow genera `web/config.js` con l'indirizzo dell'API. Se la variabile
manca, la pagina si pubblica lo stesso ma il modulo di analisi resta
disattivato: si possono solo aprire report JSON prodotti con la riga di comando.

### Dominio personalizzato (facoltativo)

Per pubblicare il frontend su `sentinella.tuodominio.it`: Settings → Pages →
Custom domain, e un record CNAME verso `enricolacchin.github.io`. Ricorda di
aggiornare `SENTINELLA_CORS_ORIGINI` sull'API con la nuova origine.

---

## 3. Alternativa: tutto su cPanel

Se preferisci non usare GitHub Pages, l'API puo' servire anche il frontend:
aggiungi la variabile `SENTINELLA_FRONTEND=/home/UTENTE/sentinella-pa/web` e
apri direttamente `https://api.tuodominio.it/`. In questo caso `web/config.js`
resta con `api: ""` (stessa origine) e `SENTINELLA_CORS_ORIGINI` non serve.

---

## 4. Aggiornare

- **API**: cPanel → Git Version Control → **Manage** → **Pull or Deploy** →
  *Update from Remote*, poi **Restart** nella pagina dell'app Python (e di nuovo
  *Run Pip Install* se sono cambiate le dipendenze).
- **Frontend**: parte da solo a ogni push su `main` che modifica `web/`.

## 5. Provare in locale

```bash
pip install -e ".[web,dev]"
```

```bash
python -m sentinella.web
```

Poi apri <http://127.0.0.1:8000>: API e frontend insieme, database in
`sentinella.sqlite3` (escluso da git).

## Protezioni attive

- **Bersagli**: solo nomi di dominio pubblici (con il suffisso consentito), porte
  80/443; nessun indirizzo IP, nessun host che risolva verso reti private,
  loopback o metadati cloud. Il controllo si ripete a ogni redirect (anti-SSRF).
- **Limiti d'uso**: numero massimo di analisi per ora per richiedente; lo stesso
  sito non viene ricontattato entro `SENTINELLA_RIUSO_MINUTI`.
- **Privacy**: gli IP dei richiedenti non sono salvati in chiaro (solo
  un'impronta con sale, cancellata dopo un giorno); i dati inseriti per la PEC
  non vengono salvati.
- **Header di sicurezza** su tutte le risposte, CSP sul frontend.

Il controllo sull'Indice PA (accettare solo domini di enti censiti) e'
previsto in una fase successiva.
