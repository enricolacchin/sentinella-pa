// Sentinella PA — interfaccia web.
//
// Il frontend non analizza nulla: invia l'URL all'API, attende il risultato e
// lo mostra. I documenti (report HTML, tecnico, per il sindaco, PEC) arrivano
// gia' pronti dall'API, prodotti dallo stesso modulo di rendering della CLI.
// Tutti i testi ricevuti vengono inseriti come testo, mai come HTML.

"use strict";

(() => {
  const CONFIG = window.SENTINELLA_CONFIG || {};
  const API = String(CONFIG.api || "").replace(/\/+$/, "");
  const INTERVALLO_MS = 1500;
  const ATTESA_MASSIMA_MS = 4 * 60 * 1000;

  const ETICHETTE_STATUS = {
    ok: "OK", attenzione: "Attenzione", problema: "Problema", errore: "Non verificabile", info: "Info",
  };
  const ETICHETTE_CATEGORIA = {
    https_tls: "HTTPS e certificato",
    security_headers: "Header di sicurezza",
    email_auth: "Protezione della posta (SPF, DMARC, DKIM)",
    dnssec: "DNSSEC",
    security_txt: "Canale per le segnalazioni (security.txt)",
    cms: "CMS",
    cookies: "Cookie",
    third_party: "Risorse di terze parti",
  };
  const DESCRIZIONE_VOTO = {
    A: "Configurazione molto buona",
    B: "Configurazione buona, con alcuni miglioramenti possibili",
    C: "Configurazione sufficiente, con interventi consigliati",
    D: "Configurazione insufficiente, interventi necessari",
    E: "Configurazione critica, interventi urgenti",
  };
  const ORDINE_STATUS = { problema: 0, attenzione: 1, errore: 2, ok: 3, info: 4 };
  const ORDINE_SEVERITA = { critica: 0, alta: 1, media: 2, bassa: 3, informativa: 4 };

  const $ = (sel) => document.querySelector(sel);
  const stato = { id: null, report: null, documenti: null };
  let attesaCorrente = 0; // per ignorare risposte di analisi superate

  // ------------------------------------------------------------ utilita'

  function el(tag, attributi = {}, ...figli) {
    const nodo = document.createElement(tag);
    for (const [k, v] of Object.entries(attributi)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") nodo.className = v;
      else nodo.setAttribute(k, v === true ? "" : v);
    }
    for (const figlio of figli.flat()) {
      if (figlio === null || figlio === undefined || figlio === "") continue;
      nodo.append(figlio instanceof Node ? figlio : document.createTextNode(String(figlio)));
    }
    return nodo;
  }

  async function chiama(percorso, opzioni = {}) {
    let risposta;
    try {
      risposta = await fetch(API + percorso, {
        ...opzioni,
        headers: { "Content-Type": "application/json", ...(opzioni.headers || {}) },
        referrerPolicy: "no-referrer",
      });
    } catch (e) {
      throw new Error("Il servizio di analisi non e' raggiungibile. Riprova tra qualche minuto.");
    }
    let dati = null;
    try { dati = await risposta.json(); } catch (e) { /* risposta non JSON */ }
    if (!risposta.ok) {
      const dettaglio = dati && typeof dati.detail === "string" ? dati.detail : `Errore ${risposta.status}`;
      throw new Error(dettaglio);
    }
    return dati;
  }

  function mostraMessaggio(testo, tipo = "errore") {
    const box = $("#messaggio");
    box.textContent = testo;
    box.className = "messaggio" + (tipo === "info" ? " info" : "");
    box.hidden = !testo;
  }

  const attendi = (ms) => new Promise((r) => setTimeout(r, ms));

  function dataLeggibile(iso) {
    const d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleString("it-IT", { dateStyle: "long", timeStyle: "short" });
  }

  function ordina(findings) {
    return [...findings].sort(
      (a, b) => (ORDINE_STATUS[a.status] - ORDINE_STATUS[b.status]) || (ORDINE_SEVERITA[a.severita] - ORDINE_SEVERITA[b.severita])
    );
  }

  function scarica(nomeFile, contenuto, tipo) {
    const url = URL.createObjectURL(new Blob([contenuto], { type: tipo }));
    const a = el("a", { href: url, download: nomeFile });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function copia(testo, bottone) {
    try {
      await navigator.clipboard.writeText(testo);
      const originale = bottone.textContent;
      bottone.textContent = "Copiato";
      setTimeout(() => { bottone.textContent = originale; }, 1500);
    } catch (e) {
      mostraMessaggio("Copia non riuscita: seleziona il testo e copialo a mano.");
    }
  }

  // ------------------------------------------------------------ analisi

  async function avviaAnalisi(url) {
    const turno = ++attesaCorrente;
    mostraMessaggio("");
    $("#risultato").hidden = true;
    $("#attesa-host").textContent = url;
    $("#attesa").hidden = false;
    $("#avvia").disabled = true;
    try {
      const avvio = await chiama("/api/analisi", { method: "POST", body: JSON.stringify({ url }) });
      await seguiAnalisi(avvio.id, turno);
    } catch (e) {
      if (turno === attesaCorrente) {
        $("#attesa").hidden = true;
        mostraMessaggio(e.message);
      }
    } finally {
      if (turno === attesaCorrente) $("#avvia").disabled = false;
    }
  }

  async function seguiAnalisi(id, turno) {
    const inizio = Date.now();
    while (turno === attesaCorrente) {
      const dati = await chiama(`/api/analisi/${encodeURIComponent(id)}`);
      if (dati.stato === "completata") {
        $("#attesa").hidden = true;
        stato.id = id;
        history.replaceState(null, "", `?analisi=${encodeURIComponent(id)}`);
        mostraRisultato(dati.report, dati.documenti);
        return;
      }
      if (dati.stato === "errore") throw new Error(dati.errore || "Analisi non riuscita.");
      if (Date.now() - inizio > ATTESA_MASSIMA_MS) throw new Error("L'analisi sta impiegando troppo tempo. Riprova piu' tardi.");
      await attendi(INTERVALLO_MS);
    }
  }

  // ------------------------------------------------------------ risultato

  function badgeStatus(status) {
    return el("span", { class: `badge s-${status}` }, ETICHETTE_STATUS[status] || status);
  }

  function bloccoCodice(etichetta, testo) {
    const bottone = el("button", { type: "button", class: "secondario copia-piccolo" }, "Copia");
    bottone.addEventListener("click", () => copia(testo, bottone));
    return el("div", { class: "codice" },
      el("div", { class: "etichetta" }, el("span", {}, etichetta), bottone),
      el("pre", {}, testo));
  }

  function schedaEsito(f) {
    const corpo = el("div", { class: "esito-corpo" }, el("p", {}, f.dettaglio));
    if (f.evidenza) corpo.append(el("div", { class: "etichetta" }, "Cosa e' stato osservato"), el("pre", {}, f.evidenza));
    if (f.rimedio) corpo.append(el("div", { class: "etichetta" }, "Come intervenire"), el("p", { class: "testo-rimedio" }, f.rimedio));
    if (f.rimedio_nginx) corpo.append(bloccoCodice("nginx", f.rimedio_nginx));
    if (f.rimedio_apache) corpo.append(bloccoCodice("Apache", f.rimedio_apache));
    if (f.rimedio_wordpress) corpo.append(bloccoCodice("WordPress / PHP", f.rimedio_wordpress));
    if (f.riferimento) corpo.append(el("p", { class: "nota" }, "Riferimenti: " + f.riferimento));
    return el("details", { class: `esito ${f.status}` },
      el("summary", {},
        el("span", { class: "esito-titolo" }, f.titolo),
        badgeStatus(f.status),
        el("span", { class: "badge neutro" }, "gravita' " + f.severita)),
      corpo);
  }

  function mostraRisultato(report, documenti) {
    stato.report = report;
    stato.documenti = documenti || null;

    // Sintesi
    const voto = $("#voto");
    voto.textContent = report.voto;
    voto.className = `voto voto-${report.voto}`;
    $("#sintesi-host").textContent = report.hostname;
    $("#sintesi-punteggio").textContent = `Voto ${report.voto} · ${report.punteggio}/100 — ${DESCRIZIONE_VOTO[report.voto] || ""}`;
    const c = report.conteggi || {};
    const parziale = $("#sintesi-parziale");
    parziale.hidden = !c.errore;
    parziale.textContent = c.errore ? `Voto parziale: ${c.errore} controlli non verificabili.` : "";
    $("#sintesi-conteggi").replaceChildren(
      el("li", { class: "s-problema" }, `${c.problema || 0} problemi`),
      el("li", { class: "s-attenzione" }, `${c.attenzione || 0} da migliorare`),
      el("li", { class: "s-ok" }, `${c.ok || 0} ok`),
      el("li", { class: "s-errore" }, `${c.errore || 0} non verificabili`),
      el("li", { class: "s-info" }, `${c.info || 0} informativi`));
    $("#sintesi-meta").textContent = `Analisi del ${dataLeggibile(report.timestamp)} · ${report.final_url}`;
    $("#condividi").hidden = !stato.id;

    // Interventi
    const daCorreggere = ordina(report.findings).filter((f) => f.status === "problema" || f.status === "attenzione");
    $("#interventi").replaceChildren(
      ...(daCorreggere.length
        ? daCorreggere.map(schedaEsito)
        : [el("p", {}, "Nessun intervento necessario sui controlli eseguiti.")]));

    // Tutti gli esiti, per area
    const gruppi = new Map();
    for (const f of report.findings) {
      if (!gruppi.has(f.categoria)) gruppi.set(f.categoria, []);
      gruppi.get(f.categoria).push(f);
    }
    $("#esiti").replaceChildren(...[...gruppi].map(([categoria, lista]) =>
      el("details", { class: "gruppo" },
        el("summary", {}, ETICHETTE_CATEGORIA[categoria] || categoria || "Altro"),
        el("table", { class: "tabella-esiti" },
          el("tbody", {}, lista.map((f) =>
            el("tr", {},
              el("td", {}, badgeStatus(f.status)),
              el("td", {}, el("strong", {}, f.titolo), el("br"), f.dettaglio))))))));

    // Documenti (assenti se il report e' stato aperto da file)
    const conDocumenti = Boolean(stato.documenti);
    document.querySelectorAll("[data-documento]").forEach((n) => { n.hidden = !conDocumenti; });
    if (conDocumenti) {
      $("#cornice-report").srcdoc = stato.documenti.html;
      $("#testo-tecnico").textContent = stato.documenti.tecnico;
      $("#testo-sindaco").textContent = stato.documenti.sindaco;
      $("#testo-pec").textContent = stato.documenti.pec;
    }
    $("#firma").textContent = report.generato_con || $("#firma").textContent;

    selezionaScheda("tab-riepilogo");
    $("#risultato").hidden = false;
    $("#risultato").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ------------------------------------------------------------ schede

  function selezionaScheda(id) {
    document.querySelectorAll('[role="tab"]').forEach((tab) => {
      const attiva = tab.id === id;
      tab.setAttribute("aria-selected", String(attiva));
      tab.tabIndex = attiva ? 0 : -1;
      $("#" + tab.getAttribute("aria-controls")).hidden = !attiva;
    });
  }

  function inizializzaSchede() {
    const schede = () => [...document.querySelectorAll('[role="tab"]')].filter((t) => !t.hidden);
    document.querySelectorAll('[role="tab"]').forEach((tab) => {
      tab.addEventListener("click", () => selezionaScheda(tab.id));
      tab.addEventListener("keydown", (e) => {
        if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
        const elenco = schede();
        const i = elenco.indexOf(tab) + (e.key === "ArrowRight" ? 1 : -1);
        const prossima = elenco[(i + elenco.length) % elenco.length];
        selezionaScheda(prossima.id);
        prossima.focus();
      });
    });
  }

  // ------------------------------------------------------------ download e copia

  function contenutoDocumento(tipo) {
    const r = stato.report;
    const base = (r && r.hostname ? r.hostname : "sentinella").replace(/[^a-z0-9.-]/gi, "_");
    if (tipo === "json") return [`${base}.json`, JSON.stringify(r, null, 2), "application/json"];
    const d = stato.documenti || {};
    const mappa = {
      html: [`${base}.html`, d.html, "text/html;charset=utf-8"],
      tecnico: [`${base}-report-tecnico.md`, d.tecnico, "text/markdown;charset=utf-8"],
      sindaco: [`${base}-report-sindaco.md`, d.sindaco, "text/markdown;charset=utf-8"],
      pec: [`${base}-bozza-pec.txt`, d.pec, "text/plain;charset=utf-8"],
    };
    return mappa[tipo];
  }

  function inizializzaAzioni() {
    document.addEventListener("click", (e) => {
      const scaricaBtn = e.target.closest("[data-scarica]");
      if (scaricaBtn && stato.report) {
        const [nome, testo, tipo] = contenutoDocumento(scaricaBtn.dataset.scarica);
        if (testo) scarica(nome, testo, tipo);
      }
      const copiaBtn = e.target.closest("[data-copia]");
      if (copiaBtn && stato.documenti) copia(stato.documenti[copiaBtn.dataset.copia] || "", copiaBtn);
    });

    $("#condividi").addEventListener("click", (e) => copia(location.href, e.currentTarget));
    $("#nuova").addEventListener("click", () => {
      attesaCorrente++;
      stato.id = stato.report = stato.documenti = null;
      history.replaceState(null, "", location.pathname);
      $("#risultato").hidden = true;
      $("#attesa").hidden = true;
      mostraMessaggio("");
      $("#url").value = "";
      $("#url").focus();
      window.scrollTo({ top: 0, behavior: "smooth" });
    });

    $("#modulo-pec").addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!stato.id) return;
      const dati = Object.fromEntries(new FormData(e.currentTarget));
      try {
        const risposta = await chiama(`/api/analisi/${encodeURIComponent(stato.id)}/pec`, {
          method: "POST", body: JSON.stringify(dati),
        });
        stato.documenti.pec = risposta.testo;
        $("#testo-pec").textContent = risposta.testo;
      } catch (err) {
        mostraMessaggio(err.message);
      }
    });

    $("#file-json").addEventListener("change", async (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      try {
        const report = JSON.parse(await file.text());
        if (!report || !Array.isArray(report.findings) || !report.voto) throw new Error();
        attesaCorrente++;
        stato.id = null;
        history.replaceState(null, "", location.pathname);
        mostraMessaggio("Report aperto dal file: i documenti (HTML, report e PEC) si generano con la riga di comando.", "info");
        mostraRisultato(report, null);
      } catch (err) {
        mostraMessaggio("Il file non sembra un report JSON di Sentinella PA.");
      } finally {
        e.target.value = "";
      }
    });
  }

  // ------------------------------------------------------------ avvio

  async function inizializza() {
    inizializzaSchede();
    inizializzaAzioni();

    $("#modulo").addEventListener("submit", (e) => {
      e.preventDefault();
      const url = $("#url").value.trim();
      if (!url) {
        mostraMessaggio("Inserisci l'indirizzo del sito da analizzare.");
        $("#url").focus();
        return;
      }
      avviaAnalisi(url);
    });

    // Su GitHub Pages senza API configurata il modulo non puo' funzionare.
    const suPages = /\.github\.io$/.test(location.hostname);
    if (!API && suPages) {
      $("#avvia").disabled = true;
      mostraMessaggio("Il servizio di analisi non e' ancora collegato: puoi comunque aprire un report JSON generato con la riga di comando.", "info");
    } else {
      chiama("/api/configurazione").then((conf) => {
        if (conf && conf.generato_con) $("#firma").textContent = conf.generato_con;
        if (conf && conf.domini_consentiti && conf.domini_consentiti.length) {
          const elenco = conf.domini_consentiti.map((d) => "." + d).join(", ");
          $("#nota-modulo").append(` Il servizio accetta domini ${elenco}, fino a ${conf.limite_per_ora} analisi l'ora.`);
        }
      }).catch(() => {
        mostraMessaggio("Il servizio di analisi non e' raggiungibile in questo momento.", "info");
      });
    }

    const id = new URLSearchParams(location.search).get("analisi");
    if (id && /^[a-f0-9]{32}$/.test(id)) {
      const turno = ++attesaCorrente;
      $("#attesa-host").textContent = "il sito";
      $("#attesa").hidden = false;
      try {
        await seguiAnalisi(id, turno);
      } catch (e) {
        $("#attesa").hidden = true;
        mostraMessaggio(e.message);
      }
    }
  }

  inizializza();
})();
