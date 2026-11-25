// Configurazione del frontend.
//
// api: indirizzo dell'API di Sentinella PA, senza barra finale.
//   ""                          -> stessa origine della pagina (sviluppo locale, o
//                                  frontend servito dall'API stessa)
//   "https://api.tuodominio.it" -> API ospitata altrove (caso GitHub Pages)
//
// Su GitHub Pages questo file viene rigenerato dal workflow di pubblicazione a
// partire dalla variabile di repository SENTINELLA_API_URL.
window.SENTINELLA_CONFIG = {
  api: ""
};
