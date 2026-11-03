# Code review — 3 novembre 2026

Base esaminata: `990a9f6af267461a0b80c215302caaee67e99586` (`main`).
La review comprende backend/API, autenticazione e autorizzazioni, cifratura, discovery e inventario,
notifiche/monitoraggio, worker, deploy/rollback/backup, helper privilegiato, frontend e relativi contratti,
configurazione Docker/Compose e documentazione operativa. Le correzioni sono state sottoposte anche a una
seconda review del diff. Non equivale a un penetration test o a una certificazione di assenza di difetti.

## Difetti corretti in questo branch

| Priorità | Problema e condizione di attivazione | Correzione e regressione |
| --- | --- | --- |
| P1 | Primo login OIDC: il nuovo `User.enabled` è `None` fino all'INSERT; il controllo precedente al flush rifiuta ogni nuovo account con 403. | Inizializzazione esplicita a `True` in `backend/app/services/oidc.py`; test con ID token RSA firmato e verifica che un account già disabilitato resti escluso. |
| P1 | Perdita di un lock dopo la prima installazione: il rollback continuava a ripristinare file e ricaricare servizi mentre un altro worker poteva possedere il lock. Anche il restore manuale ignorava la perdita del lock. | Controllo prima delle successive modifiche e dei reload, incluso ogni file ripristinato; interruzione con stato che richiede intervento manuale. Regressioni per perdita durante attivazione, rollback e restore manuale. |
| P1 | Restore manuale: dopo cinque probe TLS senza risposta, `got=None` non veniva considerato errore e l'operazione risultava riuscita. | Richiesta di corrispondenza positiva con il fingerprint precedente; test di endpoint irraggiungibile. |
| P1 | Ambiente con catena attendibile obbligatoria: una seconda handshake di verifica fallita per errore/timeout produce `chain_valid=None`, che veniva accettato. | Per endpoint raggiungibili, la verifica deve restituire esplicitamente `True`; regressioni per `False` e `None`. |
| P1 | Helper privilegiato: `install` e `write-staged` accettavano bit setuid/setgid/sticky, incluso un file root con modo `4755` nelle directory ammesse. | Rifiuto dei bit speciali nel validatore shell e nel client SSH. Test dei validatori reali, senza installare o eseguire un payload privilegiato. La portata delle directory ammesse resta un limite distinto, descritto sotto. |
| P2 | Upload multipart di una chiave non UTF-8: il decode era fuori dal blocco che gestiva `UnicodeDecodeError`, producendo un errore 500. | Errore applicativo 422 nel punto del decode, verificato sia per creazione sia per rotazione delle credenziali. |
| P2 | Regole di notifica con filtro ambiente numerico o strutturato: la configurazione veniva salvata e poteva provocare `TypeError` nel routing, interrompendo monitoraggio/discovery. | Validazione di stringa o lista di stringhe prima del salvataggio; regressioni per tipi non ammessi. Le regole malformate eventualmente già presenti nel database vanno corrette. |

Le regressioni sono state osservate fallire prima delle rispettive correzioni.

## Difetti aperti, da affrontare separatamente

Questi rilievi derivano dal tracciamento del codice; gli scenari remoti non sono stati riprodotti su server reali.

### P1 — Revoca dell'utente durante un deploy interrotto

In `backend/app/services/deployment_engine.py`, `JobRunner._run` riautorizza l'utente prima del recupero e
chiama `_abort` se è stato disabilitato, eliminato o privato del ruolo. `_abort` marca come cancellati anche
target che erano in una fase di modifica remota, senza riconciliarli.

Scenario: il worker muore tra la sostituzione di chiave e certificato; l'utente viene disabilitato; il task
viene riconsegnato. I file possono restare incoerenti e il target risultare semplicemente cancellato.
Il recupero di sicurezza deve essere distinto dall'autorizzazione a proseguire il deploy: acquisire i lock,
riconciliare/ripristinare e verificare oppure segnalare esplicitamente la necessità di intervento manuale.
Occorre una regressione con crash a metà installazione, revoca e riconsegna del task.

### P1 — Restore manuale di un backup condiviso tra servizi

`UnitRunner` associa lo stesso backup a tutti i target di un'unità che condivide file.
`restore_backup_async` ripristina l'intero manifest, ma acquisisce il lock di servizio, ricarica, verifica
e aggiorna l'inventario soltanto dell'installazione primaria o del target richiesto.

Scenario: nginx e Apache condividono materiale TLS; il deploy aggiorna entrambi; un restore manuale
ripristina i file precedenti ma ricarica soltanto il servizio primario. Il secondo può continuare a servire
il certificato nuovo mentre file e stato non lo rappresentano correttamente. Il restore deve risolvere
tutti i target/servizi/endpoint associati al backup e trattarli come un'unica unità.
Fino alla correzione, evitare questo restore manuale su backup condivisi e gestire il recupero con una procedura controllata.

### P2 — Scadenziario incompleto oltre 200 certificati

`frontend/src/routes/expirations.tsx:191` carica solo la prima pagina con `page_size: 200`, poi applica
l'intervallo di date localmente. I certificati successivi non compaiono in tabella/calendario, anche quando
corrispondono al filtro o al mese selezionato. Servono filtri temporali lato server e paginazione, oppure
il caricamento esplicito di tutte le pagine necessarie. Verificare con almeno 201 certificati.

### P2 — Lo stream SSE si chiude definitivamente alla scadenza di un'ora

`frontend/src/lib/api/sse.ts:88` interpreta ogni evento `end` come completamento del job.
`backend/app/services/events.py` invia invece anche `end` con `status: "timeout"` dopo un'ora di connessione,
pur se il job è attivo. La URL non cambia e lo stream non riparte. Distinguere il timeout dal completamento
e continuare tramite polling o nuova connessione; verificare con un evento timeout e un job non terminale.

### P2 — Un refresh può cancellare una bozza delle impostazioni

`frontend/src/routes/settings.tsx:265` include la versione server nella key di `SectionForm`.
Se un altro amministratore salva mentre il primo sta scrivendo, il refetch al ritorno del focus cambia
la key e rimonta il form, perdendo la bozza senza passare dalla gestione del conflitto sul salvataggio.
Conservare lo stato dirty fino a una decisione esplicita o mostrare il conflitto prima di sostituirlo.

## Limiti e confini di sicurezza

- La correzione dei modi speciali elimina quel percorso diretto di escalation, ma non rende il helper una
  sandbox. Le directory predefinite includono `/opt`, `/usr/local/etc` e configurazioni di servizi avviati
  come root: poter sostituire file arbitrari in tali directory resta un privilegio molto ampio, già
  segnalato in `docs/ssh-permissions.md`. Restringere le radici ai percorsi realmente necessari e trattare
  l'account/helper come credenziale altamente privilegiata; per una separazione più forte servono operazioni
  limitate ai singoli file TLS e una revisione del modello di fiducia.
- Nessun test con un IdP reale, browser Playwright o target SSH privilegiato live. I test OIDC usano token
  realmente firmati con provider HTTP simulato; i test deploy usano il filesystem/host finto della suite.
- Le dipendenze non sono state sottoposte a un audit CVE esterno in questa review.

## Verifica

- Backend: `cd backend && .venv/bin/pytest -q` — **411 passati, 53 saltati, 12 warning**.
  I 53 test di integrazione richiedono il target privilegiato locale, non disponibile in questo ambiente.
- Sottoinsieme deploy: **108 passati**; le nuove regressioni hanno riprodotto gli errori prima del fix.
- Frontend: `bun x tsc --noEmit` e `bun run build` completati con exit code 0.
- Ruff sui file Python modificati e `git diff --check`: superati.
- Verifica ulteriore del contratto SSE: il builder registrato da `services/deployments.py` restituisce già
  target completi; l'ipotesi iniziale di perdita di dettagli non è un difetto dimostrato nel flusso normale
  e non ha comportato modifiche al frontend.
