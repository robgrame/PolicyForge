
# ADR-001 — Decoupling delle azioni privilegiate (Graph → Intune/Entra) tramite worker + Service Bus

> Documento di design / Architecture Decision Record.
> **Stato:** Proposto · **Data:** 2026-06-27 · **Autore:** @robgrame (con GitHub Copilot)
> **Ambito:** separare le chiamate Microsoft Graph ad alto privilegio (Intune/Entra)
> dall'API server public-facing, spostandole su un **worker dedicato** alimentato da
> una **coda di comandi** (Azure Service Bus).
>
> Documento complementare a [`chrome-browser-cloud-management.md`](./chrome-browser-cloud-management.md)
> e [`chromium-policy-loading.md`](./chromium-policy-loading.md).

---

## 1. Contesto

Oggi `ChromePolicyManager.Api` è un'unica applicazione App Service che assolve **due
ruoli con profili di rischio molto diversi**:

1. **Superficie esposta** — riceve traffico dai client (via APIM/mTLS) e dal portale
   Admin: serve le policy, accetta i device-report, espone gli endpoint di gestione.
2. **Attore privilegiato** — esegue *direttamente* e in modo **sincrono** chiamate
   Microsoft Graph verso Intune ed Entra ID, usando la propria **User-Assigned Managed
   Identity** (`cpm-dev-api-id`) a cui sono assegnate app-role ad alto privilegio.

### 1.1 Inventario delle azioni privilegiate attuali

| Area | Codice | Operazione Graph | App-role tipiche |
|---|---|---|---|
| Push remediation | `Services/PushRemediationService.cs` → `DispatchToAssignmentAsync` / `DispatchToDeviceAsync` | `deviceManagement/managedDevices` filter `azureADDeviceId`, **send remediation command** (azione privilegiata su device) | `DeviceManagementManagedDevices.PrivilegedOperations.All`, `DeviceManagementManagedDevices.Read.All` |
| Enumerazione gruppi | `PushRemediationService.GetGroupDeviceIdsAsync` | `groups/{id}/members` con paging | `Device.Read.All`, `GroupMember.Read.All` |
| Webhook lifecycle | `Services/GroupChangeNotificationService.cs` (`BackgroundService`) | `subscriptions` POST/PATCH/DELETE (create/renew/remove) | `Group.Read.All` |
| Ricezione notifiche | `Endpoints/WebhookEndpoints.cs` (`/api/webhooks`) | — (riceve callback Graph; poi rilegge membership) | — |
| Group search (portale) | `IGraphService.SearchGroupsAsync` | `groups?$search` | `Group.Read.All` |

### 1.2 Cosa è già asincrono

Il percorso di **ingestion** dei device-report è **già disaccoppiato** via Service Bus
e va preso come *blueprint*:

```
client ─▶ API.DeviceReportQueue.EnqueueReportAsync ─▶ SB queue "device-reports" ─▶ 202
                                                              │
                                              DeviceReportProcessor (BackgroundService) ─▶ SQL
```

- `Services/DeviceReportQueue.cs` — sender MI (`ServiceBusClient(fqns, DefaultAzureCredential)`).
- `Services/DeviceReportProcessor.cs` — `BackgroundService` con `ServiceBusProcessor`.
- Config: `ServiceBus:FullyQualifiedNamespace`, `ServiceBus:DeviceReportQueue` (default `device-reports`).

> **Nota:** il `DeviceReportProcessor` gira **dentro la stessa API**. Funziona, ma non
> realizza alcuna separazione di privilegio: è un consumer *nello stesso processo*. Il
> presente ADR estende il pattern della coda **anche** alle azioni privilegiate, ma con
> il consumer in un **processo/identità separati**.

---

## 2. Problema (forze e driver)

- **Blast radius / least privilege.** L'app più esposta agli attacchi detiene il token
  Graph capace di *agire* su Intune (inviare remediation, leggere device). Una
  compromissione dell'API = capacità di azione privilegiata sul tenant.
- **Resilienza.** Le chiamate Graph sincrone falliscono o vengono *throttled* (429)
  proprio durante i dispatch a gruppi grandi; oggi l'errore si propaga al chiamante e
  non c'è retry/back-off strutturato né dead-letter.
- **Throughput & rate limit.** Un dispatch a un gruppo da N device fa N chiamate Graph
  in linea: latenza alta e rischio throttling, senza controllo di concorrenza.
- **Osservabilità & ripetibilità.** Non c'è uno stato persistente per-comando
  (in-corso/riuscito/fallito) consultabile dal portale o ri-eseguibile.
- **Separazione delle responsabilità.** Coerente con i vincoli di subscription già
  adottati (No SAS → MI ovunque; No public network → private endpoint).

---

## 3. Decisione

Introdurre un **control-plane asincrono basato su comandi**:

> L'API diventa **low-privilege**: NON detiene più app-role Graph privilegiate.
> Pubblica **comandi** su Service Bus. Un **worker Azure Functions dedicato** (con la
> propria Managed Identity privilegiata) consuma i comandi ed esegue le chiamate Graph,
> scrivendo lo **stato** in SQL. Il portale legge lo stato (eventual consistency).

```
                       ┌──────────────────────────┐
   client ─mTLS(APIM)─▶│  ChromePolicyManager.Api │   (low-priv: nessuna app-role Graph)
   portale Admin ─────▶│  - serve policy          │
                       │  - accetta report        │   enqueue command
                       │  - enqueue comandi ──────┼──────────────┐
                       └───────────┬──────────────┘              ▼
                                   │ read/write           ┌─────────────────────┐
                                   ▼                      │ SB queue cpm-commands│
                                ┌─────┐  ◀── stato ──────  └──────────┬──────────┘
                                │ SQL │                               │ SB trigger
                                └─────┘  ◀── risultati ──┐            ▼
                                                         │   ┌───────────────────────┐
   Graph webhook ─▶ /api/webhooks (API) ─ enqueue ──────┘   │ cpm-worker (Functions) │
                                                             │  MI privilegiata        │
                                                             │  Graph → Intune/Entra   │
                                                             └───────────────────────┘
```

---

## 4. Modello dei comandi

Envelope JSON unico, serializzato nel body del `ServiceBusMessage`:

```jsonc
{
  "type": "PushRemediationDispatch",   // discriminator
  "commandId": "6f1c…",                 // idempotency key (== ServiceBusMessage.MessageId)
  "correlationId": "…",                 // tracciamento end-to-end (assignment, request)
  "attempt": 1,
  "issuedBy": "user@contoso.com",       // attore (audit)
  "issuedAt": "2026-06-27T13:00:00Z",
  "payload": { /* specifico per type */ }
}
```

### 4.1 Catalogo comandi (tutte le azioni privilegiate)

| `type` | Origine (enqueue) | Payload | Azione del worker |
|---|---|---|---|
| `PushRemediationDispatch` | `AssignmentService` (toggle ON / trigger / policy update) | `{ assignmentId, reason }` | enumera gruppo → risolve managedDevice → invia remediation a batch |
| `PushRemediationDevice` | endpoint device singolo | `{ entraDeviceId, reason }` | risolve managedDevice → invia remediation |
| `GroupMembershipChanged` | `/api/webhooks` (callback Graph) | `{ groupId, changeType }` | rilegge membership → ricalcola/triggera dispatch interessati |
| `WebhookSubscriptionSync` | timer (vedi §6.2) | `{}` | crea/rinnova/rimuove `subscriptions` per i gruppi attivi |

> `GroupSearch` (autocomplete del portale) **resta sincrono** sull'API: è read-only, a
> bassissimo privilegio (`Group.Read.All`) e richiede risposta immediata. Vedi §8.1 per
> la scelta su dove tenere questa singola app-role.

---

## 5. Topologia Service Bus

### 5.1 Vincolo di tier (Basic)

Il namespace attuale è **Basic** con `disableLocalAuth=true` (MI-only, policy-compliant;
i Private Endpoint richiederebbero Premium ≈ €670/mese). **Basic supporta solo queue**:

| Funzionalità | Basic | Serve per noi? |
|---|---|---|
| Queue | ✅ | Sì |
| Dead-letter queue | ✅ | Sì (gestione fallimenti) |
| Scheduled / delayed delivery | ✅ | Sì (back-off retry) |
| Message TTL | ✅ | Sì |
| Topics / Subscriptions (fan-out) | ❌ | Evitare → usare code multiple |
| Sessions (ordering per-device) | ❌ | Non richiesto in v1 |
| Duplicate detection nativa | ❌ | **Idempotenza a livello app** (§7) |

### 5.2 Code proposte

| Queue | Producer | Consumer | Note |
|---|---|---|---|
| `cpm-commands` | API + webhook receiver | `cpm-worker` | coda comandi privilegiati |
| `cpm-commands/$DeadLetterQueue` | (sistema) | alerting/manuale | DLQ automatica |
| `device-reports` | API (esistente) | **migrare** su `cpm-worker` o lasciare in API | vedi §10 fase 3 |

Una sola coda comandi è sufficiente in v1 (volumi bassi). Se in futuro serve isolare i
ritmi (es. dispatch massivi vs webhook real-time), **splittare in code per priorità**
(`cpm-commands-bulk`, `cpm-commands-rt`) — non con i topic, non disponibili in Basic.

---

## 6. Worker: Azure Functions (trigger Service Bus)

Host scelto: **Azure Functions** con **Service Bus trigger**, identità MI privilegiata,
VNet-integrato per raggiungere SQL via private endpoint.

### 6.1 Note implementative critiche (lezioni apprese)

- **Passwordless MI su Flex Consumption:** lo scaler per-funzione **non registra** i
  trigger Service Bus passwordless finché non si forza `functionAppConfig.scaleAndConcurrency.alwaysReady = [{ name: "function:<lowercasefunctionname>", instanceCount: 1 }]`.
  Va impostato altrimenti il listener SB non parte.
- **App settings vietati su Flex:** `FUNCTIONS_WORKER_RUNTIME` e
  `FUNCTIONS_EXTENSION_VERSION` causano `BadRequest 51021`. Il runtime va definito solo
  in `functionAppConfig.runtime`.
- **Connessione SB passwordless:** usare il binding con suffisso
  `__fullyQualifiedNamespace` (es. `ServiceBusConnection__fullyQualifiedNamespace`) e MI
  — **mai** connection string SAS (il namespace ha `disableLocalAuth=true` → 401
  `LocalAuthDisabled`).
- **Cache token MI:** dopo aver assegnato nuove app-role alla UAMI del worker, il claim
  `roles` può mancare fino a ~24h (cache token della piattaforma). Per forzare un token
  fresco: `az functionapp identity remove` + `identity assign` (stessa UAMI) + restart.
- **Deploy:** usare `az functionapp deployment source config-zip` (emette *sync
  triggers*); il solo upload del blob non aggiorna i trigger.

> In alternativa, se la registrazione dei trigger SB su Flex risultasse instabile, un
> `BackgroundService` su **Container App**/**App Service** evita del tutto la
> problematica `alwaysReady`. Tenuto come fallback (§12).

### 6.2 Funzioni

| Function | Trigger | Ruolo |
|---|---|---|
| `CommandHandler` | Service Bus (`cpm-commands`) | dispatch su `type` → handler specifico |
| `WebhookSubscriptionTimer` | Timer (es. ogni 6h) | enqueue `WebhookSubscriptionSync` (rinnovo prima della scadenza Graph, max ~3 giorni) |

---

## 7. Stato comandi, idempotenza e retry

### 7.1 Tabella di stato (SQL — control-plane history)

Coerente con la regola "su SQL: config policy + storico recepito dai client". Lo stato
dei comandi è **storico operativo**, quindi va in SQL:

```sql
CREATE TABLE PrivilegedCommands (
    CommandId      UNIQUEIDENTIFIER PRIMARY KEY,   -- == ServiceBusMessage.MessageId
    Type           NVARCHAR(64)  NOT NULL,
    CorrelationId  NVARCHAR(128) NULL,
    Status         NVARCHAR(20)  NOT NULL,         -- Pending|Running|Succeeded|Failed|DeadLettered
    Attempt        INT           NOT NULL DEFAULT 1,
    PayloadJson    NVARCHAR(MAX) NOT NULL,
    ResultJson     NVARCHAR(MAX) NULL,             -- conteggi devices/sent/failed/batches
    Error          NVARCHAR(MAX) NULL,
    IssuedBy       NVARCHAR(256) NULL,
    IssuedAt       DATETIME2     NOT NULL,
    UpdatedAt      DATETIME2     NOT NULL
);
```

### 7.2 Idempotenza (necessaria: niente dedup nativa in Basic)

1. L'API, all'enqueue, **inserisce** la riga `Pending` con `CommandId` (PK) e usa lo
   stesso valore come `MessageId`.
2. Il worker, all'ingresso, fa un *upsert*: se `Status ∈ {Succeeded}` → **scarta**
   (replay/duplicato), altrimenti passa a `Running`.
3. Gli effetti Graph sono naturalmente idempotenti o resi tali (inviare due volte una
   remediation allo stesso device è innocuo / verificabile).

### 7.3 Retry e dead-letter

- Retry trasparenti del `ServiceBusProcessor` (MaxDeliveryCount, es. 5) → poi **DLQ**.
- Per back-off controllato su throttling Graph: rileggere `Retry-After`, **ri-schedulare**
  il comando con *scheduled delivery* (`ScheduleMessageAsync`) e incrementare `Attempt`.
- Un alert (Azure Monitor) sulla profondità della **DLQ** segnala i comandi morti.

---

## 8. Identità, RBAC e least privilege

| Identità | Prima | Dopo |
|---|---|---|
| `cpm-api` (UAMI) | app-role Graph **privilegiate** + SB sender/receiver | **solo** SB *Sender* su `cpm-commands`; SQL R/W; App Config Reader; (opz.) `Group.Read.All` per la search |
| `cpm-worker` (UAMI) | — | app-role Graph privilegiate (`DeviceManagementManagedDevices.PrivilegedOperations.All`, `…Read.All`, `Device.Read.All`, `Group.Read.All`); SB *Receiver* su `cpm-commands`; SQL R/W; App Config Reader |
| `cpm-admin` (SAMI) | invariata | invariata (parla solo con l'API) |

Ruoli dati-plane SB (MI): **Azure Service Bus Data Sender** (API) e **Data Receiver**
(worker), assegnati a livello di coda dove possibile.

### 8.1 Decisione su `GroupSearch`

Due opzioni:
- **(A)** Tenere `Group.Read.All` anche sull'API (search sincrona, UX immediata). Privilegio
  *read-only* e basso rischio. **Preferita.**
- **(B)** Spostare anche la search dietro un comando + polling. Sacrifica l'UX
  dell'autocomplete per purezza architetturale. Sconsigliata.

---

## 9. Flussi end-to-end

### 9.1 Push remediation (toggle / trigger / policy update)
```
Admin toggle ON ─▶ API: UpdateAssignmentPushRemediation
                   ├─ persiste PushRemediationEnabled (SQL)
                   ├─ INSERT PrivilegedCommands(Pending)
                   └─ SB.Send(cpm-commands, PushRemediationDispatch)  ──▶ 200 "in coda"
cpm-worker: trigger ─▶ Running ─▶ enumera gruppo ─▶ risolve managedDevice
            ─▶ invia remediation a batch ─▶ ResultJson(sent/failed) ─▶ Succeeded
Portale: legge stato comando (badge "in corso → completato N inviati / M falliti")
```

### 9.2 Cambio membership gruppo (real-time)
```
Graph ─▶ /api/webhooks (API, validato ClientState) ─▶ INSERT cmd + SB.Send(GroupMembershipChanged) ─▶ 202
cpm-worker ─▶ rilegge membership ─▶ ricalcola assegnazioni interessate ─▶ (eventuale) dispatch
```

### 9.3 Rinnovo subscription (timer)
```
WebhookSubscriptionTimer (worker) ogni 6h ─▶ SB.Send(WebhookSubscriptionSync)
cpm-worker ─▶ per ogni gruppo attivo: crea/PATCH(rinnova)/DELETE subscription
```

---

## 10. Migrazione incrementale

| Fase | Contenuto | Reversibile? |
|---|---|---|
| 0 | Doc (questo ADR) + provisioning `cpm-worker` (Functions) + coda `cpm-commands` + tabella `PrivilegedCommands` | ✅ |
| 1 | Spostare **PushRemediation** dietro comando; API enqueue, worker esegue. Rimuovere le app-role Intune dall'API | ✅ (feature flag `PrivilegedActions:Mode = Inline|Queued`) |
| 2 | Spostare **webhook subscription lifecycle** + handler `GroupMembershipChanged` sul worker | ✅ |
| 3 | (Opz.) Spostare anche `device-reports` processor sul worker, dismettere il `BackgroundService` in-API | ✅ |
| 4 | Hardening: alert DLQ, dashboard stato comandi nel portale, rimozione codice inline | — |

Un **feature flag** (`PrivilegedActions:Mode`) consente di mantenere il percorso inline
come fallback durante la transizione, riducendo il rischio.

---

## 11. Costi (indicativi, dev)

| Componente | Tier | Costo/mese |
|---|---|---|
| Service Bus (esistente) | Basic, MI-only | ~€0.05 / 1M operazioni |
| Functions worker | Flex Consumption (pay-per-exec) | ~€0–5 a questi volumi |
| SQL (esistente, condiviso) | — | invariato |
| (Eventuale) SB Standard per dedup/topic | Standard | ~€10 |

Impatto trascurabile in dev; il valore è **sicurezza + resilienza**, non risparmio.

---

## 12. Alternative considerate

1. **Status quo (tutto inline nell'API).** Semplice, ma non risolve blast-radius né
   resilienza. Va bene solo a volumi minimi e basso rischio.
2. **Worker come `BackgroundService` (Container App / App Service).** Evita le insidie
   `alwaysReady`/`51021` di Functions Flex; ma è un host “sempre acceso”. **Fallback** se
   i trigger SB passwordless su Flex risultano instabili.
3. **Storage Queue invece di Service Bus.** Supporta Private Endpoint su Standard a
   ~€0.05/mese e MI; ma perde DLQ nativa, scheduled delivery “first-class” e semantica
   ricca. Valida se si vuole **PE** senza salire a SB Premium.
4. **Durable Functions / orchestrazioni.** Utile se i comandi diventano *saga*
   multi-step con compensazione; over-engineering per la v1.

---

## 13. Conseguenze

**Positive**
- L'app esposta non può più *agire* privilegiatamente su Intune (riduzione netta del
  blast radius).
- Retry/back-off/DLQ strutturati; resistenza al throttling Graph.
- Stato per-comando persistente, osservabile e ri-eseguibile.
- Scalabilità del worker indipendente dalla superficie API.

**Negative / costi**
- **Eventual consistency:** le azioni non sono più istantanee — il portale deve mostrare
  lo stato “in corso”. Cambio di UX (e di aspettative).
- Più infrastruttura: una app, una UAMI, RBAC, pipeline di deploy in più.
- Idempotenza e DLQ da gestire a livello applicativo (Basic non aiuta).

---

## 14. Domande aperte

1. `GroupSearch`: confermare opzione **(A)** (search read-only sull'API).
2. Profondità retry / `MaxDeliveryCount` e politica di alert sulla DLQ.
3. Visualizzazione stato comandi nel portale: polling SQL (semplice) vs SignalR
   (real-time) — propendo per polling in v1.
4. `device-reports`: migrare sul worker (fase 3) o lasciare in-API?
5. Tier SB: restare Basic (idempotenza app) o salire a Standard per dedup/topic se i
   volumi crescono?

---

## 15. Decisioni (§14 risolte) e note di implementazione dello scaffold

Decisioni prese dal proprietario:
1. **GroupSearch read-only** resta sull'API (autocomplete, nessun decoupling).
2. **Retry/DLQ**: `maxDeliveryCount = 5` su `cpm-commands`; back-off gestito dal runtime SB; DLQ su scadenza/esaurimento tentativi. Alert su DLQ da configurare lato monitoring.
3. **Stato in tempo reale**: **SignalR** (`CommandStatusHub`).
4. **device-reports**: da migrare sul Worker (fase successiva).
5. **Tier SB**: **Basic**, idempotenza a livello applicativo (riga `PrivilegedCommands`).

Raffinamento architetturale adottato nello scaffold (deviazione rispetto alle bozze §5–§9):
- **Il Worker NON accede a SQL.** L'API arricchisce ogni payload con tutti i dati necessari
  (es. `EntraGroupId` + `GroupName` per il dispatch). Questo mantiene SQL di proprietà dell'API,
  riduce la superficie di private endpoint del Worker e semplifica la RBAC.
- **Stato via coda dedicata.** Il Worker non può scrivere direttamente sull'hub SignalR dell'API,
  quindi pubblica `CommandStatusUpdate` sulla coda **`cpm-command-status`**; un `BackgroundService`
  dell'API (`CommandStatusRelay`) la consuma, aggiorna la riga `PrivilegedCommands` e fa il
  broadcast SignalR ai client del portale.
- **Webhook membership.** Anziché un comando generico `GroupMembershipChanged` che richiederebbe
  letture SQL nel Worker, l'API (che possiede SQL) risolve le assegnazioni impattate e accoda
  direttamente `PushRemediationDispatch` concreti. Il comando `WebhookSubscriptionSync` (payload =
  elenco group id attivi) resta per la riconciliazione delle subscription Graph ed è **stub** in
  attesa della migrazione (fase 2).

### Stato implementazione (scaffold compilante, feature-flag OFF di default)
| Componente | Stato |
|---|---|
| `ChromePolicyManager.Contracts` (envelope/tipi/payload/stato) | ✅ |
| Entità EF `PrivilegedCommand` + creazione tabella idempotente | ✅ |
| `CommandQueueClient` + `ICommandPublisher` (riga Pending + enqueue) | ✅ |
| `CommandStatusHub` (SignalR) + `CommandStatusRelay` | ✅ |
| Feature flag `PrivilegedActions:Mode` (Inline default \| Queued) | ✅ |
| `/api/commands` (lista/dettaglio stato) | ✅ |
| Worker Functions isolated + `CommandHandlerFunction` (trigger SB) | ✅ |
| `PrivilegedGraphActions` (porting push remediation, no SQL/Audit) | ✅ |
| `WebhookSubscriptionSync` nel Worker | ⏳ stub (fase 2) |
| Migrazione `device-reports` sul Worker | ⏳ fase 3 |
| Infra: code `cpm-commands`/`cpm-command-status` + modulo Worker opt-in | ✅ |
| Sottoscrizione SignalR lato portale Admin | ⏳ fase 2 |

Con `PrivilegedActions:Mode` assente o `Inline`, il comportamento resta identico a oggi (l'API
esegue le chiamate Graph in-process). Impostando `Queued` (e con Service Bus configurato), i
dispatch vengono accodati al Worker.

---

## 16. Pipeline stato applicazione policy via Event Grid

Per alimentare il portale con lo **stato di applicazione delle policy** lato device si usa
**Azure Event Grid** come backbone di eventi (custom topic), separato dalla coda comandi SB.

### Razionale
- Event Grid **non consegna ai browser**: il portale è Blazor Server, quindi l'ultimo hop verso
  il client resta **SignalR**. Event Grid è il layer di distribuzione *a monte* che disaccoppia i
  produttori (API oggi, Worker dopo la migrazione device-reports) dal consumatore (l'API che fa
  broadcast SignalR), e abilita fan-out verso futuri subscriber (analytics, alerting, Teams).
- Compatibile con le policy: topic con `disableLocalAuth=true` (no SAS), pubblicazione con
  **Managed Identity** (ruolo *EventGrid Data Sender*).

### Flusso
```
Device ─▶ APIM ─▶ SB(device-reports) ─▶ DeviceReportProcessor (API)
   └─ (fallback sync: POST /api/devices/{id}/report)
                                   │ persiste DeviceState (SQL)
                                   └─ EventGrid.Publish(DevicePolicyStatusChanged)  [MI]
EventGrid topic ─▶ (subscription webhook) ─▶ POST /api/eventgrid/policy-status (API)
                                   ├─ handshake SubscriptionValidation
                                   └─ broadcast SignalR (PolicyStatusHub) ─▶ Portale (real-time)
```

### Componenti
| Lato | Componente | Ruolo |
|---|---|---|
| Contracts | `DevicePolicyStatusChangedData`, `PolicyEventTypes` | contratto evento versionato |
| API (producer) | `IEventPublisher` / `EventGridEventPublisher` | publish MI; no-op se `EventGrid:TopicEndpoint` assente |
| API (producer) | `DeviceReportProcessor` + fallback endpoint | emette l'evento dopo aver persistito il report |
| API (subscriber) | `EventGridEndpoints` (`/api/eventgrid/policy-status`) | handshake + ribroadcast |
| API (subscriber) | `PolicyStatusHub` (SignalR) | push verso il portale |
| Infra | topic `cpm-<env>-events` + RBAC + subscription opt-in | backbone eventi |

### Note operative
- La **event subscription** (webhook) è **opt-in** (`deployEventGridSubscription=true`): va
  abilitata *dopo* che l'API con `/api/eventgrid/policy-status` è deployata e raggiungibile, perché
  Event Grid esegue l'handshake di validazione alla creazione.
- Sicurezza: in scaffold l'endpoint è anonimo (la validazione autentica la subscription). In
  produzione usare delivery **AAD-secured** (Entra) verso il webhook.
- L'evento è **best-effort**: un errore di publish non fa fallire l'elaborazione del report.
- Quando i device-reports verranno migrati sul Worker (fase 3), sarà il Worker a pubblicare gli
  eventi sullo stesso topic: l'API resta l'unico subscriber/broadcaster SignalR, senza modifiche
  al contratto.

> Differenza con la coda `cpm-command-status`: quest'ultima serve il ciclo di vita dei **comandi
> privilegiati** (semantica work-queue/affidabilità), mentre Event Grid serve le **notifiche di
> stato** ad alto fan-out verso il portale. Sono due domini distinti e coesistono.

---

*Fine ADR-001.*
