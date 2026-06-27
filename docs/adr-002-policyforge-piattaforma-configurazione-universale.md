
# ADR-002 — PolicyForge: piattaforma universale di desired-state configuration per device Intune

> Documento di design / Architecture Decision Record.
> **Stato:** Proposto · **Data:** 2026-06-27 · **Autore:** @robgrame (con GitHub Copilot)
> **Ambito:** generalizzare `PolicyForge` (specifico per gli ADMX di Google Chrome)
> in una piattaforma **agnostica** capace di gestire *qualunque* ADMX e, soprattutto,
> classi di configurazione che Intune oggi non copre bene o non copre affatto
> (registry arbitrario, servizi Windows, scheduled task, file, gruppi locali,
> variabili d'ambiente…) — una sorta di **Group Policy Preferences per il mondo
> cloud-only / Intune**.
>
> Documento fondativo del repository **PolicyForge** (clone evolutivo di
> PolicyForge). Erede e complementare di
> [`adr-001-decoupling-azioni-privilegiate.md`](./adr-001-decoupling-azioni-privilegiate.md).

---

## 1. Contesto

`PolicyForge` nasce per colmare un gap puntuale: gli ADMX di Chrome non si
applicano sui device **Entra ID–only** perché Chrome usa `RegisterGPNotification()` e il
GP Client Service non rispecchia le chiavi `PolicyManager` su
`HKLM\SOFTWARE\Policies\Google\Chrome`. La soluzione consegna le policy **direttamente nel
registry** del device via Intune Proactive Remediation, bypassando la pipeline GP rotta.

Il problema, però, è **molto più ampio di Chrome**. Lo stesso meccanismo — *risolvi sul
server lo stato desiderato → applica via script → riporta lo stato reale* — è una base
ideale per una piattaforma generale di configurazione. Intune oggi presenta diversi
**buchi funzionali** che gli amministratori coprono a mano con script PowerShell sparsi,
Remediations non versionate e OMA-URI fragili.

### 1.1 Gap di Intune che PolicyForge intende colmare

| Dominio | Limite attuale di Intune | Valore di PolicyForge |
|---|---|---|
| **ADMX di terze parti** | Import macchinoso, limiti di dimensione, nessun versioning/lifecycle, alcuni ADMX non si ingeriscono | Ingestion di *qualunque* ADMX/ADML, catalogo navigabile, **versioning legato alla versione prodotto** (già realizzato per Chrome: `AdmxVersion`) |
| **Registry arbitrario** | Solo via OMA-URI (Policy CSP) o script PS; nessun modello dichiarativo, niente targeting fine | Valori registry dichiarativi e **tipizzati** (`REG_SZ`/`DWORD`/`QWORD`/`MULTI_SZ`/`EXPAND_SZ`/`BINARY`), stile GPP |
| **Servizi Windows** | Non gestiti nativamente | Startup type, stato desiderato (running/stopped), account, recovery actions |
| **Scheduled Tasks** | No | Crea/aggiorna/abilita/disabilita task (XML o definizione dichiarativa) |
| **File / cartelle / shortcut** | No | Deploy di file/contenuti, creazione cartelle, collegamenti (`.lnk`), ACL di base |
| **Local users & groups** | Solo LAPS / Account Protection limitato | Membership dichiarativa dei gruppi locali (add/remove/replace), gestione utenti locali |
| **Variabili d'ambiente** | No | Set/remove di env var di sistema/utente |
| **Drift detection & remediation** | Solo Remediations script-based, output non strutturato | Ciclo **Detect → Apply → Remediate → Report** per ogni item, con compliance per device e storico |

### 1.2 Cosa riusiamo "as-is" da PolicyForge

Quasi tutto lo scaffolding è **già generico** e di alto valore:

- **Auth & sicurezza**: Entra ID, **Managed Identity passwordless** (no SAS), App
  Configuration come provider `IConfiguration`, APIM/mTLS per il traffico device.
- **Infra Bicep** parametrica con SKU **dev/prod**, script di deploy infra+codice.
- **Decoupling azioni privilegiate** (ADR-001): worker + Service Bus per le chiamate
  Graph ad alto privilegio.
- **Pipeline di stato**: Service Bus per l'ingestion dei report, **Event Grid + SignalR**
  per gli aggiornamenti live nel portale.
- **Targeting**: assegnazione a gruppi/device via Microsoft Graph.
- **Versioning + ADMX version tracking**: bozze, versioni immutabili, traccia della
  versione ADMX/prodotto.
- **Client model**: detection + inline remediation come Intune script (scelta confermata
  per la v1).

> In altre parole: **non riscriviamo la piattaforma**. Generalizziamo il *dominio* e
> introduciamo un'astrazione a **provider**; tutto il resto (auth, infra, code, reporting)
> resta.

---

## 2. Decisione

Costruiamo **PolicyForge**: una piattaforma di **desired-state configuration** in cui ogni
unità di configurazione è un **ConfigurationItem** polimorfico, gestito da un **provider**
pluggabile che implementa un contratto uniforme `Detect / Apply / Remediate / Report`,
sia **lato server** (catalogo, validazione, materializzazione) sia **lato client** (script
di applicazione e reporting).

Il client per la **v1** resta il modello attuale: uno script di **detection + inline
remediation** distribuito come Intune Proactive Remediation (nessun installer/agent
dedicato). Lo script diventa però **multi-provider**: legge dal server il profilo
assegnato (composto da item di tipi diversi) e applica ciascun item con la logica del
provider corrispondente.

---

## 3. Modello di dominio

Sostituiamo il modello "PolicySet specifico per Chrome" con un modello generico:

```
ConfigurationProfile            (ex PolicySet — versionato, assegnabile)
 ├─ metadata: nome, descrizione, owner, tag, targetOS
 └─ ConfigurationProfileVersion (immutabile una volta pubblicata)
     ├─ versionNumber, state (Draft/Published/Archived)
     ├─ admxVersion?            (già esistente — vale per gli item AdmxPolicy)
     └─ ConfigurationItem[]     ── ognuno con un ProviderType e un payload tipizzato:
          ├─ AdmxPolicy           { namespace, policyId, value, scope(HKLM/HKCU) }
          ├─ RegistryValue        { hive, key, name, type, data }
          ├─ WindowsService       { name, startupType, desiredState, account? }
          ├─ ScheduledTask        { name, definitionXml | declarative, state }
          ├─ FileResource         { targetPath, source(content/url), acl?, ensure }
          ├─ LocalGroupMembership { group, members[], action(Add/Remove/Replace) }
          └─ EnvironmentVariable  { scope(Machine/User), name, value, ensure }
```

### 3.1 Contratto del provider

Ogni provider implementa un'interfaccia comune (nomi indicativi):

```csharp
public interface IConfigurationProvider
{
    string ProviderType { get; }                 // "RegistryValue", "WindowsService", ...

    // Lato server: valida e "compila" l'item in istruzioni serializzabili per il client.
    ValidationResult Validate(ConfigurationItem item);
    ResolvedInstruction Compile(ConfigurationItem item);
}
```

Lato **client** ogni provider espone le funzioni PowerShell `Test-<Provider>` (detect),
`Set-<Provider>` (apply/remediate) e produce un **record di compliance** per item
(`Compliant` / `Drifted` / `Error`), aggregato nel report di device che già fluisce in
Service Bus → SQL → Event Grid → SignalR.

### 3.2 Idempotenza & desired-state

Ogni provider è **idempotente**: `Test` determina se lo stato reale combacia col desiderato;
`Set` viene invocato solo in caso di drift. Il report distingue **detect-only** (audit) da
**enforce** (remediation attiva), riusando il concetto del toggle "Push remediation".

---

## 4. Provider v1 (scope confermato)

Inclusi nella prima versione, oltre all'**ADMX generico** (sempre incluso):

1. **RegistryValue** — il mattone fondamentale (molti altri domini ci si appoggiano).
2. **WindowsService** — startup type + stato desiderato + recovery.
3. **ScheduledTask** — create/update/enable/disable.
4. **FileResource** — file/cartelle/shortcut con `ensure: Present/Absent`.
5. **LocalGroupMembership** — gestione membership gruppi locali.
6. **EnvironmentVariable** — env var di sistema/utente.

Rinviati a iterazioni successive (già previsti nel modello, non implementati in v1):
hosts file/DNS, firewall rules, power options, printer/drive mapping, INI files,
certificati.

---

## 5. Generalizzazione del motore ADMX

Il parser ADMX attuale è tarato su Chrome ma la struttura ADMX/ADML è **standard**. La
generalizzazione consiste in:

- **Ingestion multi-ADMX**: upload di coppie `.admx` + `.adml` (più lingue), parsing dei
  `namespace`, `categories`, `policies`, `elements` (enum/decimal/text/list/boolean) e
  delle `supportedOn`/`presentation`.
- **Catalogo per prodotto**: ogni ADMX importato diventa un *namespace* navigabile; gli
  item `AdmxPolicy` referenziano `(namespace, policyId)`.
- **Versioning prodotto**: `AdmxVersion` (già modellato) traccia a quale versione del
  prodotto/ADMX si riferisce una policy, per gestire gli aggiornamenti ADMX nel tempo.
- **Materializzazione registry**: ogni `AdmxPolicy` compila verso chiavi/valori registry
  reali (riuso del provider **RegistryValue** come backend di applicazione).

> Conseguenza elegante: **AdmxPolicy → RegistryValue** è "solo" una compilazione. Il client
> applica tutto tramite il provider RegistryValue, mentre il server conserva la semantica
> ricca (enum, label, supportedOn) per l'authoring.

---

## 6. Client (modello script — v1)

Confermato il modello attuale (Intune Proactive Remediation, niente agent):

```
Intune ──(detection script)──▶ device
   device ──GET profilo assegnato──▶ API  (mTLS/APIM, deviceId Entra)
   per ogni ConfigurationItem:
        Test-<Provider>  → compliant? sì → skip ; no → Set-<Provider> (se enforce)
   device ──POST report compliance──▶ API ──▶ Service Bus ──▶ SQL ──▶ Event Grid ──▶ SignalR
```

- Lo script di remediation diventa **modulare**: un dispatcher che, in base al
  `ProviderType` di ciascun item, invoca il blocco PowerShell del provider.
- Il payload server→client è una lista di **ResolvedInstruction** tipizzate (JSON), già
  compilate e validate.
- Mantiene il pattern attuale: `deviceId` da `dsregcmd`, risoluzione via Graph
  `devices?$filter=deviceId eq '{id}'`, inline remediation (il flag `runRemediationScript`
  di Intune non è impostabile in modo affidabile via Graph).

---

## 7. Riuso architettura & vincoli di subscription

Invariati rispetto a PolicyForge e **non negoziabili**:

- **No SAS** ovunque → **Managed Identity** con `DefaultAzureCredential`.
- **No Public Network Access** sui data-plane (SQL, Storage) → **Private Endpoint** +
  VNet integration sulle App Service (`vnetRouteAllEnabled: true`).
- **Service Bus** Basic con `disableLocalAuth: true` (MI only).
- **APIM** con mTLS per il traffico device.
- **App Configuration** come unica fonte di configurazione (provider `IConfiguration`).
- **SQL** via Private Endpoint; SKU **dev/prod** parametrici in Bicep.

---

## 8. Roadmap di refactor (fasi)

| Fase | Contenuto | Esito |
|---|---|---|
| **0 — Bootstrap** | Repo `PolicyForge` creato, seed dal codice attuale, **questo ADR** | ✅ in corso |
| **1 — Rename & namespace** | `PolicyForge.*` → `PolicyForge.*` (progetti, namespace, `.slnx`, infra prefissi `pf-` → `pf-`), README riscritto sul nuovo scope | build verde |
| **2 — Astrazione provider** | `IConfigurationProvider`, modello `ConfigurationProfile/Item`, refactor del dominio Chrome→generico; **AdmxPolicy** e **RegistryValue** come primi provider | API + Admin compilano, Chrome resta caso d'uso valido |
| **3 — Provider v1 restanti** | WindowsService, ScheduledTask, FileResource, LocalGroupMembership, EnvironmentVariable (server validate/compile + client Test/Set) | provider testati singolarmente |
| **4 — ADMX generico** | Ingestion multi-ADMX, catalogo per namespace, authoring UI generalizzata | import di un ADMX arbitrario funzionante |
| **5 — Client multi-provider** | Dispatcher PowerShell modulare, ResolvedInstruction tipizzate, reporting compliance per item | E2E su un device di test |
| **6 — Infra & deploy** | Bicep/parametri rinominati, App Config keys, pipeline di deploy dev/prod | deploy pulito su `rg-pf-dev` |

> Le fasi 1–2 sono il refactor "rischioso" (rename + dominio). Le successive sono additive.

---

## 9. Naming & convenzioni

- **Prodotto/namespace**: `PolicyForge` (`PolicyForge.Api`, `PolicyForge.Admin`,
  `PolicyForge.Worker`, `PolicyForge.Contracts`).
- **Prefisso risorse Azure**: `pf-{env}-*` (es. `pf-dev-api`, `rg-pf-dev`,
  `pf-dev-config`). RG dev di riferimento: `rg-pf-dev`.
- **Solution**: `PolicyForge.slnx`.
- **Provider naming**: `<Dominio>Provider` server-side, `Test-/Set-<Dominio>` client-side.

---

## 10. Conseguenze

**Positive**
- Una sola piattaforma copre Chrome *e* qualunque altro ADMX *e* configurazioni non-policy.
- Modello estensibile: nuovi domini = nuovo provider, senza toccare il core.
- Riuso massimo di auth/infra/reporting già hardenizzati e policy-compliant.

**Negative / rischi**
- Refactor del dominio (fasi 1–2) tocca molti file; serve build/test incrementale.
- Provider "potenti" (registry/servizi/file) ampliano la superficie di rischio sui device:
  vanno gestiti con audit-first, scoping per gruppo e enforce opt-in.
- L'idempotenza e il rollback per i provider che modificano lo stato OS (servizi, gruppi
  locali) richiedono attenzione (snapshot dello stato precedente nel report).

---

## 11. Domande aperte — RISOLTE

> Tutte le domande aperte sono state risolte e implementate (2026-06-25).

1. **Rollback / undo** — ✅ *Implementato*. Lo stato precedente di ogni item modificato
   viene catturato (snapshot inverso) lato client e riportato; UI di audit in `Snapshots.razor`.
2. **Scoping di sicurezza** — ✅ *Implementato*. `ConfigurationGuardrails` (deny-list anti-footgun)
   blocca in fase di compile/versioning prefissi registry protetti, servizi critici, delete su
   `C:\Windows`, task `\Microsoft\Windows`, modifiche al gruppo Administrators. Configurabile via
   `PolicyForge:Guardrails`.
3. **Conflitti tra profili** — ✅ *Implementato come warning*. Il compiler rileva item duplicati/
   sovrapposti e popola `ResolvedConfiguration.Warnings` (non bloccante); mostrati nell'anteprima
   di compile in `Profiles.razor`.
4. **Targeting HKCU** — ✅ *Implementato*. Il dispatcher client retargeta gli item user-scope su
   ogni hive utente caricato (`HKEY_USERS\<sid>`, SID Entra `S-1-12-1-` e on-prem `S-1-5-21-`) durante
   il passaggio SYSTEM, e registra uno scheduled task per-utente AtLogon (`ApplyUser`) per i profili
   non caricati / futuri.
5. **Visibilità repo** — ✅ *Risolto*. Repo **pubblico** con licenza **Apache-2.0**.

