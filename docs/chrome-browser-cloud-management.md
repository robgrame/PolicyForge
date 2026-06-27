
# Chrome Browser Cloud Management (CBCM) — il canale di gestione nativo di Chrome

> Documento tecnico di riferimento — analisi del codice sorgente di Chromium per
> comprendere **come funziona il canale di gestione cloud nativo e proprietario**
> con cui Google gestisce Chrome a livello Enterprise (l'equivalente "MDM per il
> browser"), e come si rapporta all'approccio *registry-based* di Chrome Policy
> Manager (`src/Client/Detect-ChromePolicy.ps1`,
> `src/Client/Remediate-ChromePolicy.ps1`).
>
> Documento complementare a [`chromium-policy-loading.md`](./chromium-policy-loading.md),
> che descrive il **Platform provider** (lettura del registro Windows). Questo
> documento descrive il **Cloud provider**.

## 1. Scopo e fonti

Oltre al provider che legge `HKLM\SOFTWARE\Policies\Google\Chrome` (il *Platform
provider* analizzato nell'altro documento), Chrome incorpora un secondo canale
**indipendente**: **Chrome Browser Cloud Management (CBCM)**. È il prodotto
Enterprise gestito dalla **Google Admin Console** (admin.google.com) che permette
di amministrare i browser Chrome — inventario, policy, report, comandi remoti —
con un modello del tutto analogo a un MDM, **senza** Group Policy e **senza**
registro come trasporto.

Sorgenti analizzati (branch `main` di Chromium, dominio pubblico
[chromium.googlesource.com](https://chromium.googlesource.com/chromium/src/)):

| File / area | Percorso nel repo Chromium | Ruolo |
|---|---|---|
| `cloud_policy_constants.cc/.h` | `components/policy/core/common/cloud/` | Costanti del **protocollo Device Management** (DM): tipi di richiesta, header di auth, query param, tipi di policy, endpoint di default |
| `cloud_policy_client.cc/.h` | `components/policy/core/common/cloud/` | Client del **DMServer**: registrazione, fetch policy, upload status, remote commands |
| `device_management_service.cc/.h` | `components/policy/core/common/cloud/` | Trasporto HTTP verso il DMServer (costruzione URL, job, retry) |
| `cloud_policy_core` / `cloud_policy_manager` / `cloud_policy_store` | `components/policy/core/common/cloud/` | Orchestrazione, ciclo di refresh, persistenza e validazione delle policy cloud |
| `cloud_policy_validator.cc` | `components/policy/core/common/cloud/` | Validazione della `PolicyFetchResponse` (firma, chiave pubblica, timestamp, DM token, tipo) |
| `affiliation.cc/.h` | `components/policy/core/common/cloud/` | Calcolo dell'**affiliation** (utente vs dispositivo nello stesso tenant) |
| `browser_dm_token_storage_win.cc` | `chrome/browser/policy/` | Persistenza su Windows di **client id**, **enrollment token** e **DM token** |
| `chrome_browser_cloud_management_controller` | `components/policy/core/common/cloud/` + `chrome/browser/enterprise/` | Avvio/coordinamento dell'enrollment lato browser |

> Nota sui riferimenti: in questo documento si citano **file e simboli**
> (funzioni/classi) realmente presenti nel codice analizzato, anziché numeri di
> riga, perché lo stack cloud è distribuito su molti file e i numeri di riga
> cambiano frequentemente tra le revisioni.

---

## 2. CBCM vs canale registro/GPO — quadro generale

Chrome costruisce le policy effettive unendo **più provider** in
`PolicyServiceImpl`. I principali su Windows desktop sono:

```
   ┌─────────────────────────────┐
   │  Platform provider          │  ← Registro/GPO  (POLICY_SOURCE_PLATFORM)
   │  policy_loader_win.cc       │     HKLM/HKCU\...\Policies\Google\Chrome
   ├─────────────────────────────┤
   │  Cloud machine provider     │  ← CBCM          (POLICY_SOURCE_CLOUD)
   │  (machine-level browser)    │     DMServer  ── google/chrome/machine-level-user
   ├─────────────────────────────┤
   │  Cloud user/profile provider│  ← Profilo gestito (Dasher account)
   │  UserCloudPolicyManager     │     DMServer  ── google/chrome/user
   └─────────────────────────────┘
                 │
                 ▼
        PolicyServiceImpl::MergeFrom()   →  PolicyMap effettiva
        (livello, scope, sorgente, precedenza)
```

- **Platform provider** = ciò che scrive **Chrome Policy Manager** (chiavi di
  registro). Sorgente `POLICY_SOURCE_PLATFORM`.
- **Cloud provider** = CBCM. Sorgente `POLICY_SOURCE_CLOUD` (machine) e
  `POLICY_SOURCE_CLOUD` con scope utente per il profilo gestito.
- I provider **coesistono**: una stessa macchina può avere policy via registro
  **e** via cloud. La risoluzione dei conflitti è governata dalle policy di
  **precedenza** (§11).

La differenza sostanziale: il Platform provider è un trasporto **locale**
(registro) che qualcuno deve popolare (GPO, MDM/Intune, o appunto la nostra
soluzione); CBCM è un trasporto **di rete** end-to-end verso l'infrastruttura
di Google.

---

## 3. Il protocollo Device Management (DM)

Tutto il canale cloud parla un unico protocollo applicativo, il **Device
Management protocol**, definito nel namespace `policy::dm_protocol`
(`cloud_policy_constants.cc`). È lo **stesso protocollo** usato dall'enrollment
di ChromeOS: cambia solo il *tipo di registrazione* e il *policy type*.

### 3.1 Endpoint e trasporto

- Le richieste vanno al **DMServer** di Google. L'URL di default è configurato
  in `cloud_policy_constants.cc` (`kDefaultDeviceManagementServerUrl`,
  storicamente `https://m.google.com/devicemanagement/data/api`) e può essere
  sovrascritto dallo switch `--device-management-url` (utile per i test).
- Il trasporto HTTP è implementato da **`DeviceManagementService`**, che impacca
  ogni operazione in un *job* con retry e backoff.

### 3.2 Parametri di query (URL)

Ogni chiamata porta una serie di parametri identificativi
(`cloud_policy_constants.cc`, namespace `dm_protocol`):

| Costante | Query param | Significato |
|---|---|---|
| `kParamRequest` | `request` | tipo di operazione (vedi §3.3) |
| `kParamDeviceID` | `deviceid` | **client id** della macchina/browser (§5.1) |
| `kParamDeviceType` | `devicetype` | tipo (`kValueDeviceType = "2"`) |
| `kParamAppType` | `apptype` | `kValueAppType = "Chrome"` |
| `kParamPlatform` | `platform` | OS/arch del client |
| `kParamAgent` | `agent` | user-agent applicativo (versione Chrome) |
| `kParamProfileID` | `profileid` | id del profilo (registrazione profilo) |
| `kParamOAuthToken` | `oauth_token` | token OAuth (auth utente) |
| `kParamCritical`, `kParamLastError`, `kParamRetry` | `critical`, `lasterror`, `retry` | flag diagnostici/ritrasmissione |

### 3.3 Tipi di richiesta (`request=`)

Il valore di `request` seleziona l'operazione. I più rilevanti per il browser:

| Costante | Valore | Uso |
|---|---|---|
| `kValueRequestRegisterBrowser` | `register_browser` | **Enrollment CBCM** di un browser (machine-level) |
| `kValueRequestRegister` | `register` | Registrazione (device, ChromeOS) |
| `kValueRequestRegisterProfile` | `register_profile` | Registrazione di un **profilo** gestito |
| `kValueRequestTokenBasedRegister` | `token_based_register` | Registrazione tramite enrollment token |
| `kValueRequestCertBasedRegister` | `certificate_based_register` | Registrazione basata su certificato |
| `kValueRequestPolicy` | `policy` | **Fetch delle policy** |
| `kValueRequestUploadStatus` | `status_upload` | Upload stato/telemetria |
| `kValueRequestChromeDesktopReport` | `chrome_desktop_report` | Report inventario Chrome desktop (CBCM) |
| `kValueRequestChromeProfileReport` | `chrome_profile_report` | Report a livello profilo |
| `kValueRequestRemoteCommands` | `remote_commands` | Recupero/ack **comandi remoti** |
| `kValueRequestUploadCertificate` | `cert_upload` | Upload certificato |
| `kValueRequestUnregister` | `unregister` | De-registrazione |
| `kValueRequestApiAuthorization` | `api_authorization` | Autorizzazione API (service accounts) |

### 3.4 Header di autorizzazione

L'header `Authorization` usa prefissi distinti a seconda della credenziale
(`cloud_policy_constants.cc`):

| Prefisso | Costante | Quando |
|---|---|---|
| `GoogleEnrollmentToken token=` | `kEnrollmentTokenAuthHeaderPrefix` | Durante l'**enrollment** (si presenta l'enrollment token) |
| `GoogleDMToken token=` | `kDMTokenAuthHeaderPrefix` | Per tutte le chiamate **post-enrollment** (policy, status, remote commands) |
| `GoogleLogin auth=` | `kServiceTokenAuthHeaderPrefix` | Service token (legacy/utente) |
| `OAuth` | `kOAuthTokenHeaderPrefix` | Auth utente OAuth |
| `GoogleDM3PAuth …` | `kOidcAuthHeaderPrefix` | Auth **OIDC di terze parti** (`oauth_token=`, `id_token=`, `encrypted_user_information=`) — scenario di enrollment via IdP non-Google |

> Questo è il cuore del modello di sicurezza: l'**enrollment token** è un segreto
> condiviso a livello di organizzazione che serve **solo** per ottenere il **DM
> token**; da quel momento in poi ogni macchina si autentica con il **proprio**
> DM token, univoco e revocabile dalla Admin Console.

### 3.5 Tipi di policy (`policy_type`)

Il fetch chiede uno o più *policy type* (`cloud_policy_constants.cc`):

| Costante | Valore | Scope |
|---|---|---|
| `kChromeMachineLevelUserCloudPolicyType` | `google/chrome/machine-level-user` | **CBCM** (browser, machine-level) |
| `kChromeUserPolicyType` | `google/chrome/user` | Profilo/utente gestito |
| `kChromeDevicePolicyType` | `google/chromeos/device` | ChromeOS device |
| `kChromePublicAccountPolicyType` | `google/chromeos/publicaccount` | ChromeOS public session |
| `kChromeExtensionPolicyType` | `google/chrome/extension` | Policy per **estensioni** consegnate via cloud |

Il valore distingue **quale tabella di policy** il DMServer deve restituire. Per
CBCM su Windows il tipo è `google/chrome/machine-level-user`.

---

## 4. Identità e token

CBCM si fonda su **tre identificativi** distinti, gestiti su Windows da
`BrowserDMTokenStorageWin` (`chrome/browser/policy/browser_dm_token_storage_win.cc`).

### 4.1 Client id — `InitClientId()`

Il **client id** della macchina è il **MachineGuid di Windows**, letto da:

```
HKLM\SOFTWARE\Microsoft\Cryptography  →  valore "MachineGuid"   (KEY_WOW64_64KEY)
```

È lo stesso GUID usato da molti agent come identità stabile della macchina. Viene
inviato come `deviceid` nel protocollo DM.

### 4.2 Enrollment token — `InitEnrollmentToken()`

L'**enrollment token** è fornito dalla Admin Console e iniettato come policy.
`BrowserDMTokenStorageWin::InitEnrollmentToken()` lo legge tramite
`InstallUtil::GetCloudManagementEnrollmentToken()`, che corrisponde alla policy:

```
HKLM\SOFTWARE\Policies\Google\Chrome\CloudManagementEnrollmentToken
```

(Può anche essere distribuito via GPO/MDM o, su altre piattaforme, file di
configurazione.) È **uguale per tutta l'organizzazione** e serve unicamente a
bootstrap dell'enrollment.

### 4.3 DM token — `InitDMToken()` / `StoreDMTokenInRegistry()`

Il **DM token** è il segreto **per-macchina** rilasciato dal DMServer dopo la
registrazione. Tre aspetti rilevanti emersi dal codice:

1. **Formato e posizione di lettura.** Il DM token è memorizzato come valore
   **`REG_BINARY`** (buffer iniziale 512 byte; tipicamente ~200 byte). La
   posizione è risolta da `InstallUtil::GetCloudManagementDmTokenLocation(...)`,
   e il loader **preferisce la posizione "app-neutral"** (quella di Google
   Update) rispetto a quella specifica del browser, per allinearsi al
   comportamento dell'updater:

   ```cpp
   // browser_dm_token_storage_win.cc — InitDMToken()
   for (const auto& location : {InstallUtil::BrowserLocation(false),   // app-neutral
                                InstallUtil::BrowserLocation(true)}) {  // browser
     std::tie(key, dm_token_value_name) =
         InstallUtil::GetCloudManagementDmTokenLocation(
             InstallUtil::ReadOnly(true), location);
     ...
     // value letta come REG_BINARY, poi TrimWhitespaceASCII
   }
   ```

2. **Scrittura tramite l'updater elevato (non dal browser).** Sotto branding
   Google Chrome, `StoreDMTokenInRegistry()` **non** scrive direttamente il
   registro: invoca un **app command di Google Update**
   (`installer::kCmdStoreDMToken`) passando il token **base64**, ed è l'updater
   (che gira elevato) a persistere il valore. Analogamente
   `DeleteDMTokenFromRegistry()` usa `kCmdDeleteDMToken`.

   ```cpp
   auto app_command = GetUpdaterAppCommand(installer::kCmdStoreDMToken);
   std::string token_base64 = base::Base64Encode(token);
   app_command.value()->execute(token_base64.c_str(), ...);
   ```

   Questa scelta è di sicurezza: il DM token (che vale come credenziale di
   gestione) viene scritto in una posizione protetta da un componente elevato,
   non dal processo del browser in user-space.

3. **Thread COM STA.** Le operazioni di store/delete girano su un
   `CreateCOMSTATaskRunner` (`com_sta_task_runner_`), perché passano per le
   interfacce COM dell'updater.

> **Conseguenza pratica per chi amministra**: l'enrollment token (in chiaro) sta
> sotto `…\Policies\Google\Chrome`, ma il DM token effettivo è binario, scritto
> dall'updater in una chiave app-neutral, e non è banalmente clonabile tra
> macchine.

---

## 5. Il flusso di enrollment (CBCM browser)

Sequenza tipica per un browser machine-level (`register_browser`), orchestrata da
`ChromeBrowserCloudManagementController` + `CloudPolicyClient`:

```
1.  Avvio Chrome
      └─ BrowserDMTokenStorageWin::InitEnrollmentToken()  → enrollment token (registro)
      └─ BrowserDMTokenStorageWin::InitDMToken()          → DM token esistente?

2.  Se NON c'è DM token e c'è enrollment token:
      └─ DeviceManagementService crea un job:
             request=register_browser
             Authorization: GoogleEnrollmentToken token=<enrollment_token>
             deviceid=<MachineGuid>, apptype=Chrome, devicetype=2, platform=...
      └─ DMServer valida l'enrollment token per il tenant
      └─ Risposta: DeviceRegisterResponse { device_management_token = <DM token> }

3.  Persistenza del DM token:
      └─ StoreDMTokenInRegistry()  (via Google Update app command, elevato)

4.  Fetch policy:
      └─ request=policy, policy_type=google/chrome/machine-level-user
             Authorization: GoogleDMToken token=<DM token>
      └─ Risposta: PolicyFetchResponse (policy firmata + chiave pubblica)

5.  Validazione (CloudPolicyValidator) → CloudPolicyStore (persistenza locale)
      → CloudPolicyManager espone un ConfigurationPolicyProvider
      → PolicyServiceImpl::MergeFrom() integra le policy cloud nella PolicyMap

6.  Refresh periodico + status_upload / chrome_desktop_report
      + (opzionale) remote_commands
```

Il punto chiave dell'architettura: dopo lo step 3, **l'enrollment token non serve
più**; tutte le chiamate successive usano il DM token per-macchina.

---

## 6. Componenti del cloud policy stack

| Componente | Responsabilità |
|---|---|
| **`CloudPolicyClient`** | Stato della connessione al DMServer; metodi `Register*`, `FetchPolicy`, `UploadDeviceStatus`, `FetchRemoteCommands`, `Unregister`. Tiene il **DM token** e gli ultimi `PolicyFetchResponse`. |
| **`DeviceManagementService`** | Costruisce gli URL (query param di §3.2), gestisce job, retry, backoff, codifica protobuf. |
| **`CloudPolicyStore`** | Persistenza locale della policy validata e della chiave pubblica; notifica i cambi. |
| **`CloudPolicyValidator`** | Verifica firma, **chiave pubblica** (con rotazione/`new_public_key`), `policy_type`, **DM token**, timestamp, `device_id`. Scarta risposte non integre. |
| **`CloudPolicyCore`** | Lega `client` + `store` + `refresh_scheduler` (cadenza del refresh). |
| **`CloudPolicyManager`** (machine/user) | Adatta lo store a un `ConfigurationPolicyProvider` consumato da `PolicyServiceImpl`. |
| **`ChromeBrowserCloudManagementController`** | Bootstrap CBCM: decide se/quando registrare, coordina token storage, reporting e metriche (`chrome_browser_cloud_management_metrics.h`). |
| **`affiliation.{cc,h}`** | Determina se l'utente del profilo è **affiliato** allo stesso tenant della macchina (abilita policy/azioni che richiedono affiliazione). |

---

## 7. Validazione e fiducia delle policy

A differenza del Platform provider (che si fida del registro perché protetto
dalle ACL di Windows), il Cloud provider **non si fida del trasporto**: ogni
`PolicyFetchResponse` è **firmata**. `CloudPolicyValidator` verifica, tra l'altro:

- **firma** del blob di policy con la **chiave pubblica** dell'organizzazione
  (con supporto alla **rotazione** della chiave via `new_public_key` firmato
  dalla chiave precedente);
- corrispondenza del **`policy_type`** atteso (es. `google/chrome/machine-level-user`);
- corrispondenza del **DM token** e del **device id**;
- **timestamp** entro finestra accettabile (anti-replay);
- (opzionale) cache/validazione del `username` per le policy utente.

Questo rende il canale resistente a manomissioni anche se l'endpoint o il
percorso di rete fossero compromessi.

---

## 8. Reporting e comandi remoti

CBCM non è solo "consegna policy": è bidirezionale, da cui l'analogia con un MDM.

- **Inventario / status** — `status_upload` e `chrome_desktop_report`
  (`kValueRequestChromeDesktopReport`) inviano alla Admin Console dati su
  versione browser, OS, profili, estensioni, policy applicate, ecc.
- **Comandi remoti** — `remote_commands` (`kValueRequestRemoteCommands`)
  permette al server di inviare comandi (es. clear browsing data) che il client
  esegue e di cui invia l'**ack** firmato.
- **Upload certificati / chiavi** — `cert_upload`,
  `browser_public_key_upload` per scenari di attestazione.

---

## 9. Machine-level vs Profile-level

CBCM ha **due piani** distinti, con token e policy type separati:

| Piano | Registrazione | Policy type | Token | Scope risultante |
|---|---|---|---|---|
| **Machine-level (CBCM)** | `register_browser` | `google/chrome/machine-level-user` | DM token per-macchina (registro, REG_BINARY) | tutta la macchina/installazione |
| **Profile-level / utente** | `register_profile` / login Dasher | `google/chrome/user` | DM token per-profilo (in profilo) | singolo profilo Chrome gestito |

`UserCloudPolicyManager` gestisce il piano profilo; `MachineLevelUserCloudPolicyManager`
quello CBCM. L'**affiliation** (§6) determina come i due piani interagiscono
(es. alcune azioni sono permesse solo se utente e macchina sono affiliati).

---

## 10. Precedenza Platform vs Cloud

Quando una stessa policy arriva sia dal registro (Platform) sia dal cloud (CBCM),
`PolicyServiceImpl` applica regole di **precedenza** configurabili tramite
apposite *meta-policy*:

- **`CloudPolicyOverridesPlatformPolicy`** — se abilitata, la policy **cloud**
  (machine) vince su quella **Platform** (registro/GPO).
- **`CloudUserPolicyOverridesCloudMachinePolicy`** — regola tra cloud **utente**
  e cloud **macchina**.

In assenza di override espliciti, la **Platform policy** (registro/GPO) ha
tipicamente precedenza sulla **cloud machine policy**. Ogni voce nella `PolicyMap`
mantiene `level` (mandatory/recommended), `scope` (machine/user) e `source`
(`POLICY_SOURCE_PLATFORM` vs `POLICY_SOURCE_CLOUD`), e i conflitti sono risolti e
**resi visibili in `chrome://policy`** (colonna "Source" e indicazione di
conflitto).

> **Implicazione operativa**: su una macchina enrollata in CBCM **e** gestita da
> Chrome Policy Manager, il comportamento dipende dal valore di
> `CloudPolicyOverridesPlatformPolicy`. Per evitare sorprese conviene
> standardizzare questa meta-policy nella flotta (vedi §12).

---

## 11. Perché non è self-hostabile

- Il **client** del protocollo DM è interamente open source nel tree Chromium
  (i file di §1).
- Il **server** (DMServer) è **chiuso e proprietario** di Google: non è
  distribuito né documentato come prodotto installabile. Lo **schema protobuf**
  delle richieste/risposte è però pubblico
  (`device_management_backend.proto`), il che ha permesso ad alcuni progetti
  sperimentali di terze parti di emulare un DMServer minimale — ma **non è uno
  scenario supportato** e non offre l'ecosistema della Admin Console (report,
  comandi, audit, gestione utenti).

Questa è esattamente la ragion d'essere di Chrome Policy Manager: fornire
gestione **centralizzata** e **self-hosted** (via Intune + API) **senza**
enrollare i browser nel cloud di Google, restando sul canale **Platform**
(registro) che è completamente sotto il nostro controllo.

---

## 12. CBCM vs Chrome Policy Manager — tabella di sintesi

| Aspetto | **CBCM (canale nativo)** | **Chrome Policy Manager (questa soluzione)** |
|---|---|---|
| Trasporto | Rete → DMServer (protocollo DM) | Registro Windows (`HKLM\…\Policies\Google\Chrome`) |
| Provider in Chrome | Cloud (`POLICY_SOURCE_CLOUD`) | Platform (`POLICY_SOURCE_PLATFORM`) |
| Identità | MachineGuid + enrollment token → DM token | `deviceId` Entra + certificato client (mTLS via APIM) |
| Backend | Proprietario Google (Admin Console) | Self-hosted (Azure: API + SQL + Intune) |
| Consegna sul client | Nativa nel browser | Script Intune Proactive Remediation che scrive il registro |
| Integrità | Policy **firmate** + validate | ACL del registro (HKLM, solo admin) |
| Bidirezionale | Sì (status, report, remote commands) | Report di compliance verso l'API |
| Self-hostable | No | Sì |
| Dipendenza da Google cloud | Sì | No |

---

## 13. Implicazioni per Chrome Policy Manager

1. **Coesistenza controllata.** Se nella flotta esiste (o esisterà) CBCM,
   definire e distribuire `CloudPolicyOverridesPlatformPolicy` in modo coerente,
   così da sapere a priori chi vince in caso di sovrapposizione.
2. **Diagnostica.** `chrome://policy` mostra la **Source** di ogni policy
   (Platform vs Cloud) e gli eventuali **conflitti**: è lo strumento principale
   per verificare che le chiavi scritte da Chrome Policy Manager siano davvero
   quelle effettive e non oscurate da una cloud policy.
3. **Nessuna sovrapposizione di trasporto.** Chrome Policy Manager non interagisce
   con il DM token né con l'updater: opera su un piano (registro) **ortogonale** a
   CBCM. Le due soluzioni non si "rompono" a vicenda; semplicemente Chrome le
   **unisce** secondo le regole di precedenza.
4. **Posizionamento.** Questo canale conferma la value-proposition della
   soluzione: portare gestione centralizzata su dispositivi **Entra-ID-only**
   **senza** enrollment cloud Google e **senza** Group Policy.

---

## 14. Riferimenti puntuali al codice

| Tema | File / simbolo |
|---|---|
| Tipi richiesta DM, header auth, query param, policy type, endpoint default | `components/policy/core/common/cloud/cloud_policy_constants.cc` (namespace `policy::dm_protocol`) |
| Client id = MachineGuid | `chrome/browser/policy/browser_dm_token_storage_win.cc` → `BrowserDMTokenStorageWin::InitClientId()` |
| Enrollment token (registro Policies) | idem → `InitEnrollmentToken()` / `InstallUtil::GetCloudManagementEnrollmentToken()` |
| DM token REG_BINARY + posizione app-neutral | idem → `InitDMToken()` / `InstallUtil::GetCloudManagementDmTokenLocation()` |
| Scrittura DM token via updater elevato | idem → `StoreDMTokenInRegistry()` (`installer::kCmdStoreDMToken`) |
| Registrazione e fetch | `components/policy/core/common/cloud/cloud_policy_client.{cc,h}` |
| Trasporto HTTP/job | `components/policy/core/common/cloud/device_management_service.{cc,h}` |
| Validazione firma/chiave | `components/policy/core/common/cloud/cloud_policy_validator.cc` |
| Persistenza/refresh | `cloud_policy_store.*`, `cloud_policy_core.*`, `cloud_policy_refresh_scheduler.*` |
| Affiliation | `components/policy/core/common/cloud/affiliation.{cc,h}` |
| Bootstrap CBCM + metriche | `ChromeBrowserCloudManagementController`, `chrome_browser_cloud_management_metrics.h` |
| Schema protobuf del protocollo | `components/policy/proto/device_management_backend.proto` |

---

## 15. Glossario

- **CBCM** — Chrome Browser Cloud Management: gestione cloud dei browser Chrome
  via Google Admin Console.
- **DMServer** — Device Management Server: backend proprietario di Google che
  implementa il protocollo DM.
- **Enrollment token** — segreto a livello organizzazione, usato solo per
  registrare la macchina/browser e ottenere il DM token.
- **DM token** — credenziale per-macchina (o per-profilo) rilasciata dal
  DMServer; autentica tutte le chiamate post-enrollment; revocabile dalla Admin
  Console.
- **Client id** — identità stabile della macchina; su Windows il **MachineGuid**.
- **Policy type** — stringa che seleziona il set di policy lato server
  (es. `google/chrome/machine-level-user`).
- **Affiliation** — condizione per cui utente e dispositivo appartengono allo
  stesso tenant gestito.
