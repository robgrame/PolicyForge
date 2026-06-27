# Gestione e caricamento delle policy in Chromium su Windows

> Documento tecnico di riferimento — analisi del codice sorgente di Chromium per
> comprendere **esattamente** come Chrome legge, converte e applica le policy
> aziendali dal registro di Windows. Costituisce la base teorica
> dell'irrobustimento del client di Chrome Policy Manager
> (`src/Client/Detect-ChromePolicy.ps1`, `src/Client/Remediate-ChromePolicy.ps1`).

## 1. Scopo e fonti

Chrome Policy Manager scrive le policy direttamente sotto
`HKLM\SOFTWARE\Policies\Google\Chrome` (bypassando la pipeline Group Policy che
non funziona sui dispositivi Entra-ID-only). Per scrivere valori che Chrome legga
**senza scartarli**, occorre conoscere la semantica esatta del *policy loader*.

Sorgenti analizzati (branch `main` di Chromium, dominio pubblico
[chromium.googlesource.com](https://chromium.googlesource.com/chromium/src/)):

| File | Percorso nel repo Chromium | Ruolo |
|------|----------------------------|-------|
| `policy_loader_win.cc` | `components/policy/core/common/policy_loader_win.cc` | Orchestrazione: lettura hive, scope, livelli, schema, merge, trigger di reload |
| `registry_dict.cc` | `components/policy/core/common/registry_dict.cc` | Modello dati registro→JSON: lettura tipi, conversione, coercizione per schema |

I riferimenti `file.cc:Lnn` nel testo puntano alle righe dei due file sopra
(versione `refs/heads/main` al momento dell'analisi, 2026-06).

---

## 2. Panoramica dell'architettura del policy stack

Su Windows il flusso è il seguente:

```
  Registro di Windows                RegistryDict                PolicyMap / PolicyBundle
  HKLM/HKCU\...\Google\Chrome  ──►  (albero in memoria)  ──►   (policy tipizzate, validate)
        │                               │                              │
   ReadRegistry()                 ConvertToJSON(schema)          LoadFrom(...) + MergeFrom(...)
   (tipi REG → base::Value)       ConvertRegistryValue()         (livello, scope, sorgente)
```

1. **`PolicyLoaderWin::Load()`** legge gli hive `HKEY_LOCAL_MACHINE` e
   `HKEY_CURRENT_USER` per la chiave radice di Chrome.
2. Ogni hive viene letto in un **`RegistryDict`** — una rappresentazione ad
   albero (valori + sottochiavi) della porzione di registro.
3. Il `RegistryDict` viene convertito in `base::Value` JSON-tipizzato tramite
   **`ConvertToJSON(schema)`**, applicando lo **schema delle policy di Chrome**.
4. Il risultato viene caricato in un **`PolicyMap`** con livello (mandatory /
   recommended), scope (machine / user) e sorgente (`POLICY_SOURCE_PLATFORM`),
   poi fuso (`MergeFrom`) con le altre origini.

Il caricamento è **asincrono e periodico** (`periodic_updates=true`,
`policy_loader_win.cc:L255`) e reagisce alle notifiche di Group Policy.

---

## 3. `PolicyLoaderWin` — ciclo di vita e orchestrazione

### 3.1 Costruzione e registrazione delle notifiche GP

Nel costruttore (`policy_loader_win.cc:L249-L274`) il loader si registra per le
notifiche di modifica delle policy:

```cpp
::RegisterGPNotification(user_policy_changed_event_.handle(),    false); // utente
::RegisterGPNotification(machine_policy_changed_event_.handle(), true);  // macchina
```

- Il secondo parametro (`bMachine`) distingue le notifiche **macchina** (`true`)
  da quelle **utente** (`false`).
- Se la registrazione **fallisce**, viene impostato
  `user_policy_watcher_failed_` / `machine_policy_watcher_failed_` e il loader
  **continua comunque** ad operare in modalità solo-periodica.

> **Rilevanza per Chrome Policy Manager.** `RegisterGPNotification` è il
> meccanismo che su un dispositivo *domain-joined* sveglia Chrome quando il
> *Group Policy Client Service* aggiorna le chiavi. Sui dispositivi **Entra-ID
> only** questa pipeline non popola `HKLM\SOFTWARE\Policies\Google\Chrome`;
> tuttavia, poiché il loader è anche **periodico**, scrivere direttamente quelle
> chiavi è sufficiente: Chrome le rileva al successivo refresh (entro pochi
> minuti) o al riavvio, senza dipendere dalla notifica GP.

### 3.2 `Load()` — scope, hive e rami della chiave radice

`Load()` (`policy_loader_win.cc:L302-L344`) itera due **scope**, ciascuno legato
a un hive:

```cpp
static const struct { PolicyScope scope; HKEY hive; } kScopes[] = {
    {POLICY_SCOPE_MACHINE, HKEY_LOCAL_MACHINE},   // HKLM
    {POLICY_SCOPE_USER,    HKEY_CURRENT_USER},    // HKCU
};
```

Per ogni scope:

1. `gpo_dict.ReadRegistry(hive, chrome_policy_key_)` legge l'intero sottoalbero
   della chiave radice di Chrome (`...\SOFTWARE\Policies\Google\Chrome`).
2. Vengono **estratti e rimossi** dal dizionario radice due rami speciali
   (`policy_loader_win.cc:L327-L331`):
   - `RemoveKey("recommended")` → policy **a livello RECOMMENDED**
   - `RemoveKey("3rdparty")` → policy di **estensioni / terze parti**
3. Ciò che resta nella radice sono le policy **MANDATORY** di Chrome.

Le costanti dei rami (`policy_loader_win.cc:L71-L73`):

```cpp
const char kKeyMandatory[]   = "policy";       // usato per i 3rd-party
const char kKeyRecommended[] = "recommended";
const char kKeyThirdParty[]  = "3rdparty";
```

Mappa risultante delle sorgenti registro → (livello, scope):

| Percorso registro | Livello | Scope (hive) |
|-------------------|---------|--------------|
| `HKLM\SOFTWARE\Policies\Google\Chrome\<Policy>` | Mandatory | Machine |
| `HKLM\SOFTWARE\Policies\Google\Chrome\Recommended\<Policy>` | Recommended | Machine |
| `HKCU\SOFTWARE\Policies\Google\Chrome\<Policy>` | Mandatory | User |
| `HKCU\SOFTWARE\Policies\Google\Chrome\Recommended\<Policy>` | Recommended | User |
| `…\Chrome\3rdparty\extensions\<id>\policy\…` | Mandatory | (estensione) |
| `…\Chrome\3rdparty\extensions\<id>\recommended\…` | Recommended | (estensione) |

### 3.3 `LoadChromePolicy` e `ParsePolicy` — applicazione dello schema

`LoadChromePolicy` (`policy_loader_win.cc:L364-L375`):

```cpp
const Schema* chrome_schema = schema_map()->GetSchema(
    PolicyNamespace(POLICY_DOMAIN_CHROME, ""));
ParsePolicy(gpo_dict, level, scope, *chrome_schema, &policy);
if (ShouldFilterSensitivePolicies())
    FilterSensitivePolicies(&policy);
chrome_policy_map->MergeFrom(policy);
```

`ParsePolicy` (`policy_loader_win.cc:L77-L94`) è il punto di giunzione
registro→policy:

```cpp
std::optional<base::Value> policy_value(gpo_dict->ConvertToJSON(schema));
const base::DictValue* policy_dict = policy_value->GetIfDict();
policy->LoadFrom(*policy_dict, level, scope, POLICY_SOURCE_PLATFORM);
```

Punti chiave:

- La conversione registro→JSON è **guidata dallo schema** delle policy di Chrome
  (`ConvertToJSON(schema)`): è qui che i tipi REG vengono coercati nei tipi
  attesi (vedi §5).
- La sorgente è sempre **`POLICY_SOURCE_PLATFORM`** (policy "di piattaforma",
  la categoria che il GPO/registro produce).
- `FilterSensitivePolicies` può **rimuovere** alcune policy considerate
  sensibili quando provengono da una sorgente a basso livello di fiducia.

### 3.4 `Load3rdPartyPolicy` — policy di estensione

`Load3rdPartyPolicy` (`policy_loader_win.cc:L377-L428`) gestisce il ramo
`3rdparty`:

- Unico dominio mappato: `"extensions"` → `POLICY_DOMAIN_EXTENSIONS`.
- Sotto `3rdparty\extensions\` ogni **sottochiave è l'ID di un'estensione**
  (`component->first`).
- Per ogni estensione si cerca lo schema corrispondente in `schema_map()`; se
  l'estensione **non è installata o non supporta policy**, il ramo è **ignorato**.
- Per ciascun ID si leggono due livelli: `policy` (mandatory) e `recommended`.

### 3.5 Reload, sezione critica e watch

- **`Reload(force)`** (`policy_loader_win.cc:L346-L362`): prima di leggere entra
  in una `ScopedCriticalPolicySection` (sezione critica di GP) per evitare di
  leggere uno stato di registro incoerente mentre il GP Client scrive.
- **`SetupWatches`** (`L430-L446`) arma i watcher sugli eventi utente/macchina.
- **`OnObjectSignaled`** (`L448-L454`): alla notifica di modifica chiama
  `Reload(false)`. Il loader resetta i watch **prima** di leggere
  (`Load()` → `SetupWatches()`, `L305-L306`) per non perdere notifiche.

> **Conseguenza pratica.** Le scritture del client diventano effettive:
> (a) immediatamente se l'utente apre `chrome://policy` → *Reload policies*;
> (b) al refresh periodico del loader; (c) al riavvio di Chrome. Non è richiesta
> alcuna notifica GP perché il refresh periodico legge comunque gli hive.

---

## 4. `RegistryDict` — modello dati e lettura del registro

`RegistryDict` (`registry_dict.cc`) rappresenta un nodo del registro con due
mappe distinte (`registry_dict.h`):

- **`values_`** (`ValueMap`): i **valori** del nodo (nome → `base::Value`).
- **`keys_`** (`KeyMap`): le **sottochiavi** (nome → `RegistryDict` figlio).

Entrambe sono `std::map` ordinate con **`CaseInsensitiveStringCompare`**
(`registry_dict.cc:L154-L157`):

```cpp
bool CaseInsensitiveStringCompare::operator()(const std::string& a,
                                              const std::string& b) const {
  return base::CompareCaseInsensitiveASCII(a, b) < 0;
}
```

> **Implicazione sull'ordinamento.** I nomi sono ordinati **lessicograficamente,
> case-insensitive**. Per le liste codificate come valori numerati (`"1"`,
> `"2"`, …, vedi §6) questo significa che oltre i 9 elementi l'ordine diventa
> `"1","10","11",…,"2",…` (ordine di stringa, non numerico). È un comportamento
> intrinseco di Chrome: le liste "ordinate" con più di 9 elementi vanno
> codificate come **stringa JSON** se l'ordine è significativo.

### 4.1 `ReadRegistry` — quali tipi REG vengono letti

`ReadRegistry` (`registry_dict.cc:L248-L308`) prima legge **tutti i valori**, poi
ricorre sulle sottochiavi. La gestione dei tipi è il cuore del problema:

| Tipo registro (`it.Type()`) | Esito | `base::Value` prodotto |
|-----------------------------|-------|------------------------|
| `REG_SZ` | letto | stringa (UTF-8) |
| `REG_EXPAND_SZ` | letto | stringa, con **espansione delle variabili d'ambiente** (`ExpandEnvironmentVariables`); fallback a `REG_SZ` se l'espansione fallisce |
| `REG_DWORD_LITTLE_ENDIAN` | letto **solo se** `ValueSize() == 4 byte` | intero (`static_cast<int>`) |
| `REG_DWORD_BIG_ENDIAN` | letto **solo se** `ValueSize() == 4 byte` | intero (conversione big-endian) |
| `REG_NONE` | **ignorato** | — (warning a log) |
| `REG_LINK` | **ignorato** | — |
| `REG_MULTI_SZ` | **ignorato** | — |
| `REG_RESOURCE_LIST` | **ignorato** | — |
| `REG_FULL_RESOURCE_DESCRIPTOR` | **ignorato** | — |
| `REG_RESOURCE_REQUIREMENTS_LIST` | **ignorato** | — |
| `REG_QWORD_LITTLE_ENDIAN` (`REG_QWORD`) | **ignorato** | — |

Estratto rilevante (`registry_dict.cc:L255-L298`):

```cpp
case REG_EXPAND_SZ:  // espande %VAR% poi -> stringa, altrimenti fallthrough
case REG_SZ:         // -> stringa UTF-8
case REG_DWORD_LITTLE_ENDIAN:
case REG_DWORD_BIG_ENDIAN:
    if (it.ValueSize() == sizeof(DWORD)) { /* -> int */ continue; }
    [[fallthrough]];
case REG_NONE: case REG_LINK: case REG_MULTI_SZ:
case REG_RESOURCE_LIST: case REG_FULL_RESOURCE_DESCRIPTOR:
case REG_RESOURCE_REQUIREMENTS_LIST: case REG_QWORD_LITTLE_ENDIAN:
    break;  // tipo non supportato -> warning, valore scartato
```

> **Regola d'oro per il client.** Chrome legge **solo** `REG_SZ`,
> `REG_EXPAND_SZ` e `REG_DWORD` (esattamente 4 byte). **Mai** emettere
> `REG_QWORD` o `REG_MULTI_SZ`: verrebbero scartati silenziosamente. Gli interi
> a 64 bit fuori dal range di `Int32` e i double **non** vanno scritti come
> `REG_QWORD`, bensì come `REG_SZ` numerico (Chrome li coerce via schema, §5).

### 4.2 `ConvertToJSON` — da albero registro a `base::Value`

`ConvertToJSON(schema)` (`registry_dict.cc:L310-L381`) genera il `base::Value`
finale in base al **tipo dello schema** del nodo:

- **DICT** (`L315-L352`): itera **prima `values_`, poi `keys_`**; per ogni
  nome cerca le proprietà dello schema corrispondenti
  (`GetMatchingProperties`) e applica `ConvertRegistryValue` (per i valori) o
  ricorre `ConvertToJSON` (per le sottochiavi).
- **LIST** (`L353-L375`): considera **solo i nomi numerici**
  (`IsKeyNumerical`), ricorrendo sulle sottochiavi numerate e convertendo i
  valori numerati come item della lista.

> **Conflitto valore vs sottochiave (importante).** In modalità DICT i `values_`
> vengono processati **prima** dei `keys_`, e `result.Set(...)` **sovrascrive**.
> Se uno stesso nome esiste **sia come valore sia come sottochiave**, vince la
> sottochiave (processata per ultima). Questo rende lo stato **non
> deterministico/ambiguo** durante un cambio di forma (scalare ↔ lista/dict). Il
> client di Chrome Policy Manager elimina perciò **entrambe** le rappresentazioni
> dello stesso nome prima di riscrivere (funzione `Remove-PolicyEntry`).

### 4.3 `IsKeyNumerical` e le liste

`IsKeyNumerical` (`registry_dict.cc:L36-L39`) accetta un nome solo se
`base::StringToInt` riesce. I nomi **non numerici** dentro una lista sono
**ignorati** sia in `ConvertToJSON` (LIST) sia in `ConvertRegistryValue` (LIST).

---

## 5. `ConvertRegistryValue` — coercizione guidata dallo schema

`ConvertRegistryValue(value, schema)` (`registry_dict.cc:L43-L152`) è la funzione
che adatta il tipo "grezzo" letto dal registro al tipo atteso dallo schema della
policy. Logica:

1. **Schema non valido** → ritorna il valore così com'è (`value.Clone()`).
2. **Tipo già corretto** (`value.type() == schema.type()`) → usa il valore,
   ricorrendo per dict/list.
3. Altrimenti applica le conversioni seguenti:

| Tipo schema | Input accettati dal registro | Risultato |
|-------------|------------------------------|-----------|
| `BOOLEAN` | `int` (DWORD) → `!= 0`; oppure `string` "0"/"1"/numerico (`StringToInt`) | bool |
| `INTEGER` | `int` (DWORD); oppure `string` numerica (`StringToInt`, 32 bit) | int |
| `DOUBLE` | `double`, `int`, oppure `string` numerica (`StringToDouble`) | double |
| `LIST` | `dict` con chiavi **numeriche** (subkey numerate); **oppure** `string` JSON (fallthrough) | list |
| `DICT` | `string` JSON, parsata con `JSON_ALLOW_TRAILING_COMMAS`; il tipo risultante **deve** combaciare con lo schema | dict |
| `STRING` / `BINARY` | nessuna conversione possibile | — |
| (default) | — | `LOG(WARNING)` + `std::nullopt` (valore scartato) |

Estratti chiave:

```cpp
// BOOLEAN (L82-L91): DWORD o stringa "0"/"1"
if (value.is_int())    return base::Value(value.GetInt() != 0);
if (value.is_string() && base::StringToInt(value.GetString(), &int_value))
    return base::Value(int_value != 0);

// INTEGER (L92-L99): stringa numerica accettata
if (value.is_string() && base::StringToInt(value.GetString(), &int_value))
    return base::Value(int_value);

// LIST (L111-L130): subkey numerate -> item, altrimenti fallthrough a JSON string
// DICT (L131-L142): stringa JSON -> dict (JSON_ALLOW_TRAILING_COMMAS)
std::optional<base::Value> result = base::JSONReader::Read(
    value.GetString(), base::JSONParserOptions::JSON_ALLOW_TRAILING_COMMAS);
```

> **Sfruttamento lato client.** Poiché `BOOLEAN`/`INTEGER`/`DOUBLE` accettano
> anche **stringhe**, e `LIST`/`DICT` accettano una **stringa JSON**, il client
> può rappresentare in modo robusto qualunque valore con i soli tipi
> `REG_SZ`/`REG_DWORD`:
> - bool → `REG_DWORD` 0/1
> - int (Int32) → `REG_DWORD`; int fuori range → `REG_SZ` numerico
> - double → `REG_SZ` (cultura invariante)
> - lista di scalari → subkey con valori numerati `1..N`
> - lista di oggetti / dizionari → singolo `REG_SZ` con JSON compatto

---

## 6. Rappresentazione delle strutture nel registro

### 6.1 Valori scalari

| Valore Chrome | Tipo registro consigliato | Esempio |
|---------------|---------------------------|---------|
| Stringa | `REG_SZ` | `HomepageLocation = "https://intra"` |
| Booleano | `REG_DWORD` (0/1) | `BookmarkBarEnabled = 1` |
| Intero (≤ 32 bit) | `REG_DWORD` | `DownloadRestrictions = 3` |
| Intero (> 32 bit) | `REG_SZ` numerico | `"5000000000"` |
| Double | `REG_SZ` (invariante) | `"1.5"` |

### 6.2 Liste

Forma **canonica** (compatibile con ADMX/GPO): una **sottochiave** con il nome
della policy contenente valori **numerati**:

```
HKLM\SOFTWARE\Policies\Google\Chrome\URLBlocklist
    "1" = "example.com"      (REG_SZ)
    "2" = "ads.example.net"  (REG_SZ)
    "3" = "*://tracker/*"    (REG_SZ)
```

Forma **alternativa** (accettata via `ConvertRegistryValue` LIST→JSON): un unico
`REG_SZ` con un array JSON. Preferibile quando **l'ordine conta** e gli elementi
sono più di 9, oppure quando gli item sono **oggetti**:

```
URLBlocklist = ["example.com","ads.example.net","*://tracker/*"]   (REG_SZ)
```

### 6.3 Dizionari / policy complesse

Codificati come un singolo `REG_SZ` con JSON compatto (parsato con
`JSON_ALLOW_TRAILING_COMMAS`):

```
ExtensionSettings = {"*":{"installation_mode":"blocked"}}   (REG_SZ)
```

### 6.4 Policy di estensione (3rd party)

```
HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<extension-id>\policy
    <NomeImpostazione> = <valore>     (mandatory)
HKLM\...\3rdparty\extensions\<extension-id>\recommended
    <NomeImpostazione> = <valore>     (recommended)
```

Vengono applicate **solo** se l'estensione è installata e pubblica uno schema
(`policy_loader_win.cc:L409-L413`).

---

## 7. Livelli, scope e precedenza

- **Livello**: `MANDATORY` (ramo radice / `…\extensions\<id>\policy`) vs
  `RECOMMENDED` (sottochiave `Recommended` / `…\recommended`). Le mandatory non
  sono modificabili dall'utente; le recommended impostano solo il default.
- **Scope**: `MACHINE` (HKLM) vs `USER` (HKCU).
- **Sorgente**: sempre `POLICY_SOURCE_PLATFORM` per le policy da registro
  (`policy_loader_win.cc:L93`).

> **Vedi anche**: oltre al *Platform provider* descritto qui, Chrome possiede un
> secondo provider **cloud nativo** (Chrome Browser Cloud Management) con sorgente
> `POLICY_SOURCE_CLOUD`. Il funzionamento di quel canale, il protocollo Device
> Management e la sua interazione/precedenza con il registro sono documentati in
> [`chrome-browser-cloud-management.md`](./chrome-browser-cloud-management.md).

`Load()` legge **prima** la macchina (HKLM) e **poi** l'utente (HKCU), fondendo
nello stesso `PolicyMap` via `MergeFrom` (`policy_loader_win.cc:L321-L341`,
`L374`). La risoluzione dei conflitti finale (es. mandatory-machine prevale su
recommended-user) è applicata dallo strato `PolicyMap`/provider, non da questi
due file; questo documento si limita a ciò che è osservabile nel loader.

---

## 8. Trigger di ricaricamento

| Trigger | Meccanismo | Riferimento |
|---------|------------|-------------|
| Notifica GP (utente/macchina) | `RegisterGPNotification` + watcher → `OnObjectSignaled` → `Reload(false)` | `L266-L272`, `L448-L454` |
| Refresh periodico | `AsyncPolicyLoader(..., periodic_updates=true)` | `L255` |
| Reload manuale | `chrome://policy` → *Reload policies* | (UI) |
| Sezione critica | `ScopedCriticalPolicySection` prima della lettura | `L354-L357` |

Su dispositivi Entra-ID-only la **notifica GP non scatta** per le chiavi di
Chrome (il GP Client non le popola), ma il **refresh periodico** legge comunque
gli hive: per questo la scrittura diretta nel registro funziona.

---

## 9. Implicazioni per Chrome Policy Manager (lato client)

Le regole derivate dall'analisi sono implementate identicamente in
`Detect-ChromePolicy.ps1` e `Remediate-ChromePolicy.ps1` (funzione
`Write-RegistryPolicy` e helper associati):

1. **Solo tipi leggibili.** Si emettono esclusivamente `REG_SZ` e `REG_DWORD`
   (4 byte). Mai `REG_QWORD`/`REG_MULTI_SZ` (verrebbero scartati, §4.1).
2. **Coercizione sicura.** Interi fuori da `Int32` e double scritti come
   `REG_SZ` numerico, sfruttando la coercizione di schema `INTEGER`/`DOUBLE`
   (§5).
3. **Pulizia dei conflitti di forma.** Prima di scrivere si rimuovono **sia il
   valore sia la sottochiave** con lo stesso nome, per evitare l'ambiguità
   valore-vs-sottochiave di `ConvertToJSON` DICT (§4.2).
4. **Liste e dizionari.** Liste di scalari come valori numerati `1..N`; liste di
   oggetti e dizionari come **stringa JSON** in un singolo `REG_SZ` (§6).
5. **Verifica fedele a Chrome.** La verifica di conformità non si fida solo
   dell'hash del manifest: rilegge il registro **come fa Chrome**
   (`REG_DWORD`→int, `REG_SZ`→stringa, subkey numerate→lista,
   stringa JSON→dict) e confronta con il valore atteso, rilevando manomissioni e
   drift (`Read-AppliedPolicy` / `Test-AllPoliciesApplied`).

### 9.1 Nota su WOW6432 e redirezione

La chiave `HKLM\SOFTWARE\Policies` **non** è soggetta a redirezione
Wow6432Node (il ramo `Policies` è condiviso tra viste a 32 e 64 bit): PowerShell
a 32 o 64 bit scrive nello stesso percorso che Chrome legge. Resta comunque
buona prassi eseguire i client in PowerShell a 64 bit.

---

## 10. Riferimenti puntuali al codice

**`policy_loader_win.cc`**

- `L71-L73` — costanti `policy` / `recommended` / `3rdparty`
- `L77-L94` — `ParsePolicy` (ConvertToJSON + LoadFrom, `POLICY_SOURCE_PLATFORM`)
- `L249-L274` — costruttore, `RegisterGPNotification`
- `L302-L344` — `Load()` (scope/hive, rami speciali, merge)
- `L364-L375` — `LoadChromePolicy` (schema, filtro sensibili, MergeFrom)
- `L377-L428` — `Load3rdPartyPolicy` (estensioni)
- `L346-L362`, `L430-L454` — Reload, sezione critica, watch

**`registry_dict.cc`**

- `L36-L39` — `IsKeyNumerical`
- `L43-L152` — `ConvertRegistryValue` (coercizione per schema)
- `L154-L157` — `CaseInsensitiveStringCompare`
- `L228-L240` — `Merge`
- `L248-L308` — `ReadRegistry` (tipi REG supportati/ignorati)
- `L310-L381` — `ConvertToJSON` (DICT/LIST)

---

## 11. Appendice — esempio completo di layout registro

```
HKLM\SOFTWARE\Policies\Google\Chrome
    HomepageLocation        REG_SZ     "https://intranet.contoso.com"
    BookmarkBarEnabled      REG_DWORD  1
    DownloadRestrictions    REG_DWORD  3
    ExtensionSettings       REG_SZ     {"*":{"installation_mode":"blocked"}}

HKLM\SOFTWARE\Policies\Google\Chrome\URLBlocklist
    1                       REG_SZ     "example.com"
    2                       REG_SZ     "ads.example.net"

HKLM\SOFTWARE\Policies\Google\Chrome\Recommended
    RestoreOnStartup        REG_DWORD  4

HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<id>\policy
    <Setting>               REG_SZ     "<value>"
```

Equivalente JSON prodotto da `ConvertToJSON` (semplificato):

```json
{
  "HomepageLocation": "https://intranet.contoso.com",
  "BookmarkBarEnabled": true,
  "DownloadRestrictions": 3,
  "ExtensionSettings": { "*": { "installation_mode": "blocked" } },
  "URLBlocklist": ["example.com", "ads.example.net"]
}
```

---

*Documento generato a partire dall'analisi diretta del codice sorgente pubblico
di Chromium (`components/policy/core/common/`), branch `main`.*
