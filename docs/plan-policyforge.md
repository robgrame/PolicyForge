# PolicyForge — piano di sviluppo

Evoluzione di ChromePolicyManager in una piattaforma di desired-state config
universale per device Windows gestiti da Intune (qualunque ADMX + registry,
servizi, scheduled task, file, gruppi locali, variabili d'ambiente — stile GPP).

## Fasi completate
- [x] Phase 0 — Bootstrap repo + ADR-002 (design)
- [x] Phase 1 — Rename ChromePolicyManager.* -> PolicyForge.*
- [x] Phase 2 — Provider abstraction + dominio configurazione generico
- [x] Phase 3 — 5 provider v1 + endpoint engine + test
- [x] Phase 4 — Ingestion ADMX namespace-aware e multi-prodotto
- [x] Phase 5 — Client dispatcher multi-provider (remediation Intune)
- [x] Phase 6 — Rename infra cpm-/ChromePolicyManager -> pf-/PolicyForge,
      endpoint GET /api/configuration/resolve/{deviceId} + assegnazioni profilo

Build soluzione verde; 11 test passano.

## Punti aperti (ADR-002) — da decidere con l'utente
- Rollback/undo: snapshot dello stato precedente per Registry/Service prima di Enforce.
- Security scoping/guardrails per provider (es. registry keys vietate, path di sistema).
- Precedenza nei conflitti tra profili (oltre al priority "first writer wins").
- Contesto per-utente (HKCU): la remediation gira come SYSTEM; serve un runner utente.
- Visibilità repo (privata vs pubblica) e licenza.
- UI Admin per authoring di profili generici multi-provider (oltre alle policy Chrome).
