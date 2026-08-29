# ZeroVault Phase 3 — Task List

## Execution

- [x] Refactor `src/server/state.js` to use `VaultManager`
- [x] Refactor `src/server/routes/vault.routes.js`
  - [x] Use `VaultManager` for init/unlock/lock
  - [x] Add CRUD routes (`/api/entries/*`)
  - [x] Delete unsafe `/api/vault/save`
  - [x] Mask raw errors
- [x] Refactor `src/server/routes/audit.routes.js`
- [x] Update integration tests (`tests/router.test.js` or `tests/integration.test.js`)
- [x] Run test suite
- [x] Commit and push
