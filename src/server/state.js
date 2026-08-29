class VaultState {
  constructor() {
    this.locked = true;
    this.vaultPath = null;
    this.secrets = { items: [] };
    this.lastUnlocked = null;
  }

  unlock(vaultPath, secrets) {
    this.locked = false;
    this.vaultPath = vaultPath;
    this.secrets = secrets || { items: [] };
    this.lastUnlocked = Date.now();
  }

  lock() {
    this.locked = true;
    this.secrets = { items: [] };
    this.lastUnlocked = null;
  }

  isUnlocked() {
    return !this.locked;
  }

  getSecrets() {
    if (this.locked) throw new Error('Vault is locked');
    return this.secrets;
  }
}

export const vaultState = new VaultState();
