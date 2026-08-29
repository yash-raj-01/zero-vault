import { randomUUID } from 'node:crypto';
import { createVault, unlockVault } from './vault.js';
import { atomicWriteSync, readFileSyncSafe } from './persistence.js';
import { VaultError } from './errors.js';

export class VaultLockedError extends VaultError {
  constructor(message = 'Vault is currently locked. Action not permitted.') {
    super(message);
    this.name = 'VaultLockedError';
  }
}

export class VaultManager {
  /**
   * @param {string} filePath - Absolute path to the .zvault file
   */
  constructor(filePath) {
    this.filePath = filePath;
    this.unlocked = false;
    this.credentials = [];
    
    // We hold the master password internally only while unlocked to facilitate seamless saves.
    // It is zero-filled immediately upon lock().
    this._passwordBuffer = null;
  }

  /**
   * Initializes a completely new empty vault at the specified file path.
   * Will overwrite existing file if it exists.
   * Does NOT leave the vault unlocked (must call unlock() after).
   * 
   * @param {Buffer} password 
   */
  async initializeVault(password) {
    if (!Buffer.isBuffer(password) || password.length === 0) {
      throw new VaultError('Password must be a non-empty Buffer');
    }
    const emptyPayload = { credentials: [] };
    const binaryData = createVault(password, emptyPayload);
    atomicWriteSync(this.filePath, binaryData);
  }

  /**
   * Unlocks the vault. Reads from disk, decrypts, and holds state in memory.
   * 
   * @param {Buffer} password 
   */
  unlock(password) {
    if (!Buffer.isBuffer(password) || password.length === 0) {
      throw new VaultError('Password must be a non-empty Buffer');
    }

    const binaryData = readFileSyncSafe(this.filePath);
    if (!binaryData) {
      throw new VaultError(`Vault file not found: ${this.filePath}`);
    }

    const parsed = unlockVault(password, binaryData);
    
    this.credentials = Array.isArray(parsed.credentials) ? parsed.credentials : [];
    this.unlocked = true;

    // Retain the password in memory to allow future atomic saves on CRUD operations.
    this._passwordBuffer = Buffer.allocUnsafe(password.length);
    password.copy(this._passwordBuffer);
  }

  /**
   * Locks the vault. Clears decrypted credentials and zero-fills sensitive key material.
   */
  lock() {
    this.credentials = [];
    this.unlocked = false;
    
    if (this._passwordBuffer) {
      this._passwordBuffer.fill(0);
      this._passwordBuffer = null;
    }
  }

  isUnlocked() {
    return this.unlocked;
  }

  /**
   * Internal function to save the current credential state to disk.
   */
  _save() {
    this._assertUnlocked();
    const payload = { credentials: this.credentials };
    const binaryData = createVault(this._passwordBuffer, payload);
    atomicWriteSync(this.filePath, binaryData);
  }

  _assertUnlocked() {
    if (!this.unlocked || !this._passwordBuffer) {
      throw new VaultLockedError();
    }
  }

  // ==========================================
  // Credential CRUD Operations
  // ==========================================

  createEntry(data) {
    this._assertUnlocked();
    
    if (!data.service || typeof data.service !== 'string') {
      throw new VaultError('Entry must have a valid string "service" field');
    }

    const now = new Date().toISOString();
    const entry = {
      id: randomUUID(),
      service: data.service,
      username: data.username || '',
      password: data.password || '',
      notes: data.notes || '',
      createdAt: now,
      updatedAt: now
    };

    this.credentials.push(entry);
    this._save();
    return entry.id;
  }

  listEntries() {
    this._assertUnlocked();
    // Return summaries (omit passwords)
    return this.credentials.map(c => ({
      id: c.id,
      service: c.service,
      username: c.username,
      updatedAt: c.updatedAt
    }));
  }

  getEntry(id) {
    this._assertUnlocked();
    const entry = this.credentials.find(c => c.id === id);
    if (!entry) throw new VaultError(`Credential not found for id: ${id}`);
    
    // Return a deep copy so callers can't accidentally mutate internal state
    return { ...entry };
  }

  updateEntry(id, updates) {
    this._assertUnlocked();
    const idx = this.credentials.findIndex(c => c.id === id);
    if (idx === -1) throw new VaultError(`Credential not found for id: ${id}`);

    const current = this.credentials[idx];
    const updatedEntry = {
      ...current,
      service: updates.service !== undefined ? updates.service : current.service,
      username: updates.username !== undefined ? updates.username : current.username,
      password: updates.password !== undefined ? updates.password : current.password,
      notes: updates.notes !== undefined ? updates.notes : current.notes,
      updatedAt: new Date().toISOString()
    };

    this.credentials[idx] = updatedEntry;
    this._save();
  }

  deleteEntry(id) {
    this._assertUnlocked();
    const initialLen = this.credentials.length;
    this.credentials = this.credentials.filter(c => c.id !== id);
    
    if (this.credentials.length === initialLen) {
      throw new VaultError(`Credential not found for id: ${id}`);
    }
    this._save();
  }
}
