# ZeroVault

A completely zero-dependency, encrypted secret vault, security scanner, and 2FA authenticator built strictly using the Node.js standard library and vanilla web technologies.

## Features (Phase 1)
- **Zero Dependencies**: 0 npm runtime packages. Pure `node:http` and `node:crypto`.
- **Secure Encrypted Vault**: AES-256-GCM authenticated encryption with outer HMAC-SHA256 signature for constant-time rejection.
- **Modern Vanilla UI**: Glassmorphism dark-theme single-page application.
- **CLI Suite**: Full terminal support for password generation, TOTP, and vault unlocking.
- **Secret Scanner**: Detects exposed AWS keys, Stripe keys, GitHub PATs, and high-entropy strings locally.
- **CSPRNG Generators**: Cryptographically secure password, passphrase (Diceware), and Hex/Base64 key generation.
- **File Protection**: Inspect permissions, secure files to `0o600`, and securely shred sensitive data in multiple passes.

## Architecture
- **Server**: Native `node:http` custom router with static file delivery.
- **Frontend**: Vanilla HTML5, CSS3 Variables, ES6 JavaScript. No React, no Tailwind, no build step.
- **Crypto**: `node:crypto` AES-GCM, HMAC, HKDF.

## Getting Started

### Prerequisites
- Node.js >= 25.0.0

### Run the App
```bash
# Start the local server and web UI on port 3000
npm start

# Or using the CLI
node bin/zerovault.js serve --port 8080
```

### CLI Tools
```bash
# Generate a secure password
node bin/zerovault.js generate password

# Generate a TOTP token from a base32 secret
node bin/zerovault.js totp JBSWY3DPEHPK3PXP

# Scan text for exposed secrets
node bin/zerovault.js scan "const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';"
```

### Testing
```bash
npm test
```

## Security Architecture & Threat Model

### Crypto Architecture
ZeroVault relies entirely on the Node.js native `node:crypto` module. We use **AES-256-GCM** for authenticated encryption of the payload, and an **HMAC-SHA256** outer signature over the entire vault structure to provide a fast, constant-time rejection of incorrect passwords or tampered files before decryption is even attempted.

### Key Derivation
The master password is never stored or used directly as an encryption key. It is derived using **Argon2id** (`crypto.argon2Sync`) along with a randomly generated 32-byte salt. The output of Argon2id is then passed through **HKDF-SHA256** to securely expand and separate the derived material into two independent 256-bit keys:
1. `encKey`: Used for AES-256-GCM.
2. `macKey`: Used for HMAC-SHA256.

### Vault Format
The `.zvault` file is a custom binary format structured as follows:
- `MAGIC` (4 bytes): `ZVLT`
- `VERSION` (1 byte): `0x01`
- `KDF_ID` (1 byte): `0x01` (Argon2id)
- `KDF_PARAMS` (12 bytes): time, memory, parallelism
- `SALT` (32 bytes)
- `IV` (12 bytes)
- `HMAC` (32 bytes): Outer signature of (Header + Tag + Ciphertext)
- `TAG` (16 bytes): GCM Authentication Tag
- `CIPHERTEXT` (variable): The AES-256-GCM encrypted JSON payload.

### Vault Protection
- The vault writes atomically using `.tmp` files and `fs.renameSync` to ensure that power loss or write interruptions do not corrupt an existing vault.
- `VaultManager` explicitly zeroes out the master password buffer in memory (`buf.fill(0)`) when the vault is locked.
- API endpoints are designed to never leak the master password, and errors are sanitized to prevent stack traces from leaking secrets.

### Security Assumptions & Limitations
- **Node.js Memory Constraints:** Node.js runs in user-land V8 and lacks `mlock()` to pin memory. While `Buffer` objects used for crypto keys are securely zero-filled after use, V8 strings (like those returned by `JSON.parse`) are immutable and cannot be zeroed out. They remain in memory until the Garbage Collector collects them. They could be paged to disk by the OS.
- **Side-Channel Protections:** The outer HMAC check uses `crypto.timingSafeEqual` to prevent timing attacks on password validation.
- **Threat Model — What we do NOT protect against:** ZeroVault assumes the host machine is reasonably secure. It **does not** protect against:
  - Malware running on the host machine.
  - A compromised operating system (root/Admin access).
  - Advanced memory inspection/dumping of the Node process.
  - Hardware keyloggers.
  - A fully compromised physical machine.
  If your host is compromised, any password manager that unlocks secrets in memory is compromised.
