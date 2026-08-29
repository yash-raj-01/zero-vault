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
