# Encryption 
**Client-Side Zero-Knowledge Encryption platform.**

Encryption is a secure, browser-based encryption tool designed for local, military-grade data protection. It operates entirely client-side, ensuring that your keys and data never leave your device. 

## Features
- **Zero-Knowledge Architecture:** 100% of cryptography happens inside the browser. No data, passwords, or keys are transmitted or stored on any server.
- **Advanced Cryptography:** Utilizes AES-256-GCM for authenticated encryption and Argon2id (via WebAssembly) for robust, state-of-the-art key derivation.
- **Chunked File Streaming:** Capable of processing massive files without memory exhaustion. Data is encrypted in 64 MiB buffered logical chunks with unique initialization vectors (IVs) and Additional Authenticated Data (AAD) block validation.
- **Secret Key System:** A two-factor encryption mechanism providing you with a deterministic, portable 32-byte secret key that operates seamlessly alongside standard passwords, replacing rigid hardware lock-ins.
- **Military-Grade Generators:** Includes highly secure entropy-validated password generators and EFF wordlist diceware passphrase generation.

## Security Overview
Encryption employs a modern v4 binary blob structure ensuring strict integrity and anti-tampering:
- **KDF:** PBKDF2 (legacy support) & Argon2id (standard v4).
- **Integrity Validation:** AAD validation prevents chunk deletion, truncation, and reordering.
- **Supply Chain Security:** Strictly limited edge functions with enforced `wasm-unsafe-eval` and tightly bound content security policies (CSP).

## Getting Started
### Prerequisites
- Node.js 18+

### Setup
```bash
npm install
npm run dev
```

### Build for Production
```bash
npm run build
```

---
*Built with Next.js, WebAssembly, and standard Web Crypto APIs.*
