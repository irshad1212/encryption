/* eslint-disable @typescript-eslint/no-explicit-any */
// Web Worker for crypto operations — v4 blob format with Argon2id KDF + AAD
// V1-V3 legacy decrypt uses PBKDF2
export { }; // Module boundary — prevents TS "Cannot redeclare" errors

import { argon2id as argon2idHash } from "hash-wasm";

// eslint-disable-next-line no-var
var _workerCtx = globalThis as unknown as {
    onmessage: ((e: MessageEvent) => void) | null;
    postMessage: (message: any, options?: any) => void;
};

const BLOB_VERSION = 0x04;
const SUPPORTED_VERSIONS = new Set([0x01, 0x02, 0x03, 0x04]);
const V4_HEADER_SIZE = 10;
const KDF_ARGON2ID = 0x01;
const KDF_PBKDF2 = 0x02;

interface WorkerCryptoConfig {
    algorithm: string;
    kdf: string;
    argon2Memory: number;
    argon2Passes: number;
    argon2Parallelism: number;
    iterations: number;
    saltLength: number;
    ivLength: number;
    hashAlgorithm: string;
}

const DEFAULT_CONFIG: WorkerCryptoConfig = {
    algorithm: "AES-256-GCM",
    kdf: "argon2id",
    argon2Memory: 65536,
    argon2Passes: 3,
    argon2Parallelism: 1,
    iterations: 1_000_000,
    saltLength: 32,
    ivLength: 12,
    hashAlgorithm: "SHA-512",
};

function getKeyLength(algorithm: string): number {
    if (algorithm === "AES-192-GCM") return 192;
    if (algorithm === "AES-128-GCM") return 128;
    return 256;
}

function getRandomBytes(length: number): Uint8Array<ArrayBuffer> {
    const bytes = new Uint8Array(length) as Uint8Array<ArrayBuffer>;
    crypto.getRandomValues(bytes);
    return bytes;
}

function wipeBuffer(buffer: ArrayBuffer | Uint8Array): void {
    const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    view.fill(0);
}

function encodeConfigByte(): number {
    return (0 << 4) | 2; // AES-256-GCM | SHA-512
}

function decodeConfigLegacyV2(byte: number): { algorithm: string; hashAlgorithm: string } {
    const algArr = ["AES-256-GCM", "AES-192-GCM", "AES-128-GCM"];
    const hashArr = ["SHA-256", "SHA-384", "SHA-512"];
    return {
        algorithm: algArr[(byte >> 4) & 0x0f] ?? "AES-256-GCM",
        hashAlgorithm: hashArr[byte & 0x0f] ?? "SHA-256",
    };
}

/**
 * Derive AES key — Argon2id (v4) or PBKDF2 (legacy)
 */
async function deriveKey(
    password: string,
    salt: Uint8Array,
    config: WorkerCryptoConfig
): Promise<CryptoKey> {
    if (config.kdf === "argon2id") {
        const encoder = new TextEncoder();
        const passwordBytes = encoder.encode(password);
        const hashHex = await argon2idHash({
            password: new TextDecoder().decode(passwordBytes),
            salt,
            parallelism: config.argon2Parallelism,
            iterations: config.argon2Passes,
            memorySize: config.argon2Memory,
            hashLength: 32,
            outputType: "hex",
        });
        passwordBytes.fill(0);
        // Convert hex to bytes
        const rawKey = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            rawKey[i] = parseInt(hashHex.substring(i * 2, i * 2 + 2), 16);
        }
        const key = await crypto.subtle.importKey(
            "raw",
            rawKey.buffer as ArrayBuffer,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
        wipeBuffer(rawKey);
        return key;
    }

    // PBKDF2 fallback
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);
    const keyMaterial = await crypto.subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt.buffer as ArrayBuffer, iterations: config.iterations, hash: config.hashAlgorithm },
        keyMaterial,
        { name: "AES-GCM", length: getKeyLength(config.algorithm) },
        false,
        ["encrypt", "decrypt"]
    );
    passwordBytes.fill(0);
    return key;
}

/**
 * Build v4 header (10 bytes)
 */
function buildV4Header(config: WorkerCryptoConfig): Uint8Array {
    const header = new Uint8Array(V4_HEADER_SIZE);
    header[0] = BLOB_VERSION;
    header[1] = config.kdf === "argon2id" ? KDF_ARGON2ID : KDF_PBKDF2;
    header[2] = encodeConfigByte();
    header[3] = config.saltLength;
    header[4] = config.ivLength;
    const mem = config.argon2Memory;
    header[5] = (mem >> 24) & 0xff;
    header[6] = (mem >> 16) & 0xff;
    header[7] = (mem >> 8) & 0xff;
    header[8] = mem & 0xff;
    header[9] = ((config.argon2Passes & 0x0f) << 4) | (config.argon2Parallelism & 0x0f);
    return header;
}

_workerCtx.onmessage = async (e: MessageEvent) => {
    const { type, data, password, id, config: rawConfig } = e.data;
    const config: WorkerCryptoConfig = rawConfig
        ? { ...DEFAULT_CONFIG, ...rawConfig }
        : DEFAULT_CONFIG;

    try {
        switch (type) {
            // ─── ENCRYPT FILE ────────────────────────────────────────
            case "encrypt-file": {
                const kdfLabel = config.kdf === "argon2id"
                    ? `Argon2id (${(config.argon2Memory / 1024).toFixed(0)} MiB, ${config.argon2Passes}p)`
                    : `PBKDF2 (${config.iterations.toLocaleString()} itr)`;

                _workerCtx.postMessage({ id, stage: "deriving-key", progress: 10, message: `Deriving key: ${kdfLabel}...` });

                const salt = getRandomBytes(config.saltLength);
                const iv = getRandomBytes(config.ivLength);
                const key = await deriveKey(password, salt, config);
                const header = buildV4Header(config);

                _workerCtx.postMessage({ id, stage: "encrypting", progress: 40, message: "Encrypting with AES-256-GCM (AAD)..." });

                const ciphertext = await crypto.subtle.encrypt(
                    { name: "AES-GCM", iv: iv.buffer as ArrayBuffer, additionalData: header.buffer as ArrayBuffer },
                    key,
                    data
                );

                const blob = new Uint8Array(V4_HEADER_SIZE + config.saltLength + config.ivLength + ciphertext.byteLength);
                blob.set(header, 0);
                blob.set(salt, V4_HEADER_SIZE);
                blob.set(iv, V4_HEADER_SIZE + config.saltLength);
                blob.set(new Uint8Array(ciphertext), V4_HEADER_SIZE + config.saltLength + config.ivLength);

                wipeBuffer(salt);
                wipeBuffer(iv);
                wipeBuffer(data);

                _workerCtx.postMessage(
                    { id, stage: "done", progress: 100, message: "Encryption complete", result: blob.buffer },
                    { transfer: [blob.buffer] }
                );
                break;
            }

            // ─── DECRYPT FILE ────────────────────────────────────────
            case "decrypt-file": {
                const view = new Uint8Array(data);
                if (view.length < 8) throw new Error("⛔ Blob too small");

                const version = view[0];
                if (!SUPPORTED_VERSIONS.has(version)) throw new Error(`⛔ Unknown version (0x${version.toString(16).padStart(2, "0")})`);

                if (version === 0x01) { await decryptLegacyV1File(view, password, id, data); }
                else if (version === 0x02) { await decryptLegacyV2File(view, password, id, data); }
                else if (version === 0x03) { await decryptLegacyV3File(view, password, id, data); }
                else { await decryptV4File(view, password, id, data); }
                break;
            }

            // ─── ENCRYPT TEXT ────────────────────────────────────────
            case "encrypt-text": {
                const kdfLabel = config.kdf === "argon2id"
                    ? `Argon2id (${(config.argon2Memory / 1024).toFixed(0)} MiB)`
                    : `PBKDF2 (${config.iterations.toLocaleString()} itr)`;

                _workerCtx.postMessage({ id, stage: "deriving-key", progress: 10, message: `Deriving key: ${kdfLabel}...` });

                const encoder = new TextEncoder();
                const textData = encoder.encode(data);
                const salt = getRandomBytes(config.saltLength);
                const iv = getRandomBytes(config.ivLength);
                const key = await deriveKey(password, salt, config);
                const header = buildV4Header(config);

                _workerCtx.postMessage({ id, stage: "encrypting", progress: 50, message: "Encrypting with AES-256-GCM (AAD)..." });

                const ciphertext = await crypto.subtle.encrypt(
                    { name: "AES-GCM", iv: iv.buffer as ArrayBuffer, additionalData: header.buffer as ArrayBuffer },
                    key,
                    textData
                );

                const blob = new Uint8Array(V4_HEADER_SIZE + config.saltLength + config.ivLength + ciphertext.byteLength);
                blob.set(header, 0);
                blob.set(salt, V4_HEADER_SIZE);
                blob.set(iv, V4_HEADER_SIZE + config.saltLength);
                blob.set(new Uint8Array(ciphertext), V4_HEADER_SIZE + config.saltLength + config.ivLength);

                wipeBuffer(salt);
                wipeBuffer(iv);
                wipeBuffer(textData);

                const bytes = new Uint8Array(blob.buffer);
                let binary = "";
                for (let i = 0; i < bytes.byteLength; i++) {
                    binary += String.fromCharCode(bytes[i]);
                }
                const base64 = btoa(binary);

                _workerCtx.postMessage({ id, stage: "done", progress: 100, message: "Encryption complete", result: base64 });
                break;
            }

            // ─── DECRYPT TEXT ────────────────────────────────────────
            case "decrypt-text": {
                _workerCtx.postMessage({ id, stage: "deriving-key", progress: 10, message: "Processing encrypted text..." });

                const binaryStr = atob(data.trim());
                const bytes = new Uint8Array(binaryStr.length);
                for (let i = 0; i < binaryStr.length; i++) {
                    bytes[i] = binaryStr.charCodeAt(i);
                }

                const view = new Uint8Array(bytes);
                if (view.length < 8) throw new Error("⛔ Blob too small");

                const version = view[0];
                if (!SUPPORTED_VERSIONS.has(version)) throw new Error(`⛔ Unknown version (0x${version.toString(16).padStart(2, "0")})`);

                if (version === 0x01) { await decryptLegacyV1Text(view, password, id, bytes); }
                else if (version === 0x02) { await decryptLegacyV2Text(view, password, id, bytes); }
                else if (version === 0x03) { await decryptLegacyV3Text(view, password, id, bytes); }
                else { await decryptV4Text(view, password, id, bytes); }
                break;
            }

            default:
                throw new Error(`Unknown operation: ${type}`);
        }
    } catch (error: any) {
        const message = error instanceof Error ? error.message : "Unknown error occurred";
        _workerCtx.postMessage({ id, stage: "error", progress: 0, message, error: message });
    }
};

// ─── V4 Decrypt (Argon2id + AAD) ─────────────────────────────────────

async function decryptV4File(view: Uint8Array, password: string, id: string, originalData: ArrayBuffer) {
    if (view.length < V4_HEADER_SIZE + 1) throw new Error("⛔ Truncated v4 blob");

    const header = view.slice(0, V4_HEADER_SIZE);
    const kdfByte = header[1];
    const saltLen = header[3];
    const ivLen = header[4];
    const argon2Mem = (header[5] << 24) | (header[6] << 16) | (header[7] << 8) | header[8];
    const argon2Passes = (header[9] >> 4) & 0x0f;
    const argon2Para = header[9] & 0x0f;

    const salt = view.slice(V4_HEADER_SIZE, V4_HEADER_SIZE + saltLen);
    const iv = view.slice(V4_HEADER_SIZE + saltLen, V4_HEADER_SIZE + saltLen + ivLen);
    const ciphertext = view.slice(V4_HEADER_SIZE + saltLen + ivLen);

    const decConfig: WorkerCryptoConfig = {
        algorithm: "AES-256-GCM",
        kdf: kdfByte === KDF_ARGON2ID ? "argon2id" : "pbkdf2",
        argon2Memory: argon2Mem,
        argon2Passes: argon2Passes,
        argon2Parallelism: argon2Para,
        iterations: 1_000_000,
        saltLength: saltLen,
        ivLength: ivLen,
        hashAlgorithm: "SHA-512",
    };

    const kdfLabel = decConfig.kdf === "argon2id" ? `Argon2id (${(argon2Mem / 1024).toFixed(0)} MiB)` : "PBKDF2";
    _workerCtx.postMessage({ id, stage: "deriving-key", progress: 10, message: `Deriving key: ${kdfLabel}...` });

    const key = await deriveKey(password, salt, decConfig);
    _workerCtx.postMessage({ id, stage: "decrypting", progress: 40, message: "Decrypting AES-256-GCM (AAD-verified)..." });

    try {
        const plaintext = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv.buffer as ArrayBuffer, additionalData: header.buffer as ArrayBuffer },
            key,
            ciphertext.buffer as ArrayBuffer
        );
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext); wipeBuffer(originalData);
        _workerCtx.postMessage({ id, stage: "done", progress: 100, message: "Decryption complete", result: plaintext }, { transfer: [plaintext] });
    } catch {
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext);
        throw new Error("Decryption failed. Wrong password, tampered header, or corrupted file.");
    }
}

async function decryptV4Text(view: Uint8Array, password: string, id: string, bytes: Uint8Array) {
    if (view.length < V4_HEADER_SIZE + 1) throw new Error("⛔ Truncated v4 text");

    const header = view.slice(0, V4_HEADER_SIZE);
    const kdfByte = header[1];
    const saltLen = header[3];
    const ivLen = header[4];
    const argon2Mem = (header[5] << 24) | (header[6] << 16) | (header[7] << 8) | header[8];
    const argon2Passes = (header[9] >> 4) & 0x0f;
    const argon2Para = header[9] & 0x0f;

    const salt = view.slice(V4_HEADER_SIZE, V4_HEADER_SIZE + saltLen);
    const iv = view.slice(V4_HEADER_SIZE + saltLen, V4_HEADER_SIZE + saltLen + ivLen);
    const ciphertext = view.slice(V4_HEADER_SIZE + saltLen + ivLen);

    const decConfig: WorkerCryptoConfig = {
        algorithm: "AES-256-GCM",
        kdf: kdfByte === KDF_ARGON2ID ? "argon2id" : "pbkdf2",
        argon2Memory: argon2Mem,
        argon2Passes: argon2Passes,
        argon2Parallelism: argon2Para,
        iterations: 1_000_000,
        saltLength: saltLen,
        ivLength: ivLen,
        hashAlgorithm: "SHA-512",
    };

    const key = await deriveKey(password, salt, decConfig);
    _workerCtx.postMessage({ id, stage: "decrypting", progress: 50, message: "Decrypting AES-256-GCM (AAD-verified)..." });

    try {
        const plaintext = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv.buffer as ArrayBuffer, additionalData: header.buffer as ArrayBuffer },
            key,
            ciphertext.buffer as ArrayBuffer
        );
        const decoder = new TextDecoder();
        const text = decoder.decode(plaintext);
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext); wipeBuffer(bytes); wipeBuffer(plaintext);
        _workerCtx.postMessage({ id, stage: "done", progress: 100, message: "Decryption complete", result: text });
    } catch {
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext); wipeBuffer(bytes);
        throw new Error("Decryption failed. Wrong password, tampered header, or corrupted text.");
    }
}

// ─── Legacy V3 (PBKDF2 + AAD) ───────────────────────────────────────

async function decryptLegacyV3File(view: Uint8Array, password: string, id: string, originalData: ArrayBuffer) {
    const headerSize = 8;
    const header = view.slice(0, headerSize);
    const saltLen = header[2];
    const ivLen = header[3];
    const iterations = (header[4] << 24) | (header[5] << 16) | (header[6] << 8) | header[7];

    if (view.length < headerSize + saltLen + ivLen + 1) throw new Error("⛔ Truncated v3 blob");

    const salt = view.slice(headerSize, headerSize + saltLen);
    const iv = view.slice(headerSize + saltLen, headerSize + saltLen + ivLen);
    const ciphertext = view.slice(headerSize + saltLen + ivLen);

    const decConfig: WorkerCryptoConfig = {
        ...DEFAULT_CONFIG, kdf: "pbkdf2", iterations, saltLength: saltLen, ivLength: ivLen,
    };

    _workerCtx.postMessage({ id, stage: "deriving-key", progress: 10, message: `Deriving key (PBKDF2, ${iterations.toLocaleString()} itr)...` });
    const key = await deriveKey(password, salt, decConfig);
    _workerCtx.postMessage({ id, stage: "decrypting", progress: 40, message: "Decrypting AES-256-GCM (AAD-verified)..." });

    try {
        const plaintext = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv.buffer as ArrayBuffer, additionalData: header.buffer as ArrayBuffer },
            key, ciphertext.buffer as ArrayBuffer
        );
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext); wipeBuffer(originalData);
        _workerCtx.postMessage({ id, stage: "done", progress: 100, message: "Decryption complete (legacy v3)", result: plaintext }, { transfer: [plaintext] });
    } catch {
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext);
        throw new Error("Decryption failed. Wrong password, tampered header, or corrupted file.");
    }
}

async function decryptLegacyV3Text(view: Uint8Array, password: string, id: string, bytes: Uint8Array) {
    const headerSize = 8;
    const header = view.slice(0, headerSize);
    const saltLen = header[2];
    const ivLen = header[3];
    const iterations = (header[4] << 24) | (header[5] << 16) | (header[6] << 8) | header[7];

    const salt = view.slice(headerSize, headerSize + saltLen);
    const iv = view.slice(headerSize + saltLen, headerSize + saltLen + ivLen);
    const ciphertext = view.slice(headerSize + saltLen + ivLen);

    const decConfig: WorkerCryptoConfig = {
        ...DEFAULT_CONFIG, kdf: "pbkdf2", iterations, saltLength: saltLen, ivLength: ivLen,
    };

    const key = await deriveKey(password, salt, decConfig);
    _workerCtx.postMessage({ id, stage: "decrypting", progress: 50, message: "Decrypting AES-256-GCM (AAD-verified)..." });

    try {
        const plaintext = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv.buffer as ArrayBuffer, additionalData: header.buffer as ArrayBuffer },
            key, ciphertext.buffer as ArrayBuffer
        );
        const decoder = new TextDecoder();
        const text = decoder.decode(plaintext);
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext); wipeBuffer(bytes); wipeBuffer(plaintext);
        _workerCtx.postMessage({ id, stage: "done", progress: 100, message: "Decryption complete (legacy v3)", result: text });
    } catch {
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext); wipeBuffer(bytes);
        throw new Error("Decryption failed. Wrong password, tampered header, or corrupted text.");
    }
}

// ─── Legacy V2 (PBKDF2, no AAD) ─────────────────────────────────────

async function decryptLegacyV2File(view: Uint8Array, password: string, id: string, originalData: ArrayBuffer) {
    const { algorithm, hashAlgorithm } = decodeConfigLegacyV2(view[1]);
    const saltLen = view[2]; const ivLen = view[3];
    const iterations = (view[4] << 24) | (view[5] << 16) | (view[6] << 8) | view[7];
    const headerSize = 8;

    const salt = view.slice(headerSize, headerSize + saltLen);
    const iv = view.slice(headerSize + saltLen, headerSize + saltLen + ivLen);
    const ciphertext = view.slice(headerSize + saltLen + ivLen);

    const decConfig: WorkerCryptoConfig = { ...DEFAULT_CONFIG, kdf: "pbkdf2", algorithm, iterations, saltLength: saltLen, ivLength: ivLen, hashAlgorithm };

    _workerCtx.postMessage({ id, stage: "deriving-key", progress: 10, message: `Deriving key (legacy v2, ${iterations.toLocaleString()} itr)...` });
    const key = await deriveKey(password, salt, decConfig);
    _workerCtx.postMessage({ id, stage: "decrypting", progress: 40, message: `Decrypting legacy v2 (${algorithm})...` });

    try {
        const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv.buffer as ArrayBuffer }, key, ciphertext.buffer as ArrayBuffer);
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext); wipeBuffer(originalData);
        _workerCtx.postMessage({ id, stage: "done", progress: 100, message: "Decryption complete (legacy v2)", result: plaintext }, { transfer: [plaintext] });
    } catch {
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext);
        throw new Error("Decryption failed. Wrong password or corrupted file.");
    }
}

async function decryptLegacyV2Text(view: Uint8Array, password: string, id: string, bytes: Uint8Array) {
    const { algorithm, hashAlgorithm } = decodeConfigLegacyV2(view[1]);
    const saltLen = view[2]; const ivLen = view[3];
    const iterations = (view[4] << 24) | (view[5] << 16) | (view[6] << 8) | view[7];
    const headerSize = 8;

    const salt = view.slice(headerSize, headerSize + saltLen);
    const iv = view.slice(headerSize + saltLen, headerSize + saltLen + ivLen);
    const ciphertext = view.slice(headerSize + saltLen + ivLen);

    const decConfig: WorkerCryptoConfig = { ...DEFAULT_CONFIG, kdf: "pbkdf2", algorithm, iterations, saltLength: saltLen, ivLength: ivLen, hashAlgorithm };
    const key = await deriveKey(password, salt, decConfig);
    _workerCtx.postMessage({ id, stage: "decrypting", progress: 50, message: `Decrypting legacy v2 (${algorithm})...` });

    try {
        const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv.buffer as ArrayBuffer }, key, ciphertext.buffer as ArrayBuffer);
        const decoder = new TextDecoder(); const text = decoder.decode(plaintext);
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext); wipeBuffer(bytes); wipeBuffer(plaintext);
        _workerCtx.postMessage({ id, stage: "done", progress: 100, message: "Decryption complete (legacy v2)", result: text });
    } catch {
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext); wipeBuffer(bytes);
        throw new Error("Decryption failed. Wrong password or corrupted text.");
    }
}

// ─── Legacy V1 ───────────────────────────────────────────────────────

async function decryptLegacyV1File(view: Uint8Array, password: string, id: string, originalData: ArrayBuffer) {
    const SALT_LEN = 16; const IV_LEN = 12;
    const salt = view.slice(1, 1 + SALT_LEN);
    const iv = view.slice(1 + SALT_LEN, 1 + SALT_LEN + IV_LEN);
    const ciphertext = view.slice(1 + SALT_LEN + IV_LEN);

    const decConfig: WorkerCryptoConfig = { ...DEFAULT_CONFIG, kdf: "pbkdf2", iterations: 250000, saltLength: SALT_LEN, ivLength: IV_LEN, hashAlgorithm: "SHA-256" };

    _workerCtx.postMessage({ id, stage: "deriving-key", progress: 10, message: "Deriving key (legacy v1)..." });
    const key = await deriveKey(password, salt, decConfig);
    _workerCtx.postMessage({ id, stage: "decrypting", progress: 40, message: "Decrypting legacy v1..." });

    try {
        const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv.buffer as ArrayBuffer }, key, ciphertext.buffer as ArrayBuffer);
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext); wipeBuffer(originalData);
        _workerCtx.postMessage({ id, stage: "done", progress: 100, message: "Decryption complete (legacy v1)", result: plaintext }, { transfer: [plaintext] });
    } catch {
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext);
        throw new Error("Decryption failed. Wrong password or corrupted file.");
    }
}

async function decryptLegacyV1Text(view: Uint8Array, password: string, id: string, bytes: Uint8Array) {
    const SALT_LEN = 16; const IV_LEN = 12;
    const salt = view.slice(1, 1 + SALT_LEN);
    const iv = view.slice(1 + SALT_LEN, 1 + SALT_LEN + IV_LEN);
    const ciphertext = view.slice(1 + SALT_LEN + IV_LEN);

    const decConfig: WorkerCryptoConfig = { ...DEFAULT_CONFIG, kdf: "pbkdf2", iterations: 250000, saltLength: SALT_LEN, ivLength: IV_LEN, hashAlgorithm: "SHA-256" };
    const key = await deriveKey(password, salt, decConfig);
    _workerCtx.postMessage({ id, stage: "decrypting", progress: 50, message: "Decrypting legacy v1..." });

    try {
        const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv.buffer as ArrayBuffer }, key, ciphertext.buffer as ArrayBuffer);
        const decoder = new TextDecoder(); const text = decoder.decode(plaintext);
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext); wipeBuffer(bytes); wipeBuffer(plaintext);
        _workerCtx.postMessage({ id, stage: "done", progress: 100, message: "Decryption complete (legacy v1)", result: text });
    } catch {
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext); wipeBuffer(bytes);
        throw new Error("Decryption failed. Wrong password or corrupted text.");
    }
}
