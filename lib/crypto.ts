// AES-256-GCM Encryption/Decryption with Argon2id KDF (primary) + PBKDF2-SHA512 (legacy)
// Zero-knowledge: all operations run client-side only
// Blob v4: Argon2id KDF. Blob v1-v3: PBKDF2 legacy decrypt only.

import { type CryptoConfig, DEFAULT_CONFIG } from "./crypto-config";
import { deriveKeyArgon2id } from "./argon2";

// Blob v4: [version:1][kdfByte:1][configByte:1][saltLen:1][ivLen:1][argon2Mem:4][argon2Passes:1][argon2Para:1][salt:N][iv:N][ciphertext:rest]
// Header (10 bytes) is passed as AAD to AES-GCM so any tampering is detected
const BLOB_VERSION = 0x04;
const SUPPORTED_VERSIONS = new Set([0x01, 0x02, 0x03, 0x04]);
const V4_HEADER_SIZE = 10;
const IV_LEN = 12;
const CHUNK_SIZE = 64 * 1024 * 1024; // 64 MiB per chunk

// KDF byte values
const KDF_ARGON2ID = 0x01;
const KDF_PBKDF2 = 0x02;

export interface CryptoProgress {
    stage: "idle" | "deriving-key" | "encrypting" | "decrypting" | "done" | "error";
    progress: number;
    message: string;
}

function getRandomBytes(length: number): Uint8Array<ArrayBuffer> {
    const bytes = new Uint8Array(length) as Uint8Array<ArrayBuffer>;
    crypto.getRandomValues(bytes);
    return bytes;
}

export function wipeBuffer(buffer: ArrayBuffer | Uint8Array): void {
    const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    view.fill(0);
}

// Config byte: bit7 = backup key flag, bits 4-6 = algorithm, bits 0-3 = hash
function encodeConfigByte(backupKeyFlag?: boolean): number {
    // AES-256-GCM (0) | SHA-512 (2) | backup key flag in bit 7
    return ((backupKeyFlag ? 0x80 : 0) | (0 << 4) | 2);
}

function decodeConfigByte(byte: number): { algorithm: CryptoConfig["algorithm"]; hashAlgorithm: CryptoConfig["hashAlgorithm"] } {
    return { algorithm: "AES-256-GCM", hashAlgorithm: "SHA-512" };
}

/** Check if the config byte has the backup key flag set */
export function hasBackupKeyFlag(configByte: number): boolean {
    return (configByte & 0x80) !== 0;
}

// For legacy v2 decryption
function decodeConfigLegacy(byte: number): { algorithm: string; hashAlgorithm: string } {
    const algArr = ["AES-256-GCM", "AES-192-GCM", "AES-128-GCM"];
    const hashArr = ["SHA-256", "SHA-384", "SHA-512"];
    return {
        algorithm: algArr[(byte >> 4) & 0x0f] ?? "AES-256-GCM",
        hashAlgorithm: hashArr[byte & 0x0f] ?? "SHA-256",
    };
}

function getKeyLengthForAlgorithm(algorithm: string): number {
    if (algorithm === "AES-192-GCM") return 192;
    if (algorithm === "AES-128-GCM") return 128;
    return 256;
}

/**
 * Derive AES-GCM key using Argon2id (v4) or PBKDF2 (legacy).
 */
export async function deriveKey(
    password: string,
    salt: Uint8Array,
    config: CryptoConfig = DEFAULT_CONFIG,
    keyLength: number = 256
): Promise<CryptoKey> {
    if (config.kdf === "argon2id") {
        const rawKey = await deriveKeyArgon2id(password, salt, {
            memorySize: config.argon2Memory,
            passes: config.argon2Passes,
            parallelism: config.argon2Parallelism,
        });
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

    // PBKDF2 fallback (legacy)
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);
    const keyMaterial = await crypto.subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt.buffer as ArrayBuffer, iterations: config.iterations, hash: config.hashAlgorithm },
        keyMaterial,
        { name: "AES-GCM", length: keyLength },
        false,
        ["encrypt", "decrypt"]
    );
    passwordBytes.fill(0);
    return key;
}

/**
 * Encrypt data with AES-256-GCM + Argon2id KDF.
 * V4 header authenticated via AES-GCM AAD.
 */
export async function encryptData(
    data: ArrayBuffer,
    password: string,
    config: CryptoConfig = DEFAULT_CONFIG,
    onProgress?: (p: CryptoProgress) => void
): Promise<ArrayBuffer> {
    const kdfLabel = config.kdf === "argon2id"
        ? `Argon2id (${(config.argon2Memory / 1024).toFixed(0)} MiB, ${config.argon2Passes} passes)`
        : `PBKDF2 (${config.iterations.toLocaleString()} iterations)`;

    onProgress?.({ stage: "deriving-key", progress: 5, message: `Deriving key: ${kdfLabel}...` });

    const salt = getRandomBytes(config.saltLength);
    const key = await deriveKey(password, salt, config);

    // Build v4 header
    const header = new Uint8Array(V4_HEADER_SIZE);
    header[0] = BLOB_VERSION;
    header[1] = config.kdf === "argon2id" ? KDF_ARGON2ID : KDF_PBKDF2;
    header[2] = encodeConfigByte(config.backupKeyFlag);
    header[3] = config.saltLength;
    header[4] = config.ivLength;
    const mem = config.argon2Memory;
    header[5] = (mem >> 24) & 0xff;
    header[6] = (mem >> 16) & 0xff;
    header[7] = (mem >> 8) & 0xff;
    header[8] = mem & 0xff;
    header[9] = ((config.argon2Passes & 0x0f) << 4) | (config.argon2Parallelism & 0x0f);

    const inputView = new Uint8Array(data);
    const totalBytes = inputView.byteLength;
    const numChunks = Math.max(1, Math.ceil(totalBytes / CHUNK_SIZE));

    onProgress?.({ stage: "encrypting", progress: 15, message: `Encrypting ${numChunks} chunk(s)...` });

    const chunkOutputs: { iv: Uint8Array; ct: Uint8Array }[] = [];
    let totalCtBytes = 0;

    for (let i = 0; i < numChunks; i++) {
        const chunkStart = i * CHUNK_SIZE;
        const chunkEnd = Math.min(chunkStart + CHUNK_SIZE, totalBytes);
        const chunkData = inputView.slice(chunkStart, chunkEnd);
        const chunkIv = getRandomBytes(IV_LEN);

        const aad = new Uint8Array(V4_HEADER_SIZE + 4);
        aad.set(header, 0);
        aad[V4_HEADER_SIZE] = (i >> 24) & 0xff;
        aad[V4_HEADER_SIZE + 1] = (i >> 16) & 0xff;
        aad[V4_HEADER_SIZE + 2] = (i >> 8) & 0xff;
        aad[V4_HEADER_SIZE + 3] = i & 0xff;

        const ct = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: chunkIv.buffer as ArrayBuffer, additionalData: aad.buffer as ArrayBuffer },
            key,
            chunkData.buffer as ArrayBuffer
        );
        wipeBuffer(chunkData);
        chunkOutputs.push({ iv: chunkIv, ct: new Uint8Array(ct) });
        totalCtBytes += IV_LEN + 4 + ct.byteLength;

        const pct = 15 + Math.round(((i + 1) / numChunks) * 80);
        onProgress?.({ stage: "encrypting", progress: pct, message: `Encrypted chunk ${i + 1}/${numChunks}` });
    }

    // Assemble blob
    const blobSize = V4_HEADER_SIZE + config.saltLength + 4 + totalCtBytes;
    const blob = new Uint8Array(blobSize);
    let offset = 0;
    blob.set(header, offset); offset += V4_HEADER_SIZE;
    blob.set(salt, offset); offset += config.saltLength;
    blob[offset] = (numChunks >> 24) & 0xff;
    blob[offset + 1] = (numChunks >> 16) & 0xff;
    blob[offset + 2] = (numChunks >> 8) & 0xff;
    blob[offset + 3] = numChunks & 0xff;
    offset += 4;

    for (const { iv: cIv, ct } of chunkOutputs) {
        blob.set(cIv, offset); offset += IV_LEN;
        const ctLen = ct.byteLength;
        blob[offset] = (ctLen >> 24) & 0xff;
        blob[offset + 1] = (ctLen >> 16) & 0xff;
        blob[offset + 2] = (ctLen >> 8) & 0xff;
        blob[offset + 3] = ctLen & 0xff;
        offset += 4;
        blob.set(ct, offset); offset += ctLen;
        wipeBuffer(cIv); wipeBuffer(ct);
    }

    wipeBuffer(salt);
    wipeBuffer(data);

    onProgress?.({ stage: "done", progress: 100, message: "Encryption complete" });
    return blob.buffer;
}

/**
 * Decrypt data: auto-detect version and config from blob header.
 */
export async function decryptData(
    blob: ArrayBuffer,
    password: string,
    onProgress?: (p: CryptoProgress) => void
): Promise<ArrayBuffer> {
    const view = new Uint8Array(blob);

    if (view.length < 8) {
        throw new Error("⛔ Unsupported or tampered blob — file too small to be valid");
    }

    const version = view[0];

    if (!SUPPORTED_VERSIONS.has(version)) {
        throw new Error(`⛔ Unsupported or tampered blob — unknown format version (0x${version.toString(16).padStart(2, "0")})`);
    }

    if (version === 0x01) return decryptLegacyV1(view, password, onProgress);
    if (version === 0x02) return decryptLegacyV2(view, password, onProgress);
    if (version === 0x03) return decryptLegacyV3(view, password, onProgress);
    return decryptV4(view, password, onProgress);
}

// ─── V4 Decrypt (Argon2id + AAD) ─────────────────────────────────────

async function decryptV4(
    view: Uint8Array,
    password: string,
    onProgress?: (p: CryptoProgress) => void
): Promise<ArrayBuffer> {
    if (view.length < V4_HEADER_SIZE + 1) throw new Error("⛔ Truncated v4 data");

    const header = view.slice(0, V4_HEADER_SIZE);
    const kdfByte = header[1];
    const saltLen = header[3];
    const argon2Mem = (header[5] << 24) | (header[6] << 16) | (header[7] << 8) | header[8];
    const argon2Passes = (header[9] >> 4) & 0x0f;
    const argon2Para = header[9] & 0x0f;

    let offset = V4_HEADER_SIZE;
    const salt = view.slice(offset, offset + saltLen); offset += saltLen;

    if (view.length < offset + 4) throw new Error("⛔ Truncated v4 — missing chunk count");
    const numChunks = (view[offset] << 24) | (view[offset + 1] << 16) | (view[offset + 2] << 8) | view[offset + 3];
    offset += 4;
    if (numChunks < 1 || numChunks > 100_000) throw new Error("⛔ Invalid chunk count");

    const config: CryptoConfig = {
        algorithm: "AES-256-GCM",
        kdf: kdfByte === KDF_ARGON2ID ? "argon2id" : "pbkdf2",
        argon2Memory: argon2Mem,
        argon2Passes: argon2Passes,
        argon2Parallelism: argon2Para,
        iterations: 1_000_000,
        saltLength: saltLen,
        ivLength: IV_LEN,
        hashAlgorithm: "SHA-512",
    };

    const kdfLabel = config.kdf === "argon2id"
        ? `Argon2id (${(argon2Mem / 1024).toFixed(0)} MiB, ${argon2Passes} passes)`
        : "PBKDF2";

    onProgress?.({ stage: "deriving-key", progress: 5, message: `Deriving key: ${kdfLabel}...` });
    const key = await deriveKey(password, salt, config);

    onProgress?.({ stage: "decrypting", progress: 15, message: `Decrypting ${numChunks} chunk(s)...` });

    const plaintextParts: ArrayBuffer[] = [];
    let totalPlaintext = 0;

    try {
        for (let i = 0; i < numChunks; i++) {
            if (offset + IV_LEN + 4 > view.length) throw new Error(`⛔ Truncated chunk ${i}`);
            const chunkIv = view.slice(offset, offset + IV_LEN); offset += IV_LEN;
            const ctLen = (view[offset] << 24) | (view[offset + 1] << 16) | (view[offset + 2] << 8) | view[offset + 3];
            offset += 4;
            if (offset + ctLen > view.length) throw new Error(`⛔ Truncated chunk ${i} ciphertext`);
            const chunkCt = view.slice(offset, offset + ctLen); offset += ctLen;

            const aad = new Uint8Array(V4_HEADER_SIZE + 4);
            aad.set(header, 0);
            aad[V4_HEADER_SIZE] = (i >> 24) & 0xff;
            aad[V4_HEADER_SIZE + 1] = (i >> 16) & 0xff;
            aad[V4_HEADER_SIZE + 2] = (i >> 8) & 0xff;
            aad[V4_HEADER_SIZE + 3] = i & 0xff;

            const pt = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: chunkIv.buffer as ArrayBuffer, additionalData: aad.buffer as ArrayBuffer },
                key,
                chunkCt.buffer as ArrayBuffer
            );
            wipeBuffer(chunkIv); wipeBuffer(chunkCt);
            plaintextParts.push(pt);
            totalPlaintext += pt.byteLength;

            const pct = 15 + Math.round(((i + 1) / numChunks) * 80);
            onProgress?.({ stage: "decrypting", progress: pct, message: `Decrypted chunk ${i + 1}/${numChunks}` });
        }

        const combined = new Uint8Array(totalPlaintext);
        let cOffset = 0;
        for (const part of plaintextParts) {
            combined.set(new Uint8Array(part), cOffset);
            cOffset += part.byteLength;
            wipeBuffer(part);
        }

        wipeBuffer(salt);
        onProgress?.({ stage: "done", progress: 100, message: "Decryption complete" });
        return combined.buffer;
    } catch (err) {
        wipeBuffer(salt);
        if (err instanceof Error && err.message.startsWith("⛔")) throw err;
        throw new Error("Decryption failed. Wrong password, tampered header, or corrupted file.");
    }
}

// ─── Legacy V3 (PBKDF2 + AAD) ───────────────────────────────────────

async function decryptLegacyV3(
    view: Uint8Array,
    password: string,
    onProgress?: (p: CryptoProgress) => void
): Promise<ArrayBuffer> {
    const headerSize = 8;
    const header = view.slice(0, headerSize);
    const saltLen = header[2];
    const ivLen = header[3];
    const iterations = (header[4] << 24) | (header[5] << 16) | (header[6] << 8) | header[7];

    if (view.length < headerSize + saltLen + ivLen + 1) {
        throw new Error("⛔ Unsupported or tampered blob — truncated v3 data");
    }

    const salt = view.slice(headerSize, headerSize + saltLen);
    const iv = view.slice(headerSize + saltLen, headerSize + saltLen + ivLen);
    const ciphertext = view.slice(headerSize + saltLen + ivLen);

    const config: CryptoConfig = {
        algorithm: "AES-256-GCM",
        kdf: "pbkdf2",
        argon2Memory: 65536,
        argon2Passes: 3,
        argon2Parallelism: 1,
        iterations,
        saltLength: saltLen,
        ivLength: ivLen,
        hashAlgorithm: "SHA-512",
    };

    onProgress?.({ stage: "deriving-key", progress: 10, message: `Deriving key (PBKDF2, ${iterations.toLocaleString()} itr)...` });
    const key = await deriveKey(password, salt, config);

    onProgress?.({ stage: "decrypting", progress: 30, message: "Decrypting with AES-256-GCM (AAD-verified)..." });

    try {
        const plaintext = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv.buffer as ArrayBuffer,
                additionalData: header.buffer as ArrayBuffer,
            },
            key,
            ciphertext.buffer as ArrayBuffer
        );
        wipeBuffer(salt);
        wipeBuffer(iv);
        wipeBuffer(ciphertext);
        onProgress?.({ stage: "done", progress: 100, message: "Decryption complete (legacy v3)" });
        return plaintext;
    } catch {
        wipeBuffer(salt);
        wipeBuffer(iv);
        wipeBuffer(ciphertext);
        throw new Error("Decryption failed. Wrong password, tampered header, or corrupted file.");
    }
}

// ─── Legacy V2 (PBKDF2, no AAD) ─────────────────────────────────────

async function decryptLegacyV2(
    view: Uint8Array,
    password: string,
    onProgress?: (p: CryptoProgress) => void
): Promise<ArrayBuffer> {
    const { algorithm, hashAlgorithm } = decodeConfigLegacy(view[1]);
    const saltLen = view[2];
    const ivLen = view[3];
    const iterations = (view[4] << 24) | (view[5] << 16) | (view[6] << 8) | view[7];
    const headerSize = 8;

    if (view.length < headerSize + saltLen + ivLen + 1) throw new Error("⛔ Truncated v2 data");

    const salt = view.slice(headerSize, headerSize + saltLen);
    const iv = view.slice(headerSize + saltLen, headerSize + saltLen + ivLen);
    const ciphertext = view.slice(headerSize + saltLen + ivLen);

    const keyLength = getKeyLengthForAlgorithm(algorithm);

    onProgress?.({ stage: "deriving-key", progress: 10, message: `Deriving key (legacy v2, ${iterations.toLocaleString()} itr)...` });

    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);
    const keyMaterial = await crypto.subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt.buffer as ArrayBuffer, iterations, hash: hashAlgorithm },
        keyMaterial,
        { name: "AES-GCM", length: keyLength },
        false,
        ["decrypt"]
    );
    passwordBytes.fill(0);

    onProgress?.({ stage: "decrypting", progress: 30, message: `Decrypting legacy v2 (${algorithm})...` });

    try {
        const plaintext = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
            key,
            ciphertext.buffer as ArrayBuffer
        );
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext);
        onProgress?.({ stage: "done", progress: 100, message: "Decryption complete (legacy v2)" });
        return plaintext;
    } catch {
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext);
        throw new Error("Decryption failed. Wrong password or corrupted file.");
    }
}

// ─── Legacy V1 ───────────────────────────────────────────────────────

async function decryptLegacyV1(
    view: Uint8Array,
    password: string,
    onProgress?: (p: CryptoProgress) => void
): Promise<ArrayBuffer> {
    const SALT_LEN = 16;
    const IV_LEN = 12;

    if (view.length < 1 + SALT_LEN + IV_LEN + 1) throw new Error("⛔ Truncated v1 data");

    const salt = view.slice(1, 1 + SALT_LEN);
    const iv = view.slice(1 + SALT_LEN, 1 + SALT_LEN + IV_LEN);
    const ciphertext = view.slice(1 + SALT_LEN + IV_LEN);

    onProgress?.({ stage: "deriving-key", progress: 10, message: "Deriving key (legacy v1)..." });

    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);
    const keyMaterial = await crypto.subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt.buffer as ArrayBuffer, iterations: 250000, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
    );
    passwordBytes.fill(0);

    onProgress?.({ stage: "decrypting", progress: 30, message: "Decrypting legacy v1..." });

    try {
        const plaintext = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
            key,
            ciphertext.buffer as ArrayBuffer
        );
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext);
        onProgress?.({ stage: "done", progress: 100, message: "Decryption complete (legacy v1)" });
        return plaintext;
    } catch {
        wipeBuffer(salt); wipeBuffer(iv); wipeBuffer(ciphertext);
        throw new Error("Decryption failed. Wrong password or corrupted file.");
    }
}

// ─── Text Encrypt/Decrypt ────────────────────────────────────────────

export async function encryptText(
    text: string,
    password: string,
    config: CryptoConfig = DEFAULT_CONFIG,
    onProgress?: (p: CryptoProgress) => void
): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const encrypted = await encryptData(data.buffer as ArrayBuffer, password, config, onProgress);
    wipeBuffer(data);
    const bytes = new Uint8Array(encrypted);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const result = btoa(binary);
    wipeBuffer(encrypted);
    return result;
}

export async function decryptText(
    base64: string,
    password: string,
    onProgress?: (p: CryptoProgress) => void
): Promise<string> {
    const binary = atob(base64.trim());
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    const decrypted = await decryptData(bytes.buffer as ArrayBuffer, password, onProgress);
    const decoder = new TextDecoder();
    const text = decoder.decode(decrypted);
    wipeBuffer(bytes);
    wipeBuffer(decrypted);
    return text;
}

// Re-export password strength for pages that import from crypto.ts
export { getPasswordStrength } from "./crypto-config";
