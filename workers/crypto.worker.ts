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
const CHUNK_SIZE = 64 * 1024 * 1024; // 64 MiB per chunk
const IV_LEN = 12;

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
    backupKeyFlag?: boolean;
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

function encodeConfigByte(backupKeyFlag?: boolean): number {
    return ((backupKeyFlag ? 0x80 : 0) | (0 << 4) | 2); // AES-256-GCM | SHA-512 | backup flag
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
    header[2] = encodeConfigByte(config.backupKeyFlag);
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
            // ─── ENCRYPT FILE (chunked) ──────────────────────────────
            case "encrypt-file": {
                const kdfLabel = config.kdf === "argon2id"
                    ? `Argon2id (${(config.argon2Memory / 1024).toFixed(0)} MiB, ${config.argon2Passes}p)`
                    : `PBKDF2 (${config.iterations.toLocaleString()} itr)`;

                _workerCtx.postMessage({ id, stage: "deriving-key", progress: 5, message: `Deriving key: ${kdfLabel}...` });

                const salt = getRandomBytes(config.saltLength);
                const key = await deriveKey(password, salt, config);
                const header = buildV4Header(config);

                const inputView = new Uint8Array(data);
                const totalBytes = inputView.byteLength;
                const numChunks = Math.max(1, Math.ceil(totalBytes / CHUNK_SIZE));

                _workerCtx.postMessage({ id, stage: "encrypting", progress: 15, message: `Encrypting ${numChunks} chunk(s)...` });

                // Pre-calculate output size: header + salt + chunk_count(4) + chunks
                // Each chunk: IV(12) + ciphertext_len(4) + ciphertext (plaintext + 16 GCM tag)
                const chunkOutputs: { iv: Uint8Array; ct: Uint8Array }[] = [];
                let totalCtBytes = 0;

                for (let i = 0; i < numChunks; i++) {
                    const chunkStart = i * CHUNK_SIZE;
                    const chunkEnd = Math.min(chunkStart + CHUNK_SIZE, totalBytes);
                    const chunkData = inputView.slice(chunkStart, chunkEnd);
                    const chunkIv = getRandomBytes(IV_LEN);

                    // Per-chunk AAD: header || chunk_index(4 bytes BE)
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
                    _workerCtx.postMessage({ id, stage: "encrypting", progress: pct, message: `Encrypted chunk ${i + 1}/${numChunks}` });
                }

                // Assemble: header(10) + salt(N) + chunk_count(4) + chunks
                const blobSize = V4_HEADER_SIZE + config.saltLength + 4 + totalCtBytes;
                const blob = new Uint8Array(blobSize);
                let offset = 0;
                blob.set(header, offset); offset += V4_HEADER_SIZE;
                blob.set(salt, offset); offset += config.saltLength;
                // chunk count (4 bytes BE)
                blob[offset] = (numChunks >> 24) & 0xff;
                blob[offset + 1] = (numChunks >> 16) & 0xff;
                blob[offset + 2] = (numChunks >> 8) & 0xff;
                blob[offset + 3] = numChunks & 0xff;
                offset += 4;

                for (const { iv: cIv, ct } of chunkOutputs) {
                    blob.set(cIv, offset); offset += IV_LEN;
                    // ciphertext length (4 bytes BE)
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

            // ─── ENCRYPT TEXT (chunked format, single chunk) ───────
            case "encrypt-text": {
                const kdfLabel = config.kdf === "argon2id"
                    ? `Argon2id (${(config.argon2Memory / 1024).toFixed(0)} MiB)`
                    : `PBKDF2 (${config.iterations.toLocaleString()} itr)`;

                _workerCtx.postMessage({ id, stage: "deriving-key", progress: 10, message: `Deriving key: ${kdfLabel}...` });

                const encoder = new TextEncoder();
                const textData = encoder.encode(data);
                const salt = getRandomBytes(config.saltLength);
                const chunkIv = getRandomBytes(IV_LEN);
                const key = await deriveKey(password, salt, config);
                const header = buildV4Header(config);

                _workerCtx.postMessage({ id, stage: "encrypting", progress: 50, message: "Encrypting with AES-256-GCM (AAD)..." });

                // Per-chunk AAD: header || chunk_index(0)
                const aad = new Uint8Array(V4_HEADER_SIZE + 4);
                aad.set(header, 0);
                // chunk index 0 = all zeros (already initialized)

                const ct = await crypto.subtle.encrypt(
                    { name: "AES-GCM", iv: chunkIv.buffer as ArrayBuffer, additionalData: aad.buffer as ArrayBuffer },
                    key,
                    textData
                );
                const ctArr = new Uint8Array(ct);

                // Build chunked blob: header + salt + chunk_count(1) + [iv + len + ct]
                const blobSize = V4_HEADER_SIZE + config.saltLength + 4 + IV_LEN + 4 + ctArr.byteLength;
                const blob = new Uint8Array(blobSize);
                let off = 0;
                blob.set(header, off); off += V4_HEADER_SIZE;
                blob.set(salt, off); off += config.saltLength;
                // chunk count = 1
                blob[off] = 0; blob[off + 1] = 0; blob[off + 2] = 0; blob[off + 3] = 1; off += 4;
                // chunk: iv + len + ciphertext
                blob.set(chunkIv, off); off += IV_LEN;
                const ctLen = ctArr.byteLength;
                blob[off] = (ctLen >> 24) & 0xff; blob[off + 1] = (ctLen >> 16) & 0xff;
                blob[off + 2] = (ctLen >> 8) & 0xff; blob[off + 3] = ctLen & 0xff; off += 4;
                blob.set(ctArr, off);

                wipeBuffer(salt);
                wipeBuffer(chunkIv);
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
    const argon2Mem = (header[5] << 24) | (header[6] << 16) | (header[7] << 8) | header[8];
    const argon2Passes = (header[9] >> 4) & 0x0f;
    const argon2Para = header[9] & 0x0f;

    let offset = V4_HEADER_SIZE;
    const salt = view.slice(offset, offset + saltLen); offset += saltLen;

    // Read chunk count (4 bytes BE)
    if (view.length < offset + 4) throw new Error("⛔ Truncated v4 blob — missing chunk count");
    const numChunks = (view[offset] << 24) | (view[offset + 1] << 16) | (view[offset + 2] << 8) | view[offset + 3];
    offset += 4;

    if (numChunks < 1 || numChunks > 100_000) throw new Error("⛔ Invalid chunk count");

    const decConfig: WorkerCryptoConfig = {
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

    const kdfLabel = decConfig.kdf === "argon2id" ? `Argon2id (${(argon2Mem / 1024).toFixed(0)} MiB)` : "PBKDF2";
    _workerCtx.postMessage({ id, stage: "deriving-key", progress: 5, message: `Deriving key: ${kdfLabel}...` });

    const key = await deriveKey(password, salt, decConfig);
    _workerCtx.postMessage({ id, stage: "decrypting", progress: 15, message: `Decrypting ${numChunks} chunk(s)...` });

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

            // Per-chunk AAD: header || chunk_index(4 bytes BE)
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
            _workerCtx.postMessage({ id, stage: "decrypting", progress: pct, message: `Decrypted chunk ${i + 1}/${numChunks}` });
        }

        // Combine plaintext parts
        const combined = new Uint8Array(totalPlaintext);
        let cOffset = 0;
        for (const part of plaintextParts) {
            combined.set(new Uint8Array(part), cOffset);
            cOffset += part.byteLength;
            wipeBuffer(part);
        }

        wipeBuffer(salt); wipeBuffer(originalData);
        _workerCtx.postMessage(
            { id, stage: "done", progress: 100, message: "Decryption complete", result: combined.buffer },
            { transfer: [combined.buffer] }
        );
    } catch (err) {
        wipeBuffer(salt);
        if (err instanceof Error && err.message.startsWith("⛔")) throw err;
        throw new Error("Decryption failed. Wrong password, tampered header, or corrupted file.");
    }
}

async function decryptV4Text(view: Uint8Array, password: string, id: string, bytes: Uint8Array) {
    if (view.length < V4_HEADER_SIZE + 1) throw new Error("⛔ Truncated v4 text");

    const header = view.slice(0, V4_HEADER_SIZE);
    const kdfByte = header[1];
    const saltLen = header[3];
    const argon2Mem = (header[5] << 24) | (header[6] << 16) | (header[7] << 8) | header[8];
    const argon2Passes = (header[9] >> 4) & 0x0f;
    const argon2Para = header[9] & 0x0f;

    let offset = V4_HEADER_SIZE;
    const salt = view.slice(offset, offset + saltLen); offset += saltLen;

    // Read chunk count
    const numChunks = (view[offset] << 24) | (view[offset + 1] << 16) | (view[offset + 2] << 8) | view[offset + 3];
    offset += 4;

    const decConfig: WorkerCryptoConfig = {
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

    const key = await deriveKey(password, salt, decConfig);
    _workerCtx.postMessage({ id, stage: "decrypting", progress: 50, message: "Decrypting AES-256-GCM (AAD-verified)..." });

    const plaintextParts: ArrayBuffer[] = [];
    let totalPlaintext = 0;

    try {
        for (let i = 0; i < numChunks; i++) {
            const chunkIv = view.slice(offset, offset + IV_LEN); offset += IV_LEN;
            const ctLen = (view[offset] << 24) | (view[offset + 1] << 16) | (view[offset + 2] << 8) | view[offset + 3];
            offset += 4;
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
        }

        const combined = new Uint8Array(totalPlaintext);
        let cOffset = 0;
        for (const part of plaintextParts) {
            combined.set(new Uint8Array(part), cOffset);
            cOffset += part.byteLength;
            wipeBuffer(part);
        }

        const decoder = new TextDecoder();
        const text = decoder.decode(combined);
        wipeBuffer(salt); wipeBuffer(bytes); wipeBuffer(combined);
        _workerCtx.postMessage({ id, stage: "done", progress: 100, message: "Decryption complete", result: text });
    } catch {
        wipeBuffer(salt); wipeBuffer(bytes);
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
