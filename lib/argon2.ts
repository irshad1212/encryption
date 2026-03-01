// Argon2id WASM wrapper — uses hash-wasm (inline WASM, no external .wasm files)
// Returns raw 32-byte key material for import into WebCrypto

import { argon2id } from "hash-wasm";

export interface Argon2idConfig {
    memorySize: number;   // KiB (e.g. 65536 = 64 MiB)
    passes: number;       // time cost / iterations
    parallelism: number;  // lanes (1 for single-threaded WASM)
}

export const DEFAULT_ARGON2_CONFIG: Argon2idConfig = {
    memorySize: 65536,     // 64 MiB
    passes: 3,
    parallelism: 1,
};

export const ARGON2_MEMORY_PRESETS = [
    { value: 65536, label: "64 MB", description: "Standard (default)" },
    { value: 131072, label: "128 MB", description: "Strong" },
    { value: 262144, label: "256 MB", description: "Maximum, slower" },
];

/**
 * Derive a 32-byte key using Argon2id WASM.
 * Returns raw key bytes suitable for crypto.subtle.importKey("raw", ...).
 */
export async function deriveKeyArgon2id(
    password: string,
    salt: Uint8Array,
    config: Argon2idConfig = DEFAULT_ARGON2_CONFIG
): Promise<Uint8Array> {
    // hash-wasm argon2id returns hex string; we need raw bytes
    const hashHex = await argon2id({
        password,
        salt,
        parallelism: config.parallelism,
        iterations: config.passes,
        memorySize: config.memorySize,
        hashLength: 32, // 256 bits for AES-256
        outputType: "hex",
    });

    // Convert hex to Uint8Array
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        bytes[i] = parseInt(hashHex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}
