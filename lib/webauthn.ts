// WebAuthn second-factor support for encryption hardening
// Uses a hardware credential as additional entropy mixed with the password
// Credential rawId stored in IndexedDB for re-authentication

const DB_NAME = "encryption-webauthn";
const STORE_NAME = "credentials";

export interface StoredCredential {
    id: string;
    rawId: ArrayBuffer;
    name: string;
    createdAt: number;
}

/**
 * Check if WebAuthn is available in this browser
 */
export function isWebAuthnAvailable(): boolean {
    return (
        typeof window !== "undefined" &&
        !!window.PublicKeyCredential &&
        typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function"
    );
}

/**
 * Check if a platform authenticator (fingerprint, face, etc.) is available
 */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
    if (!isWebAuthnAvailable()) return false;
    try {
        return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
        return false;
    }
}

// IndexedDB helpers
function openDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, 1);
        request.onupgradeneeded = () => {
            const db = request.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME, { keyPath: "id" });
            }
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

/**
 * Register a new WebAuthn credential (hardware key / biometric)
 */
export async function registerCredential(
    name: string = "Encryption Key"
): Promise<StoredCredential> {
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    const userId = new Uint8Array(16);
    crypto.getRandomValues(userId);

    const credential = (await navigator.credentials.create({
        publicKey: {
            challenge: challenge.buffer as ArrayBuffer,
            rp: { name: "Encryption App", id: window.location.hostname },
            user: {
                id: userId.buffer as ArrayBuffer,
                name: "encryption-user",
                displayName: "Encryption User",
            },
            pubKeyCredParams: [
                { alg: -7, type: "public-key" },   // ES256
                { alg: -257, type: "public-key" },  // RS256
            ],
            authenticatorSelection: {
                authenticatorAttachment: "platform",
                userVerification: "preferred",
                residentKey: "preferred",
            },
            timeout: 60000,
        },
    })) as PublicKeyCredential | null;

    if (!credential) {
        throw new Error("WebAuthn registration cancelled or failed");
    }

    const rawId = credential.rawId;
    const id = bufferToBase64(rawId);

    const stored: StoredCredential = {
        id,
        rawId,
        name,
        createdAt: Date.now(),
    };

    // Store in IndexedDB
    const db = await openDB();
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).put({
        id: stored.id,
        rawId: Array.from(new Uint8Array(stored.rawId)),
        name: stored.name,
        createdAt: stored.createdAt,
    });
    await new Promise<void>((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
    db.close();

    return stored;
}

/**
 * Authenticate with an existing WebAuthn credential and get the secret
 */
export async function getCredentialSecret(): Promise<Uint8Array> {
    const db = await openDB();
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);

    const allCreds = await new Promise<StoredCredential[]>((resolve, reject) => {
        const request = store.getAll();
        request.onsuccess = () => {
            const results = request.result.map((r: { id: string; rawId: number[]; name: string; createdAt: number }) => ({
                ...r,
                rawId: new Uint8Array(r.rawId).buffer,
            }));
            resolve(results);
        };
        request.onerror = () => reject(request.error);
    });
    db.close();

    if (allCreds.length === 0) {
        throw new Error("No WebAuthn credentials registered. Please register a key first.");
    }

    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    const allowCredentials = allCreds.map((c) => ({
        type: "public-key" as const,
        id: c.rawId,
    }));

    const assertion = (await navigator.credentials.get({
        publicKey: {
            challenge: challenge.buffer as ArrayBuffer,
            allowCredentials,
            userVerification: "preferred",
            timeout: 60000,
        },
    })) as PublicKeyCredential | null;

    if (!assertion) {
        throw new Error("WebAuthn authentication cancelled or failed");
    }

    // Use the authenticatorData as the hardware secret
    const response = assertion.response as AuthenticatorAssertionResponse;
    const authData = new Uint8Array(response.authenticatorData);

    // Hash the authenticator data to get a fixed-length secret
    const secretHash = await crypto.subtle.digest("SHA-256", authData);
    return new Uint8Array(secretHash);
}

/**
 * Combine password + WebAuthn secret using HKDF
 * Returns a merged key material buffer suitable for PBKDF2 input
 */
export async function combineWithPassword(
    password: string,
    webauthnSecret: Uint8Array
): Promise<string> {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);

    // Concatenate password + webauthn secret
    const combined = new Uint8Array(passwordBytes.length + webauthnSecret.length);
    combined.set(passwordBytes, 0);
    combined.set(webauthnSecret, passwordBytes.length);

    // Import as HKDF key material
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        combined,
        "HKDF",
        false,
        ["deriveBits"]
    );

    // Derive 512 bits using HKDF
    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: "HKDF",
            hash: "SHA-512",
            salt: encoder.encode("encryption-app-webauthn-v1"),
            info: encoder.encode("password-hardware-combined"),
        },
        keyMaterial,
        512
    );

    // Convert to hex string as enhanced "password" for PBKDF2
    const bytes = new Uint8Array(derivedBits);
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, "0");
    }

    // Wipe intermediate buffers
    combined.fill(0);
    passwordBytes.fill(0);
    bytes.fill(0);

    return hex;
}

/**
 * List stored WebAuthn credentials
 */
export async function listCredentials(): Promise<StoredCredential[]> {
    try {
        const db = await openDB();
        const tx = db.transaction(STORE_NAME, "readonly");
        const store = tx.objectStore(STORE_NAME);

        const results = await new Promise<StoredCredential[]>((resolve, reject) => {
            const request = store.getAll();
            request.onsuccess = () => {
                resolve(
                    request.result.map((r: { id: string; rawId: number[]; name: string; createdAt: number }) => ({
                        ...r,
                        rawId: new Uint8Array(r.rawId).buffer,
                    }))
                );
            };
            request.onerror = () => reject(request.error);
        });
        db.close();
        return results;
    } catch {
        return [];
    }
}

/**
 * Delete a stored credential
 */
export async function deleteCredential(id: string): Promise<void> {
    const db = await openDB();
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).delete(id);
    await new Promise<void>((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
    db.close();
}

/**
 * Check if any credentials are registered
 */
export async function hasCredentials(): Promise<boolean> {
    const creds = await listCredentials();
    return creds.length > 0;
}

// Utility
function bufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
