// Hardened crypto configuration — security-first defaults
// Argon2id KDF (WASM) + AES-256-GCM + SHA-512
// PBKDF2 retained only for legacy v1-v3 blob decryption

export type KdfType = "argon2id" | "pbkdf2";

export interface CryptoConfig {
    algorithm: "AES-256-GCM";
    kdf: KdfType;
    // Argon2id params (used when kdf === "argon2id")
    argon2Memory: number;   // KiB
    argon2Passes: number;
    argon2Parallelism: number;
    // PBKDF2 params (used when kdf === "pbkdf2" — legacy only)
    iterations: number;
    saltLength: number;
    ivLength: number;
    hashAlgorithm: "SHA-512";
    // Backup key flag (set when a backup key was used as 2nd factor)
    backupKeyFlag?: boolean;
}

// Hardened defaults: Argon2id primary KDF
export const DEFAULT_CONFIG: CryptoConfig = {
    algorithm: "AES-256-GCM",
    kdf: "argon2id",
    argon2Memory: 65536,       // 64 MiB
    argon2Passes: 3,
    argon2Parallelism: 1,
    iterations: 1_000_000,     // fallback for PBKDF2 legacy
    saltLength: 32,
    ivLength: 12,
    hashAlgorithm: "SHA-512",
};

// Argon2id memory presets
export const ARGON2_MEMORY_PRESETS = [
    { value: 65536, label: "64 MB", description: "Standard (default)" },
    { value: 131072, label: "128 MB", description: "Strong" },
    { value: 262144, label: "256 MB", description: "Maximum, slower" },
];

export const ARGON2_PASSES_MIN = 2;
export const ARGON2_PASSES_MAX = 8;

// Legacy PBKDF2 — kept for decrypting v1-v3 blobs only
export const MIN_ITERATIONS = 1_000_000;
export const MAX_ITERATIONS = 4_000_000;

export const ITERATION_PRESETS = [
    { value: 1_000_000, label: "1M", description: "Strong (default)" },
    { value: 1_500_000, label: "1.5M", description: "Very strong" },
    { value: 2_000_000, label: "2M", description: "Maximum, slower" },
    { value: 4_000_000, label: "4M", description: "Paranoid, very slow" },
];

export const SALT_LENGTH_OPTIONS = [
    { value: 32, label: "32 bytes", description: "Maximum (256-bit, default)" },
];

export const IV_LENGTH_OPTIONS = [
    { value: 12, label: "12 bytes", description: "Standard GCM (96-bit)" },
];

export function getKeyLength(): number {
    return 256; // Always AES-256
}

// ─── Hard Password Policy ────────────────────────────────────────────

export const MIN_PASSWORD_LENGTH = 16;
export const MIN_PASSWORD_ENTROPY = 80;

export interface PasswordValidation {
    valid: boolean;
    errors: string[];
    entropy: number;
    strength: { score: number; label: string; color: string };
}

/**
 * Validate a password against the hard security policy.
 * Requires ≥16 chars AND ≥80 bits estimated entropy.
 */
export function validatePassword(password: string): PasswordValidation {
    const errors: string[] = [];
    const entropy = estimatePasswordEntropy(password);
    const strength = getPasswordStrength(password);

    if (password.length < MIN_PASSWORD_LENGTH) {
        errors.push(`Minimum ${MIN_PASSWORD_LENGTH} characters required (currently ${password.length})`);
    }

    if (entropy < MIN_PASSWORD_ENTROPY) {
        errors.push(`Minimum ${MIN_PASSWORD_ENTROPY} bits entropy required (currently ~${entropy} bits). Add more variety.`);
    }

    // Check character diversity
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasDigit = /[0-9]/.test(password);
    const hasSymbol = /[^a-zA-Z0-9]/.test(password);

    if (!hasLower || !hasUpper || !hasDigit) {
        errors.push("Use a mix of uppercase, lowercase, and numbers");
    }

    if (!hasSymbol && password.length < 24) {
        errors.push("Add symbols or use ≥24 characters");
    }

    return {
        valid: errors.length === 0,
        errors,
        entropy,
        strength,
    };
}

/**
 * Estimate entropy of a password based on character pool and length
 */
function estimatePasswordEntropy(password: string): number {
    if (password.length === 0) return 0;

    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;

    if (poolSize === 0) poolSize = 26;

    return Math.floor(password.length * Math.log2(poolSize));
}

/**
 * Password strength meter (0–100)
 */
export function getPasswordStrength(password: string): {
    score: number;
    label: string;
    color: string;
} {
    if (password.length === 0) return { score: 0, label: "Enter a password", color: "bg-muted" };

    let score = 0;
    if (password.length >= 16) score += 20;
    if (password.length >= 20) score += 10;
    if (password.length >= 24) score += 10;
    if (password.length >= 32) score += 10;
    if (/[a-z]/.test(password)) score += 10;
    if (/[A-Z]/.test(password)) score += 10;
    if (/[0-9]/.test(password)) score += 10;
    if (/[^a-zA-Z0-9]/.test(password)) score += 15;

    const entropy = estimatePasswordEntropy(password);
    if (entropy >= 80) score += 5;

    score = Math.min(score, 100);

    if (score < 30) return { score, label: "Weak", color: "bg-destructive" };
    if (score < 50) return { score, label: "Fair", color: "bg-orange-500" };
    if (score < 70) return { score, label: "Good", color: "bg-yellow-500" };
    if (score < 90) return { score, label: "Strong", color: "bg-green-500" };
    return { score, label: "Very Strong", color: "bg-emerald-500" };
}

// ─── Password Generator ──────────────────────────────────────────────

export interface PasswordGenConfig {
    length: number;
    uppercase: boolean;
    lowercase: boolean;
    numbers: boolean;
    symbols: boolean;
    excludeAmbiguous: boolean;
    customSymbols: string;
}

// Generator default enforces ≥80 bits entropy
export const DEFAULT_PASSWORD_CONFIG: PasswordGenConfig = {
    length: 24,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
    excludeAmbiguous: false,
    customSymbols: "!@#$%^&*()-_=+[]{}|;:,.<>?",
};

const CHAR_SETS = {
    uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    uppercaseNoAmbiguous: "ABCDEFGHJKLMNPQRSTUVWXYZ",
    lowercase: "abcdefghijklmnopqrstuvwxyz",
    lowercaseNoAmbiguous: "abcdefghjkmnpqrstuvwxyz",
    numbers: "0123456789",
    numbersNoAmbiguous: "23456789",
};

export function generatePassword(config: PasswordGenConfig): string {
    // Enforce minimum 16 chars for generator
    const length = Math.max(config.length, MIN_PASSWORD_LENGTH);

    let chars = "";
    if (config.uppercase) chars += config.excludeAmbiguous ? CHAR_SETS.uppercaseNoAmbiguous : CHAR_SETS.uppercase;
    if (config.lowercase) chars += config.excludeAmbiguous ? CHAR_SETS.lowercaseNoAmbiguous : CHAR_SETS.lowercase;
    if (config.numbers) chars += config.excludeAmbiguous ? CHAR_SETS.numbersNoAmbiguous : CHAR_SETS.numbers;
    if (config.symbols) chars += config.customSymbols;
    if (chars.length === 0) chars = CHAR_SETS.lowercase + CHAR_SETS.numbers;

    const array = new Uint32Array(length);
    crypto.getRandomValues(array);

    let password = "";
    for (let i = 0; i < length; i++) {
        password += chars[array[i] % chars.length];
    }

    // Ensure at least one char from each enabled set
    const required: string[] = [];
    if (config.uppercase) {
        const set = config.excludeAmbiguous ? CHAR_SETS.uppercaseNoAmbiguous : CHAR_SETS.uppercase;
        const idx = new Uint32Array(1);
        crypto.getRandomValues(idx);
        required.push(set[idx[0] % set.length]);
    }
    if (config.lowercase) {
        const set = config.excludeAmbiguous ? CHAR_SETS.lowercaseNoAmbiguous : CHAR_SETS.lowercase;
        const idx = new Uint32Array(1);
        crypto.getRandomValues(idx);
        required.push(set[idx[0] % set.length]);
    }
    if (config.numbers) {
        const set = config.excludeAmbiguous ? CHAR_SETS.numbersNoAmbiguous : CHAR_SETS.numbers;
        const idx = new Uint32Array(1);
        crypto.getRandomValues(idx);
        required.push(set[idx[0] % set.length]);
    }
    if (config.symbols && config.customSymbols.length > 0) {
        const idx = new Uint32Array(1);
        crypto.getRandomValues(idx);
        required.push(config.customSymbols[idx[0] % config.customSymbols.length]);
    }

    const passwordArr = password.split("");
    const positions = new Uint32Array(required.length);
    crypto.getRandomValues(positions);
    for (let i = 0; i < required.length && i < passwordArr.length; i++) {
        passwordArr[positions[i] % passwordArr.length] = required[i];
    }

    return passwordArr.join("");
}

export function estimateGeneratorEntropy(config: PasswordGenConfig): number {
    let poolSize = 0;
    if (config.uppercase) poolSize += config.excludeAmbiguous ? 24 : 26;
    if (config.lowercase) poolSize += config.excludeAmbiguous ? 24 : 26;
    if (config.numbers) poolSize += config.excludeAmbiguous ? 8 : 10;
    if (config.symbols) poolSize += config.customSymbols.length;
    if (poolSize === 0) poolSize = 36;
    const length = Math.max(config.length, MIN_PASSWORD_LENGTH);
    return Math.floor(length * Math.log2(poolSize));
}

export function getEntropyLabel(bits: number): { label: string; color: string } {
    if (bits < 40) return { label: "Weak", color: "text-red-500" };
    if (bits < 60) return { label: "Fair", color: "text-orange-500" };
    if (bits < 80) return { label: "Below Minimum", color: "text-yellow-500" };
    if (bits < 100) return { label: "Strong", color: "text-green-500" };
    return { label: "Very Strong", color: "text-emerald-500" };
}

export function estimateCrackTime(bits: number): string {
    const guessesPerSec = 1e10;
    const totalGuesses = Math.pow(2, bits);
    const seconds = totalGuesses / guessesPerSec / 2;

    if (seconds < 1) return "Instantly";
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
    if (seconds < 31536000 * 1000) return `${Math.round(seconds / 31536000)} years`;
    if (seconds < 31536000 * 1e6) return `${Math.round(seconds / 31536000 / 1000)}K years`;
    if (seconds < 31536000 * 1e9) return `${Math.round(seconds / 31536000 / 1e6)}M years`;
    return "Heat death of universe+";
}
