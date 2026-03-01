// System Capability Detection — runs entirely in the browser
// No data is stored or transmitted; used for UI display and file size limits only

export interface SystemCapabilities {
    cpuCores: number;
    ramGB: number | null;
    browser: string;
    platform: string;
    webCryptoAvailable: boolean;
    webWorkersAvailable: boolean;
    indexedDBAvailable: boolean;
    readableStreamAvailable: boolean;
}

export type PerformanceTier = "low" | "medium" | "high";

export interface SystemLimits {
    maxFileSizeMB: number;
    maxFileSizeBytes: number;
    tier: PerformanceTier;
    tierLabel: string;
    forceChunkMode: boolean;
}

function parseBrowser(ua: string): string {
    if (ua.includes("Firefox")) return "Firefox";
    if (ua.includes("Edg")) return "Edge";
    if (ua.includes("Chrome")) return "Chrome";
    if (ua.includes("Safari")) return "Safari";
    if (ua.includes("Opera") || ua.includes("OPR")) return "Opera";
    return "Unknown";
}

function parsePlatform(): string {
    if (typeof navigator === "undefined") return "Unknown";
    const ua = navigator.userAgent;
    if (/Android/i.test(ua)) return "Android";
    if (/iPhone|iPad|iPod/i.test(ua)) return "iOS";
    if (/Win/i.test(navigator.platform || "")) return "Windows";
    if (/Mac/i.test(navigator.platform || "")) return "macOS";
    if (/Linux/i.test(navigator.platform || "")) return "Linux";
    return "Unknown";
}

export function getSystemCapabilities(): SystemCapabilities {
    if (typeof window === "undefined") {
        return {
            cpuCores: 1,
            ramGB: null,
            browser: "Unknown",
            platform: "Unknown",
            webCryptoAvailable: false,
            webWorkersAvailable: false,
            indexedDBAvailable: false,
            readableStreamAvailable: false,
        };
    }

    const nav = navigator as Navigator & { deviceMemory?: number };

    return {
        cpuCores: nav.hardwareConcurrency || 1,
        ramGB: nav.deviceMemory ?? null,
        browser: parseBrowser(nav.userAgent),
        platform: parsePlatform(),
        webCryptoAvailable: !!(window.crypto && window.crypto.subtle),
        webWorkersAvailable: typeof Worker !== "undefined",
        indexedDBAvailable: typeof indexedDB !== "undefined",
        readableStreamAvailable: typeof ReadableStream !== "undefined",
    };
}

export function calculateSystemLimits(caps: SystemCapabilities): SystemLimits {
    const { ramGB, cpuCores } = caps;

    // Determine performance tier
    let tier: PerformanceTier;
    if (ramGB !== null && ramGB >= 8 && cpuCores >= 6) {
        tier = "high";
    } else if (ramGB !== null && ramGB <= 2 || cpuCores <= 2) {
        tier = "low";
    } else {
        tier = "medium";
    }

    // Calculate max file size
    let maxFileSizeMB: number;

    if (tier === "low") {
        maxFileSizeMB = 100;
    } else if (tier === "high") {
        maxFileSizeMB = 1024; // 1GB
    } else {
        // Medium: calculate dynamically
        if (ramGB !== null) {
            const usableMemoryBytes = ramGB * 1024 * 1024 * 1024 * 0.25;
            maxFileSizeMB = Math.round((usableMemoryBytes * 0.5) / (1024 * 1024));
        } else {
            maxFileSizeMB = 256; // default for unknown
        }
    }

    // Enforce caps
    maxFileSizeMB = Math.max(25, Math.min(1024, maxFileSizeMB));

    const tierLabels: Record<PerformanceTier, string> = {
        low: "Low",
        medium: "Medium",
        high: "High",
    };

    return {
        maxFileSizeMB,
        maxFileSizeBytes: maxFileSizeMB * 1024 * 1024,
        tier,
        tierLabel: tierLabels[tier],
        forceChunkMode: tier === "low",
    };
}

export function formatFileSize(bytes: number): string {
    if (bytes === 0) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const value = bytes / Math.pow(1024, i);
    return `${value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`;
}
