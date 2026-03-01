// Hardened service worker — only whitelisted paths cached
const CACHE_NAME = "encryption-v2";
const WHITELISTED_PATHS = [
    "/",
    "/encrypt",
    "/decrypt",
    "/text",
];

// Install: cache only whitelisted shell assets
self.addEventListener("install", (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll(WHITELISTED_PATHS))
    );
    self.skipWaiting();
});

// Activate: clean old caches
self.addEventListener("activate", (event) => {
    event.waitUntil(
        caches.keys().then((keys) =>
            Promise.all(
                keys
                    .filter((key) => key !== CACHE_NAME)
                    .map((key) => caches.delete(key))
            )
        )
    );
    self.clients.claim();
});

// Fetch: cache-first for whitelisted, network-only for everything else
self.addEventListener("fetch", (event) => {
    if (event.request.method !== "GET") return;

    const url = new URL(event.request.url);
    const isWhitelisted = WHITELISTED_PATHS.some((path) => url.pathname === path);

    // Only serve from cache if path is whitelisted
    if (!isWhitelisted) {
        // Do NOT cache non-whitelisted paths — network only
        return;
    }

    event.respondWith(
        caches.match(event.request).then((cached) => {
            if (cached) return cached;

            return fetch(event.request)
                .then((response) => {
                    // Only cache valid basic responses for whitelisted paths
                    if (
                        response.status === 200 &&
                        response.type === "basic"
                    ) {
                        const clone = response.clone();
                        caches.open(CACHE_NAME).then((cache) => {
                            cache.put(event.request, clone);
                        });
                    }
                    return response;
                })
                .catch(() => {
                    if (event.request.mode === "navigate") {
                        return caches.match("/");
                    }
                    return new Response("Offline", { status: 503 });
                });
        })
    );
});
