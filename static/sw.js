importScripts('./uv/uv.bundle.js');
importScripts('./uv/uv.config.js');
importScripts('./uv/uv.sw.js');

const sw = new UVServiceWorker();
const ASSET_CACHE_NAME = 'uv-static-cache-v1';

// Static asset extensions that can be safely cached locally like a regular browser
const CACHEABLE_EXTENSIONS = /\.(js|mjs|css|woff2?|ttf|eot|otf|svg|png|jpe?g|gif|webp|ico)(\?.*)?$/i;

self.addEventListener('fetch', (event) => {
    const { request } = event;

    // Only cache idempotent GET requests for static media/scripts/stylesheets
    const isCacheableAsset =
        request.method === 'GET' &&
        CACHEABLE_EXTENSIONS.test(request.url) &&
        request.destination !== 'document';

    if (isCacheableAsset) {
        event.respondWith(
            (async () => {
                const cache = await caches.open(ASSET_CACHE_NAME);
                const cachedResponse = await cache.match(request);

                if (cachedResponse) {
                    // Stale-while-revalidate: return cached copy instantly, revalidate in background
                    fetchAndCache(event, cache).catch(() => {});
                    return cachedResponse;
                }

                // If not in cache, fetch via UV and store clone in cache
                return fetchAndCache(event, cache);
            })()
        );
        return;
    }

    // Default: pass directly through Ultraviolet service worker handler
    event.respondWith(sw.fetch(event));
});

async function fetchAndCache(event, cache) {
    const response = await sw.fetch(event);
    if (response && response.status === 200) {
        try {
            await cache.put(event.request, response.clone());
        } catch {
            // Handled safely if response stream is uncloneable
        }
    }
    return response;
}
