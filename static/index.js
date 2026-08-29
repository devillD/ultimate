import { BrowserChrome } from './js/BrowserChrome.js';
import { initWebRTCPatch } from './js/WebRTCPatch.js';
import { initDownloadBlocker } from './js/DownloadBlocker.js';

// 1. Initialize client-side WebRTC IP leak protection
initWebRTCPatch();

// 2. Initialize client-side download neutralizer
initDownloadBlocker(document);

// 3. Initialize Browser UI Chrome & Shared Address Bar
window.addEventListener('DOMContentLoaded', () => {
    window.browserChrome = new BrowserChrome();

    // Register service worker in background
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('./sw.js', {
            scope: __uv$config.prefix,
        }).catch((err) => {
            console.warn('[SW Background Registration]', err);
        });
    }
});
