import { AddressBar } from './AddressBar.js';
import { initDownloadBlocker } from './DownloadBlocker.js';

/**
 * Controller for the Browser UI Chrome (navigation toolbar, iframe management, loading indicators).
 */
export class BrowserChrome {
    constructor() {
        this.landingView = document.getElementById('landing-view');
        this.chromeView = document.getElementById('chrome-view');
        this.iframe = document.getElementById('proxy-frame');
        this.progressBar = document.getElementById('nav-progress-bar');
        this.loadingSpinner = document.getElementById('loading-spinner');

        // Toolbar Action Buttons
        this.btnBack = document.getElementById('btn-back');
        this.btnForward = document.getElementById('btn-forward');
        this.btnReload = document.getElementById('btn-reload');
        this.btnHome = document.getElementById('btn-home');
        this.btnStop = document.getElementById('btn-stop');

        // Address Bar Components
        this.landingAddressBar = new AddressBar({
            formElement: document.getElementById('landing-form'),
            inputElement: document.getElementById('landing-input'),
            onNavigate: (url) => this.navigate(url),
        });

        this.toolbarAddressBar = new AddressBar({
            formElement: document.getElementById('toolbar-form'),
            inputElement: document.getElementById('toolbar-input'),
            onNavigate: (url) => this.navigate(url),
        });

        this.initEventListeners();
    }

    /**
     * Initializes UI button listeners and iframe load hooks.
     */
    initEventListeners() {
        if (this.btnBack) {
            this.btnBack.addEventListener('click', () => {
                try {
                    if (this.iframe && this.iframe.contentWindow) {
                        this.iframe.contentWindow.history.back();
                    }
                } catch {
                    // Handled safely
                }
            });
        }

        if (this.btnForward) {
            this.btnForward.addEventListener('click', () => {
                try {
                    if (this.iframe && this.iframe.contentWindow) {
                        this.iframe.contentWindow.history.forward();
                    }
                } catch {
                    // Handled safely
                }
            });
        }

        if (this.btnReload) {
            this.btnReload.addEventListener('click', () => {
                this.startLoading();
                try {
                    if (this.iframe && this.iframe.contentWindow) {
                        this.iframe.contentWindow.location.reload();
                    }
                } catch {
                    const currentSrc = this.iframe.src;
                    this.iframe.src = currentSrc;
                }
            });
        }

        if (this.btnStop) {
            this.btnStop.addEventListener('click', () => {
                try {
                    if (this.iframe && this.iframe.contentWindow) {
                        this.iframe.contentWindow.stop();
                    }
                } catch {
                    // Handled safely
                }
                this.finishLoading();
            });
        }

        if (this.btnHome) {
            this.btnHome.addEventListener('click', () => {
                this.showLanding();
            });
        }

        if (this.iframe) {
            this.iframe.addEventListener('load', () => {
                this.handleFrameLoaded();
            });
        }
    }

    /**
     * Starts the animated loading progress bar and spinner.
     */
    startLoading() {
        if (this.progressBar) {
            this.progressBar.style.width = '35%';
            this.progressBar.style.opacity = '1';
        }
        if (this.loadingSpinner) {
            this.loadingSpinner.style.display = 'inline-block';
        }
    }

    /**
     * Completes and fades out the loading progress indicator.
     */
    finishLoading() {
        if (this.progressBar) {
            this.progressBar.style.width = '100%';
            setTimeout(() => {
                this.progressBar.style.opacity = '0';
                setTimeout(() => {
                    this.progressBar.style.width = '0%';
                }, 200);
            }, 300);
        }
        if (this.loadingSpinner) {
            this.loadingSpinner.style.display = 'none';
        }
    }

    /**
     * Navigates the proxy iframe to the target URL using Ultraviolet encoding.
     * @param {string} destinationUrl - Raw target URL (e.g., https://example.com).
     */
    async navigate(destinationUrl) {
        if (!destinationUrl) return;

        this.startLoading();
        this.showChrome();

        // Register Service Worker if needed
        if ('serviceWorker' in navigator) {
            try {
                const reg = await navigator.serviceWorker.register('./sw.js', {
                    scope: __uv$config.prefix,
                });
                if (reg.installing || reg.waiting) {
                    await new Promise((resolve) => {
                        const sw = reg.installing || reg.waiting;
                        sw.addEventListener('statechange', () => {
                            if (sw.state === 'activated') resolve();
                        });
                        setTimeout(resolve, 600);
                    });
                }
            } catch (err) {
                console.warn('[SW Registration]', err);
            }
        }

        const encodedUrl = __uv$config.prefix + __uv$config.encodeUrl(destinationUrl);
        this.toolbarAddressBar.setValue(destinationUrl);
        this.iframe.src = encodedUrl;
    }

    /**
     * Handles the iframe 'load' event, synchronizing the real URL back to the address bar.
     */
    handleFrameLoaded() {
        this.finishLoading();

        try {
            const frameWin = this.iframe.contentWindow;
            if (frameWin) {
                // Ensure presentation API mock exists for YouTube / media frameworks
                if (!frameWin.navigator.presentation) {
                    frameWin.navigator.presentation = { defaultRequest: null, receiver: null };
                }

                const path = frameWin.location.pathname;
                if (path && path.startsWith(__uv$config.prefix)) {
                    const encoded = path.slice(__uv$config.prefix.length);
                    if (encoded) {
                        const decodedUrl = __uv$config.decodeUrl(encoded);
                        this.toolbarAddressBar.setValue(decodedUrl);
                    }
                }

                // Attach download blocker to frame document if accessible
                if (frameWin.document) {
                    initDownloadBlocker(frameWin.document);
                }
            }
        } catch {
            // Handled if restricted by browser security policies
        }
    }

    /**
     * Displays the browser chrome and iframe viewport.
     */
    showChrome() {
        if (this.landingView) this.landingView.style.display = 'none';
        if (this.chromeView) this.chromeView.style.display = 'flex';
    }

    /**
     * Switches back to the clean Landing Page view.
     */
    showLanding() {
        if (this.iframe) this.iframe.src = 'about:blank';
        if (this.chromeView) this.chromeView.style.display = 'none';
        if (this.landingView) this.landingView.style.display = 'flex';
        this.landingAddressBar.setValue('');
    }
}
