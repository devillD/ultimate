/**
 * Client-Side Download Interceptor and Neutralizer.
 * Intercepts <a download> clicks and blob/data save triggers to disable file downloads.
 */
export function initDownloadBlocker(targetDocument = document) {
    if (!targetDocument) return;

    /**
     * Shows a non-intrusive banner notification that downloads are disabled.
     */
    function showDownloadBlockedToast() {
        let toast = document.getElementById('proxy-download-toast');
        if (!toast) {
            toast = document.createElement('div');
            toast.id = 'proxy-download-toast';
            toast.style.position = 'fixed';
            toast.style.bottom = '20px';
            toast.style.right = '20px';
            toast.style.backgroundColor = '#d32f2f';
            toast.style.color = '#ffffff';
            toast.style.padding = '12px 20px';
            toast.style.borderRadius = '8px';
            toast.style.boxShadow = '0 4px 12px rgba(0,0,0,0.4)';
            toast.style.fontFamily = 'system-ui, -apple-system, sans-serif';
            toast.style.fontSize = '14px';
            toast.style.zIndex = '999999';
            toast.style.transition = 'opacity 0.3s ease';
            toast.innerText = 'Downloads are strictly disabled on this proxy instance.';
            document.body.appendChild(toast);
        }

        toast.style.opacity = '1';
        toast.style.display = 'block';

        clearTimeout(toast._timer);
        toast._timer = setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => {
                toast.style.display = 'none';
            }, 300);
        }, 3500);
    }

    // 1. Capture click events on anchor elements with download attribute or blob/data URLs
    targetDocument.addEventListener(
        'click',
        (event) => {
            const anchor = event.target.closest('a');
            if (!anchor) return;

            const hasDownloadAttr = anchor.hasAttribute('download');
            const href = anchor.getAttribute('href') || '';
            const isDataOrBlob = href.startsWith('blob:') || href.startsWith('data:application/octet-stream');

            if (hasDownloadAttr || isDataOrBlob) {
                event.preventDefault();
                event.stopPropagation();
                anchor.removeAttribute('download');
                showDownloadBlockedToast();
            }
        },
        true
    );

    // 2. MutationObserver to strip download attributes as soon as elements are added
    const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
            for (const node of mutation.addedNodes) {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    if (node.tagName === 'A' && node.hasAttribute('download')) {
                        node.removeAttribute('download');
                    }
                    const downloadLinks = node.querySelectorAll ? node.querySelectorAll('a[download]') : [];
                    for (const link of downloadLinks) {
                        link.removeAttribute('download');
                    }
                }
            }
        }
    });

    observer.observe(targetDocument.documentElement || targetDocument.body, {
        childList: true,
        subtree: true,
    });
}
