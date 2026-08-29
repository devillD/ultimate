/**
 * Client-side WebRTC IP Leak Patcher.
 * Overrides window.RTCPeerConnection to prevent local/internal IP address leaks
 * via STUN candidate gathering.
 */
export function initWebRTCPatch() {
    if (typeof window === 'undefined' || !window.RTCPeerConnection) return;

    const OriginalRTCPeerConnection = window.RTCPeerConnection;

    function PatchedRTCPeerConnection(configuration, ...args) {
        // Strip host candidate gathering where possible
        if (configuration && configuration.iceCandidatePoolSize) {
            configuration.iceCandidatePoolSize = 0;
        }

        const pc = new OriginalRTCPeerConnection(configuration, ...args);

        // Filter local host candidates from icecandidate events
        const originalAddEventListener = pc.addEventListener.bind(pc);
        pc.addEventListener = function (type, listener, options) {
            if (type === 'icecandidate') {
                const wrappedListener = function (event) {
                    if (event && event.candidate) {
                        const candStr = event.candidate.candidate || '';
                        // 'typ host' exposes local private IPs (e.g. 192.168.x.x, 10.x.x.x)
                        if (candStr.includes('typ host')) {
                            // Suppress local host candidate
                            return;
                        }
                    }
                    return listener.call(this, event);
                };
                return originalAddEventListener(type, wrappedListener, options);
            }
            return originalAddEventListener(type, listener, options);
        };

        return pc;
    }

    PatchedRTCPeerConnection.prototype = OriginalRTCPeerConnection.prototype;
    window.RTCPeerConnection = PatchedRTCPeerConnection;
}
