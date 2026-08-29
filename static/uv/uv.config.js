self.__uv$config = {
    prefix: '/-/',
    bare: '/bare/',
    encodeUrl: Ultraviolet.codec.xorb64.encode,
    decodeUrl: Ultraviolet.codec.xorb64.decode,
    handler: '/uv/uv.handler.js',
    bundle: '/uv/uv.bundle.js',
    config: '/uv/uv.config.js',
    sw: '/uv/uv.sw.js',
    construct(ultraviolet) {
        if (ultraviolet && ultraviolet.html) {
            const origWrap = ultraviolet.html.wrapSrcset;
            if (typeof origWrap === 'function') {
                ultraviolet.html.wrapSrcset = function (str, ...args) {
                    if (typeof str !== 'string') return '';
                    return origWrap.call(this, str, ...args);
                };
            }
            const origUnwrap = ultraviolet.html.unwrapSrcset;
            if (typeof origUnwrap === 'function') {
                ultraviolet.html.unwrapSrcset = function (str, ...args) {
                    if (typeof str !== 'string') return '';
                    return origUnwrap.call(this, str, ...args);
                };
            }
        }
    },
};
