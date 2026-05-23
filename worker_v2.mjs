const BARE_PREFIX = "/bare/";
const TEMP_META_TTL = 30_000;
const tempMeta = new Map();
const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);
const UNSAFE_REQUEST_HEADERS = new Set([
  "accept-encoding",
  "cf-connecting-ip",
  "cf-ipcountry",
  "cf-ray",
  "cf-visitor",
  "content-length",
  "host",
  "x-forwarded-proto",
  "x-real-ip",
]);

export class BareMetaStore {
  constructor(state) {
    this.state = state;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const now = Date.now();

    if (url.pathname === "/new") {
      const id = randomHex(32);
      await this.state.storage.put(id, { expires: now + TEMP_META_TTL });
      return new Response(id);
    }

    const id = url.searchParams.get("id");
    if (!id) {
      return json(400, {
        code: "MISSING_BARE_HEADER",
        id: "request.headers.x-bare-id",
        message: "Header was not specified",
      });
    }

    const record = await this.state.storage.get(id);
    if (!record || record.expires < now) {
      await this.state.storage.delete(id);
      return json(400, {
        code: "INVALID_BARE_HEADER",
        id: "request.headers.x-bare-id",
        message: "Unregistered ID",
      });
    }

    if (url.pathname === "/set") {
      const meta = await request.json();
      await this.state.storage.put(id, { ...record, meta });
      return new Response(null, { status: 204 });
    }

    if (url.pathname === "/get") {
      await this.state.storage.delete(id);
      return json(200, record.meta ?? null);
    }

    return json(404, { message: "Not found." });
  }
}

function json(status, body, extraHeaders = {}) {
  const payload = JSON.stringify(body, null, "\t");
  return new Response(payload, {
    status,
    headers: {
      "content-type": "application/json",
      ...extraHeaders,
    },
  });
}

function bareHeaders() {
  return {
    "x-robots-tag": "noindex",
    "access-control-allow-headers": "*",
    "access-control-allow-methods": "*",
    "access-control-allow-origin": "*",
    "access-control-expose-headers": "*",
    "access-control-max-age": "86400",
  };
}

function cleanupTempMeta() {
  const now = Date.now();
  for (const [id, record] of tempMeta) {
    if (record.expires < now) tempMeta.delete(id);
  }
}

function metadataStore(env) {
  if (!env.BARE_META) return null;
  return env.BARE_META.get(env.BARE_META.idFromName("global"));
}

function headerObject(headers) {
  const output = Object.create(null);
  for (const [name, value] of headers) output[name] = value;

  if (typeof headers.getSetCookie === "function") {
    const cookies = headers.getSetCookie();
    if (cookies.length) output["set-cookie"] = cookies;
  }

  return output;
}

function loadForwardedHeaders(request, forward, target) {
  if (!Array.isArray(forward)) return;

  for (const header of forward) {
    const value = request.headers.get(header);
    if (value !== null) target[header] = value;
  }
}

function makeHeaders(input) {
  const headers = new Headers();

  for (const [name, value] of Object.entries(input)) {
    if (!isForwardableRequestHeader(name)) continue;

    if (Array.isArray(value)) {
      for (const item of value) headers.append(name, item);
    } else {
      headers.set(name, value);
    }
  }

  headers.set("accept-encoding", "identity");
  return headers;
}

function isForwardableRequestHeader(name) {
  const normalized = name.toLowerCase();

  if (normalized.startsWith(":")) return false;
  if (normalized.startsWith("cf-")) return false;
  if (normalized.startsWith("x-bare-")) return false;

  return !HOP_BY_HOP_HEADERS.has(normalized) && !UNSAFE_REQUEST_HEADERS.has(normalized);
}

function readHeaders(request) {
  const remote = Object.create(null);
  const headers = Object.create(null);

  for (const prop of ["host", "port", "protocol", "path"]) {
    const header = `x-bare-${prop}`;
    const value = request.headers.get(header);

    if (value === null) {
      return {
        error: {
          code: "MISSING_BARE_HEADER",
          id: `request.headers.${header}`,
          message: "Header was not specified.",
        },
      };
    }

    if (prop === "port") {
      const port = Number.parseInt(value, 10);
      if (Number.isNaN(port)) {
        return {
          error: {
            code: "INVALID_BARE_HEADER",
            id: `request.headers.${header}`,
            message: "Header was not a valid integer.",
          },
        };
      }

      remote[prop] = port;
    } else {
      remote[prop] = value;
    }
  }

  const bareHeaderValue = request.headers.get("x-bare-headers");
  if (bareHeaderValue === null) {
    return {
      error: {
        code: "MISSING_BARE_HEADER",
        id: "request.headers.x-bare-headers",
        message: "Header was not specified.",
      },
    };
  }

  try {
    const parsed = JSON.parse(bareHeaderValue);
    for (const [header, value] of Object.entries(parsed)) {
      if (typeof value !== "string" && !Array.isArray(value)) {
        return {
          error: {
            code: "INVALID_BARE_HEADER",
            id: `bare.headers.${header}`,
            message: "Header was not a String or Array.",
          },
        };
      }
    }
    Object.assign(headers, parsed);
  } catch (error) {
    return {
      error: {
        code: "INVALID_BARE_HEADER",
        id: "request.headers.x-bare-headers",
        message: `Header contained invalid JSON. (${error.message})`,
      },
    };
  }

  const forwardHeaderValue = request.headers.get("x-bare-forward-headers");
  if (forwardHeaderValue === null) {
    return {
      error: {
        code: "MISSING_BARE_HEADER",
        id: "request.headers.x-bare-forward-headers",
        message: "Header was not specified.",
      },
    };
  }

  try {
    loadForwardedHeaders(request, JSON.parse(forwardHeaderValue), headers);
  } catch (error) {
    return {
      error: {
        code: "INVALID_BARE_HEADER",
        id: "request.headers.x-bare-forward-headers",
        message: `Header contained invalid JSON. (${error.message})`,
      },
    };
  }

  return { remote, headers };
}

function remoteUrl(remote) {
  if (remote.protocol !== "http:" && remote.protocol !== "https:" && remote.protocol !== "ws:" && remote.protocol !== "wss:") {
    throw new RangeError(`Unsupported protocol: '${remote.protocol}'`);
  }

  const url = new URL(`${remote.protocol}//${remote.host}`);
  if (remote.port) url.port = String(remote.port);
  url.pathname = "/";
  return new URL(remote.path || "/", url).toString();
}

function decodeProtocol(protocol) {
  if (typeof protocol !== "string") throw new TypeError("protocol must be a string");

  let result = "";
  for (let i = 0; i < protocol.length; i += 1) {
    const char = protocol[i];
    if (char === "%") {
      result += String.fromCharCode(Number.parseInt(protocol.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      result += char;
    }
  }
  return result;
}

function randomHex(bytes) {
  const values = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(values, (value) => value.toString(16).padStart(2, "0")).join("");
}

async function handleBareHttp(request) {
  const responseHeaders = bareHeaders();
  const { error, remote, headers } = readHeaders(request);

  if (error) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: responseHeaders });
    }
    return json(400, error, responseHeaders);
  }

  let upstream;
  let target;
  try {
    target = remoteUrl(remote);
    upstream = await fetch(target, {
      method: request.method,
      headers: makeHeaders(headers),
      body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
      redirect: "manual",
    });
  } catch (error) {
    return json(
      500,
      {
        code: "CONNECTION_FAILED",
        id: "request",
        message: error instanceof Error ? error.message : String(error),
        target,
      },
      responseHeaders,
    );
  }

  responseHeaders["x-bare-headers"] = JSON.stringify(headerObject(upstream.headers));
  responseHeaders["x-bare-status"] = String(upstream.status);
  responseHeaders["x-bare-status-text"] = upstream.statusText;

  const encoding = upstream.headers.get("content-encoding") || upstream.headers.get("x-content-encoding");
  if (encoding) responseHeaders["content-encoding"] = encoding;

  return new Response(upstream.body, {
    status: 200,
    headers: responseHeaders,
  });
}

async function handleWsMeta(request, env) {
  const id = request.headers.get("x-bare-id");
  if (id === null) {
    return json(400, {
      code: "MISSING_BARE_HEADER",
      id: "request.headers.x-bare-id",
      message: "Header was not specified",
    });
  }

  const store = metadataStore(env);
  if (store) return store.fetch(`https://bare-meta/get?id=${encodeURIComponent(id)}`);

  const record = tempMeta.get(id);
  if (!record) {
    return json(400, {
      code: "INVALID_BARE_HEADER",
      id: "request.headers.x-bare-id",
      message: "Unregistered ID",
    });
  }

  tempMeta.delete(id);
  return json(200, record.meta ?? null);
}

function handleWsNewMeta(env) {
  const store = metadataStore(env);
  if (store) return store.fetch("https://bare-meta/new");

  cleanupTempMeta();
  const id = randomHex(32);
  tempMeta.set(id, { expires: Date.now() + TEMP_META_TTL });
  return new Response(id);
}

async function handleBareSocket(request, env) {
  if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
    return new Response("Expected Upgrade: websocket", { status: 426 });
  }

  const protocols = request.headers.get("sec-websocket-protocol");
  if (!protocols) return new Response("Missing Sec-WebSocket-Protocol", { status: 400 });

  const [firstProtocol, encodedData] = protocols.split(/,\s*/g);
  if (firstProtocol !== "bare" || !encodedData) return new Response("Invalid Bare websocket protocol", { status: 400 });

  let meta;
  try {
    meta = JSON.parse(decodeProtocol(encodedData));
  } catch (error) {
    return json(400, {
      code: "INVALID_BARE_HEADER",
      id: "request.headers.sec-websocket-protocol",
      message: error instanceof Error ? error.message : String(error),
    });
  }

  const { remote, headers = {}, forward_headers: forwardHeaders, id } = meta;
  loadForwardedHeaders(request, forwardHeaders, headers);

  let target;
  try {
    target = remoteUrl(remote);
  } catch (error) {
    return json(400, {
      code: "INVALID_BARE_HEADER",
      id: "bare.remote",
      message: error instanceof Error ? error.message : String(error),
    });
  }

  if (!target.startsWith("ws://") && !target.startsWith("wss://")) {
    return new Response("Invalid websocket target protocol", { status: 400 });
  }

  let upstreamResponse;
  try {
    upstreamResponse = await fetch(target, {
      headers: makeHeaders(headers),
    });
  } catch (error) {
    return json(502, {
      code: "CONNECTION_FAILED",
      id: "request",
      message: error instanceof Error ? error.message : String(error),
      target,
    });
  }

  const upstream = upstreamResponse.webSocket;
  if (!upstream) return new Response("Remote did not accept websocket", { status: 502 });

  if (id) {
    const meta = {
      headers: headerObject(upstreamResponse.headers),
    };

    const store = metadataStore(env);
    if (store) {
      await store.fetch(`https://bare-meta/set?id=${encodeURIComponent(id)}`, {
        method: "POST",
        body: JSON.stringify(meta),
      });
    } else {
      const record = tempMeta.get(id);
      if (record) record.meta = meta;
    }
  }

  const [client, server] = Object.values(new WebSocketPair());
  server.accept({ allowHalfOpen: true });
  upstream.accept({ allowHalfOpen: true });
  server.binaryType = "arraybuffer";
  upstream.binaryType = "arraybuffer";

  server.addEventListener("message", (event) => {
    if (upstream.readyState === WebSocket.OPEN) upstream.send(event.data);
  });

  upstream.addEventListener("message", (event) => {
    if (server.readyState === WebSocket.OPEN) server.send(event.data);
  });

  server.addEventListener("close", (event) => {
    if (upstream.readyState === WebSocket.OPEN || upstream.readyState === WebSocket.CLOSING) upstream.close(event.code, event.reason);
  });

  upstream.addEventListener("close", (event) => {
    if (server.readyState === WebSocket.OPEN || server.readyState === WebSocket.CLOSING) server.close(event.code, event.reason);
  });

  server.addEventListener("error", () => {
    if (upstream.readyState === WebSocket.OPEN || upstream.readyState === WebSocket.CLOSING) upstream.close(1011, "Proxy error");
  });

  upstream.addEventListener("error", () => {
    if (server.readyState === WebSocket.OPEN || server.readyState === WebSocket.CLOSING) server.close(1011, "Proxy error");
  });

  return new Response(null, {
    status: 101,
    webSocket: client,
    headers: {
      "sec-websocket-protocol": "bare",
    },
  });
}

async function handleBare(request, env) {
  cleanupTempMeta();

  const url = new URL(request.url);
  const service = url.pathname.slice(BARE_PREFIX.length - 1);

  if (service === "/") {
    if (request.method !== "GET") {
      return json(405, { message: "This route only accepts the GET method." });
    }

    return json(200, {
      versions: ["v1"],
      language: "Cloudflare Workers",
      memoryUsage: 0,
      maintainer: undefined,
      developer: {
        name: "TOMPHTTP Worker Bare Server",
        repository: "https://github.com/tomphttp/bare-server-node",
      },
    });
  }

  if (service === "/v1/") {
    if (request.headers.get("upgrade")?.toLowerCase() === "websocket") {
      return handleBareSocket(request, env);
    }
    return handleBareHttp(request);
  }

  if (service === "/v1/ws-meta") return handleWsMeta(request, env);
  if (service === "/v1/ws-new-meta") return handleWsNewMeta(env);

  return json(404, { message: "Not found." });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith(BARE_PREFIX)) return handleBare(request, env);

    if (env.ASSETS) return env.ASSETS.fetch(request);

    return new Response("Static assets binding is not configured.", { status: 500 });
  },
};
