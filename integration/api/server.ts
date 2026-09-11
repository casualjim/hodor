// Demo API server. Validates the REAL token only; the client container
// holds just the deterministic fake. Listeners:
//   8443  HTTPS (HTTP semantics)          - MITM path, https:// grant
//   8000  cleartext HTTP                  - MITM path, http:// grant
//   9000  cleartext TCP line protocol     - raw substitution, tcp:// grant
//   9443  TLS line protocol               - MITM + raw substitution, https:// grant
//   9444  TLS line protocol, no grant     - spliced untouched by hodor
const REAL = process.env.HODOR_REAL ?? "";
const CERT_DIR = process.env.CERT_DIR ?? "/certs";
if (!REAL) {
  console.error("HODOR_REAL not set");
  process.exit(1);
}

const tls = { cert: Bun.file(`${CERT_DIR}/api.crt`), key: Bun.file(`${CERT_DIR}/api.key`) };

const fetch = (req: Request) => {
  const auth = req.headers.get("authorization") ?? "";
  console.log(`req ${req.url} auth=${auth.slice(0, 14)}…`);
  if (auth === `Bearer ${REAL}`) {
    return new Response(`token:${REAL}\n`);
  }
  return new Response(`unauthorized:${auth}\n`, { status: 401 });
};

Bun.serve({
  hostname: "0.0.0.0",
  port: 8443,
  tls,
  fetch,
});

// Plain HTTP twin for the http:// grant scenario (transparent capture).
Bun.serve({
  hostname: "0.0.0.0",
  port: 8000,
  fetch,
});

type LineState = { buf: string };
const lineHandlers = {
  data(socket: Bun.Socket<LineState>, chunk: Buffer) {
    socket.data.buf += chunk.toString();
    let nl = socket.data.buf.indexOf("\n");
    while (nl >= 0) {
      const line = socket.data.buf.slice(0, nl);
      socket.data.buf = socket.data.buf.slice(nl + 1);
      const m = /^AUTH (.*)$/.exec(line);
      const token = m?.[1] ?? "";
      console.log(`auth token=${token.slice(0, 14)}…`);
      socket.write(token === REAL ? `OK ${REAL}\n` : `ERR ${token}\n`);
      nl = socket.data.buf.indexOf("\n");
    }
  },
};

Bun.listen<LineState>({ hostname: "0.0.0.0", port: 9000, socket: lineHandlers, data: { buf: "" } });
Bun.listen<LineState>({ hostname: "0.0.0.0", port: 9443, tls, socket: lineHandlers, data: { buf: "" } });
Bun.listen<LineState>({ hostname: "0.0.0.0", port: 9444, tls, socket: lineHandlers, data: { buf: "" } });
console.log("api listening: 8443 https, 8000 http, 9000 tcp, 9443 tls-mitm, 9444 tls-splice");
