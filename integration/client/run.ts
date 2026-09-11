// Demo client. Shares hodor's network namespace; hodor's TUN capture takes
// every connection transparently. The client knows nothing about the proxy:
// it just talks to api by hostname. It holds ONLY the fake token; every
// passing scenario proves hodor swapped it for the real one (and redacted
// replies). Hard bounds everywhere: 5s per network await, 20s per scenario,
// 90s for the whole run — the demo never sits silent.
import { connect, type Socket } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { readFile } from "node:fs/promises";

const FAKE = process.env.HODOR_FAKE ?? "";
const CERT_DIR = process.env.CERT_DIR ?? "/certs";
const ATTEMPT_TIMEOUT_MS = 5000;
const SCENARIO_BUDGET_MS = 20000;
const TOTAL_BUDGET_MS = 90000;
const DEADLINE = Date.now() + TOTAL_BUDGET_MS;

if (!FAKE) {
  console.error("HODOR_FAKE not set");
  process.exit(1);
}

function outOfTime() {
  return Date.now() > DEADLINE;
}

function race<T>(what: string, p: Promise<T>): Promise<T> {
  return Promise.race([
    p,
    new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(`${what}: timed out after ${ATTEMPT_TIMEOUT_MS}ms`)), ATTEMPT_TIMEOUT_MS).unref?.();
    }),
  ]);
}

function stage(what: string) {
  process.stderr.write(`[${new Date().toISOString().slice(17, 23)}] ${what}\n`);
}

async function tlsTo(host: string, port: number, ca: Buffer): Promise<TLSSocket> {
  stage(`tls ${host}:${port} connecting`);
  const tls = tlsConnect({ host, port, servername: host, ca, rejectUnauthorized: true });
  await race(`tls ${host}:${port} handshake`, new Promise<void>((resolve, reject) => {
    tls.once("secureConnect", () => resolve());
    tls.once("error", reject);
  }));
  stage(`tls ${host}:${port} handshake ok`);
  return tls;
}

function exchange(sock: Socket | TLSSocket, payload: string): Promise<string> {
  return race("line reply", new Promise<string>((resolve, reject) => {
    let buf = "";
    const onData = (c: Buffer) => {
      buf += c.toString();
      if (buf.includes("\n")) {
        sock.off("data", onData);
        sock.destroy();
        resolve(buf);
      }
    };
    sock.once("error", reject);
    sock.on("data", onData);
    sock.write(payload);
  }));
}

async function readAll(sock: Socket | TLSSocket): Promise<string> {
  return race("http reply", new Promise<string>((resolve, reject) => {
    let buf = "";
    sock.on("data", (c: Buffer) => {
      buf += c.toString();
    });
    sock.once("end", () => resolve(buf));
    sock.once("error", reject);
  }));
}

async function retry(what: string, fn: () => Promise<boolean>) {
  const deadline = Date.now() + SCENARIO_BUDGET_MS;
  let last = "no attempt completed";
  for (let attempt = 1; attempt <= 100; attempt++) {
    if (Date.now() > deadline || outOfTime()) {
      console.error(`FAIL ${what}: ${last}`);
      process.exit(1);
    }
    try {
      stage(`${what} attempt ${attempt}`);
      if (await fn()) {
        console.log(`PASS ${what}`);
        return;
      }
      last = "assertion false";
    } catch (err) {
      last = String(err);
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  console.error(`FAIL ${what}: ${last}`);
  process.exit(1);
}

const ca = await readFile(`${CERT_DIR}/ca.crt`);

// 1. https:// grant, HTTP over MITM TLS: server must see the real bearer;
//    the redacted body comes back carrying the fake.
await retry("https mitm substitutes request and redacts response", async () => {
  const tls = await tlsTo("api", 8443, ca);
  stage("http request sent");
  tls.write(`GET /echo HTTP/1.1\r\nHost: api\r\nAuthorization: Bearer ${FAKE}\r\nConnection: close\r\n\r\n`);
  const resp = await readAll(tls);
  tls.destroy();
  const status = resp.split("\r\n", 1)[0];
  const body = resp.split("\r\n\r\n", 2)[1] ?? "";
  stage(`http reply: ${JSON.stringify({ status, body })}`);
  return status === "HTTP/1.1 200 OK" && body === `token:${FAKE}\n`;
});

// 2. http:// grant, cleartext HTTP through transparent capture: server must
//    see the real bearer; the redacted body comes back carrying the fake.
await retry("http mitm substitutes request and redacts response", async () => {
  stage("http api:8000 connecting");
  const sock = await race("http api:8000 connect", new Promise<Socket>((resolve, reject) => {
    const s = connect(8000, "api");
    s.once("connect", () => resolve(s));
    s.once("error", reject);
  }));
  sock.write(`GET /echo HTTP/1.1\r\nHost: api\r\nAuthorization: Bearer ${FAKE}\r\nConnection: close\r\n\r\n`);
  const resp = await readAll(sock);
  sock.destroy();
  const status = resp.split("\r\n", 1)[0];
  const body = resp.split("\r\n\r\n", 2)[1] ?? "";
  stage(`http reply: ${JSON.stringify({ status, body })}`);
  return status === "HTTP/1.1 200 OK" && body === `token:${FAKE}\n`;
});

// 3. tcp:// grant, cleartext raw stream: opaque substitution both ways.
await retry("tcp raw substitutes both directions", async () => {
  stage("tcp api:9000 connecting");
  const sock = await race("tcp api:9000 connect", new Promise<Socket>((resolve, reject) => {
    const s = connect(9000, "api");
    s.once("connect", () => resolve(s));
    s.once("error", reject);
  }));
  stage("tcp api:9000 connected");
  return (await exchange(sock, `AUTH ${FAKE}\n`)) === `OK ${FAKE}\n`;
});

// 4. https:// grant, non-HTTP payload inside MITM TLS: raw machines on the
//    terminated legs.
await retry("tcp over tls mitm substitutes both directions", async () => {
  const tls = await tlsTo("api", 9443, ca);
  return (await exchange(tls, `AUTH ${FAKE}\n`)) === `OK ${FAKE}\n`;
});

// 5. No grant: hodor never terminates the TLS, the handshake passes through
//    to the api server (its own CA-signed leaf verifies), and the fake
//    arrives untouched, so the server rejects it.
await retry("grantless tls splices untouched", async () => {
  const tls = await tlsTo("api", 9444, ca);
  return (await exchange(tls, `AUTH ${FAKE}\n`)) === `ERR ${FAKE}\n`;
});

console.log("all scenarios passed");
process.exit(0);
