import { spawn } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";

export const EXCHANGE_PATH = "/v1/runner/exchange";
export const RETRY_DELAYS_MS = [1000, 3000, 9000];
export const ENGINE_NAME = "paidwen-engine";
export const MIN_ENGINE_VERSION = "0.1.0-202609301300";
export const PUBLIC_KEY_FILE = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "engine-public-key.pem",
);

const TIMEOUT_MS = 30_000;
const DOWNLOAD_TIMEOUT_MS = 120_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_ENGINE_BYTES = 200 * 1024 * 1024;
const MAX_UNPACKED_BYTES = 1024 * 1024 * 1024;
const MAX_ENTRIES = 20_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);
const SEMVER = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

export class BootstrapError extends Error {
  constructor(message) {
    super(message);
    this.name = "BootstrapError";
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function printable(value) {
  let out = "";
  for (const char of String(value)) {
    const code = char.codePointAt(0) ?? 0;
    out += code < 32 || code === 127 ? "?" : char;
  }
  return out.slice(0, 200);
}

function redact(value, secrets) {
  let out = value;
  for (const secret of secrets) {
    if (secret && secret.length >= 8) out = out.split(secret).join("[redacted]");
  }
  return out;
}

function reason(error) {
  if (!(error instanceof Error)) return String(error);
  if (error.name === "TimeoutError" || error.name === "AbortError") return "timed out";
  return typeof error.cause?.code === "string" ? error.cause.code : error.message;
}

function sentence(text) {
  return /[.!?]$/.test(text) ? text : `${text}.`;
}

export function apiBase(api) {
  let url;
  try {
    url = new URL(String(api));
  } catch {
    throw new BootstrapError("The Paidwen API address is not a URL.");
  }
  const local = url.protocol === "http:" && LOOPBACK.has(url.hostname);
  if (url.protocol !== "https:" && !local) {
    throw new BootstrapError("The Paidwen API address must use https.");
  }
  if (url.username || url.password) {
    throw new BootstrapError("The Paidwen API address must not carry credentials.");
  }
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

export function engineAddress(api, url) {
  const base = new URL(`${apiBase(api)}/`);
  let target;
  try {
    target = new URL(String(url), base);
  } catch {
    throw new BootstrapError("The engine address is not a URL.");
  }
  if (target.origin !== base.origin) {
    throw new BootstrapError("The engine address is not on the Paidwen API. Paidwen refused it.");
  }
  return target.href;
}

export function readOidcToken(file) {
  let content;
  try {
    content = readFileSync(file, "utf8").trim();
  } catch {
    throw new BootstrapError(
      "The OIDC token is missing. The job needs the permission id-token: write.",
    );
  } finally {
    rmSync(file, { force: true });
  }
  let token = content;
  if (content.startsWith("{")) {
    try {
      token = JSON.parse(content).value;
    } catch {
      token = undefined;
    }
  }
  if (typeof token !== "string" || token.length < 20 || /\s/.test(token)) {
    throw new BootstrapError("GitHub did not return an OIDC token.");
  }
  return token;
}

async function readBody(response, limit, what) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > limit) {
    throw new BootstrapError(`${what} answered a body that is too large.`);
  }
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => undefined);
      throw new BootstrapError(`${what} answered a body that is too large.`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

async function request(url, init, options) {
  const { what, limit, secrets = [] } = options;
  const delays = options.retryDelaysMs ?? RETRY_DELAYS_MS;
  let failure;
  for (let attempt = 0; attempt <= delays.length; attempt++) {
    if (attempt > 0) await sleep(delays[attempt - 1] ?? 0);
    try {
      const response = await fetch(url, {
        ...init,
        redirect: "manual",
        signal: AbortSignal.timeout(options.timeoutMs ?? TIMEOUT_MS),
      });
      const body = await readBody(response, limit, what);
      if (response.status >= 500 && attempt < delays.length) {
        failure = new BootstrapError(`${what} answered ${response.status}.`);
        continue;
      }
      return { status: response.status, body };
    } catch (error) {
      if (error instanceof BootstrapError) throw error;
      failure = new BootstrapError(`${what} failed: ${redact(reason(error), secrets)}.`);
    }
  }
  throw failure ?? new BootstrapError(`${what} failed.`);
}

function excerpt(body, secrets) {
  let message = body.toString("utf8");
  try {
    const parsed = JSON.parse(message);
    const value = parsed?.message ?? parsed?.error;
    if (typeof value === "string") message = value;
  } catch {}
  const clean = printable(redact(message.replace(/\s+/g, " ").trim(), secrets));
  return clean ? `: ${clean}` : "";
}

export function checkExchangeResponse(value) {
  const engine = value?.engine;
  const valid =
    typeof value?.token === "string" &&
    value.token.length >= 16 &&
    value.token.length <= 4096 &&
    !/\s/.test(value.token) &&
    typeof value.expiresAt === "string" &&
    typeof engine?.version === "string" &&
    /^[0-9A-Za-z][0-9A-Za-z.+-]{0,39}$/.test(engine.version) &&
    typeof engine.url === "string" &&
    engine.url.length > 0 &&
    typeof engine.sha256 === "string" &&
    /^[0-9a-f]{64}$/i.test(engine.sha256) &&
    typeof engine.signature === "string" &&
    /^[A-Za-z0-9+/]+={0,2}$/.test(engine.signature) &&
    typeof value.plan === "object" &&
    value.plan !== null;
  if (!valid) throw new BootstrapError("The token exchange answered an unexpected body.");
  return value;
}

export async function exchangeToken({ api, verification, oidc, retryDelaysMs, timeoutMs }) {
  if (!UUID.test(String(verification ?? ""))) {
    throw new BootstrapError("The verification input is not a Paidwen verification identifier.");
  }
  const { status, body } = await request(
    `${apiBase(api)}${EXCHANGE_PATH}`,
    {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "user-agent": "paidwen-bootstrap",
      },
      body: JSON.stringify({ verification, oidc }),
    },
    {
      what: "The token exchange",
      limit: MAX_RESPONSE_BYTES,
      secrets: [oidc],
      retryDelaysMs,
      timeoutMs,
    },
  );
  if (status < 200 || status >= 300) {
    throw new BootstrapError(
      sentence(`The token exchange answered ${status}${excerpt(body, [oidc])}`),
    );
  }
  let value;
  try {
    value = JSON.parse(body.toString("utf8"));
  } catch {
    throw new BootstrapError("The token exchange answered without JSON.");
  }
  return checkExchangeResponse(value);
}

export async function downloadEngine({ api, engine, token, retryDelaysMs, timeoutMs }) {
  const { status, body } = await request(
    engineAddress(api, engine.url),
    {
      method: "GET",
      headers: {
        accept: "application/octet-stream",
        authorization: `Bearer ${token}`,
        "user-agent": "paidwen-bootstrap",
      },
    },
    {
      what: "The engine download",
      limit: MAX_ENGINE_BYTES,
      secrets: [token],
      retryDelaysMs,
      timeoutMs: timeoutMs ?? DOWNLOAD_TIMEOUT_MS,
    },
  );
  if (status !== 200) throw new BootstrapError(`The engine download answered ${status}.`);
  return body;
}

export function releaseStatement({ version, sha256, size }) {
  return [
    ENGINE_NAME,
    `version ${version}`,
    `sha256 ${String(sha256).toLowerCase()}`,
    `size ${size}`,
    "",
  ].join("\n");
}

function compareDigits(a, b) {
  const x = a.replace(/^0+(?=\d)/, "");
  const y = b.replace(/^0+(?=\d)/, "");
  if (x.length !== y.length) return x.length < y.length ? -1 : 1;
  return x === y ? 0 : x < y ? -1 : 1;
}

export function compareEngineVersions(a, b) {
  const left = SEMVER.exec(String(a));
  const right = SEMVER.exec(String(b));
  if (!left || !right) return Number.NaN;
  for (let i = 1; i <= 3; i++) {
    const order = compareDigits(left[i] ?? "0", right[i] ?? "0");
    if (order !== 0) return order;
  }
  const x = left[4] ? left[4].split(".") : [];
  const y = right[4] ? right[4].split(".") : [];
  if (x.length === 0 || y.length === 0) {
    return x.length === y.length ? 0 : x.length === 0 ? 1 : -1;
  }
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const p = x[i];
    const q = y[i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    if (p === q) continue;
    const numeric = /^\d+$/.test(p);
    if (numeric && /^\d+$/.test(q)) return compareDigits(p, q);
    if (numeric) return -1;
    if (/^\d+$/.test(q)) return 1;
    return p < q ? -1 : 1;
  }
  return 0;
}

export function checkEngineVersion(version, minimum = MIN_ENGINE_VERSION) {
  const order = compareEngineVersions(version, minimum);
  if (Number.isNaN(order)) {
    throw new BootstrapError(
      `The Paidwen engine version ${printable(version)} cannot be compared with ${printable(minimum)}. Paidwen refused to run it.`,
    );
  }
  if (order < 0) {
    throw new BootstrapError(
      `The Paidwen engine ${printable(version)} is older than ${printable(minimum)}, the oldest engine this action accepts. Paidwen refused to run it.`,
    );
  }
}

export function verifyEngine(bundle, engine, publicKeyPem) {
  const digest = createHash("sha256").update(bundle).digest("hex");
  if (digest !== String(engine.sha256).toLowerCase()) {
    throw new BootstrapError(
      "The Paidwen engine does not match its SHA-256 fingerprint. Paidwen refused to run it.",
    );
  }
  let key;
  try {
    key = createPublicKey(publicKeyPem);
  } catch {
    throw new BootstrapError("The pinned Paidwen public key is unreadable.");
  }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new BootstrapError("The pinned Paidwen public key is not an ed25519 key.");
  }
  const statement = releaseStatement({
    version: String(engine.version),
    sha256: digest,
    size: bundle.length,
  });
  const signature = Buffer.from(String(engine.signature), "base64");
  const valid =
    signature.length === 64 && verify(null, Buffer.from(statement, "utf8"), key, signature);
  if (!valid) {
    throw new BootstrapError(
      "The signature of the Paidwen engine does not match the pinned public key. Paidwen refused to run it.",
    );
  }
  return digest;
}

function field(block, start, length) {
  const slice = block.subarray(start, start + length);
  const end = slice.indexOf(0);
  return slice.subarray(0, end === -1 ? slice.length : end).toString("utf8");
}

function octal(block, start, length) {
  const slice = block.subarray(start, start + length);
  if ((slice[0] ?? 0) & 0x80) {
    throw new BootstrapError("The engine archive uses an unsupported number encoding.");
  }
  const value = slice.toString("latin1").split("\0")[0]?.trim() ?? "";
  if (value === "") return 0;
  if (!/^[0-7]+$/.test(value)) throw new BootstrapError("The engine archive is damaged.");
  return Number.parseInt(value, 8);
}

function checksumMatches(block) {
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : (block[i] ?? 0);
  return sum === octal(block, 148, 8);
}

function paxRecords(data) {
  const records = {};
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space === -1) break;
    const length = Number.parseInt(data.subarray(offset, space).toString("latin1"), 10);
    if (!Number.isInteger(length) || length <= space - offset) {
      throw new BootstrapError("The engine archive is damaged.");
    }
    const record = data.subarray(space + 1, offset + length - 1).toString("utf8");
    const eq = record.indexOf("=");
    if (eq > 0) records[record.slice(0, eq)] = record.slice(eq + 1);
    offset += length;
  }
  return records;
}

export function listTarEntries(tar) {
  const entries = [];
  let offset = 0;
  let next = {};
  while (offset + 512 <= tar.length) {
    const block = tar.subarray(offset, offset + 512);
    if (block.every((byte) => byte === 0)) break;
    if (!checksumMatches(block)) throw new BootstrapError("The engine archive is damaged.");
    const type = block[156] === 0 ? "0" : String.fromCharCode(block[156] ?? 48);
    const meta = type === "x" || type === "g" || type === "L" || type === "K";
    const size = meta ? octal(block, 124, 12) : (next.size ?? octal(block, 124, 12));
    const start = offset + 512;
    if (start + size > tar.length) throw new BootstrapError("The engine archive is truncated.");
    const data = tar.subarray(start, start + size);
    offset = start + Math.ceil(size / 512) * 512;
    if (type === "x") {
      const records = paxRecords(data);
      if (records.path !== undefined) next.name = records.path;
      if (records.linkpath !== undefined) next.link = records.linkpath;
      if (records.size !== undefined) {
        if (!/^\d+$/.test(records.size)) throw new BootstrapError("The engine archive is damaged.");
        next.size = Number(records.size);
      }
      continue;
    }
    if (type === "g") continue;
    if (type === "L" || type === "K") {
      const value = data.toString("utf8").split("\0")[0] ?? "";
      if (type === "L") next.name = value;
      else next.link = value;
      continue;
    }
    const ustar = block.subarray(257, 262).toString("latin1") === "ustar";
    const prefix = ustar ? field(block, 345, 155) : "";
    const base = field(block, 0, 100);
    entries.push({
      name: next.name ?? (prefix ? `${prefix}/${base}` : base),
      type,
      link: next.link ?? field(block, 157, 100),
      size,
    });
    if (entries.length > MAX_ENTRIES) {
      throw new BootstrapError("The engine archive holds too many entries.");
    }
    next = {};
  }
  return entries;
}

const TYPE_NAMES = {
  1: "a hard link",
  2: "a symbolic link",
  3: "a character device",
  4: "a block device",
  6: "a named pipe",
};

export function checkEntries(entries, dest) {
  if (entries.length === 0) throw new BootstrapError("The engine archive is empty.");
  const root = path.resolve(dest);
  for (const entry of entries) {
    const name = entry.name;
    if (entry.type !== "0" && entry.type !== "7" && entry.type !== "5") {
      const kind = TYPE_NAMES[entry.type] ?? `an entry of type ${printable(entry.type)}`;
      throw new BootstrapError(
        `The engine archive holds ${kind} (${printable(name)}). Paidwen refused to run it.`,
      );
    }
    const outside = () =>
      new BootstrapError(
        `The engine archive holds an entry outside its folder (${printable(name)}). Paidwen refused to run it.`,
      );
    if (
      name === "" ||
      name.includes("\\") ||
      name.includes("\0") ||
      name.startsWith("/") ||
      /^[A-Za-z]:/.test(name)
    ) {
      throw outside();
    }
    const segments = name.split("/").filter((segment) => segment !== "" && segment !== ".");
    if (segments.includes("..")) throw outside();
    const target = path.resolve(root, ...segments);
    if (target !== root && !target.startsWith(`${root}${path.sep}`)) throw outside();
  }
}

function runTar(args, input, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn("tar", args, { cwd, stdio: ["pipe", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      reject(new BootstrapError(`tar could not start: ${error.message}.`));
    });
    child.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new BootstrapError(`tar could not extract the engine: ${printable(stderr)}`));
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end(input);
  });
}

export async function extractEngine(bundle, dest) {
  let tar;
  try {
    tar = gunzipSync(bundle, { maxOutputLength: MAX_UNPACKED_BYTES });
  } catch {
    throw new BootstrapError("The engine archive is not a valid gzip file.");
  }
  const entries = listTarEntries(tar);
  checkEntries(entries, dest);
  rmSync(dest, { recursive: true, force: true });
  mkdirSync(dest, { recursive: true });
  await runTar(["-xzf", "-"], bundle, dest);
  if (!existsSync(path.join(dest, "host.mjs"))) {
    throw new BootstrapError("The engine archive has no host.mjs.");
  }
  return entries.length;
}

export function checkEngineManifest(engineDir, version) {
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(path.join(engineDir, "package.json"), "utf8"));
  } catch {
    manifest = undefined;
  }
  if (manifest?.name !== ENGINE_NAME || manifest?.version !== version) {
    throw new BootstrapError(
      `The package.json of the Paidwen engine does not carry the signed version ${printable(version)}. Paidwen refused to run it.`,
    );
  }
}

function writeSecret(file, content) {
  writeFileSync(file, content, { mode: 0o600 });
  chmodSync(file, 0o600);
}

export async function run(options) {
  const print = options.print ?? ((line) => console.log(line));
  const dir = path.resolve(options.dir);
  const oidc = readOidcToken(options.oidcFile);
  if (options.mask) print(`::add-mask::${oidc}`);
  const client = { retryDelaysMs: options.retryDelaysMs, timeoutMs: options.timeoutMs };
  const response = await exchangeToken({
    api: options.api,
    verification: options.verification,
    oidc,
    ...client,
  });
  if (options.mask) print(`::add-mask::${response.token}`);
  checkEngineVersion(response.engine.version, options.minEngineVersion ?? MIN_ENGINE_VERSION);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeSecret(path.join(dir, "exchange.json"), `${JSON.stringify(response, null, 2)}\n`);
  writeSecret(path.join(dir, "token"), response.token);
  const bundle = await downloadEngine({
    api: options.api,
    engine: response.engine,
    token: response.token,
    ...client,
  });
  const digest = verifyEngine(bundle, response.engine, options.publicKeyPem);
  const engineDir = path.join(dir, "engine");
  await extractEngine(bundle, engineDir);
  try {
    checkEngineManifest(engineDir, response.engine.version);
  } catch (error) {
    rmSync(engineDir, { recursive: true, force: true });
    throw error;
  }
  return { response, engineDir, digest };
}

function readPinnedKey() {
  try {
    return readFileSync(PUBLIC_KEY_FILE, "utf8");
  } catch {
    throw new BootstrapError("The pinned Paidwen public key is missing from the action.");
  }
}

function setOutput(name, value) {
  const file = process.env.GITHUB_OUTPUT;
  try {
    if (file) appendFileSync(file, `${name}=${value}\n`);
  } catch {}
}

function describe(error) {
  return error instanceof BootstrapError
    ? error.message
    : `unexpected error: ${error instanceof Error ? error.message : String(error)}`;
}

async function main() {
  const temp = process.env.RUNNER_TEMP;
  if (!temp) {
    console.error("Paidwen: RUNNER_TEMP is not set. This script runs inside GitHub Actions.");
    return 1;
  }
  const dir = path.join(temp, "paidwen");
  const oidcFile = path.join(dir, "oidc.json");
  try {
    const { response, digest } = await run({
      api: process.env.PAIDWEN_API ?? "",
      verification: process.env.PAIDWEN_VERIFICATION ?? "",
      oidcFile,
      dir,
      publicKeyPem: readPinnedKey(),
      mask: process.env.GITHUB_ACTIONS === "true",
    });
    setOutput("engine-version", response.engine.version);
    setOutput("locale", response.plan.locale === "fr" ? "fr" : "en");
    setOutput("ready", "true");
    console.log(
      `Paidwen: engine ${response.engine.version} verified (SHA-256 ${digest.slice(0, 12)}, signed with the pinned key).`,
    );
  } catch (error) {
    setOutput("ready", "false");
    console.error(`Paidwen: ${describe(error)}`);
  } finally {
    rmSync(oidcFile, { force: true });
  }
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      setOutput("ready", "false");
      console.error(`Paidwen: ${describe(error)}`);
      process.exitCode = 0;
    },
  );
}
