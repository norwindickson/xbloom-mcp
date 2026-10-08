// xBloom MCP Server
// Self-hosted Deno MCP service for ChatGPT, Codex, and other MCP clients.
// Each client links its own xBloom account through xbloom_login.

import { Buffer } from "node:buffer";
import {
  constants,
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  publicEncrypt,
  randomBytes,
} from "node:crypto";

// --- XBloom API constants ---

const API_BASE = "https://client-api.xbloom.com";
const SHARE_BASE = "https://share-h5.xbloom.com";

const RSA_PUBLIC_KEY_B64 =
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4LF40GZ72SdhMyl765K/i4nY5" +
  "CPcHz2Q1IKWKZ9S79xmK7G8pUhbVf4EZLvnNF1+9IvOFQUKV5Z7ZNNviqSpnql9" +
  "tAT+8+J/He0R7pcirvVSxgdr2i9V/C/gmqAEZ5qVTzRnd3uWdFoKzPdEBxP0Ipor" +
  "J1VBbCv90yBSOhVxO+QIDAQAB";

const pemBody = RSA_PUBLIC_KEY_B64.match(/.{1,64}/g)!.join("\n");
const RSA_PUBLIC_KEY_PEM =
  `-----BEGIN PUBLIC KEY-----\n${pemBody}\n-----END PUBLIC KEY-----`;

const API_HEADERS: Record<string, string> = {
  "Content-Type": "application/json",
  "Referer": `${SHARE_BASE}/`,
  "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
};

// --- AES encryption for stored credentials ---

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
const SUPABASE_REST_URL = Deno.env.get("SUPABASE_REST_URL") || `${SUPABASE_URL}/rest/v1`;
const SUPABASE_SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

function getEncryptionKey(): Buffer {
  const secret = Deno.env.get("SESSION_ENCRYPTION_KEY") || "";
  if (secret.length < 32) {
    throw new Error("SESSION_ENCRYPTION_KEY must be at least 32 bytes");
  }
  return createHash("sha256").update(secret).digest();
}

interface UserCredentials {
  memberId: number;
  token: string;
  email: string;
}

function encryptCredentials(creds: UserCredentials): string {
  const key = getEncryptionKey();
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", key, iv);
  // Deno 2.4 node:crypto omits the full padding block for aligned input.
  // Apply PKCS#7 explicitly, including a full block when already aligned.
  cipher.setAutoPadding(false);
  const plain = Buffer.from(JSON.stringify(creds), "utf-8");
  const padding = 16 - (plain.length % 16);
  const padded = Buffer.concat([plain, Buffer.alloc(padding, padding)]);
  const encrypted = Buffer.concat([
    cipher.update(padded),
    cipher.final(),
  ]);
  return Buffer.concat([iv, encrypted]).toString("base64url");
}

function decryptCredentials(blob: string): UserCredentials | null {
  try {
    const key = getEncryptionKey();
    const combined = Buffer.from(blob, "base64url");
    if (combined.length < 17) return null;
    const iv = combined.subarray(0, 16);
    const encrypted = combined.subarray(16);
    const decipher = createDecipheriv("aes-256-cbc", key, iv);
    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);
    return JSON.parse(decrypted.toString("utf-8"));
  } catch {
    return null;
  }
}

// --- Diagnostics ---
// A fresh id per isolate. Supabase Edge Functions are stateless and may route
// consecutive requests to different isolates, so two back-to-back tool calls can
// legitimately log different INSTANCE_IDs. Because of this, nothing may be trusted
// to survive in module-level memory between invocations — all session state that
// must outlive a single request lives in the user_sessions table below.
const INSTANCE_ID = crypto.randomUUID();

// Short, non-reversible tag so logs can correlate session keys without leaking tokens.
function keyFingerprint(key: string): string {
  if (!key) return "<empty>";
  return createHmac("sha256", "xbloom-log-fp").update(key).digest("hex").slice(
    0,
    8,
  );
}

function log(event: string, fields: Record<string, unknown> = {}): void {
  console.log(JSON.stringify({ instance: INSTANCE_ID, event, ...fields }));
}

// --- DB storage (encrypted, RLS-protected, keyed by MCP session / OAuth token) ---

const SESSION_TTL_SECONDS = 60 * 60 * 24 * 365; // 1 year, matches OAuth expires_in

function expiryTimestamp(): string {
  return new Date(Date.now() + SESSION_TTL_SECONDS * 1000).toISOString();
}

interface SessionRow {
  access_token: string;
  refresh_token?: string | null;
  encrypted_creds?: string | null;
}

const REST_HEADERS: Record<string, string> = {
  "apikey": SUPABASE_SERVICE_KEY,
  "Authorization": `Bearer ${SUPABASE_SERVICE_KEY}`,
};

// Log a PostgREST failure WITHOUT the response body: on constraint violations the
// body's `details` field echoes the conflicting column VALUES verbatim (e.g. the
// full access_token), which would leak live bearer tokens into logs. Keep only the
// structured code/message, which never contain row values.
async function logDbFail(event: string, resp: Response): Promise<void> {
  let code: unknown, message: unknown;
  try {
    const body = JSON.parse(await resp.text());
    code = body?.code;
    message = body?.message;
  } catch { /* non-JSON error body */ }
  log(event, { status: resp.status, code, message });
}

// Idempotent upsert keyed on access_token. `on_conflict=access_token` is REQUIRED:
// PostgREST's merge-duplicates infers the conflict target from the primary key only
// unless this param is given, so without it a table whose access_token is UNIQUE (not
// PK) would 409 instead of upserting. Returns false (never throws) on any failure.
async function upsertSessionRow(row: SessionRow): Promise<boolean> {
  try {
    const resp = await fetch(
      `${SUPABASE_REST_URL}/user_sessions?on_conflict=access_token`,
      {
        method: "POST",
        headers: {
          ...REST_HEADERS,
          "Content-Type": "application/json",
          "Prefer": "resolution=merge-duplicates,return=minimal",
        },
        body: JSON.stringify({
          ...row,
          expires_at: expiryTimestamp(),
          updated_at: new Date().toISOString(),
        }),
      },
    );
    if (!resp.ok) {
      await logDbFail("db.upsert.fail", resp);
      return false;
    }
    return true;
  } catch (e) {
    // Network-level failure (DNS, reset) — must not escape as an unhandled rejection.
    log("db.upsert.fail", { error: String(e) });
    return false;
  }
}

// Called at login: attach the encrypted XBloom creds to the row for this session key.
async function storeSession(
  accessToken: string,
  creds: UserCredentials,
): Promise<boolean> {
  const encrypted = encryptCredentials(creds);
  const ok = await upsertSessionRow({
    access_token: accessToken,
    encrypted_creds: encrypted,
  });
  log("session.store", { key: keyFingerprint(accessToken), ok });
  return ok;
}

// Called at the start of every authed tool handler. Throws on a DB transport error
// so a transient PostgREST outage surfaces as a retryable error, NOT as a bogus
// "you need to log in first" (which would prompt the user to re-enter credentials).
async function getSession(
  accessToken: string,
): Promise<UserCredentials | null> {
  const resp = await fetch(
    `${SUPABASE_REST_URL}/user_sessions?access_token=eq.${
      encodeURIComponent(accessToken)
    }&expires_at=gt.${
      encodeURIComponent(new Date().toISOString())
    }&select=encrypted_creds`,
    { headers: REST_HEADERS },
  );
  if (!resp.ok) throw new Error(`user_sessions lookup failed: ${resp.status}`);
  const rows = await resp.json().catch(() => null);
  const row = Array.isArray(rows) ? rows[0] : null;
  let creds: UserCredentials | null = null;
  if (row?.encrypted_creds) {
    creds = decryptCredentials(row.encrypted_creds);
    // Row exists but the blob won't decrypt; keep this distinct from a missing session.
    if (!creds) {
      log("session.decrypt_failed", { key: keyFingerprint(accessToken) });
    }
  }
  log("session.lookup", {
    key: keyFingerprint(accessToken),
    found: !!creds,
    hasRow: !!row,
  });
  return creds;
}

// Look up a session by its refresh token — used only during OAuth token rotation, so
// creds stored under the old access token survive the switch to a new one. Throws on a
// DB transport error so the caller returns a retryable 5xx rather than silently
// dropping the session; returns null only for a genuine miss.
async function getRowByRefreshToken(
  refreshToken: string,
): Promise<{ encrypted_creds: string | null } | null> {
  if (!refreshToken) return null;
  const resp = await fetch(
    `${SUPABASE_REST_URL}/user_sessions?refresh_token=eq.${
      encodeURIComponent(refreshToken)
    }&expires_at=gt.${
      encodeURIComponent(new Date().toISOString())
    }&select=encrypted_creds`,
    { headers: REST_HEADERS },
  );
  if (!resp.ok) {
    throw new Error(`user_sessions refresh lookup failed: ${resp.status}`);
  }
  const rows = await resp.json().catch(() => null);
  return Array.isArray(rows) && rows.length ? rows[0] : null;
}

// Invalidate a rotated refresh token's row so old access/refresh tokens can't be
// replayed. Best-effort: rotation still succeeds if cleanup fails.
async function deleteSessionByRefreshToken(
  refreshToken: string,
): Promise<void> {
  if (!refreshToken) return;
  try {
    await fetch(
      `${SUPABASE_REST_URL}/user_sessions?refresh_token=eq.${
        encodeURIComponent(refreshToken)
      }`,
      {
        method: "DELETE",
        headers: { ...REST_HEADERS, "Prefer": "return=minimal" },
      },
    );
  } catch { /* best-effort */ }
}

// --- RSA Encryption (hutool-style chunking) ---

function rsaEncrypt(payload: Record<string, unknown>): string {
  const plaintext = Buffer.from(JSON.stringify(payload), "utf-8");
  const chunkSize = 117;
  const chunks: Buffer[] = [];
  for (let i = 0; i < plaintext.length; i += chunkSize) {
    const chunk = plaintext.subarray(i, i + chunkSize);
    const encrypted = publicEncrypt(
      { key: RSA_PUBLIC_KEY_PEM, padding: constants.RSA_PKCS1_PADDING },
      chunk,
    );
    chunks.push(encrypted);
  }
  return Buffer.concat(chunks).toString("base64");
}

// --- HTTP helpers ---

async function postPlain(
  endpoint: string,
  payload: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  try {
    const resp = await fetch(`${API_BASE}/${endpoint}`, {
      method: "POST",
      headers: API_HEADERS,
      body: JSON.stringify(payload),
    });
    return await resp.json();
  } catch (e) {
    return { result: "error", error: String(e) };
  }
}

async function postEncrypted(
  endpoint: string,
  payload: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  try {
    const encrypted = rsaEncrypt(payload);
    const resp = await fetch(`${API_BASE}/${endpoint}`, {
      method: "POST",
      headers: { ...API_HEADERS, "Content-Type": "application/json" },
      body: JSON.stringify(encrypted),
    });
    return await resp.json();
  } catch (e) {
    return { result: "error", error: String(e) };
  }
}

// Turn an XBloom non-success response into a user-facing message. XBloom returns its
// own reason under one of several possible keys — surface that instead of always
// blaming session expiry (a validation reject and an expired token are NOT the same),
// and only suggest re-login when the failure actually looks auth-related. The XBloom
// token is durable in practice, so genuine "log in again" cases are rare; the common
// case is a validation error whose real message the user needs to see.
function xbloomFailure(resp: Record<string, unknown>, action: string): string {
  const detail = [
    resp.msg,
    resp.message,
    resp.errorMsg,
    resp.errorMessage,
    resp.error,
    resp.reason,
    resp.tips,
    resp.info,
  ].find((v) => typeof v === "string" && (v as string).trim()) as
    | string
    | undefined;
  const looksAuth = !detail ||
    /token|login|auth|expire|unauthor|登录|登陆|会话|未登录/i.test(detail);
  const reauth = looksAuth
    ? " If this looks like a session issue, run xbloom_login again."
    : "";
  return detail
    ? `Failed to ${action}: ${detail}.${reauth}`
    : `Failed to ${action}. Your XBloom session may have expired — run xbloom_login again.`;
}

// --- Auth ---

function authBase(creds: UserCredentials): Record<string, unknown> {
  return {
    interfaceVersion: 20240918,
    skey: "testskey",
    phoneType: "Android",
    memberId: creds.memberId,
    clientType: 2,
    languageType: 1,
    token: creds.token,
  };
}

// --- Tool definitions ---

const TOOLS = [
  {
    name: "xbloom_login",
    description:
      "Log in to your XBloom account. Required once before using other tools. Your password is used to authenticate and is never stored.",
    inputSchema: {
      type: "object" as const,
      properties: {
        email: { type: "string", description: "XBloom account email" },
        password: { type: "string", description: "XBloom account password" },
      },
      required: ["email", "password"],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "xbloom_account_profile",
    description:
      "Return the connected XBloom account identity. Use this to distinguish connected accounts.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [] as string[],
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
    _meta: { "openai/profile": true },
  },
  {
    name: "xbloom_list_recipes",
    description:
      "List all recipes on your XBloom account. Returns recipe IDs needed for edit/delete.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [] as string[],
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "xbloom_create_recipe",
    description:
      "Push a new coffee recipe to your XBloom account. Appears in the xBloom iOS app. For tea, use xbloom_create_tea_recipe instead.",
    inputSchema: {
      type: "object" as const,
      properties: {
        name: { type: "string", description: "Recipe name" },
        dose_g: { type: "number", description: "Coffee dose in grams (1-31)" },
        ratio: {
          type: "number",
          description: "Water ratio (total = dose_g * ratio)",
        },
        grind_size: {
          type: "number",
          description: "Grind size 40-120 (lower = finer)",
        },
        grind_rpm: { type: "number", description: "Grinder RPM 60-120" },
        pours: {
          type: "array",
          description: "Pour steps",
          items: {
            type: "object",
            properties: {
              volume_ml: {
                type: "number",
                description:
                  "Water volume for THIS INDIVIDUAL pour step in ml (NOT the total). E.g. for 15g dose at 1:15 ratio (225ml total) split across 4 pours: 45, 65, 60, 55",
              },
              temperature_c: { type: "number" },
              pattern: {
                type: "string",
                enum: ["centered", "circular", "spiral"],
              },
              flow_rate: { type: "number" },
              pause_seconds: { type: "integer" },
              agitate_before: { type: "boolean" },
              agitate_after: { type: "boolean" },
            },
          },
        },
        color: { type: "string", description: "Hex color (default: #C9D5B8)" },
      },
      required: ["name", "dose_g", "ratio", "grind_size", "grind_rpm", "pours"],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "xbloom_create_tea_recipe",
    description:
      "Push a new tea recipe to your XBloom account for the Omni Tea Brewer. Uses tea-specific settings (no grinding, longer steep times, lower doses). Max 3 steeps, max 90ml per steep, max 10g dose, steep up to 360 seconds.",
    inputSchema: {
      type: "object" as const,
      properties: {
        name: { type: "string", description: "Tea recipe name" },
        dose_g: { type: "number", description: "Tea dose in grams (1-10)" },
        ratio: {
          type: "number",
          description: "Water ratio (total = dose_g * ratio)",
        },
        steeps: {
          type: "array",
          description: "Steep steps (max 3)",
          items: {
            type: "object",
            properties: {
              volume_ml: {
                type: "number",
                description: "Water volume per steep (max 90ml)",
              },
              temperature_c: {
                type: "number",
                description:
                  "Water temperature. Green: 70-80, White: 75-85, Oolong: 85-95, Black: 90-100, Herbal: 100",
              },
              steep_seconds: {
                type: "integer",
                description: "Steep time in seconds (0-360)",
              },
              flow_rate: {
                type: "number",
                description: "Water flow rate (default 3.0)",
              },
            },
          },
        },
        color: { type: "string", description: "Hex color (default: #A8C686)" },
      },
      required: ["name", "dose_g", "ratio", "steeps"],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "xbloom_edit_recipe",
    description:
      "Edit an existing recipe by recipe_id. Only pass fields to change. If updating pours, pass the full list.",
    inputSchema: {
      type: "object" as const,
      properties: {
        recipe_id: { type: "integer", description: "Recipe ID from list" },
        name: { type: "string" },
        dose_g: { type: "number" },
        ratio: { type: "number" },
        grind_size: { type: "number" },
        grind_rpm: { type: "number" },
        pours: {
          type: "array",
          items: {
            type: "object",
            properties: {
              volume_ml: { type: "number" },
              temperature_c: { type: "number" },
              pattern: {
                type: "string",
                enum: ["centered", "circular", "spiral"],
              },
              flow_rate: { type: "number" },
              pause_seconds: { type: "integer" },
              agitate_before: { type: "boolean" },
              agitate_after: { type: "boolean" },
            },
          },
        },
        color: { type: "string" },
      },
      required: ["recipe_id"],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "xbloom_delete_recipe",
    description: "Delete a recipe. Cannot be undone.",
    inputSchema: {
      type: "object" as const,
      properties: {
        recipe_id: { type: "integer", description: "Recipe ID from list" },
      },
      required: ["recipe_id"],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "xbloom_fetch_recipe",
    description:
      "Fetch a recipe from a share URL or ID. Does not require login.",
    inputSchema: {
      type: "object" as const,
      properties: {
        share_url: { type: "string", description: "Share URL or encoded ID" },
      },
      required: ["share_url"],
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
  },
];

// --- Tool implementations ---

const PATTERN_MAP: Record<string, number> = {
  centered: 1,
  spiral: 2,
  circular: 3,
};
const PATTERN_REV: Record<number, string> = {
  1: "centered",
  2: "spiral",
  3: "circular",
};

interface Pour {
  volume_ml?: number;
  temperature_c?: number;
  pattern?: string;
  flow_rate?: number;
  pause_seconds?: number;
  agitate_before?: boolean;
  agitate_after?: boolean;
}

function buildPourList(pours: Pour[]) {
  return pours.map((p, i) => ({
    theName: i === 0 ? "Bloom" : `Pour ${i + 1}`,
    volume: Number(p.volume_ml ?? 30),
    temperature: Number(p.temperature_c ?? 93),
    flowRate: Number(p.flow_rate ?? 3.0),
    pattern: PATTERN_MAP[p.pattern ?? "circular"] ?? 2,
    pausing: Number(p.pause_seconds ?? 0),
    isEnableVibrationBefore: p.agitate_before ? 1 : 2,
    isEnableVibrationAfter: p.agitate_after ? 1 : 2,
  }));
}

async function loginXbloom(
  args: Record<string, unknown>,
  accessToken: string,
): Promise<string> {
  const resp = await postPlain("tMemberLogin.thtml", {
    interfaceVersion: 20240918,
    skey: "testskey",
    clientType: 2,
    phoneType: "Android",
    languageType: 1,
    email: args.email as string,
    password: args.password as string,
  });

  if (resp.result === "success") {
    const member = resp.member as Record<string, unknown> | undefined;
    const token = resp.token as string | undefined;
    // Confirm XBloom actually returned the fields we depend on for later requests.
    if (!member || !member.tableId || !token) {
      log("login.capture.fail", {
        key: keyFingerprint(accessToken),
        hasMember: !!member,
        hasToken: !!token,
      });
      return `Login response was missing expected fields (member id / token). Please try again.`;
    }
    const creds: UserCredentials = {
      memberId: member.tableId as number,
      token,
      email: args.email as string,
    };
    const saved = await storeSession(accessToken, creds);
    log("login.success", {
      key: keyFingerprint(accessToken),
      memberId: creds.memberId,
      tokenCaptured: true,
      saved,
    });
    if (!saved) {
      return `Login succeeded but session could not be saved. Please try again.`;
    }
    return `Logged in successfully. Your recipes are now accessible.`;
  }

  log("login.fail", { key: keyFingerprint(accessToken), result: resp.result });
  return `Login failed. Please check your email and password.`;
}

async function listRecipes(creds: UserCredentials): Promise<string> {
  const payload = {
    ...authBase(creds),
    pageNumber: 1,
    countPerPage: 100,
    adaptedModel: 1,
  };
  const resp = await postEncrypted("tuMyTeaRecipeCreated.tuhtml", payload);
  if (resp.result === "success") {
    const recipes = (resp.list as Record<string, unknown>[]) || [];
    if (!recipes.length) return "No recipes found.";
    const lines = [`Found ${recipes.length} recipes:\n`];
    for (const r of recipes) {
      lines.push(
        `  [${r.tableId}] ${r.theName} — ${r.dose}g, 1:${r.grandWater}, grind ${r.grinderSize}, rpm ${r.rpm}`,
      );
      if (r.shareRecipeLink) lines.push(`    Share: ${r.shareRecipeLink}`);
    }
    return lines.join("\n");
  }
  return xbloomFailure(resp, "list recipes");
}

async function createRecipe(
  args: Record<string, unknown>,
  creds: UserCredentials,
): Promise<string> {
  const pourList = buildPourList(args.pours as Pour[]);
  const payload = {
    ...authBase(creds),
    theName: args.name,
    dose: Number(args.dose_g),
    grandWater: Number(args.ratio),
    grinderSize: Number(args.grind_size),
    rpm: Number(args.grind_rpm),
    cupType: 2,
    adaptedModel: 1,
    isEnableBypassWater: 2,
    isSetGrinderSize: 1,
    theColor: (args.color as string) || "#C9D5B8",
    theSubsetId: 0,
    bypassTemp: 85.0,
    bypassVolume: 5.0,
    subSetType: 2,
    appPlace: [4],
    createTimeStamp: Date.now(),
    isShortcuts: 2,
    pourDataJSONStr: JSON.stringify(pourList),
  };
  const resp = await postEncrypted("tuRecipeAdd.tuhtml", payload);
  if (resp.result === "success") {
    const shareId = btoa(String(resp.tableId));
    return `Recipe '${args.name}' created!\nShare: ${SHARE_BASE}/?id=${
      encodeURIComponent(shareId)
    }`;
  }
  return xbloomFailure(resp, "create the recipe");
}

async function createTeaRecipe(
  args: Record<string, unknown>,
  creds: UserCredentials,
): Promise<string> {
  const steeps = ((args.steeps as Array<Record<string, unknown>>) || []).slice(
    0,
    3,
  );
  const pourList = steeps.map((s, i) => ({
    theName: i === 0 ? "Steep 1" : `Steep ${i + 1}`,
    volume: Math.min(Number(s.volume_ml ?? 80), 90),
    temperature: Number(s.temperature_c ?? 85),
    flowRate: Number(s.flow_rate ?? 3.0),
    pattern: 3, // circular
    pausing: Math.min(Number(s.steep_seconds ?? 120), 360),
    isEnableVibrationBefore: 2,
    isEnableVibrationAfter: 2,
  }));
  const payload = {
    ...authBase(creds),
    theName: args.name,
    dose: Math.min(Number(args.dose_g), 10),
    grandWater: Number(args.ratio),
    grinderSize: 50,
    rpm: 60,
    cupType: 4,
    adaptedModel: 1,
    isEnableBypassWater: 2,
    isSetGrinderSize: 2,
    theColor: (args.color as string) || "#A8C686",
    theSubsetId: 0,
    bypassTemp: 85.0,
    bypassVolume: 5.0,
    subSetType: 2,
    appPlace: [4],
    createTimeStamp: Date.now(),
    isShortcuts: 2,
    pourDataJSONStr: JSON.stringify(pourList),
  };
  const resp = await postEncrypted("tuRecipeAdd.tuhtml", payload);
  if (resp.result === "success") {
    const shareId = btoa(String(resp.tableId));
    return `Tea recipe '${args.name}' created!\nShare: ${SHARE_BASE}/?id=${
      encodeURIComponent(shareId)
    }`;
  }
  return xbloomFailure(resp, "create the tea recipe");
}

async function editRecipe(
  args: Record<string, unknown>,
  creds: UserCredentials,
): Promise<string> {
  const recipeId = args.recipe_id as number;
  const listPayload = {
    ...authBase(creds),
    pageNumber: 1,
    countPerPage: 100,
    adaptedModel: 1,
  };
  const listResp = await postEncrypted(
    "tuMyTeaRecipeCreated.tuhtml",
    listPayload,
  );
  let current: Record<string, unknown> | null = null;
  if (listResp.result === "success") {
    for (const r of (listResp.list as Record<string, unknown>[]) || []) {
      if (r.tableId === recipeId) {
        current = r;
        break;
      }
    }
  }
  if (!current) return `Recipe [${recipeId}] not found.`;

  const payload: Record<string, unknown> = {
    ...authBase(creds),
    tableId: recipeId,
    theName: (args.name as string) || current.theName,
    dose: args.dose_g && Number(args.dose_g) > 0
      ? Number(args.dose_g)
      : Number(current.dose),
    grandWater: args.ratio && Number(args.ratio) > 0
      ? Number(args.ratio)
      : Number(current.grandWater),
    grinderSize: args.grind_size && Number(args.grind_size) > 0
      ? Number(args.grind_size)
      : Number(current.grinderSize),
    rpm: args.grind_rpm && Number(args.grind_rpm) > 0
      ? Number(args.grind_rpm)
      : Number(current.rpm),
    theColor: (args.color as string) || current.theColor || "#C9D5B8",
    cupType: current.cupType ?? 2,
    adaptedModel: 1,
    isEnableBypassWater: 2,
    isSetGrinderSize: current.isSetGrinderSize ?? 1,
    theSubsetId: current.theSubsetId ?? 0,
    bypassTemp: current.bypassTemp ?? 85.0,
    bypassVolume: current.bypassVolume ?? 5.0,
    subSetType: 2,
    appPlace: [4],
    isShortcuts: current.isShortcuts ?? 2,
  };

  if (args.pours) {
    payload.pourDataJSONStr = JSON.stringify(
      buildPourList(args.pours as Pour[]),
    );
  } else {
    const existing = (current.pourList as Record<string, unknown>[]) || [];
    payload.pourDataJSONStr = JSON.stringify(existing.map((p) => ({
      theName: p.theName,
      volume: Number(p.volume ?? 30),
      temperature: Number(p.temperature ?? 93),
      flowRate: Number(p.flowRate ?? 3.0),
      pattern: Number(p.pattern ?? 2),
      pausing: Number(p.pausing ?? 0),
      isEnableVibrationBefore: Number(p.isEnableVibrationBefore ?? 2),
      isEnableVibrationAfter: Number(p.isEnableVibrationAfter ?? 2),
    })));
  }

  const resp = await postEncrypted("tuRecipeUpdate.tuhtml", payload);
  if (resp.result === "success") return `Recipe [${recipeId}] updated!`;
  return xbloomFailure(resp, `update recipe [${recipeId}]`);
}

async function deleteRecipe(
  args: Record<string, unknown>,
  creds: UserCredentials,
): Promise<string> {
  const resp = await postEncrypted("tuRecipeDelete.tuhtml", {
    ...authBase(creds),
    tableId: args.recipe_id,
  });
  if (resp.result === "success") return `Recipe [${args.recipe_id}] deleted.`;
  return xbloomFailure(resp, `delete recipe [${args.recipe_id}]`);
}

async function fetchRecipe(args: Record<string, unknown>): Promise<string> {
  let shareId: string | null = args.share_url as string;
  if (shareId.includes("share-h5.xbloom.com")) {
    const url = new URL(shareId);
    shareId = url.searchParams.get("id");
  }
  if (!shareId) return `Could not parse share ID from: ${args.share_url}`;

  const resp = await postPlain("RecipeDetail.html", {
    tableIdOfRSA: shareId,
    interfaceVersion: 19700101,
    skey: "testskey",
  });
  if (resp.result === "success") {
    const rv = resp.recipeVo as Record<string, unknown>;
    const pourList = (rv.pourList as Record<string, unknown>[]) || [];
    return JSON.stringify(
      {
        name: rv.theName ?? "Imported Recipe",
        dose_g: rv.dose ?? 15,
        ratio: rv.grandWater ?? 15,
        grind_size: rv.grinderSize ?? 70,
        grind_rpm: rv.rpm ?? 80,
        cup_type: "omni",
        pours: pourList.map((p) => ({
          volume_ml: p.volume ?? 30,
          temperature_c: p.temperature ?? 93,
          pattern: PATTERN_REV[Number(p.pattern ?? 2)] ?? "circular",
          flow_rate: p.flowRate ?? 3.0,
          pause_seconds: p.pausing ?? 0,
          agitate_before: p.isEnableVibrationBefore === 1,
          agitate_after: p.isEnableVibrationAfter === 1,
        })),
      },
      null,
      2,
    );
  }
  return `Failed to fetch recipe. The share URL may be invalid or the recipe may have been deleted.`;
}

// --- Tool dispatch ---

async function handleToolCall(
  params: Record<string, unknown>,
  accessToken: string,
) {
  const name = params.name as string;
  const args = (params.arguments as Record<string, unknown>) || {};

  // Per-call diagnostics: correlate the isolate + session key across login and the
  // failing call. If login and a later call log different `key` fingerprints, the
  // session key is not stable between requests (the root cause of "log in first").
  log("tool.call", { tool: name, key: keyFingerprint(accessToken) });

  try {
    // Fetch recipe doesn't require auth
    if (name === "xbloom_fetch_recipe") {
      return { content: [{ type: "text", text: await fetchRecipe(args) }] };
    }

    // All other tools require a valid bearer token
    if (!accessToken) {
      log("tool.no_key", { tool: name });
      return {
        content: [{
          type: "text",
          text: "Authentication required. Please reconnect the integration.",
        }],
        isError: true,
      };
    }

    if (name === "xbloom_login") {
      return {
        content: [{ type: "text", text: await loginXbloom(args, accessToken) }],
      };
    }

    // Look up the stored session. If it's missing, briefly retry before giving up: an
    // SSE client can pipeline login+create, so a create may arrive while login's
    // session write is still committing on a concurrent request. Retrying absorbs that
    // race instead of returning "log in first" — which makes agents re-login and loop.
    // (This is NOT XBloom returning 401; a truly expired XBloom token surfaces as a
    // per-tool "session may have expired" message from the tool functions below.)
    let creds = await getSession(accessToken);
    for (let i = 0; i < 6 && !creds; i++) {
      await new Promise((r) => setTimeout(r, 400));
      creds = await getSession(accessToken);
    }
    if (!creds) {
      log("tool.no_session", { tool: name, key: keyFingerprint(accessToken) });
      return {
        content: [{
          type: "text",
          text:
            "You need to log in first. Use xbloom_login with your XBloom email and password.",
        }],
        isError: true,
      };
    }

    if (name === "xbloom_account_profile") {
      return {
        structuredContent: { email: creds.email },
        content: [{
          type: "text",
          text: `Connected XBloom account: ${creds.email}`,
        }],
      };
    }

    let result: string;
    switch (name) {
      case "xbloom_list_recipes":
        result = await listRecipes(creds);
        break;
      case "xbloom_create_recipe":
        result = await createRecipe(args, creds);
        break;
      case "xbloom_create_tea_recipe":
        result = await createTeaRecipe(args, creds);
        break;
      case "xbloom_edit_recipe":
        result = await editRecipe(args, creds);
        break;
      case "xbloom_delete_recipe":
        result = await deleteRecipe(args, creds);
        break;
      default:
        return {
          content: [{ type: "text", text: `Unknown tool: ${name}` }],
          isError: true,
        };
    }
    return { content: [{ type: "text", text: result }] };
  } catch (e) {
    return {
      content: [{ type: "text", text: `Error: ${String(e)}` }],
      isError: true,
    };
  }
}

// --- JSON-RPC helpers ---

function jsonRpcOk(id: unknown, result: unknown) {
  return new Response(JSON.stringify({ jsonrpc: "2.0", id, result }), {
    headers: { "Content-Type": "application/json" },
  });
}

function jsonRpcErr(id: unknown, code: number, message: string) {
  return new Response(
    JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } }),
    {
      headers: { "Content-Type": "application/json" },
    },
  );
}

// --- OAuth 2.0 (auto-approve, unique tokens per user) ---

function generateToken(): string {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

// OAuth token-endpoint response. Cache-Control: no-store is required by RFC 6749
// §5.1 for any response carrying tokens, so intermediaries don't cache the secrets.
function tokenResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}

// --- OAuth durable state (PKCE codes + registered clients) ---
// Stored in the DB, NOT in memory: /register, /authorize and /token are separate
// requests that may each hit a different Edge isolate, so any in-memory store would
// fail intermittently (the same statelessness that broke session storage).

const AUTH_CODE_TTL_SECONDS = 600; // 10 minutes
const DEVICE_CODE_TTL_SECONDS = 600;
const DEVICE_POLL_INTERVAL_SECONDS = 5;

function hashDeviceCode(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function makeUserCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("").match(/.{1,4}/g)!.join("-");
}

async function storeDeviceCode(row: {
  deviceCode: string;
  userCode: string;
  clientId: string;
  scope: string | null;
}): Promise<boolean> {
  try {
    const resp = await fetch(`${SUPABASE_REST_URL}/oauth_device_codes`, {
      method: "POST",
      headers: { ...REST_HEADERS, "Content-Type": "application/json", "Prefer": "return=minimal" },
      body: JSON.stringify({
        device_code_hash: hashDeviceCode(row.deviceCode),
        user_code: row.userCode,
        client_id: row.clientId,
        scope: row.scope,
        status: "pending",
        expires_at: new Date(Date.now() + DEVICE_CODE_TTL_SECONDS * 1000).toISOString(),
        interval_seconds: DEVICE_POLL_INTERVAL_SECONDS,
      }),
    });
    return resp.ok;
  } catch { return false; }
}

async function getDeviceCode(deviceCode: string): Promise<{ status: string; client_id: string; scope: string | null } | null> {
  const resp = await fetch(`${SUPABASE_REST_URL}/oauth_device_codes?device_code_hash=eq.${encodeURIComponent(hashDeviceCode(deviceCode))}&expires_at=gt.${encodeURIComponent(new Date().toISOString())}&select=status,client_id,scope,interval_seconds`, { headers: REST_HEADERS });
  if (!resp.ok) throw new Error("device code lookup failed");
  const rows = await resp.json().catch(() => []);
  return Array.isArray(rows) && rows.length ? rows[0] : null;
}

async function updateDeviceStatus(userCode: string, status: "approved" | "denied"): Promise<boolean> {
  const resp = await fetch(`${SUPABASE_REST_URL}/oauth_device_codes?user_code=eq.${encodeURIComponent(userCode)}&expires_at=gt.${encodeURIComponent(new Date().toISOString())}`, {
    method: "PATCH",
    headers: { ...REST_HEADERS, "Content-Type": "application/json", "Prefer": "return=minimal" },
    body: JSON.stringify({ status }),
  });
  return resp.ok;
}

function deviceHtml(message = ""): Response {
  const safe = message.replace(/[&<>\"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '\"': "&quot;", "'": "&#39;" }[c]!));
  return new Response(`<!doctype html><meta name="viewport" content="width=device-width"><title>xBloom MCP authorization</title><style>body{font:16px system-ui;max-width: thirtyrem;max-width:30rem;margin:4rem auto;padding:0 1rem}input,button{font:inherit;padding:.6rem;margin:.3rem 0}button{cursor:pointer}</style><h1>xBloom MCP</h1><p>An MCP client is requesting access to this server. Enter the code shown in your client.</p>${safe ? `<p>${safe}</p>` : ""}<form method="post"><input name="user_code" autocomplete="one-time-code" placeholder="XXXX-XXXX" required><br><button name="action" value="approve">Approve</button><button name="action" value="deny">Deny</button></form>`, { headers: { "Content-Type": "text/html; charset=utf-8", ...CORS_HEADERS } });
}

async function consumeApprovedDeviceCode(deviceCode: string): Promise<{ client_id: string; scope: string | null } | null> {
  const resp = await fetch(`${SUPABASE_REST_URL}/oauth_device_codes?device_code_hash=eq.${encodeURIComponent(hashDeviceCode(deviceCode))}&status=eq.approved&expires_at=gt.${encodeURIComponent(new Date().toISOString())}`, {
    method: "PATCH",
    headers: { ...REST_HEADERS, "Content-Type": "application/json", "Prefer": "return=representation" },
    body: JSON.stringify({ status: "consumed" }),
  });
  if (!resp.ok) throw new Error("device code consume failed");
  const rows = await resp.json().catch(() => []);
  return Array.isArray(rows) && rows.length ? rows[0] : null;
}

function isLoopback(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "[::1]";
}

// Persist a dynamically-registered client's redirect URIs so /authorize can validate
// against them (exact match, per the MCP spec's open-redirect requirement).
async function storeClient(
  clientId: string,
  redirectUris: string[],
): Promise<void> {
  try {
    await fetch(`${SUPABASE_REST_URL}/oauth_clients?on_conflict=client_id`, {
      method: "POST",
      headers: {
        ...REST_HEADERS,
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates,return=minimal",
      },
      body: JSON.stringify({
        client_id: clientId,
        redirect_uris: redirectUris,
      }),
    });
  } catch {
    /* best-effort; /authorize falls back to the https/loopback baseline */
  }
}

async function getClientRedirectUris(
  clientId: string,
): Promise<string[] | null> {
  if (!clientId) return null;
  try {
    const resp = await fetch(
      `${SUPABASE_REST_URL}/oauth_clients?client_id=eq.${
        encodeURIComponent(clientId)
      }&select=redirect_uris`,
      { headers: REST_HEADERS },
    );
    if (!resp.ok) return null;
    const rows = await resp.json().catch(() => null);
    const uris = Array.isArray(rows) && rows.length
      ? rows[0].redirect_uris
      : null;
    return Array.isArray(uris) ? uris : null;
  } catch {
    return null;
  }
}

// redirect_uri policy: exact-match a registered URI when the client is known; otherwise
// fall back to the spec baseline (HTTPS, or http on loopback) so a client that
// registered before this feature shipped isn't locked out, while arbitrary http
// phishing targets are still rejected.
function redirectAllowed(
  redirectUri: string,
  registered: string[] | null,
): boolean {
  if (registered && registered.length) return registered.includes(redirectUri);
  let u: URL;
  try {
    u = new URL(redirectUri);
  } catch {
    return false;
  }
  if (u.protocol === "https:") return true;
  if (u.protocol === "http:" && isLoopback(u.hostname)) return true;
  return false;
}

async function storeAuthCode(row: {
  code: string;
  code_challenge: string | null;
  code_challenge_method: string | null;
  redirect_uri: string;
  client_id: string | null;
}): Promise<boolean> {
  try {
    const resp = await fetch(`${SUPABASE_REST_URL}/oauth_codes`, {
      method: "POST",
      headers: {
        ...REST_HEADERS,
        "Content-Type": "application/json",
        "Prefer": "return=minimal",
      },
      body: JSON.stringify({
        ...row,
        expires_at: new Date(Date.now() + AUTH_CODE_TTL_SECONDS * 1000)
          .toISOString(),
      }),
    });
    if (!resp.ok) await logDbFail("oauth.code.store.fail", resp);
    return resp.ok;
  } catch (e) {
    log("oauth.code.store.fail", { error: String(e) });
    return false;
  }
}

// Atomically fetch-and-delete a non-expired code (one-time use). Throws on a DB
// transport error; returns null for a genuinely absent/expired code.
async function consumeAuthCode(code: string): Promise<
  {
    code_challenge: string | null;
    code_challenge_method: string | null;
    redirect_uri: string;
  } | null
> {
  if (!code) return null;
  const resp = await fetch(
    `${SUPABASE_REST_URL}/oauth_codes?code=eq.${
      encodeURIComponent(code)
    }&expires_at=gt.${
      encodeURIComponent(new Date().toISOString())
    }&select=code_challenge,code_challenge_method,redirect_uri`,
    {
      method: "DELETE",
      headers: {
        ...REST_HEADERS,
        "Prefer": "return=representation",
        "Accept": "application/json",
      },
    },
  );
  if (!resp.ok) throw new Error(`oauth_codes consume failed: ${resp.status}`);
  const rows = await resp.json().catch(() => null);
  return Array.isArray(rows) && rows.length ? rows[0] : null;
}

// PKCE verification (RFC 7636). Consume-then-verify order means a failed check still
// burns the code, so a code can't be brute-forced against.
function verifyPkce(
  challenge: string | null,
  method: string | null,
  verifier: string,
): boolean {
  if (!challenge) return true; // no challenge was registered → nothing to verify
  if (!verifier) return false;
  if (method === "S256") {
    return Buffer.from(createHash("sha256").update(verifier).digest()).toString(
      "base64url",
    ) === challenge;
  }
  return verifier === challenge; // "plain"
}

async function handleDeviceAuthorization(req: Request): Promise<Response> {
  const contentType = req.headers.get("content-type") || "";
  const params = contentType.includes("application/json")
    ? new URLSearchParams(await req.json() as Record<string, string>)
    : new URLSearchParams(await req.text());
  const clientId = params.get("client_id") || "";
  if (!clientId) return tokenResponse({ error: "invalid_request" }, 400);
  const deviceCode = generateToken();
  const userCode = makeUserCode();
  if (!(await storeDeviceCode({ deviceCode, userCode, clientId, scope: params.get("scope") }))) return tokenResponse({ error: "temporarily_unavailable" }, 503);
  return tokenResponse({ device_code: deviceCode, user_code: userCode, verification_uri: `${BASE_URL}/device`, verification_uri_complete: `${BASE_URL}/device?user_code=${encodeURIComponent(userCode)}`, expires_in: DEVICE_CODE_TTL_SECONDS, interval: DEVICE_POLL_INTERVAL_SECONDS });
}

async function handleDevicePage(req: Request, url: URL): Promise<Response> {
  if (req.method === "GET") {
    const code = url.searchParams.get("user_code") || "";
    return deviceHtml(code ? `Code prefilled: ${code}` : "");
  }
  const body = new URLSearchParams(await req.text());
  const userCode = (body.get("user_code") || "").trim().toUpperCase();
  const action = body.get("action");
  if (!/^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(userCode)) return deviceHtml("Invalid code.");
  if (action !== "approve" && action !== "deny") return deviceHtml("Choose Approve or Deny.");
  const ok = await updateDeviceStatus(userCode, action === "approve" ? "approved" : "denied");
  return ok ? deviceHtml(action === "approve" ? "Approved. Return to your MCP client." : "Denied.") : deviceHtml("Code expired or not found.");
}

async function handleAuthorize(url: URL): Promise<Response> {
  const redirectUri = url.searchParams.get("redirect_uri");
  const state = url.searchParams.get("state");
  const clientId = url.searchParams.get("client_id") || "";
  const codeChallenge = url.searchParams.get("code_challenge");
  const codeChallengeMethod = url.searchParams.get("code_challenge_method") ||
    "plain";

  if (!redirectUri) {
    return new Response("Missing redirect_uri", { status: 400 });
  }

  // Open-redirect protection: only bounce the browser to a redirect_uri the client
  // registered (exact match), or an HTTPS/loopback URI for pre-registration clients.
  const registered = await getClientRedirectUris(clientId);
  if (!redirectAllowed(redirectUri, registered)) {
    log("oauth.authorize.bad_redirect", { client: keyFingerprint(clientId) });
    return new Response("Invalid redirect_uri", { status: 400 });
  }

  // Require PKCE (MCP clients MUST use it) — never issue a code redeemable without proof.
  if (!codeChallenge) {
    log("oauth.authorize.no_pkce", { client: keyFingerprint(clientId) });
    return new Response("code_challenge required (PKCE)", { status: 400 });
  }

  let redirect: URL;
  try {
    redirect = new URL(redirectUri);
  } catch {
    return new Response("Invalid redirect_uri", { status: 400 });
  }

  const code = generateToken();
  if (
    !(await storeAuthCode({
      code,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      redirect_uri: redirectUri,
      client_id: clientId || null,
    }))
  ) {
    return new Response("Authorization temporarily unavailable, please retry", {
      status: 503,
    });
  }

  log("oauth.authorize", {
    client: keyFingerprint(clientId),
    method: codeChallengeMethod,
  });
  redirect.searchParams.set("code", code);
  if (state) redirect.searchParams.set("state", state);
  return Response.redirect(redirect.toString(), 302);
}

async function handleToken(req: Request): Promise<Response> {
  const contentType = req.headers.get("content-type") || "";
  let params: URLSearchParams;
  if (contentType.includes("application/json")) {
    params = new URLSearchParams(await req.json() as Record<string, string>);
  } else {
    params = new URLSearchParams(await req.text());
  }

  const grantType = params.get("grant_type");
  const dbUnavailable = () =>
    tokenResponse({
      error: "temporarily_unavailable",
      error_description: "Session store unavailable, please retry.",
    }, 503);

  if (grantType === "authorization_code") {
    // Validate the authorization code (one-time use) and PKCE before issuing anything.
    const code = params.get("code") || "";
    const codeVerifier = params.get("code_verifier") || "";
    const redirectUri = params.get("redirect_uri") || "";
    let codeRow;
    try {
      codeRow = await consumeAuthCode(code);
    } catch {
      return dbUnavailable();
    }
    if (!codeRow) {
      log("oauth.code.invalid", {});
      return tokenResponse({
        error: "invalid_grant",
        error_description: "Invalid or expired authorization code.",
      }, 400);
    }
    if (
      codeRow.redirect_uri && redirectUri &&
      codeRow.redirect_uri !== redirectUri
    ) {
      return tokenResponse({
        error: "invalid_grant",
        error_description: "redirect_uri mismatch.",
      }, 400);
    }
    if (
      !verifyPkce(
        codeRow.code_challenge,
        codeRow.code_challenge_method,
        codeVerifier,
      )
    ) {
      log("oauth.pkce.fail", {});
      return tokenResponse({
        error: "invalid_grant",
        error_description: "PKCE verification failed.",
      }, 400);
    }

    const accessToken = generateToken();
    const refreshToken = generateToken();
    // Pre-create the session row linking access_token <-> refresh_token. The XBloom
    // creds aren't attached until xbloom_login, but recording the pair now means a
    // later refresh_token exchange can find this session by its refresh_token. If the
    // write fails, do NOT issue tokens — a token with no backing row would silently
    // lose the refresh linkage and log the user out at the next rotation.
    if (
      !(await upsertSessionRow({
        access_token: accessToken,
        refresh_token: refreshToken,
      }))
    ) {
      return dbUnavailable();
    }
    log("oauth.issue", {
      grant: "authorization_code",
      access: keyFingerprint(accessToken),
      refresh: keyFingerprint(refreshToken),
    });
    return tokenResponse({
      access_token: accessToken,
      token_type: "bearer",
      expires_in: SESSION_TTL_SECONDS,
      refresh_token: refreshToken,
    });
  }

  if (grantType === "urn:ietf:params:oauth:grant-type:device_code") {
    const deviceCode = params.get("device_code") || "";
    if (!deviceCode) return tokenResponse({ error: "invalid_request" }, 400);
    let row;
    try { row = await getDeviceCode(deviceCode); } catch { return dbUnavailable(); }
    if (!row) return tokenResponse({ error: "expired_token" }, 400);
    if (row.status === "pending") return tokenResponse({ error: "authorization_pending" }, 400);
    if (row.status === "denied") return tokenResponse({ error: "access_denied" }, 400);
    if (row.status !== "approved") return tokenResponse({ error: "expired_token" }, 400);
    let consumed;
    try { consumed = await consumeApprovedDeviceCode(deviceCode); } catch { return dbUnavailable(); }
    if (!consumed) return tokenResponse({ error: "expired_token" }, 400);
    const accessToken = generateToken();
    const refreshToken = generateToken();
    if (!(await upsertSessionRow({ access_token: accessToken, refresh_token: refreshToken }))) return dbUnavailable();
    log("oauth.issue", { grant: "device_code", access: keyFingerprint(accessToken), refresh: keyFingerprint(refreshToken) });
    return tokenResponse({ access_token: accessToken, token_type: "bearer", expires_in: SESSION_TTL_SECONDS, refresh_token: refreshToken, scope: consumed.scope || undefined });
  }

  if (grantType === "refresh_token") {
    const oldRefreshToken = params.get("refresh_token") || "";

    // Look up the session by its REFRESH token. Distinguish a genuine miss (unknown/
    // expired token → invalid_grant per RFC 6749 §5.2, so the client re-runs the auth
    // flow) from a transient DB error (getRowByRefreshToken throws → 503, retryable).
    // Silently rotating on a miss would strand the stored creds and log the user out.
    let oldRow: { encrypted_creds: string | null } | null;
    try {
      oldRow = await getRowByRefreshToken(oldRefreshToken);
    } catch {
      return dbUnavailable();
    }
    if (!oldRow) {
      log("oauth.refresh.miss", {
        oldRefresh: keyFingerprint(oldRefreshToken),
      });
      return tokenResponse({
        error: "invalid_grant",
        error_description: "Unknown or expired refresh token.",
      }, 400);
    }

    const newAccessToken = generateToken();
    const newRefreshToken = generateToken();
    // Carry the encrypted creds forward. Omit the field entirely when absent rather
    // than writing an explicit null, to avoid ever clobbering creds on a merge.
    if (
      !(await upsertSessionRow({
        access_token: newAccessToken,
        refresh_token: newRefreshToken,
        ...(oldRow.encrypted_creds
          ? { encrypted_creds: oldRow.encrypted_creds }
          : {}),
      }))
    ) {
      return dbUnavailable();
    }
    // Invalidate the old row so the rotated-away tokens can't be replayed.
    await deleteSessionByRefreshToken(oldRefreshToken);
    log("oauth.refresh", {
      oldRefresh: keyFingerprint(oldRefreshToken),
      newAccess: keyFingerprint(newAccessToken),
      migratedCreds: !!oldRow.encrypted_creds,
    });

    return tokenResponse({
      access_token: newAccessToken,
      token_type: "bearer",
      expires_in: SESSION_TTL_SECONDS,
      refresh_token: newRefreshToken,
    });
  }

  return tokenResponse({ error: "unsupported_grant_type" }, 400);
}

// --- Main handler ---

// Set this to the public URL of this Edge Function. It is used in OAuth discovery
// and SSE endpoint events, so a hard-coded upstream deployment URL is unsafe here.
const BASE_URL = (Deno.env.get("XBLOOM_MCP_BASE_URL") ||
  "http://127.0.0.1:54321/functions/v1/xbloom-mcp").replace(/\/$/, "");

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, Mcp-Session-Id",
};

function jsonResponse(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

function getSessionKey(req: Request): string {
  // Only an OAuth bearer token may identify an account session.
  const auth = req.headers.get("authorization") || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  return "";
}

async function validAccessToken(token: string): Promise<boolean> {
  if (!token) return false;
  const resp = await fetch(
    `${SUPABASE_REST_URL}/user_sessions?access_token=eq.${encodeURIComponent(token)}&expires_at=gt.${encodeURIComponent(new Date().toISOString())}&select=access_token&limit=1`,
    { headers: REST_HEADERS },
  );
  if (!resp.ok) throw new Error(`OAuth token lookup failed: ${resp.status}`);
  const rows = await resp.json();
  return Array.isArray(rows) && rows.length === 1;
}

function oauthChallenge(): Response {
  const metadata = new URL("/.well-known/oauth-protected-resource", BASE_URL);
  return new Response("OAuth authorization required", {
    status: 401,
    headers: {
      "WWW-Authenticate": `Bearer resource_metadata="${metadata}"`,
      ...CORS_HEADERS,
    },
  });
}

// --- SSE transport ---
// Claude Desktop uses SSE: client GETs /sse to open a stream,
// server sends an "endpoint" event with a POST URL,
// client POSTs JSON-RPC messages to that URL,
// server sends responses as SSE "message" events on the stream.

// SSE session auth + outbound message queue live in Postgres, NOT in isolate memory:
// on Supabase Edge the GET /sse stream and its POST /message requests can land on
// different isolates. POST writes the response to sse_outbox; the GET /sse isolate
// polls the outbox and flushes it onto the stream (see the SSE handlers below).
const SSE_SESSION_TTL_SECONDS = 60 * 30; // 30 min
const SSE_STREAM_MAX_MS = 110_000; // bounded stream lifetime; SSE clients reconnect
const SSE_POLL_MS = 400;

async function storeSseSession(
  sessionId: string,
  accessToken: string,
): Promise<boolean> {
  try {
    const resp = await fetch(
      `${SUPABASE_REST_URL}/sse_sessions?on_conflict=session_id`,
      {
        method: "POST",
        headers: {
          ...REST_HEADERS,
          "Content-Type": "application/json",
          "Prefer": "resolution=merge-duplicates,return=minimal",
        },
        body: JSON.stringify({
          session_id: sessionId,
          access_token: accessToken,
          expires_at: new Date(Date.now() + SSE_SESSION_TTL_SECONDS * 1000)
            .toISOString(),
        }),
      },
    );
    return resp.ok;
  } catch {
    return false;
  }
}

// { token } if the SSE session exists (token may be ""); null if unknown/expired.
async function getSseSession(
  sessionId: string,
): Promise<{ token: string } | null> {
  if (!sessionId) return null;
  try {
    const resp = await fetch(
      `${SUPABASE_REST_URL}/sse_sessions?session_id=eq.${
        encodeURIComponent(sessionId)
      }&expires_at=gt.${
        encodeURIComponent(new Date().toISOString())
      }&select=access_token`,
      { headers: REST_HEADERS },
    );
    if (!resp.ok) return null;
    const rows = await resp.json().catch(() => null);
    return Array.isArray(rows) && rows.length
      ? { token: rows[0].access_token ?? "" }
      : null;
  } catch {
    return null;
  }
}

async function pushSseMessage(
  sessionId: string,
  payload: unknown,
): Promise<void> {
  try {
    await fetch(`${SUPABASE_REST_URL}/sse_outbox`, {
      method: "POST",
      headers: {
        ...REST_HEADERS,
        "Content-Type": "application/json",
        "Prefer": "return=minimal",
      },
      body: JSON.stringify({ session_id: sessionId, payload }),
    });
  } catch { /* the client reconnects and retries */ }
}

async function drainSseOutbox(
  sessionId: string,
  afterId: number,
): Promise<{ id: number; payload: unknown }[]> {
  try {
    const resp = await fetch(
      `${SUPABASE_REST_URL}/sse_outbox?session_id=eq.${
        encodeURIComponent(sessionId)
      }&id=gt.${afterId}&order=id.asc&select=id,payload`,
      { headers: REST_HEADERS },
    );
    if (!resp.ok) return [];
    const rows = await resp.json().catch(() => null);
    return Array.isArray(rows) ? rows : [];
  } catch {
    return [];
  }
}

async function deleteSseOutbox(ids: number[]): Promise<void> {
  if (!ids.length) return;
  try {
    await fetch(`${SUPABASE_REST_URL}/sse_outbox?id=in.(${ids.join(",")})`, {
      method: "DELETE",
      headers: { ...REST_HEADERS, "Prefer": "return=minimal" },
    });
  } catch { /* best-effort; gt.lastId guards against re-send */ }
}

async function handleMcpMessage(
  body: Record<string, unknown>,
  accessToken: string,
): Promise<Record<string, unknown> | null> {
  const method = body.method as string;
  const id = body.id;
  const params = (body.params as Record<string, unknown>) || {};

  switch (method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "xbloom-chatgpt", version: "2.1.0" },
          instructions:
            "Use xbloom_login once before private account tools. Read before editing when the target recipe is ambiguous. Never expose credentials. Confirm the exact recipe before deletion.",
        },
      };
    case "notifications/initialized":
      return null; // No response for notifications
    case "tools/list":
      return { jsonrpc: "2.0", id, result: { tools: TOOLS } };
    case "tools/call":
      return {
        jsonrpc: "2.0",
        id,
        result: await handleToolCall(params, accessToken || ""),
      };
    default:
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Method not found: ${method}` },
      };
  }
}

Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  const path = url.pathname;

  if (req.method === "OPTIONS") {
    return new Response(null, { headers: CORS_HEADERS });
  }

  // Handle DELETE for SSE session cleanup
  if (req.method === "DELETE") {
    return new Response(null, { status: 200, headers: CORS_HEADERS });
  }

  // OAuth discovery. Every .well-known probe is answered here and nowhere else: an
  // unknown one must 404 rather than fall through to the health handler below, which
  // would 200 with a document containing no endpoints — clients accept that as valid
  // metadata, find no registration_endpoint, and abandon the OAuth flow.
  if (req.method === "GET" && path.includes("/.well-known/")) {
    if (path.includes("oauth-protected-resource")) {
      return jsonResponse({
        resource: BASE_URL,
        authorization_servers: [BASE_URL],
        bearer_methods_supported: ["header"],
      });
    }
    // openid-configuration serves the same document: RFC 8414 puts the canonical URL
    // at the origin root (supabase.co/.well-known/...), which belongs to Supabase's
    // gateway and 401s before reaching this function. Clients that fall back to a
    // path-appended probe reach us here, so both names must resolve.
    if (
      path.includes("oauth-authorization-server") ||
      path.includes("openid-configuration")
    ) {
      return jsonResponse({
        issuer: BASE_URL,
        authorization_endpoint: `${BASE_URL}/authorize`,
        device_authorization_endpoint: `${BASE_URL}/device_authorization`,
        token_endpoint: `${BASE_URL}/token`,
        registration_endpoint: `${BASE_URL}/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
        token_endpoint_auth_methods_supported: [
          "none",
          "client_secret_post",
          "client_secret_basic",
        ],
        code_challenge_methods_supported: ["S256", "plain"],
      });
    }
    return new Response(JSON.stringify({ error: "not_found" }), {
      status: 404,
      headers: { "Content-Type": "application/json", ...CORS_HEADERS },
    });
  }

  // RFC 8628 device authorization and human approval page.
  if (path.endsWith("/device_authorization") && req.method === "POST") return handleDeviceAuthorization(req);
  if (path.endsWith("/device") && (req.method === "GET" || req.method === "POST")) return handleDevicePage(req, url);

  // OAuth endpoints
  if (req.method === "GET" && path.endsWith("/authorize")) {
    return handleAuthorize(url);
  }
  if (req.method === "POST" && path.endsWith("/token")) return handleToken(req);
  if (req.method === "POST" && path.endsWith("/register")) {
    let body: Record<string, unknown> = {};
    try {
      body = await req.json();
    } catch { /* ok */ }
    const clientId = generateToken();
    const redirectUris = Array.isArray(body.redirect_uris)
      ? body.redirect_uris as string[]
      : [];
    // Persist client_id -> redirect_uris so /authorize can validate exact matches.
    await storeClient(clientId, redirectUris);
    return jsonResponse({
      client_id: clientId,
      client_secret: generateToken(),
      client_name: body.client_name || "Claude",
      redirect_uris: redirectUris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post",
    });
  }

  // Require a server-issued bearer token before accepting either transport.
  // A 401 with protected-resource metadata lets ChatGPT/Claude discover OAuth.
  const resourcePath = new URL(BASE_URL).pathname.replace(/\/$/, "");
  if (path === resourcePath || path === `${resourcePath}/` || path.endsWith("/sse") || path.endsWith("/message")) {
    try {
      if (!(await validAccessToken(getSessionKey(req)))) return oauthChallenge();
    } catch {
      return new Response("Authorization store unavailable", { status: 503 });
    }
  }

  // --- SSE transport ---
  // GET /sse — open SSE stream, send endpoint URL
  if (req.method === "GET" && path.endsWith("/sse")) {
    const accessToken = getSessionKey(req) || "";
    const sessionId = generateToken();
    await storeSseSession(sessionId, accessToken);
    log("sse.open", {
      session: keyFingerprint(sessionId),
      key: keyFingerprint(accessToken),
    });

    const encoder = new TextEncoder();
    let cancelled = false;
    const stream = new ReadableStream({
      async start(controller) {
        // Tell the client where to POST messages.
        controller.enqueue(
          encoder.encode(
            `event: endpoint\ndata: ${BASE_URL}/message?sessionId=${sessionId}\n\n`,
          ),
        );
        // Relay loop: flush responses written to sse_outbox by POST /message (which may
        // run on a different isolate) onto this stream. This is what makes SSE survive
        // multi-isolate routing.
        let lastId = 0;
        let sincePing = 0;
        const deadline = Date.now() + SSE_STREAM_MAX_MS;
        try {
          while (!cancelled && Date.now() < deadline) {
            const rows = await drainSseOutbox(sessionId, lastId);
            if (rows.length) {
              for (const r of rows) {
                controller.enqueue(
                  encoder.encode(
                    `event: message\ndata: ${JSON.stringify(r.payload)}\n\n`,
                  ),
                );
                const rid = Number(r.id);
                if (rid > lastId) lastId = rid;
              }
              await deleteSseOutbox(rows.map((r) => Number(r.id)));
              sincePing = 0;
            } else if (++sincePing >= 25) {
              controller.enqueue(encoder.encode(`: ping\n\n`)); // keepalive (~10s idle)
              sincePing = 0;
            }
            await new Promise((res) => setTimeout(res, SSE_POLL_MS));
          }
        } catch { /* client disconnected */ }
        try {
          controller.close();
        } catch { /* already closed */ }
      },
      cancel() {
        cancelled = true;
      },
    });

    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        ...CORS_HEADERS,
      },
    });
  }

  // POST /message?sessionId=xxx — receive JSON-RPC; the response is queued in
  // sse_outbox and delivered by the GET /sse relay loop (on whichever isolate holds
  // the stream). Works regardless of which isolate handles this POST.
  if (req.method === "POST" && path.endsWith("/message")) {
    const sessionId = url.searchParams.get("sessionId") || "";
    const session = await getSseSession(sessionId);

    if (!session) {
      log("sse.session.miss", {});
      return new Response(JSON.stringify({ error: "Invalid session" }), {
        status: 400,
        headers: { "Content-Type": "application/json", ...CORS_HEADERS },
      });
    }

    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return new Response(JSON.stringify({ error: "Parse error" }), {
        status: 400,
        headers: { "Content-Type": "application/json", ...CORS_HEADERS },
      });
    }

    // Process synchronously: the session write (e.g. login's storeSession) must be
    // committed before we ack, so a client that sends its NEXT call after this 202
    // (or after seeing login's result) reliably sees the committed session. Acking
    // early and processing in the background reintroduces a login->create race that
    // surfaces as "You need to log in first". The response is queued to sse_outbox and
    // delivered on the stream by the GET /sse relay loop.
    const response = await handleMcpMessage(
      body,
      getSessionKey(req) || session.token,
    );
    if (response) await pushSseMessage(sessionId, response);

    return new Response(null, { status: 202, headers: CORS_HEADERS });
  }

  // --- Streamable HTTP transport (POST to root) ---

  // Health
  if (req.method === "GET") {
    return jsonResponse({ name: "xbloom-mcp", status: "ok" });
  }
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  // MCP JSON-RPC over POST
  let sessionKey = getSessionKey(req);

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return jsonRpcErr(null, -32700, "Parse error");
  }

  const method = body.method as string;
  const response = await handleMcpMessage(body, sessionKey);
  if (!response) {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...CORS_HEADERS,
  };
  return new Response(JSON.stringify(response), { headers });
});
