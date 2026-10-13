// SADI NEWS backend: login, shared database and media uploads on Netlify Functions + Netlify Blobs.
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const OWNER_EMAIL = (process.env.OWNER_EMAIL || "lwaziimange2@gmail.com").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const SECRET = process.env.SESSION_SECRET || "";
const COOKIE = "sadi_session";
const MAX_DOC = 100000;
const MAX_STAFF_UPLOAD = 5 * 1024 * 1024; // Netlify Functions accept request bodies up to about 6 MB
const MAX_USER_UPLOAD = 1536 * 1024;
const TYPES = /^(image\/(png|jpeg|gif|webp|svg\+xml)|video\/(mp4|webm))$/;
const PUBLIC = new Set(["articles", "media", "ads", "users", "roles", "live", "settings", "livechat"]);
const ADMIN_ONLY = new Set(["subscribers", "adstats"]);
const ID_RE = /^[A-Za-z0-9_-]{1,80}$/;

const dataStore = () => getStore({ name: "sadi-data", consistency: "strong" });
const authStore = () => getStore({ name: "sadi-auth", consistency: "strong" });
const assetStore = () => getStore({ name: "sadi-assets", consistency: "strong" });

const J = (obj, status = 200, headers = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers } });
const fail = (status, error, code) => J({ error, code: code || (status === 401 || status === 403 ? "permission_denied" : "error") }, status);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const newId = () => Date.now().toString(36) + crypto.randomBytes(4).toString("hex");

/* ---------- sessions ---------- */
function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  return body + "." + sig;
}
function verify(tok) {
  if (!SECRET || !tok) return null;
  const [body, sig] = tok.split(".");
  if (!body || !sig) return null;
  const good = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  const a = Buffer.from(sig), b = Buffer.from(good);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}
function readCookie(req, name) {
  const m = (req.headers.get("cookie") || "").split(/;\s*/).find((c) => c.startsWith(name + "="));
  return m ? m.slice(name.length + 1) : null;
}
const sessionCookie = (tok, maxAge) => `${COOKIE}=${tok}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
async function viewer(req) {
  const s = verify(readCookie(req, COOKIE));
  if (!s) return { uid: null, role: "visitor" };
  let role = "reader";
  if (s.uid === "owner" && s.email === OWNER_EMAIL) role = "admin";
  else {
    const r = await dataStore().get("roles/" + s.uid, { type: "json" });
    if (r && r.role === "author") role = "author";
  }
  return { uid: s.uid, email: s.email, name: s.name, role };
}
const scrypt = (pw, salt) => new Promise((res, rej) => crypto.scrypt(pw, salt, 64, (e, k) => (e ? rej(e) : res(k))));

/* ---------- auth routes ---------- */
async function auth(action, req) {
  if (action === "me") {
    const v = await viewer(req);
    return J(v.uid ? { uid: v.uid, email: v.email, name: v.name, role: v.role } : {});
  }
  if (action === "logout") return J({ ok: true }, 200, { "Set-Cookie": sessionCookie("", 0) });
  if (req.method !== "POST") return fail(405, "Method not allowed");
  if (!SECRET) return fail(500, "The site isn't fully set up yet: add SESSION_SECRET in Netlify.", "not_configured");
  const body = await req.json().catch(() => ({}));
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!/^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$/.test(email)) return fail(400, "Enter a valid email address.");
  const issue = (uid, name) => J({ uid, email, name }, 200, { "Set-Cookie": sessionCookie(sign({ uid, email, name, exp: Date.now() + 30 * 864e5 }), 30 * 86400) });

  if (action === "register") {
    const name = String(body.name || "").trim().slice(0, 40) || email.split("@")[0];
    if (password.length < 8 || password.length > 200) return fail(400, "Use a password of at least 8 characters.");
    if (email === OWNER_EMAIL) return fail(403, "That email belongs to the site owner. Use Sign in.");
    const key = sha(email), st = authStore();
    if (await st.get(key, { type: "json" })) return fail(409, "An account with that email already exists. Sign in instead.");
    const uid = crypto.randomBytes(9).toString("base64url"), salt = crypto.randomBytes(16).toString("hex");
    const hash = (await scrypt(password, salt)).toString("hex");
    await st.setJSON(key, { uid, email, name, salt, hash, created: Date.now() });
    return issue(uid, name);
  }
  if (action === "login") {
    if (email === OWNER_EMAIL) {
      if (!ADMIN_PASSWORD) return fail(500, "Owner login isn't set up yet: add ADMIN_PASSWORD in Netlify.", "not_configured");
      const ok = crypto.timingSafeEqual(Buffer.from(sha(password)), Buffer.from(sha(ADMIN_PASSWORD)));
      if (!ok) { await sleep(600); return fail(401, "Wrong email or password.", "bad_login"); }
      return issue("owner", "Site Owner");
    }
    const acct = await authStore().get(sha(email), { type: "json" });
    let ok = false;
    if (acct) {
      const h = (await scrypt(password, acct.salt)).toString("hex");
      ok = crypto.timingSafeEqual(Buffer.from(h), Buffer.from(acct.hash));
    }
    if (!ok) { await sleep(600); return fail(401, "Wrong email or password.", "bad_login"); }
    return issue(acct.uid, acct.name);
  }
  return fail(404, "Not found");
}

/* ---------- database rules ---------- */
function validCol(c) { return PUBLIC.has(c) || ADMIN_ONLY.has(c) || /^data\/users\/[A-Za-z0-9_-]{1,80}$/.test(c); }
function parsePath(p) {
  if (typeof p !== "string") return null;
  const seg = p.split("/").filter(Boolean);
  if (seg.length < 2) return null;
  const id = seg.pop(), col = seg.join("/");
  return validCol(col) && ID_RE.test(id) ? { col, id } : null;
}
function canRead(col, v) {
  if (PUBLIC.has(col)) return true;
  if (ADMIN_ONLY.has(col)) return v.role === "admin";
  return false;
}
function filterRead(col, docs, v) {
  const admin = v.role === "admin";
  if (col === "articles" || col === "media")
    return docs.filter((d) => admin || d.data.status === "published" || d.data.status === undefined || (v.uid && d.data.authorId === v.uid));
  if (col === "users")
    return docs.map((d) => (admin || d.id === v.uid || !d.data.authorApplication ? d : { id: d.id, data: { ...d.data, authorApplication: undefined } }));
  return docs;
}
async function listCol(col, v) {
  if (!canRead(col, v)) return null;
  const st = dataStore();
  const { blobs } = await st.list({ prefix: col + "/" });
  let keys = blobs.map((b) => b.key).filter((k) => !k.slice(col.length + 1).includes("/")).sort();
  if (col === "livechat") keys = keys.slice(-100);
  const docs = (await Promise.all(keys.map(async (k) => {
    const d = await st.get(k, { type: "json" });
    return d ? { id: k.slice(col.length + 1), data: d } : null;
  }))).filter(Boolean);
  return filterRead(col, docs, v);
}
function writeRules(col, id, d, ex, v) {
  const admin = v.role === "admin", author = v.role === "author", uid = v.uid;
  const deny = (m) => ({ error: m || "You don't have permission for that." });
  if (col === "livechat") {
    const text = String(d.text || "").trim().slice(0, 240);
    if (!uid || ex || !text) return deny();
    return { data: { uid, name: String(d.name || v.name || "Reader").slice(0, 40), text, t: Date.now() } };
  }
  if (col === "adstats") {
    const n = (x) => (Number.isFinite(x) && x >= 0 ? Math.floor(x) : 0);
    const oi = (ex && ex.imp) || 0, oc = (ex && ex.clk) || 0;
    return { data: { imp: Math.max(oi, Math.min(n(d.imp), oi + 200)), clk: Math.max(oc, Math.min(n(d.clk), oc + 200)) } };
  }
  if (admin) return { data: d };
  if (col === "articles" || col === "media") {
    if (!author || (ex && ex.authorId !== uid)) return deny();
    return { data: { ...d, authorId: uid, status: d.status === "draft" ? "draft" : "pending", featured: false } };
  }
  if (col === "users") {
    if (!uid || id !== uid) return deny();
    const out = { ...d }, exA = ex && ex.authorApplication;
    if (d.authorApplication) {
      const st = exA && exA.status === "approved" ? "approved" : exA && exA.status === "rejected" && d.authorApplication.status === "rejected" ? "rejected" : "pending";
      out.authorApplication = { ...d.authorApplication, status: st };
    } else if (exA) out.authorApplication = exA;
    return { data: out };
  }
  if (col === "subscribers") return uid && id === uid ? { data: d } : deny();
  if (col.startsWith("data/users/")) {
    if (!uid || col.split("/")[2] !== uid || id !== "prefs") return deny();
    return { data: { saved: Array.isArray(d.saved) ? d.saved.filter((x) => typeof x === "string").slice(0, 500) : [] } };
  }
  return deny();
}
function canDelete(col, id, ex, v) {
  if (v.role === "admin") return true;
  if ((col === "articles" || col === "media") && v.role === "author" && ex && ex.authorId === v.uid) return true;
  if (col.startsWith("data/users/") && v.uid && col.split("/")[2] === v.uid) return true;
  return false;
}

async function db(req) {
  const v = await viewer(req);
  const b = await req.json().catch(() => ({}));
  const st = dataStore();
  switch (b.op) {
    case "list": {
      if (!validCol(b.col)) return fail(400, "Bad collection");
      const docs = await listCol(b.col, v);
      return docs ? J({ docs }) : fail(403, "Not allowed");
    }
    case "listMany": {
      const cols = Array.isArray(b.cols) ? b.cols.filter(validCol).slice(0, 12) : [];
      const out = {};
      await Promise.all(cols.map(async (c) => { out[c] = await listCol(c, v); }));
      return J({ results: out });
    }
    case "get": {
      const p = parsePath(b.path);
      if (!p) return fail(400, "Bad path");
      if (p.col.startsWith("data/users/") && !(v.uid && (p.col.split("/")[2] === v.uid || v.role === "admin"))) return fail(403, "Not allowed");
      if (!p.col.startsWith("data/users/") && !canRead(p.col, v)) return fail(403, "Not allowed");
      const d = await st.get(p.col + "/" + p.id, { type: "json" });
      const hit = d ? filterRead(p.col, [{ id: p.id, data: d }], v) : [];
      return J({ exists: hit.length > 0, data: hit.length ? hit[0].data : null });
    }
    case "set":
    case "add": {
      const p = b.op === "add" ? (validCol(b.col) ? { col: b.col, id: newId() } : null) : parsePath(b.path);
      if (!p) return fail(400, "Bad path");
      if (!v.uid && p.col !== "adstats") return fail(401, "Sign in first.");
      const d = b.data;
      if (!d || typeof d !== "object" || Array.isArray(d)) return fail(400, "Bad data");
      if (JSON.stringify(d).length > MAX_DOC) return fail(413, "That is too large.", "too_large");
      const key = p.col + "/" + p.id;
      const ex = b.op === "add" ? null : await st.get(key, { type: "json" });
      const r = writeRules(p.col, p.id, d, ex, v);
      if (r.error) return fail(403, r.error);
      await st.setJSON(key, r.data);
      return J({ id: p.id });
    }
    case "delete": {
      const p = parsePath(b.path);
      if (!p) return fail(400, "Bad path");
      const ex = await st.get(p.col + "/" + p.id, { type: "json" });
      if (!canDelete(p.col, p.id, ex, v)) return fail(403, "You don't have permission for that.");
      await st.delete(p.col + "/" + p.id);
      return J({ ok: true });
    }
    case "assetDelete": {
      if (!ID_RE.test(String(b.id || ""))) return fail(400, "Bad id");
      const a = await assetStore().getWithMetadata(b.id, { type: "arrayBuffer" });
      if (!a) return J({ ok: true });
      if (!(v.role === "admin" || (v.uid && a.metadata && a.metadata.uid === v.uid))) return fail(403, "Not allowed");
      await assetStore().delete(b.id);
      return J({ ok: true });
    }
    default: return fail(400, "Unknown operation");
  }
}

/* ---------- uploads and media delivery ---------- */
async function upload(req) {
  const v = await viewer(req);
  if (!v.uid) return fail(401, "Sign in first.");
  const type = (req.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
  if (!TYPES.test(type)) return fail(415, "That file type isn't accepted.", "bad_type");
  const staff = v.role === "admin" || v.role === "author";
  if (!staff && !type.startsWith("image/")) return fail(403, "Only authors can upload that.");
  const limit = staff ? MAX_STAFF_UPLOAD : MAX_USER_UPLOAD;
  if ((Number(req.headers.get("content-length")) || 0) > limit) return fail(413, "Too large", "too_large");
  const ab = await req.arrayBuffer();
  if (ab.byteLength > limit || ab.byteLength === 0) return fail(413, "Too large", "too_large");
  const id = crypto.randomBytes(16).toString("hex");
  await assetStore().set(id, ab, { metadata: { type, uid: v.uid } });
  return J({ id, url: "/_blob/" + id });
}
async function asset(id, req) {
  if (!/^[a-f0-9]{32}$/.test(id)) return new Response("Not found", { status: 404 });
  const a = await assetStore().getWithMetadata(id, { type: "arrayBuffer" });
  if (!a) return new Response("Not found", { status: 404 });
  const buf = Buffer.from(a.data), total = buf.length;
  const headers = {
    "Content-Type": (a.metadata && a.metadata.type) || "application/octet-stream",
    "Cache-Control": "public, max-age=31536000, immutable",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
    "Accept-Ranges": "bytes",
  };
  const m = /^bytes=(\d*)-(\d*)$/.exec(req.headers.get("range") || "");
  if (m && (m[1] || m[2])) {
    let start = m[1] ? Number(m[1]) : Math.max(0, total - Number(m[2]));
    let end = m[1] && m[2] ? Math.min(Number(m[2]), total - 1) : total - 1;
    if (start > end || start >= total) return new Response(null, { status: 416, headers: { "Content-Range": `bytes */${total}` } });
    return new Response(buf.subarray(start, end + 1), { status: 206, headers: { ...headers, "Content-Range": `bytes ${start}-${end}/${total}`, "Content-Length": String(end - start + 1) } });
  }
  return new Response(buf, { status: 200, headers: { ...headers, "Content-Length": String(total) } });
}

export default async (req) => {
  try {
    const url = new URL(req.url);
    const parts = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);
    if (req.method !== "GET" && req.method !== "HEAD") {
      const o = req.headers.get("origin");
      if (o && new URL(o).host !== url.host) return fail(403, "Bad origin");
    }
    if (parts[0] === "auth") return await auth(parts[1], req);
    if (parts[0] === "db" && req.method === "POST") return await db(req);
    if (parts[0] === "upload" && req.method === "POST") return await upload(req);
    if (parts[0] === "asset" && parts[1]) return await asset(parts[1], req);
    return fail(404, "Not found");
  } catch (e) {
    console.error(e);
    return fail(500, "Server error");
  }
};
export const config = { path: "/api/*" };
