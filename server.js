const express = require("express");
const http = require("http");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { WebSocketServer } = require("ws");

const PORT = process.env.PORT || 3000;
if (!process.env.DATABASE_URL) { console.error("DATABASE_URL is missing"); process.exit(1); }
if (!process.env.JWT_SECRET) console.warn("WARNING: JWT_SECRET not set, users will be logged out on every restart");
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const q = (text, params) => pool.query(text, params);

async function init() {
  await q(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at BIGINT NOT NULL)`);
  await q(`CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower ON users (LOWER(username))`);
  await q(`CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    receiver_id INTEGER REFERENCES users(id),
    text TEXT NOT NULL,
    created_at BIGINT NOT NULL)`);
  await q(`CREATE INDEX IF NOT EXISTS messages_pair ON messages (sender_id, receiver_id)`);
}

const app = express();
app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.get("/health", (req, res) => res.send("ok")); // used by the uptime pinger

const hits = new Map();
function limit(req, res, next) {
  const k = req.ip, now = Date.now();
  const arr = (hits.get(k) || []).filter(t => now - t < 60000);
  if (arr.length >= 20) return res.status(429).json({ error: "محاولات كثيرة، انتظر دقيقة" });
  arr.push(now); hits.set(k, arr); next();
}
const sign = u => jwt.sign({ id: u.id, username: u.username }, SECRET, { expiresIn: "30d" });
function auth(req, res, next) {
  try { req.user = jwt.verify((req.headers.authorization || "").replace("Bearer ", ""), SECRET); next(); }
  catch { res.status(401).json({ error: "غير مصرح" }); }
}
const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: "خطأ في الخادم" }); });

app.post("/api/register", limit, wrap(async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  if (!/^[\w\u0600-\u06FF.-]{3,20}$/.test(username)) return res.status(400).json({ error: "اسم المستخدم 3-20 حرفاً (حروف وأرقام و _ . -)" });
  if (password.length < 6) return res.status(400).json({ error: "كلمة المرور 6 أحرف على الأقل" });
  try {
    const r = await q("INSERT INTO users (username, password_hash, created_at) VALUES ($1,$2,$3) RETURNING id",
      [username, bcrypt.hashSync(password, 10), Date.now()]);
    const u = { id: r.rows[0].id, username };
    res.json({ token: sign(u), user: u });
} catch (e) {
  console.error("REGISTER ERROR:", {
    code: e.code,
    constraint: e.constraint,
    detail: e.detail,
    message: e.message
  });

  if (
    e.code === "23505" &&
    e.constraint === "users_username_lower"
  ) {
    return res.status(409).json({
      error: "اسم المستخدم مستخدم مسبقاً"
    });
  }

  throw e;
}
}));

app.post("/api/login", limit, wrap(async (req, res) => {
  const r = await q("SELECT * FROM users WHERE LOWER(username) = LOWER($1)", [String(req.body.username || "").trim()]);
  const u = r.rows[0];
  if (!u || !bcrypt.compareSync(String(req.body.password || ""), u.password_hash))
    return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });
  res.json({ token: sign(u), user: { id: u.id, username: u.username } });
}));

app.get("/api/users", auth, wrap(async (req, res) => {
  res.json((await q("SELECT id, username FROM users ORDER BY username")).rows);
}));

app.get("/api/messages", auth, wrap(async (req, res) => {
  const w = parseInt(req.query.with, 10) || 0, me = req.user.id;
  const r = w === 0
    ? await q("SELECT id, sender_id, receiver_id, text FROM messages WHERE receiver_id IS NULL ORDER BY id DESC LIMIT 200")
    : await q(`SELECT id, sender_id, receiver_id, text FROM messages
        WHERE (sender_id=$1 AND receiver_id=$2) OR (sender_id=$2 AND receiver_id=$1) ORDER BY id DESC LIMIT 200`, [me, w]);
  res.json(r.rows.reverse());
}));

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: "/ws" });
const sockets = new Map();

wss.on("connection", (ws, req) => {
  let user;
  try { user = jwt.verify(new URL(req.url, "http://x").searchParams.get("token"), SECRET); }
  catch { return ws.close(4001); }
  if (!sockets.has(user.id)) sockets.set(user.id, new Set());
  sockets.get(user.id).add(ws);
  ws.isAlive = true; ws.on("pong", () => (ws.isAlive = true));
  ws.on("close", () => sockets.get(user.id)?.delete(ws));
  ws.on("message", async raw => {
    try {
      const d = JSON.parse(raw);
      const text = String(d.text || "").trim().slice(0, 1000);
      if (!text) return;
      const to = d.to ? parseInt(d.to, 10) : null;
      if (to && !(await q("SELECT 1 FROM users WHERE id=$1", [to])).rowCount) return;
      const r = await q("INSERT INTO messages (sender_id, receiver_id, text, created_at) VALUES ($1,$2,$3,$4) RETURNING id",
        [user.id, to, text, Date.now()]);
      const msg = JSON.stringify({ type: "message", message: { id: r.rows[0].id, sender_id: user.id, receiver_id: to, text } });
      const targets = to === null ? [...sockets.values()].flatMap(s => [...s]) : [...(sockets.get(user.id) || []), ...(sockets.get(to) || [])];
      targets.forEach(c => c.readyState === 1 && c.send(msg));
    } catch (e) { console.error(e); }
  });
});
setInterval(() => wss.clients.forEach(c => { if (!c.isAlive) return c.terminate(); c.isAlive = false; c.ping(); }), 30000);

init().then(() => server.listen(PORT, () => console.log("Chat running on port " + PORT)))
  .catch(e => { console.error("DB init failed", e); process.exit(1); });
