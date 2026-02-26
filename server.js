import express from "express";
import crypto from "crypto";
import pg from "pg";

const app = express();
app.use(express.json({ limit: "256kb" }));

const API_SECRET = process.env.API_SECRET; // set in Render
if (!API_SECRET) throw new Error("Missing API_SECRET env var");

const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Render provides this if you link DB
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

const md5 = (s) => crypto.createHash("md5").update(s).digest("hex");
const now = () => Math.floor(Date.now() / 1000);

function bad(res, reason) {
  return res.status(400).json({ ok: false, reason });
}

function enforceFresh(ts) {
  return Math.abs(now() - ts) <= 300; // 5 minutes
}

function verifySig(ts, core, sig) {
  const expect = md5(`${ts}|${core}|${API_SECRET}`);
  return expect === sig;
}

async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS births (
      id BIGSERIAL PRIMARY KEY,
      kit_sid TEXT,
      p1_sid TEXT,
      p2_sid TEXT,
      gen INT,
      tier INT,
      dna_hash TEXT,
      cert_id TEXT UNIQUE,
      cert_ts BIGINT,
      owner_uuid TEXT,
      created_at BIGINT
    );

    CREATE TABLE IF NOT EXISTS transfers (
      id BIGSERIAL PRIMARY KEY,
      sid TEXT,
      from_owner TEXT,
      to_owner TEXT,
      ts BIGINT
    );

    CREATE TABLE IF NOT EXISTS audit (
      id BIGSERIAL PRIMARY KEY,
      event TEXT,
      payload JSONB,
      ts BIGINT
    );
  `);
}

await initSchema();

// --------- ROUTES ---------
app.get("/health", (_req, res) => res.json({ ok: true }));

app.post("/ebk/birth", async (req, res) => {
  const b = req.body || {};
  const ts = Number(b.ts || 0);
  const sig = String(b.sig || "");

  const core = [
    b.cert_id, b.cert_ts, b.p1, b.p2, b.gen, b.tier, b.dna_hash, b.owner
  ].join("|");

  if (!enforceFresh(ts)) return bad(res, "stale ts");
  if (!verifySig(ts, core, sig)) return bad(res, "bad sig");

  const created_at = now();

  try {
    await pool.query(
      `INSERT INTO births
       (kit_sid,p1_sid,p2_sid,gen,tier,dna_hash,cert_id,cert_ts,owner_uuid,created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       ON CONFLICT (cert_id) DO NOTHING`,
      [
        b.kit_sid || null,
        b.p1 || null,
        b.p2 || null,
        Number(b.gen || 0),
        Number(b.tier || 0),
        b.dna_hash || null,
        b.cert_id || null,
        Number(b.cert_ts || 0),
        b.owner || null,
        created_at
      ]
    );

    await pool.query(
      `INSERT INTO audit(event,payload,ts) VALUES ($1,$2,$3)`,
      ["birth", b, created_at]
    );

    res.json({ ok: true });
  } catch (e) {
    return bad(res, "db error");
  }
});

app.post("/ebk/transfer", async (req, res) => {
  const b = req.body || {};
  const ts = Number(b.ts || 0);
  const sig = String(b.sig || "");

  const core = [b.sid, b.from_owner, b.to_owner].join("|");

  if (!enforceFresh(ts)) return bad(res, "stale ts");
  if (!verifySig(ts, core, sig)) return bad(res, "bad sig");

  try {
    await pool.query(
      `INSERT INTO transfers(sid,from_owner,to_owner,ts) VALUES ($1,$2,$3,$4)`,
      [b.sid || null, b.from_owner || null, b.to_owner || null, ts]
    );

    await pool.query(
      `INSERT INTO audit(event,payload,ts) VALUES ($1,$2,$3)`,
      ["transfer", b, now()]
    );

    res.json({ ok: true });
  } catch (e) {
    return bad(res, "db error");
  }
});

app.post("/ebk/verify", async (req, res) => {
  const b = req.body || {};
  const ts = Number(b.ts || 0);
  const sig = String(b.sig || "");

  const core = [b.cert_id, b.dna_hash].join("|");

  if (!enforceFresh(ts)) return bad(res, "stale ts");
  if (!verifySig(ts, core, sig)) return bad(res, "bad sig");

  try {
    const { rows } = await pool.query(
      `SELECT * FROM births WHERE cert_id=$1 LIMIT 1`,
      [b.cert_id]
    );

    if (!rows.length) return res.json({ ok: false, reason: "not found" });

    const row = rows[0];
    if (b.dna_hash && row.dna_hash && b.dna_hash !== row.dna_hash)
      return res.json({ ok: false, reason: "dna mismatch" });

    res.json({ ok: true, record: row });
  } catch (e) {
    return bad(res, "db error");
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("EBK API listening on", port));
