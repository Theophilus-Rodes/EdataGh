const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const session = require("express-session");
const path = require("path");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;

// Africa's Talking
const AfricasTalking = require("africastalking");

const app = express();
app.set("trust proxy", 1);

// ✅ CORS (only once)
app.use(cors({
  origin: ["https://edatagh.com", "http://localhost:8080", "http://localhost:3000"],
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ Session (also set cookie name so logout clearCookie matches)
app.use(session({
  name: "edata.sid",
  secret: "edata_secret_key",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: true, // DigitalOcean uses HTTPS
  }
}));




app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("edata.sid", {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
    });
    res.json({ ok: true });
  });
});



// Serve everything in THIS folder (same folder as index.js)
app.use(express.static(path.join(__dirname)));

// ✅ Force route (fixes "Cannot GET /login.html")
app.get("/login.html", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

// Database
// =======================
// DigitalOcean MySQL (Managed) ✅ FIXED
// =======================
const fs = require("fs");


// Option A (recommended): put the CA certificate content in env var DB_SSL_CA
// If you paste it with "\n", this converts it back to real new lines.
const caFromEnv = process.env.DB_SSL_CA
  ? process.env.DB_SSL_CA.replace(/\\n/g, "\n")
  : null;

// Option B: if you saved the CA file inside your repo (e.g. backend/ca.pem)
// const caFromFile = fs.readFileSync(require("path").join(__dirname, "ca.pem"), "utf8");

const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 25060),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,

  ssl: caFromEnv
    ? { ca: caFromEnv, rejectUnauthorized: true }
    : { rejectUnauthorized: true },

  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// ✅ quick connection test
db.query("SELECT 1 AS ok", (err) => {
  if (err) console.error("❌ DB Error:", err.message);
  else console.log("✅ Database connected (DigitalOcean)");
});




// Login API
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Missing email or password" });
  }

  db.query(
    "SELECT id, fullname, email, password, status FROM users WHERE email = ? LIMIT 1",
    [email],
    (err, results) => {
      if (err) {
        console.error("Query error:", err);
        return res.status(500).json({ message: "Server error" });
      }

      if (results.length === 0) {
        return res.status(401).json({ message: "Invalid login details" });
      }

      const user = results[0];

      // ✅ PLAIN TEXT CHECK
      if (password !== user.password) {
        return res.status(401).json({ message: "Invalid login details" });
      }

      // ✅ ADMIN ONLY
      if (user.status !== "admin") {
        return res.status(403).json({ message: "Access denied" });
      }

      req.session.admin = user.id;

      return res.json({ success: true, redirect: "/admindashboard.html" });
    }
  );
});

// ADD NEW PRICE
app.post("/api/admin-prices", (req, res) => {
  const { network, package_name, price } = req.body;

  if (!network || !package_name || price === undefined) {
    return res.status(400).json({ ok: false, message: "Missing fields" });
  }

  const sql = "INSERT INTO admin_prices (network, package_name, price, status) VALUES (?,?,?, 'active')";
  db.query(sql, [String(network).toLowerCase(), package_name, Number(price)], (err, result) => {
    if (err) return res.status(500).json({ ok: false, message: "DB error" });
    res.json({ ok: true, id: result.insertId });
  });
});


// GET ALL ADMIN PRICES
// GET ALL ADMIN PRICES (ORDERED: MTN → TELECEL → AIRTELTIGO, PRICE ASC)
app.get("/api/admin-prices", (req, res) => {
  const sql = `
    SELECT *
    FROM admin_prices
    ORDER BY
      CASE LOWER(TRIM(network))
        WHEN 'mtn' THEN 1
        WHEN 'telecel' THEN 2
        WHEN 'airteltigo' THEN 3
        ELSE 4
      END,
      price ASC,
      id DESC
  `;

  db.query(sql, (err, rows) => {
    if (err) {
      console.error("admin-prices error:", err);
      return res.status(500).json({ ok: false, message: "DB error" });
    }

    res.json({ ok: true, rows: rows || [] });
  });
});


// UPDATE PRICE ROW
app.put("/api/admin-prices/:id", (req, res) => {
  const { id } = req.params;
  const { package_name, price, network } = req.body;

  if (!package_name || price === undefined || !network) {
    return res.status(400).json({ ok: false, message: "Missing fields" });
  }

  const sql = "UPDATE admin_prices SET network=?, package_name=?, price=? WHERE id=?";
  db.query(sql, [String(network).toLowerCase(), package_name, Number(price), Number(id)], (err) => {
    if (err) return res.status(500).json({ ok: false, message: "DB error" });
    res.json({ ok: true });
  });
});


// TOGGLE STATUS
app.patch("/api/admin-prices/:id/status", (req, res) => {
  const { id } = req.params;
  const { status } = req.body; // 'active' or 'inactive'

  if (!["active", "inactive"].includes(String(status))) {
    return res.status(400).json({ ok: false, message: "Invalid status" });
  }

  const sql = "UPDATE admin_prices SET status=? WHERE id=?";
  db.query(sql, [status, Number(id)], (err) => {
    if (err) return res.status(500).json({ ok: false, message: "DB error" });
    res.json({ ok: true });
  });
});


// GET current admin info (from session)
app.get("/api/admin/me", (req, res) => {
  if (!req.session || !req.session.admin) {
    return res.status(401).json({ ok: false, message: "Not logged in" });
  }

  const adminId = req.session.admin;

  db.query(
    "SELECT id, fullname AS username, email FROM users WHERE id = ? LIMIT 1",
    [adminId],
    (err, rows) => {
      if (err) {
        console.log("DB ERROR (GET):", err);
        return res.status(500).json({ ok: false, message: "DB error" });
      }

      if (!rows.length) {
        return res.status(404).json({ ok: false, message: "Admin not found" });
      }

      return res.json({ ok: true, user: rows[0] });
    }
  );
});



// UPDATE current admin info (NO HASHING)
app.put("/api/admin/me", (req, res) => {
  if (!req.session || !req.session.admin) {
    return res.status(401).json({ ok: false, message: "Not logged in" });
  }

  const adminId = req.session.admin;
  const { username, email, new_password } = req.body;

  if (!username || !email) {
    return res.status(400).json({ ok: false, message: "Name and email are required" });
  }

  // If password is provided, update it
  if (new_password && String(new_password).trim().length > 0) {
    if (String(new_password).trim().length < 4) {
      return res.status(400).json({ ok: false, message: "Password must be at least 4 characters" });
    }

    db.query(
      "UPDATE users SET fullname=?, email=?, password=? WHERE id=? LIMIT 1",
      [username, email, new_password.trim(), adminId],
      (err) => {
        if (err) {
          console.log("DB ERROR (UPDATE + PASS):", err);
          return res.status(500).json({ ok: false, message: "DB error" });
        }
        return res.json({ ok: true, message: "Profile updated (password changed)." });
      }
    );

  } else {
    // Update name + email only
    db.query(
      "UPDATE users SET fullname=?, email=? WHERE id=? LIMIT 1",
      [username, email, adminId],
      (err) => {
        if (err) {
          console.log("DB ERROR (UPDATE):", err);
          return res.status(500).json({ ok: false, message: "DB error" });
        }
        return res.json({ ok: true, message: "Profile updated." });
      }
    );
  }
});











// ===========================================
// GET MTN ADMIN DATA PACKAGES
// ===========================================
// ===========================================
// ===========================================
// GET MTN ADMIN PRICES (NEW SAFE ENDPOINT)
// URL: /api/mtn-prices
// ===========================================
app.get("/api/mtn-prices", (req, res) => {
  const sql = `
    SELECT id, network, package_name, price, status, created_at, updated_at
    FROM admin_prices
    WHERE LOWER(TRIM(network)) = 'mtn'
      AND LOWER(TRIM(status)) = 'active'
    ORDER BY price ASC
  `;

  db.query(sql, (err, rows) => {
    if (err) {
      console.error("❌ mtn-prices fetch error:", err);
      return res.status(500).json({ ok: false, message: "DB error" });
    }

    return res.json({ ok: true, rows: rows || [] });
  });
});




// ===========================================
// GET TELECEL ADMIN PRICES
// ===========================================
app.get("/api/telecel-prices", (req, res) => {
  
  const sql = `
    SELECT id, network, package_name, price, status, created_at, updated_at
    FROM admin_prices
    WHERE LOWER(TRIM(network)) = 'telecel'
      AND LOWER(TRIM(status)) = 'active'
    ORDER BY price ASC
  `;

  db.query(sql, (err, rows) => {
    if (err) {
      console.error("❌ telecel_prices fetch error:", err);
      return res.status(500).json({ ok: false, message: "DB error" });
    }
    res.json({ ok: true, rows: rows || [] });
  });
});


// ===========================================
// GET AIRTELTIGO ADMIN PRICES
// ===========================================
app.get("/api/airteltigo-prices", (req, res) => {
  const sql = `
    SELECT id, network, package_name, price, status, created_at, updated_at
    FROM admin_prices
    WHERE LOWER(TRIM(network)) = 'airteltigo'
      AND LOWER(TRIM(status)) = 'active'
    ORDER BY price ASC
  `;

  db.query(sql, (err, rows) => {
    if (err) {
      console.error("❌ airteltigo_prices fetch error:", err);
      return res.status(500).json({ ok: false, message: "DB error" });
    }
    res.json({ ok: true, rows: rows || [] });
  });
});











// =====================================================
// ✅ YOUR EXISTING AFRICA'S TALKING CONFIG (KEPT)
// =====================================================
const AT_USERNAME = "EdataSell";
const AT_API_KEY = process.env.AT_API_KEY || "PASTE_YOURS_IN_ENV";
const AT_SENDER_ID = process.env.AT_SENDER_ID || "";

const OTP_TTL = 5 * 60 * 1000;                 // 5 minutes
const COOLDOWN_MS = 20 * 1000;                 // 20 seconds
const VERIFIED_WINDOW_MS = 10 * 60 * 1000;     // 10 minutes after verify
const MAX_ATTEMPTS = 5;

// IMPORTANT: set this in DigitalOcean env (Settings → App → Environment Variables)
const OTP_SECRET = process.env.OTP_SECRET || "CHANGE_ME_IN_ENV_NOW";

const at = AfricasTalking({ username: AT_USERNAME, apiKey: AT_API_KEY });
const sms = at.SMS;

// ✅ keep your normalizer
function normalizePhoneToE164Ghana(input = "") {
  const v = String(input).replace(/\s+/g, "").replace(/^\+/, "");
  if (/^0\d{9}$/.test(v)) return "+233" + v.slice(1);
  if (/^233\d{9}$/.test(v)) return "+" + v;
  if (/^\d{9}$/.test(v)) return "+233" + v;
  if (/^\d{10,15}$/.test(v)) return "+" + v;
  return null;
}

function generateOtp(len = 6) {
  let s = "";
  for (let i = 0; i < len; i++) s += Math.floor(Math.random() * 10);
  return s;
}

function genSessionId() {
  return crypto.randomBytes(24).toString("hex"); // stable unique id
}

function hashOtp(otp) {
  // hash = sha256(secret:otp) so we never store OTP in plain text
  return crypto.createHash("sha256").update(`${OTP_SECRET}:${otp}`).digest("hex");
}

async function sendOtpSmsAfricaTalking(toE164, otp) {
  const message = `EDATA OTP: ${otp}\nExpires in 5 minutes. Do not share this code.`;
  const options = { to: [toE164], message };
  if (AT_SENDER_ID && AT_SENDER_ID.trim()) options.from = AT_SENDER_ID.trim();
  return sms.send(options);
}

// =====================================================
// ✅ OPTIONAL: cleanup job to keep table small
// =====================================================
setInterval(async () => {
  try {
    await db.promise().query(
      `DELETE FROM momo_otp_sessions
       WHERE created_at < (NOW() - INTERVAL 2 DAY)`
    );
  } catch (e) {
    console.error("OTP cleanup error:", e.message);
  }
}, 60 * 60 * 1000); // hourly


// =====================================================
// POST /api/send-momo-otp  body: { momo_number }
// =====================================================
app.post("/api/send-momo-otp", async (req, res) => {
  try {
    const momoRaw = req.body?.momo_number;
    const momoE164 = normalizePhoneToE164Ghana(momoRaw);
    if (!momoE164) return res.json({ ok: false, message: "Invalid MoMo number format." });

    // ✅ DB-based cooldown (works on DigitalOcean / multiple instances)
    const [cool] = await db.promise().query(
      `SELECT last_sent_at
       FROM momo_otp_sessions
       WHERE momo_e164 = ?
       ORDER BY created_at DESC
       LIMIT 1`,
      [momoE164]
    );

    if (cool.length) {
      const lastSentAt = new Date(cool[0].last_sent_at).getTime();
      if (Date.now() - lastSentAt < COOLDOWN_MS) {
        return res.json({ ok: false, message: "Please wait a few seconds and try again." });
      }
    }

    const otp = generateOtp(6);
    const session_id = genSessionId();
    const expiresAt = new Date(Date.now() + OTP_TTL);
    const otpHash = hashOtp(otp);

    // ✅ INSERT FIRST (so verify never complains)
    await db.promise().query(
      `INSERT INTO momo_otp_sessions
        (session_id, momo_e164, otp_hash, attempts, expires_at, verified_until, consumed_at, last_sent_at)
       VALUES (?, ?, ?, 0, ?, NULL, NULL, NOW())`,
      [session_id, momoE164, otpHash, expiresAt]
    );

    // ✅ THEN send SMS (if sms fails, remove DB row)
    try {
      await sendOtpSmsAfricaTalking(momoE164, otp);
    } catch (smsErr) {
      await db.promise().query(`DELETE FROM momo_otp_sessions WHERE session_id=?`, [session_id]);
      console.error("❌ OTP SMS send failed:", smsErr?.response?.data || smsErr.message || smsErr);
      return res.status(500).json({ ok: false, message: "Failed to send OTP." });
    }

    return res.json({ ok: true, message: "OTP sent successfully.", session_id });
  } catch (err) {
    console.error("❌ send-momo-otp error:", err?.response?.data || err);
    return res.status(500).json({ ok: false, message: "Failed to send OTP." });
  }
});


// =====================================================
// POST /api/verify-momo-otp  body: { momo_number, otp, session_id }
// =====================================================
app.post("/api/verify-momo-otp", async (req, res) => {
  try {
    const momoRaw = req.body?.momo_number;
    const momoE164 = normalizePhoneToE164Ghana(momoRaw);

    const otp = String(req.body?.otp || "").trim();
    let session_id = String(req.body?.session_id || "").trim();

    if (!momoE164) return res.json({ ok: false, message: "Invalid MoMo number." });
    if (!/^\d{4,8}$/.test(otp)) return res.json({ ok: false, message: "Invalid OTP code." });

    // ✅ load session by id; if missing or not found, fallback to latest active session for number
    let rec = null;

    if (session_id) {
      const [rows] = await db.promise().query(
        `SELECT *
         FROM momo_otp_sessions
         WHERE session_id = ?
         LIMIT 1`,
        [session_id]
      );
      rec = rows[0] || null;
    }

    if (!rec) {
      const [rows2] = await db.promise().query(
        `SELECT *
         FROM momo_otp_sessions
         WHERE momo_e164 = ?
           AND expires_at > NOW()
           AND otp_hash IS NOT NULL
         ORDER BY created_at DESC
         LIMIT 1`,
        [momoE164]
      );
      rec = rows2[0] || null;
      if (rec) session_id = rec.session_id;
    }

    if (!rec) return res.json({ ok: false, message: "No OTP request found. Please send OTP again." });

    if (rec.momo_e164 !== momoE164) {
      return res.json({ ok: false, message: "OTP session mismatch. Please request a new OTP." });
    }

    if (new Date(rec.expires_at).getTime() < Date.now()) {
      return res.json({ ok: false, message: "OTP expired. Please request a new OTP." });
    }

    const attempts = Number(rec.attempts || 0) + 1;
    if (attempts > MAX_ATTEMPTS) {
      await db.promise().query(`DELETE FROM momo_otp_sessions WHERE session_id=?`, [session_id]);
      return res.json({ ok: false, message: "Too many attempts. Please request a new OTP." });
    }

    const ok = hashOtp(otp) === rec.otp_hash;

    if (!ok) {
      await db.promise().query(
        `UPDATE momo_otp_sessions SET attempts=? WHERE session_id=?`,
        [attempts, session_id]
      );
      return res.json({ ok: false, message: "Incorrect OTP." });
    }

    // ✅ verified window + invalidate OTP immediately (no reuse)
    const verifiedUntil = new Date(Date.now() + VERIFIED_WINDOW_MS);

    await db.promise().query(
      `UPDATE momo_otp_sessions
       SET verified_until=?, otp_hash=NULL, expires_at=NOW(), attempts=?
       WHERE session_id=?`,
      [verifiedUntil, attempts, session_id]
    );

    return res.json({
      ok: true,
      message: "OTP verified.",
      session_id,
      verified_until: verifiedUntil,
    });
  } catch (err) {
    console.error("❌ verify-momo-otp error:", err?.response?.data || err);
    return res.status(500).json({ ok: false, message: "OTP verification failed." });
  }
});


// =====================================================
// ✅ DB-based verification check (works on DO)
// =====================================================
async function isOtpVerifiedNow(momoRaw, session_id) {
  const momoE164 = normalizePhoneToE164Ghana(momoRaw);
  if (!momoE164) return { ok: false };

  const sid = String(session_id || "").trim();

  // If sid missing, fallback to latest verified session for number
  if (!sid) {
    const [rows] = await db.promise().query(
      `SELECT session_id, verified_until, consumed_at
       FROM momo_otp_sessions
       WHERE momo_e164 = ?
         AND verified_until IS NOT NULL
         AND verified_until > NOW()
       ORDER BY created_at DESC
       LIMIT 1`,
      [momoE164]
    );
    if (!rows.length) return { ok: false };
    return { ok: true, session_id: rows[0].session_id, consumed_at: rows[0].consumed_at };
  }

  const [rows] = await db.promise().query(
    `SELECT session_id, verified_until, consumed_at, momo_e164
     FROM momo_otp_sessions
     WHERE session_id = ?
     LIMIT 1`,
    [sid]
  );
  if (!rows.length) return { ok: false };

  const rec = rows[0];
  if (rec.momo_e164 !== momoE164) return { ok: false };

  const verifiedOk = rec.verified_until && new Date(rec.verified_until).getTime() > Date.now();
  if (!verifiedOk) return { ok: false };

  return { ok: true, session_id: rec.session_id, consumed_at: rec.consumed_at };
}














// =======================
// MTN PRICES ENDPOINT
// =======================
app.get("/api/mtn-prices", (req, res) => {
  const sql = `
    SELECT id, network, package_name, price, status, created_at, updated_at
    FROM admin_prices
    WHERE LOWER(TRIM(network)) = 'mtn'
      AND LOWER(TRIM(status)) = 'active'
    ORDER BY price ASC
  `;
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).json({ ok: false, message: "DB error" });
    res.json({ ok: true, rows: rows || [] });
  });
});

// =======================
// THETELLER CONFIG
// =======================
const THETELLER = {
  endpoint: "https://prod.theteller.net/v1.1/transaction/process",
  statusBase: "https://prod.theteller.net/v1.1/users/transactions",
  merchantId: process.env.THETELLER_MERCHANT_ID || "TTM-00009388",
  username: process.env.THETELLER_USERNAME || "louis66a20ac942e74",
  apiKey: process.env.THETELLER_API_KEY || "ZmVjZWZlZDc2MzA4OWU0YmZhOTk5MDBmMDAxNDhmOWY=",
};
THETELLER.basicToken = Buffer.from(`${THETELLER.username}:${THETELLER.apiKey}`).toString("base64");

// Helpers
function thetellerAmount12(ghsAmount) {
  const pesewas = Math.round(Number(ghsAmount || 0) * 100);
  return String(pesewas).padStart(12, "0");
}
function getSwitchCode(network) {
  const n = String(network || "").toLowerCase().trim();
  if (n === "mtn" || n.includes("mtn")) return "MTN";
  if (n.includes("airteltigo") || n.includes("airtel") || n.includes("tigo") || n.includes("atl")) return "ATL";
  if (n.includes("telecel") || n.includes("vodafone") || n.includes("voda") || n.includes("vdf")) return "VDF";
  return null;
}
function formatMsisdnForTheTeller(msisdn) {
  let n = String(msisdn || "").trim().replace(/[^\d]/g, "");
  if (n.startsWith("0") && n.length === 10) n = "233" + n.slice(1);
  if (n.length === 9) n = "233" + n;
  if (n.startsWith("233") && n.length === 12) return n;
  return n;
}
function makeTransactionId() {
  return `EDATA-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
}
function isInitAccepted(data) {
  const status = String(data?.status || "").toLowerCase();
  const code = String(data?.code || "");
  const goodWords = ["approved","success","successful","pending","processing","initiated","queued","accepted","ok"];
  if (goodWords.some(w => status.includes(w))) return true;
  const goodCodes = new Set(["00","000","200","201","202","100","101","102","099"]);
  if (goodCodes.has(code)) return true;
  if (data?.transaction_id || data?.reference) return true;
  return false;
}

// Minimal MoMo network detection by prefix (Ghana)
function detectMomoNetwork(msisdn) {
  const d = String(msisdn || "").replace(/\D/g, "");
  const prefix = d.startsWith("233") ? "0" + d.slice(3, 6) : d.slice(0, 3);

  // MTN
  if (["024","025","053","054","055","059"].includes(prefix)) return "mtn";
  // AirtelTigo
  if (["026","027","056","057"].includes(prefix)) return "airteltigo";
  // Telecel/Vodafone
  if (["020","050"].includes(prefix)) return "telecel";

  return "";
}

// ===============================
// PENDING STORE (MEMORY)
// ===============================
const pendingOrders = new Map();



// =====================================================
// POST /api/buy-data-theteller
// body: { package_id, momo_number, recipient_number, vendor_id, otp_session_id }
// =====================================================
app.post("/api/buy-data-theteller", async (req, res) => {
  const { package_id, momo_number, recipient_number, vendor_id } = req.body;

  // ✅ accept both names to avoid frontend mismatch
  const otp_session_id = req.body.otp_session_id || req.body.session_id;

  const vid = Number(vendor_id || 1);

  if (!package_id || !momo_number || !recipient_number) {
    return res.json({ ok: false, message: "Missing required fields." });
  }

  // ✅ verify OTP in DB
  const otpCheck = await isOtpVerifiedNow(momo_number, otp_session_id);
  if (!otpCheck.ok) {
    return res.json({ ok: false, message: "OTP not verified. Please verify OTP first." });
  }

  // ✅ consume OTP session so it cannot be reused (prevents double prompts)
  // (If you don’t want this, you can remove this block)
  try {
    const conn = await db.promise().getConnection();
    try {
      await conn.beginTransaction();

      const [sessRows] = await conn.query(
        `SELECT session_id, consumed_at, verified_until
         FROM momo_otp_sessions
         WHERE session_id=?
         FOR UPDATE`,
        [otpCheck.session_id]
      );

      if (!sessRows.length) {
        await conn.rollback();
        conn.release();
        return res.json({ ok: false, message: "OTP session not found. Please verify again." });
      }

      const sess = sessRows[0];
      if (!sess.verified_until || new Date(sess.verified_until).getTime() <= Date.now()) {
        await conn.rollback();
        conn.release();
        return res.json({ ok: false, message: "OTP session expired. Please verify again." });
      }

      if (sess.consumed_at) {
        await conn.rollback();
        conn.release();
        return res.json({ ok: false, message: "OTP already used. Please request a new OTP." });
      }

      await conn.query(
        `UPDATE momo_otp_sessions SET consumed_at=NOW() WHERE session_id=?`,
        [otpCheck.session_id]
      );

      await conn.commit();
      conn.release();
    } catch (e) {
      await conn.rollback();
      conn.release();
      console.error("OTP consume tx error:", e.message);
      return res.status(500).json({ ok: false, message: "Could not start payment." });
    }
  } catch (e) {
    console.error("OTP consume error:", e.message);
    return res.status(500).json({ ok: false, message: "Could not start payment." });
  }

  try {
    const [rows] = await db.promise().query(
      "SELECT id, package_name, price, network FROM admin_prices WHERE id=? AND status='active' LIMIT 1",
      [package_id]
    );
    if (!rows.length) return res.json({ ok: false, message: "Package not found or inactive." });

    const pkg = rows[0];

    const payerNet = detectMomoNetwork(momo_number);
    const rSwitch = getSwitchCode(payerNet);
    if (!rSwitch) return res.json({ ok: false, message: "Unsupported payer network." });

    const transactionId = makeTransactionId();

    // ✅ insert pending first
    await db.promise().query(
      `INSERT INTO orders
        (transaction_id, vendor_id, network, package_id, package_name, amount, recipient_number, momo_number, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
      [
        transactionId,
        vid,
        String(pkg.network || "").toLowerCase(),
        Number(pkg.id),
        String(pkg.package_name),
        Number(pkg.price),
        String(recipient_number),
        String(momo_number),
      ]
    );

    // ✅ theteller init
    const payload = {
      amount: thetellerAmount12(pkg.price),
      processing_code: "000200",
      transaction_id: transactionId,
      desc: `EDATA Bundle - ${pkg.package_name}`,
      merchant_id: THETELLER.merchantId,
      subscriber_number: formatMsisdnForTheTeller(momo_number),
      "r-switch": rSwitch,
      redirect_url: process.env.THETELLER_REDIRECT_URL || "https://edatagh.com/payment-callback",
    };

    const tt = await axios.post(THETELLER.endpoint, payload, {
      headers: {
        "Content-Type": "application/json",
        Authorization: `Basic ${THETELLER.basicToken}`,
        "Cache-Control": "no-cache",
      },
      timeout: 30000,
    });

    if (!isInitAccepted(tt.data)) {
      await db.promise().query(
        `UPDATE orders
         SET status='failed', raw_status=?
         WHERE transaction_id=? AND status='pending'`,
        [JSON.stringify(tt.data), transactionId]
      );
      return res.json({ ok: false, message: "Payment prompt not accepted.", theteller: tt.data });
    }

    await db.promise().query(
      `UPDATE orders
       SET raw_status=?
       WHERE transaction_id=? AND status='pending'`,
      [JSON.stringify(tt.data), transactionId]
    );

    return res.json({
      ok: true,
      message: "✅ Prompt sent. Please approve on your phone.",
      transaction_id: transactionId,
      vendor_id: vid,
    });
  } catch (err) {
    console.error("❌ TheTeller INIT error:", err.response?.data || err.message);
    return res.status(500).json({ ok: false, message: "Payment could not be initiated." });
  }
});

// GET /api/theteller-status?transaction_id=...
app.get("/api/theteller-status", async (req, res) => {
  const transaction_id = String(req.query.transaction_id || "").trim();
  if (!transaction_id) return res.json({ ok: false, status: "unknown" });

  try {
    const url = `${THETELLER.statusBase}/${encodeURIComponent(transaction_id)}/status`;

    const resp = await axios.get(url, {
      headers: {
        Authorization: `Basic ${THETELLER.basicToken}`,
        "Merchant-Id": THETELLER.merchantId,
        "Cache-Control": "no-cache",
      },
      timeout: 30000,
    });

    const raw = resp.data || {};
    const statusRaw = raw.status ?? raw.Status ?? raw.transaction_status ?? raw.state ?? "";
    const codeRaw = raw.code ?? raw.Code ?? raw.response_code ?? "";

    const status = String(statusRaw).toLowerCase().trim();
    const code = String(codeRaw).trim();

    const approved =
      code === "000" || code === "00" || code === "0" ||
      status.includes("success") || status.includes("approved") || status.includes("paid") || status.includes("complete");

    const failed =
      status.includes("fail") || status.includes("decline") || status.includes("cancel") ||
      ["failed","declined","cancelled","canceled","reversed"].includes(status);

    const pending =
      status.includes("pending") || status.includes("processing") || status.includes("progress") ||
      status.includes("initiated") || status.includes("queued") || code === "099";

    // ✅ APPROVED -> UPDATE ORDER
    if (approved) {
      await db.promise().query(
        `UPDATE orders
         SET status='approved', raw_status=?
         WHERE transaction_id=? AND status <> 'approved'`,
        [JSON.stringify(raw), transaction_id]
      );

      return res.json({ ok: true, status: "approved", raw });
    }

    // ✅ FAILED -> UPDATE ORDER
    if (failed) {
      await db.promise().query(
        `UPDATE orders
         SET status='failed', raw_status=?
         WHERE transaction_id=? AND status <> 'failed'`,
        [JSON.stringify(raw), transaction_id]
      );

      return res.json({ ok: true, status: "failed", raw });
    }

    // ✅ PENDING -> keep as pending (no update needed)
    if (pending) return res.json({ ok: true, status: "pending", raw });

    return res.json({ ok: true, status: status || "unknown", raw });
  } catch (e) {
    console.error("❌ TheTeller status error:", e.response?.data || e.message);
    return res.json({ ok: false, status: "unknown" });
  }
});





// =====================================================
// ✅ BACKGROUND JOB (PROD): updates even if user closes page
// =====================================================
const AUTO_CONFIRM_INTERVAL_MS = 20 * 1000; // 20 seconds
const PENDING_LOOKBACK_HOURS = 48;          // check pending up to 48 hours
const PENDING_BATCH_SIZE = 60;              // per run
const EXPIRE_AFTER_MINUTES = 360;           // 6 hours (adjust if you want)

async function fetchTheTellerStatus(transaction_id) {
  const url = `${THETELLER.statusBase}/${encodeURIComponent(transaction_id)}/status`;

  const resp = await axios.get(url, {
    headers: {
      Authorization: `Basic ${THETELLER.basicToken}`,
      "Merchant-Id": THETELLER.merchantId,
      "Cache-Control": "no-cache",
    },
    timeout: 30000,
  });

  const raw = resp.data || {};
  const statusRaw = raw.status ?? raw.Status ?? raw.transaction_status ?? raw.state ?? "";
  const codeRaw = raw.code ?? raw.Code ?? raw.response_code ?? "";

  const status = String(statusRaw).toLowerCase().trim();
  const code = String(codeRaw).trim();

  const approved =
    ["000", "00", "0"].includes(code) ||
    status.includes("approved") ||
    status.includes("success") ||
    status.includes("paid") ||
    status.includes("complete");

  const failed =
    status.includes("fail") ||
    status.includes("decline") ||
    status.includes("cancel") ||
    ["failed", "declined", "cancelled", "canceled", "reversed"].includes(status);

  const pending =
    status.includes("pending") ||
    status.includes("processing") ||
    status.includes("progress") ||
    status.includes("initiated") ||
    status.includes("queued") ||
    code === "099";

  return { raw, approved, failed, pending, status, code };
}

async function checkAndUpdatePendingOrders() {
  try {
    // expire very old pendings (optional safety)
    await db.promise().query(
      `UPDATE orders
       SET status='expired'
       WHERE status='pending'
         AND created_at < (NOW() - INTERVAL ? MINUTE)`,
      [EXPIRE_AFTER_MINUTES]
    );

    const [pendingRows] = await db.promise().query(
      `SELECT transaction_id
       FROM orders
       WHERE status='pending'
         AND created_at >= (NOW() - INTERVAL ? HOUR)
       ORDER BY created_at DESC
       LIMIT ?`,
      [PENDING_LOOKBACK_HOURS, PENDING_BATCH_SIZE]
    );

    if (!pendingRows.length) return;

    for (const row of pendingRows) {
      const transaction_id = String(row.transaction_id || "").trim();
      if (!transaction_id) continue;

      try {
        const r = await fetchTheTellerStatus(transaction_id);

        if (r.approved) {
          await db.promise().query(
            `UPDATE orders
             SET status='approved', raw_status=?
             WHERE transaction_id=? AND status='pending'`,
            [JSON.stringify(r.raw), transaction_id]
          );
        } else if (r.failed) {
          await db.promise().query(
            `UPDATE orders
             SET status='failed', raw_status=?
             WHERE transaction_id=? AND status='pending'`,
            [JSON.stringify(r.raw), transaction_id]
          );
        }
      } catch (innerErr) {
        console.error("Auto-confirm status error:", transaction_id, innerErr?.response?.data || innerErr.message);
      }
    }
  } catch (err) {
    console.error("Auto-confirm job error:", err.message);
  }
}

setInterval(checkAndUpdatePendingOrders, AUTO_CONFIRM_INTERVAL_MS);
console.log("✅ Auto-confirm job started (PROD).");






const ExcelJS = require("exceljs");

// ===============================
// ADMIN: COUNT APPROVED (BADGES)
// ===============================
app.get("/api/admin/approved-counts", async (req, res) => {
  try {
    const [rows] = await db.promise().query(`
      SELECT network, COUNT(*) as count
      FROM orders
      WHERE status='approved'
      GROUP BY network
    `);

    const counts = { mtn: 0, telecel: 0, airteltigo: 0 };
    for (const r of rows) {
      const k = String(r.network || "").toLowerCase();
      if (k in counts) counts[k] = Number(r.count || 0);
    }
    res.json({ ok: true, counts });
  } catch (e) {
    console.error("approved-counts error:", e.message);
    res.status(500).json({ ok: false, message: "DB error" });
  }
});

// ==============================================
// ADMIN: LIST DOWNLOADED BATCHES BY NETWORK
// ==============================================
app.get("/api/admin/order-batches", async (req, res) => {
  const network = String(req.query.network || "").toLowerCase().trim();
  if (!["mtn", "telecel", "airteltigo"].includes(network)) {
    return res.status(400).json({ ok: false, message: "Invalid network" });
  }

  try {
    const [rows] = await db.promise().query(
      `
      SELECT 
        download_batch,
        network,
        COUNT(*) AS items,
        MIN(downloaded_at) AS downloaded_at,
        SUM(CASE WHEN delivered_at IS NOT NULL THEN 1 ELSE 0 END) AS delivered_items
      FROM orders
      WHERE network=? AND download_batch IS NOT NULL
      GROUP BY download_batch, network
      ORDER BY MIN(downloaded_at) DESC
      `,
      [network]
    );

    // include details for each batch
    const batches = [];
    for (const b of rows) {
      const [items] = await db.promise().query(
        `SELECT id, package_name, amount, recipient_number, momo_number, status
         FROM orders
         WHERE download_batch=? ORDER BY id ASC`,
        [b.download_batch]
      );

      batches.push({
        download_batch: b.download_batch,
        network: b.network,
        items_count: Number(b.items || 0),
        downloaded_at: b.downloaded_at,
        delivered_items: Number(b.delivered_items || 0),
        all_delivered: Number(b.delivered_items || 0) === Number(b.items || 0),
        items,
      });
    }

    res.json({ ok: true, batches });
  } catch (e) {
    console.error("order-batches error:", e.message);
    res.status(500).json({ ok: false, message: "DB error" });
  }
});




function extractGbNumber(packageName) {
  const s = String(packageName || "").toLowerCase();

  // matches: 1gb, 2.5gb, 10 gb, etc
  const m = s.match(/(\d+(?:\.\d+)?)\s*gb/);
  if (m) return m[1]; // returns "5" or "2.5"

  return ""; // if not found
}


// =====================================================
// ADMIN: DOWNLOAD APPROVED ORDERS (AND MARK APPROVED->PENDING)
// =====================================================
// GET /api/admin/download-orders?network=mtn|telecel|airteltigo
app.get("/api/admin/download-orders", async (req, res) => {
  const network = String(req.query.network || "").toLowerCase().trim();
  if (!["mtn", "telecel", "airteltigo"].includes(network)) {
    return res.status(400).send("Invalid network");
  }

  const batchId = `DL-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

  try {
    // 1) pick approved that are not yet downloaded
    const [rows] = await db.promise().query(
      `
      SELECT id, transaction_id, package_name, amount, recipient_number, momo_number, network, created_at
      FROM orders
      WHERE network=? AND status='approved' AND download_batch IS NULL
      ORDER BY id ASC
      `,
      [network]
    );

    if (!rows.length) {
      return res.status(404).send("No approved orders to download.");
    }

    const ids = rows.map(r => r.id);

    // 2) mark them as downloaded batch + change approved -> pending (as you requested)
    await db.promise().query(
      `
      UPDATE orders
     SET download_batch=?, downloaded_at=NOW(), status='processing'
      WHERE id IN (${ids.map(() => "?").join(",")})
      `,
      [batchId, ...ids]
    );

    // 3) create Excel
    const wb = new ExcelJS.Workbook();
    const ws = wb.addWorksheet(`${network.toUpperCase()} Orders`);

 ws.columns = [
  { header: "Recipient Number", key: "recipient_number", width: 18 },
  { header: "GB", key: "gb", width: 10 },
];

   rows.forEach(r => {
  ws.addRow({
    recipient_number: r.recipient_number,
    gb: extractGbNumber(r.package_name),
  });
});


    res.setHeader(
      "Content-Disposition",
      `attachment; filename=${network}-orders-${batchId}.xlsx`
    );
    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );

    await wb.xlsx.write(res);
    res.end();
  } catch (e) {
    console.error("download-orders error:", e.message);
    res.status(500).send("Server error downloading orders.");
  }
});

// =======================================
// ADMIN: MARK ONE BATCH AS DELIVERED
// =======================================
// POST /api/admin/mark-delivered  body: { download_batch }
app.post("/api/admin/mark-delivered", async (req, res) => {
  const batch = String(req.body.download_batch || "").trim();
  if (!batch) return res.status(400).json({ ok: false, message: "Missing batch" });

  try {
   await db.promise().query(
  `UPDATE orders 
   SET delivered_at=NOW(), status='delivered'
   WHERE download_batch=?`,
  [batch]
);
    res.json({ ok: true, message: "Batch marked delivered." });
  } catch (e) {
    console.error("mark-delivered error:", e.message);
    res.status(500).json({ ok: false, message: "DB error" });
  }
});












// =====================================================
// ADMIN: GET FAILED + PENDING ORDERS (WITH SEARCH)
// GET /api/admin/error-orders?search=0532687733
// =====================================================
app.get("/api/admin/error-orders", async (req, res) => {
  const search = String(req.query.search || "").trim();

  try {
    let sql = `
      SELECT id, transaction_id, vendor_id, network, package_id, package_name,
             amount, recipient_number, momo_number, status, created_at
      FROM orders
      WHERE status IN ('failed','pending')
    `;
    const params = [];

    if (search) {
      sql += ` AND recipient_number = ? `;
      params.push(search);
    }

    sql += ` ORDER BY id DESC LIMIT 2000 `;

    const [rows] = await db.promise().query(sql, params);
    res.json({ ok: true, rows });
  } catch (e) {
    console.error("error-orders error:", e.message);
    res.status(500).json({ ok: false, message: "DB error" });
  }
});

// =====================================================
// ADMIN: DOWNLOAD SELECTED ERROR ORDERS AS EXCEL
// POST /api/admin/download-selected-errors
// body: { ids: [1,2,3] }
// After download -> status becomes 'processing' + batch is set
// =====================================================
app.post("/api/admin/download-selected-errors", async (req, res) => {
  const ids = Array.isArray(req.body.ids) ? req.body.ids.map(Number).filter(Boolean) : [];

  if (!ids.length) return res.status(400).send("No rows selected.");

  const batchId = `ERR-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

  try {
    // 1) Fetch only selectable rows (failed/pending)
    const placeholders = ids.map(() => "?").join(",");
    const [rows] = await db.promise().query(
      `
      SELECT id, transaction_id, vendor_id, network, package_id, package_name,
             amount, recipient_number, momo_number, status, created_at
      FROM orders
      WHERE id IN (${placeholders})
        AND status IN ('failed','pending')
      ORDER BY id ASC
      `,
      ids
    );

    if (!rows.length) {
      return res.status(404).send("Selected rows not found, or not in failed/pending.");
    }

    const realIds = rows.map(r => r.id);

    // 2) Update status -> processing and add batch so it shows on admin_download_orders.html
    await db.promise().query(
      `
      UPDATE orders
      SET status='processing',
          download_batch=?,
          downloaded_at=NOW()
      WHERE id IN (${realIds.map(() => "?").join(",")})
      `,
      [batchId, ...realIds]
    );

    // 3) Build Excel
    const wb = new ExcelJS.Workbook();
    const ws = wb.addWorksheet(`Recovered Orders`);

 ws.columns = [
  { header: "Recipient Number", key: "recipient_number", width: 18 },
  { header: "GB", key: "gb", width: 10 },
];

    rows.forEach(r => {
  ws.addRow({
    recipient_number: r.recipient_number,
    gb: extractGbNumber(r.package_name),
  });
});


    res.setHeader(
      "Content-Disposition",
      `attachment; filename=recovered-orders-${batchId}.xlsx`
    );
    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );

    await wb.xlsx.write(res);
    res.end();
  } catch (e) {
    console.error("download-selected-errors error:", e.message);
    res.status(500).send("Server error downloading selected orders.");
  }
});






// COUNT APPROVED ORDERS
app.get("/api/orders/approved-count", async (req, res) => {
  try {
    const [rows] = await db.promise().query(
      "SELECT COUNT(*) AS total FROM orders WHERE status = 'approved'"
    );

    res.json({ ok: true, total: rows[0].total });
  } catch (err) {
    console.error("Approved count error:", err.message);
    res.status(500).json({ ok: false, total: 0 });
  }
});


// COUNT ALL TRANSACTIONS (ALL ORDERS)
app.get("/api/orders/total-count", async (req, res) => {
  try {
    const [rows] = await db.promise().query(
      "SELECT COUNT(*) AS total FROM orders"
    );

    res.json({ ok: true, total: rows[0].total });
  } catch (err) {
    console.error("Total orders count error:", err.message);
    res.status(500).json({ ok: false, total: 0 });
  }
});


// TOTAL REVENUE (approved + processing)
app.get("/api/orders/total-revenue", async (req, res) => {
  try {
    const [rows] = await db.promise().query(
      `
      SELECT COALESCE(SUM(amount), 0) AS total
      FROM orders
      WHERE status IN ('approved', 'processing')
      `
    );

    res.json({ ok: true, total: rows[0].total });
  } catch (err) {
    console.error("Total revenue error:", err.message);
    res.status(500).json({ ok: false, total: 0 });
  }
});

// COUNT ERROR ORDERS (failed + expired)
app.get("/api/orders/error-count", async (req, res) => {
  try {
    const [rows] = await db.promise().query(
      `
      SELECT COUNT(*) AS total
      FROM orders
      WHERE status IN ('failed', 'expired')
      `
    );

    res.json({ ok: true, total: rows[0].total });
  } catch (err) {
    console.error("Error orders count error:", err.message);
    res.status(500).json({ ok: false, total: 0 });
  }
});






/////////////////////////////////////////////////////////////////////////////////////////////////////////
// ================================
// AFA: CREATE DRAFT
// ================================
app.post("/api/afa/create-draft", async (req, res) => {
  try {
    const {
      full_name, phone_number, id_number,
      date_of_birth, town, occupation, email,
      price
    } = req.body;

    if (!full_name || !phone_number || !id_number || !date_of_birth || !town || !occupation || !email) {
      return res.json({ ok:false, message:"All fields are required." });
    }

    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email));
    if (!emailOk) return res.json({ ok:false, message:"Invalid email address." });

    const p = Number(price || 15);
    if (!Number.isFinite(p) || p <= 0) return res.json({ ok:false, message:"Invalid price." });

    const [ins] = await db.promise().query(
      `INSERT INTO afa_registrations
        (full_name, phone_number, id_number, date_of_birth, town, occupation, email, price, payment_status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'draft')`,
      [full_name, phone_number, id_number, date_of_birth, town, occupation, email, p]
    );

    return res.json({ ok:true, registration_id: ins.insertId, price: p });
  } catch (e) {
    console.error("AFA create-draft error:", e.message);
    return res.status(500).json({ ok:false, message:"Server error creating draft." });
  }
});


// ================================
// AFA: PAY (OTP must be verified)
// ================================
app.post("/api/afa/pay", async (req, res) => {
  const { registration_id, momo_number } = req.body;
  const otp_session_id = req.body.otp_session_id || req.body.session_id;

  if (!registration_id || !momo_number || !otp_session_id) {
    return res.json({ ok:false, message:"Missing required fields." });
  }

  // ✅ OTP verified?
  const otpCheck = await isOtpVerifiedNow(momo_number, otp_session_id);
  if (!otpCheck.ok) {
    return res.json({ ok:false, message:"OTP not verified. Please verify OTP first." });
  }

  try {
    // fetch registration
const [rows] = await db.promise().query(
  `SELECT id, price, payment_status, phone_number, transaction_id
   FROM afa_registrations
   WHERE id=? LIMIT 1`,
  [Number(registration_id)]
);

    if (!rows.length) return res.json({ ok:false, message:"Registration not found." });

    const reg = rows[0];
    if (reg.payment_status === "approved") {
      return res.json({ ok:true, message:"Already approved.", transaction_id: reg.transaction_id });
    }

    const payerNet = detectMomoNetwork(momo_number);
    const rSwitch = getSwitchCode(payerNet);
    if (!rSwitch) return res.json({ ok:false, message:"Unsupported payer network." });

    const transactionId = makeTransactionId();
    const amount = Number(reg.price || 15);

    // mark pending + save momo
    await db.promise().query(
      `UPDATE afa_registrations
       SET momo_number=?, transaction_id=?, payment_status='pending'
       WHERE id=?`,
      [String(momo_number), transactionId, Number(registration_id)]
    );

    // store payment attempt
  await db.promise().query(
  `INSERT INTO afa_payments 
    (registration_id, transaction_id, amount, momo_number, phone_number, status)
   VALUES (?, ?, ?, ?, ?, 'pending')`,
  [
    Number(registration_id),
    transactionId,
    amount,
    String(momo_number),     // payer MoMo number
    String(reg.phone_number) // ✅ actual AFA receiving number
  ]
);


    // theteller init
    const payload = {
      amount: thetellerAmount12(amount),
      processing_code: "000200",
      transaction_id: transactionId,
      desc: `EDATA AFA Registration`,
      merchant_id: THETELLER.merchantId,
      subscriber_number: formatMsisdnForTheTeller(momo_number),
      "r-switch": rSwitch,
      redirect_url: process.env.THETELLER_REDIRECT_URL || "https://edatagh.com/payment-callback",
    };

    const tt = await axios.post(THETELLER.endpoint, payload, {
      headers: {
        "Content-Type": "application/json",
        Authorization: `Basic ${THETELLER.basicToken}`,
        "Cache-Control": "no-cache",
      },
      timeout: 30000,
    });

    if (!isInitAccepted(tt.data)) {
      await db.promise().query(
        `UPDATE afa_registrations SET payment_status='failed', raw_status=? WHERE id=?`,
        [JSON.stringify(tt.data), Number(registration_id)]
      );
      await db.promise().query(
        `UPDATE afa_payments SET status='failed', raw_status=? WHERE transaction_id=?`,
        [JSON.stringify(tt.data), transactionId]
      );

      return res.json({ ok:false, message:"Payment prompt not accepted.", theteller: tt.data });
    }

    // save init response
    await db.promise().query(
      `UPDATE afa_payments SET raw_status=? WHERE transaction_id=?`,
      [JSON.stringify(tt.data), transactionId]
    );

    return res.json({
      ok:true,
      message:"✅ Prompt sent. Please approve on your phone.",
      transaction_id: transactionId
    });
  } catch (e) {
    console.error("AFA pay error:", e.response?.data || e.message);
    return res.status(500).json({ ok:false, message:"Payment could not be initiated." });
  }
});


// ================================
// AFA: STATUS (checks payment + updates if approved)
// ================================
app.get("/api/afa/status", async (req, res) => {
  const transaction_id = String(req.query.transaction_id || "").trim();
  if (!transaction_id) return res.json({ ok:false, status:"unknown" });

  try {
    const url = `${THETELLER.statusBase}/${encodeURIComponent(transaction_id)}/status`;
    const resp = await axios.get(url, {
      headers: {
        Authorization: `Basic ${THETELLER.basicToken}`,
        "Merchant-Id": THETELLER.merchantId,
        "Cache-Control": "no-cache",
      },
      timeout: 30000,
    });

    const raw = resp.data || {};
    const statusRaw = raw.status ?? raw.Status ?? raw.transaction_status ?? raw.state ?? "";
    const codeRaw = raw.code ?? raw.Code ?? raw.response_code ?? "";

    const status = String(statusRaw).toLowerCase().trim();
    const code = String(codeRaw).trim();

    const approved =
      ["000", "00", "0"].includes(code) ||
      status.includes("success") ||
      status.includes("approved") ||
      status.includes("paid") ||
      status.includes("complete");

    const failed =
      status.includes("fail") || status.includes("decline") || status.includes("cancel") ||
      ["failed","declined","cancelled","canceled","reversed"].includes(status);

    if (approved) {
      // update both tables to approved
      await db.promise().query(
        `UPDATE afa_payments SET status='approved', raw_status=? WHERE transaction_id=?`,
        [JSON.stringify(raw), transaction_id]
      );
      await db.promise().query(
        `UPDATE afa_registrations
         SET payment_status='approved', raw_status=?
         WHERE transaction_id=?`,
        [JSON.stringify(raw), transaction_id]
      );

      return res.json({ ok:true, status:"approved", raw });
    }

    if (failed) {
      await db.promise().query(
        `UPDATE afa_payments SET status='failed', raw_status=? WHERE transaction_id=?`,
        [JSON.stringify(raw), transaction_id]
      );
      await db.promise().query(
        `UPDATE afa_registrations
         SET payment_status='failed', raw_status=?
         WHERE transaction_id=?`,
        [JSON.stringify(raw), transaction_id]
      );

      return res.json({ ok:true, status:"failed", raw });
    }

    return res.json({ ok:true, status:"pending", raw });
  } catch (e) {
    console.error("AFA status error:", e.response?.data || e.message);
    return res.json({ ok:false, status:"unknown" });
  }
});














// ================================
// GET approved count (badge)
// ================================
app.get("/api/admin/afa/approved-count", async (req, res) => {
  try {
    const [rows] = await db.promise().query(
      `SELECT COUNT(*) AS total
       FROM afa_payments
       WHERE status='approved'`
    );
    return res.json({ ok: true, total: Number(rows[0]?.total || 0) });
  } catch (e) {
    console.error("AFA approved-count error:", e.message);
    return res.status(500).json({ ok: false, message: "DB error" });
  }
});


// ================================
// GET batches (downloaded/delivered grouped by package_id)
// ================================
app.get("/api/admin/afa/batches", async (req, res) => {
  try {
    const [rows] = await db.promise().query(
      `
      SELECT
        package_id,
        status,
        COUNT(*) AS count,
        MIN(downloaded_at) AS downloaded_at,
        MIN(delivered_at) AS delivered_at
      FROM afa_payments
      WHERE package_id IS NOT NULL
        AND status IN ('downloaded','delivered')
      GROUP BY package_id, status
      ORDER BY downloaded_at DESC
      `
    );

    return res.json({ ok: true, batches: rows });
  } catch (e) {
    console.error("AFA batches error:", e.message);
    return res.status(500).json({ ok: false, message: "DB error" });
  }
});


// ================================
// DOWNLOAD approved orders as Excel
// - selects all status='approved'
// - assigns a package_id
// - marks them status='downloaded'
// - excel contains ONLY phone_number column
// ================================
app.get("/api/admin/afa/download", async (req, res) => {
  try {
    // ✅ fetch approved rows
    const [rows] = await db.promise().query(
      `SELECT id, phone_number
       FROM afa_payments
       WHERE status='approved'
       ORDER BY created_at ASC`
    );

    if (!rows.length) {
      return res.status(400).json({ ok: false, message: "No approved AFA orders to download." });
    }

    const packageId = "AFA_" + Date.now(); // batch id

    // ✅ mark as downloaded in ONE query
    const ids = rows.map(r => r.id);
    await db.promise().query(
      `UPDATE afa_payments
       SET status='downloaded',
           package_id=?,
           downloaded_at=NOW()
       WHERE id IN (?)`,
      [packageId, ids]
    );

    // ✅ create excel (ONLY phone_number)
    const wb = new ExcelJS.Workbook();
    const ws = wb.addWorksheet("AFA Orders");

    ws.columns = [
      { header: "phone_number", key: "phone_number", width: 20 },
    ];

    rows.forEach(r => ws.addRow({ phone_number: String(r.phone_number || "") }));

    // styling (simple)
    ws.getRow(1).font = { bold: true };

    res.setHeader(
      "Content-Disposition",
      `attachment; filename="AFA_Orders_${packageId}.xlsx"`
    );
    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );

    await wb.xlsx.write(res);
    res.end();

  } catch (e) {
    console.error("AFA download error:", e.message);
    return res.status(500).json({ ok: false, message: "Failed to download AFA orders." });
  }
});


// ================================
// MARK batch as delivered
// ================================
app.post("/api/admin/afa/mark-delivered", async (req, res) => {
  try {
    const package_id = String(req.body?.package_id || "").trim();
    if (!package_id) return res.json({ ok: false, message: "Missing package_id" });

    const [r] = await db.promise().query(
      `UPDATE afa_payments
       SET status='delivered',
           delivered_at=NOW()
       WHERE package_id=?
         AND status='downloaded'`,
      [package_id]
    );

    return res.json({ ok: true, message: "Marked delivered.", updated: r.affectedRows });
  } catch (e) {
    console.error("AFA mark-delivered error:", e.message);
    return res.status(500).json({ ok: false, message: "DB error" });
  }
});

// ================================
// GET phone numbers in a batch
// ================================
// GET full details in a batch
// ================================
app.get("/api/admin/afa/batch/:package_id", async (req, res) => {
  try {
    const package_id = String(req.params.package_id || "").trim();
    if (!package_id) return res.json({ ok: false, message: "Missing package_id" });

    const [rows] = await db.promise().query(
      `SELECT package_id, phone_number, momo_number, amount, status
       FROM afa_payments
       WHERE package_id=?
       ORDER BY id ASC`,
      [package_id]
    );

    return res.json({ ok: true, package_id, total: rows.length, items: rows });
  } catch (e) {
    console.error("AFA batch details error:", e.message);
    return res.status(500).json({ ok: false, message: "DB error" });
  }
});


// DELETE admin price
app.delete("/api/admin-prices/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.json({ ok: false, message: "Invalid ID" });

    const [result] = await db.promise().query(
      "DELETE FROM admin_prices WHERE id=? LIMIT 1",
      [id]
    );

    if (!result.affectedRows) {
      return res.json({ ok: false, message: "Price not found." });
    }

    return res.json({ ok: true, message: "Deleted." });
  } catch (e) {
    console.error("Delete admin price error:", e.message);
    return res.status(500).json({ ok: false, message: "DB error" });
  }
});




app.post("/api/admin/delete-selected-errors", (req, res) => {
  const ids = req.body.ids;

  if (!Array.isArray(ids) || !ids.length) {
    return res.json({ ok: false, message: "No IDs provided." });
  }

  const sql = `DELETE FROM admin_orders WHERE id IN (?) AND status IN ('failed','pending')`;

  db.query(sql, [ids], (err, result) => {
    if (err) return res.status(500).json({ ok: false, message: "DB error" });
    return res.json({ ok: true, deleted: result.affectedRows });
  });
});







app.listen(PORT, () => {
  console.log(`EDATA server running on port ${PORT}`);
});
