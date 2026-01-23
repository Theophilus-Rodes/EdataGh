const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const session = require("express-session");
const path = require("path");
const cors = require("cors");
const axios = require("axios");

const PORT = process.env.PORT || 3000;

// Africa's Talking
const AfricasTalking = require("africastalking");

const app = express();
app.use(cors());
app.set("trust proxy", 1); // ✅ required on DigitalOcean App Platform

app.use(cors({
  origin: ["https://edatagh.com", "http://localhost:8080"],
  credentials: true
}));


// Parse JSON & form data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Sessions
app.use(session({
  name: "edata.sid",
  secret: "edata_secret_key",
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    httpOnly: true,
    secure: true,      // ✅ HTTPS only (you are on https)
    sameSite: "lax",   // ✅ works for same-site (edatagh.com + /edatagh-backend)
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  }
}));

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("edata.sid");
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












////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ============================
//  AFRICA'S TALKING OTP (SMS)
// ============================
const AT_USERNAME = "EdataSell";
const AT_API_KEY = "atsk_91c3d30e1254e773f8bf39bb8e26c7be3ee7e366061e1de8af3a9f4e724a96bfd09826bf"; // rotate first
const AT_SENDER_ID = "";
const OTP_TTL = 300 * 1000;

const at = AfricasTalking({ username: AT_USERNAME, apiKey: AT_API_KEY });
const sms = at.SMS;

// In-memory OTP store: momo -> { otp, expiresAt, attempts, sessionId, verifiedUntil }
const otpStore = new Map();

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
  return "otp_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2, 9);
}

async function sendOtpSmsAfricaTalking(toE164, otp) {
  const message = `EDATA OTP: ${otp}\nExpires in ${Math.round(OTP_TTL / 60000)} minutes. Do not share this code.`;

  const options = { to: [toE164], message };
  if (AT_SENDER_ID && AT_SENDER_ID.trim()) options.from = AT_SENDER_ID.trim();

  return sms.send(options);
}

// POST /api/send-momo-otp  body: { momo_number }
app.post("/api/send-momo-otp", async (req, res) => {
  try {
    const momoRaw = req.body?.momo_number;
    const momoE164 = normalizePhoneToE164Ghana(momoRaw);

    if (!momoE164) return res.json({ ok: false, message: "Invalid MoMo number format." });

    const existing = otpStore.get(momoE164);
    if (existing && Date.now() < existing.expiresAt) {
      return res.json({ ok: false, message: "OTP already sent. Please check your SMS." });
    }

    const otp = generateOtp(6);
    const sessionId = genSessionId();
    const expiresAt = Date.now() + OTP_TTL;

    otpStore.set(momoE164, { otp, expiresAt, attempts: 0, sessionId, verifiedUntil: 0 });

    await sendOtpSmsAfricaTalking(momoE164, otp);

    return res.json({ ok: true, message: "OTP sent successfully.", session_id: sessionId });
  } catch (err) {
    console.error("❌ send-momo-otp error:", err?.response?.data || err);
    return res.status(500).json({ ok: false, message: "Failed to send OTP." });
  }
});

// POST /api/verify-momo-otp  body: { momo_number, otp, session_id }
app.post("/api/verify-momo-otp", (req, res) => {
  try {
    const momoRaw = req.body?.momo_number;
    const otp = String(req.body?.otp || "").trim();
    const sessionId = String(req.body?.session_id || "").trim();

    const momoE164 = normalizePhoneToE164Ghana(momoRaw);
    if (!momoE164) return res.json({ ok: false, message: "Invalid MoMo number." });
    if (!/^\d{4,8}$/.test(otp)) return res.json({ ok: false, message: "Invalid OTP code." });

    const rec = otpStore.get(momoE164);
    if (!rec) return res.json({ ok: false, message: "No OTP request found. Please send OTP again." });

    if (sessionId && rec.sessionId !== sessionId) {
      return res.json({ ok: false, message: "OTP session mismatch. Please request a new OTP." });
    }

    if (Date.now() > rec.expiresAt) {
      otpStore.delete(momoE164);
      return res.json({ ok: false, message: "OTP expired. Please request a new OTP." });
    }

    rec.attempts = (rec.attempts || 0) + 1;
    if (rec.attempts > 5) {
      otpStore.delete(momoE164);
      return res.json({ ok: false, message: "Too many attempts. Please request a new OTP." });
    }

    if (otp !== rec.otp) {
      otpStore.set(momoE164, rec);
      return res.json({ ok: false, message: "Incorrect OTP." });
    }

    rec.verifiedUntil = Date.now() + (10 * 60 * 1000); // 10 minutes
    otpStore.set(momoE164, rec);

    return res.json({ ok: true, message: "OTP verified." });
  } catch (err) {
    console.error("❌ verify-momo-otp error:", err);
    return res.status(500).json({ ok: false, message: "OTP verification failed." });
  }
});

function isOtpVerifiedNow(momoRaw) {
  const momoE164 = normalizePhoneToE164Ghana(momoRaw);
  if (!momoE164) return false;
  const rec = otpStore.get(momoE164);
  if (!rec) return false;
  return Date.now() < (rec.verifiedUntil || 0);
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

// POST /api/buy-data-theteller
// body: { package_id, momo_number, recipient_number, vendor_id }
app.post("/api/buy-data-theteller", async (req, res) => {
  const { package_id, momo_number, recipient_number, vendor_id } = req.body;
  const vid = Number(vendor_id || 1);

  if (!package_id || !momo_number || !recipient_number) {
    return res.json({ ok: false, message: "Missing required fields." });
  }

  if (!isOtpVerifiedNow(momo_number)) {
    return res.json({ ok: false, message: "OTP not verified. Please verify OTP first." });
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

    // ✅ 1) INSERT PENDING FIRST (so we never miss it)
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

    // ✅ 2) NOW call TheTeller
    const payload = {
      amount: thetellerAmount12(pkg.price),
      processing_code: "000200",
      transaction_id: transactionId,
      desc: `EDATA Bundle - ${pkg.package_name}`,
      merchant_id: THETELLER.merchantId,
      subscriber_number: formatMsisdnForTheTeller(momo_number),
      "r-switch": rSwitch,
      redirect_url: "https://example.com/payment-callback",
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
      // ✅ mark failed if init rejected
      await db.promise().query(
        `UPDATE orders
         SET status='failed', raw_status=?
         WHERE transaction_id=? AND status='pending'`,
        [JSON.stringify(tt.data), transactionId]
      );

      return res.json({ ok: false, message: "Payment prompt not accepted.", theteller: tt.data });
    }

    // optional: store init response
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

    // If the error happened after insert, background job can still confirm later.
    // If insert did not happen, you’ll see it in logs and can retry.
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

// ===========================================
// BACKGROUND JOB: AUTO CONFIRM PENDING ORDERS
// - Keeps working even if user closes the page
// - Updates orders only when TheTeller confirms
// - Expires old pending orders to avoid forever-pending
// ===========================================
const AUTO_CONFIRM_INTERVAL_MS = 30 * 1000; // 30 seconds
const PENDING_LOOKBACK_HOURS = 6;           // only check recent pendings
const PENDING_BATCH_SIZE = 25;              // how many to check per run
const EXPIRE_AFTER_MINUTES = 15;            // pending older than this -> expired

async function checkAndUpdatePendingOrders() {
  try {
    // ✅ 1) Expire old pending orders (no approval after X minutes)
    await db.promise().query(
      `UPDATE orders
       SET status='expired'
       WHERE status='pending'
         AND created_at < (NOW() - INTERVAL ? MINUTE)`,
      [EXPIRE_AFTER_MINUTES]
    );

    // ✅ 2) Fetch recent pending transactions to check with TheTeller
    const [pending] = await db.promise().query(
      `
      SELECT transaction_id
      FROM orders
      WHERE status='pending'
        AND created_at >= (NOW() - INTERVAL ? HOUR)
      ORDER BY created_at DESC
      LIMIT ?
      `,
      [PENDING_LOOKBACK_HOURS, PENDING_BATCH_SIZE]
    );

    if (!pending.length) return;

    // ✅ 3) Check each pending transaction status
    for (const row of pending) {
      const transaction_id = String(row.transaction_id || "").trim();
      if (!transaction_id) continue;

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

        // ✅ Strong confirmation checks
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

        if (approved) {
          // ✅ Mark approved only if still pending (prevents double updates)
          await db.promise().query(
            `UPDATE orders
             SET status='approved', raw_status=?
             WHERE transaction_id=? AND status='pending'`,
            [JSON.stringify(raw), transaction_id]
          );
        } else if (failed) {
          // ✅ Mark failed only if still pending
          await db.promise().query(
            `UPDATE orders
             SET status='failed', raw_status=?
             WHERE transaction_id=? AND status='pending'`,
            [JSON.stringify(raw), transaction_id]
          );
        }
        // pending/unknown -> do nothing, next run will check again

      } catch (innerErr) {
        // ignore this one and retry later
        console.error(
          "Auto-confirm status error:",
          transaction_id,
          innerErr?.response?.data || innerErr.message
        );
      }
    }
  } catch (err) {
    console.error("Auto-confirm job error:", err.message);
  }
}

// ✅ Start background auto-confirm
setInterval(checkAndUpdatePendingOrders, AUTO_CONFIRM_INTERVAL_MS);
console.log("✅ Auto-confirm job started.");







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



app.listen(PORT, () => {
  console.log(`EDATA server running on port ${PORT}`);
});
