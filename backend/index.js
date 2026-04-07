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


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


app.post("/api/agent/register", (req, res) => {
  try {
    const {
      first_name,
      last_name,
      phone,
      email,
      gender,
      address,
      pin,
      confirm_pin
    } = req.body || {};

    if (!first_name || !last_name || !phone || !email || !gender || !address || !pin || !confirm_pin) {
      return res.status(422).json({ ok: false, error: "All fields are required." });
    }

    const cleanPhone = normalizePhone(phone);
    const cleanEmail = String(email).trim().toLowerCase();
    const cleanGender = String(gender).trim();

    const allowedGender = ["Male", "Female", "Other"];
    if (!allowedGender.includes(cleanGender)) {
      return res.status(422).json({ ok: false, error: "Invalid gender." });
    }

    if (!isValidPin(pin)) {
      return res.status(422).json({ ok: false, error: "PIN must be exactly 4 digits." });
    }

    if (String(pin) !== String(confirm_pin)) {
      return res.status(422).json({ ok: false, error: "PINs do not match." });
    }

    // ✅ 1) Check phone/email exists
    db.query(
      "SELECT id FROM agents WHERE phone = ? OR email = ? LIMIT 1",
      [cleanPhone, cleanEmail],
      (err, existsRows) => {
        if (err) {
          console.error("REGISTER DB CHECK ERROR:", err);
          return res.status(500).json({ ok: false, error: "Database error." });
        }

        if (existsRows && existsRows.length > 0) {
          return res.status(409).json({ ok: false, error: "Phone number or email already exists." });
        }

        // ✅ 2) Check if PIN has been used by any agent (compare against hashed pins)
        db.query(
          "SELECT pin_hash FROM agents WHERE pin_hash IS NOT NULL",
          [],
          (pinErr, pinRows) => {
            if (pinErr) {
              console.error("REGISTER PIN LIST ERROR:", pinErr);
              return res.status(500).json({ ok: false, error: "Database error." });
            }

            // Compare pin with each pin_hash
            let i = 0;

            const checkNext = () => {
              if (!pinRows || i >= pinRows.length) {
                // ✅ PIN not used -> hash and create account
                return bcrypt.hash(String(pin), 10, (hashErr, hash) => {
                  if (hashErr) {
                    console.error("REGISTER HASH ERROR:", hashErr);
                    return res.status(500).json({ ok: false, error: "Server error." });
                  }

                  db.query(
                    `INSERT INTO agents
                     (first_name, last_name, phone, email, gender, address, pin_hash, status)
                     VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`,
                    [
                      String(first_name).trim(),
                      String(last_name).trim(),
                      cleanPhone,
                      cleanEmail,
                      cleanGender,
                      String(address).trim(),
                      hash
                    ],
                    (insErr) => {
                      if (insErr) {
                        console.error("REGISTER INSERT ERROR:", insErr);
                        return res.status(500).json({ ok: false, error: "Database insert failed." });
                      }

                      return res.json({
                        ok: true,
                        message: "Account created successfully. Await admin approval."
                      });
                    }
                  );
                });
              }

              const currentHash = String(pinRows[i].pin_hash || "");
              i++;

              bcrypt.compare(String(pin), currentHash, (cmpErr, same) => {
                if (cmpErr) {
                  console.error("REGISTER PIN COMPARE ERROR:", cmpErr);
                  return res.status(500).json({ ok: false, error: "Server error." });
                }

                if (same) {
                  return res.status(409).json({
                    ok: false,
                    error: "PIN already used. Choose a different PIN."
                  });
                }

                checkNext();
              });
            };

            checkNext();
          }
        );
      }
    );

  } catch (e) {
    console.error("REGISTER ERROR:", e);
    return res.status(500).json({ ok: false, error: "Server error." });
  }
});



app.post("/api/agent/login", (req, res) => {
  try {
    const { phone, pin } = req.body || {};

    if (!phone || !pin) {
      return res.status(422).json({ ok: false, error: "Phone and PIN are required." });
    }

    if (!isValidPin(pin)) {
      return res.status(422).json({ ok: false, error: "PIN must be exactly 4 digits." });
    }

    const cleanPhone = normalizePhone(phone);

    db.query(
      "SELECT id, first_name, last_name, phone, email, pin_hash, status FROM agents WHERE phone = ? LIMIT 1",
      [cleanPhone],
      (err, rows) => {
        if (err) {
          console.error("LOGIN DB ERROR:", err);
          return res.status(500).json({ ok: false, error: "Database error." });
        }

        if (!rows || rows.length === 0) {
          return res.status(401).json({ ok: false, error: "Invalid login details." });
        }

        const agent = rows[0];

        if (agent.status === "pending") {
          return res.status(403).json({ ok: false, error: "Contact admin to activate your account." });
        }

        if (agent.status !== "active") {
          return res.status(403).json({ ok: false, error: "Account is inactive." });
        }

        bcrypt.compare(String(pin), String(agent.pin_hash || ""), (cmpErr, ok) => {
          if (cmpErr) {
            console.error("LOGIN COMPARE ERROR:", cmpErr);
            return res.status(500).json({ ok: false, error: "Server error." });
          }

          if (!ok) {
            return res.status(401).json({ ok: false, error: "Invalid login details." });
          }

          return res.json({
            ok: true,
            message: "Login successful",
            agent: {
              id: agent.id,
              name: `${agent.first_name} ${agent.last_name}`,
              phone: agent.phone,
              email: agent.email
            }
          });
        });
      }
    );

  } catch (e) {
    console.error("LOGIN ERROR:", e);
    return res.status(500).json({ ok: false, error: "Server error." });
  }
});







// =============================
// EDATA ADMIN AGENTS API (mysql2 callback style)
// Table: agents
// status: pending | active | inactive
// =============================

// GET all agents
app.get("/api/admin/agents", (req, res) => {
  const sql = `
    SELECT id, first_name, last_name, phone, email, gender, address, status, created_at
    FROM agents
    ORDER BY id DESC
  `;

  db.query(sql, (err, rows) => {
    if (err) {
      console.error("GET /api/admin/agents error:", err);
      return res.status(500).json({ error: "Failed to fetch agents" });
    }
    return res.json(rows);
  });
});

// GET single agent by id (full details)
app.get("/api/admin/agents/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: "Invalid id" });

  db.query("SELECT * FROM agents WHERE id = ? LIMIT 1", [id], (err, rows) => {
    if (err) {
      console.error("GET /api/admin/agents/:id error:", err);
      return res.status(500).json({ error: "Failed to fetch agent" });
    }
    if (!rows || rows.length === 0) return res.status(404).json({ error: "Agent not found" });
    return res.json(rows[0]);
  });
});

// UPDATE status (pending/active/inactive)
app.put("/api/admin/agents/:id/status", (req, res) => {
  const id = parseInt(req.params.id, 10);
  const status = String(req.body.status || "").toLowerCase().trim();

  if (!id) return res.status(400).json({ error: "Invalid id" });

  const allowed = new Set(["pending", "active", "inactive"]);
  if (!allowed.has(status)) {
    return res.status(400).json({ error: "Invalid status. Use pending, active, inactive" });
  }

  db.query("UPDATE agents SET status = ? WHERE id = ?", [status, id], (err, result) => {
    if (err) {
      console.error("PUT /api/admin/agents/:id/status error:", err);
      return res.status(500).json({ error: "Failed to update status" });
    }
    if (!result || result.affectedRows === 0) return res.status(404).json({ error: "Agent not found" });

    return res.json({ success: true, id, status });
  });
});

// DELETE agent
app.delete("/api/admin/agents/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: "Invalid id" });

  db.query("DELETE FROM agents WHERE id = ?", [id], (err, result) => {
    if (err) {
      console.error("DELETE /api/admin/agents/:id error:", err);
      return res.status(500).json({ error: "Failed to delete agent" });
    }
    if (!result || result.affectedRows === 0) return res.status(404).json({ error: "Agent not found" });

    return res.json({ success: true });
  });
});




// ✅ GET agent profile
app.get("/api/agent/profile/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: "Invalid agent id" });

  const sql = `
    SELECT id, first_name, last_name, phone, email, gender, address, status, created_at
    FROM agents
    WHERE id = ?
    LIMIT 1
  `;

  db.query(sql, [id], (err, rows) => {
    if (err) {
      console.error("GET /api/agent/profile/:id error:", err);
      return res.status(500).json({ error: "Failed to load profile" });
    }
    if (!rows || rows.length === 0) return res.status(404).json({ error: "Agent not found" });
    return res.json(rows[0]);
  });
});



// ✅ UPDATE agent profile
app.put("/api/agent/profile/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: "Invalid agent id" });

  const first_name = String(req.body.first_name || "").trim();
  const last_name  = String(req.body.last_name || "").trim();
  const phone      = String(req.body.phone || "").trim();
  const email      = String(req.body.email || "").trim();
  const gender     = String(req.body.gender || "").trim();  // "Male" / "Female" etc
  const address    = String(req.body.address || "").trim();

  if (!first_name || !last_name || !phone) {
    return res.status(400).json({ error: "First name, last name and phone are required." });
  }

  const sql = `
    UPDATE agents
    SET first_name=?, last_name=?, phone=?, email=?, gender=?, address=?
    WHERE id=?
  `;

  db.query(sql, [first_name, last_name, phone, email, gender, address, id], (err, result) => {
    if (err) {
      console.error("PUT /api/agent/profile/:id error:", err);
      return res.status(500).json({ error: "Failed to update profile" });
    }
    if (!result || result.affectedRows === 0) return res.status(404).json({ error: "Agent not found" });
    return res.json({ success: true });
  });
});


// ✅ CHANGE agent password/PIN
app.put("/api/agent/profile/:id/change-pin", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: "Invalid agent id" });

  const old_pin = String(req.body.old_pin || "").trim();
  const new_pin = String(req.body.new_pin || "").trim();
  const confirm = String(req.body.confirm || "").trim();

  if (!old_pin || !new_pin || !confirm) {
    return res.status(400).json({ error: "Old PIN, new PIN and confirm PIN are required." });
  }
  if (new_pin !== confirm) {
    return res.status(400).json({ error: "New PIN and Confirm PIN do not match." });
  }
  if (new_pin.length < 4) {
    return res.status(400).json({ error: "New PIN must be at least 4 characters." });
  }

  // Get current hash
  db.query("SELECT pin_hash FROM agents WHERE id=? LIMIT 1", [id], (err, rows) => {
    if (err) {
      console.error("SELECT pin_hash error:", err);
      return res.status(500).json({ error: "Failed to change PIN" });
    }
    if (!rows || rows.length === 0) return res.status(404).json({ error: "Agent not found" });

    const currentHash = rows[0].pin_hash || "";

    // Compare old pin with hash
    const ok = bcrypt.compareSync(old_pin, currentHash);
    if (!ok) return res.status(400).json({ error: "Old PIN is incorrect." });

    // Hash new pin
    const newHash = bcrypt.hashSync(new_pin, 10);

    db.query("UPDATE agents SET pin_hash=? WHERE id=?", [newHash, id], (err2, result) => {
      if (err2) {
        console.error("UPDATE pin_hash error:", err2);
        return res.status(500).json({ error: "Failed to change PIN" });
      }
      if (!result || result.affectedRows === 0) return res.status(404).json({ error: "Agent not found" });

      return res.json({ success: true });
    });
  });
});
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////












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
  const network = (req.query.network || "").trim().toLowerCase();

  let sql = `
    SELECT id, network, package_name, price, status
    FROM admin_prices
    WHERE LOWER(status) = 'active'
  `;

  const params = [];

  if (network) {
    sql += ` AND LOWER(network) = ?`;
    params.push(network);
  }

  sql += ` ORDER BY id DESC`;

  db.query(sql, params, (err, results) => {
    if (err) {
      console.error("Error fetching admin prices:", err);
      return res.status(500).json({
        ok: false,
        message: "Database error"
      });
    }

    res.json({
      ok: true,
      rows: results
    });
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



/////////////////////////////////////////////////////////////////////////////////////


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

// ✅ Helpers (place ABOVE routes)
function normalizePhone(input = "") {
  let p = String(input).trim().replace(/\s+/g, "");
  p = p.replace(/[^0-9+]/g, "");

  // remove leading +
  if (p.startsWith("+")) p = p.slice(1);

  // 054xxxxxxx -> 23354xxxxxxx
  if (p.startsWith("0") && p.length === 10) {
    p = "233" + p.slice(1);
  }

  return p;
}

function isValidPin(pin) {
  return /^\d{4}$/.test(String(pin || ""));
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

async function sendTheTellerDepositPrompt({ phone, network, amount, transaction_id }) {
  const msisdn = formatMsisdnForTheTeller(phone);
  const rSwitch = getSwitchCode(network) || detectMomoNetwork(msisdn);

  if (!rSwitch) {
    throw new Error("Invalid network");
  }

  const payload = {
    merchant_id: THETELLER.merchantId,
    transaction_id,
    processing_code: "000200",
    amount: thetellerAmount12(amount),
    desc: "Wallet Deposit",
    subscriber_number: msisdn,
    "r-switch": rSwitch
  };

  const response = await axios.post(THETELLER.endpoint, payload, {
    headers: {
      Authorization: `Basic ${THETELLER.basicToken}`,
      "Content-Type": "application/json"
    }
  });

  return response.data;
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

  if (!transaction_id) {
    return res.json({ ok: false, status: "unknown", message: "transaction_id is required" });
  }

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
      status.includes("success") || status.includes("approved") ||
      status.includes("paid") || status.includes("complete");

    const failed =
      status.includes("fail") || status.includes("decline") ||
      status.includes("cancel") ||
      ["failed", "declined", "cancelled", "canceled", "reversed"].includes(status);

    const pending =
      status.includes("pending") || status.includes("processing") ||
      status.includes("progress") || status.includes("initiated") ||
      status.includes("queued") || code === "099";

    if (approved) {
      await db.promise().query(
        `UPDATE orders
         SET status='approved', raw_status=?
         WHERE transaction_id=? AND status <> 'approved'`,
        [JSON.stringify(raw), transaction_id]
      );

      return res.json({ ok: true, transaction_id, status: "approved", raw });
    }

    if (failed) {
      await db.promise().query(
        `UPDATE orders
         SET status='failed', raw_status=?
         WHERE transaction_id=? AND status <> 'failed'`,
        [JSON.stringify(raw), transaction_id]
      );

      return res.json({ ok: true, transaction_id, status: "failed", raw });
    }

    if (pending) {
      await db.promise().query(
        `UPDATE orders
         SET raw_status=?
         WHERE transaction_id=?`,
        [JSON.stringify(raw), transaction_id]
      );

      return res.json({ ok: true, transaction_id, status: "pending", raw });
    }

    await db.promise().query(
      `UPDATE orders
       SET raw_status=?
       WHERE transaction_id=?`,
      [JSON.stringify(raw), transaction_id]
    );

    return res.json({ ok: true, transaction_id, status: status || "unknown", raw });
  } catch (e) {
    console.error("❌ TheTeller status error:", e.response?.data || e.message);
    return res.json({
      ok: false,
      transaction_id,
      status: "unknown",
      message: e.response?.data?.message || e.message || "Status check failed"
    });
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








/////// / ///// /////
app.post("/api/wallet/deposit", async (req, res) => {
  const { user_id, phone, network, amount } = req.body;

  if (!user_id || !phone || !network || !amount) {
    return res.status(400).json({
      ok: false,
      message: "Missing fields"
    });
  }

  const transaction_id = "DEP" + Date.now();

  db.query(
    `INSERT INTO wallet_deposits (user_id, transaction_id, reference, phone, network, amount, status)
     VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
    [user_id, transaction_id, transaction_id, phone, network, amount],
    async (insertErr) => {
      if (insertErr) {
        console.error("Insert deposit error:", insertErr);
        return res.status(500).json({
          ok: false,
          message: "Failed to save deposit"
        });
      }

      try {
  const tellerResponse = await sendTheTellerDepositPrompt({
          phone,
          network,
          amount,
          transaction_id
        });

        return res.json({
          ok: true,
          message: "Approve payment on your phone",
          transaction_id,
          teller: tellerResponse
        });

      } catch (err) {
        console.error("Deposit error:", err);

        db.query(
          `UPDATE wallet_deposits SET status='failed' WHERE transaction_id=?`,
          [transaction_id]
        );

        return res.status(500).json({
          ok: false,
          message: "Deposit failed"
        });
      }
    }
  );
});



app.post("/api/wallet/deposit/complete", (req, res) => {
  const { transaction_id, status } = req.body;

  if (!transaction_id) {
    return res.status(400).json({
      ok: false,
      message: "transaction_id required"
    });
  }

  db.query(
    `SELECT * FROM wallet_deposits WHERE transaction_id = ? LIMIT 1`,
    [transaction_id],
    (err, rows) => {
      if (err) {
        console.error("Select deposit error:", err);
        return res.status(500).json({
          ok: false,
          message: "Database error"
        });
      }

      if (!rows.length) {
        return res.status(404).json({
          ok: false,
          message: "Deposit not found"
        });
      }

      const deposit = rows[0];

      if (deposit.status === "success") {
        return res.json({
          ok: true,
          message: "Already completed"
        });
      }

      if (status !== "success") {
        db.query(
          `UPDATE wallet_deposits SET status = 'failed' WHERE transaction_id = ?`,
          [transaction_id],
          (failErr) => {
            if (failErr) console.error("Failed-status update error:", failErr);

            return res.json({
              ok: false,
              message: "Deposit failed"
            });
          }
        );
        return;
      }

      db.query(
        `UPDATE wallet_deposits SET status = 'success' WHERE transaction_id = ?`,
        [transaction_id],
        (updDepositErr) => {
          if (updDepositErr) {
            console.error("Update deposit success error:", updDepositErr);
            return res.status(500).json({
              ok: false,
              message: "Failed to update deposit status"
            });
          }

          db.query(
            `UPDATE agents
             SET balance = balance + ?, sales_deposit = sales_deposit + ?
             WHERE id = ?`,
            [deposit.amount, deposit.amount, deposit.user_id],
            (updAgentErr, updAgentResult) => {
              if (updAgentErr) {
                console.error("Update agent balance error:", updAgentErr);
                return res.status(500).json({
                  ok: false,
                  message: "Failed to update agent wallet balance"
                });
              }

              if (updAgentResult.affectedRows === 0) {
                return res.status(404).json({
                  ok: false,
                  message: "Agent not found for wallet update"
                });
              }

              return res.json({
                ok: true,
                message: "Wallet funded successfully"
              });
            }
          );
        }
      );
    }
  );
});



app.get("/api/wallet/:agentId", (req, res) => {
  const agentId = req.params.agentId;

  db.query(
    `SELECT balance, sales_deposit, overdraft
     FROM agents
     WHERE id = ?
     LIMIT 1`,
    [agentId],
    (err, rows) => {
      if (err) {
        console.error("Wallet fetch error:", err);
        return res.status(500).json({
          ok: false,
          message: "Database error"
        });
      }

      if (!rows.length) {
        return res.status(404).json({
          ok: false,
          message: "Agent not found"
        });
      }

      return res.json({
        ok: true,
        data: rows[0]
      });
    }
  );
});





///////////////CART
app.post("/api/cart/add", (req, res) => {
  const {
    agent_id,
    package_id,
    network,
    package_name,
    price,
    quantity,
    recipient_number
  } = req.body;

  if (!agent_id || !package_id || !network || !package_name || !price || !recipient_number) {
    return res.status(400).json({
      ok: false,
      message: "Missing required fields"
    });
  }

  const qty = parseInt(quantity) || 1;
  const amount = parseFloat(price);
  const total = amount * qty;

  const sql = `
    INSERT INTO cart (
      agent_id,
      package_id,
      network,
      package_name,
      amount,
      quantity,
      total,
      recipient_number
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(
    sql,
    [agent_id, package_id, network, package_name, amount, qty, total, recipient_number],
    (err, result) => {
      if (err) {
        console.error("Cart insert error:", err);
        return res.status(500).json({
          ok: false,
          message: "Failed to add item to cart"
        });
      }

      res.json({
        ok: true,
        message: "Item added to cart successfully",
        cart_id: result.insertId
      });
    }
  );
});


app.get("/api/cart/:agent_id", (req, res) => {
  const { agent_id } = req.params;

  const sql = `
    SELECT id, agent_id, package_id, network, package_name, amount, quantity, total, recipient_number
FROM cart
WHERE agent_id = ?
    ORDER BY id DESC
  `;

  db.query(sql, [agent_id], (err, rows) => {
    if (err) {
      console.error("Fetch cart error:", err);
      return res.status(500).json({
        ok: false,
        message: "Failed to fetch cart"
      });
    }

    res.json({
      ok: true,
      rows
    });
  });
});


app.delete("/api/cart/:id", (req, res) => {
  const { id } = req.params;

  db.query("DELETE FROM cart WHERE id = ?", [id], (err, result) => {
    if (err) {
      console.error("Delete cart error:", err);
      return res.status(500).json({
        ok: false,
        message: "Failed to remove item"
      });
    }

    res.json({
      ok: true,
      message: "Item removed successfully"
    });
  });
});






/////Bulk Routs
app.post("/api/cart/bulk-add", async (req, res) => {
  try {
    const { agent_id, items } = req.body;

    if (!agent_id || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({
        ok: false,
        message: "agent_id and items are required"
      });
    }

    const values = [];

    for (const item of items) {
      if (
        !item.package_id ||
        !item.network ||
        !item.package_name ||
        !item.amount ||
        !item.recipient_number
      ) {
        continue;
      }

      const qty = parseInt(item.quantity || 1) || 1;
      const amount = parseFloat(item.amount || 0);
      const total = parseFloat(item.total || (amount * qty));

      values.push([
        agent_id,
        item.package_id,
        item.network,
        item.package_name,
        amount,
        qty,
        total,
        "active",
        item.recipient_number
      ]);
    }

    if (!values.length) {
      return res.status(400).json({
        ok: false,
        message: "No valid items to insert"
      });
    }

    const sql = `
      INSERT INTO cart
      (agent_id, package_id, network, package_name, amount, quantity, total, status, recipient_number)
      VALUES ?
    `;

    db.query(sql, [values], (err, result) => {
      if (err) {
        console.error("Bulk cart insert error:", err);
        return res.status(500).json({
          ok: false,
          message: "Failed to insert bulk cart items"
        });
      }

      res.json({
        ok: true,
        message: "Bulk cart items inserted successfully",
        inserted_count: result.affectedRows
      });
    });

  } catch (error) {
    console.error("Bulk upload route error:", error);
    res.status(500).json({
      ok: false,
      message: "Server error during bulk upload"
    });
  }
});





/////BULK DOWNLOAD ADMIN 
app.post("/api/cart/buy-from-account", (req, res) => {
  const { agent_id } = req.body;

  if (!agent_id) {
    return res.status(400).json({
      ok: false,
      message: "agent_id is required"
    });
  }

  const getAgentSql = `SELECT id, balance, overdraft FROM agents WHERE id = ? LIMIT 1`;
  const getCartSql = `
    SELECT id, agent_id, package_id, network, package_name, amount, quantity, total, recipient_number
    FROM cart
    WHERE agent_id = ? AND status = 'active'
    ORDER BY id ASC
  `;

  db.query(getAgentSql, [agent_id], (agentErr, agentRows) => {
    if (agentErr) {
      console.error("Agent fetch error:", agentErr);
      return res.status(500).json({
        ok: false,
        message: "Failed to fetch agent account"
      });
    }

    if (!agentRows.length) {
      return res.status(404).json({
        ok: false,
        message: "Agent not found"
      });
    }

    const agent = agentRows[0];
    const currentBalance = parseFloat(agent.balance || 0);
    const currentOverdraft = parseFloat(agent.overdraft || 0);
    const availableToSpend = currentBalance + currentOverdraft;

    db.query(getCartSql, [agent_id], (cartErr, cartRows) => {
      if (cartErr) {
        console.error("Cart fetch error:", cartErr);
        return res.status(500).json({
          ok: false,
          message: "Failed to fetch cart items"
        });
      }

      if (!cartRows.length) {
        return res.status(400).json({
          ok: false,
          message: "Your cart is empty"
        });
      }

      const totalCartAmount = cartRows.reduce((sum, item) => {
        return sum + parseFloat(item.total || 0);
      }, 0);

      if (availableToSpend < totalCartAmount) {
        return res.status(400).json({
          ok: false,
          message: "You do not have enough amount in your account and overdraft",
          balance: currentBalance,
          overdraft: currentOverdraft,
          available_to_spend: availableToSpend,
          total: totalCartAmount
        });
      }

      const newBalance = currentBalance - totalCartAmount;

      const updateBalanceSql = `UPDATE agents SET balance = ? WHERE id = ?`;

      db.query(updateBalanceSql, [newBalance, agent_id], (updateErr) => {
        if (updateErr) {
          console.error("Balance update error:", updateErr);
          return res.status(500).json({
            ok: false,
            message: "Failed to deduct account balance"
          });
        }

        const now = new Date();
        const orderValues = cartRows.map(item => {
          const transactionId = `ACC-${Date.now()}-${Math.floor(Math.random() * 100000)}`;
          return [
            transactionId,
            agent_id,
            item.network,
            item.package_id,
            item.package_name,
            item.amount,
            item.recipient_number || "",
            "", // momo_number empty because payment is from account
            "approved",
            now
          ];
        });

        const insertOrdersSql = `
          INSERT INTO orders
          (transaction_id, vendor_id, network, package_id, package_name, amount, recipient_number, momo_number, status, created_at)
          VALUES ?
        `;

        db.query(insertOrdersSql, [orderValues], (orderErr, orderResult) => {
          if (orderErr) {
            console.error("Insert orders error:", orderErr);
            return res.status(500).json({
              ok: false,
              message: "Failed to insert orders"
            });
          }

          const deleteCartSql = `DELETE FROM cart WHERE agent_id = ?`;

          db.query(deleteCartSql, [agent_id], (deleteErr) => {
            if (deleteErr) {
              console.error("Delete cart error:", deleteErr);
              return res.status(500).json({
                ok: false,
                message: "Orders inserted but failed to clear cart"
              });
            }

            return res.json({
              ok: true,
              message: "Payment completed successfully from account",
              deducted: totalCartAmount,
              previous_balance: currentBalance,
              overdraft: currentOverdraft,
              balance_left: newBalance,
              available_to_spend_left: newBalance + currentOverdraft,
              orders_inserted: orderResult.affectedRows
            });
          });
        });
      });
    });
  });
});



///// cart payment 
app.post("/api/cart/buy-with-momo", async (req, res) => {
  const { agent_id, momo_number, otp_session_id } = req.body;

  if (!agent_id || !momo_number) {
    return res.json({ ok: false, message: "agent_id and momo_number are required." });
  }

  let transactionId = "";
  let cartCount = 0;
  let grandTotal = 0;
  let ordersInserted = false;

  try {
    // 1. Verify OTP
    const otpCheck = await isOtpVerifiedNow(momo_number, otp_session_id);
    if (!otpCheck.ok) {
      return res.json({ ok: false, message: "OTP not verified. Please verify OTP first." });
    }

    // 2. Load cart rows first
    const [cartRows] = await db.promise().query(
      `SELECT id, agent_id, package_id, network, package_name, amount, quantity, total, recipient_number
       FROM cart
       WHERE agent_id = ? AND status = 'active'
       ORDER BY id ASC`,
      [agent_id]
    );

    if (!cartRows.length) {
      return res.json({ ok: false, message: "Your cart is empty." });
    }

    cartCount = cartRows.length;
    grandTotal = cartRows.reduce((sum, item) => sum + Number(item.total || 0), 0);

    const payerNet = detectMomoNetwork(momo_number);
    const rSwitch = getSwitchCode(payerNet);
    if (!rSwitch) {
      return res.json({ ok: false, message: "Unsupported payer network." });
    }

    transactionId = makeTransactionId();

    // 3. Consume OTP only after everything else is ready
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

    // 4. Insert pending orders first with transaction_id
    const orderValues = cartRows.map(item => ([
      transactionId,
      Number(agent_id),
      String(item.network || "").toLowerCase(),
      Number(item.package_id),
      String(item.package_name || ""),
      Number(item.amount || 0),
      String(item.recipient_number || ""),
      String(momo_number),
      "pending"
    ]));

    await db.promise().query(
      `INSERT INTO orders
       (transaction_id, vendor_id, network, package_id, package_name, amount, recipient_number, momo_number, status)
       VALUES ?`,
      [orderValues]
    );

    ordersInserted = true;

    // 5. Send prompt
    const payload = {
      amount: thetellerAmount12(grandTotal),
      processing_code: "000200",
      transaction_id: transactionId,
      desc: `EDATA Cart Payment - ${cartRows.length} item(s)`,
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
      timeout: 45000,
    });

    await db.promise().query(
      `UPDATE orders
       SET raw_status=?
       WHERE transaction_id=?`,
      [JSON.stringify(tt.data || {}), transactionId]
    );

    if (!isInitAccepted(tt.data)) {
      await db.promise().query(
        `UPDATE orders
         SET status='failed', raw_status=?
         WHERE transaction_id=? AND status='pending'`,
        [JSON.stringify(tt.data || {}), transactionId]
      );

      return res.json({
        ok: false,
        message: "Payment prompt not accepted.",
        transaction_id: transactionId,
        total_amount: grandTotal,
        item_count: cartCount,
        theteller: tt.data || {}
      });
    }

    return res.json({
      ok: true,
      message: "Prompt sent. Please approve on your phone.",
      transaction_id: transactionId,
      total_amount: grandTotal,
      item_count: cartCount
    });

  } catch (err) {
    console.error("❌ Cart MoMo INIT error:", err.response?.data || err.message);

    // Important: if we already created transaction/order rows,
    // return the transaction_id so frontend can still track it.
    if (transactionId && ordersInserted) {
      try {
        await db.promise().query(
          `UPDATE orders
           SET raw_status=?
           WHERE transaction_id=?`,
          [JSON.stringify(err.response?.data || { error: err.message }), transactionId]
        );
      } catch (_) {}

      return res.status(200).json({
        ok: false,
        recoverable: true,
        message: "Payment request may still be processing. If you received a prompt or have already paid, tap 'I've completed the payment'.",
        transaction_id: transactionId,
        total_amount: grandTotal,
        item_count: cartCount
      });
    }

    return res.status(500).json({
      ok: false,
      message: "Payment could not be initiated."
    });
  }
});


app.post("/api/cart/recover-momo-transaction", async (req, res) => {
  const { agent_id, momo_number } = req.body;

  if (!agent_id || !momo_number) {
    return res.status(400).json({
      ok: false,
      message: "agent_id and momo_number are required"
    });
  }

  try {
    const [rows] = await db.promise().query(
      `SELECT transaction_id, status, raw_status
       FROM orders
       WHERE vendor_id = ?
         AND momo_number = ?
         AND transaction_id IS NOT NULL
       ORDER BY id DESC
       LIMIT 1`,
      [agent_id, momo_number]
    );

    if (!rows.length) {
      return res.json({
        ok: false,
        message: "No recent transaction found"
      });
    }

    return res.json({
      ok: true,
      transaction_id: rows[0].transaction_id,
      status: rows[0].status || "pending",
      raw_status: rows[0].raw_status || null
    });
  } catch (err) {
    console.error("Recover momo transaction error:", err.message);
    return res.status(500).json({
      ok: false,
      message: "Could not recover transaction"
    });
  }
});


app.post("/api/cart/clear-after-momo-success", async (req, res) => {
  const { agent_id, transaction_id } = req.body;

  if (!agent_id || !transaction_id) {
    return res.json({ ok: false, message: "agent_id and transaction_id are required." });
  }

  try {
    const [rows] = await db.promise().query(
      `SELECT id
       FROM orders
       WHERE transaction_id = ?
         AND vendor_id = ?
         AND status = 'approved'
       LIMIT 1`,
      [transaction_id, agent_id]
    );

    if (!rows.length) {
      return res.json({ ok: false, message: "Payment not yet approved." });
    }

    await db.promise().query(
      `DELETE FROM cart WHERE agent_id = ?`,
      [agent_id]
    );

    return res.json({
      ok: true,
      message: "Cart cleared after successful payment."
    });
  } catch (err) {
    console.error("Clear cart after momo success error:", err.message);
    return res.status(500).json({ ok: false, message: "Failed to clear cart." });
  }
});





///// Status ceck
app.get("/api/agent-orders/:agent_id", (req, res) => {
  const { agent_id } = req.params;
  const recipient = (req.query.recipient || "").trim();

  let sql = `
    SELECT 
      id,
      transaction_id,
      vendor_id,
      network,
      package_id,
      package_name,
      amount,
      recipient_number,
      momo_number,
      status,
      created_at,
      updated_at,
      delivered_at
    FROM orders
    WHERE vendor_id = ?
  `;

  const params = [agent_id];

  if (recipient) {
    sql += ` AND recipient_number LIKE ?`;
    params.push(`%${recipient}%`);
  }

  sql += ` ORDER BY id DESC`;

  db.query(sql, params, (err, rows) => {
    if (err) {
      console.error("Fetch agent orders error:", err);
      return res.status(500).json({
        ok: false,
        message: "Failed to fetch orders"
      });
    }

    res.json({
      ok: true,
      rows
    });
  });
});




///// notification 
app.post("/api/notifications", (req, res) => {
  const { title, message, type, status } = req.body;

  if (!title || !message) {
    return res.status(400).json({
      success: false,
      message: "Title and message are required"
    });
  }

  const sql = `
    INSERT INTO notifications (title, message, type, status)
    VALUES (?, ?, ?, ?)
  `;

  db.query(
    sql,
    [
      title.trim(),
      message.trim(),
      (type || "notification").trim(),
      (status || "active").trim()
    ],
    (err, result) => {
      if (err) {
        console.error("Error creating notification:", err);
        return res.status(500).json({
          success: false,
          message: "Database error while creating notification"
        });
      }

      res.json({
        success: true,
        message: "Notification created successfully",
        id: result.insertId
      });
    }
  );
});




app.get("/api/notifications", (req, res) => {
  const sql = `
    SELECT id, title, message, type, status, created_at, updated_at
    FROM notifications
    ORDER BY id DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching notifications:", err);
      return res.status(500).json({
        success: false,
        message: "Database error while fetching notifications"
      });
    }

    res.json({
      success: true,
      data: results
    });
  });
});


app.get("/api/notifications/:id", (req, res) => {
  const { id } = req.params;

  const sql = `
    SELECT id, title, message, type, status, created_at, updated_at
    FROM notifications
    WHERE id = ?
    LIMIT 1
  `;

  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error("Error fetching notification:", err);
      return res.status(500).json({
        success: false,
        message: "Database error while fetching notification"
      });
    }

    if (results.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Notification not found"
      });
    }

    res.json({
      success: true,
      data: results[0]
    });
  });
});



app.put("/api/notifications/:id", (req, res) => {
  const { id } = req.params;
  const { title, message, type, status } = req.body;

  if (!title || !message) {
    return res.status(400).json({
      success: false,
      message: "Title and message are required"
    });
  }

  const sql = `
    UPDATE notifications
    SET title = ?, message = ?, type = ?, status = ?
    WHERE id = ?
  `;

  db.query(
    sql,
    [
      title.trim(),
      message.trim(),
      (type || "notification").trim(),
      (status || "active").trim(),
      id
    ],
    (err, result) => {
      if (err) {
        console.error("Error updating notification:", err);
        return res.status(500).json({
          success: false,
          message: "Database error while updating notification"
        });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({
          success: false,
          message: "Notification not found"
        });
      }

      res.json({
        success: true,
        message: "Notification updated successfully"
      });
    }
  );
});

app.delete("/api/notifications/:id", (req, res) => {
  const { id } = req.params;

  const sql = `DELETE FROM notifications WHERE id = ?`;

  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error("Error deleting notification:", err);
      return res.status(500).json({
        success: false,
        message: "Database error while deleting notification"
      });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "Notification not found"
      });
    }

    res.json({
      success: true,
      message: "Notification deleted successfully"
    });
  });
});

///// batch count 
app.get("/api/agent/notifications/count", (req, res) => {
  const sql = `
    SELECT COUNT(*) AS total
    FROM notifications
    WHERE status = 'active'
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error getting notification count:", err);
      return res.status(500).json({
        success: false,
        message: "Database error"
      });
    }

    res.json({
      success: true,
      total: results[0].total || 0
    });
  });
});

app.get("/api/agent/notifications", (req, res) => {
  const sql = `
    SELECT id, title, message, type, created_at, updated_at
    FROM notifications
    WHERE status = 'active'
    ORDER BY id DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching agent notifications:", err);
      return res.status(500).json({
        success: false,
        message: "Database error"
      });
    }

    res.json({
      success: true,
      data: results
    });
  });
});


app.get("/api/agent/notifications/:id", (req, res) => {
  const { id } = req.params;

  const sql = `
    SELECT id, title, message, type, created_at, updated_at
    FROM notifications
    WHERE id = ? AND status = 'active'
    LIMIT 1
  `;

  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error("Error fetching single notification:", err);
      return res.status(500).json({
        success: false,
        message: "Database error"
      });
    }

    if (results.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Notification not found"
      });
    }

    res.json({
      success: true,
      data: results[0]
    });
  });
});



///// Cart Count 
app.get("/api/cart/count/:agent_id", (req, res) => {
  const { agent_id } = req.params;

  if (!agent_id) {
    return res.status(400).json({
      ok: false,
      message: "agent_id is required"
    });
  }

  const sql = `
    SELECT COUNT(*) AS total
    FROM cart
    WHERE agent_id = ? AND status = 'active'
  `;

  db.query(sql, [agent_id], (err, rows) => {
    if (err) {
      console.error("Cart count error:", err);
      return res.status(500).json({
        ok: false,
        message: "Failed to fetch cart count"
      });
    }

    return res.json({
      ok: true,
      count: rows[0].total
    });
  });
});



/////Network Status
app.get("/api/admin/network-delivery-status", (req, res) => {
  const sql = `
    SELECT id, network, delivery_status, delivery_time, updated_at
    FROM network_delivery_status
    ORDER BY id DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching network delivery status:", err);
      return res.status(500).json({
        success: false,
        message: "Database error"
      });
    }

    res.json({
      success: true,
      data: results
    });
  });
});

app.post("/api/admin/network-delivery-status", (req, res) => {
  const { network, delivery_status, delivery_time } = req.body;

  if (!network || !delivery_status || !delivery_time) {
    return res.status(400).json({
      success: false,
      message: "Network, delivery status and delivery time are required"
    });
  }

  const sql = `
    INSERT INTO network_delivery_status (network, delivery_status, delivery_time)
    VALUES (?, ?, ?)
  `;

  db.query(sql, [network, delivery_status, delivery_time], (err, result) => {
    if (err) {
      console.error("Error adding network delivery status:", err);
      return res.status(500).json({
        success: false,
        message: "Database error"
      });
    }

    res.json({
      success: true,
      message: "Network delivery setting added successfully",
      id: result.insertId
    });
  });
});


app.put("/api/admin/network-delivery-status/:id", (req, res) => {
  const { id } = req.params;
  const { network, delivery_status, delivery_time } = req.body;

  if (!network || !delivery_status || !delivery_time) {
    return res.status(400).json({
      success: false,
      message: "Network, delivery status and delivery time are required"
    });
  }

  const sql = `
    UPDATE network_delivery_status
    SET network = ?, delivery_status = ?, delivery_time = ?, updated_at = NOW()
    WHERE id = ?
  `;

  db.query(sql, [network, delivery_status, delivery_time, id], (err, result) => {
    if (err) {
      console.error("Error updating network delivery status:", err);
      return res.status(500).json({
        success: false,
        message: "Database error"
      });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "Record not found"
      });
    }

    res.json({
      success: true,
      message: "Network delivery setting updated successfully"
    });
  });
});


app.delete("/api/admin/network-delivery-status/:id", (req, res) => {
  const { id } = req.params;

  const sql = `DELETE FROM network_delivery_status WHERE id = ?`;

  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error("Error deleting network delivery status:", err);
      return res.status(500).json({
        success: false,
        message: "Database error"
      });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "Record not found"
      });
    }

    res.json({
      success: true,
      message: "Record deleted successfully"
    });
  });
});

///// Check Network
app.get("/api/network-delivery-status", (req, res) => {
  const sql = `
    SELECT t1.id, t1.network, t1.delivery_status, t1.delivery_time, t1.updated_at
    FROM network_delivery_status t1
    INNER JOIN (
      SELECT network, MAX(updated_at) AS latest_updated
      FROM network_delivery_status
      GROUP BY network
    ) t2
    ON t1.network = t2.network
    AND t1.updated_at = t2.latest_updated
    ORDER BY t1.updated_at DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching latest delivery status:", err);
      return res.status(500).json({
        success: false,
        message: "Database error"
      });
    }

    res.json({
      success: true,
      data: results
    });
  });
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

///// Approve check status 
app.post("/api/cart/recover-momo-transaction", (req, res) => {
  const { agent_id, momo_number } = req.body;

  if (!agent_id || !momo_number) {
    return res.status(400).json({
      ok: false,
      message: "agent_id and momo_number are required"
    });
  }

  const sql = `
    SELECT transaction_id
    FROM momo_transactions
    WHERE agent_id = ?
      AND momo_number = ?
      AND transaction_id IS NOT NULL
    ORDER BY id DESC
    LIMIT 1
  `;

  db.query(sql, [agent_id, momo_number], (err, rows) => {
    if (err) {
      console.error("Recover transaction error:", err);
      return res.status(500).json({
        ok: false,
        message: "Database error"
      });
    }

    if (!rows.length) {
      return res.json({
        ok: false,
        message: "No recent transaction found"
      });
    }

    res.json({
      ok: true,
      transaction_id: rows[0].transaction_id
    });
  });
});



///// Annouce pop
app.get("/api/agent/announcements", (req, res) => {
  const sql = `
    SELECT id, title, message, type, created_at, updated_at
    FROM notifications
    WHERE status = 'active'
      AND LOWER(type) = 'announcement'
    ORDER BY id DESC
  `;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching announcements:", err);
      return res.status(500).json({
        success: false,
        message: "Database error"
      });
    }

    res.json({
      success: true,
      data: results
    });
  });
});


///// Admin Money Send 
app.get("/api/admin-agent-wallet-list", (req, res) => {
  const search = (req.query.search || "").trim();

  let sql = `
    SELECT
      id,
      first_name,
      last_name,
      phone,
      email,
      gender,
      address,
      status,
      created_at,
      balance,
      sales_deposit,
      overdraft
    FROM agents
  `;

  let params = [];

  if (search) {
    sql += `
      WHERE
        first_name LIKE ?
        OR last_name LIKE ?
        OR phone LIKE ?
        OR email LIKE ?
    `;
    const like = `%${search}%`;
    params = [like, like, like, like];
  }

  sql += ` ORDER BY id DESC`;

  db.query(sql, params, (err, results) => {
    if (err) {
      console.error("Error fetching admin wallet agents:", err);
      return res.status(500).json({
        success: false,
        message: "Database error while fetching agents"
      });
    }

    return res.json({
      success: true,
      data: results
    });
  });
});


app.post("/api/admin-agent-wallet/deposit/:id", (req, res) => {
  const agentId = Number(req.params.id);
  const amount = Number(req.body.amount);

  if (!agentId || !amount || amount <= 0) {
    return res.status(400).json({
      success: false,
      message: "Valid agent ID and amount are required"
    });
  }

  const transactionId = `ADMINDEP${Date.now()}`;
  const reference = `ADMINDEP${Date.now()}`;

  const getAgentSql = `SELECT id, phone FROM agents WHERE id = ? LIMIT 1`;

  db.query(getAgentSql, [agentId], (err, rows) => {
    if (err) {
      console.error("Error finding agent:", err);
      return res.status(500).json({
        success: false,
        message: "Database error while finding agent"
      });
    }

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: "Agent not found"
      });
    }

    const agentPhone = rows[0].phone || "";

    const insertDepositSql = `
      INSERT INTO wallet_deposits
      (user_id, transaction_id, reference, phone, network, amount, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'admin', ?, 'success', NOW(), NOW())
    `;

    db.query(insertDepositSql, [agentId, transactionId, reference, agentPhone, amount], (err2) => {
      if (err2) {
        console.error("Error inserting wallet deposit:", err2);
        return res.status(500).json({
          success: false,
          message: "Failed to save deposit history"
        });
      }

      const updateAgentSql = `
        UPDATE agents
        SET
          balance = COALESCE(balance, 0) + ?,
          status = 'active'
        WHERE id = ?
      `;

      db.query(updateAgentSql, [amount, agentId], (err3, result) => {
        if (err3) {
          console.error("Error updating agent balance:", err3);
          return res.status(500).json({
            success: false,
            message: "Deposit saved but failed to update agent balance"
          });
        }

        if (result.affectedRows === 0) {
          return res.status(404).json({
            success: false,
            message: "Agent not found after deposit"
          });
        }

        return res.json({
          success: true,
          message: "Deposit added successfully and agent activated"
        });
      });
    });
  });
});


app.post("/api/admin-agent-wallet/deduct-balance/:id", (req, res) => {
  const agentId = Number(req.params.id);
  const amount = Number(req.body.amount);

  if (!agentId || !amount || amount <= 0) {
    return res.status(400).json({
      success: false,
      message: "Valid agent ID and amount are required"
    });
  }

  db.query(`SELECT balance FROM agents WHERE id = ?`, [agentId], (err, rows) => {
    if (err) {
      console.error("Error checking balance:", err);
      return res.status(500).json({
        success: false,
        message: "Database error while checking balance"
      });
    }

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: "Agent not found"
      });
    }

    const currentBalance = Number(rows[0].balance || 0);

    if (amount > currentBalance) {
      return res.status(400).json({
        success: false,
        message: "Insufficient balance"
      });
    }

    const insertAdjustmentSql = `
      INSERT INTO wallet_adjustments (agent_id, action_type, amount, note, created_at)
      VALUES (?, 'deduct', ?, 'Admin deducted from balance', NOW())
    `;

    db.query(insertAdjustmentSql, [agentId, amount], (err2) => {
      if (err2) {
        console.error("Error inserting wallet adjustment:", err2);
        return res.status(500).json({
          success: false,
          message: "Failed to save deduction history"
        });
      }

      db.query(
        `UPDATE agents SET balance = COALESCE(balance, 0) - ? WHERE id = ?`,
        [amount, agentId],
        (err3) => {
          if (err3) {
            console.error("Error deducting balance:", err3);
            return res.status(500).json({
              success: false,
              message: "Failed to deduct balance"
            });
          }

          return res.json({
            success: true,
            message: "Balance deducted successfully"
          });
        }
      );
    });
  });
});


app.post("/api/admin-agent-wallet/add-overdraft/:id", (req, res) => {
  const agentId = Number(req.params.id);
  const amount = Number(req.body.amount);

  if (!agentId || !amount || amount <= 0) {
    return res.status(400).json({
      success: false,
      message: "Valid agent ID and amount are required"
    });
  }

  const insertSql = `
    INSERT INTO overdraft_transactions (agent_id, action_type, amount, note, created_at)
    VALUES (?, 'add', ?, 'Admin added overdraft', NOW())
  `;

  db.query(insertSql, [agentId, amount], (err) => {
    if (err) {
      console.error("Error saving overdraft transaction:", err);
      return res.status(500).json({
        success: false,
        message: "Failed to save overdraft history"
      });
    }

    db.query(
      `UPDATE agents SET overdraft = COALESCE(overdraft, 0) + ? WHERE id = ?`,
      [amount, agentId],
      (err2, result) => {
        if (err2) {
          console.error("Error updating agent overdraft:", err2);
          return res.status(500).json({
            success: false,
            message: "Failed to update overdraft"
          });
        }

        if (result.affectedRows === 0) {
          return res.status(404).json({
            success: false,
            message: "Agent not found"
          });
        }

        return res.json({
          success: true,
          message: "Overdraft added successfully"
        });
      }
    );
  });
});


app.post("/api/admin-agent-wallet/deduct-overdraft/:id", (req, res) => {
  const agentId = Number(req.params.id);
  const amount = Number(req.body.amount);

  if (!agentId || !amount || amount <= 0) {
    return res.status(400).json({
      success: false,
      message: "Valid agent ID and amount are required"
    });
  }

  db.query(`SELECT overdraft FROM agents WHERE id = ?`, [agentId], (err, rows) => {
    if (err) {
      console.error("Error checking overdraft:", err);
      return res.status(500).json({
        success: false,
        message: "Database error while checking overdraft"
      });
    }

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: "Agent not found"
      });
    }

    const currentOverdraft = Number(rows[0].overdraft || 0);

    if (amount > currentOverdraft) {
      return res.status(400).json({
        success: false,
        message: "Insufficient overdraft"
      });
    }

    const insertSql = `
      INSERT INTO overdraft_transactions (agent_id, action_type, amount, note, created_at)
      VALUES (?, 'deduct', ?, 'Admin deducted overdraft', NOW())
    `;

    db.query(insertSql, [agentId, amount], (err2) => {
      if (err2) {
        console.error("Error saving overdraft deduction:", err2);
        return res.status(500).json({
          success: false,
          message: "Failed to save overdraft deduction history"
        });
      }

      db.query(
        `UPDATE agents SET overdraft = COALESCE(overdraft, 0) - ? WHERE id = ?`,
        [amount, agentId],
        (err3) => {
          if (err3) {
            console.error("Error deducting overdraft:", err3);
            return res.status(500).json({
              success: false,
              message: "Failed to deduct overdraft"
            });
          }

          return res.json({
            success: true,
            message: "Overdraft deducted successfully"
          });
        }
      );
    });
  });
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


/////Agent Momo Front
app.post("/api/recover-buy-data-transaction", async (req, res) => {
  const { vendor_id, momo_number, recipient_number, package_id } = req.body;

  if (!vendor_id || !momo_number || !recipient_number || !package_id) {
    return res.status(400).json({
      ok: false,
      message: "vendor_id, momo_number, recipient_number and package_id are required"
    });
  }

  try {
    const [rows] = await db.promise().query(
      `SELECT transaction_id, status, raw_status
       FROM orders
       WHERE vendor_id = ?
         AND momo_number = ?
         AND recipient_number = ?
         AND package_id = ?
         AND transaction_id IS NOT NULL
       ORDER BY id DESC
       LIMIT 1`,
      [vendor_id, momo_number, recipient_number, package_id]
    );

    if (!rows.length) {
      return res.json({
        ok: false,
        message: "No recent transaction found"
      });
    }

    return res.json({
      ok: true,
      transaction_id: rows[0].transaction_id,
      status: rows[0].status || "pending",
      raw_status: rows[0].raw_status || null
    });
  } catch (err) {
    console.error("Recover buy-data transaction error:", err.message);
    return res.status(500).json({
      ok: false,
      message: "Could not recover transaction"
    });
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

  const sql = `DELETE FROM orders WHERE id IN (?) AND status IN ('failed','pending')`;

  db.query(sql, [ids], (err, result) => {
    if (err) return res.status(500).json({ ok: false, message: "DB error" });
    return res.json({ ok: true, deleted: result.affectedRows });
  });
});



///// API KEYS
// GENERATE AGENT API KEY
app.post("/api/developer/generate-key", (req, res) => {
  const { phone, pin } = req.body;

  if (!phone || !pin) {
    return res.status(400).json({
      success: false,
      message: "Phone and PIN are required"
    });
  }

  const sql = `
    SELECT id, first_name, last_name, phone, pin_hash, status
    FROM agents
    WHERE phone = ?
    LIMIT 1
  `;

  db.query(sql, [phone.trim()], async (err, results) => {
    if (err) {
      console.error("Error checking agent:", err);
      return res.status(500).json({
        success: false,
        message: "Database error"
      });
    }

    if (!results.length) {
      return res.status(404).json({
        success: false,
        message: "Agent not found"
      });
    }

    const agent = results[0];

    if (String(agent.status).toLowerCase() !== "active") {
      return res.status(403).json({
        success: false,
        message: "Your account is not active"
      });
    }

    try {
      const pinOk = await bcrypt.compare(pin.trim(), agent.pin_hash);

      if (!pinOk) {
        return res.status(401).json({
          success: false,
          message: "Invalid PIN"
        });
      }

      const apiKey = "eda_" + crypto.randomBytes(24).toString("hex");

      const insertSql = `
        INSERT INTO agent_api_keys (agent_id, api_key, status)
        VALUES (?, ?, 'active')
      `;

      db.query(insertSql, [agent.id, apiKey], (insertErr) => {
        if (insertErr) {
          console.error("Error saving API key:", insertErr);
          return res.status(500).json({
            success: false,
            message: "Could not save API key"
          });
        }

        return res.json({
          success: true,
          message: "API key generated successfully",
          data: {
            agent_id: agent.id,
            name: `${agent.first_name} ${agent.last_name}`,
            phone: agent.phone,
            api_key: apiKey,
            base_url: "https://edatagh.com/edatagh-backend"
          }
        });
      });
    } catch (e) {
      console.error("PIN compare error:", e);
      return res.status(500).json({
        success: false,
        message: "Server error"
      });
    }
  });
});

function verifyAgentApiKey(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const apiKey = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7).trim()
    : null;

  if (!apiKey) {
    return res.status(401).json({
      success: false,
      message: "Missing API key. Use Authorization: Bearer YOUR_API_KEY"
    });
  }

  const sql = `
    SELECT ak.id, ak.agent_id, ak.api_key, ak.status, a.phone, a.first_name, a.last_name
    FROM agent_api_keys ak
    JOIN agents a ON ak.agent_id = a.id
    WHERE ak.api_key = ?
      AND ak.status = 'active'
    LIMIT 1
  `;

  db.query(sql, [apiKey], (err, results) => {
    if (err) {
      console.error("API key verification error:", err);
      return res.status(500).json({
        success: false,
        message: "Server error"
      });
    }

    if (!results.length) {
      return res.status(401).json({
        success: false,
        message: "Invalid or revoked API key"
      });
    }

    req.agent = results[0];
    next();
  });
}

app.get("/api/dev/auth", verifyAgentApiKey, (req, res) => {
  res.json({
    success: true,
    message: "Authentication successful",
    data: {
      agent_id: req.agent.agent_id,
      name: `${req.agent.first_name} ${req.agent.last_name}`,
      phone: req.agent.phone
    }
  });
});

app.get("/api/dev/check-balance", verifyAgentApiKey, (req, res) => {
  const sql = `
    SELECT COALESCE(SUM(amount), 0) AS balance
    FROM wallet_deposits
    WHERE agent_id = ?
  `;

  db.query(sql, [req.agent.agent_id], (err, results) => {
    if (err) {
      console.error("Balance fetch error:", err);
      return res.status(500).json({
        success: false,
        message: "Could not fetch balance"
      });
    }

    res.json({
      success: true,
      data: {
        agent_id: req.agent.agent_id,
        balance: Number(results[0].balance || 0)
      }
    });
  });
});

app.post("/api/dev/make-order", verifyAgentApiKey, (req, res) => {
  const { network, package_name, recipient_number, amount } = req.body;

  if (!network || !package_name || !recipient_number || !amount) {
    return res.status(400).json({
      success: false,
      message: "network, package_name, recipient_number and amount are required"
    });
  }

  const packageId = "PKG" + Date.now();

  const sql = `
    INSERT INTO orders (
      agent_id,
      network,
      package_name,
      recipient_number,
      amount,
      status,
      package_id,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, 'pending', ?, NOW())
  `;

  db.query(
    sql,
    [
      req.agent.agent_id,
      network,
      package_name,
      recipient_number,
      amount,
      packageId
    ],
    (err, result) => {
      if (err) {
        console.error("Order insert error:", err);
        return res.status(500).json({
          success: false,
          message: "Could not create order"
        });
      }

      res.json({
        success: true,
        message: "Order created successfully",
        data: {
          order_id: result.insertId,
          package_id: packageId,
          status: "pending"
        }
      });
    }
  );
});

app.get("/api/dev/order-status/:orderId", verifyAgentApiKey, (req, res) => {
  const { orderId } = req.params;

  const sql = `
    SELECT id, network, package_name, recipient_number, amount, status, package_id, created_at
    FROM orders
    WHERE id = ?
      AND agent_id = ?
    LIMIT 1
  `;

  db.query(sql, [orderId, req.agent.agent_id], (err, results) => {
    if (err) {
      console.error("Order status error:", err);
      return res.status(500).json({
        success: false,
        message: "Could not fetch order status"
      });
    }

    if (!results.length) {
      return res.status(404).json({
        success: false,
        message: "Order not found"
      });
    }

    res.json({
      success: true,
      data: results[0]
    });
  });
});

app.post("/api/dev/afa-register", verifyAgentApiKey, (req, res) => {
  const {
    first_name,
    last_name,
    ghana_card_number,
    town,
    occupation,
    date_of_birth,
    phone
  } = req.body;

  if (
    !first_name ||
    !last_name ||
    !ghana_card_number ||
    !town ||
    !occupation ||
    !date_of_birth ||
    !phone
  ) {
    return res.status(400).json({
      success: false,
      message: "All AFA registration fields are required"
    });
  }

  const sql = `
    INSERT INTO afa_registrations (
      agent_id,
      first_name,
      last_name,
      ghana_card_number,
      town,
      occupation,
      date_of_birth,
      phone,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
  `;

  db.query(
    sql,
    [
      req.agent.agent_id,
      first_name,
      last_name,
      ghana_card_number,
      town,
      occupation,
      date_of_birth,
      phone
    ],
    (err, result) => {
      if (err) {
        console.error("AFA registration error:", err);
        return res.status(500).json({
          success: false,
          message: "Could not complete AFA registration"
        });
      }

      res.json({
        success: true,
        message: "AFA registration successful",
        data: {
          registration_id: result.insertId
        }
      });
    }
  );
});






app.listen(PORT, () => {
  console.log(`EDATA server running on port ${PORT}`);
});
