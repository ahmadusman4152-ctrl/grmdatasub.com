const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is not configured.");
  process.exit(1);
}

// PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));

// CORS
const allowedOrigins = new Set([
  "https://grmdatasub.com",
  "https://www.grmdatasub.com"
]);

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (allowedOrigins.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }

  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

// Serve website files
app.use(express.static(__dirname));

// Password hashing
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto.scryptSync(password, salt, 64, {
    N: 16384,
    r: 8,
    p: 1
  }).toString("hex");

  return `${salt}:${hash}`;
}

// Health check
app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      message: "G R M DATA SUB backend is running",
      database: "connected"
    });
  } catch (error) {
    console.error("Health check error:", error);

    res.status(503).json({
      status: "error",
      message: "Database connection unavailable"
    });
  }
});

// Register user
app.post("/api/register", async (req, res) => {
  try {
    const { fullName, email, phone, password } = req.body;

    if (!fullName || !email || !phone || !password) {
      return res.status(400).json({
        message: "All fields are required."
      });
    }

    const cleanName = String(fullName).trim();
    const cleanEmail = String(email).trim().toLowerCase();
    const cleanPhone = String(phone).trim();
    const cleanPassword = String(password);

    if (cleanName.length < 2) {
      return res.status(400).json({
        message: "Please enter your full name."
      });
    }

    if (cleanEmail.length > 254 || !cleanEmail.includes("@")) {
      return res.status(400).json({
        message: "Please enter a valid email address."
      });
    }

    if (cleanPhone.length < 7 || cleanPhone.length > 20) {
      return res.status(400).json({
        message: "Please enter a valid phone number."
      });
    }

    if (cleanPassword.length < 8) {
      return res.status(400).json({
        message: "Password must be at least 8 characters."
      });
    }

    const passwordHash = hashPassword(cleanPassword);

    const userId = crypto.randomUUID();

    await pool.query(
      `
      INSERT INTO users
      (
        id,
        full_name,
        email,
        phone,
        password_hash
      )
      VALUES ($1, $2, $3, $4, $5)
      `,
      [
        userId,
        cleanName,
        cleanEmail,
        cleanPhone,
        passwordHash
      ]
    );

    res.status(201).json({
      message: "Account created successfully."
    });

  } catch (error) {
    console.error("Registration error:", error);

    if (error.code === "23505") {
      return res.status(409).json({
        message: "Email already registered."
      });
    }

    res.status(500).json({
      message: "Unable to create account. Please try again."
    });
  }
});

// Create database tables
async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      full_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      wallet_balance NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  console.log("Database tables are ready.");
}

// Start server
async function startServer() {
  try {
    await initializeDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `G R M DATA SUB server running on port ${PORT}`
      );
    });

  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

startServer();
