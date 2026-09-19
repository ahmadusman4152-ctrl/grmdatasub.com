const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is not configured.");
  process.exit(1);
}

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

// Verify password
function verifyPassword(password, storedHash) {
  const [salt, originalHash] = storedHash.split(":");

  if (!salt || !originalHash) {
    return false;
  }

  const hash = crypto.scryptSync(password, salt, 64, {
    N: 16384,
    r: 8,
    p: 1
  });

  const original = Buffer.from(originalHash, "hex");

  return (
    original.length === hash.length &&
    crypto.timingSafeEqual(original, hash)
  );
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

// Register
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
      (id, full_name, email, phone, password_hash)
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

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required."
      });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const cleanPassword = String(password);

    const result = await pool.query(
      `
      SELECT id, full_name, email, phone, password_hash, wallet_balance
      FROM users
      WHERE email = $1
      LIMIT 1
      `,
      [cleanEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        message: "Invalid email or password."
      });
    }

    const user = result.rows[0];

    const passwordValid = verifyPassword(
      cleanPassword,
      user.password_hash
    );

    if (!passwordValid) {
      return res.status(401).json({
        message: "Invalid email or password."
      });
    }

    // Create a secure random login token.
    const token = crypto.randomBytes(32).toString("hex");

    const tokenHash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    await pool.query(
      `
      INSERT INTO sessions
      (id, user_id, token_hash, expires_at)
      VALUES ($1, $2, $3, NOW() + INTERVAL '7 days')
      `,
      [
        crypto.randomUUID(),
        user.id,
        tokenHash
      ]
    );

    res.json({
      message: "Login successful.",
      token,
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        phone: user.phone,
        walletBalance: user.wallet_balance
      }
    });

  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      message: "Unable to login. Please try again."
    });
  }
});

// Current logged-in user
app.get("/api/me", async (req, res) => {
  try {
    const auth = req.headers.authorization || "";

    if (!auth.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "Authentication required."
      });
    }

    const token = auth.substring(7);

    const tokenHash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const result = await pool.query(
      `
      SELECT
        u.id,
        u.full_name,
        u.email,
        u.phone,
        u.wallet_balance
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1
      AND s.expires_at > NOW()
      LIMIT 1
      `,
      [tokenHash]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        message: "Session expired or invalid."
      });
    }

    const user = result.rows[0];

    res.json({
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        phone: user.phone,
        walletBalance: user.wallet_balance
      }
    });

  } catch (error) {
    console.error("Authentication error:", error);

    res.status(500).json({
      message: "Unable to verify account."
    });
  }
});
|
// Paystack verification
app.post("/api/paystack/verify", async (req, res) => {
  try {
    const auth = req.headers.authorization || "";

    if (!auth.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "Authentication required."
      });
    }

    const token = auth.substring(7);

    const tokenHash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const userResult = await pool.query(
      `
      SELECT u.id, u.email
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1
      AND s.expires_at > NOW()
      LIMIT 1
      `,
      [tokenHash]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        message: "Session expired or invalid."
      });
    }

    const user = userResult.rows[0];

    const { reference } = req.body;

    if (!reference || typeof reference !== "string") {
      return res.status(400).json({
        message: "Transaction reference is required."
      });
    }

    if (!process.env.PAYSTACK_SECRET_KEY) {
      return res.status(500).json({
        message: "Paystack secret key is not configured."
      });
    }

    const paystackResponse = await fetch(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
        }
      }
    );

    const paystackData = await paystackResponse.json();

    if (!paystackResponse.ok || !paystackData.status) {
      return res.status(400).json({
        message: "Unable to verify Paystack transaction."
      });
    }

    const transaction = paystackData.data;

    if (transaction.status !== "success") {
      return res.status(400).json({
        message: "Payment was not successful."
      });
    }

    if (transaction.currency !== "NGN") {
      return res.status(400).json({
        message: "Invalid transaction currency."
      });
    }

    const transactionEmail = String(
      transaction.customer?.email || ""
    ).trim().toLowerCase();

    if (transactionEmail !== user.email.toLowerCase()) {
      return res.status(403).json({
        message: "Transaction does not belong to this account."
      });
    }

    const amountNaira = Number(transaction.amount) / 100;

    if (!Number.isFinite(amountNaira) || amountNaira <= 0) {
      return res.status(400).json({
        message: "Invalid transaction amount."
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const transactionResult = await client.query(
        `
        INSERT INTO wallet_transactions
        (
          id,
          user_id,
          reference,
          amount,
          currency,
          status
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (reference) DO NOTHING
        RETURNING id
        `,
        [
          crypto.randomUUID(),
          user.id,
          reference,
          amountNaira,
          transaction.currency,
          transaction.status
        ]
      );

      if (transactionResult.rows.length === 0) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          message: "This transaction has already been credited."
        });
      }

      const updatedUser = await client.query(
        `
        UPDATE users
        SET
          wallet_balance = wallet_balance + $1,
          updated_at = NOW()
        WHERE id = $2
        RETURNING wallet_balance
        `,
        [amountNaira, user.id]
      );

      await client.query("COMMIT");

      return res.json({
        message: "Wallet funded successfully.",
        amount: amountNaira,
        walletBalance: updatedUser.rows[0].wallet_balance,
        reference
      });

    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }

  } catch (error) {
    console.error("Paystack verification error:", error);

    res.status(500).json({
      message: "Unable to verify payment. Please try again."
    });
  }
});
// Logout
app.post("/api/logout", async (req, res) => {
  try {
    const auth = req.headers.authorization || "";

    if (auth.startsWith("Bearer ")) {
      const token = auth.substring(7);

      const tokenHash = crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

      await pool.query(
        "DELETE FROM sessions WHERE token_hash = $1",
        [tokenHash]
      );
    }

    res.json({
      message: "Logged out successfully."
    });

  } catch (error) {
    console.error("Logout error:", error);

    res.status(500).json({
      message: "Unable to logout."
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
    
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reference TEXT UNIQUE NOT NULL,
      amount NUMERIC(12, 2) NOT NULL,
      currency TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
