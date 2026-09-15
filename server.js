const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Allow the website to communicate with this backend
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
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

// Serve website files
app.use(express.static(__dirname));

// Demo users storage
const users = [];

// Hash passwords safely for this demo
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");

  return `${salt}:${hash}`;
}

// Backend health test
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    message: "G R M DATA SUB backend is running"
  });
});

// Registration
app.post("/api/register", (req, res) => {
  const { fullName, email, phone, password } = req.body;

  if (!fullName || !email || !phone || !password) {
    return res.status(400).json({
      message: "All fields are required."
    });
  }

  const normalizedEmail = String(email).trim().toLowerCase();

  if (users.some(user => user.email === normalizedEmail)) {
    return res.status(409).json({
      message: "Email already registered."
    });
  }

  users.push({
    id: crypto.randomUUID(),
    fullName: String(fullName).trim(),
    email: normalizedEmail,
    phone: String(phone).trim(),
    passwordHash: hashPassword(String(password))
  });

  res.status(201).json({
    message: "Account created successfully."
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`G R M DATA SUB server running on port ${PORT}`);
});
