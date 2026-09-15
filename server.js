const express = require("express");

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve the website files
app.use(express.static(__dirname));

// Test route
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    message: "G R M DATA SUB backend is running"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`G R M DATA SUB server running on port ${PORT}`);
});
