const express = require("express");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;
const isProduction = process.env.NODE_ENV === "production";

if (!JWT_SECRET) {
  console.warn("Warning: JWT_SECRET is not set. Set it in your environment before deploying.");
}

// Basic in-memory user store placeholder.
// Replace with a real database (SQLite/Postgres) before production use.
const users = new Map();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

function setAuthCookie(res, token) {
  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "strict",
    secure: isProduction,
    maxAge: 24 * 60 * 60 * 1000,
  });
}

router.get("/login", (req, res) => {
  res.render("login", { title: "Login", csrfToken: res.locals.csrfToken });
});

router.get("/register", (req, res) => {
  res.render("register", { title: "Register", csrfToken: res.locals.csrfToken });
});

router.post("/register", authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send("Email and password are required");
  }
  if (users.has(email)) {
    return res.status(409).send("User already exists");
  }

  const bcrypt = require("bcryptjs");
  const passwordHash = await bcrypt.hash(password, 12);
  users.set(email, { email, passwordHash });

  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "1d" });
  setAuthCookie(res, token);
  res.redirect("/dashboard");
});

router.post("/login", authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = users.get(email);
  if (!user) {
    return res.status(401).send("Invalid credentials");
  }

  const bcrypt = require("bcryptjs");
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    return res.status(401).send("Invalid credentials");
  }

  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "1d" });
  setAuthCookie(res, token);
  res.redirect("/dashboard");
});

router.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/auth/login");
});

module.exports = router;
