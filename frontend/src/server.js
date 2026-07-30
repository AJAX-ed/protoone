require("dotenv").config();

const express = require("express");
const path = require("path");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const csurf = require("csurf");
const rateLimit = require("express-rate-limit");

const authRoutes = require("./routes/auth");
const dashboardRoutes = require("./routes/dashboard");

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === "production";

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  hsts: isProduction ? { maxAge: 63072000, includeSubDomains: true, preload: true } : false,
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "..", "public")));

const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

const csrfProtection = csurf({
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: isProduction,
  },
});

app.use(csrfProtection);
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

app.get("/", (req, res) => {
  res.render("index", { title: "Secure JEE/NEET Self-Study MVP" });
});

app.use("/auth", authRoutes);
app.use("/dashboard", dashboardRoutes);

app.get("/health", (req, res) => res.json({ status: "ok" }));

// CSRF error handler
app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).send("Invalid CSRF token");
  }
  next(err);
});

// Generic error handler: never leak stack traces in production
app.use((err, req, res, next) => {
  console.error(err);
  const message = isProduction ? "Internal Server Error" : err.message;
  res.status(err.status || 500).send(message);
});

app.listen(PORT, () => {
  console.log(`Frontend SSR server listening on port ${PORT} (env=${process.env.NODE_ENV || "development"})`);
});
