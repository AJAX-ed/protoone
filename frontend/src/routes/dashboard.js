const express = require("express");
const jwt = require("jsonwebtoken");

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware: verify JWT from httpOnly cookie
function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies.token;
  if (!token) {
    return res.redirect("/auth/login");
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      res.clearCookie("token");
      return res.redirect("/auth/login");
    }
    req.user = decoded;
    next();
  });
}

router.get("/", requireAuth, (req, res) => {
  res.render("dashboard", {
    title: "Dashboard",
    user: req.user,
    csrfToken: res.locals.csrfToken,
  });
});

module.exports = router;
