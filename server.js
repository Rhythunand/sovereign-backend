/* ==========================
   ENV & IMPORTS
========================== */
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import fs from "fs";
import path from "path";
import nodemailer from "nodemailer";
import { fileURLToPath } from "url";

/* ==========================
   __DIRNAME FIX (ESM)
========================== */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ==========================
   APP INIT
========================== */
const app = express();
app.use(express.json());
app.use(cors());

/* ==========================
   PATHS
========================== */
const USERS_PATH = path.join(__dirname, "users.json");
const OTPS_PATH = path.join(__dirname, "otps.json");
const ADMIN_PATH = path.join(__dirname, "admin-config.json");
const CART_PATH = path.join(__dirname, "cart.json");
const ORDERS_PATH = path.join(__dirname, "orders.json");
const INVOICES_PATH = path.join(__dirname, "invoices.json");

/* ==========================
   INIT FILES
========================== */
if (!fs.existsSync(USERS_PATH)) fs.writeFileSync(USERS_PATH, "[]");
if (!fs.existsSync(OTPS_PATH)) fs.writeFileSync(OTPS_PATH, "[]");
if (!fs.existsSync(CART_PATH)) fs.writeFileSync(CART_PATH, "[]");
if (!fs.existsSync(ORDERS_PATH)) fs.writeFileSync(ORDERS_PATH, "[]");
if (!fs.existsSync(INVOICES_PATH)) fs.writeFileSync(INVOICES_PATH, "[]");

/* ==========================
   INIT ADMIN (PASSWORD ONLY)
========================== */
if (!fs.existsSync(ADMIN_PATH)) {
  const hash = bcrypt.hashSync("admin123", 10);
  fs.writeFileSync(
    ADMIN_PATH,
    JSON.stringify({ passwordHash: hash }, null, 2)
  );
  console.log("✅ Admin initialized: password = admin123");
}

/* ==========================
   HELPERS
========================== */
const read = (filePath) => {
  if (!fs.existsSync(filePath)) return [];
  return JSON.parse(fs.readFileSync(filePath, "utf8") || "[]");
};

const write = (filePath, data) => {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
};

const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret";

/* ==========================
   MAILER
========================== */
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

/* ==========================
   MIDDLEWARE
========================== */
const requireAdmin = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) throw new Error();
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== "admin") throw new Error();
    req.admin = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Unauthorized admin" });
  }
};

const authenticate = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) throw new Error();
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Unauthorized" });
  }
};

/* ==========================
   ROUTES
========================== */
app.get("/ping", (req, res) =>
  res.json({ status: "ok", message: "Server is live" })
);

/* ---------- ADMIN LOGIN ---------- */
app.post("/api/admin/login", async (req, res) => {
  const { password } = req.body;
  const admin = JSON.parse(fs.readFileSync(ADMIN_PATH, "utf8"));

  const match = await bcrypt.compare(password, admin.passwordHash);
  if (!match) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "2h" });
  res.json({ token });
});

/* ---------- CHANGE ADMIN PASSWORD ---------- */
app.post("/api/admin/change-password", requireAdmin, async (req, res) => {
  const { currentPassword, newPassword, confirmNewPassword } = req.body;
  if (newPassword !== confirmNewPassword) {
    return res.status(400).json({ message: "Passwords do not match" });
  }

  const admin = JSON.parse(fs.readFileSync(ADMIN_PATH, "utf8"));
  const ok = await bcrypt.compare(currentPassword, admin.passwordHash);
  if (!ok) return res.status(401).json({ message: "Wrong password" });

  admin.passwordHash = await bcrypt.hash(newPassword, 10);
  fs.writeFileSync(ADMIN_PATH, JSON.stringify(admin, null, 2));
  res.json({ message: "Password updated" });
});

/* ---------- USER SIGNUP ---------- */
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;
  const users = read(USERS_PATH);
  if (users.find(u => u.email === email)) {
    return res.status(409).json({ message: "User exists" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  users.push({ id: Date.now(), name, email, passwordHash, verified: false });
  write(USERS_PATH, users);

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  write(OTPS_PATH, [...read(OTPS_PATH), {
    email, code, expires: Date.now() + 600000
  }]);

  await transporter.sendMail({
    to: email,
    subject: "Verify your email",
    html: `<h2>Your OTP: ${code}</h2>`
  });

  res.json({ message: "OTP sent" });
});

/* ---------- VERIFY OTP ---------- */
app.post("/api/verify-otp", (req, res) => {
  const { email, code } = req.body;
  const otps = read(OTPS_PATH);
  const entry = otps.find(o => o.email === email && o.code === code);

  if (!entry || entry.expires < Date.now()) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  const users = read(USERS_PATH);
  const user = users.find(u => u.email === email);
  user.verified = true;
  write(USERS_PATH, users);
  write(OTPS_PATH, otps.filter(o => o.email !== email));

  const token = jwt.sign(
    { id: user.id, email, role: "user" },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ token, user });
});

/* ---------- LOGIN USER ---------- */
app.post("/api/login-user", async (req, res) => {
  const { email, password } = req.body;
  const user = read(USERS_PATH).find(u => u.email === email);
  if (!user || !user.verified) {
    return res.status(401).json({ message: "Invalid login" });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ message: "Invalid login" });

  const token = jwt.sign(
    { id: user.id, email, role: "user" },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ token, user });
});

/* ---------- ADMIN STATS ---------- */
app.get("/api/admin/stats", requireAdmin, (req, res) => {
  const orders = read(ORDERS_PATH);
  const users = read(USERS_PATH);

  const revenue = orders.reduce((s, o) => s + Number(o.total || 0), 0);
  const itemsSold = orders.reduce((s, o) => s + (o.items?.length || 0), 0);

  res.json({
    stats: {
      totalUsers: users.length,
      totalOrders: orders.length,
      totalRevenue: revenue,
      totalItemsSold: itemsSold
    },
    recentOrders: orders.slice(-5).reverse()
  });
});

/* ==========================
   START SERVER
========================== */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Sovereign backend running on port ${PORT}`)
);
