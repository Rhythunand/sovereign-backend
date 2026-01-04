/* ==========================
   ENV & IMPORTS
========================== */
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import nodemailer from "nodemailer";
import mongoose from "mongoose";

/* ==========================
   APP INIT
========================== */
const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret";

/* ==========================
   MONGODB CONNECT
========================== */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB error:", err));

/* ==========================
   SCHEMAS
========================== */
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  passwordHash: String,
  verified: Boolean
});

const OtpSchema = new mongoose.Schema({
  email: String,
  code: String,
  expires: Number
});

const OrderSchema = new mongoose.Schema({
  userId: String,
  items: Array,
  total: Number,
  createdAt: { type: Date, default: Date.now }
});

const AdminSchema = new mongoose.Schema({
  passwordHash: String
});

/* ==========================
   MODELS
========================== */
const User = mongoose.model("User", UserSchema);
const OTP = mongoose.model("OTP", OtpSchema);
const Order = mongoose.model("Order", OrderSchema);
const Admin = mongoose.model("Admin", AdminSchema);

/* ==========================
   INIT ADMIN
========================== */
const ADMIN_SEED_PASSWORD = process.env.ADMIN_SEED_PASSWORD;

(async () => {
  if (!ADMIN_SEED_PASSWORD) return;

  const exists = await Admin.findOne();
  if (!exists) {
    const hash = await bcrypt.hash(ADMIN_SEED_PASSWORD, 10);
    await Admin.create({ passwordHash: hash });
    console.log("✅ Admin initialized from ENV");
  }
})();

/* ==========================
   MAILER
========================== */
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

/* ==========================
   MIDDLEWARE
========================== */
const requireAdmin = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
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
    req.user = jwt.verify(token, JWT_SECRET);
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
  const admin = await Admin.findOne();
  const ok = await bcrypt.compare(password, admin.passwordHash);
  if (!ok) return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "2h" });
  res.json({ token });
});

/* ---------- USER SIGNUP ---------- */
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (await User.findOne({ email })) {
    return res.status(409).json({ message: "User exists" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  await User.create({ name, email, passwordHash, verified: false });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  await OTP.create({
    email,
    code,
    expires: Date.now() + 600000
  });

  await transporter.sendMail({
    to: email,
    subject: "Verify your email",
    html: `<h2>Your OTP: ${code}</h2>`
  });

  res.json({ message: "OTP sent" });
});

/* ---------- VERIFY OTP ---------- */
app.post("/api/verify-otp", async (req, res) => {
  const { email, code } = req.body;
  const entry = await OTP.findOne({ email, code });

  if (!entry || entry.expires < Date.now()) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  const user = await User.findOne({ email });
  user.verified = true;
  await user.save();
  await OTP.deleteMany({ email });

  const token = jwt.sign(
    { id: user._id, email, role: "user" },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ token, user });
});

/* ---------- LOGIN USER ---------- */
app.post("/api/login-user", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user || !user.verified) {
    return res.status(401).json({ message: "Invalid login" });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ message: "Invalid login" });

  const token = jwt.sign(
    { id: user._id, email, role: "user" },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ token, user });
});

/* ---------- ADMIN STATS ---------- */
app.get("/api/admin/stats", requireAdmin, async (req, res) => {
  const orders = await Order.find();
  const users = await User.find();

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
app.listen(PORT, () =>
  console.log(`🚀 Sovereign backend running on port ${PORT}`)
);

