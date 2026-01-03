require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const nodemailer = require("nodemailer");

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

   //INIT FILES\\
if (!fs.existsSync(USERS_PATH)) fs.writeFileSync(USERS_PATH, "[]");
if (!fs.existsSync(OTPS_PATH)) fs.writeFileSync(OTPS_PATH, "[]");
if (!fs.existsSync(CART_PATH)) fs.writeFileSync(CART_PATH, "[]"); // ✅ Add this
if (!fs.existsSync(ORDERS_PATH)) fs.writeFileSync(ORDERS_PATH, "[]"); // ✅ Add this
if (!fs.existsSync(INVOICES_PATH)) fs.writeFileSync(INVOICES_PATH, "[]"); // ✅ Add this

// Initialize Admin with admin / admin123\\
/* ==========================
   INIT ADMIN (Password Only)\\
========================== */
if (!fs.existsSync(ADMIN_PATH)) {
  // Default password: admin123
  const hash = bcrypt.hashSync("admin123", 10);
  fs.writeFileSync(
    ADMIN_PATH, 
    JSON.stringify({ passwordHash: hash }, null, 2)
  );
  console.log("✅ Admin initialized: Login with password 'admin123'");
}

/* ==========================
   HELPERS
========================== */
const read = (filePath) => {
    try {
        if (!fs.existsSync(filePath)) return [];
        const data = fs.readFileSync(filePath, "utf8");
        return JSON.parse(data || "[]");
    } catch (err) {
        throw new Error("File system read error");
    }
};

const write = (filePath, data) => {
    try {
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
    } catch (err) {
        throw new Error("File system write error");
    }
};

const JWT_SECRET = process.env.JWT_SECRET || "your_fallback_secret";


/* ==========================
   MAILER
========================== */
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

console.log("Email being used:", process.env.EMAIL_USER);

/* ==========================
   MIDDLEWARE
========================== */
const requireAdmin = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: "No token provided" });

  try {
    const token = auth.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== "admin") throw new Error("Not an admin");
    req.admin = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid or unauthorized token" });
  }
};

const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ message: "Unauthorized: No token provided" });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        // Attach the trusted ID from the token to the request object
        req.user = { id: decoded.id }; 
        next();
    } catch (err) {
        return res.status(401).json({ message: "Unauthorized: Invalid or expired token" });
    }
};

/* ==========================
   ROUTES
========================== */

// Health Check
app.get("/ping", (req, res) => res.json({ status: "ok", message: "Server is live" }));

/* ---------- ADMIN LOGIN (PASSWORD ONLY) ---------- */
app.post("/api/admin/login", async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ message: "Password is required" });
    }

    // Read config directly as an object
    const adminData = JSON.parse(fs.readFileSync(ADMIN_PATH, "utf8"));

    // Compare provided password with the stored hash
    const isMatch = await bcrypt.compare(password, adminData.passwordHash);

    if (!isMatch) {
      // 401 Unauthorized for failed password
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Issue JWT - Role remains 'admin' for middleware compatibility
    const token = jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "2h" });

    res.json({ 
      token, 
      message: "Admin login successful" 
    });

  } catch (error) {
    console.error("Admin Login Error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/admin/dashboard", requireAdmin, (req, res) => {
  res.json({ message: "Welcome to the Admin Dashboard 👑" });
});

/* ---------- ADMIN CHANGE PASSWORD ---------- */
app.post("/api/admin/change-password", requireAdmin, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmNewPassword } = req.body;

    if (!currentPassword || !newPassword || !confirmNewPassword) {
      return res.status(400).json({ message: "All password fields are required" });
    }

    if (newPassword !== confirmNewPassword) {
      return res.status(400).json({ message: "New passwords do not match" });
    }

    const adminData = JSON.parse(fs.readFileSync(ADMIN_PATH, "utf8"));

    // Verify current password
    const isMatch = await bcrypt.compare(currentPassword, adminData.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: "Current password is incorrect" });
    }

    // Hash the new password and save
    const salt = await bcrypt.genSalt(10);
    adminData.passwordHash = await bcrypt.hash(newPassword, salt);

    fs.writeFileSync(ADMIN_PATH, JSON.stringify(adminData, null, 2));

    res.json({ message: "Password updated successfully. Please log in again." });
  } catch (error) {
    console.error("Admin Change Password Error:", error);
    res.status(500).json({ message: "Server error during password update" });
  }
});

/* ---------- USER SIGNUP ---------- */
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const users = read(USERS_PATH);
  if (users.find((u) => u.email === email)) {
    return res.status(409).json({ message: "User already exists" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const newUser = {
    id: Date.now(),
    name,
    email,
    passwordHash,
    verified: false,
  };

  users.push(newUser);
  write(USERS_PATH, users);

  // Generate OTP
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const otps = read(OTPS_PATH).filter((o) => o.email !== email);
  otps.push({
    email,
    code,
    expires: Date.now() + 10 * 60 * 1000, // 10 minutes
  });
  write(OTPS_PATH, otps);

  try {
    await transporter.sendMail({
      to: email,
      from: `"Sovereign Antiques" <${process.env.EMAIL_USER}>`,
      subject: "Verify your email",
      html: `<h1>Your Verification Code: ${code}</h1><p>This code expires in 10 minutes.</p>`,
    });
    res.json({ message: "User registered. OTP sent to email." });
  } catch (err) {
    console.error("Mail Error:", err);
    res.status(500).json({ message: "Error sending OTP email" });
  }
});


/* ---------- VERIFY OTP ---------- */
app.post("/api/verify-otp", (req, res) => {
  const { email, code } = req.body;
  const otps = read(OTPS_PATH);
  const entry = otps.find((o) => o.email === email && o.code === code);

  if (!entry || entry.expires < Date.now()) {
    return res.status(400).json({ message: "Invalid or expired OTP" });
  }

  const users = read(USERS_PATH);
  const user = users.find((u) => u.email === email);
  if (user) {
    user.verified = true;
    write(USERS_PATH, users);
  }

  // Remove used OTP
  write(OTPS_PATH, otps.filter((o) => o.email !== email));

  const token = jwt.sign(
    { id: user.id, email: user.email, role: "user" }, 
    JWT_SECRET, 
    { expiresIn: "7d" }
  );
  res.json({ token, user: { name: user.name, email: user.email }, message: "Email verified successfully" });
});

/* ---------- USER LOGIN ---------- */
app.post("/api/login-user", async (req, res) => {
  const { email, password } = req.body;
  const users = read(USERS_PATH);
  const user = users.find((u) => u.email === email);

  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  if (!user.verified) {
    return res.status(403).json({ message: "Please verify your email first" });
  }

  const isMatch = await bcrypt.compare(password, user.passwordHash);
  if (!isMatch) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email, role: "user" }, 
    JWT_SECRET, 
    { expiresIn: "7d" }
);
  res.json({ token, user: { name: user.name, email: user.email } });
});

/* ==========================
   SECURE CART ROUTES
========================== */
app.get("/api/cart", authenticate, (req, res) => {
    try {
        const carts = read(path.join(__dirname, "cart.json"));
        // Find the specific cart belonging to the logged-in user
        const userCart = carts.find(c => c.userId === req.user.id);
        
        if (!userCart) {
            return res.json({ userId: req.user.id, items: [] });
        }
        res.json(userCart);
    } catch (error) {
        res.status(500).json({ message: "Error reading cart data" });
    }
});

/* ==========================
   SECURE ORDERS ROUTES
========================== */
app.get("/api/orders", authenticate, (req, res) => {
    try {
        const allOrders = read(path.join(__dirname, "orders.json"));
        // Filter orders so users only see their own history
        const userOrders = allOrders.filter(o => o.userId === req.user.id);
        res.json(userOrders);
    } catch (error) {
        res.status(500).json({ message: "Error reading orders" });
    }
});

/* ==========================
   SECURE INVOICE ROUTES
========================== */
app.get("/api/invoices/:invoiceId", authenticate, (req, res) => {
    try {
        const { invoiceId } = req.params;
        const allInvoices = read(path.join(__dirname, "invoices.json"));
        
        const invoice = allInvoices.find(i => i.invoiceId === invoiceId);

        if (!invoice) {
            return res.status(404).json({ message: "Invoice not found" });
        }

        // Check ownership: The userId in the JSON must match the token's userId
        if (invoice.userId !== req.user.id) {
            return res.status(403).json({ message: "Forbidden: You do not own this invoice" });
        }

        res.json(invoice);
    } catch (error) {
        res.status(500).json({ message: "Error retrieving invoice" });
    }
});

/* ---------- PLACE ORDER & GENERATE INVOICE ---------- */
app.post("/api/checkout", authenticate, async (req, res) => {
    try {
        const userId = req.user.id; // From JWT, purely backend-trusted
        const { items, total } = req.body;

        if (!items || items.length === 0) {
            return res.status(400).json({ message: "Cart is empty" });
        }

        // 1. Create the Order object
        const orderId = "ORD-" + Date.now();
        const invoiceId = "INV-" + Math.floor(100000 + Math.random() * 900000);
        
        const newOrder = {
            orderId,
            userId,
            items,
            total,
            invoiceId,
            status: "Paid",
            createdAt: new Date().toISOString()
        };

        // 2. Create the Invoice object linked to the user
        const newInvoice = {
            invoiceId,
            userId,
            orderId,
            total,
            billingEmail: req.user.email, // If you added email to your JWT payload
            createdAt: new Date().toISOString()
        };

        // 3. Save to JSON files (using your write/read helpers)
        const orders = read(ORDERS_PATH);
        const invoices = read(INVOICES_PATH);

        orders.push(newOrder);
        invoices.push(newInvoice);

        write(ORDERS_PATH, orders);
        write(INVOICES_PATH, invoices);

        // 4. Optional: Clear the user's cart.json after successful order
        let carts = read(CART_PATH);
        carts = carts.filter(c => c.userId !== userId);
        write(CART_PATH, carts);

        res.status(201).json({ 
            message: "Order placed successfully", 
            orderId, 
            invoiceId 
        });

    } catch (error) {
        console.error("Checkout Error:", error);
        res.status(500).json({ message: "Internal server error during checkout" });
    }
});

/* ---------- ADMIN: SECURE DASHBOARD DATA ---------- */
app.get("/api/admin/stats", requireAdmin, (req, res) => {
    try {
        const orders = read(ORDERS_PATH);
        const users = read(USERS_PATH);

        // 1. Calculate Revenue
        const totalRevenue = orders.reduce((sum, order) => sum + (Number(order.total) || 0), 0);

        // 2. Order Status Breakdown
        const pendingOrders = orders.filter(o => o.status === "Pending").length;
        const completedOrders = orders.filter(o => o.status === "Paid" || o.status === "Completed").length;

        // 3. Calculate Total Items Sold
        let totalItemsSold = 0;
        orders.forEach(order => {
            if (order.items && Array.isArray(order.items)) {
                totalItemsSold += order.items.length;
            }
        });

        // 4. Get 5 Most Recent Orders
        const recentOrders = orders
            .slice(-5)
            .reverse()
            .map(o => ({
                id: o.orderId,
                date: new Date(o.createdAt).toLocaleDateString(),
                amount: o.total,
                status: o.status
            }));

        res.json({
            success: true,
            stats: {
                totalUsers: users.length,
                totalOrders: orders.length,
                totalRevenue: totalRevenue.toFixed(2),
                pendingOrders,
                completedOrders,
                totalItemsSold
            },
            recentOrders
        });
    } catch (error) {
        console.error("Dashboard Stats Error:", error);
        res.status(500).json({ message: "Error generating dashboard data" });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});