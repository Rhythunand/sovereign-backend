// This URL must match your Node.js server port
const API_URL = 'https://sovereign-backend-6pcz.onrender.com';

/* =======================
    USER SIGNUP
======================== */
async function signup() {
    // Get values from your HTML input IDs
    const name = document.getElementById("name")?.value;
    const email = document.getElementById("email")?.value;
    const password = document.getElementById("password")?.value;

    if (!name || !email || !password) {
        alert("Please fill in all fields");
        return;
    }

    try {
        const res = await fetch(`${API_URL}/signup`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, email, password })
        });

        const data = await res.json();
        
        if (res.ok) {
            alert("OTP sent to your email!");
            // Switch view if you are using Alpine.js or show the OTP input
        } else {
            alert("Error: " + data.message);
        }
    } catch (err) {
        console.error("Signup Error:", err);
        alert("Could not connect to server. Ensure Node.js is running on port 5000.");
    }
}

/* =======================
    VERIFY OTP
======================== */
async function verifyOtp() {
    const email = document.getElementById("email")?.value; // Or stored in a variable
    const code = document.getElementById("otpCode")?.value;

    try {
        const res = await fetch(`${API_URL}/verify-otp`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, code })
        });

        const data = await res.json();
        if (res.ok) {
            alert("Account verified successfully!");
            location.reload(); // Refresh to log in
        } else {
            alert(data.message);
        }
    } catch (err) {
        alert("Verification failed.");
    }
}

/* =======================
    USER LOGIN
======================== */
async function loginUser() {
    const email = document.getElementById("loginEmail")?.value;
    const password = document.getElementById("loginPassword")?.value;

    try {
        const res = await fetch(`${API_URL}/login-user`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password })
        });

        const data = await res.json();
        if (res.ok) {
            localStorage.setItem('userToken', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            alert("Welcome back, " + data.user.name);
            window.location.href = "/catalog"; // Or your main page
        } else {
            alert(data.message);
        }
    } catch (err) {
        alert("Login failed.");
    }

}

