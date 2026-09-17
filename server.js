const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "fortiva-development-secret";

app.use(cors());
app.use(express.json());

/*
  Temporary in-memory account storage.

  IMPORTANT:
  This is for testing the login system only.
  Accounts will be lost whenever the Render service restarts.

  We will connect a real database before using this
  for actual customers.
*/
const users = [];


/* =========================
   HEALTH CHECK
========================= */

app.get("/", (req, res) => {
    res.json({
        online: true,
        service: "Fortiva Capital Backend"
    });
});


/* =========================
   REGISTER
========================= */

app.post("/api/register", async (req, res) => {
    try {
        const {
            fullName,
            phone,
            email,
            password
        } = req.body;

        if (!fullName || !phone || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required."
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                success: false,
                message: "Password must contain at least 6 characters."
            });
        }

        const existingUser = users.find(
            user =>
                user.phone === phone ||
                user.email.toLowerCase() === email.toLowerCase()
        );

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: "An account with that phone number or email already exists."
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const user = {
            id: Date.now().toString(),
            fullName: fullName.trim(),
            phone: phone.trim(),
            email: email.trim().toLowerCase(),
            passwordHash,
            createdAt: new Date().toISOString()
        };

        users.push(user);

        res.status(201).json({
            success: true,
            message: "Account created successfully.",
            user: {
                id: user.id,
                fullName: user.fullName,
                phone: user.phone,
                email: user.email
            }
        });

    } catch (error) {
        console.error("Registration error:", error);

        res.status(500).json({
            success: false,
            message: "Unable to create account."
        });
    }
});


/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {
    try {
        const {
            phone,
            password
        } = req.body;

        if (!phone || !password) {
            return res.status(400).json({
                success: false,
                message: "Phone number and password are required."
            });
        }

        const user = users.find(
            user => user.phone === phone.trim()
        );

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Invalid phone number or password."
            });
        }

        const passwordCorrect = await bcrypt.compare(
            password,
            user.passwordHash
        );

        if (!passwordCorrect) {
            return res.status(401).json({
                success: false,
                message: "Invalid phone number or password."
            });
        }

        const token = jwt.sign(
            {
                userId: user.id,
                phone: user.phone
            },
            JWT_SECRET,
            {
                expiresIn: "7d"
            }
        );

        res.json({
            success: true,
            message: "Login successful.",
            token,
            user: {
                id: user.id,
                fullName: user.fullName,
                phone: user.phone,
                email: user.email
            }
        });

    } catch (error) {
        console.error("Login error:", error);

        res.status(500).json({
            success: false,
            message: "Unable to login."
        });
    }
});


/* =========================
   AUTHENTICATED USER
========================= */

app.get("/api/me", (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                message: "Authentication required."
            });
        }

        const token = authHeader.split(" ")[1];

        const decoded = jwt.verify(token, JWT_SECRET);

        const user = users.find(
            user => user.id === decoded.userId
        );

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "User account not found."
            });
        }

        res.json({
            success: true,
            user: {
                id: user.id,
                fullName: user.fullName,
                phone: user.phone,
                email: user.email,
                createdAt: user.createdAt
            }
        });

    } catch (error) {
        return res.status(401).json({
            success: false,
            message: "Invalid or expired login session."
        });
    }
});


/* =========================
   START SERVER
========================= */

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Fortiva Capital backend running on port ${PORT}`);
});
