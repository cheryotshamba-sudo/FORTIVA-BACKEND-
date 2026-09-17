const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET =
  process.env.JWT_SECRET || "fortiva-development-secret";

app.use(cors());
app.use(express.json());

// Temporary in-memory account storage
const users = [];

// Health check
app.get("/", (req, res) => {
  res.json({
    message: "Fortiva Capital backend is running"
  });
});

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { fullName, email, phone, password } = req.body;

    if (!fullName || !email || !phone || !password) {
      return res.status(400).json({
        message: "All fields are required"
      });
    }

    const existingUser = users.find(
      user =>
        user.email.toLowerCase() === email.toLowerCase() ||
        user.phone === phone
    );

    if (existingUser) {
      return res.status(409).json({
        message: "Email or phone number already registered"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = {
      id: Date.now().toString(),
      fullName,
      email: email.toLowerCase(),
      phone,
      password: hashedPassword
    };

    users.push(user);

    res.status(201).json({
      message: "Account created successfully"
    });
  } catch (error) {
    console.error("Registration error:", error);

    res.status(500).json({
      message: "Server error"
    });
  }
});

// LOGIN
// The identifier can be either EMAIL or PHONE NUMBER
app.post("/api/login", async (req, res) => {
  try {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
      return res.status(400).json({
        message: "Phone number/email and password are required"
      });
    }

    const loginValue = identifier.trim();

    const user = users.find(
      user =>
        user.email.toLowerCase() === loginValue.toLowerCase() ||
        user.phone === loginValue
    );

    if (!user) {
      return res.status(401).json({
        message: "Invalid phone number/email or password"
      });
    }

    const passwordCorrect = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordCorrect) {
      return res.status(401).json({
        message: "Invalid phone number/email or password"
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        phone: user.phone
      },
      JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone
      }
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      message: "Server error"
    });
  }
});

app.listen(PORT, () => {
  console.log(`Fortiva Capital backend running on port ${PORT}`);
});
