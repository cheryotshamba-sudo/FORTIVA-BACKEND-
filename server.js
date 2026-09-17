const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 10000;

const JWT_SECRET =
  process.env.JWT_SECRET || "fortiva-development-secret";

const PAYLOR_API_KEY = process.env.PAYLOR_API_KEY;
const PAYLOR_CHANNEL_ID = process.env.PAYLOR_CHANNEL_ID;
const PAYLOR_WEBHOOK_SECRET = process.env.PAYLOR_WEBHOOK_SECRET;

const BACKEND_URL =
  process.env.BACKEND_URL ||
  "https://fortiva-backend-hvqy.onrender.com";

const PAYLOR_BASE_URL =
  "https://api.paylorke.com/api/v1";


// --------------------------------------------------
// MIDDLEWARE
// --------------------------------------------------

app.use(cors());

app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    }
  })
);


// --------------------------------------------------
// TEMPORARY IN-MEMORY STORAGE
// --------------------------------------------------

const users = [];
const deposits = [];


// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get("/", (req, res) => {
  res.json({
    message: "Fortiva Capital backend is running"
  });
});


// --------------------------------------------------
// REGISTER
// --------------------------------------------------

app.post("/api/register", async (req, res) => {
  try {
    const {
      fullName,
      email,
      phone,
      password
    } = req.body;

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

    const hashedPassword = await bcrypt.hash(
      password,
      10
    );

    const user = {
      id: Date.now().toString(),
      fullName,
      email: email.toLowerCase(),
      phone,
      password: hashedPassword,
      balance: 0
    };

    users.push(user);

    res.status(201).json({
      message: "Account created successfully"
    });

  } catch (error) {

    console.error(
      "Registration error:",
      error
    );

    res.status(500).json({
      message: "Server error"
    });
  }
});


// --------------------------------------------------
// LOGIN
// --------------------------------------------------

app.post("/api/login", async (req, res) => {
  try {

    const {
      identifier,
      password
    } = req.body;

    if (!identifier || !password) {
      return res.status(400).json({
        message:
          "Phone number/email and password are required"
      });
    }

    const loginValue =
      identifier.trim();

    const user = users.find(
      user =>
        user.email.toLowerCase() ===
          loginValue.toLowerCase() ||
        user.phone === loginValue
    );

    if (!user) {
      return res.status(401).json({
        message:
          "Invalid phone number/email or password"
      });
    }

    const passwordCorrect =
      await bcrypt.compare(
        password,
        user.password
      );

    if (!passwordCorrect) {
      return res.status(401).json({
        message:
          "Invalid phone number/email or password"
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
        phone: user.phone,
        balance: user.balance || 0
      }
    });

  } catch (error) {

    console.error(
      "Login error:",
      error
    );

    res.status(500).json({
      message: "Server error"
    });
  }
});


// --------------------------------------------------
// JWT AUTHENTICATION
// --------------------------------------------------

function authenticateToken(req, res, next) {

  const authHeader =
    req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      message: "Authentication required"
    });
  }

  const parts =
    authHeader.split(" ");

  if (
    parts.length !== 2 ||
    parts[0] !== "Bearer"
  ) {
    return res.status(401).json({
      message: "Invalid authorization header"
    });
  }

  const token = parts[1];

  try {

    const decoded =
      jwt.verify(
        token,
        JWT_SECRET
      );

    req.user = decoded;

    next();

  } catch (error) {

    return res.status(401).json({
      message: "Invalid or expired token"
    });
  }
}


// --------------------------------------------------
// GET CURRENT USER
// --------------------------------------------------

app.get(
  "/api/me",
  authenticateToken,
  (req, res) => {

    const user =
      users.find(
        user =>
          user.id === req.user.id
      );

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    res.json({
      user: {
        id: user.id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        balance: user.balance || 0
      }
    });
  }
);


// --------------------------------------------------
// DEPOSIT / PAYLOR STK PUSH
// --------------------------------------------------

app.post(
  "/api/deposit",
  authenticateToken,
  async (req, res) => {

    try {

      const {
        amount,
        phone
      } = req.body;


      // -----------------------------
      // CHECK PAYLOR CONFIGURATION
      // -----------------------------

      if (!PAYLOR_API_KEY) {

        console.error(
          "PAYLOR_API_KEY is missing"
        );

        return res.status(500).json({
          message:
            "Paylor API key is not configured"
        });
      }


      // -----------------------------
      // VALIDATE AMOUNT
      // -----------------------------

      const depositAmount =
        Number(amount);

      if (
        !Number.isFinite(
          depositAmount
        ) ||
        depositAmount <= 0
      ) {

        return res.status(400).json({
          message:
            "Enter a valid deposit amount"
        });
      }


      // -----------------------------
      // NORMALIZE PHONE NUMBER
      // -----------------------------

      let normalizedPhone =
        String(phone || "")
          .trim()
          .replace(/\s+/g, "");


      if (
        normalizedPhone.startsWith("+254")
      ) {

        normalizedPhone =
          normalizedPhone.substring(1);

      } else if (
        normalizedPhone.startsWith("07") ||
        normalizedPhone.startsWith("01")
      ) {

        normalizedPhone =
          "254" +
          normalizedPhone.substring(1);
      }


      // -----------------------------
      // VALIDATE KENYAN PHONE
      // -----------------------------

      if (
        !/^254[17]\d{8}$/.test(
          normalizedPhone
        )
      ) {

        return res.status(400).json({
          message:
            "Enter a valid Kenyan M-Pesa phone number"
        });
      }


      // -----------------------------
      // UNIQUE PAYMENT REFERENCE
      // -----------------------------

      const reference =
        "FORTIVA-" +
        Date.now() +
        "-" +
        crypto
          .randomBytes(4)
          .toString("hex")
          .toUpperCase();


      // -----------------------------
      // CREATE DEPOSIT RECORD
      // -----------------------------

      const deposit = {

        id: Date.now().toString(),

        userId: req.user.id,

        amount: depositAmount,

        phone: normalizedPhone,

        reference,

        status: "PENDING",

        createdAt:
          new Date().toISOString()
      };

      deposits.push(deposit);


      // -----------------------------
      // PAYLOR REQUEST
      // -----------------------------

      const paylorBody = {

        phone: normalizedPhone,

        amount: depositAmount,

        reference,

        description:
          `Fortiva Capital deposit ${reference}`,

        callbackUrl:
          `${BACKEND_URL}/api/paylor-callback`
      };


      // Only send channelId when it exists
      if (PAYLOR_CHANNEL_ID) {

        paylorBody.channelId =
          PAYLOR_CHANNEL_ID;
      }


      console.log(
        "Sending Paylor STK Push:",
        {
          phone: normalizedPhone,
          amount: depositAmount,
          reference
        }
      );


      const paylorResponse =
        await fetch(
          `${PAYLOR_BASE_URL}/merchants/payments/stk-push`,
          {
            method: "POST",

            headers: {
              "Authorization":
                `Bearer ${PAYLOR_API_KEY}`,

              "Content-Type":
                "application/json",

              "Idempotency-Key":
                reference
            },

            body:
              JSON.stringify(
                paylorBody
              )
          }
        );


      const paylorData =
        await paylorResponse
          .json()
          .catch(() => ({}));


      console.log(
        "Paylor response:",
        paylorResponse.status,
        paylorData
      );


      // -----------------------------
      // PAYLOR ERROR
      // -----------------------------

      if (!paylorResponse.ok) {

        deposit.status = "FAILED";

        return res.status(
          paylorResponse.status
        ).json({

          message:
            paylorData?.error?.message ||
            paylorData?.message ||
            "Paylor could not initiate the STK Push",

          error:
            paylorData?.error?.code ||
            paylorData?.error ||
            null,

          reference
        });
      }


      // -----------------------------
      // STK PUSH SENT
      // -----------------------------

      deposit.gatewayTransactionId =
        paylorData.transactionId ||
        paylorData.id ||
        null;

      deposit.status =
        paylorData.status ||
        "SENT";


      return res.json({

        message:
          "STK Push sent successfully. Check your M-Pesa phone and enter your PIN.",

        status:
          deposit.status,

        transactionId:
          deposit.gatewayTransactionId,

        reference
      });

    } catch (error) {

      console.error(
        "Deposit error:",
        error
      );

      return res.status(500).json({
        message:
          "Unable to send STK Push"
      });
    }
  }
);


// --------------------------------------------------
// PAYLOR CALLBACK
// --------------------------------------------------

app.post(
  "/api/paylor-callback",
  async (req, res) => {

    try {

      const signature =
        req.headers[
          "x-webhook-signature"
        ];

      if (!PAYLOR_WEBHOOK_SECRET) {

        console.error(
          "PAYLOR_WEBHOOK_SECRET is missing"
        );

        return res.status(500).json({
          message:
            "Webhook secret is not configured"
        });
      }


      if (!signature) {

        return res.status(401).json({
          message:
            "Missing webhook signature"
        });
      }


      const expectedSignature =
        crypto
          .createHmac(
            "sha256",
            PAYLOR_WEBHOOK_SECRET
          )
          .update(
            req.rawBody
          )
          .digest("hex");


      const signatureBuffer =
        Buffer.from(
          signature,
          "utf8"
        );

      const expectedBuffer =
        Buffer.from(
          expectedSignature,
          "utf8"
        );


      if (
        signatureBuffer.length !==
        expectedBuffer.length ||
        !crypto.timingSafeEqual(
          signatureBuffer,
          expectedBuffer
        )
      ) {

        console.error(
          "Invalid Paylor webhook signature"
        );

        return res.status(401).json({
          message:
            "Invalid webhook signature"
        });
      }


      const {
        event,
        transaction
      } = req.body;


      console.log(
        "Paylor callback:",
        event,
        transaction
      );


      if (!transaction) {

        return res.json({
          received: true
        });
      }


      const reference =
        transaction.reference;


      const deposit =
        deposits.find(
          item =>
            item.reference ===
            reference
        );


      if (!deposit) {

        console.warn(
          "Deposit not found:",
          reference
        );

        return res.json({
          received: true
        });
      }


      // -----------------------------
      // PAYMENT SUCCESS
      // -----------------------------

      if (
        event === "payment.success" ||
        transaction.status === "COMPLETED"
      ) {

        deposit.status =
          "COMPLETED";

        deposit.providerRef =
          transaction.providerRef ||
          null;

        deposit.mpesaReceipt =
          transaction.mpesaReceipt ||
          null;

        deposit.completedAt =
          new Date().toISOString();


        // Find account
        const user =
          users.find(
            item =>
              item.id ===
              deposit.userId
          );


        if (user) {

          user.balance =
            (user.balance || 0) +
            Number(deposit.amount);

          console.log(
            `Deposit completed for ${user.email}: KES ${deposit.amount}`
          );
        }
      }


      // -----------------------------
      // PAYMENT FAILED
      // -----------------------------

      if (
        event === "payment.failed" ||
        transaction.status === "FAILED"
      ) {

        deposit.status =
          "FAILED";

        deposit.failedAt =
          new Date().toISOString();
      }


      return res.json({
        received: true
      });

    } catch (error) {

      console.error(
        "Paylor callback error:",
        error
      );

      return res.status(500).json({
        message:
          "Callback processing error"
      });
    }
  }
);


// --------------------------------------------------
// START SERVER
// --------------------------------------------------

app.listen(
  PORT,
  () => {

    console.log(
      `Fortiva Capital backend running on port ${PORT}`
    );
  }
);
