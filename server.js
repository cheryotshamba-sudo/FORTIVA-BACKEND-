const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

// ======================================================
// CONFIGURATION
// ======================================================

const PORT = process.env.PORT || 10000;

const JWT_SECRET =
  process.env.JWT_SECRET || "fortiva-development-secret";

const DATABASE_URL = process.env.DATABASE_URL;

const PAYLOR_API_KEY = process.env.PAYLOR_API_KEY;
const PAYLOR_CHANNEL_ID = process.env.PAYLOR_CHANNEL_ID;
const PAYLOR_WEBHOOK_SECRET = process.env.PAYLOR_WEBHOOK_SECRET;

const BACKEND_URL =
  process.env.BACKEND_URL ||
  "https://fortiva-backend-hvqy.onrender.com";

const PAYLOR_BASE_URL =
  "https://api.paylorke.com/api/v1";

// ======================================================
// DATABASE
// ======================================================

if (!DATABASE_URL) {
  console.error("DATABASE_URL is not configured");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

pool.on("error", (err) => {
  console.error("Unexpected PostgreSQL pool error:", err);
});

// ======================================================
// MIDDLEWARE
// ======================================================

app.use(cors());

// IMPORTANT:
// Keep raw body for Paylor webhook signature verification.
app.use(
  "/api/paylor-callback",
  express.raw({
    type: "*/*",
  })
);

app.use(express.json());

// ======================================================
// DATABASE SETUP
// ======================================================

async function setupDatabase() {
  const client = await pool.connect();

  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        full_name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        balance NUMERIC(12,2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS deposits (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id),
        amount NUMERIC(12,2) NOT NULL,
        phone TEXT NOT NULL,
        reference TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING',
        gateway_transaction_id TEXT,
        provider_ref TEXT,
        mpesa_receipt TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        failed_at TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS withdrawals (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id),
        amount NUMERIC(12,2) NOT NULL,
        phone TEXT NOT NULL,
        reference TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        failed_at TIMESTAMP
      )
    `);

    // Add Paylor tracking columns to existing withdrawals table.
    await client.query(`
      ALTER TABLE withdrawals
      ADD COLUMN IF NOT EXISTS gateway_transaction_id TEXT
    `);

    await client.query(`
      ALTER TABLE withdrawals
      ADD COLUMN IF NOT EXISTS provider_ref TEXT
    `);

    await client.query(`
      ALTER TABLE withdrawals
      ADD COLUMN IF NOT EXISTS mpesa_receipt TEXT
    `);

    await client.query(`
      ALTER TABLE withdrawals
      ADD COLUMN IF NOT EXISTS refunded_at TIMESTAMP
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS investments (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id),
        amount NUMERIC(12,2) NOT NULL,
        reference TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log("Database tables ready");
  } finally {
    client.release();
  }
}

// ======================================================
// HELPERS
// ======================================================

function normalizeKenyanPhone(phone) {
  if (!phone) return null;

  let value = String(phone).trim();

  if (value.startsWith("+254")) {
    value = value.substring(1);
  }

  if (value.startsWith("07") || value.startsWith("01")) {
    value = "254" + value.substring(1);
  }

  if (/^254[17]\d{8}$/.test(value)) {
    return value;
  }

  return null;
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function generateId() {
  return crypto.randomUUID();
}

function generateReference(prefix) {
  return `${prefix}-${Date.now()}-${crypto
    .randomBytes(4)
    .toString("hex")
    .toUpperCase()}`;
}

function verifyPaylorWebhook(rawBody, signature) {
  if (!PAYLOR_WEBHOOK_SECRET) {
    return false;
  }

  if (!signature) {
    return false;
  }

  const expected = crypto
    .createHmac("sha256", PAYLOR_WEBHOOK_SECRET)
    .update(rawBody)
    .digest("hex");

  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected),
      Buffer.from(signature)
    );
  } catch {
    return false;
  }
}

function getWebhookBody(req) {
  try {
    if (Buffer.isBuffer(req.body)) {
      return JSON.parse(req.body.toString("utf8"));
    }

    return req.body || {};
  } catch (error) {
    console.error("Webhook JSON parse error:", error.message);
    return {};
  }
}

// ======================================================
// ROOT
// ======================================================

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Fortiva Capital backend is running",
  });
});

// ======================================================
// REGISTER
// ======================================================

app.post("/api/register", async (req, res) => {
  try {
    const { fullName, email, phone, password } = req.body;

    if (!fullName || !email || !phone || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({
        success: false,
        message: "Invalid email address",
      });
    }

    const normalizedPhone = normalizeKenyanPhone(phone);

    if (!normalizedPhone) {
      return res.status(400).json({
        success: false,
        message: "Invalid Kenyan phone number",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters",
      });
    }

    const existing = await pool.query(
      `
      SELECT id
      FROM users
      WHERE email = $1 OR phone = $2
      LIMIT 1
      `,
      [email.toLowerCase().trim(), normalizedPhone]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Email or phone number already registered",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const userId = generateId();

    await pool.query(
      `
      INSERT INTO users
      (id, full_name, email, phone, password, balance)
      VALUES ($1, $2, $3, $4, $5, 0)
      `,
      [
        userId,
        fullName.trim(),
        email.toLowerCase().trim(),
        normalizedPhone,
        hashedPassword,
      ]
    );

    res.json({
      success: true,
      message: "Account created successfully",
      userId,
    });
  } catch (error) {
    console.error("Register error:", error);

    res.status(500).json({
      success: false,
      message: "Registration failed",
    });
  }
});

// ======================================================
// LOGIN
// ======================================================

app.post("/api/login", async (req, res) => {
  try {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
      return res.status(400).json({
        success: false,
        message: "Phone number/email and password are required",
      });
    }

    const value = identifier.trim();

    let userResult;

    if (value.includes("@")) {
      userResult = await pool.query(
        `
        SELECT *
        FROM users
        WHERE LOWER(email) = LOWER($1)
        LIMIT 1
        `,
        [value]
      );
    } else {
      const normalizedPhone = normalizeKenyanPhone(value);

      if (!normalizedPhone) {
        return res.status(401).json({
          success: false,
          message: "Invalid phone number or password",
        });
      }

      userResult = await pool.query(
        `
        SELECT *
        FROM users
        WHERE phone = $1
        LIMIT 1
        `,
        [normalizedPhone]
      );
    }

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Invalid phone number or password",
      });
    }

    const user = userResult.rows[0];

    const passwordMatches = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordMatches) {
      return res.status(401).json({
        success: false,
        message: "Invalid phone number or password",
      });
    }

    const token = jwt.sign(
      {
        userId: user.id,
      },
      JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        phone: user.phone,
        balance: Number(user.balance),
      },
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      success: false,
      message: "Login failed",
    });
  }
});

// ======================================================
// AUTHENTICATION
// ======================================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Authentication required",
    });
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    req.userId = decoded.userId;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token",
    });
  }
}

// ======================================================
// CURRENT USER
// ======================================================

app.get("/api/me", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id, full_name, email, phone, balance, created_at
      FROM users
      WHERE id = $1
      `,
      [req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const user = result.rows[0];

    res.json({
      success: true,
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        phone: user.phone,
        balance: Number(user.balance),
        createdAt: user.created_at,
      },
    });
  } catch (error) {
    console.error("Me error:", error);

    res.status(500).json({
      success: false,
      message: "Could not load user",
    });
  }
});

// ======================================================
// COMPLETE DEPOSIT
// ======================================================

async function completeDeposit(deposit, payment) {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const lockedDeposit = await client.query(
      `
      SELECT *
      FROM deposits
      WHERE id = $1
      FOR UPDATE
      `,
      [deposit.id]
    );

    if (lockedDeposit.rows.length === 0) {
      throw new Error("Deposit not found");
    }

    const currentDeposit = lockedDeposit.rows[0];

    // Prevent double-crediting.
    if (currentDeposit.status === "COMPLETED") {
      await client.query("COMMIT");
      return;
    }

    const userResult = await client.query(
      `
      SELECT *
      FROM users
      WHERE id = $1
      FOR UPDATE
      `,
      [currentDeposit.user_id]
    );

    if (userResult.rows.length === 0) {
      throw new Error("User not found");
    }

    const user = userResult.rows[0];

    const newBalance =
      Number(user.balance) + Number(currentDeposit.amount);

    await client.query(
      `
      UPDATE users
      SET balance = $1
      WHERE id = $2
      `,
      [newBalance, currentDeposit.user_id]
    );

    await client.query(
      `
      UPDATE deposits
      SET
        status = 'COMPLETED',
        gateway_transaction_id = COALESCE($1, gateway_transaction_id),
        provider_ref = COALESCE($2, provider_ref),
        mpesa_receipt = COALESCE($3, mpesa_receipt),
        completed_at = CURRENT_TIMESTAMP
      WHERE id = $4
      `,
      [
        payment.transactionId || null,
        payment.providerRef || null,
        payment.mpesaReceipt || null,
        currentDeposit.id,
      ]
    );

    await client.query("COMMIT");

    console.log(
      `Deposit completed: ${currentDeposit.reference} KES ${currentDeposit.amount}`
    );
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

// ======================================================
// DEPOSIT
// ======================================================

app.post("/api/deposit", authenticateToken, async (req, res) => {
  try {
    const { amount, phone } = req.body;

    const numericAmount = Number(amount);

    if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid deposit amount",
      });
    }

    const normalizedPhone = normalizeKenyanPhone(phone);

    if (!normalizedPhone) {
      return res.status(400).json({
        success: false,
        message: "Invalid Kenyan phone number",
      });
    }

    if (!PAYLOR_API_KEY || !PAYLOR_CHANNEL_ID) {
      return res.status(500).json({
        success: false,
        message: "Payment gateway is not configured",
      });
    }

    const reference = generateReference("FORTIVA");
    const depositId = generateId();

    await pool.query(
      `
      INSERT INTO deposits
      (id, user_id, amount, phone, reference, status)
      VALUES ($1, $2, $3, $4, $5, 'PENDING')
      `,
      [
        depositId,
        req.userId,
        numericAmount,
        normalizedPhone,
        reference,
      ]
    );

    try {
      const response = await fetch(
        `${PAYLOR_BASE_URL}/merchants/payments/stk-push`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${PAYLOR_API_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            phone: normalizedPhone,
            amount: numericAmount,
            reference,
            channelId: PAYLOR_CHANNEL_ID,
            callbackUrl: `${BACKEND_URL}/api/paylor-callback`,
          }),
        }
      );

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        await pool.query(
          `
          UPDATE deposits
          SET status = 'FAILED',
              failed_at = CURRENT_TIMESTAMP
          WHERE id = $1
          `,
          [depositId]
        );

        return res.status(400).json({
          success: false,
          message:
            data.message ||
            data.error ||
            "Payment request failed",
        });
      }

      const gatewayTransactionId =
        data.transactionId ||
        data.id ||
        null;

      await pool.query(
        `
        UPDATE deposits
        SET
          gateway_transaction_id = $1,
          status = $2
        WHERE id = $3
        `,
        [
          gatewayTransactionId,
          data.status || "PENDING",
          depositId,
        ]
      );

      res.json({
        success: true,
        message:
          data.message ||
          "STK Push sent successfully",
        depositId,
        reference,
        transactionId: gatewayTransactionId,
        status: data.status || "PENDING",
      });
    } catch (gatewayError) {
      console.error(
        "Paylor deposit error:",
        gatewayError
      );

      await pool.query(
        `
        UPDATE deposits
        SET status = 'FAILED',
            failed_at = CURRENT_TIMESTAMP
        WHERE id = $1
        `,
        [depositId]
      );

      return res.status(500).json({
        success: false,
        message: "Could not connect to payment gateway",
      });
    }
  } catch (error) {
    console.error("Deposit error:", error);

    res.status(500).json({
      success: false,
      message: "Deposit failed",
    });
  }
});

// ======================================================
// PAYLOR CALLBACK
// Handles BOTH deposits and withdrawals.
// ======================================================

app.post("/api/paylor-callback", async (req, res) => {
  try {
    const rawBody = Buffer.isBuffer(req.body)
      ? req.body
      : Buffer.from(JSON.stringify(req.body || {}));

    const signature =
      req.headers["x-webhook-signature"];

    if (
      PAYLOR_WEBHOOK_SECRET &&
      !verifyPaylorWebhook(rawBody, signature)
    ) {
      console.error("Invalid Paylor webhook signature");

      return res.status(401).json({
        success: false,
        message: "Invalid webhook signature",
      });
    }

    const body = getWebhookBody(req);

    console.log("Paylor callback received:", body);

    const payment =
      body.payment ||
      body.transaction ||
      body.data ||
      body;

    const reference =
      payment.reference ||
      body.reference ||
      body.internalReference;

    if (!reference) {
      return res.status(200).json({
        success: true,
        message: "Callback received without reference",
      });
    }

    const statusRaw =
      payment.status ||
      body.status ||
      payment.event ||
      body.event ||
      "";

    const status = String(statusRaw).toUpperCase();

    const event = String(
      payment.event ||
      body.event ||
      ""
    ).toLowerCase();

    const providerRef =
      payment.providerRef ||
      payment.providerReference ||
      body.providerRef ||
      null;

    const mpesaReceipt =
      payment.mpesaReceipt ||
      payment.mpesa_receipt ||
      body.mpesaReceipt ||
      body.mpesa_receipt ||
      payment.metadata?.mpesaReceipt ||
      body.metadata?.mpesaReceipt ||
      null;

    const transactionId =
      payment.transactionId ||
      payment.id ||
      body.transactionId ||
      body.id ||
      null;

    // ==================================================
    // WITHDRAWAL CALLBACK
    // ==================================================

    if (reference.startsWith("WDR-")) {
      const isCompleted =
        status === "COMPLETED" ||
        status === "SUCCESS" ||
        status === "SUCCEEDED" ||
        event === "payment.success" ||
        event === "payment.completed";

      const isFailed =
        status === "FAILED" ||
        status === "CANCELLED" ||
        status === "CANCELED" ||
        status === "REJECTED" ||
        status === "ERROR" ||
        event === "payment.failed" ||
        event === "payment.failure";

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        const withdrawalResult = await client.query(
          `
          SELECT *
          FROM withdrawals
          WHERE reference = $1
          FOR UPDATE
          `,
          [reference]
        );

        if (withdrawalResult.rows.length === 0) {
          await client.query("ROLLBACK");

          return res.status(200).json({
            success: true,
            message: "Withdrawal reference not found",
          });
        }

        const withdrawal =
          withdrawalResult.rows[0];

        if (isCompleted) {
          if (
            withdrawal.status !== "COMPLETED"
          ) {
            await client.query(
              `
              UPDATE withdrawals
              SET
                status = 'COMPLETED',
                gateway_transaction_id =
                  COALESCE($1, gateway_transaction_id),
                provider_ref =
                  COALESCE($2, provider_ref),
                mpesa_receipt =
                  COALESCE($3, mpesa_receipt),
                completed_at = CURRENT_TIMESTAMP
              WHERE id = $4
              `,
              [
                transactionId,
                providerRef,
                mpesaReceipt,
                withdrawal.id,
              ]
            );
          }

          await client.query("COMMIT");

          console.log(
            `Withdrawal completed: ${reference} KES ${withdrawal.amount}`
          );

          return res.status(200).json({
            success: true,
            message: "Withdrawal callback processed",
          });
        }

        if (isFailed) {
          // Refund only if this withdrawal has not already
          // been completed or refunded.
          if (
            withdrawal.status !== "FAILED" &&
            withdrawal.status !== "COMPLETED"
          ) {
            const userResult = await client.query(
              `
              SELECT balance
              FROM users
              WHERE id = $1
              FOR UPDATE
              `,
              [withdrawal.user_id]
            );

            if (userResult.rows.length > 0) {
              const currentBalance =
                Number(userResult.rows[0].balance);

              const refundedBalance =
                currentBalance +
                Number(withdrawal.amount);

              await client.query(
                `
                UPDATE users
                SET balance = $1
                WHERE id = $2
                `,
                [
                  refundedBalance,
                  withdrawal.user_id,
                ]
              );
            }

            await client.query(
              `
              UPDATE withdrawals
              SET
                status = 'FAILED',
                gateway_transaction_id =
                  COALESCE($1, gateway_transaction_id),
                provider_ref =
                  COALESCE($2, provider_ref),
                mpesa_receipt =
                  COALESCE($3, mpesa_receipt),
                failed_at = CURRENT_TIMESTAMP,
                refunded_at = CURRENT_TIMESTAMP
              WHERE id = $4
              `,
              [
                transactionId,
                providerRef,
                mpesaReceipt,
                withdrawal.id,
              ]
            );

            console.log(
              `Withdrawal failed and refunded: ${reference} KES ${withdrawal.amount}`
            );
          }

          await client.query("COMMIT");

          return res.status(200).json({
            success: true,
            message: "Withdrawal failure processed",
          });
        }

        await client.query(
          `
          UPDATE withdrawals
          SET
            gateway_transaction_id =
              COALESCE($1, gateway_transaction_id),
            provider_ref =
              COALESCE($2, provider_ref),
            mpesa_receipt =
              COALESCE($3, mpesa_receipt)
          WHERE id = $4
          `,
          [
            transactionId,
            providerRef,
            mpesaReceipt,
            withdrawal.id,
          ]
        );

        await client.query("COMMIT");

        return res.status(200).json({
          success: true,
          message: "Withdrawal status received",
        });
      } catch (withdrawalCallbackError) {
        await client.query("ROLLBACK");

        console.error(
          "Withdrawal callback error:",
          withdrawalCallbackError
        );

        return res.status(500).json({
          success: false,
          message: "Withdrawal callback processing failed",
        });
      } finally {
        client.release();
      }
    }

    // ==================================================
    // DEPOSIT CALLBACK
    // ==================================================

    const depositResult = await pool.query(
      `
      SELECT *
      FROM deposits
      WHERE reference = $1
      LIMIT 1
      `,
      [reference]
    );

    if (depositResult.rows.length === 0) {
      return res.status(200).json({
        success: true,
        message: "Deposit reference not found",
      });
    }

    const deposit = depositResult.rows[0];

    const depositCompleted =
      status === "COMPLETED" ||
      status === "SUCCESS" ||
      status === "SUCCEEDED" ||
      event === "payment.success" ||
      event === "payment.completed" ||
      payment.metadata?.callbackResultCode === 0 ||
      body.metadata?.callbackResultCode === 0;

    const depositFailed =
      status === "FAILED" ||
      status === "CANCELLED" ||
      status === "CANCELED" ||
      status === "REJECTED" ||
      event === "payment.failed" ||
      event === "payment.failure";

    if (depositCompleted) {
      await completeDeposit(deposit, {
        transactionId,
        providerRef,
        mpesaReceipt,
      });

      return res.status(200).json({
        success: true,
        message: "Deposit completed",
      });
    }

    if (depositFailed) {
      await pool.query(
        `
        UPDATE deposits
        SET
          status = 'FAILED',
          gateway_transaction_id =
            COALESCE($1, gateway_transaction_id),
          provider_ref =
            COALESCE($2, provider_ref),
          mpesa_receipt =
            COALESCE($3, mpesa_receipt),
          failed_at = CURRENT_TIMESTAMP
        WHERE id = $4
          AND status <> 'COMPLETED'
        `,
        [
          transactionId,
          providerRef,
          mpesaReceipt,
          deposit.id,
        ]
      );

      return res.status(200).json({
        success: true,
        message: "Deposit marked failed",
      });
    }

    await pool.query(
      `
      UPDATE deposits
      SET
        gateway_transaction_id =
          COALESCE($1, gateway_transaction_id),
        provider_ref =
          COALESCE($2, provider_ref),
        mpesa_receipt =
          COALESCE($3, mpesa_receipt),
        status = COALESCE($4, status)
      WHERE id = $5
      `,
      [
        transactionId,
        providerRef,
        mpesaReceipt,
        payment.status || body.status || null,
        deposit.id,
      ]
    );

    return res.status(200).json({
      success: true,
      message: "Deposit callback received",
    });
  } catch (error) {
    console.error(
      "Paylor callback error:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Callback processing failed",
    });
  }
});

// ======================================================
// PAYMENT STATUS - DEPOSITS
// ======================================================

app.get(
  "/api/payment-status",
  authenticateToken,
  async (req, res) => {
    try {
      const transactionId =
        req.query.transactionId;

      if (!transactionId) {
        return res.status(400).json({
          success: false,
          message: "Transaction ID is required",
        });
      }

      const depositResult = await pool.query(
        `
        SELECT *
        FROM deposits
        WHERE gateway_transaction_id = $1
          AND user_id = $2
        LIMIT 1
        `,
        [transactionId, req.userId]
      );

      if (depositResult.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Deposit not found",
        });
      }

      const deposit =
        depositResult.rows[0];

      if (deposit.status === "COMPLETED") {
        return res.json({
          success: true,
          status: "COMPLETED",
          amount: Number(deposit.amount),
          reference: deposit.reference,
          mpesaReceipt: deposit.mpesa_receipt,
        });
      }

      if (!PAYLOR_API_KEY) {
        return res.json({
          success: true,
          status: deposit.status,
          reference: deposit.reference,
        });
      }

      const response = await fetch(
        `${PAYLOR_BASE_URL}/merchants/payments/transactions/${encodeURIComponent(
          transactionId
        )}`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${PAYLOR_API_KEY}`,
          },
        }
      );

      const data = await response.json().catch(
        () => ({})
      );

      if (response.ok) {
        const status = String(
          data.status || ""
        ).toUpperCase();

        const payment = {
          transactionId:
            data.transactionId ||
            data.id ||
            transactionId,
          providerRef:
            data.providerRef || null,
          mpesaReceipt:
            data.mpesaReceipt ||
            data.metadata?.mpesaReceipt ||
            null,
        };

        if (
          status === "COMPLETED" ||
          status === "SUCCESS" ||
          status === "SUCCEEDED"
        ) {
          await completeDeposit(
            deposit,
            payment
          );

          return res.json({
            success: true,
            status: "COMPLETED",
            amount: Number(deposit.amount),
            reference: deposit.reference,
            mpesaReceipt:
              payment.mpesaReceipt,
          });
        }

        if (
          status === "FAILED" ||
          status === "CANCELLED" ||
          status === "CANCELED" ||
          status === "REJECTED"
        ) {
          await pool.query(
            `
            UPDATE deposits
            SET
              status = 'FAILED',
              provider_ref =
                COALESCE($1, provider_ref),
              mpesa_receipt =
                COALESCE($2, mpesa_receipt),
              failed_at = CURRENT_TIMESTAMP
            WHERE id = $3
              AND status <> 'COMPLETED'
            `,
            [
              payment.providerRef,
              payment.mpesaReceipt,
              deposit.id,
            ]
          );

          return res.json({
            success: true,
            status: "FAILED",
            reference: deposit.reference,
          });
        }
      }

      return res.json({
        success: true,
        status: deposit.status,
        reference: deposit.reference,
      });
    } catch (error) {
      console.error(
        "Payment status error:",
        error
      );

      res.status(500).json({
        success: false,
        message: "Could not check payment status",
      });
    }
  }
);

// ======================================================
// WITHDRAWAL - PAYLOR B2C
// ======================================================

app.post(
  "/api/withdraw",
  authenticateToken,
  async (req, res) => {
    const client = await pool.connect();

    let withdrawalId = null;
    let reference = null;
    let amount = null;

    try {
      amount = Number(req.body.amount);
      const phone = req.body.phone;

      // Paylor B2C limits from the API documentation.
      if (
        !Number.isFinite(amount) ||
        amount < 10 ||
        amount > 150000
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Withdrawal amount must be between KES 10 and KES 150,000",
        });
      }

      const normalizedPhone =
        normalizeKenyanPhone(phone);

      if (!normalizedPhone) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid Kenyan M-Pesa phone number",
        });
      }

      if (!PAYLOR_API_KEY) {
        return res.status(500).json({
          success: false,
          message:
            "Paylor API key is not configured",
        });
      }

      // --------------------------------------------------
      // Reserve/deduct balance first.
      // This prevents another withdrawal from spending
      // the same balance while Paylor is being contacted.
      // --------------------------------------------------

      await client.query("BEGIN");

      const userResult = await client.query(
        `
        SELECT id, balance
        FROM users
        WHERE id = $1
        FOR UPDATE
        `,
        [req.userId]
      );

      if (userResult.rows.length === 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      const currentBalance =
        Number(userResult.rows[0].balance);

      if (currentBalance < amount) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          success: false,
          message: "Insufficient balance",
          balance: currentBalance,
        });
      }

      const newBalance =
        currentBalance - amount;

      withdrawalId = generateId();
      reference = generateReference("WDR");

      await client.query(
        `
        UPDATE users
        SET balance = $1
        WHERE id = $2
        `,
        [newBalance, req.userId]
      );

      await client.query(
        `
        INSERT INTO withdrawals
        (
          id,
          user_id,
          amount,
          phone,
          reference,
          status
        )
        VALUES ($1, $2, $3, $4, $5, 'PENDING')
        `,
        [
          withdrawalId,
          req.userId,
          amount,
          normalizedPhone,
          reference,
        ]
      );

      await client.query("COMMIT");

      // --------------------------------------------------
      // Send B2C request to Paylor.
      // --------------------------------------------------

      let response;

      try {
        response = await fetch(
          `${PAYLOR_BASE_URL}/merchants/payments/b2c`,
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${PAYLOR_API_KEY}`,
              "Content-Type": "application/json",
              "Idempotency-Key": reference,
            },
            body: JSON.stringify({
              phone: normalizedPhone,
              amount,
              reference,
              remarks:
                "Fortiva Capital withdrawal",
              commandId: "BusinessPayment",
              callbackUrl:
                `${BACKEND_URL}/api/paylor-callback`,
            }),
          }
        );
      } catch (gatewayError) {
        console.error(
          "Paylor B2C connection error:",
          gatewayError
        );

        await refundFailedWithdrawal(
          withdrawalId
        );

        return res.status(502).json({
          success: false,
          message:
            "Could not connect to Paylor. Your balance has been restored.",
        });
      }

      const data = await response.json().catch(
        () => ({})
      );

      console.log(
        "Paylor B2C response:",
        data
      );

      const gatewayTransactionId =
        data.transactionId ||
        data.id ||
        null;

      const gatewayStatus = String(
        data.status || ""
      ).toUpperCase();

      // --------------------------------------------------
      // Paylor rejected the payout.
      // Refund immediately.
      // --------------------------------------------------

      if (
        !response.ok ||
        !gatewayTransactionId
      ) {
        await refundFailedWithdrawal(
          withdrawalId,
          gatewayTransactionId
        );

        return res.status(400).json({
          success: false,
          message:
            data.message ||
            data.error ||
            "Paylor rejected the withdrawal. Your balance has been restored.",
          reference,
        });
      }

      // --------------------------------------------------
      // Paylor accepted/queued the payout.
      // Keep withdrawal PENDING until callback confirms.
      // --------------------------------------------------

      await pool.query(
        `
        UPDATE withdrawals
        SET
          gateway_transaction_id = $1,
          status = 'PENDING'
        WHERE id = $2
        `,
        [
          gatewayTransactionId,
          withdrawalId,
        ]
      );

      const balanceResult =
        await pool.query(
          `
          SELECT balance
          FROM users
          WHERE id = $1
          `,
          [req.userId]
        );

      const finalBalance =
        Number(
          balanceResult.rows[0].balance
        );

      res.json({
        success: true,
        message:
          data.message ||
          "Withdrawal request submitted successfully",
        withdrawalId,
        reference,
        transactionId:
          gatewayTransactionId,
        amount,
        phone: normalizedPhone,
        status:
          gatewayStatus || "PENDING",
        balance: finalBalance,
      });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch {}

      console.error(
        "Withdrawal error:",
        error
      );

      // If money was already deducted and the
      // withdrawal was created, attempt a refund.
      if (withdrawalId) {
        try {
          await refundFailedWithdrawal(
            withdrawalId
          );
        } catch (refundError) {
          console.error(
            "Emergency withdrawal refund error:",
            refundError
          );
        }
      }

      res.status(500).json({
        success: false,
        message:
          "Withdrawal failed. Please try again.",
      });
    } finally {
      client.release();
    }
  }
);

// ======================================================
// REFUND FAILED WITHDRAWAL
// ======================================================

async function refundFailedWithdrawal(
  withdrawalId,
  gatewayTransactionId = null
) {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const withdrawalResult =
      await client.query(
        `
        SELECT *
        FROM withdrawals
        WHERE id = $1
        FOR UPDATE
        `,
        [withdrawalId]
      );

    if (
      withdrawalResult.rows.length === 0
    ) {
      await client.query("ROLLBACK");
      return;
    }

    const withdrawal =
      withdrawalResult.rows[0];

    // Never refund a completed withdrawal.
    if (
      withdrawal.status === "COMPLETED" ||
      withdrawal.refunded_at
    ) {
      await client.query("COMMIT");
      return;
    }

    const userResult =
      await client.query(
        `
        SELECT balance
        FROM users
        WHERE id = $1
        FOR UPDATE
        `,
        [withdrawal.user_id]
      );

    if (userResult.rows.length === 0) {
      throw new Error(
        "User not found while refunding withdrawal"
      );
    }

    const currentBalance =
      Number(userResult.rows[0].balance);

    const refundedBalance =
      currentBalance +
      Number(withdrawal.amount);

    await client.query(
      `
      UPDATE users
      SET balance = $1
      WHERE id = $2
      `,
      [
        refundedBalance,
        withdrawal.user_id,
      ]
    );

    await client.query(
      `
      UPDATE withdrawals
      SET
        status = 'FAILED',
        gateway_transaction_id =
          COALESCE($1, gateway_transaction_id),
        failed_at = CURRENT_TIMESTAMP,
        refunded_at = CURRENT_TIMESTAMP
      WHERE id = $2
      `,
      [
        gatewayTransactionId,
        withdrawalId,
      ]
    );

    await client.query("COMMIT");

    console.log(
      `Withdrawal refunded: ${withdrawal.reference} KES ${withdrawal.amount}`
    );
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

// ======================================================
// WITHDRAWAL HISTORY
// ======================================================

app.get(
  "/api/withdrawals",
  authenticateToken,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          id,
          amount,
          phone,
          reference,
          status,
          gateway_transaction_id,
          provider_ref,
          mpesa_receipt,
          created_at,
          completed_at,
          failed_at
        FROM withdrawals
        WHERE user_id = $1
        ORDER BY created_at DESC
        `,
        [req.userId]
      );

      res.json({
        success: true,
        withdrawals: result.rows.map(
          (row) => ({
            id: row.id,
            amount: Number(row.amount),
            phone: row.phone,
            reference: row.reference,
            status: row.status,
            transactionId:
              row.gateway_transaction_id,
            providerRef:
              row.provider_ref,
            mpesaReceipt:
              row.mpesa_receipt,
            createdAt: row.created_at,
            completedAt:
              row.completed_at,
            failedAt: row.failed_at,
          })
        ),
      });
    } catch (error) {
      console.error(
        "Withdrawals history error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Could not load withdrawals",
      });
    }
  }
);

// ======================================================
// INVEST
// ======================================================

app.post(
  "/api/invest",
  authenticateToken,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const amount = Number(
        req.body.amount
      );

      if (
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid investment amount",
        });
      }

      await client.query("BEGIN");

      const userResult =
        await client.query(
          `
          SELECT *
          FROM users
          WHERE id = $1
          FOR UPDATE
          `,
          [req.userId]
        );

      if (
        userResult.rows.length === 0
      ) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      const user =
        userResult.rows[0];

      const currentBalance =
        Number(user.balance);

      if (currentBalance < amount) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          success: false,
          message: "Insufficient balance",
          balance: currentBalance,
        });
      }

      const newBalance =
        currentBalance - amount;

      const investmentId =
        generateId();

      const reference =
        generateReference("INV");

      await client.query(
        `
        UPDATE users
        SET balance = $1
        WHERE id = $2
        `,
        [
          newBalance,
          req.userId,
        ]
      );

      await client.query(
        `
        INSERT INTO investments
        (
          id,
          user_id,
          amount,
          reference,
          status
        )
        VALUES ($1, $2, $3, $4, 'ACTIVE')
        `,
        [
          investmentId,
          req.userId,
          amount,
          reference,
        ]
      );

      await client.query("COMMIT");

      res.json({
        success: true,
        message:
          "Investment created successfully",
        investmentId,
        reference,
        amount,
        status: "ACTIVE",
        balance: newBalance,
      });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch {}

      console.error(
        "Investment error:",
        error
      );

      res.status(500).json({
        success: false,
        message: "Investment failed",
      });
    } finally {
      client.release();
    }
  }
);

// ======================================================
// INVESTMENT HISTORY
// ======================================================

app.get(
  "/api/investments",
  authenticateToken,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          id,
          amount,
          reference,
          status,
          created_at
        FROM investments
        WHERE user_id = $1
        ORDER BY created_at DESC
        `,
        [req.userId]
      );

      res.json({
        success: true,
        investments: result.rows.map(
          (row) => ({
            id: row.id,
            amount: Number(row.amount),
            reference: row.reference,
            status: row.status,
            createdAt: row.created_at,
          })
        ),
      });
    } catch (error) {
      console.error(
        "Investments history error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Could not load investments",
      });
    }
  }
);

// ======================================================
// TRANSACTIONS
// ======================================================

app.get(
  "/api/transactions",
  authenticateToken,
  async (req, res) => {
    try {
      const deposits =
        await pool.query(
          `
          SELECT
            id,
            'DEPOSIT' AS type,
            amount,
            reference,
            status,
            created_at
          FROM deposits
          WHERE user_id = $1
          `,
          [req.userId]
        );

      const withdrawals =
        await pool.query(
          `
          SELECT
            id,
            'WITHDRAWAL' AS type,
            amount,
            reference,
            status,
            created_at
          FROM withdrawals
          WHERE user_id = $1
          `,
          [req.userId]
        );

      const investments =
        await pool.query(
          `
          SELECT
            id,
            'INVESTMENT' AS type,
            amount,
            reference,
            status,
            created_at
          FROM investments
          WHERE user_id = $1
          `,
          [req.userId]
        );

      const transactions = [
        ...deposits.rows,
        ...withdrawals.rows,
        ...investments.rows,
      ]
        .map((row) => ({
          id: row.id,
          type: row.type,
          amount: Number(row.amount),
          reference: row.reference,
          status: row.status,
          createdAt: row.created_at,
        }))
        .sort(
          (a, b) =>
            new Date(b.createdAt) -
            new Date(a.createdAt)
        );

      res.json({
        success: true,
        transactions,
      });
    } catch (error) {
      console.error(
        "Transactions error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Could not load transactions",
      });
    }
  }
);

// ======================================================
// DEPOSIT HISTORY
// ======================================================

app.get(
  "/api/deposits",
  authenticateToken,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          id,
          amount,
          phone,
          reference,
          status,
          gateway_transaction_id,
          provider_ref,
          mpesa_receipt,
          created_at,
          completed_at,
          failed_at
        FROM deposits
        WHERE user_id = $1
        ORDER BY created_at DESC
        `,
        [req.userId]
      );

      res.json({
        success: true,
        deposits: result.rows.map(
          (row) => ({
            id: row.id,
            amount: Number(row.amount),
            phone: row.phone,
            reference: row.reference,
            status: row.status,
            transactionId:
              row.gateway_transaction_id,
            providerRef:
              row.provider_ref,
            mpesaReceipt:
              row.mpesa_receipt,
            createdAt: row.created_at,
            completedAt:
              row.completed_at,
            failedAt: row.failed_at,
          })
        ),
      });
    } catch (error) {
      console.error(
        "Deposits history error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Could not load deposits",
      });
    }
  }
);

// ======================================================
// HEALTH
// ======================================================

app.get("/health", async (req, res) => {
  let database = "unknown";

  try {
    await pool.query("SELECT 1");
    database = "connected";
  } catch {
    database = "disconnected";
  }

  res.json({
    success: true,
    status: "online",
    database,
    features: {
      registration: true,
      login: true,
      deposits: true,
      withdrawals: true,
      paylorB2C: true,
      investments: true,
      transactions: true,
    },
    paylorApiKeyConfigured:
      !!PAYLOR_API_KEY,
    paylorChannelConfigured:
      !!PAYLOR_CHANNEL_ID,
    webhookSecretConfigured:
      !!PAYLOR_WEBHOOK_SECRET,
    backendUrl: BACKEND_URL,
  });
});

// ======================================================
// START SERVER
// ======================================================

async function startServer() {
  try {
    await setupDatabase();

    console.log(
      `Paylor: API key ${
        PAYLOR_API_KEY
          ? "configured"
          : "NOT configured"
      }`
    );

    console.log(
      `Paylor channel: ${
        PAYLOR_CHANNEL_ID
          ? "configured"
          : "NOT configured"
      }`
    );

    console.log(
      `Paylor webhook: ${
        PAYLOR_WEBHOOK_SECRET
          ? "secret configured"
          : "secret NOT configured"
      }`
    );

    console.log(
      `Backend URL: ${BACKEND_URL}`
    );

    app.listen(PORT, () => {
      console.log(
        `Fortiva Capital backend running on port ${PORT}`
      );
    });
  } catch (error) {
    console.error(
      "Failed to start server:",
      error
    );

    process.exit(1);
  }
}

startServer();
