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

if (!DATABASE_URL) {
  console.error("DATABASE_URL is not configured");
  process.exit(1);
}

// ======================================================
// DATABASE
// ======================================================

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// ======================================================
// MIDDLEWARE
// ======================================================

app.use(cors());

// Paylor callback needs the original raw body
// for webhook signature verification.
app.use(
  "/api/paylor-callback",
  express.raw({
    type: "*/*"
  })
);

// Normal JSON for other routes.
app.use(express.json());

// ======================================================
// DATABASE SETUP
// ======================================================

async function setupDatabase() {
  try {
    await pool.query(`
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

    await pool.query(`
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

    // ==================================================
    // WITHDRAWALS
    // ==================================================

    await pool.query(`
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

    // ==================================================
    // INVESTMENTS
    // ==================================================

    await pool.query(`
      CREATE TABLE IF NOT EXISTS investments (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id),
        amount NUMERIC(12,2) NOT NULL,
        reference TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log("PostgreSQL database connected");
    console.log("Database tables ready");

  } catch (error) {

    console.error(
      "Database setup error:",
      error
    );

    process.exit(1);
  }
}

// ======================================================
// HOME
// ======================================================

app.get("/", (req, res) => {

  res.json({
    message:
      "Fortiva Capital backend is running",
    database:
      "connected",
    paymentGateway:
      "Paylor"
  });

});

// ======================================================
// REGISTER
// ======================================================

app.post("/api/register", async (req, res) => {

  try {

    const {
      fullName,
      email,
      phone,
      password
    } = req.body;

    if (
      !fullName ||
      !email ||
      !phone ||
      !password
    ) {

      return res.status(400).json({
        message:
          "All fields are required"
      });
    }

    const cleanEmail =
      String(email)
        .trim()
        .toLowerCase();

    const cleanPhone =
      String(phone)
        .trim()
        .replace(/\s+/g, "");

    const existingUser =
      await pool.query(
        `
        SELECT id
        FROM users
        WHERE email = $1
           OR phone = $2
        LIMIT 1
        `,
        [
          cleanEmail,
          cleanPhone
        ]
      );

    if (
      existingUser.rows.length > 0
    ) {

      return res.status(409).json({
        message:
          "Email or phone number already registered"
      });
    }

    const hashedPassword =
      await bcrypt.hash(
        password,
        10
      );

    const userId =
      crypto.randomUUID();

    await pool.query(
      `
      INSERT INTO users
      (
        id,
        full_name,
        email,
        phone,
        password,
        balance
      )
      VALUES
      ($1, $2, $3, $4, $5, $6)
      `,
      [
        userId,
        String(fullName).trim(),
        cleanEmail,
        cleanPhone,
        hashedPassword,
        0
      ]
    );

    return res.status(201).json({
      message:
        "Account created successfully"
    });

  } catch (error) {

    console.error(
      "Registration error:",
      error
    );

    return res.status(500).json({
      message:
        "Server error"
    });
  }
});

// ======================================================
// LOGIN
// ======================================================

app.post("/api/login", async (req, res) => {

  try {

    const {
      identifier,
      password
    } = req.body;

    if (
      !identifier ||
      !password
    ) {

      return res.status(400).json({
        message:
          "Phone number/email and password are required"
      });
    }

    const loginValue =
      String(identifier).trim();

    const result =
      await pool.query(
        `
        SELECT *
        FROM users
        WHERE LOWER(email) = LOWER($1)
           OR phone = $1
        LIMIT 1
        `,
        [loginValue]
      );

    if (
      result.rows.length === 0
    ) {

      return res.status(401).json({
        message:
          "Invalid phone number/email or password"
      });
    }

    const user =
      result.rows[0];

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

    const token =
      jwt.sign(
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

    return res.json({

      message:
        "Login successful",

      token,

      user: {
        id: user.id,
        fullName:
          user.full_name,
        email:
          user.email,
        phone:
          user.phone,
        balance:
          Number(user.balance || 0)
      }

    });

  } catch (error) {

    console.error(
      "Login error:",
      error
    );

    return res.status(500).json({
      message:
        "Server error"
    });
  }
});

// ======================================================
// AUTHENTICATION
// ======================================================

function authenticateToken(
  req,
  res,
  next
) {

  const authHeader =
    req.headers.authorization;

  if (!authHeader) {

    return res.status(401).json({
      message:
        "Authentication required"
    });
  }

  const parts =
    authHeader.split(" ");

  if (
    parts.length !== 2 ||
    parts[0] !== "Bearer"
  ) {

    return res.status(401).json({
      message:
        "Invalid authorization header"
    });
  }

  const token =
    parts[1];

  try {

    const decoded =
      jwt.verify(
        token,
        JWT_SECRET
      );

    req.user =
      decoded;

    next();

  } catch (error) {

    return res.status(401).json({
      message:
        "Invalid or expired token"
    });
  }
}

// ======================================================
// GET CURRENT USER
// ======================================================

app.get(
  "/api/me",
  authenticateToken,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            id,
            full_name,
            email,
            phone,
            balance
          FROM users
          WHERE id = $1
          LIMIT 1
          `,
          [req.user.id]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          message:
            "User not found"
        });
      }

      const user =
        result.rows[0];

      return res.json({

        user: {
          id: user.id,
          fullName:
            user.full_name,
          email:
            user.email,
          phone:
            user.phone,
          balance:
            Number(user.balance || 0)
        }

      });

    } catch (error) {

      console.error(
        "Get user error:",
        error
      );

      return res.status(500).json({
        message:
          "Server error"
      });
    }
  }
);

// ======================================================
// COMPLETE A DEPOSIT
// ======================================================

async function completeDeposit(
  deposit,
  payment
) {

  const client =
    await pool.connect();

  try {

    await client.query(
      "BEGIN"
    );

    const lockedDeposit =
      await client.query(
        `
        SELECT *
        FROM deposits
        WHERE id = $1
        FOR UPDATE
        `,
        [deposit.id]
      );

    if (
      lockedDeposit.rows.length === 0
    ) {

      await client.query(
        "ROLLBACK"
      );

      return false;
    }

    const currentDeposit =
      lockedDeposit.rows[0];

    if (
      currentDeposit.status ===
      "COMPLETED"
    ) {

      await client.query(
        "COMMIT"
      );

      console.log(
        "Deposit already completed:",
        currentDeposit.reference
      );

      return true;
    }

    const providerRef =
      payment?.providerRef ||
      payment?.provider_ref ||
      payment?.data?.providerRef ||
      payment?.data?.provider_ref ||
      null;

    const mpesaReceipt =
      payment?.mpesaReceipt ||
      payment?.mpesa_receipt ||
      payment?.metadata?.mpesaReceipt ||
      payment?.metadata?.mpesa_receipt ||
      payment?.data?.mpesaReceipt ||
      payment?.data?.metadata?.mpesaReceipt ||
      null;

    await client.query(
      `
      UPDATE deposits
      SET
        status = $1,
        gateway_transaction_id =
          COALESCE($2, gateway_transaction_id),
        provider_ref = $3,
        mpesa_receipt = $4,
        completed_at =
          CURRENT_TIMESTAMP,
        failed_at = NULL
      WHERE id = $5
      `,
      [
        "COMPLETED",
        payment?.transactionId ||
          payment?.id ||
          null,
        providerRef,
        mpesaReceipt,
        currentDeposit.id
      ]
    );

    await client.query(
      `
      UPDATE users
      SET balance =
        balance + $1
      WHERE id = $2
      `,
      [
        Number(
          currentDeposit.amount
        ),
        currentDeposit.user_id
      ]
    );

    await client.query(
      "COMMIT"
    );

    console.log(
      "DEPOSIT COMPLETED:",
      currentDeposit.reference,
      currentDeposit.amount
    );

    return true;

  } catch (error) {

    await client.query(
      "ROLLBACK"
    );

    throw error;

  } finally {

    client.release();
  }
}

// ======================================================
// DEPOSIT
// ======================================================

app.post(
  "/api/deposit",
  authenticateToken,
  async (req, res) => {

    try {

      let {
        amount,
        phone
      } = req.body;

      console.log(
        "DEPOSIT REQUEST:",
        {
          amount,
          phone,
          userId:
            req.user.id
        }
      );

      if (!PAYLOR_API_KEY) {

        return res.status(500).json({
          message:
            "Paylor API key is not configured"
        });
      }

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

      phone =
        String(phone || "")
          .trim()
          .replace(/\s+/g, "");

      if (
        phone.startsWith("+254")
      ) {

        phone =
          phone.substring(1);

      } else if (
        phone.startsWith("07") ||
        phone.startsWith("01")
      ) {

        phone =
          "254" +
          phone.substring(1);
      }

      if (
        !/^254[17]\d{8}$/.test(phone)
      ) {

        return res.status(400).json({
          message:
            "Enter a valid Kenyan M-Pesa phone number"
        });
      }

      const reference =
        "FORTIVA-" +
        Date.now() +
        "-" +
        Math.floor(
          Math.random() * 10000
        );

      const depositId =
        crypto.randomUUID();

      await pool.query(
        `
        INSERT INTO deposits
        (
          id,
          user_id,
          amount,
          phone,
          reference,
          status
        )
        VALUES
        ($1, $2, $3, $4, $5, $6)
        `,
        [
          depositId,
          req.user.id,
          depositAmount,
          phone,
          reference,
          "PENDING"
        ]
      );

      const callbackUrl =
        `${BACKEND_URL}/api/paylor-callback`;

      const paylorBody = {

        phone: phone,

        amount:
          depositAmount,

        reference:
          reference,

        description:
          "Fortiva Capital Deposit",

        callbackUrl:
          callbackUrl

      };

      if (PAYLOR_CHANNEL_ID) {

        paylorBody.channelId =
          PAYLOR_CHANNEL_ID;
      }

      const response =
        await fetch(
          `${PAYLOR_BASE_URL}/merchants/payments/stk-push`,
          {
            method: "POST",

            headers: {
              Authorization:
                `Bearer ${PAYLOR_API_KEY}`,

              "Content-Type":
                "application/json",

              Accept:
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

      const responseData =
        await response
          .json()
          .catch(() => ({}));

      if (!response.ok) {

        await pool.query(
          `
          UPDATE deposits
          SET
            status = $1,
            failed_at =
              CURRENT_TIMESTAMP
          WHERE id = $2
          `,
          [
            "FAILED",
            depositId
          ]
        );

        return res.status(
          response.status
        ).json({

          success: false,

          message:
            responseData?.error?.message ||
            responseData?.message ||
            "Paylor could not initiate the STK Push",

          reference:
            reference

        });
      }

      const transactionId =
        responseData?.transactionId ||
        responseData?.id ||
        null;

      const status =
        responseData?.status ||
        "SENT";

      if (!transactionId) {

        await pool.query(
          `
          UPDATE deposits
          SET
            status = $1,
            failed_at =
              CURRENT_TIMESTAMP
          WHERE id = $2
          `,
          [
            "FAILED",
            depositId
          ]
        );

        return res.status(502).json({
          success: false,
          message:
            "Paylor did not return a transaction ID",
          data:
            responseData
        });
      }

      await pool.query(
        `
        UPDATE deposits
        SET
          gateway_transaction_id = $1,
          status = $2
        WHERE id = $3
        `,
        [
          transactionId,
          status,
          depositId
        ]
      );

      return res.json({

        success: true,

        paid: false,

        transactionId:
          transactionId,

        checkout_request_id:
          transactionId,

        reference:
          reference,

        status:
          status,

        data:
          responseData

      });

    } catch (error) {

      console.error(
        "Deposit error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to send STK Push"
      });
    }
  }
);

// ======================================================
// PAYLOR WEBHOOK
// ======================================================

app.post(
  "/api/paylor-callback",
  async (req, res) => {

    try {

      const signature =
        req.headers[
          "x-webhook-signature"
        ];

      if (!PAYLOR_WEBHOOK_SECRET) {

        return res.status(500).json({
          success: false,
          message:
            "Webhook secret is not configured"
        });
      }

      if (!signature) {

        return res.status(401).json({
          success: false,
          message:
            "Missing webhook signature"
        });
      }

      const rawBody =
        Buffer.isBuffer(req.body)
          ? req.body
          : Buffer.from(
              JSON.stringify(
                req.body || {}
              )
            );

      const expectedSignature =
        crypto
          .createHmac(
            "sha256",
            PAYLOR_WEBHOOK_SECRET
          )
          .update(rawBody)
          .digest("hex");

      let receivedSignature =
        String(signature)
          .trim()
          .toLowerCase();

      if (
        receivedSignature.startsWith(
          "sha256="
        )
      ) {

        receivedSignature =
          receivedSignature.substring(
            7
          );
      }

      const receivedBuffer =
        Buffer.from(
          receivedSignature,
          "utf8"
        );

      const expectedBuffer =
        Buffer.from(
          expectedSignature,
          "utf8"
        );

      if (
        receivedBuffer.length !==
        expectedBuffer.length
      ) {

        return res.status(401).json({
          success: false,
          message:
            "Invalid signature"
        });
      }

      if (
        !crypto.timingSafeEqual(
          receivedBuffer,
          expectedBuffer
        )
      ) {

        return res.status(401).json({
          success: false,
          message:
            "Invalid signature"
        });
      }

      let payment;

      try {

        payment =
          JSON.parse(
            rawBody.toString("utf8")
          );

      } catch (error) {

        return res.status(400).json({
          success: false,
          message:
            "Invalid webhook JSON"
        });
      }

      const transaction =
        payment?.transaction ||
        payment?.data?.transaction ||
        payment;

      const reference =
        transaction?.reference ||
        payment?.reference ||
        null;

      const transactionId =
        transaction?.transactionId ||
        transaction?.id ||
        payment?.transactionId ||
        payment?.id ||
        null;

      const paymentStatus =
        String(
          transaction?.status ||
          payment?.status ||
          ""
        ).toUpperCase();

      if (!reference) {

        return res.status(200).json({
          success: true,
          received: true
        });
      }

      const depositResult =
        await pool.query(
          `
          SELECT *
          FROM deposits
          WHERE reference = $1
          LIMIT 1
          `,
          [reference]
        );

      if (
        depositResult.rows.length === 0
      ) {

        return res.status(200).json({
          success: true,
          received: true
        });
      }

      const deposit =
        depositResult.rows[0];

      if (
        paymentStatus ===
          "COMPLETED" ||
        payment?.event ===
          "payment.success"
      ) {

        await completeDeposit(
          deposit,
          {
            ...payment,
            ...transaction,
            transactionId:
              transactionId
          }
        );
      }

      if (
        paymentStatus ===
          "FAILED" ||
        paymentStatus ===
          "CANCELLED" ||
        payment?.event ===
          "payment.failed"
      ) {

        await pool.query(
          `
          UPDATE deposits
          SET
            status = $1,
            failed_at =
              CURRENT_TIMESTAMP
          WHERE id = $2
            AND status <> 'COMPLETED'
          `,
          [
            "FAILED",
            deposit.id
          ]
        );
      }

      return res.status(200).json({
        success: true,
        received: true
      });

    } catch (error) {

      console.error(
        "Paylor webhook error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Callback processing error"
      });
    }
  }
);

// ======================================================
// PAYMENT STATUS / RECONCILIATION
// ======================================================

app.post(
  "/api/payment-status",
  authenticateToken,
  async (req, res) => {

    try {

      const transactionId =
        req.body?.transactionId ||
        req.body?.checkout_request_id ||
        req.body?.transaction_id ||
        req.query?.transactionId ||
        req.query?.checkout_request_id;

      if (!transactionId) {

        return res.status(400).json({
          success: false,
          message:
            "transactionId is required"
        });
      }

      if (!PAYLOR_API_KEY) {

        return res.status(500).json({
          success: false,
          message:
            "Paylor API key is not configured"
        });
      }

      const response =
        await fetch(
          `${PAYLOR_BASE_URL}/merchants/payments/transactions/${encodeURIComponent(transactionId)}`,
          {
            method: "GET",

            headers: {
              Authorization:
                `Bearer ${PAYLOR_API_KEY}`,

              Accept:
                "application/json"
            }
          }
        );

      const responseData =
        await response
          .json()
          .catch(() => ({}));

      if (!response.ok) {

        return res.status(
          response.status
        ).json({

          success: false,

          message:
            "Unable to check payment status",

          data:
            responseData

        });
      }

      const payment =
        responseData?.data ||
        responseData?.transaction ||
        responseData?.payment ||
        responseData;

      const paymentStatus =
        String(
          payment?.status ||
          responseData?.status ||
          ""
        ).toUpperCase();

      const depositResult =
        await pool.query(
          `
          SELECT *
          FROM deposits
          WHERE gateway_transaction_id = $1
          LIMIT 1
          `,
          [transactionId]
        );

      if (
        depositResult.rows.length > 0
      ) {

        const deposit =
          depositResult.rows[0];

        if (
          paymentStatus ===
          "COMPLETED"
        ) {

          await completeDeposit(
            deposit,
            {
              ...responseData,
              ...payment,
              transactionId:
                transactionId
            }
          );

        } else if (
          paymentStatus ===
            "FAILED" ||
          paymentStatus ===
            "CANCELLED"
        ) {

          await pool.query(
            `
            UPDATE deposits
            SET
              status = $1,
              failed_at =
                CURRENT_TIMESTAMP
            WHERE id = $2
              AND status <> 'COMPLETED'
            `,
            [
              "FAILED",
              deposit.id
            ]
          );

        }
      }

      return res.json({

        success: true,

        status:
          paymentStatus.toLowerCase(),

        data:
          responseData

      });

    } catch (error) {

      console.error(
        "Payment status error:",
        error
      );

      return res.status(500).json({

        success: false,

        message:
          "Unable to check payment status",

        data:
          null

      });
    }
  }
);

// ======================================================
// WITHDRAW FUNDS
// ======================================================
//
// This creates a withdrawal request and deducts the
// requested amount from the available balance.
//
// Actual M-Pesa payout requires a configured payout
// provider. The endpoint therefore returns PENDING.
// ======================================================

app.post(
  "/api/withdraw",
  authenticateToken,
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      let {
        amount,
        phone
      } = req.body;

      const withdrawalAmount =
        Number(amount);

      if (
        !Number.isFinite(
          withdrawalAmount
        ) ||
        withdrawalAmount <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Enter a valid withdrawal amount"
        });
      }

      phone =
        String(phone || "")
          .trim()
          .replace(/\s+/g, "");

      if (
        phone.startsWith("+254")
      ) {

        phone =
          phone.substring(1);

      } else if (
        phone.startsWith("07") ||
        phone.startsWith("01")
      ) {

        phone =
          "254" +
          phone.substring(1);
      }

      if (
        !/^254[17]\d{8}$/.test(phone)
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Enter a valid Kenyan M-Pesa phone number"
        });
      }

      await client.query(
        "BEGIN"
      );

      // Lock the user row so two simultaneous
      // withdrawals cannot spend the same balance.
      const userResult =
        await client.query(
          `
          SELECT
            id,
            balance
          FROM users
          WHERE id = $1
          FOR UPDATE
          `,
          [req.user.id]
        );

      if (
        userResult.rows.length === 0
      ) {

        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          success: false,
          message:
            "User not found"
        });
      }

      const currentBalance =
        Number(
          userResult.rows[0].balance || 0
        );

      if (
        withdrawalAmount >
        currentBalance
      ) {

        await client.query(
          "ROLLBACK"
        );

        return res.status(400).json({
          success: false,
          message:
            "Insufficient available balance",
          balance:
            currentBalance
        });
      }

      const reference =
        "WDR-" +
        Date.now() +
        "-" +
        Math.floor(
          Math.random() * 10000
        );

      const withdrawalId =
        crypto.randomUUID();

      // Deduct the balance atomically.
      await client.query(
        `
        UPDATE users
        SET balance =
          balance - $1
        WHERE id = $2
        `,
        [
          withdrawalAmount,
          req.user.id
        ]
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
        VALUES
        ($1, $2, $3, $4, $5, $6)
        `,
        [
          withdrawalId,
          req.user.id,
          withdrawalAmount,
          phone,
          reference,
          "PENDING"
        ]
      );

      await client.query(
        "COMMIT"
      );

      console.log(
        "WITHDRAWAL REQUEST CREATED:",
        {
          reference,
          amount:
            withdrawalAmount,
          phone,
          userId:
            req.user.id
        }
      );

      return res.json({

        success: true,

        message:
          "Withdrawal request submitted",

        withdrawalId:
          withdrawalId,

        reference:
          reference,

        amount:
          withdrawalAmount,

        phone:
          phone,

        status:
          "PENDING",

        balance:
          currentBalance -
          withdrawalAmount

      });

    } catch (error) {

      try {
        await client.query(
          "ROLLBACK"
        );
      } catch (_) {}

      console.error(
        "Withdrawal error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to process withdrawal"
      });

    } finally {

      client.release();
    }
  }
);

// ======================================================
// GET WITHDRAWAL HISTORY
// ======================================================

app.get(
  "/api/withdrawals",
  authenticateToken,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            id,
            amount,
            phone,
            reference,
            status,
            created_at,
            completed_at,
            failed_at
          FROM withdrawals
          WHERE user_id = $1
          ORDER BY created_at DESC
          `,
          [req.user.id]
        );

      return res.json({

        success: true,

        withdrawals:
          result.rows.map(
            (item) => ({

              id:
                item.id,

              amount:
                Number(
                  item.amount
                ),

              phone:
                item.phone,

              reference:
                item.reference,

              status:
                item.status,

              createdAt:
                item.created_at,

              completedAt:
                item.completed_at,

              failedAt:
                item.failed_at

            })
          )

      });

    } catch (error) {

      console.error(
        "Withdrawal history error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load withdrawal history"
      });
    }
  }
);

// ======================================================
// INVEST FUNDS
// ======================================================
//
// Investment moves money from the available balance
// into an ACTIVE investment record.
// ======================================================

app.post(
  "/api/invest",
  authenticateToken,
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      const investmentAmount =
        Number(
          req.body?.amount
        );

      if (
        !Number.isFinite(
          investmentAmount
        ) ||
        investmentAmount <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Enter a valid investment amount"
        });
      }

      await client.query(
        "BEGIN"
      );

      const userResult =
        await client.query(
          `
          SELECT
            id,
            balance
          FROM users
          WHERE id = $1
          FOR UPDATE
          `,
          [req.user.id]
        );

      if (
        userResult.rows.length === 0
      ) {

        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          success: false,
          message:
            "User not found"
        });
      }

      const currentBalance =
        Number(
          userResult.rows[0].balance || 0
        );

      if (
        investmentAmount >
        currentBalance
      ) {

        await client.query(
          "ROLLBACK"
        );

        return res.status(400).json({
          success: false,
          message:
            "Insufficient available balance",
          balance:
            currentBalance
        });
      }

      const reference =
        "INV-" +
        Date.now() +
        "-" +
        Math.floor(
          Math.random() * 10000
        );

      const investmentId =
        crypto.randomUUID();

      await client.query(
        `
        UPDATE users
        SET balance =
          balance - $1
        WHERE id = $2
        `,
        [
          investmentAmount,
          req.user.id
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
        VALUES
        ($1, $2, $3, $4, $5)
        `,
        [
          investmentId,
          req.user.id,
          investmentAmount,
          reference,
          "ACTIVE"
        ]
      );

      await client.query(
        "COMMIT"
      );

      const newBalance =
        currentBalance -
        investmentAmount;

      console.log(
        "INVESTMENT CREATED:",
        {
          reference,
          amount:
            investmentAmount,
          userId:
            req.user.id
        }
      );

      return res.json({

        success: true,

        message:
          "Investment created successfully",

        investmentId:
          investmentId,

        reference:
          reference,

        amount:
          investmentAmount,

        status:
          "ACTIVE",

        balance:
          newBalance

      });

    } catch (error) {

      try {
        await client.query(
          "ROLLBACK"
        );
      } catch (_) {}

      console.error(
        "Investment error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to create investment"
      });

    } finally {

      client.release();
    }
  }
);

// ======================================================
// GET INVESTMENT HISTORY
// ======================================================

app.get(
  "/api/investments",
  authenticateToken,
  async (req, res) => {

    try {

      const result =
        await pool.query(
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
          [req.user.id]
        );

      return res.json({

        success: true,

        investments:
          result.rows.map(
            (item) => ({

              id:
                item.id,

              amount:
                Number(
                  item.amount
                ),

              reference:
                item.reference,

              status:
                item.status,

              createdAt:
                item.created_at

            })
          )

      });

    } catch (error) {

      console.error(
        "Investment history error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load investment history"
      });
    }
  }
);

// ======================================================
// GET ALL TRANSACTIONS
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
            amount,
            reference,
            status,
            created_at
          FROM deposits
          WHERE user_id = $1
          `,
          [req.user.id]
        );

      const withdrawals =
        await pool.query(
          `
          SELECT
            amount,
            reference,
            status,
            created_at
          FROM withdrawals
          WHERE user_id = $1
          `,
          [req.user.id]
        );

      const investments =
        await pool.query(
          `
          SELECT
            amount,
            reference,
            status,
            created_at
          FROM investments
          WHERE user_id = $1
          `,
          [req.user.id]
        );

      const transactions = [

        ...deposits.rows.map(
          (item) => ({
            type:
              "DEPOSIT",

            amount:
              Number(
                item.amount
              ),

            reference:
              item.reference,

            status:
              item.status,

            createdAt:
              item.created_at
          })
        ),

        ...withdrawals.rows.map(
          (item) => ({
            type:
              "WITHDRAWAL",

            amount:
              Number(
                item.amount
              ),

            reference:
              item.reference,

            status:
              item.status,

            createdAt:
              item.created_at
          })
        ),

        ...investments.rows.map(
          (item) => ({
            type:
              "INVESTMENT",

            amount:
              Number(
                item.amount
              ),

            reference:
              item.reference,

            status:
              item.status,

            createdAt:
              item.created_at
          })
        )

      ];

      transactions.sort(
        (a, b) =>
          new Date(b.createdAt) -
          new Date(a.createdAt)
      );

      return res.json({

        success: true,

        transactions:
          transactions

      });

    } catch (error) {

      console.error(
        "Transactions error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load transactions"
      });
    }
  }
);

// ======================================================
// GET DEPOSIT HISTORY
// ======================================================

app.get(
  "/api/deposits",
  authenticateToken,
  async (req, res) => {

    try {

      const result =
        await pool.query(
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
          [req.user.id]
        );

      return res.json({
        success: true,
        deposits:
          result.rows.map(
            (deposit) => ({
              id:
                deposit.id,

              amount:
                Number(
                  deposit.amount
                ),

              phone:
                deposit.phone,

              reference:
                deposit.reference,

              status:
                deposit.status,

              transactionId:
                deposit.gateway_transaction_id,

              providerRef:
                deposit.provider_ref,

              mpesaReceipt:
                deposit.mpesa_receipt,

              createdAt:
                deposit.created_at,

              completedAt:
                deposit.completed_at,

              failedAt:
                deposit.failed_at
            })
          )
      });

    } catch (error) {

      console.error(
        "Deposit history error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load deposit history"
      });
    }
  }
);

// ======================================================
// HEALTH CHECK
// ======================================================

app.get(
  "/health",
  (req, res) => {

    res.json({

      success: true,

      service:
        "Fortiva Capital Backend",

      paymentGateway:
        "Paylor",

      database:
        "PostgreSQL",

      features: {
        login:
          true,

        registration:
          true,

        deposits:
          true,

        withdrawals:
          true,

        investments:
          true,

        transactions:
          true
      },

      status:
        "online"

    });
  }
);

// ======================================================
// START SERVER
// ======================================================

async function startServer() {

  await setupDatabase();

  app.listen(
    PORT,
    () => {

      console.log("");

      console.log(
        `Fortiva Capital backend running on port ${PORT}`
      );

      console.log(
        "Paylor:",
        PAYLOR_API_KEY
          ? "API key configured"
          : "API key missing"
      );

      console.log(
        "Paylor channel:",
        PAYLOR_CHANNEL_ID
          ? "configured"
          : "not configured"
      );

      console.log(
        "Paylor webhook:",
        PAYLOR_WEBHOOK_SECRET
          ? "secret configured"
          : "secret missing"
      );

      console.log(
        "Backend URL:",
        BACKEND_URL
      );

    }
  );
}

startServer();
