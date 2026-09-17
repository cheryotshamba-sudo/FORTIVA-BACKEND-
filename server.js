const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

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


// --------------------------------------------------
// POSTGRESQL DATABASE
// --------------------------------------------------

if (!DATABASE_URL) {
  console.error("DATABASE_URL is not configured");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});


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
// DATABASE SETUP
// --------------------------------------------------

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


// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get("/", (req, res) => {

  res.json({
    message: "Fortiva Capital backend is running",
    database: "connected"
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


    const cleanEmail =
      email.trim().toLowerCase();

    const cleanPhone =
      phone.trim();


    const existingUser =
      await pool.query(
        `
        SELECT id
        FROM users
        WHERE email = $1 OR phone = $2
        LIMIT 1
        `,
        [
          cleanEmail,
          cleanPhone
        ]
      );


    if (existingUser.rows.length > 0) {

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
      VALUES ($1, $2, $3, $4, $5, $6)
      `,
      [
        userId,
        fullName.trim(),
        cleanEmail,
        cleanPhone,
        hashedPassword,
        0
      ]
    );


    res.status(201).json({

      message:
        "Account created successfully"

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


    const result =
      await pool.query(
        `
        SELECT *
        FROM users
        WHERE LOWER(email) = LOWER($1)
           OR phone = $1
        LIMIT 1
        `,
        [
          loginValue
        ]
      );


    if (result.rows.length === 0) {

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


    res.json({

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


// --------------------------------------------------
// GET CURRENT USER
// --------------------------------------------------

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
          [
            req.user.id
          ]
        );


      if (result.rows.length === 0) {

        return res.status(404).json({
          message:
            "User not found"
        });

      }


      const user =
        result.rows[0];


      res.json({

        user: {

          id:
            user.id,

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


      res.status(500).json({
        message:
          "Server error"
      });

    }

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


      if (!PAYLOR_API_KEY) {

        console.error(
          "PAYLOR_API_KEY is missing"
        );

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


      const reference =
        "FORTIVA-" +
        Date.now() +
        "-" +
        crypto
          .randomBytes(4)
          .toString("hex")
          .toUpperCase();


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
        VALUES ($1, $2, $3, $4, $5, $6)
        `,
        [
          depositId,
          req.user.id,
          depositAmount,
          normalizedPhone,
          reference,
          "PENDING"
        ]
      );


      const paylorBody = {

        phone:
          normalizedPhone,

        amount:
          depositAmount,

        reference,

        description:
          `Fortiva Capital deposit ${reference}`,

        callbackUrl:
          `${BACKEND_URL}/api/paylor-callback`

      };


      if (PAYLOR_CHANNEL_ID) {

        paylorBody.channelId =
          PAYLOR_CHANNEL_ID;

      }


      console.log(
        "Sending Paylor STK Push:",
        {
          phone:
            normalizedPhone,

          amount:
            depositAmount,

          reference
        }
      );


      const paylorResponse =
        await fetch(
          `${PAYLOR_BASE_URL}/merchants/payments/stk-push`,
          {

            method:
              "POST",

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


      if (!paylorResponse.ok) {

        await pool.query(
          `
          UPDATE deposits
          SET status = $1,
              failed_at = CURRENT_TIMESTAMP
          WHERE id = $2
          `,
          [
            "FAILED",
            depositId
          ]
        );


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


      const gatewayTransactionId =
        paylorData.transactionId ||
        paylorData.id ||
        null;


      const gatewayStatus =
        paylorData.status ||
        "SENT";


      await pool.query(
        `
        UPDATE deposits
        SET gateway_transaction_id = $1,
            status = $2
        WHERE id = $3
        `,
        [
          gatewayTransactionId,
          gatewayStatus,
          depositId
        ]
      );


      return res.json({

        message:
          "STK Push sent successfully. Check your M-Pesa phone and enter your PIN.",

        status:
          gatewayStatus,

        transactionId:
          gatewayTransactionId,

        reference

      });


    } catch (error) {

      console.error(
        "Deposit error:",
        error
      );


      res.status(500).json({
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


      const depositResult =
        await pool.query(
          `
          SELECT *
          FROM deposits
          WHERE reference = $1
          LIMIT 1
          `,
          [
            reference
          ]
        );


      if (
        depositResult.rows.length === 0
      ) {

        console.warn(
          "Deposit not found:",
          reference
        );

        return res.json({
          received: true
        });

      }


      const deposit =
        depositResult.rows[0];


      // ----------------------------------------
      // PAYMENT SUCCESS
      // ----------------------------------------

      if (
        event === "payment.success" ||
        transaction.status === "COMPLETED"
      ) {

        // Prevent adding the same deposit twice
        if (
          deposit.status !== "COMPLETED"
        ) {

          const client =
            await pool.connect();

          try {

            await client.query(
              "BEGIN"
            );


            await client.query(
              `
              UPDATE deposits
              SET status = $1,
                  provider_ref = $2,
                  mpesa_receipt = $3,
                  completed_at = CURRENT_TIMESTAMP
              WHERE id = $4
              `,
              [
                "COMPLETED",

                transaction.providerRef ||
                  null,

                transaction.mpesaReceipt ||
                  null,

                deposit.id
              ]
            );


            await client.query(
              `
              UPDATE users
              SET balance = balance + $1
              WHERE id = $2
              `,
              [
                Number(deposit.amount),
                deposit.user_id
              ]
            );


            await client.query(
              "COMMIT"
            );


            console.log(
              `Deposit completed: ${deposit.reference} KES ${deposit.amount}`
            );


          } catch (error) {

            await client.query(
              "ROLLBACK"
            );

            throw error;

          } finally {

            client.release();

          }

        }

      }


      // ----------------------------------------
      // PAYMENT FAILED
      // ----------------------------------------

      if (
        event === "payment.failed" ||
        transaction.status === "FAILED"
      ) {

        await pool.query(
          `
          UPDATE deposits
          SET status = $1,
              failed_at = CURRENT_TIMESTAMP
          WHERE id = $2
          `,
          [
            "FAILED",
            deposit.id
          ]
        );

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

async function startServer() {

  await setupDatabase();

  app.listen(
    PORT,
    () => {

      console.log(
        `Fortiva Capital backend running on port ${PORT}`
      );

    }
  );

}

startServer();
