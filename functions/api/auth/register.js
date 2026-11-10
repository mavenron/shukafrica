const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

const COUNTRIES = {
  GH: { prefix: "+233", digits: 9 },
  BF: { prefix: "+226", digits: 8 },
  TG: { prefix: "+228", digits: 8 }
};

const ITERATIONS = 100000;
const REGISTRATION_LIMIT = 5;
const RATE_WINDOW_SECONDS = 15 * 60;
const TOKEN_SECONDS = 30 * 60;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

function makeToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));

  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derived = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt,
    iterations: ITERATIONS,
    hash: "SHA-256"
  }, key, 256);

  const hex = bytes =>
    Array.from(new Uint8Array(bytes))
      .map(byte => byte.toString(16).padStart(2, "0"))
      .join("");

  return `pbkdf2_sha256$${ITERATIONS}$${hex(salt)}$${hex(derived)}`;
}

async function checkRegistrationLimit(db, bucketKey, now) {
  const result = await db.prepare(`
    INSERT INTO email_verification_rate_limits
      (bucket_key, window_start, request_count)
    VALUES (?, ?, 1)
    ON CONFLICT(bucket_key) DO UPDATE SET
      window_start = CASE
        WHEN ? - window_start >= ?
        THEN ?
        ELSE window_start
      END,
      request_count = CASE
        WHEN ? - window_start >= ?
        THEN 1
        ELSE request_count + 1
      END
    RETURNING request_count
  `).bind(
    bucketKey,
    now,
    now,
    RATE_WINDOW_SECONDS,
    now,
    now,
    RATE_WINDOW_SECONDS
  ).first();

  return result && result.request_count <= REGISTRATION_LIMIT;
}

export async function onRequestPost({ request, env }) {
  if (!env.DB || !env.RESEND_API_KEY) {
    return json({
      success: false,
      error: "Registration service temporarily unavailable."
    }, 503);
  }

  const origin = request.headers.get("Origin") || "";

  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return json({
      success: false,
      error: "Origin not allowed."
    }, 403);
  }

  if (!(request.headers.get("Content-Type") || "")
    .toLowerCase().includes("application/json")) {
    return json({
      success: false,
      error: "JSON required."
    }, 415);
  }

  let body;

  try {
    const raw = await request.text();

    if (raw.length > 10000) {
      return json({
        success: false,
        error: "Request too large."
      }, 413);
    }

    body = JSON.parse(raw);
  } catch {
    return json({
      success: false,
      error: "Invalid registration data."
    }, 400);
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return json({
      success: false,
      error: "Invalid registration data."
    }, 400);
  }

  const name = typeof body.name === "string"
    ? body.name.trim()
    : "";

  const email = typeof body.email === "string"
    ? body.email.trim().toLowerCase()
    : "";

  const password = body.password;

  const country = typeof body.country === "string"
    ? body.country.trim().toUpperCase()
    : "";

  const phone = typeof body.phone === "string"
    ? body.phone.trim()
    : "";

  if (name.length < 2 || name.length > 100) {
    return json({ success: false, error: "Enter a valid name." }, 400);
  }

  if (
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    return json({ success: false, error: "Enter a valid email address." }, 400);
  }

  if (
    typeof password !== "string" ||
    password.length < 12 ||
    password.length > 128
  ) {
    return json({
      success: false,
      error: "Password must be 12–128 characters."
    }, 400);
  }

  const countryInfo = COUNTRIES[country];

  if (!countryInfo) {
    return json({
      success: false,
      error: "Registration is currently available in Ghana, Burkina Faso and Togo."
    }, 400);
  }

  const phonePattern = new RegExp(
    "^" + countryInfo.prefix.replace("+", "\\+") +
    "[0-9]{" + countryInfo.digits + "}$"
  );

  if (!phonePattern.test(phone)) {
    return json({
      success: false,
      error: "Enter a valid international phone number."
    }, 400);
  }

  let pendingId = null;

  try {
    const ip = request.headers.get("CF-Connecting-IP");

    if (!ip) {
      return json({
        success: false,
        error: "Unable to process this request."
      }, 400);
    }

    const now = Math.floor(Date.now() / 1000);

    const ipHash = await sha256(ip);

    const allowed = await checkRegistrationLimit(
      env.DB,
      "register:ip:" + ipHash,
      now
    );

    if (!allowed) {
      return json({
        success: false,
        error: "Too many registration attempts. Please try again in 15 minutes."
      }, 429);
    }

    // Clean expired pending registrations.
    await env.DB.prepare(`
      DELETE FROM pending_seller_registrations
      WHERE verification_expires_at <= ?
    `).bind(new Date().toISOString()).run();

    // Protect existing permanent seller accounts.
    const existingEmail = await env.DB.prepare(`
      SELECT id FROM sellers
      WHERE email = ? COLLATE NOCASE
      LIMIT 1
    `).bind(email).first();

    if (existingEmail) {
      return json({
        success: false,
        error: "An account with this email already exists."
      }, 409);
    }

    const existingPhone = await env.DB.prepare(`
      SELECT id FROM sellers
      WHERE phone = ?
      LIMIT 1
    `).bind(phone).first();

    if (existingPhone) {
      return json({
        success: false,
        error: "This phone number is already registered."
      }, 409);
    }

    const pendingEmail = await env.DB.prepare(`
      SELECT id FROM pending_seller_registrations
      WHERE email = ? COLLATE NOCASE
      LIMIT 1
    `).bind(email).first();

    const pendingPhone = await env.DB.prepare(`
      SELECT id FROM pending_seller_registrations
      WHERE phone = ?
      LIMIT 1
    `).bind(phone).first();

    if (pendingEmail || pendingPhone) {
      return json({
        success: false,
        error: "A registration with this email or phone is already pending. Please use the resend verification option."
      }, 409);
    }

    const passwordHash = await hashPassword(password);
    const token = makeToken();
    const tokenHash = await sha256(token);
    const expiresAt = new Date(
      Date.now() + TOKEN_SECONDS * 1000
    ).toISOString();

    pendingId = crypto.randomUUID();

    await env.DB.prepare(`
      INSERT INTO pending_seller_registrations (
        id,
        name,
        email,
        password_hash,
        country,
        phone,
        verification_token_hash,
        verification_expires_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      pendingId,
      name,
      email,
      passwordHash,
      country,
      phone,
      tokenHash,
      expiresAt
    ).run();

    const verificationUrl =
      "https://shukafrica.com/verify-email.html?token=" + token;

    const emailResponse = await fetch(
      "https://api.resend.com/emails",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${env.RESEND_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          from: "ShukAfrica <verify@mail.shukafrica.com>",
          to: [email],
          subject: "Verify your ShukAfrica seller email",
          html: `
            <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto">
              <h2>Welcome to ShukAfrica</h2>
              <p>Hello ${name.replace(/[&<>"']/g, "")},</p>
              <p>Please verify your email address to activate your seller account.</p>
              <p>
                <a href="${verificationUrl}"
                  style="display:inline-block;padding:14px 22px;background:#176b45;color:white;text-decoration:none;border-radius:7px">
                  Verify my email
                </a>
              </p>
              <p>This link expires in 30 minutes.</p>
              <p>If you did not request this account, you can ignore this email.</p>
            </div>
          `
        })
      }
    );

    if (!emailResponse.ok) {
      const providerError = await emailResponse.text();

      console.error("Resend email error:", {
        status: emailResponse.status,
        response: providerError
      });

      await env.DB.prepare(`
        DELETE FROM pending_seller_registrations
        WHERE id = ?
      `).bind(pendingId).run();

      return json({
        success: false,
        error: "We could not send your verification email. Please try again."
      }, 502);
    }

    return json({
      success: true,
      message: "A verification link has been sent. Please check your inbox and spam folder. The link expires in 30 minutes."
    }, 201);

  } catch (error) {
    console.error("Seller registration failed:", error);

    if (pendingId) {
      try {
        await env.DB.prepare(`
          DELETE FROM pending_seller_registrations
          WHERE id = ?
        `).bind(pendingId).run();
      } catch (cleanupError) {
        console.error("Pending registration cleanup failed:", cleanupError);
      }
    }

    if (
      error?.message?.toLowerCase().includes("unique") ||
      error?.message?.toLowerCase().includes("constraint")
    ) {
      return json({
        success: false,
        error: "This email or phone number is already registered or pending."
      }, 409);
    }

    return json({
      success: false,
      error: "Could not complete registration. Please try again."
    }, 500);
  }
}
  
