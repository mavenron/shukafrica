const SESSION_SECONDS = 7 * 24 * 60 * 60;
const ITERATIONS = 100000;

const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

const COUNTRY_PREFIXES = {
  GH: { prefix: "+233", digits: 9 },
  BF: { prefix: "+226", digits: 8 },
  TG: { prefix: "+228", digits: 8 }
};

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extra
    }
  });
}

function makeToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));

  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(new Uint8Array(digest))
    .map(x => x.toString(16).padStart(2, "0"))
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
      .map(x => x.toString(16).padStart(2, "0"))
      .join("");

  return `pbkdf2_sha256$${ITERATIONS}$${hex(salt)}$${hex(derived)}`;
}

export async function onRequestPost({ request, env }) {
  if (!env.DB) {
    return json({
      success: false,
      error: "Database unavailable."
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
      error: "Invalid JSON."
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

  const otpId = typeof body.otp_id === "string"
    ? body.otp_id.trim()
    : "";

  const countryInfo = COUNTRY_PREFIXES[country];

  if (name.length < 2 || name.length > 100) {
    return json({
      success: false,
      error: "Enter a valid name."
    }, 400);
  }

  if (
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    return json({
      success: false,
      error: "Enter a valid email."
    }, 400);
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

  if (!countryInfo) {
    return json({
      success: false,
      error: "Only Ghana, Burkina Faso and Togo are supported."
    }, 400);
  }

  const phonePattern = new RegExp(
    "^" + countryInfo.prefix.replace("+", "\\+") +
    "[0-9]{" + countryInfo.digits + "}$"
  );

  if (!phonePattern.test(phone)) {
    return json({
      success: false,
      error: "Enter a valid phone number for the selected country."
    }, 400);
  }

  if (!/^OTP-[A-Za-z0-9-]+$/.test(otpId)) {
    return json({
      success: false,
      error: "Phone verification is required. Please verify your number first."
    }, 400);
  }

  try {
    // Check whether the email already belongs to a seller.
    const existingEmail = await env.DB.prepare(`
      SELECT id
      FROM sellers
      WHERE email = ?
      LIMIT 1
    `).bind(email).first();

    if (existingEmail) {
      return json({
        success: false,
        error: "An account with this email already exists."
      }, 409);
    }

    // Check whether the phone already belongs to a seller.
    const existingPhone = await env.DB.prepare(`
      SELECT id
      FROM sellers
      WHERE phone = ?
      LIMIT 1
    `).bind(phone).first();

    if (existingPhone) {
      return json({
        success: false,
        error: "This phone number is already registered."
      }, 409);
    }

    const now = new Date().toISOString();

    // Confirm this exact OTP was verified and has not expired.
    const verification = await env.DB.prepare(`
      SELECT id
      FROM phone_verifications
      WHERE otp_id = ?
        AND phone = ?
        AND verified = 1
        AND expires_at > ?
      LIMIT 1
    `).bind(
      otpId,
      phone,
      now
    ).first();

    if (!verification) {
      return json({
        success: false,
        error: "Phone verification is missing or expired. Please verify again."
      }, 400);
    }

    const sellerId = crypto.randomUUID();
    const passwordHash = await hashPassword(password);

    const token = makeToken();
    const tokenHash = await sha256(token);

    const sessionId = crypto.randomUUID();

    const expiresAt = new Date(
      Date.now() + SESSION_SECONDS * 1000
    ).toISOString();

    // Consume OTP, create seller and create session together.
    const results = await env.DB.batch([
      env.DB.prepare(`
        UPDATE phone_verifications
        SET verified = 2,
            consumed_by = ?
        WHERE id = ?
          AND otp_id = ?
          AND phone = ?
          AND verified = 1
          AND expires_at > ?
      `).bind(
        sellerId,
        verification.id,
        otpId,
        phone,
        now
      ),

      env.DB.prepare(`
        INSERT INTO sellers
          (id, name, email, password_hash, country, phone)
        SELECT ?, ?, ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1
          FROM phone_verifications
          WHERE id = ?
            AND otp_id = ?
            AND phone = ?
            AND verified = 2
            AND consumed_by = ?
            AND expires_at > ?
        )
      `).bind(
        sellerId,
        name,
        email,
        passwordHash,
        country,
        phone,
        verification.id,
        otpId,
        phone,
        sellerId,
        now
      ),

      env.DB.prepare(`
        INSERT INTO seller_sessions
          (id, phone, token_hash, expires_at)
        SELECT ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1
          FROM sellers
          WHERE id = ?
        )
      `).bind(
        sessionId,
        "email:" + sellerId,
        tokenHash,
        expiresAt,
        sellerId
      )
    ]);

    // Confirm all three database operations succeeded.
    if (
      !Array.isArray(results) ||
      results.length !== 3 ||
      results[0]?.meta?.changes !== 1 ||
      results[1]?.meta?.changes !== 1 ||
      results[2]?.meta?.changes !== 1
    ) {
      throw new Error(
        "Registration transaction did not complete."
      );
    }

    return json({
      success: true,
      seller: {
        id: sellerId,
        name,
        email,
        country,
        phone
      }
    }, 201, {
      "Set-Cookie":
        `shuk_seller_session=${token}; Path=/; Max-Age=${SESSION_SECONDS}; HttpOnly; Secure; SameSite=Lax`
    });

  } catch (error) {
    console.error("Registration error:", error);

    if (
      error?.message?.toLowerCase().includes("unique") ||
      error?.message?.toLowerCase().includes("constraint")
    ) {
      return json({
        success: false,
        error: "This email or phone number is already registered."
      }, 409);
    }

    return json({
      success: false,
      error: "Could not create account. Please try again."
    }, 500);
  }
        }
