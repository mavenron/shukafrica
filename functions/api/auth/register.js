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
      error: "Enter a valid email address."
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

  const countryInfo = COUNTRIES[country];

  if (!countryInfo) {
    return json({
      success: false,
      error: "ShukAfrica seller registration is currently available in Ghana, Burkina Faso and Togo."
    }, 400);
  }

  // Cloudflare IP country restriction.
  const ipCountry = request.headers.get("CF-IPCountry") || "";

  if (ipCountry !== country) {
    return json({
      success: false,
      error: "Your selected country does not match your current network location."
    }, 403);
  }

  // Phone is optional. If supplied, validate its country format.
  if (phone) {
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
  }

  try {
    const existingEmail = await env.DB.prepare(`
      SELECT id FROM sellers
      WHERE email = ?
      LIMIT 1
    `).bind(email).first();

    if (existingEmail) {
      return json({
        success: false,
        error: "An account with this email already exists."
      }, 409);
    }

    if (phone) {
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
    }

    const sellerId = crypto.randomUUID();
    const passwordHash = await hashPassword(password);

    await env.DB.prepare(`
      INSERT INTO sellers (
        id,
        name,
        email,
        password_hash,
        country,
        phone,
        email_verified,
        email_verification_token_hash,
        email_verification_expires_at
      )
      VALUES (?, ?, ?, ?, ?, ?, 0, NULL, NULL)
    `).bind(
      sellerId,
      name,
      email,
      passwordHash,
      country,
      phone || null
    ).run();

    return json({
      success: true,
      message: "Account created. Please verify your email to activate it.",
      seller: {
        id: sellerId,
        name,
        email,
        country
      }
    }, 201);

  } catch (error) {
    console.error("Seller registration failed:", error);

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
      error: "Could not create your account. Please try again."
    }, 500);
  }
  }
    
