
const SESSION_COOKIE = "shuk_open_market_session";
const SESSION_SECONDS = 7 * 24 * 60 * 60;
const PBKDF2_ITERATIONS = 310000;

function json(data, status = 200, extraHeaders = {}) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

function clean(value, maxLength = 200) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64url(value) {
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);

  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return [
    "pbkdf2",
    PBKDF2_ITERATIONS,
    base64url(salt),
    base64url(new Uint8Array(derivedBits))
  ].join("$");
}

async function createSession(userId, secret) {
  const encoder = new TextEncoder();

  const payload = base64url(
    encoder.encode(JSON.stringify({
      sub: userId,
      exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS
    }))
  );

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(payload)
  );

  return `${payload}.${base64url(new Uint8Array(signature))}`;
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.OPEN_MARKET_DB) {
      return json({
        success: false,
        error: "Open Market database binding is missing."
      }, 500);
    }

    if (!env.OPEN_MARKET_SESSION_SECRET ||
        env.OPEN_MARKET_SESSION_SECRET.length < 32) {
      return json({
        success: false,
        error: "Open Market session secret is not configured."
      }, 500);
    }

    const contentType = request.headers.get("Content-Type") || "";

    if (!contentType.toLowerCase().includes("application/json")) {
      return json({
        success: false,
        error: "Send registration details as JSON."
      }, 415);
    }

    let body;

    try {
      body = await request.json();
    } catch {
      return json({
        success: false,
        error: "Invalid JSON request."
      }, 400);
    }

    const fullName = clean(body.full_name, 100);
    const email = clean(body.email, 254).toLowerCase();
    const password =
      typeof body.password === "string" ? body.password : "";

    if (fullName.length < 2) {
      return json({
        success: false,
        error: "Enter your full name."
      }, 400);
    }

    if (
      !email ||
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      return json({
        success: false,
        error: "Enter a valid email address."
      }, 400);
    }

    if (password.length < 10 || password.length > 128) {
      return json({
        success: false,
        error: "Your password must be 10–128 characters long."
      }, 400);
    }

    const existing = await env.OPEN_MARKET_DB
      .prepare(
        "SELECT id FROM open_market_users WHERE email = ? LIMIT 1"
      )
      .bind(email)
      .first();

    if (existing) {
      return json({
        success: false,
        error: "An account with this email already exists."
      }, 409);
    }

    const userId = crypto.randomUUID();
    const passwordHash = await hashPassword(password);

    await env.OPEN_MARKET_DB
      .prepare(`
        INSERT INTO open_market_users (
          id,
          full_name,
          email,
          password_hash
        ) VALUES (?, ?, ?, ?)
      `)
      .bind(userId, fullName, email, passwordHash)
      .run();

    const session = await createSession(
      userId,
      env.OPEN_MARKET_SESSION_SECRET
    );

    const cookie = [
      `${SESSION_COOKIE}=${session}`,
      "Path=/",
      `Max-Age=${SESSION_SECONDS}`,
      "HttpOnly",
      "Secure",
      "SameSite=Lax"
    ].join("; ");

    return json({
      success: true,
      message: "Open Market account created successfully.",
      user: {
        id: userId,
        full_name: fullName,
        email
      }
    }, 201, {
      "Set-Cookie": cookie
    });

  } catch (error) {
    console.error("Open Market registration error:", error);

    if (
      error?.message &&
      /unique constraint/i.test(error.message)
    ) {
      return json({
        success: false,
        error: "An account with this email already exists."
      }, 409);
    }

    return json({
      success: false,
      error: "Unable to create your account. Please try again."
    }, 500);
  }
}
