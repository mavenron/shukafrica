const SESSION_COOKIE = "shuk_open_market_session";
const SESSION_SECONDS = 7 * 24 * 60 * 60;
const ITERATIONS = 310000;

function json(data, status = 200, extraHeaders = {}) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

function clean(value, maxLength = 254) {
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

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const result = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return `pbkdf2$${ITERATIONS}$${base64url(salt)}$${base64url(new Uint8Array(result))}`;
}

async function createSession(userId, secret) {
  const payload = base64url(
    new TextEncoder().encode(JSON.stringify({
      sub: userId,
      exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS
    }))
  );

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload)
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

    if (
      typeof env.OPEN_MARKET_SESSION_SECRET !== "string" ||
      env.OPEN_MARKET_SESSION_SECRET.length < 32
    ) {
      return json({
        success: false,
        error: "Open Market session secret is not configured correctly."
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
    const email = clean(body.email).toLowerCase();
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
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      return json({
        success: false,
        error: "Enter a valid email address."
      }, 400);
    }

    if (password.length < 8 || password.length > 128) {
      return json({
        success: false,
        error: "Password must be between 8 and 128 characters."
      }, 400);
    }

    const existing = await env.OPEN_MARKET_DB
      .prepare(`
        SELECT id
        FROM open_market_users
        WHERE email = ?
        LIMIT 1
      `)
      .bind(email)
      .first();

    if (existing) {
      return json({
        success: false,
        error: "An account with this email already exists. Please log in."
      }, 409);
    }

    const userId = crypto.randomUUID();
    const passwordHash = await hashPassword(password);

    await env.OPEN_MARKET_DB
      .prepare(`
        INSERT INTO open_market_users
          (id, full_name, email, password_hash)
        VALUES (?, ?, ?, ?)
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
      message: "Account created successfully.",
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

    return json({
      success: false,
      error: "Unable to create your account. Please try again."
    }, 500);
  }
}
