
const SESSION_COOKIE = "shuk_open_market_session";
const SESSION_SECONDS = 7 * 24 * 60 * 60;

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

function fromBase64url(value) {
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded =
    base64 + "=".repeat((4 - base64.length % 4) % 4);

  const binary = atob(padded);

  return Uint8Array.from(
    binary,
    character => character.charCodeAt(0)
  );
}

async function verifyPassword(password, storedHash) {
  if (typeof storedHash !== "string") return false;

  const parts = storedHash.split("$");

  if (parts.length !== 4 || parts[0] !== "pbkdf2") {
    return false;
  }

  const iterations = Number(parts[1]);

  if (iterations !== 310000) {
    return false;
  }

  try {
    const salt = fromBase64url(parts[2]);
    const expected = fromBase64url(parts[3]);

    if (salt.length !== 16 || expected.length !== 32) {
      return false;
    }

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
        iterations,
        hash: "SHA-256"
      },
      key,
      256
    );

    const actual = new Uint8Array(result);
    let difference = 0;

    for (let i = 0; i < expected.length; i++) {
      difference |= actual[i] ^ expected[i];
    }

    return difference === 0;
  } catch {
    return false;
  }
}

async function createSession(userId, secret) {
  const payload = base64url(
    new TextEncoder().encode(
      JSON.stringify({
        sub: userId,
        exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS
      })
    )
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
        error: "Send login details as JSON."
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

    const email = clean(body.email).toLowerCase();
    const password =
      typeof body.password === "string" ? body.password : "";

    if (
      !email ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      password.length === 0 ||
      password.length > 128
    ) {
      return json({
        success: false,
        error: "Invalid email or password."
      }, 400);
    }

    const user = await env.OPEN_MARKET_DB
      .prepare(`
        SELECT id, full_name, email, password_hash
        FROM open_market_users
        WHERE email = ?
        LIMIT 1
      `)
      .bind(email)
      .first();

    if (
      !user ||
      !(await verifyPassword(password, user.password_hash))
    ) {
      return json({
        success: false,
        error: "Incorrect email or password."
      }, 401);
    }

    const session = await createSession(
      user.id,
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
      message: "Login successful.",
      user: {
        id: user.id,
        full_name: user.full_name,
        email: user.email
      }
    }, 200, {
      "Set-Cookie": cookie
    });

  } catch (error) {
    console.error("Open Market login error:", error);

    return json({
      success: false,
      error: "Unable to log in. Please try again."
    }, 500);
  }
      }
      
