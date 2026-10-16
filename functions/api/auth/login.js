

const SESSION_SECONDS = 7 * 24 * 60 * 60;
const ITERATIONS = 100000;
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

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function verifyPassword(password, stored) {
  const parts = stored.split("$");

  if (
    parts.length !== 4 ||
    parts[0] !== "pbkdf2_sha256" ||
    Number(parts[1]) !== ITERATIONS ||
    !/^[0-9a-f]{32}$/.test(parts[2]) ||
    !/^[0-9a-f]{64}$/.test(parts[3])
  ) {
    return false;
  }

  const salt = Uint8Array.from(
    parts[2].match(/.{2}/g),
    byte => parseInt(byte, 16)
  );

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

  return await sha256(
    Array.from(new Uint8Array(derived))
      .map(byte => byte.toString(16).padStart(2, "0"))
      .join("")
  ) === await sha256(parts[3]);
}

function makeToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));

  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export async function onRequestPost({ request, env }) {
  if (!env.DB) {
    return json({
      success: false,
      error: "Database unavailable."
    }, 503);
  }

  const origin = request.headers.get("Origin") || "";
  const allowed = new Set([
    "https://shukafrica.com",
    "https://www.shukafrica.com",
    "https://shukafrica.pages.dev"
  ]);

  if (origin && !allowed.has(origin)) {
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
      error: "Invalid login data."
    }, 400);
  }

  const email = typeof body?.email === "string"
    ? body.email.trim().toLowerCase()
    : "";
  const password = body?.password;

  if (
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    typeof password !== "string" ||
    password.length < 1 ||
    password.length > 128
  ) {
    return json({
      success: false,
      error: "Invalid email or password."
    }, 400);
  }

  try {
    const seller = await env.DB.prepare(`
      SELECT id, name, email, country, password_hash
      FROM sellers
      WHERE email = ?
      LIMIT 1
    `).bind(email).first();

    if (
      !seller ||
      !await verifyPassword(password, seller.password_hash)
    ) {
      return json({
        success: false,
        error: "Invalid email or password."
      }, 401);
    }

    const token = makeToken();
    const tokenHash = await sha256(token);
    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(
      Date.now() + SESSION_SECONDS * 1000
    ).toISOString();

    await env.DB.prepare(`
      INSERT INTO seller_sessions
        (id, phone, token_hash, expires_at)
      VALUES (?, ?, ?, ?)
    `).bind(
      sessionId,
      "email:" + seller.id,
      tokenHash,
      expiresAt
    ).run();

    return json({
      success: true,
      seller: {
        id: seller.id,
        name: seller.name,
        email: seller.email,
        country: seller.country
      },
      expires_at: expiresAt
    }, 200, {
      "Set-Cookie":
        `shuk_seller_session=${token}; Path=/; Max-Age=${SESSION_SECONDS}; HttpOnly; Secure; SameSite=Lax`
    });

  } catch (error) {
    console.error("Login failed:", error);

    return json({
      success: false,
      error: "Unable to log in right now."
    }, 500);
  }
    }
