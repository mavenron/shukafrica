
const SESSION_SECONDS = 7 * 24 * 60 * 60;
const ITERATIONS = 100000;

const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

function json(data, status = 200, headers = {}) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers
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

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt,
    iterations: ITERATIONS,
    hash: "SHA-256"
  }, key, 256);

  const hex = bytes =>
    Array.from(new Uint8Array(bytes))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

  return `pbkdf2_sha256$${ITERATIONS}$${hex(salt)}$${hex(bits)}`;
}

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function onRequestPost({ request, env }) {
  const origin = request.headers.get("Origin") || "";

  if (!ALLOWED_ORIGINS.has(origin)) {
    return json({ success: false, error: "Request not allowed." }, 403);
  }

  if (!env.DB) {
    return json({ success: false, error: "Database unavailable." }, 503);
  }

  if (!(request.headers.get("Content-Type") || "")
    .toLowerCase().includes("application/json")) {
    return json({ success: false, error: "JSON required." }, 415);
  }

  let body;

  try {
    const raw = await request.text();
    if (raw.length > 10000) {
      return json({ success: false, error: "Request too large." }, 413);
    }
    body = JSON.parse(raw);
  } catch {
    return json({ success: false, error: "Invalid registration data." }, 400);
  }

  const name = typeof body?.name === "string" ? body.name.trim() : "";
  const email = typeof body?.email === "string"
    ? body.email.trim().toLowerCase()
    : "";
  const password = body?.password;

  if (name.length < 2 || name.length > 100) {
    return json({ success: false, error: "Enter your name." }, 400);
  }

  if (
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    return json({ success: false, error: "Enter a valid email." }, 400);
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

  try {
    const existing = await env.DB.prepare(
      "SELECT id FROM rental_owners WHERE email = ? LIMIT 1"
    ).bind(email).first();

    if (existing) {
      return json({
        success: false,
        error: "An account with this email already exists."
      }, 409);
    }

    const ownerId = crypto.randomUUID();
    const passwordHash = await hashPassword(password);
    const token = makeToken();
    const tokenHash = await sha256(token);
    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(
      Date.now() + SESSION_SECONDS * 1000
    ).toISOString();

    await env.DB.batch([
      env.DB.prepare(`
        INSERT INTO rental_owners (id, name, email, password_hash)
        VALUES (?, ?, ?, ?)
      `).bind(ownerId, name, email, passwordHash),

      env.DB.prepare(`
        INSERT INTO rental_owner_sessions
          (id, owner_id, token_hash, expires_at)
        VALUES (?, ?, ?, ?)
      `).bind(sessionId, ownerId, tokenHash, expiresAt)
    ]);

    return json({
      success: true,
      owner: { id: ownerId, name, email }
    }, 201, {
      "Set-Cookie":
        `shuk_rental_session=${token}; Path=/; Max-Age=${SESSION_SECONDS}; HttpOnly; Secure; SameSite=Lax`
    });
  } catch (error) {
    console.error("Rental registration failed:", error);
    return json({
      success: false,
      error: "Could not create the rental account."
    }, 500);
  }
                 }

