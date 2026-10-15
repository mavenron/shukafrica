
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
    return json({ success: false, error: "Database unavailable." }, 503);
  }

  const origin = request.headers.get("Origin");
  const allowed = new Set([
    "https://shukafrica.com",
    "https://www.shukafrica.com",
    "https://shukafrica.pages.dev"
  ]);

  if (origin && !allowed.has(origin)) {
    return json({ success: false, error: "Origin not allowed." }, 403);
  }

  const type = request.headers.get("Content-Type") || "";
  if (!type.toLowerCase().includes("application/json")) {
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
    return json({ success: false, error: "Invalid JSON." }, 400);
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return json({ success: false, error: "Invalid registration data." }, 400);
  }

  const name = typeof body.name === "string" ? body.name.trim() : "";
  const email = typeof body.email === "string"
    ? body.email.trim().toLowerCase()
    : "";
  const password = body.password;
  const country = typeof body.country === "string" ? body.country.trim() : "";

  const countries = new Set(["GH", "CI", "BF", "TG"]);

  if (name.length < 2 || name.length > 100) {
    return json({ success: false, error: "Enter a valid name." }, 400);
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

  if (!countries.has(country)) {
    return json({ success: false, error: "Select a supported country." }, 400);
  }

  try {
    const existing = await env.DB.prepare(
      "SELECT id FROM sellers WHERE email = ? LIMIT 1"
    ).bind(email).first();

    if (existing) {
      return json({
        success: false,
        error: "An account with this email already exists."
      }, 409);
    }

    const sellerId = crypto.randomUUID();
    const passwordHash = await hashPassword(password);
    const token = makeToken();
    const tokenHash = await sha256(token);
    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(
      Date.now() + SESSION_SECONDS * 1000
    ).toISOString();

    await env.DB.batch([
      env.DB.prepare(`
        INSERT INTO sellers
          (id, name, email, password_hash, country)
        VALUES (?, ?, ?, ?, ?)
      `).bind(sellerId, name, email, passwordHash, country),

      env.DB.prepare(`
        INSERT INTO seller_sessions
          (id, phone, token_hash, expires_at)
        VALUES (?, ?, ?, ?)
      `).bind(sessionId, "email:" + sellerId, tokenHash, expiresAt)
    ]);

    return json({
      success: true,
      seller: {
        id: sellerId,
        name,
        email,
        country
      }
    }, 201, {
      "Set-Cookie":
        `shuk_seller_session=${token}; Path=/; Max-Age=${SESSION_SECONDS}; HttpOnly; Secure; SameSite=Lax`
    });

  } catch (error) {
    console.error("Registration error:", error);
    return json({
      success: false,
      error: "Could not create account."
    }, 500);
  }
}
