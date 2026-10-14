const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

const WINDOW_SECONDS = 15 * 60;
const SESSION_SECONDS = 7 * 24 * 60 * 60;

function json(data, status, origin, extraHeaders = {}) {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...extraHeaders
  };

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
    headers["Access-Control-Allow-Credentials"] = "true";
  }

  return new Response(JSON.stringify(data), { status, headers });
}

async function hashKey(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));

  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function consumeLimit(db, key, limit, now) {
  const cutoff = now - WINDOW_SECONDS;

  const row = await db.prepare(`
    INSERT INTO otp_rate_limits
      (bucket_key, window_start, request_count)
    VALUES (?, ?, 1)
    ON CONFLICT(bucket_key) DO UPDATE SET
      window_start = CASE
        WHEN otp_rate_limits.window_start <= ?
        THEN excluded.window_start
        ELSE otp_rate_limits.window_start
      END,
      request_count = CASE
        WHEN otp_rate_limits.window_start <= ?
        THEN 1
        ELSE otp_rate_limits.request_count + 1
      END
    WHERE otp_rate_limits.window_start <= ?
       OR otp_rate_limits.request_count < ?
    RETURNING request_count
  `).bind(key, now, cutoff, cutoff, cutoff, limit).first();

  return row !== null;
}

export async function onRequestPost({ request, env }) {
  const origin = request.headers.get("Origin") || "";

  if (!ALLOWED_ORIGINS.has(origin)) {
    return json({ error: "Origin not allowed." }, 403, origin);
  }

  if (!env.DB || !env.AKOMASMS_API_KEY) {
    return json({
      error: "Verification service is not configured."
    }, 503, origin);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON request." }, 400, origin);
  }

  const otpId =
    typeof body?.otp_id === "string" ? body.otp_id.trim() : "";
  const code =
    typeof body?.code === "string" ? body.code.trim() : "";

  if (
    !/^OTP-[A-Za-z0-9-]+$/.test(otpId) ||
    !/^\d{6}$/.test(code)
  ) {
    return json({
      error: "Enter a valid OTP ID and six-digit code."
    }, 400, origin);
  }

  try {
    const record = await env.DB.prepare(`
      SELECT id, phone, verified, expires_at
      FROM phone_verifications
      WHERE otp_id = ?
      LIMIT 1
    `).bind(otpId).first();

    if (!record) {
      return json({
        error: "Verification request not found. Request a new code."
      }, 404, origin);
    }

    if (record.verified === 1) {
      return json({
        error: "This code has already been used. Request a new code."
      }, 409, origin);
    }

    if (Date.parse(record.expires_at) <= Date.now()) {
      return json({
        error: "This code has expired. Request a new code."
      }, 400, origin);
    }

    const now = Math.floor(Date.now() / 1000);
    const attemptKey = await hashKey("verify:" + otpId);

    if (!await consumeLimit(env.DB, attemptKey, 5, now)) {
      return json({
        error: "Too many attempts. Request a new code."
      }, 429, origin);
    }

    const upstream = await fetch(
      "https://api.akomasms.com/v1/otp/verify",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${env.AKOMASMS_API_KEY}`,
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify({ otp_id: otpId, code })
      }
    );

    const result = await upstream.json().catch(() => ({}));

    if (
      !upstream.ok ||
      result.success !== true ||
      result.verified !== true
    ) {
      return json({
        success: false,
        verified: false,
        error: "The code is invalid, expired, or could not be verified."
      }, 400, origin);
    }

    // Consume this OTP before issuing a session.
    const updated = await env.DB.prepare(`
      UPDATE phone_verifications
      SET verified = 1
      WHERE otp_id = ?
        AND verified = 0
        AND expires_at > ?
    `).bind(otpId, new Date().toISOString()).run();

    if (updated.meta.changes !== 1) {
      return json({
        error: "The code expired or was already used. Request a new code."
      }, 409, origin);
    }

    const token = randomToken();
    const tokenHash = await hashKey(token);
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
      record.phone,
      tokenHash,
      expiresAt
    ).run();

    return json({
      success: true,
      verified: true,
      session_expires_at: expiresAt
    }, 200, origin, {
      "Set-Cookie":
        `shuk_seller_session=${token}; Path=/; Max-Age=${SESSION_SECONDS}; HttpOnly; Secure; SameSite=Lax`
    });

  } catch {
    return json({
      error: "Verification service is temporarily unavailable. If needed, request a new code."
    }, 503, origin);
  }
}

export async function onRequestOptions({ request }) {
  const origin = request.headers.get("Origin") || "";

  if (!ALLOWED_ORIGINS.has(origin)) {
    return new Response(null, { status: 403 });
  }

  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    }
  });
}
