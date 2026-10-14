
const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

const WINDOW_SECONDS = 15 * 60;

function json(data, status, origin) {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  };

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
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

  if (!body || typeof body.phone !== "string") {
    return json({ error: "Enter a valid phone number." }, 400, origin);
  }

  let phone = body.phone.trim().replace(/[\s()-]/g, "");

  if (/^0\d{9}$/.test(phone)) {
    phone = "+233" + phone.slice(1);
  }

  if (!/^\+233\d{9}$/.test(phone)) {
    return json({
      error: "Enter a valid Ghana phone number, e.g. +233241234567."
    }, 400, origin);
  }

  const ip = request.headers.get("CF-Connecting-IP");

  if (!ip) {
    return json({
      error: "Request could not be validated. Please try again."
    }, 400, origin);
  }

  const now = Math.floor(Date.now() / 1000);

  try {
    const phoneKey = await hashKey("phone:" + phone);
    const ipKey = await hashKey("ip:" + ip);

    const phoneAllowed = await consumeLimit(
      env.DB, phoneKey, 3, now
    );

    if (!phoneAllowed) {
      return json({
        error: "Too many verification requests for this number. Try again later."
      }, 429, origin);
    }

    const ipAllowed = await consumeLimit(
      env.DB, ipKey, 10, now
    );

    if (!ipAllowed) {
      return json({
        error: "Too many verification requests. Try again later."
      }, 429, origin);
    }

    const upstream = await fetch(
      "https://api.akomasms.com/v1/otp/send",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${env.AKOMASMS_API_KEY}`,
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify({
          phone,
          sender_id: "AKOMASMS",
          expires_in: 300,
          length: 6,
          channel: "sms"
        })
      }
    );

    const result = await upstream.json().catch(() => ({}));

    if (!upstream.ok || result.success !== true ||
        typeof result.otp_id !== "string" ||
        !result.otp_id) {
      return json({
        error: "AkomaSMS could not start verification. Please try again later."
      }, 502, origin);
    }

    const id = crypto.randomUUID();
    const expiresAt = new Date((now + 300) * 1000).toISOString();

    await env.DB.prepare(`
      INSERT INTO phone_verifications
        (id, phone, otp_id, verified, expires_at)
      VALUES (?, ?, ?, 0, ?)
    `).bind(id, phone, result.otp_id, expiresAt).run();

    return json({
      success: true,
      otp_id: result.otp_id,
      expires_in: 300
    }, 200, origin);

  } catch {
    return json({
      error: "Verification could not be started. Please try again later."
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
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    }
  });
}

