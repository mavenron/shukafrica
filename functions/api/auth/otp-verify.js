const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

const WINDOW_SECONDS = 15 * 60;

function json(data, status = 200, origin = "") {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  };

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
  }

  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}

async function hashKey(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

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
  `).bind(
    key,
    now,
    cutoff,
    cutoff,
    cutoff,
    limit
  ).first();

  return row !== null;
}

export async function onRequestPost({ request, env }) {
  const origin = request.headers.get("Origin") || "";

  if (!ALLOWED_ORIGINS.has(origin)) {
    return json({
      error: "Origin not allowed."
    }, 403);
  }

  if (!env.DB || !env.AKOMASMS_API_KEY) {
    return json({
      error: "Verification service is not configured."
    }, 503, origin);
  }

  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().includes("application/json")) {
    return json({
      error: "Please submit a valid JSON request."
    }, 415, origin);
  }

  let body;

  try {
    const raw = await request.text();

    if (raw.length > 5000) {
      return json({
        error: "Request too large."
      }, 413, origin);
    }

    body = JSON.parse(raw);
  } catch {
    return json({
      error: "Invalid verification request."
    }, 400, origin);
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return json({
      error: "Invalid verification request."
    }, 400, origin);
  }

  const otpId = typeof body.otp_id === "string"
    ? body.otp_id.trim()
    : "";

  const code = typeof body.code === "string"
    ? body.code.trim()
    : "";

  const phone = typeof body.phone === "string"
    ? body.phone.trim()
    : "";

  if (
    !/^OTP-[A-Za-z0-9-]+$/.test(otpId) ||
    !/^\d{6}$/.test(code) ||
    !/^\+(233\d{9}|226\d{8}|228\d{8})$/.test(phone)
  ) {
    return json({
      error: "Enter a valid phone number and six-digit verification code."
    }, 400, origin);
  }

  const ip = request.headers.get("CF-Connecting-IP");

  if (!ip) {
    return json({
      error: "Request could not be validated."
    }, 400, origin);
  }

  const now = Math.floor(Date.now() / 1000);

  try {
    const attemptKey = await hashKey("otp:" + otpId);
    const ipKey = await hashKey("verify-ip:" + ip);

    if (!await consumeLimit(env.DB, ipKey, 20, now)) {
      return json({
        error: "Too many verification attempts. Try again later."
      }, 429, origin);
    }

    if (!await consumeLimit(env.DB, attemptKey, 5, now)) {
      return json({
        error: "Too many attempts for this verification code."
      }, 429, origin);
    }

    const record = await env.DB.prepare(`
      SELECT id, phone, verified, expires_at
      FROM phone_verifications
      WHERE otp_id = ?
      LIMIT 1
    `).bind(otpId).first();

    if (!record || record.phone !== phone) {
      return json({
        error: "Verification record does not match this phone number."
      }, 400, origin);
    }

    if (record.verified !== 0) {
      return json({
        error: "This verification code has already been used or invalidated."
      }, 409, origin);
    }

    const expiry = Date.parse(record.expires_at);

    if (!Number.isFinite(expiry) || expiry <= Date.now()) {
      return json({
        error: "Verification code has expired. Request a new code."
      }, 400, origin);
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
        body: JSON.stringify({
          otp_id: otpId,
          code
        })
      }
    );

    const result = await upstream.json().catch(() => ({}));

    if (
      !upstream.ok ||
      result.success !== true ||
      result.verified !== true
    ) {
      return json({
        error: "Incorrect verification code. Please try again."
      }, 400, origin);
    }

    const updated = await env.DB.prepare(`
      UPDATE phone_verifications
      SET verified = 1
      WHERE id = ?
        AND otp_id = ?
        AND phone = ?
        AND verified = 0
        AND expires_at > ?
    `).bind(
      record.id,
      otpId,
      phone,
      new Date().toISOString()
    ).run();

    if (!updated.meta || updated.meta.changes !== 1) {
      return json({
        error: "Verification expired or has already been used."
      }, 409, origin);
    }

    return json({
      success: true,
      verified: true,
      phone,
      message: "Phone number verified. You can now complete registration."
    }, 200, origin);

  } catch (error) {
    console.error("OTP verification failed:", error);

    return json({
      error: "Phone verification could not be completed."
    }, 503, origin);
  }
}

export async function onRequestOptions({ request }) {
  const origin = request.headers.get("Origin") || "";

  if (!ALLOWED_ORIGINS.has(origin)) {
    return new Response(null, {
      status: 403
    });
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
  
