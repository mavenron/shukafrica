
const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

const WINDOW_SECONDS = 15 * 60;

const COUNTRY_RULES = {
  GH: { prefix: "+233", digits: 9 },
  BF: { prefix: "+226", digits: 8 },
  TG: { prefix: "+228", digits: 8 }
};

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

function normalizePhone(country, input) {
  const rule = COUNTRY_RULES[country];

  if (!rule || typeof input !== "string") return null;

  let number = input.trim().replace(/[\s()-]/g, "");

  // Accept local numbers beginning with 0.
  if (number.startsWith("0")) {
    number = rule.prefix + number.slice(1);
  } else if (/^\d+$/.test(number)) {
    number = rule.prefix + number;
  }

  const expected = new RegExp(
    "^" + rule.prefix.replace("+", "\\+") +
    "\\d{" + rule.digits + "}$"
  );

  return expected.test(number) ? number : null;
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
    const raw = await request.text();

    if (raw.length > 5000) {
      return json({ error: "Request too large." }, 413, origin);
    }

    body = JSON.parse(raw);
  } catch {
    return json({ error: "Invalid JSON request." }, 400, origin);
  }

  const country = typeof body?.country === "string"
    ? body.country.trim().toUpperCase()
    : "";

  const phone = normalizePhone(country, body?.phone);

  if (!phone) {
    return json({
      error: "Enter a valid phone number for your selected country."
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

    if (
      !upstream.ok ||
      result.success !== true ||
      typeof result.otp_id !== "string" ||
      !result.otp_id
    ) {
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
      phone,
      country,
      expires_in: 300
    }, 200, origin);

  } catch (error) {
    console.error("OTP send failed:", error);

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
