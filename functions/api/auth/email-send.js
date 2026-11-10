const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

const TOKEN_SECONDS = 30 * 60;
const RATE_WINDOW_SECONDS = 15 * 60;
const EMAIL_LIMIT = 3;
const IP_LIMIT = 10;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

function makeToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));

  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
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

async function checkRateLimit(db, bucketKey, limit, now) {
  const result = await db.prepare(`
    INSERT INTO email_verification_rate_limits
      (bucket_key, window_start, request_count)
    VALUES (?, ?, 1)
    ON CONFLICT(bucket_key) DO UPDATE SET
      window_start = CASE
        WHEN ? - window_start >= ?
        THEN ?
        ELSE window_start
      END,
      request_count = CASE
        WHEN ? - window_start >= ?
        THEN 1
        ELSE request_count + 1
      END
    RETURNING request_count
  `).bind(
    bucketKey,
    now,
    now,
    RATE_WINDOW_SECONDS,
    now,
    now,
    RATE_WINDOW_SECONDS
  ).first();

  return result && result.request_count <= limit;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

export async function onRequestPost({ request, env }) {
  if (!env.DB || !env.RESEND_API_KEY) {
    return json({
      success: false,
      error: "Email service unavailable."
    }, 503);
  }

  const origin = request.headers.get("Origin") || "";

  if (origin && !ALLOWED_ORIGINS.has(origin)) {
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

    if (raw.length > 5000) {
      return json({
        success: false,
        error: "Request too large."
      }, 413);
    }

    body = JSON.parse(raw);
  } catch {
    return json({
      success: false,
      error: "Invalid request."
    }, 400);
  }

  const email = typeof body?.email === "string"
    ? body.email.trim().toLowerCase()
    : "";

  if (
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    return json({
      success: false,
      error: "Enter a valid email address."
    }, 400);
  }

  try {
    const ip = request.headers.get("CF-Connecting-IP");

    if (!ip) {
      return json({
        success: false,
        error: "Unable to process this request."
      }, 400);
    }

    const now = Math.floor(Date.now() / 1000);

    await env.DB.prepare(`
      DELETE FROM email_verification_rate_limits
      WHERE window_start < ?
    `).bind(now - 86400).run();

    // Remove expired pending registrations.
    await env.DB.prepare(`
      DELETE FROM pending_seller_registrations
      WHERE verification_expires_at <= ?
    `).bind(new Date().toISOString()).run();

    const emailKey = "email:" + await sha256(email);
    const ipKey = "ip:" + await sha256(ip);

    const ipAllowed = await checkRateLimit(
      env.DB,
      ipKey,
      IP_LIMIT,
      now
    );

    if (!ipAllowed) {
      return json({
        success: false,
        error: "Too many requests. Please try again in 15 minutes."
      }, 429);
    }

    const emailAllowed = await checkRateLimit(
      env.DB,
      emailKey,
      EMAIL_LIMIT,
      now
    );

    if (!emailAllowed) {
      return json({
        success: false,
        error: "Too many requests for this email. Please try again in 15 minutes."
      }, 429);
    }

    const pending = await env.DB.prepare(`
      SELECT id, name, email
      FROM pending_seller_registrations
      WHERE email = ? COLLATE NOCASE
      LIMIT 1
    `).bind(email).first();

    // Do not disclose whether an email is registered.
  if (!pending) {
  return json({
    success: false,
    error: "No active pending registration was found. Please register again."
  }, 404);
}

    const token = makeToken();
    const tokenHash = await sha256(token);

    const expiresAt = new Date(
      Date.now() + TOKEN_SECONDS * 1000
    ).toISOString();

    const updateResult = await env.DB.prepare(`
      UPDATE pending_seller_registrations
      SET verification_token_hash = ?,
          verification_expires_at = ?
      WHERE id = ?
    `).bind(
      tokenHash,
      expiresAt,
      pending.id
    ).run();

    if (Number(updateResult?.meta?.changes) !== 1) {
      return json({
        success: false,
        error: "Could not prepare verification. Please try again."
      }, 500);
    }

    const verificationUrl =
      "https://shukafrica.com/verify-email.html?token=" +
      encodeURIComponent(token);

    let response;

    try {
      response = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${env.RESEND_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          from: "ShukAfrica <verify@mail.shukafrica.com>",
          to: [pending.email],
          subject: "Verify your ShukAfrica seller account",
          html: `
            <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;line-height:1.6">
              <h2>Welcome to ShukAfrica, ${escapeHtml(pending.name)}!</h2>
              <p>Please verify your email address to activate your seller account.</p>
              <p>
                <a href="${verificationUrl}"
                   style="display:inline-block;padding:13px 22px;background:#176b45;color:#fff;text-decoration:none;border-radius:6px">
                  Verify my email
                </a>
              </p>
              <p>This link expires in 30 minutes and can only be used once.</p>
              <p>If you did not request this account, you can ignore this email.</p>
              <p>ShukAfrica Team</p>
            </div>
          `
        })
      });
    } catch (error) {
      console.error("Resend request failed:", error);

      return json({
        success: false,
        error: "Could not send verification email. Please try again."
      }, 502);
    }

    if (!response.ok) {
      const providerError = await response.text();

      console.error("Resend email error:", {
        status: response.status,
        response: providerError
      });

      return json({
        success: false,
        error: "Could not send verification email. Please try again."
      }, 502);
    }

    return json({
      success: true,
      message: "Verification email sent. Please check your inbox."
    });

  } catch (error) {
    console.error("Email verification send failed:", error);

    return json({
      success: false,
      error: "Unable to send verification email right now."
    }, 500);
  }
}
  
