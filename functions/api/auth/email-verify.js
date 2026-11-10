const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

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

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function onRequestPost({ request, env }) {
  if (!env.DB) {
    return json({
      success: false,
      error: "Database unavailable."
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

    if (raw.length > 1000) {
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

  const token = typeof body?.token === "string"
    ? body.token.trim()
    : "";

  if (!/^[a-f0-9]{64}$/i.test(token)) {
    return json({
      success: false,
      error: "Invalid or expired verification link."
    }, 400);
  }

  try {
    const tokenHash = await sha256(token);
    const now = new Date().toISOString();

    const result = await env.DB.prepare(`
      UPDATE sellers
      SET email_verified = 1,
          email_verification_token_hash = NULL,
          email_verification_expires_at = NULL,
          updated_at = CURRENT_TIMESTAMP
      WHERE email_verification_token_hash = ?
        AND email_verification_expires_at > ?
        AND email_verified = 0
    `).bind(tokenHash, now).run();

    if (result.meta?.changes !== 1) {
      return json({
        success: false,
        error: "This link is invalid, expired, or has already been used. Please request a new verification email."
      }, 400);
    }

    return json({
      success: true,
      message: "Your email has been verified successfully."
    });

  } catch (error) {
    console.error("Email verification error:", error);

    return json({
      success: false,
      error: "Could not verify your email right now."
    }, 500);
  }
      }
