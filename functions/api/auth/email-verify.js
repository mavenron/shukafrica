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

    const pending = await env.DB.prepare(`
      SELECT
        id,
        name,
        email,
        password_hash,
        country,
        phone
      FROM pending_seller_registrations
      WHERE verification_token_hash = ?
        AND verification_expires_at > ?
      LIMIT 1
    `).bind(tokenHash, now).first();

    if (!pending) {
      return json({
        success: false,
        error: "This link is invalid, expired, or has already been used. Please register again or request a new verification email."
      }, 400);
    }

    // Insert the permanent seller and remove the pending record
    // together, so a partial operation cannot leave inconsistent data.
    const results = await env.DB.batch([
      env.DB.prepare(`
        INSERT INTO sellers (
          id,
          name,
          email,
          password_hash,
          country,
          phone,
          email_verified,
          email_verification_token_hash,
          email_verification_expires_at
        )
        SELECT ?, ?, ?, ?, ?, ?, 1, NULL, NULL
        WHERE EXISTS (
          SELECT 1
          FROM pending_seller_registrations
          WHERE id = ?
            AND verification_token_hash = ?
            AND verification_expires_at > ?
        )
        AND NOT EXISTS (
          SELECT 1 FROM sellers
          WHERE email = ? COLLATE NOCASE
        )
        AND NOT EXISTS (
          SELECT 1 FROM sellers
          WHERE phone = ?
        )
      `).bind(
        pending.id,
        pending.name,
        pending.email,
        pending.password_hash,
        pending.country,
        pending.phone,
        pending.id,
        tokenHash,
        now,
        pending.email,
        pending.phone
      ),

      env.DB.prepare(`
        DELETE FROM pending_seller_registrations
        WHERE id = ?
          AND verification_token_hash = ?
          AND verification_expires_at > ?
          AND EXISTS (
            SELECT 1 FROM sellers
            WHERE id = ?
              AND email = ?
          )
      `).bind(
        pending.id,
        tokenHash,
        now,
        pending.id,
        pending.email
      )
    ]);

    const inserted = Number(results?.[0]?.meta?.changes || 0);
    const deleted = Number(results?.[1]?.meta?.changes || 0);

    if (inserted !== 1 || deleted !== 1) {
      console.error("Verification transaction did not complete", {
        inserted,
        deleted
      });

      return json({
        success: false,
        error: "Verification could not be completed. Please request a new verification email."
      }, 409);
    }

    return json({
      success: true,
      message: "Your email has been verified and your ShukAfrica seller account is now active. You can log in."
    });

  } catch (error) {
    console.error("Email verification error:", error);

    if (
      error?.message?.toLowerCase().includes("unique") ||
      error?.message?.toLowerCase().includes("constraint")
    ) {
      return json({
        success: false,
        error: "This email or phone number is already registered."
      }, 409);
    }

    return json({
      success: false,
      error: "Could not verify your email right now."
    }, 500);
  }
}
