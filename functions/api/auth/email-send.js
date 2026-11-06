
const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

const TOKEN_SECONDS = 30 * 60;

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
    const seller = await env.DB.prepare(`
      SELECT id, name, email, email_verified
      FROM sellers
      WHERE email = ?
      LIMIT 1
    `).bind(email).first();

    if (!seller) {
      return json({
        success: true,
        message: "If the account requires verification, an email will be sent."
      });
    }

    if (seller.email_verified === 1) {
      return json({
        success: true,
        message: "This email is already verified."
      });
    }

    const token = makeToken();
    const tokenHash = await sha256(token);

    const expiresAt = new Date(
      Date.now() + TOKEN_SECONDS * 1000
    ).toISOString();

    await env.DB.prepare(`
      UPDATE sellers
      SET email_verification_token_hash = ?,
          email_verification_expires_at = ?,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
        AND email_verified = 0
    `).bind(
      tokenHash,
      expiresAt,
      seller.id
    ).run();

    const verificationUrl =
      "https://shukafrica.com/verify-email.html?token=" +
      encodeURIComponent(token);

    const response = await fetch(
      "https://api.resend.com/emails",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${env.RESEND_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          from: "ShukAfrica <verify@mail.shukafrica.com>",
          to: [seller.email],
          subject: "Verify your ShukAfrica account",
          html: `
            <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;line-height:1.6">
              <h2>Welcome to ShukAfrica, ${String(seller.name)
                .replace(/[&<>"']/g, char => ({
                  "&": "&amp;",
                  "<": "&lt;",
                  ">": "&gt;",
                  '"': "&quot;",
                  "'": "&#39;"
                })[char])}!</h2>

              <p>Please verify your email address to activate your seller account.</p>

              <p>
                <a href="${verificationUrl}"
                   style="display:inline-block;padding:13px 22px;background:#111;color:#fff;text-decoration:none;border-radius:6px">
                  Verify my email
                </a>
              </p>

              <p>This link expires in 30 minutes and can only be used once.</p>
              <p>If you did not create this account, you can ignore this email.</p>
              <p>ShukAfrica Team</p>
            </div>
          `
        })
      }
    );

    if (!response.ok) {
      const providerError = await response.text();

      console.error("Resend email error:", providerError);

      await env.DB.prepare(`
        UPDATE sellers
        SET email_verification_token_hash = NULL,
            email_verification_expires_at = NULL
        WHERE id = ?
          AND email_verification_token_hash = ?
      `).bind(seller.id, tokenHash).run();

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
          
