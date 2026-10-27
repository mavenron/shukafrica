
const SESSION_COOKIE = "shuk_open_market_session";

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function base64urlDecode(value) {
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded =
    base64 + "=".repeat((4 - base64.length % 4) % 4);

  const binary = atob(padded);

  return Uint8Array.from(
    binary,
    character => character.charCodeAt(0)
  );
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";

  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");

    if (separator === -1) continue;

    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();

    if (key === name) return value;
  }

  return "";
}

async function verifySession(token, secret) {
  try {
    const parts = token.split(".");

    if (parts.length !== 2) return null;

    const [payload, signature] = parts;

    if (!payload || !signature) return null;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const validSignature = await crypto.subtle.verify(
      "HMAC",
      key,
      base64urlDecode(signature),
      new TextEncoder().encode(payload)
    );

    if (!validSignature) return null;

    const decodedPayload = new TextDecoder().decode(
      base64urlDecode(payload)
    );

    const session = JSON.parse(decodedPayload);

    if (
      typeof session.sub !== "string" ||
      !session.sub ||
      typeof session.exp !== "number" ||
      session.exp <= Math.floor(Date.now() / 1000)
    ) {
      return null;
    }

    return session;
  } catch {
    return null;
  }
}

export async function onRequestGet({ request, env }) {
  try {
    if (
      !env.OPEN_MARKET_DB ||
      typeof env.OPEN_MARKET_SESSION_SECRET !== "string" ||
      env.OPEN_MARKET_SESSION_SECRET.length < 32
    ) {
      return json({
        success: false,
        authenticated: false,
        error: "Open Market authentication is not configured."
      }, 500);
    }

    const token = getCookie(request, SESSION_COOKIE);

    if (!token) {
      return json({
        success: true,
        authenticated: false,
        user: null
      });
    }

    const session = await verifySession(
      token,
      env.OPEN_MARKET_SESSION_SECRET
    );

    if (!session) {
      return json({
        success: true,
        authenticated: false,
        user: null
      });
    }

    const user = await env.OPEN_MARKET_DB
      .prepare(`
        SELECT id, full_name, email
        FROM open_market_users
        WHERE id = ?
        LIMIT 1
      `)
      .bind(session.sub)
      .first();

    if (!user) {
      return json({
        success: true,
        authenticated: false,
        user: null
      });
    }

    return json({
      success: true,
      authenticated: true,
      user
    });

  } catch (error) {
    console.error("Open Market session error:", error);

    return json({
      success: false,
      authenticated: false,
      error: "Unable to verify the Open Market session."
    }, 500);
  }
}
