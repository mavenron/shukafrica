
const SESSION_COOKIE = "shuk_open_market_session";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";

  for (const part of cookie.split(";")) {
    const index = part.indexOf("=");

    if (index < 0) continue;

    if (part.slice(0, index).trim() === name) {
      return part.slice(index + 1).trim();
    }
  }

  return null;
}

function base64UrlToBytes(value) {
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

async function getSellerId(request, secret) {
  try {
    if (!secret) return null;

    const token = getCookie(request, SESSION_COOKIE);
    if (!token) return null;

    const parts = token.split(".");
    if (parts.length !== 2) return null;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlToBytes(parts[1]),
      new TextEncoder().encode(parts[0])
    );

    if (!valid) return null;

    const payload = JSON.parse(
      new TextDecoder().decode(
        base64UrlToBytes(parts[0])
      )
    );

    if (
      !payload.sub ||
      !payload.exp ||
      payload.exp <= Math.floor(Date.now() / 1000)
    ) {
      return null;
    }

    return payload.sub;
  } catch {
    return null;
  }
}

export async function onRequestGet({ request, env }) {
  try {
    if (!env.OPEN_MARKET_DB) {
  return json({
    success: false,
    error: "Open Market database is not configured."
  }, 500);
    }

    const sellerId = await getSellerId(
      request,
      env.OPEN_MARKET_SESSION_SECRET
    );

    if (!sellerId) {
      return json({
        success: false,
        error: "Please log in to your Open Market account."
      }, 401);
    }

    const result = await env.OPEN_MARKET_DB.prepare(`
      SELECT
        id,
        category,
        job_type,
        title,
        seller_name,
        contact,
        price,
        location,
        country,
        region,
        description,
        delivery,
        image_1,
        image_2,
        image_3,
        image_4,
        image_5,
        video_url,
        status,
        created_at
      FROM open_market_listings
      WHERE seller_id = ?
      ORDER BY created_at DESC
    `).bind(sellerId).all();

    return json({
      success: true,
      listings: result.results || []
    });
  } catch (error) {
    console.error("Open Market seller listings error:", error);

    return json({
      success: false,
      error: "Unable to load your listings."
    }, 500);
  }
  }
