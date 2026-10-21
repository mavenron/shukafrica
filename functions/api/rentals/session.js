
const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

function json(data, status = 200, origin = "") {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  };

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Credentials"] = "true";
    headers["Vary"] = "Origin";
  }

  return new Response(JSON.stringify(data), { status, headers });
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

export async function onRequestGet({ request, env }) {
  const origin = request.headers.get("Origin") || "";

  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return json({ authenticated: false }, 403);
  }

  if (!env.DB) {
    return json({
      authenticated: false,
      error: "Database unavailable."
    }, 503, origin);
  }

  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(
    /(?:^|;\s*)shuk_rental_session=([^;]+)/
  );
  const token = match ? match[1] : "";

  if (!token || token.length > 200) {
    return json({ authenticated: false }, 401, origin);
  }

  try {
    const tokenHash = await sha256(token);

    const session = await env.DB.prepare(`
      SELECT owner_id, expires_at
      FROM rental_owner_sessions
      WHERE token_hash = ?
      LIMIT 1
    `).bind(tokenHash).first();

    if (
      !session ||
      !session.expires_at ||
      !Number.isFinite(Date.parse(session.expires_at)) ||
      Date.parse(session.expires_at) <= Date.now()
    ) {
      return json({ authenticated: false }, 401, origin);
    }

    const owner = await env.DB.prepare(`
      SELECT id, name, email
      FROM rental_owners
      WHERE id = ?
      LIMIT 1
    `).bind(session.owner_id).first();

    if (!owner) {
      return json({ authenticated: false }, 401, origin);
    }

    return json({
      authenticated: true,
      owner: {
        id: owner.id,
        name: owner.name,
        email: owner.email
      },
      expires_at: session.expires_at
    }, 200, origin);

  } catch (error) {
    console.error("Rental session check failed:", error);

    return json({
      authenticated: false,
      error: "Could not verify Rentals session."
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
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    }
  });
}
  
