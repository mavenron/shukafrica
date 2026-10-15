const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev",
]);

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers,
    },
  });
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function onRequestPost({ request, env }) {
  const origin = request.headers.get("Origin");

  if (!origin || !ALLOWED_ORIGINS.has(origin)) {
    return json({ error: "Request origin not allowed." }, 403);
  }

  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)shuk_seller_session=([^;]+)/);
  const token = match ? match[1] : null;

  const headers = {
    "Set-Cookie":
      "shuk_seller_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Vary": "Origin",
  };

  if (token) {
    const tokenHash = await sha256Hex(decodeURIComponent(token));

    await env.DB.prepare(
      "DELETE FROM seller_sessions WHERE token_hash = ?"
    ).bind(tokenHash).run();
  }

  return json({ success: true, message: "Logged out successfully." }, 200, headers);
}

export async function onRequestOptions({ request }) {
  const origin = request.headers.get("Origin");

  if (!origin || !ALLOWED_ORIGINS.has(origin)) {
    return new Response(null, { status: 403 });
  }

  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Vary": "Origin",
    },
  });
}
