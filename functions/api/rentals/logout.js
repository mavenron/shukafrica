
const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

function json(data, status = 200, origin = "") {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Vary": "Origin"
  };

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Credentials"] = "true";
  }

  return new Response(JSON.stringify(data), { status, headers });
}

export async function onRequest({ request, env }) {
  const origin = request.headers.get("Origin") || "";

  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return json({ error: "Origin not allowed." }, 403);
  }

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Vary": "Origin"
      }
    });
  }

  if (request.method !== "POST") {
    return json({ error: "Method not allowed." }, 405, origin);
  }

  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)shuk_rental_session=([^;]*)/);
  const token = match ? decodeURIComponent(match[1]) : "";

  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Set-Cookie":
      "shuk_rental_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
    "Vary": "Origin"
  };

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Credentials"] = "true";
  }

  try {
    if (token) {
      const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(token)
      );

      const tokenHash = Array.from(new Uint8Array(digest))
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");

      await env.DB.prepare(
        "DELETE FROM rental_owner_sessions WHERE token_hash = ?"
      ).bind(tokenHash).run();
    }

    return new Response(
      JSON.stringify({ success: true, message: "Logged out." }),
      { status: 200, headers }
    );
  } catch {
    return json({ error: "Unable to log out. Please try again." }, 500, origin);
  }
}
  
