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

  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}

async function hashKey(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function onRequestGet({ request, env }) {
  const origin = request.headers.get("Origin") || "";

  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return json({ authenticated: false }, 403, origin);
  }

  if (!env.DB) {
    console.error("SESSION DIAGNOSTIC: DB binding missing");
    return json({ authenticated: false }, 503, origin);
  }

  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(
    /(?:^|;\s*)shuk_seller_session=([^;]+)/
  );

  const token = match ? match[1] : "";

  console.log("SESSION DIAGNOSTIC: cookie check", {
    cookiePresent: Boolean(cookie),
    sessionCookiePresent: Boolean(token),
    tokenLength: token.length
  });

  if (!token || token.length > 200) {
    return json({ authenticated: false }, 401, origin);
  }

  try {
    const tokenHash = await hashKey(token);

    const session = await env.DB.prepare(`
      SELECT id, phone, expires_at
      FROM seller_sessions
      WHERE token_hash = ?
      LIMIT 1
    `).bind(tokenHash).first();

    console.log("SESSION DIAGNOSTIC: database session lookup", {
      sessionFound: Boolean(session),
      sessionId: session?.id || null,
      phonePrefix: session?.phone?.startsWith("email:") || false,
      expiresAt: session?.expires_at || null
    });

    if (
      !session ||
      !session.expires_at ||
      !Number.isFinite(Date.parse(session.expires_at)) ||
      Date.parse(session.expires_at) <= Date.now()
    ) {
      return json({ authenticated: false }, 401, origin);
    }

    if (
      typeof session.phone === "string" &&
      session.phone.startsWith("email:")
    ) {
      const sellerId = session.phone.slice(6);

      const seller = await env.DB.prepare(`
        SELECT id, name, email, country, phone, email_verified
        FROM sellers
        WHERE id = ?
        LIMIT 1
      `).bind(sellerId).first();

      console.log("SESSION DIAGNOSTIC: seller lookup", {
        sellerFound: Boolean(seller),
        sellerId: seller?.id || null,
        emailVerified: seller?.email_verified ?? null,
        emailVerifiedType: typeof seller?.email_verified
      });

      if (!seller || Number(seller.email_verified) !== 1) {
        return json({ authenticated: false }, 401, origin);
      }

      return json({
        authenticated: true,
        account_type: "email",
        seller: {
          id: seller.id,
          name: seller.name,
          email: seller.email,
          country: seller.country,
          phone: seller.phone || null
        },
        expires_at: session.expires_at
      }, 200, origin);
    }

    console.log("SESSION DIAGNOSTIC: legacy session rejected");

    return json({ authenticated: false }, 401, origin);

  } catch (error) {
    console.error("Session check failed:", error);

    return json({
      authenticated: false,
      error: "Could not check seller session."
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
