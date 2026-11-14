
const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

function json(data, status = 200, origin = "") {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Vary": "Origin"
  };

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Credentials"] = "true";
  }

  return new Response(JSON.stringify(data), {
    status,
    headers
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
    /(?:^|;\s*)shuk_seller_session=([^;]+)/
  );

  const token = match ? match[1] : "";

  if (!token || token.length > 200) {
    return json({ authenticated: false }, 401, origin);
  }

  try {
    const tokenHash = await sha256(token);

    const session = await env.DB.prepare(`
      SELECT phone, expires_at
      FROM seller_sessions
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

    if (
      typeof session.phone !== "string" ||
      !session.phone.startsWith("email:")
    ) {
      return json({ authenticated: false }, 401, origin);
    }

    const sellerId = session.phone.slice(6);

    const seller = await env.DB.prepare(`
      SELECT id, name, email, country, phone, email_verified
      FROM sellers
      WHERE id = ?
      LIMIT 1
    `).bind(sellerId).first();

    if (!seller || Number(seller.email_verified) !== 1) {
      return json({ authenticated: false }, 401, origin);
    }

    // First, look for an existing Rentals owner linked to this seller.
    let owner = await env.DB.prepare(`
      SELECT id, name, email, seller_id
      FROM rental_owners
      WHERE seller_id = ?
      LIMIT 1
    `).bind(seller.id).first();

    // If no seller link exists, check whether the owner ID
    // already matches this seller ID.
    if (!owner) {
      const existingOwner = await env.DB.prepare(`
        SELECT id, name, email, seller_id
        FROM rental_owners
        WHERE id = ?
        LIMIT 1
      `).bind(seller.id).first();

      if (existingOwner) {
        // Link the existing matching owner record.
        await env.DB.prepare(`
          UPDATE rental_owners
          SET name = ?,
              email = ?,
              seller_id = ?,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
            AND (seller_id IS NULL OR seller_id = ?)
        `).bind(
          seller.name,
          seller.email,
          seller.id,
          seller.id,
          seller.id
        ).run();
      } else {
        // Create a Rentals owner record for this seller.
        await env.DB.prepare(`
          INSERT INTO rental_owners (
            id,
            name,
            email,
            password_hash,
            seller_id
          )
          VALUES (?, ?, ?, ?, ?)
        `).bind(
          seller.id,
          seller.name,
          seller.email,
          "SHUKAFRICA_SHARED_ACCOUNT_ONLY",
          seller.id
        ).run();
      }

      // Retrieve the linked owner record.
      owner = await env.DB.prepare(`
        SELECT id, name, email, seller_id
        FROM rental_owners
        WHERE seller_id = ?
        LIMIT 1
      `).bind(seller.id).first();
    }

    if (!owner) {
      return json({
        authenticated: false,
        error: "Could not connect your Rentals account."
      }, 500, origin);
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

      owner: {
        id: owner.id,
        name: owner.name,
        email: owner.email,
        seller_id: owner.seller_id
      },

      expires_at: session.expires_at
    }, 200, origin);

  } catch (error) {
    console.error("Shared Rentals session check failed:", error);

    return json({
      authenticated: false,
      error: "Could not verify your ShukAfrica session."
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
