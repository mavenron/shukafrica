
function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

async function getSeller(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(
    /(?:^|;\s*)shuk_seller_session=([^;]+)/
  );

  if (!match || !env.DB) return null;

  let token;

  try {
    token = decodeURIComponent(match[1]);
  } catch {
    return null;
  }

  if (!token || token.length > 200) return null;

  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );

  const tokenHash = Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");

  const session = await env.DB.prepare(`
    SELECT phone, expires_at
    FROM seller_sessions
    WHERE token_hash = ?
    LIMIT 1
  `).bind(tokenHash).first();

  if (
    !session ||
    !session.phone ||
    !session.expires_at ||
    Date.parse(session.expires_at) <= Date.now()
  ) {
    return null;
  }

  // This dashboard API is for email-registered seller accounts.
  if (!session.phone.startsWith("email:")) return null;

  const sellerId = session.phone.slice(6);

  const seller = await env.DB.prepare(`
    SELECT id, name, email, country
    FROM sellers
    WHERE id = ?
    LIMIT 1
  `).bind(sellerId).first();

  return seller || null;
}

export async function onRequestGet({ request, env }) {
  try {
    const seller = await getSeller(request, env);

    if (!seller) {
      return json({
        success: false,
        error: "Please log in to your seller account."
      }, 401);
    }

    const result = await env.DB.prepare(`
      SELECT
        id, item_name, category, price_ghs, location,
        description, image_1, image_2, image_3,
        status, created_at, updated_at
      FROM marketplace_listings
      WHERE seller_id = ?
      ORDER BY created_at DESC
      LIMIT 100
    `).bind(seller.id).all();

    return json({
      success: true,
      seller: {
        id: seller.id,
        name: seller.name,
        email: seller.email,
        country: seller.country
      },
      listings: result.results || []
    });
  } catch {
    return json({
      success: false,
      error: "Unable to load your listings."
    }, 500);
  }
}

export async function onRequestDelete({ request, env }) {
  try {
    const seller = await getSeller(request, env);

    if (!seller) {
      return json({
        success: false,
        error: "Please log in to your seller account."
      }, 401);
    }

    const url = new URL(request.url);
    const id = (url.searchParams.get("id") || "").trim();

    if (!id || id.length > 100) {
      return json({
        success: false,
        error: "A valid listing ID is required."
      }, 400);
    }

    const result = await env.DB.prepare(`
      DELETE FROM marketplace_listings
      WHERE id = ? AND seller_id = ?
    `).bind(id, seller.id).run();

    if (!result.meta || result.meta.changes !== 1) {
      return json({
        success: false,
        error: "Listing not found in your account."
      }, 404);
    }

    return json({
      success: true,
      message: "Your listing has been deleted."
    });
  } catch {
    return json({
      success: false,
      error: "Unable to delete the listing."
    }, 500);
  }
}
  
