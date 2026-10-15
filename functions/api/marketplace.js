function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function clean(value, maxLength = 2000) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

async function getAuthenticatedSeller(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(
    /(?:^|;\s*)shuk_seller_session=([^;]+)/
  );
  const token = match ? match[1] : "";

  if (!token || token.length > 200 || !env.DB) {
    return null;
  }

  let decodedToken;

  try {
    decodedToken = decodeURIComponent(token);
  } catch {
    return null;
  }

  const bytes = new TextEncoder().encode(decodedToken);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
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

  if (session.phone.startsWith("email:")) {
    const sellerId = session.phone.slice(6);

    const seller = await env.DB.prepare(`
      SELECT id, name, email, country
      FROM sellers
      WHERE id = ?
      LIMIT 1
    `).bind(sellerId).first();

    if (!seller) return null;

    return {
      account_type: "email",
      seller_id: seller.id,
      name: seller.name,
      phone: null
    };
  }

  return {
    account_type: "sms",
    seller_id: null,
    name: "",
    phone: session.phone
  };
}

function validImageUrl(value) {
  if (value == null || value === "") return true;

  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.hostname === "media.shukafrica.com"
    );
  } catch {
    return false;
  }
}

export async function onRequestGet({ request, env }) {
  try {
    const url = new URL(request.url);
    const category = clean(url.searchParams.get("category"), 100);
    const search = clean(url.searchParams.get("search"), 100);
    const location = clean(url.searchParams.get("location"), 100);

    let sql = `
      SELECT
        id, item_name, category, price_ghs, location,
        description, image_1, image_2, image_3,
        created_at, updated_at
      FROM marketplace_listings
      WHERE status = 'published'
    `;

    const params = [];

    if (category) {
      sql += " AND category = ?";
      params.push(category);
    }

    if (location) {
      sql += " AND location LIKE ?";
      params.push(`%${location}%`);
    }

    if (search) {
      sql += " AND (item_name LIKE ? OR description LIKE ?)";
      params.push(`%${search}%`, `%${search}%`);
    }

    sql += " ORDER BY created_at DESC LIMIT 100";

    const result = await env.DB.prepare(sql).bind(...params).all();

    return json({
      success: true,
      listings: result.results || []
    });
  } catch {
    return json({
      success: false,
      error: "Unable to load marketplace listings."
    }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const seller = await getAuthenticatedSeller(request, env);

    if (!seller) {
      return json({
        success: false,
        error: "Please log in before submitting a listing."
      }, 401);
    }

    const contentType = request.headers.get("Content-Type") || "";

    if (!contentType.toLowerCase().includes("application/json")) {
      return json({
        success: false,
        error: "Please submit the listing as JSON."
      }, 415);
    }

    const raw = await request.text();

    if (raw.length > 30000) {
      return json({
        success: false,
        error: "The listing submission is too large."
      }, 413);
    }

    let body;

    try {
      body = JSON.parse(raw);
    } catch {
      return json({
        success: false,
        error: "Invalid listing data."
      }, 400);
    }

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return json({
        success: false,
        error: "Invalid listing data."
      }, 400);
    }

    // Email accounts use their registered name.
    // Legacy SMS accounts keep the name supplied in the listing form.
    const sellerName = seller.account_type === "email"
      ? seller.name
      : clean(body.seller_name, 100);

    // Email accounts must provide a buyer contact number.
    // Existing SMS sessions continue to use their verified number.
    const sellerPhone = seller.account_type === "email"
      ? clean(body.seller_phone || body.phone, 30)
      : clean(seller.phone, 30);

    const itemName = clean(body.item_name, 200);
    const category = clean(body.category, 100);
    const location = clean(body.location, 100);
    const description = clean(body.description, 5000);
    const price = body.price_ghs;

    if (
      !sellerName || !sellerPhone || !itemName ||
      !category || !location || !description
    ) {
      return json({
        success: false,
        error: "Please complete all required listing fields, including the contact phone."
      }, 400);
    }

    if (!/^[0-9+()\-\s]{7,30}$/.test(sellerPhone)) {
      return json({
        success: false,
        error: "Please provide a valid contact phone number."
      }, 400);
    }

    if (
      typeof price !== "number" ||
      !Number.isFinite(price) ||
      price < 0 ||
      price > 1000000000
    ) {
      return json({
        success: false,
        error: "Please provide a valid price."
      }, 400);
    }

    const images = [
      body.image_1,
      body.image_2,
      body.image_3
    ];

    if (images.some(value =>
      value != null &&
      value !== "" &&
      (typeof value !== "string" || !validImageUrl(value))
    )) {
      return json({
        success: false,
        error: "Images must use a valid ShukAfrica media URL."
      }, 400);
    }

    const id = crypto.randomUUID();

    if (seller.seller_id) {
      // Count pending and published listings toward the seller's limit.
      // The INSERT only succeeds while the seller has fewer than 10.
      const result = await env.DB.prepare(`
        INSERT INTO marketplace_listings (
          id, seller_name, seller_phone, item_name,
          category, price_ghs, location, description,
          image_1, image_2, image_3, status,
          seller_id, owner_phone
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL
        WHERE (
          SELECT COUNT(*)
          FROM marketplace_listings
          WHERE seller_id = ?
            AND status IN ('pending', 'published')
        ) < 10
      `).bind(
        id,
        sellerName,
        sellerPhone,
        itemName,
        category,
        price,
        location,
        description,
        clean(body.image_1, 1000) || null,
        clean(body.image_2, 1000) || null,
        clean(body.image_3, 1000) || null,
        seller.seller_id,
        seller.seller_id
      ).run();

      if (!result.meta || result.meta.changes !== 1) {
        return json({
          success: false,
          error: "You have reached the limit of 10 active or pending listings."
        }, 409);
      }
    } else {
      // Preserve the existing SMS listing flow.
      await env.DB.prepare(`
        INSERT INTO marketplace_listings (
          id, seller_name, seller_phone, item_name,
          category, price_ghs, location, description,
          image_1, image_2, image_3, status, owner_phone
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
      `).bind(
        id,
        sellerName,
        sellerPhone,
        itemName,
        category,
        price,
        location,
        description,
        clean(body.image_1, 1000) || null,
        clean(body.image_2, 1000) || null,
        clean(body.image_3, 1000) || null,
        seller.phone
      ).run();
    }

    return json({
      success: true,
      message: "Listing submitted for review.",
      id
    }, 201);
  } catch {
    return json({
      success: false,
      error: "Unable to submit your listing."
    }, 500);
  }
      }
