function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

function clean(value, maxLength = 2000) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

const COUNTRY_PREFIXES = {
  GH: { prefix: "+233", digits: 9 },
  BF: { prefix: "+226", digits: 8 },
  TG: { prefix: "+228", digits: 8 }
};

function phoneMatchesCountry(phone, country) {
  const info = COUNTRY_PREFIXES[country];
  if (!info) return false;

  return new RegExp(
    "^" + info.prefix.replace("+", "\\+") +
    "[0-9]{" + info.digits + "}$"
  ).test(phone);
}

function supportedPhoneCountry(phone) {
  for (const [country, info] of Object.entries(COUNTRY_PREFIXES)) {
    if (phoneMatchesCountry(phone, country)) return country;
  }

  return null;
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
    typeof session.phone !== "string" ||
    !session.expires_at ||
    Date.parse(session.expires_at) <= Date.now()
  ) {
    return null;
  }

  if (session.phone.startsWith("email:")) {
    const sellerId = session.phone.slice(6);

    const seller = await env.DB.prepare(`
      SELECT id, name, email, country, phone, email_verified
      FROM sellers
      WHERE id = ?
      LIMIT 1
    `).bind(sellerId).first();

    if (!seller) return null;

    return {
      account_type: "email",
      seller_id: seller.id,
      name: seller.name,
      email: seller.email,
      country: seller.country,
      phone: seller.phone || null,
      email_verified: seller.email_verified
    };
  }

  return {
    account_type: "sms",
    seller_id: null,
    name: "",
    phone: session.phone,
    country: supportedPhoneCountry(session.phone)
  };
}

function validImageUrl(value) {
  if (value == null || value === "") return true;
  if (typeof value !== "string") return false;

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
    if (!env.DB) {
      return json({
        success: false,
        error: "Database unavailable."
      }, 503);
    }

    const url = new URL(request.url);

    const category = clean(
      url.searchParams.get("category"),
      100
    );

    const search = clean(
      url.searchParams.get("search"),
      100
    );

    const location = clean(
      url.searchParams.get("location"),
      100
    );

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

    const result = await env.DB.prepare(sql)
      .bind(...params)
      .all();

    return json({
      success: true,
      listings: result.results || []
    });

  } catch (error) {
    console.error("Marketplace GET error:", error);

    return json({
      success: false,
      error: "Unable to load marketplace listings."
    }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.DB) {
      return json({
        success: false,
        error: "Database unavailable."
      }, 503);
    }

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

    // Email sellers must verify their email before publishing.
    if (
      seller.account_type === "email" &&
      seller.email_verified !== 1
    ) {
      return json({
        success: false,
        error: "Please verify your email before publishing."
      }, 403);
    }

    // Validate seller eligibility.
    if (
      seller.account_type === "email" &&
      !COUNTRY_PREFIXES[seller.country]
    ) {
      return json({
        success: false,
        error: "Buy & Sell publishing is currently available only to sellers registered in Ghana, Burkina Faso and Togo."
      }, 403);
    }

    // Validate listing fields.
    const sellerName = seller.account_type === "email"
      ? clean(seller.name, 100)
      : clean(body.seller_name, 100);

    const itemName = clean(body.item_name, 200);
    const category = clean(body.category, 100);
    const location = clean(body.location, 100);
    const description = clean(body.description, 5000);
    const price = body.price_ghs;

    if (
      !sellerName ||
      !itemName ||
      !category ||
      !location ||
      !description
    ) {
      return json({
        success: false,
        error: "Please complete all required listing fields."
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
      clean(body.image_1, 1000),
      clean(body.image_2, 1000),
      clean(body.image_3, 1000)
    ];

    if (images.some(value => !validImageUrl(value))) {
      return json({
        success: false,
        error: "Images must use a valid ShukAfrica media URL."
      }, 400);
    }

    // Seller phone is contact information, not SMS verification.
    let sellerPhone = seller.phone || "";

    if (seller.account_type === "email") {
      if (!sellerPhone) {
        sellerPhone = clean(body.phone, 30);

        if (!phoneMatchesCountry(sellerPhone, seller.country)) {
          return json({
            success: false,
            error: "Please provide a valid phone number for your registered country."
          }, 400);
        }

        // Prevent a phone number already belonging to
        // another seller from being attached to this account.
        const existingPhone = await env.DB.prepare(`
          SELECT id
          FROM sellers
          WHERE phone = ?
            AND id != ?
          LIMIT 1
        `).bind(
          sellerPhone,
          seller.seller_id
        ).first();

        if (existingPhone) {
          return json({
            success: false,
            error: "This phone number is already registered to another seller."
          }, 409);
        }

      } else if (!phoneMatchesCountry(sellerPhone, seller.country)) {
        return json({
          success: false,
          error: "Your saved seller phone number is invalid. Please contact support."
        }, 403);
      }
    }

    // Preserve the legacy SMS seller session flow.
    if (seller.account_type === "sms") {
      if (
        !seller.country ||
        !phoneMatchesCountry(seller.phone, seller.country)
      ) {
        return json({
          success: false,
          error: "This phone number is not supported for Buy & Sell publishing."
        }, 403);
      }
    }

    if (
      seller.account_type !== "email" &&
      seller.account_type !== "sms"
    ) {
      return json({
        success: false,
        error: "Unsupported seller account."
      }, 403);
    }

    if (!sellerPhone) {
      return json({
        success: false,
        error: "A seller contact phone number is required."
      }, 400);
    }

    // Check the listing limit before inserting.
    if (seller.seller_id) {
      const count = await env.DB.prepare(`
        SELECT COUNT(*) AS total
        FROM marketplace_listings
        WHERE seller_id = ?
          AND status IN ('pending', 'published')
      `).bind(seller.seller_id).first();

      if (Number(count?.total || 0) >= 10) {
        return json({
          success: false,
          error: "You have reached the limit of 10 active or pending listings."
        }, 409);
      }
    }

    // Save a contact phone for an existing email seller
    // who did not previously have one. No SMS verification.
    if (
      seller.account_type === "email" &&
      !seller.phone
    ) {
      const saved = await env.DB.prepare(`
        UPDATE sellers
        SET phone = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
          AND phone IS NULL
      `).bind(
        sellerPhone,
        seller.seller_id
      ).run();

      if (!saved.meta || saved.meta.changes !== 1) {
        return json({
          success: false,
          error: "Unable to save your contact phone. Please try again."
        }, 409);
      }
    }

    const id = crypto.randomUUID();

    // Email/password seller account.
    if (seller.seller_id) {
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
        images[0] || null,
        images[1] || null,
        images[2] || null,
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
      // Preserve the legacy SMS seller listing flow.
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
        images[0] || null,
        images[1] || null,
        images[2] || null,
        sellerPhone
      ).run();
    }

    return json({
      success: true,
      message: "Listing submitted for review.",
      id
    }, 201);

  } catch (error) {
    console.error("Marketplace POST error:", error);

    if (
      error?.message?.toLowerCase().includes("unique") ||
      error?.message?.toLowerCase().includes("constraint")
    ) {
      return json({
        success: false,
        error: "This phone number may already be registered to another seller."
      }, 409);
    }

    return json({
      success: false,
      error: "Unable to submit your listing."
    }, 500);
  }
  }
          
