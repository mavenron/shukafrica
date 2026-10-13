function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function authorised(request, env) {
  const supplied = request.headers.get("X-Shuk-Admin-Key");
  const expected = env.SHUK_ADMIN_KEY;

  if (
    !supplied ||
    !expected ||
    supplied.length !== expected.length
  ) {
    return false;
  }

  let difference = 0;

  for (let i = 0; i < supplied.length; i++) {
    difference |= supplied.charCodeAt(i) ^ expected.charCodeAt(i);
  }

  return difference === 0;
}

function requireAdmin(request, env) {
  return authorised(request, env)
    ? null
    : json({ success: false, error: "Unauthorised" }, 401);
}

function clean(value, max = 2000) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, max);
}

function validateListing(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return "A JSON object is required.";
  }

  for (const [key, max] of [
    ["seller_name", 100],
    ["seller_phone", 30],
    ["item_name", 200],
    ["category", 100],
    ["location", 100],
    ["description", 5000]
  ]) {
    if (!clean(body[key], max)) {
      return key.replaceAll("_", " ") + " is required.";
    }
  }

  if (!/^[0-9+()\-\s]{7,30}$/.test(body.seller_phone.trim())) {
    return "Enter a valid seller phone number.";
  }

  if (
    typeof body.price_ghs !== "number" ||
    !Number.isFinite(body.price_ghs) ||
    body.price_ghs < 0 ||
    body.price_ghs > 1000000000
  ) {
    return "Price must be a valid non-negative number.";
  }

  for (const key of ["image_1", "image_2", "image_3"]) {
    const value = body[key];

    if (value === null || value === undefined || value === "") {
      continue;
    }

    if (typeof value !== "string" || value.length > 2000) {
      return key + " is invalid.";
    }

    try {
      const url = new URL(value);

      if (
        url.protocol !== "https:" ||
        url.hostname !== "media.shukafrica.com"
      ) {
        return key + " must be a ShukAfrica media URL.";
      }
    } catch {
      return key + " must be a valid URL.";
    }
  }

  return null;
}

const SELECT_FIELDS = `
  id, seller_name, seller_phone, item_name, category,
  price_ghs, location, description,
  image_1, image_2, image_3,
  status, created_at, updated_at
`;

export async function onRequestGet({ request, env }) {
  const denied = requireAdmin(request, env);
  if (denied) return denied;

  try {
    const url = new URL(request.url);
    const status = url.searchParams.get("status");

    let sql = `
      SELECT ${SELECT_FIELDS}
      FROM marketplace_listings
    `;

    const params = [];

    if (status && ["pending", "published", "removed"].includes(status)) {
      sql += " WHERE status = ?";
      params.push(status);
    }

    sql += " ORDER BY created_at DESC LIMIT 200";

    const result = await env.DB
      .prepare(sql)
      .bind(...params)
      .all();

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

export async function onRequestPatch({ request, env }) {
  const denied = requireAdmin(request, env);
  if (denied) return denied;

  let body;

  try {
    const raw = await request.text();

    if (raw.length > 30000) {
      return json({ success: false, error: "Request is too large." }, 413);
    }

    body = JSON.parse(raw);
  } catch {
    return json({ success: false, error: "Invalid JSON." }, 400);
  }

  if (!body || typeof body.id !== "string" || !body.id.trim()) {
    return json({ success: false, error: "Listing ID is required." }, 400);
  }

  const id = body.id.trim();

  try {
    // Update only the listing status.
    if (
      typeof body.status === "string" &&
      ["pending", "published", "removed"].includes(body.status) &&
      Object.keys(body).every(key => ["id", "status"].includes(key))
    ) {
      const result = await env.DB.prepare(`
        UPDATE marketplace_listings
        SET status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(body.status, id).run();

      if (!result.meta.changes) {
        return json({ success: false, error: "Listing not found." }, 404);
      }

      return json({
        success: true,
        message: "Listing status updated."
      });
    }

    // Edit listing details.
    const problem = validateListing(body);

    if (problem) {
      return json({ success: false, error: problem }, 400);
    }

    const result = await env.DB.prepare(`
      UPDATE marketplace_listings SET
        seller_name = ?,
        seller_phone = ?,
        item_name = ?,
        category = ?,
        price_ghs = ?,
        location = ?,
        description = ?,
        image_1 = ?,
        image_2 = ?,
        image_3 = ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(
      clean(body.seller_name, 100),
      clean(body.seller_phone, 30),
      clean(body.item_name, 200),
      clean(body.category, 100),
      body.price_ghs,
      clean(body.location, 100),
      clean(body.description, 5000),
      clean(body.image_1, 2000) || null,
      clean(body.image_2, 2000) || null,
      clean(body.image_3, 2000) || null,
      id
    ).run();

    if (!result.meta.changes) {
      return json({ success: false, error: "Listing not found." }, 404);
    }

    return json({
      success: true,
      message: "Listing updated."
    });
  } catch {
    return json({
      success: false,
      error: "Unable to update the listing."
    }, 500);
  }
}

export async function onRequestDelete({ request, env }) {
  const denied = requireAdmin(request, env);
  if (denied) return denied;

  let body;

  try {
    body = await request.json();
  } catch {
    return json({ success: false, error: "Invalid JSON." }, 400);
  }

  if (!body || typeof body.id !== "string" || !body.id.trim()) {
    return json({ success: false, error: "Listing ID is required." }, 400);
  }

  try {
    const result = await env.DB.prepare(
      "DELETE FROM marketplace_listings WHERE id = ?"
    ).bind(body.id.trim()).run();

    if (!result.meta.changes) {
      return json({ success: false, error: "Listing not found." }, 404);
    }

    return json({
      success: true,
      message: "Listing deleted."
    });
  } catch {
    return json({
      success: false,
      error: "Unable to delete the listing."
    }, 500);
  }
}
