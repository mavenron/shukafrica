
const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

const MAX_BODY_SIZE = 20 * 1024;

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

function cleanText(value, maxLength) {
  if (typeof value !== "string") return null;

  const cleaned = value.trim();

  if (!cleaned || cleaned.length > maxLength) return null;

  return cleaned;
}

function optionalText(value, maxLength) {
  if (value === undefined || value === null || value === "") {
    return "";
  }

  if (typeof value !== "string") return null;

  const cleaned = value.trim();

  return cleaned.length <= maxLength ? cleaned : null;
}

function validMediaKey(value, ownerId, required = false) {
  if (value === undefined || value === null || value === "") {
    return required ? null : "";
  }

  if (typeof value !== "string" || value.length > 500) {
    return null;
  }

  // Media keys must belong to this owner's Rentals folder.
  const prefix = `rentals/${ownerId}/`;

  if (!value.startsWith(prefix)) return null;
  if (value.includes("..") || value.includes("\\") || value.includes("?")) {
    return null;
  }

  return value;
}

async function getOwner(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(
    /(?:^|;\s*)shuk_rental_session=([^;]+)/
  );

  const token = match ? match[1] : "";

  if (!token || token.length > 200) return null;

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
    return null;
  }

  const owner = await env.DB.prepare(`
    SELECT id
    FROM rental_owners
    WHERE id = ?
    LIMIT 1
  `).bind(session.owner_id).first();

  return owner || null;
}

async function readBody(request) {
  const contentLength = Number(
    request.headers.get("Content-Length") || 0
  );

  if (contentLength > MAX_BODY_SIZE) {
    throw new Error("BODY_TOO_LARGE");
  }

  const text = await request.text();

  if (new TextEncoder().encode(text).length > MAX_BODY_SIZE) {
    throw new Error("BODY_TOO_LARGE");
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new Error("INVALID_JSON");
  }
}

function getListingFields(body, ownerId, partial = false) {
  const fields = {};
  const textFields = {
    title: 120,
    description: 5000,
    price: 100,
    location: 200,
    contact: 200,
    condition: 100,
    terms: 3000
  };

  for (const [field, maxLength] of Object.entries(textFields)) {
    if (partial && !(field in body)) continue;

    const value = field === "condition" || field === "terms"
      ? optionalText(body[field], maxLength)
      : cleanText(body[field], maxLength);

    if (value === null) {
      throw new Error(`INVALID_${field.toUpperCase()}`);
    }

    fields[field] = value;
  }

  if (!partial || "availability" in body) {
    const availability = body.availability === undefined
      ? "Available"
      : body.availability;

    if (!["Available", "Not Available"].includes(availability)) {
      throw new Error("INVALID_AVAILABILITY");
    }

    fields.availability = availability;
  }

  for (const [field, required] of [
    ["image_1", true],
    ["image_2", false],
    ["image_3", false],
    ["video_key", false]
  ]) {
    if (partial && !(field in body)) continue;

    const key = validMediaKey(body[field], ownerId, required);

    if (key === null) {
      throw new Error(`INVALID_${field.toUpperCase()}`);
    }

    fields[field] = key || null;
  }

  return fields;
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
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Max-Age": "86400",
        "Vary": "Origin"
      }
    });
  }

  if (request.method !== "POST") {
    return json({ error: "Method not allowed." }, 405, origin);
  }

  if (!env.DB) {
    return json({ error: "Database unavailable." }, 503, origin);
  }

  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return json({ error: "Origin not allowed." }, 403);
  }

  if (
    request.headers.get("Content-Type")?.split(";")[0].trim()
      !== "application/json"
  ) {
    return json({ error: "Send JSON data." }, 415, origin);
  }

  try {
    const owner = await getOwner(request, env);

    if (!owner) {
      return json({ error: "Please log in to manage your rentals." }, 401, origin);
    }

    const body = await readBody(request);

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return json({ error: "Invalid request body." }, 400, origin);
    }

    if (body.action === "create") {
      const fields = getListingFields(body, owner.id);

      const id = crypto.randomUUID();

      await env.DB.prepare(`
        INSERT INTO rentals (
          id, owner_id, title, description, price,
          availability, condition, terms, location, contact,
          image_1, image_2, image_3, video_key, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'published')
      `).bind(
        id,
        owner.id,
        fields.title,
        fields.description,
        fields.price,
        fields.availability,
        fields.condition,
        fields.terms,
        fields.location,
        fields.contact,
        fields.image_1,
        fields.image_2,
        fields.image_3,
        fields.video_key
      ).run();

      return json({
        success: true,
        message: "Rental listing created.",
        id
      }, 201, origin);
    }

    if (body.action === "update") {
      const id = cleanText(body.id, 100);

      if (!id) {
        return json({ error: "Valid listing ID required." }, 400, origin);
      }

      const existing = await env.DB.prepare(`
        SELECT id FROM rentals
        WHERE id = ? AND owner_id = ? AND status = 'published'
        LIMIT 1
      `).bind(id, owner.id).first();

      if (!existing) {
        return json({ error: "Listing not found." }, 404, origin);
      }

      const fields = getListingFields(body, owner.id, true);
      const allowed = [
        "title", "description", "price", "availability",
        "condition", "terms", "location", "contact",
        "image_1", "image_2", "image_3", "video_key"
      ];

      const entries = Object.entries(fields).filter(
        ([key]) => allowed.includes(key)
      );

      if (entries.length === 0) {
        return json({ error: "No listing changes supplied." }, 400, origin);
      }

      const setClause = entries
        .map(([key]) => `${key} = ?`)
        .join(", ");

      const values = entries.map(([, value]) => value);

      await env.DB.prepare(`
        UPDATE rentals
        SET ${setClause}, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND owner_id = ? AND status = 'published'
      `).bind(...values, id, owner.id).run();

      return json({
        success: true,
        message: "Rental listing updated."
      }, 200, origin);
    }

    if (body.action === "delete") {
      const id = cleanText(body.id, 100);

      if (!id) {
        return json({ error: "Valid listing ID required." }, 400, origin);
      }

      const result = await env.DB.prepare(`
        UPDATE rentals
        SET status = 'removed', updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND owner_id = ? AND status = 'published'
      `).bind(id, owner.id).run();

      if (!result.meta || result.meta.changes === 0) {
        return json({ error: "Listing not found." }, 404, origin);
      }

      return json({
        success: true,
        message: "Rental listing removed."
      }, 200, origin);
    }

    return json({
      error: "Action must be create, update, or delete."
    }, 400, origin);

  } catch (error) {
    if (error.message === "BODY_TOO_LARGE") {
      return json({ error: "Request is too large." }, 413, origin);
    }

    if (error.message === "INVALID_JSON") {
      return json({ error: "Invalid JSON." }, 400, origin);
    }

    if (error.message.startsWith("INVALID_")) {
      return json({
        error: `Invalid listing field: ${error.message.replace("INVALID_", "").toLowerCase()}.`
      }, 400, origin);
    }

    console.error("Rental management request failed:", error);

    return json({
      error: "Unable to manage this rental listing."
    }, 500, origin);
  }
    }
