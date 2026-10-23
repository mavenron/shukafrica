
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

function validMediaKey(value, ownerId, field, required = false) {
  if (value === undefined || value === null || value === "") {
    return required ? null : "";
  }

  if (typeof value !== "string" || value.length > 200) return null;

  const prefix = `rentals/${ownerId}/`;
  if (!value.startsWith(prefix)) return null;

  const filename = value.slice(prefix.length);
  const match = filename.match(
    /^([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\.(jpg|png|webp|mp4|avi|webm)$/i
  );

  if (!match) return null;

  const extension = match[2].toLowerCase();
  const isVideo = field === "video_key";

  if (isVideo && !["mp4", "avi", "webm"].includes(extension)) {
    return null;
  }

  if (!isVideo && !["jpg", "png", "webp"].includes(extension)) {
    return null;
  }

  return value;
}

async function getOwner(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)shuk_rental_session=([^;]+)/);
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

  return await env.DB.prepare(`
    SELECT id
    FROM rental_owners
    WHERE id = ?
    LIMIT 1
  `).bind(session.owner_id).first();
}

async function readBody(request) {
  const contentLength = Number(request.headers.get("Content-Length") || 0);

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
    terms: 3000,
    instructions: 3000
  };

  for (const [field, maxLength] of Object.entries(textFields)) {
    if (partial && !Object.hasOwn(body, field)) continue;

    const isOptional = ["condition", "terms", "instructions"].includes(field);
    const value = isOptional
      ? optionalText(body[field], maxLength)
      : cleanText(body[field], maxLength);

    if (value === null) throw new Error(`INVALID_${field.toUpperCase()}`);
    fields[field] = value;
  }

  if (!partial || Object.hasOwn(body, "availability")) {
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
    if (partial && !Object.hasOwn(body, field)) continue;

    const key = validMediaKey(body[field], ownerId, field, required);

    if (key === null) throw new Error(`INVALID_${field.toUpperCase()}`);
    fields[field] = key || null;
  }

  const photoKeys = [
    fields.image_1,
    fields.image_2,
    fields.image_3
  ].filter(Boolean);

  if (new Set(photoKeys).size !== photoKeys.length) {
    throw new Error("INVALID_IMAGE_KEYS");
  }

  return fields;
}

async function verifyMedia(fields, env) {
  const mediaEntries = [
    ["image_1", "image"],
    ["image_2", "image"],
    ["image_3", "image"],
    ["video_key", "video"]
  ];

  const supplied = mediaEntries.filter(([field]) =>
    Object.hasOwn(fields, field) && fields[field]
  );

  if (supplied.length === 0) return;
  if (!env.RENTAL_MEDIA) throw new Error("RENTAL_MEDIA_UNAVAILABLE");

  for (const [field, kind] of supplied) {
    const object = await env.RENTAL_MEDIA.head(fields[field]);

    if (!object) throw new Error(`MISSING_MEDIA_${field.toUpperCase()}`);

    const contentType = (
      object.httpMetadata?.contentType || ""
    ).toLowerCase();

    if (kind === "image" && !contentType.startsWith("image/")) {
      throw new Error(`INVALID_MEDIA_${field.toUpperCase()}`);
    }

    if (kind === "video" && !contentType.startsWith("video/")) {
      throw new Error("INVALID_MEDIA_VIDEO_KEY");
    }
  }
}

// Delete media only if no other rental listing uses it.
async function deleteUnusedMedia(listing, env) {
  const keys = [...new Set([
    listing.image_1,
    listing.image_2,
    listing.image_3,
    listing.video_key
  ].filter(Boolean))];

  let deleted = 0;
  let failed = 0;

  for (const key of keys) {
    const reference = await env.DB.prepare(`
      SELECT id
      FROM rentals
      WHERE image_1 = ?
         OR image_2 = ?
         OR image_3 = ?
         OR video_key = ?
      LIMIT 1
    `).bind(key, key, key, key).first();

    if (reference) continue;

    try {
      await env.RENTAL_MEDIA.delete(key);
      deleted++;
    } catch (error) {
      console.error("Rental media deletion failed:", error);
      failed++;
    }
  }

  return { deleted, failed };
}

export async function onRequest({ request, env }) {
  const origin = request.headers.get("Origin") || "";

  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return json({ success: false, error: "Origin not allowed." }, 403);
  }

  if (request.method === "OPTIONS") {
    if (!ALLOWED_ORIGINS.has(origin)) {
      return new Response(null, { status: 403 });
    }

    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Max-Age": "86400",
        "Vary": "Origin"
      }
    });
  }

  if (!["GET", "POST"].includes(request.method)) {
    return json({ success: false, error: "Method not allowed." }, 405, origin);
  }

  if (!env.DB) {
    return json({ success: false, error: "Database unavailable." }, 503, origin);
  }

  try {
    const owner = await getOwner(request, env);

    if (!owner) {
      return json({
        success: false,
        error: "Please log in to manage your rentals."
      }, 401, origin);
    }

    if (request.method === "GET") {
      const result = await env.DB.prepare(`
        SELECT
          id, title, description, price, availability, condition,
          terms, instructions, location, contact, image_1, image_2,
          image_3, video_key, status, removed_at, created_at, updated_at
        FROM rentals
        WHERE owner_id = ?
          AND status IN ('published', 'removed')
        ORDER BY created_at DESC
        LIMIT 100
      `).bind(owner.id).all();

      return json({
        success: true,
        listings: result.results || []
      }, 200, origin);
    }

    if (
      (request.headers.get("Content-Type") || "")
        .split(";")[0].trim().toLowerCase() !== "application/json"
    ) {
      return json({ success: false, error: "Send JSON data." }, 415, origin);
    }

    const body = await readBody(request);

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return json({ success: false, error: "Invalid request body." }, 400, origin);
    }

    // CREATE
    if (body.action === "create") {
      const fields = getListingFields(body, owner.id);
      await verifyMedia(fields, env);

      const id = crypto.randomUUID();

      await env.DB.prepare(`
        INSERT INTO rentals (
          id, owner_id, title, description, price, availability,
          condition, terms, instructions, location, contact,
          image_1, image_2, image_3, video_key, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'published')
      `).bind(
        id, owner.id, fields.title, fields.description, fields.price,
        fields.availability, fields.condition, fields.terms,
        fields.instructions, fields.location, fields.contact,
        fields.image_1, fields.image_2, fields.image_3, fields.video_key
      ).run();

      return json({
        success: true,
        message: "Rental listing created.",
        id
      }, 201, origin);
    }

    // UPDATE — existing edit behavior retained.
    if (body.action === "update") {
      const id = cleanText(body.id, 100);

      if (!id) {
        return json({ success: false, error: "Valid listing ID required." }, 400, origin);
      }

      const existing = await env.DB.prepare(`
        SELECT id FROM rentals
        WHERE id = ? AND owner_id = ? AND status = 'published'
        LIMIT 1
      `).bind(id, owner.id).first();

      if (!existing) {
        return json({ success: false, error: "Listing not found." }, 404, origin);
      }

      const fields = getListingFields(body, owner.id, true);

      if (Object.keys(fields).length === 0) {
        return json({ success: false, error: "No listing changes supplied." }, 400, origin);
      }

      await verifyMedia(fields, env);

      const entries = Object.entries(fields);
      const setClause = entries.map(([key]) => `${key} = ?`).join(", ");
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

    // DELETE — permanently delete this owner's listing.
    if (body.action === "delete") {
      const id = cleanText(body.id, 100);

      if (!id) {
        return json({ success: false, error: "Valid listing ID required." }, 400, origin);
      }

      const listing = await env.DB.prepare(`
        SELECT id, image_1, image_2, image_3, video_key
        FROM rentals
        WHERE id = ? AND owner_id = ?
          AND status IN ('published', 'removed')
        LIMIT 1
      `).bind(id, owner.id).first();

      if (!listing) {
        return json({ success: false, error: "Listing not found." }, 404, origin);
      }

      const mediaKeys = [
        listing.image_1,
        listing.image_2,
        listing.image_3,
        listing.video_key
      ].filter(Boolean);

      if (mediaKeys.length && !env.RENTAL_MEDIA) {
        return json({
          success: false,
          error: "Rentals media storage is unavailable. The listing was not deleted."
        }, 503, origin);
      }

      const result = await env.DB.prepare(`
        DELETE FROM rentals
        WHERE id = ? AND owner_id = ?
          AND status IN ('published', 'removed')
      `).bind(id, owner.id).run();

      if (!result.meta || result.meta.changes === 0) {
        return json({ success: false, error: "Listing could not be deleted." }, 409, origin);
      }

      let mediaResult = { deleted: 0, failed: 0 };

      try {
        mediaResult = await deleteUnusedMedia(listing, env);
      } catch (error) {
        console.error("Rental media cleanup failed:", error);
        mediaResult.failed = new Set(mediaKeys).size;
      }

      return json({
        success: true,
        message: mediaResult.failed
          ? "Listing deleted, but some media files could not be removed."
          : "Rental listing permanently deleted.",
        mediaDeleted: mediaResult.deleted,
        mediaFailed: mediaResult.failed
      }, 200, origin);
    }

    return json({
      success: false,
      error: "Action must be create, update, or delete."
    }, 400, origin);

  } catch (error) {
    if (error.message === "BODY_TOO_LARGE") {
      return json({ success: false, error: "Request is too large." }, 413, origin);
    }

    if (error.message === "INVALID_JSON") {
      return json({ success: false, error: "Invalid JSON." }, 400, origin);
    }

    if (
      error.message.startsWith("INVALID_") ||
      error.message.startsWith("MISSING_MEDIA_")
    ) {
      return json({
        success: false,
        error: "One or more listing fields or media references are invalid, or an uploaded file is missing."
      }, 400, origin);
    }

    if (error.message === "RENTAL_MEDIA_UNAVAILABLE") {
      return json({
        success: false,
        error: "Rentals media storage is unavailable."
      }, 503, origin);
    }

    console.error("Rental management request failed:", error);

    return json({
      success: false,
      error: "Unable to manage this rental listing."
    }, 500, origin);
  }
}
