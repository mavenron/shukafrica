
const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

const PHOTO_LIMIT = 4 * 1024 * 1024;
const VIDEO_LIMIT = 10 * 1024 * 1024;

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

function detectFileType(bytes) {
  if (
    bytes.length >= 3 &&
    bytes[0] === 0xff &&
    bytes[1] === 0xd8 &&
    bytes[2] === 0xff
  ) return { type: "image/jpeg", ext: "jpg", kind: "photo" };

  if (
    bytes.length >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47 &&
    bytes[4] === 0x0d &&
    bytes[5] === 0x0a &&
    bytes[6] === 0x1a &&
    bytes[7] === 0x0a
  ) return { type: "image/png", ext: "png", kind: "photo" };

  if (
    bytes.length >= 12 &&
    String.fromCharCode(...bytes.slice(0, 4)) === "RIFF" &&
    String.fromCharCode(...bytes.slice(8, 12)) === "WEBP"
  ) return { type: "image/webp", ext: "webp", kind: "photo" };

  if (
    bytes.length >= 12 &&
    String.fromCharCode(...bytes.slice(4, 8)) === "ftyp"
  ) {
    const brand = String.fromCharCode(...bytes.slice(8, 12));

    if (["isom", "iso2", "mp41", "mp42", "avc1", "M4V ", "qt  "].includes(brand)) {
      return { type: "video/mp4", ext: "mp4", kind: "video" };
    }

    if (brand === "M4V ") {
      return { type: "video/mp4", ext: "mp4", kind: "video" };
    }
  }

  if (
    bytes.length >= 12 &&
    String.fromCharCode(...bytes.slice(0, 4)) === "RIFF" &&
    String.fromCharCode(...bytes.slice(8, 12)) === "AVI "
  ) return { type: "video/x-msvideo", ext: "avi", kind: "video" };

  if (
    bytes.length >= 4 &&
    bytes[0] === 0x1a &&
    bytes[1] === 0x45 &&
    bytes[2] === 0xdf &&
    bytes[3] === 0xa3
  ) return { type: "video/webm", ext: "webm", kind: "video" };

  return null;
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

  if (!env.DB || !env.RENTAL_MEDIA) {
    return json({
      error: "Rentals storage is not configured."
    }, 503, origin);
  }

  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().startsWith("multipart/form-data;")) {
    return json({
      error: "Upload must use multipart/form-data."
    }, 415, origin);
  }

  const length = Number(request.headers.get("Content-Length") || 0);

  if (length > VIDEO_LIMIT + 1024 * 1024) {
    return json({ error: "Upload exceeds the size limit." }, 413, origin);
  }

  try {
    const owner = await getOwner(request, env);

    if (!owner) {
      return json({
        error: "Please log in to upload rental media."
      }, 401, origin);
    }

    const form = await request.formData();
    const file = form.get("file");
    const kind = form.get("kind");

    if (!(file instanceof File)) {
      return json({ error: "Select a file to upload." }, 400, origin);
    }

    if (!["photo", "video"].includes(kind)) {
      return json({
        error: "Choose photo or video as the upload type."
      }, 400, origin);
    }

    if (file.size === 0) {
      return json({ error: "The selected file is empty." }, 400, origin);
    }

    const limit = kind === "photo" ? PHOTO_LIMIT : VIDEO_LIMIT;

    if (file.size > limit) {
      return json({
        error: kind === "photo"
          ? "Each photo must be 4 MB or smaller."
          : "The video must be 10 MB or smaller."
      }, 413, origin);
    }

    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const detected = detectFileType(bytes);

    if (!detected || detected.kind !== kind) {
      return json({
        error: "Unsupported file format or file contents."
      }, 415, origin);
    }

    const key = `rentals/${owner.id}/${crypto.randomUUID()}.${detected.ext}`;

    await env.RENTAL_MEDIA.put(key, buffer, {
      httpMetadata: {
        contentType: detected.type,
        cacheControl: "private, max-age=0, no-store"
      },
      customMetadata: {
        ownerId: owner.id,
        uploadKind: kind
      }
    });

    return json({
      success: true,
      key,
      kind,
      contentType: detected.type,
      size: file.size
    }, 201, origin);

  } catch (error) {
    console.error("Rental media upload failed:", error);

    return json({
      error: "Upload failed. Please try again."
    }, 500, origin);
  }
}
  
