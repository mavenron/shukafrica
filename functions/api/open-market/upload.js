
const SESSION_COOKIE = "shuk_open_market_session";
const MEDIA_BASE_URL = "https://market-media.shukafrica.com";

const MAX_IMAGE_SIZE = 5 * 1024 * 1024;
const MAX_VIDEO_SIZE = 10 * 1024 * 1024;

const IMAGE_TYPES = {
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/webp": "webp"
};

const VIDEO_TYPES = {
  "video/mp4": "mp4",
  "video/webm": "webm",
  "video/quicktime": "mov"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";

  for (const part of cookie.split(";")) {
    const index = part.indexOf("=");

    if (index < 0) continue;

    if (part.slice(0, index).trim() === name) {
      return part.slice(index + 1).trim();
    }
  }

  return null;
}

function base64UrlToBytes(value) {
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded =
    base64 + "=".repeat((4 - base64.length % 4) % 4);

  const binary = atob(padded);

  return Uint8Array.from(
    binary,
    character => character.charCodeAt(0)
  );
}

async function verifySession(request, secret) {
  try {
    if (!secret) return null;

    const token = getCookie(request, SESSION_COOKIE);

    if (!token) return null;

    const parts = token.split(".");

    if (parts.length !== 2) return null;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlToBytes(parts[1]),
      new TextEncoder().encode(parts[0])
    );

    if (!valid) return null;

    const payload = JSON.parse(
      new TextDecoder().decode(
        base64UrlToBytes(parts[0])
      )
    );

    if (
      !payload.sub ||
      !payload.exp ||
      payload.exp <= Math.floor(Date.now() / 1000)
    ) {
      return null;
    }

    return payload.sub;
  } catch (error) {
    console.error("Upload session verification failed:", error);
    return null;
  }
}

async function getSeller(request, env) {
  const sellerId = await verifySession(
    request,
    env.OPEN_MARKET_SESSION_SECRET
  );

  if (!sellerId || !env.OPEN_MARKET_DB) return null;

  return await env.OPEN_MARKET_DB.prepare(
    "SELECT id FROM open_market_users WHERE id = ?"
  ).bind(sellerId).first();
}

function hasImageSignature(bytes, type) {
  if (type === "image/jpeg") {
    return (
      bytes.length >= 3 &&
      bytes[0] === 0xFF &&
      bytes[1] === 0xD8 &&
      bytes[2] === 0xFF
    );
  }

  if (type === "image/png") {
    return (
      bytes.length >= 8 &&
      bytes[0] === 0x89 &&
      bytes[1] === 0x50 &&
      bytes[2] === 0x4E &&
      bytes[3] === 0x47 &&
      bytes[4] === 0x0D &&
      bytes[5] === 0x0A &&
      bytes[6] === 0x1A &&
      bytes[7] === 0x0A
    );
  }

  if (type === "image/webp") {
    return (
      bytes.length >= 12 &&
      String.fromCharCode(...bytes.slice(0, 4)) === "RIFF" &&
      String.fromCharCode(...bytes.slice(8, 12)) === "WEBP"
    );
  }

  return false;
}

function hasVideoSignature(bytes, type) {
  if (type === "video/mp4" || type === "video/quicktime") {
    return (
      bytes.length >= 12 &&
      String.fromCharCode(...bytes.slice(4, 8)) === "ftyp"
    );
  }

  if (type === "video/webm") {
    return (
      bytes.length >= 4 &&
      bytes[0] === 0x1A &&
      bytes[1] === 0x45 &&
      bytes[2] === 0xDF &&
      bytes[3] === 0xA3
    );
  }

  return false;
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.OPEN_MARKET_DB || !env.OPEN_MARKET_MEDIA) {
      return json({
        success: false,
        error: "Open Market storage is not configured."
      }, 500);
    }

    const seller = await getSeller(request, env);

    if (!seller) {
      return json({
        success: false,
        error: "Please log in to your seller account."
      }, 401);
    }

    const type = (request.headers.get("Content-Type") || "")
      .split(";")[0]
      .trim()
      .toLowerCase();

    const kind = (
      request.headers.get("X-Upload-Kind") || ""
    ).trim().toLowerCase();

    const isImage = kind === "image";
    const isVideo = kind === "video";

    if (!isImage && !isVideo) {
      return json({
        success: false,
        error: "Invalid upload type."
      }, 400);
    }

    const allowedTypes = isImage ? IMAGE_TYPES : VIDEO_TYPES;
    const maxSize = isImage ? MAX_IMAGE_SIZE : MAX_VIDEO_SIZE;

    if (!Object.prototype.hasOwnProperty.call(allowedTypes, type)) {
      return json({
        success: false,
        error: isImage
          ? "Photo must be JPG, PNG, or WebP."
          : "Video must be MP4, WebM, or MOV."
      }, 400);
    }

    const declaredLength = Number(
      request.headers.get("Content-Length") || 0
    );

    if (declaredLength > maxSize) {
      return json({
        success: false,
        error: `File exceeds the ${isImage ? "5 MB" : "10 MB"} limit.`
      }, 413);
    }

    const bytes = new Uint8Array(await request.arrayBuffer());

    if (!bytes.length) {
      return json({
        success: false,
        error: "No file was received."
      }, 400);
    }

    if (bytes.length > maxSize) {
      return json({
        success: false,
        error: `File exceeds the ${isImage ? "5 MB" : "10 MB"} limit.`
      }, 413);
    }

    const validSignature = isImage
      ? hasImageSignature(bytes, type)
      : hasVideoSignature(bytes, type);

    if (!validSignature) {
      return json({
        success: false,
        error: "The file content does not match its file type."
      }, 400);
    }

    const extension = allowedTypes[type];
    const id = crypto.randomUUID();

    const key = `open-market/${seller.id}/${id}.${extension}`;

    await env.OPEN_MARKET_MEDIA.put(key, bytes, {
      httpMetadata: {
        contentType: type,
        cacheControl: "public, max-age=31536000"
      }
    });

    return json({
      success: true,
      message: "File uploaded successfully.",
      key,
      url: `${MEDIA_BASE_URL}/${key}`,
      type: kind,
      content_type: type
    }, 201);

  } catch (error) {
    console.error("Open Market upload error:", error);

    return json({
      success: false,
      error: "Unable to upload file.",
      diagnostic: String(error?.message || error)
    }, 500);
  }
      }
        
