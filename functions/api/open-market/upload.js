
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
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
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
      new TextDecoder().decode(base64UrlToBytes(parts[0]))
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
    console.error("Open Market upload session error:", error);
    return null;
  }
}

function detectFileType(bytes) {
  // JPEG
  if (
    bytes.length >= 3 &&
    bytes[0] === 0xff &&
    bytes[1] === 0xd8 &&
    bytes[2] === 0xff
  ) {
    return "image/jpeg";
  }

  // PNG
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
  ) {
    return "image/png";
  }

  // WebP
  if (
    bytes.length >= 12 &&
    String.fromCharCode(...bytes.slice(0, 4)) === "RIFF" &&
    String.fromCharCode(...bytes.slice(8, 12)) === "WEBP"
  ) {
    return "image/webp";
  }

  // WebM
  if (
    bytes.length >= 4 &&
    bytes[0] === 0x1a &&
    bytes[1] === 0x45 &&
    bytes[2] === 0xdf &&
    bytes[3] === 0xa3
  ) {
    return "video/webm";
  }

  // MP4 and QuickTime MOV
  if (
    bytes.length >= 12 &&
    String.fromCharCode(...bytes.slice(4, 8)) === "ftyp"
  ) {
    const brand = String.fromCharCode(...bytes.slice(8, 12));

    return brand === "qt  "
      ? "video/quicktime"
      : "video/mp4";
  }

  return null;
}

/*
 * POST /api/open-market/upload
 *
 * Required headers:
 * Content-Type: actual file MIME type
 * X-Upload-Kind: photo or video
 * X-Listing-ID: UUID for the listing
 * X-Image-Slot: 1, 2 or 3 (photos only)
 *
 * Request body: raw file bytes, not FormData.
 */
export async function onRequestPost({ request, env }) {
  try {
    if (!env.OPEN_MARKET_DB || !env.OPEN_MARKET_MEDIA) {
      return json({
        success: false,
        error: "Open Market database or media storage is not configured."
      }, 500);
    }

    const sellerId = await verifySession(
      request,
      env.OPEN_MARKET_SESSION_SECRET
    );

    if (!sellerId) {
      return json({
        success: false,
        error: "Please log in again before uploading media."
      }, 401);
    }

    const seller = await env.OPEN_MARKET_DB.prepare(
      "SELECT id FROM open_market_users WHERE id = ? LIMIT 1"
    ).bind(sellerId).first();

    if (!seller) {
      return json({
        success: false,
        error: "Your seller account could not be verified."
      }, 401);
    }

    const kind = request.headers.get("X-Upload-Kind");
    const contentType = (request.headers.get("Content-Type") || "")
      .split(";")[0]
      .trim()
      .toLowerCase();

    const listingId = request.headers.get("X-Listing-ID") || "";
    const imageSlot = request.headers.get("X-Image-Slot") || "";

    const uuidPattern =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

    if (!uuidPattern.test(listingId)) {
      return json({
        success: false,
        error: "A valid listing ID is required."
      }, 400);
    }

    if (kind !== "photo" && kind !== "video") {
      return json({
        success: false,
        error: "Upload kind must be photo or video."
      }, 400);
    }

    const allowedTypes = kind === "photo"
      ? IMAGE_TYPES
      : VIDEO_TYPES;

    const maxSize = kind === "photo"
      ? MAX_IMAGE_SIZE
      : MAX_VIDEO_SIZE;

    if (!Object.prototype.hasOwnProperty.call(
      allowedTypes,
      contentType
    )) {
      return json({
        success: false,
        error: kind === "photo"
          ? "Photo must be JPG, PNG or WebP."
          : "Video must be MP4, WebM or MOV."
      }, 400);
    }

    let slot = null;

    if (kind === "photo") {
      if (!["1", "2", "3"].includes(imageSlot)) {
        return json({
          success: false,
          error: "Photo slot must be 1, 2 or 3."
        }, 400);
      }

      slot = Number(imageSlot);
    }

    const declaredLength = request.headers.get("Content-Length");

    if (declaredLength !== null) {
      const length = Number(declaredLength);

      if (!Number.isFinite(length) || length <= 0 || length > maxSize) {
        return json({
          success: false,
          error: `File exceeds the ${kind === "photo" ? "5 MB" : "10 MB"} limit or is empty.`
        }, 400);
      }
    }

    if (!request.body) {
      return json({
        success: false,
        error: "No file was received."
      }, 400);
    }

    const buffer = await request.arrayBuffer();
    const size = buffer.byteLength;

    if (size === 0) {
      return json({
        success: false,
        error: "The uploaded file is empty."
      }, 400);
    }

    if (size > maxSize) {
      return json({
        success: false,
        error: `File exceeds the ${kind === "photo" ? "5 MB" : "10 MB"} limit.`
      }, 400);
    }

    const bytes = new Uint8Array(buffer);
    const detectedType = detectFileType(bytes);

    if (detectedType !== contentType) {
      return json({
        success: false,
        error: "The file content does not match its declared file type."
      }, 400);
    }

    const extension = allowedTypes[contentType];
    const uniquePart = crypto.randomUUID();

    const filename = kind === "photo"
      ? `image-${slot}-${uniquePart}.${extension}`
      : `video-${uniquePart}.${extension}`;

    const objectKey =
      `open-market/${seller.id}/${listingId}/${filename}`;

    await env.OPEN_MARKET_MEDIA.put(objectKey, bytes, {
      httpMetadata: {
        contentType
      },
      customMetadata: {
        sellerId: String(seller.id),
        listingId,
        kind
      }
    });

    return json({
      success: true,
      message: "Media uploaded successfully.",
      kind,
      key: objectKey,
      url: `${MEDIA_BASE_URL}/${objectKey}`,
      size
    }, 201);

  } catch (error) {
    console.error("Open Market media upload error:", error);

    return json({
      success: false,
      error: "Unable to upload the media file."
    }, 500);
  }
}

