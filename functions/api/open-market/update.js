
const SESSION_COOKIE = "shuk_open_market_session";
const MEDIA_BASE_URL = "https://market-media.shukafrica.com";

const MAX_IMAGES = 3;
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

const CATEGORIES = ["shop", "store", "home-service", "jobs"];

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function clean(value, maxLength = 2000) {
  return String(value ?? "").trim().slice(0, maxLength);
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
    console.error("Open Market session verification failed:", error);
    return null;
  }
}

async function getOwnedListing(env, listingId, sellerId) {
  return env.OPEN_MARKET_DB.prepare(`
    SELECT
      id, seller_id, image_1, image_2, image_3,
      image_4, image_5, video_url
    FROM open_market_listings
    WHERE id = ? AND seller_id = ?
    LIMIT 1
  `).bind(listingId, sellerId).first();
}

function isFile(value) {
  return value &&
    typeof value === "object" &&
    typeof value.name === "string" &&
    typeof value.size === "number" &&
    typeof value.arrayBuffer === "function";
}

function mediaUrl(key) {
  return `${MEDIA_BASE_URL}/${key}`;
}

function getMediaKey(value, sellerId, listingId) {
  if (!value || typeof value !== "string") return null;

  try {
    const url = new URL(value);
    const prefix = `/open-market/${sellerId}/${listingId}/`;

    if (!url.pathname.startsWith(prefix)) return null;

    return url.pathname.slice(1);
  } catch {
    return null;
  }
}

async function deleteMedia(env, values, sellerId, listingId) {
  if (!env.OPEN_MARKET_MEDIA) return;

  const keys = [
    ...new Set(
      values
        .map(value => getMediaKey(value, sellerId, listingId))
        .filter(Boolean)
    )
  ];

  for (const key of keys) {
    try {
      await env.OPEN_MARKET_MEDIA.delete(key);
    } catch (error) {
      console.error("Open Market media cleanup failed:", error);
    }
  }
}

/*
 * POST /api/open-market/update
 * Updates an existing listing owned by the logged-in seller.
 */
export async function onRequestPost({ request, env }) {
  const newlyUploadedKeys = [];

  try {
    if 
