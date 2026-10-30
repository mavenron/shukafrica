
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
        error: "Please log in again before editing a listing."
      }, 401);
    }

    // The dashboard now sends JSON, not multipart form data.
    const data = await request.json();

    const id = clean(data.id, 100);

    if (!id) {
      return json({
        success: false,
        error: "The listing ID is required."
      }, 400);
    }

    const existing = await getOwnedListing(env, id, sellerId);

    if (!existing) {
      return json({
        success: false,
        error: "Listing not found, or it does not belong to your account."
      }, 404);
    }

    const category = clean(data.category, 40).toLowerCase();
    const title = clean(data.title, 180);
    const sellerName = clean(data.seller_name, 120);
    const contact = clean(data.contact, 60);
    const price = clean(data.price, 100);
    const location = clean(data.location, 150);
    const country = clean(data.country, 100);
    const region = clean(data.region, 100);
    const description = clean(data.description, 5000);
    const delivery = clean(data.delivery, 100);

    let jobType = clean(data.job_type, 40).toLowerCase();

    if (!CATEGORIES.includes(category)) {
      return json({
        success: false,
        error: "Please select a valid listing category."
      }, 400);
    }

    if (!title || !sellerName || !contact || !location || !description) {
      return json({
        success: false,
        error: "Please complete the title, seller name, contact, location, and description."
      }, 400);
    }

    if (category === "jobs") {
      const allowed = ["workers-needed", "seeking-work"];

      if (!allowed.includes(jobType)) {
        return json({
          success: false,
          error: "Please select a valid job type."
        }, 400);
      }
    } else {
      jobType = null;
    }

    // Only accept media uploaded to this seller's listing folder.
    function validMediaUrl(value) {
      if (typeof value !== "string" || !value.trim()) {
        return false;
      }

      try {
        const url = new URL(value);
        const expectedPrefix =
          `/open-market/${sellerId}/${id}/`;

        return (
          url.origin === MEDIA_BASE_URL &&
          url.pathname.startsWith(expectedPrefix)
        );
      } catch {
        return false;
      }
    }

    // Start with the existing photos.
    const imageUrls = [
      existing.image_1 || "",
      existing.image_2 || "",
      existing.image_3 || ""
    ];

    const replacedMedia = [];

    // Replace photos only when new photo URLs are supplied.
    if (Object.prototype.hasOwnProperty.call(data, "images")) {
      if (!Array.isArray(data.images) || data.images.length > MAX_IMAGES) {
        return json({
          success: false,
          error: "Invalid photo upload information."
        }, 400);
      }

      for (let i = 0; i < data.images.length; i++) {
        const newUrl = data.images[i];

        if (!validMediaUrl(newUrl)) {
          return json({
            success: false,
            error: `Photo ${i + 1} has an invalid media URL.`
          }, 400);
        }

        replacedMedia.push(imageUrls[i]);
        imageUrls[i] = newUrl;
      }
    }

    // Preserve the existing video unless a new value is supplied.
    let videoUrl = existing.video_url || "";

    if (Object.prototype.hasOwnProperty.call(data, "video_url")) {
      if (data.video_url === "") {
        replacedMedia.push(videoUrl);
        videoUrl = "";
      } else if (validMediaUrl(data.video_url)) {
        replacedMedia.push(videoUrl);
        videoUrl = data.video_url;
      } else {
        return json({
          success: false,
          error: "The video has an invalid media URL."
        }, 400);
      }
    }

    await env.OPEN_MARKET_DB.prepare(`
      UPDATE open_market_listings
      SET
        category = ?,
        job_type = ?,
        title = ?,
        seller_name = ?,
        contact = ?,
        price = ?,
        location = ?,
        country = ?,
        region = ?,
        description = ?,
        delivery = ?,
        image_1 = ?,
        image_2 = ?,
        image_3 = ?,
        image_4 = '',
        image_5 = '',
        video_url = ?
      WHERE id = ? AND seller_id = ?
    `).bind(
      category,
      jobType,
      title,
      sellerName,
      contact,
      price,
      location,
      country,
      region,
      description,
      delivery,
      imageUrls[0],
      imageUrls[1],
      imageUrls[2],
      videoUrl,
      id,
      sellerId
    ).run();

    // Delete old media only after the database update succeeds.
    await deleteMedia(env, replacedMedia, sellerId, id);

    return json({
      success: true,
      message: "Listing updated successfully.",
      listing: {
        id,
        category,
        job_type: jobType,
        title,
        seller_name: sellerName,
        contact,
        price,
        location,
        country,
        region,
        description,
        delivery,
        image_1: imageUrls[0],
        image_2: imageUrls[1],
        image_3: imageUrls[2],
        image_4: "",
        image_5: "",
        video_url: videoUrl,
        status: "published"
      }
    });

  } catch (error) {
    console.error("Open Market listing update error:", error);

    return json({
      success: false,
      error: "Unable to update the listing.",
      diagnostic: String(error?.message || error)
    }, 500);
  }
}

