
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

    const form = await request.formData();

    const id = clean(form.get("id"), 100);

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

    const category = clean(form.get("category"), 40).toLowerCase();
    const title = clean(form.get("title"), 180);
    const sellerName = clean(form.get("seller_name"), 120);
    const contact = clean(form.get("contact"), 60);
    const price = clean(form.get("price"), 100);
    const location = clean(form.get("location"), 150);
    const country = clean(form.get("country"), 100);
    const region = clean(form.get("region"), 100);
    const description = clean(form.get("description"), 5000);
    const delivery = clean(form.get("delivery"), 100);
    let jobType = clean(form.get("job_type"), 40).toLowerCase();

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
      const allowed = [
        "full-time",
        "part-time",
        "contract",
        "temporary",
        "other"
      ];

      if (!allowed.includes(jobType)) {
        return json({
          success: false,
          error: "Please select a valid job type."
        }, 400);
      }
    } else {
      jobType = null;
    }

    const selectedImages = form.getAll("images").filter(
      file => isFile(file) && file.size > 0
    );

    if (selectedImages.length > MAX_IMAGES) {
      return json({
        success: false,
        error: `You can upload a maximum of ${MAX_IMAGES} photos.`
      }, 400);
    }

    for (let i = 0; i < selectedImages.length; i++) {
      const file = selectedImages[i];

      if (!Object.prototype.hasOwnProperty.call(IMAGE_TYPES, file.type)) {
        return json({
          success: false,
          error: `Photo ${i + 1} must be JPG, PNG, or WebP.`
        }, 400);
      }

      if (file.size > MAX_IMAGE_SIZE) {
        return json({
          success: false,
          error: `Photo ${i + 1} exceeds the 5 MB limit.`
        }, 400);
      }
    }

    const videoFile = form.get("video");
    let video = null;

    if (isFile(videoFile) && videoFile.size > 0) {
      if (!Object.prototype.hasOwnProperty.call(VIDEO_TYPES, videoFile.type)) {
        return json({
          success: false,
          error: "Video must be MP4, WebM, or MOV."
        }, 400);
      }

      if (videoFile.size > MAX_VIDEO_SIZE) {
        return json({
          success: false,
          error: "Video exceeds the 10 MB limit."
        }, 400);
      }

      video = videoFile;
    }

    // Preserve existing media unless replacements are uploaded.
    const imageUrls = [
      existing.image_1 || "",
      existing.image_2 || "",
      existing.image_3 || ""
    ];

    let videoUrl = existing.video_url || "";
    const replacedMedia = [];

    for (let i = 0; i < selectedImages.length; i++) {
      const file = selectedImages[i];
      const extension = IMAGE_TYPES[file.type];
      const key = `open-market/${sellerId}/${id}/image-${i + 1}-${crypto.randomUUID()}.${extension}`;

      await env.OPEN_MARKET_MEDIA.put(key, file.stream(), {
        httpMetadata: { contentType: file.type }
      });

      newlyUploadedKeys.push(key);

      replacedMedia.push(imageUrls[i]);
      imageUrls[i] = mediaUrl(key);
    }

    if (video) {
      const extension = VIDEO_TYPES[video.type];
      const key = `open-market/${sellerId}/${id}/video-${crypto.randomUUID()}.${extension}`;

      await env.OPEN_MARKET_MEDIA.put(key, video.stream(), {
        httpMetadata: { contentType: video.type }
      });

      newlyUploadedKeys.push(key);
      replacedMedia.push(videoUrl);
      videoUrl = mediaUrl(key);
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

    // Remove only old media replaced during this update.
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

    // Clean up new uploads if the update fails.
    if (env.OPEN_MARKET_MEDIA) {
      for (const key of newlyUploadedKeys) {
        try {
          await env.OPEN_MARKET_MEDIA.delete(key);
        } catch (cleanupError) {
          console.error("Open Market upload cleanup failed:", cleanupError);
        }
      }
    }

    return json({
      success: false,
      error: "Unable to update the listing.",
      diagnostic: String(error?.message || error)
    }, 500);
  }
}
