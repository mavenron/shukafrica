const SESSION_COOKIE = "shuk_open_market_session";
const MEDIA_BASE_URL = "https://market-media.shukafrica.com";

const MAX_LISTINGS = 5;
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

async function getSeller(request, env) {
  const sellerId = await verifySession(
    request,
    env.OPEN_MARKET_SESSION_SECRET
  );

  if (!sellerId || !env.OPEN_MARKET_DB) return null;

  return await env.OPEN_MARKET_DB.prepare(
    "SELECT id, full_name, email FROM open_market_users WHERE id = ?"
  ).bind(sellerId).first();
}

function normalizeJobType(value) {
  const jobType = clean(value, 40).toLowerCase();

  const allowed = [
    "workers-needed",
    "seeking-work"
  ];

  return allowed.includes(jobType) ? jobType : null;
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

async function removeUploaded(env, keys) {
  if (!env.OPEN_MARKET_MEDIA) return;

  await Promise.all(
    keys.map(async key => {
      try {
        await env.OPEN_MARKET_MEDIA.delete(key);
      } catch (error) {
        console.error("Open Market media cleanup failed:", error);
      }
    })
  );
}

/*
 * GET /api/open-market/listing
 * Returns published listings for the public marketplace.
 */
export async function onRequestGet({ request, env }) {
  try {
    if (!env.OPEN_MARKET_DB) {
      return json({
        success: false,
        error: "Open Market database is not configured."
      }, 500);
    }

    const url = new URL(request.url);
    const category = clean(url.searchParams.get("category"), 40);
    const search = clean(url.searchParams.get("search"), 150);
    const location = clean(url.searchParams.get("location"), 150);

    const requestedLimit = Number.parseInt(
      url.searchParams.get("limit") || "100",
      10
    );

    const limit = Number.isFinite(requestedLimit)
      ? Math.min(Math.max(requestedLimit, 1), 100)
      : 100;

    let sql = `
      SELECT
        id, category, job_type, title, seller_name, contact, price,
        location, country, region, description, delivery,
        image_1, image_2, image_3, image_4, image_5,
        video_url, status, created_at
      FROM open_market_listings
      WHERE status = 'published'
    `;

    const params = [];

    if (category && CATEGORIES.includes(category)) {
      sql += " AND category = ?";
      params.push(category);
    }

    if (search) {
      sql += `
        AND (
          title LIKE ?
          OR description LIKE ?
          OR seller_name LIKE ?
        )
      `;

      const term = `%${search}%`;
      params.push(term, term, term);
    }

    if (location) {
      sql += " AND location LIKE ?";
      params.push(`%${location}%`);
    }

    sql += " ORDER BY created_at DESC LIMIT ?";
    params.push(limit);

    const result = await env.OPEN_MARKET_DB.prepare(sql)
      .bind(...params)
      .all();

    return json({
      success: true,
      listings: result.results || []
    });
  } catch (error) {
    console.error("Open Market public listings error:", error);

    return json({
      success: false,
      error: "Unable to load Open Market listings."
    }, 500);
  }
}

/*
 * POST /api/open-market/listing
 * Publishes a listing directly without admin approval.
 */
export async function onRequestPost({ request, env }) {
  const uploadedKeys = [];

  try {
    if (!env.OPEN_MARKET_DB) {
      return json({
        success: false,
        error: "Open Market database is not configured."
      }, 500);
    }

    if (!env.OPEN_MARKET_MEDIA) {
      return json({
        success: false,
        error: "Open Market media storage is not configured."
      }, 500);
    }

    const seller = await getSeller(request, env);

    if (!seller) {
      return json({
        success: false,
        error: "Please log in to your Open Market seller account before publishing."
      }, 401);
    }

    const countResult = await env.OPEN_MARKET_DB.prepare(`
      SELECT COUNT(*) AS total
      FROM open_market_listings
      WHERE seller_id = ?
    `).bind(seller.id).first();

    if (Number(countResult?.total || 0) >= MAX_LISTINGS) {
      return json({
        success: false,
        error: `You can publish a maximum of ${MAX_LISTINGS} listings.`
      }, 400);
    }

    const form = await request.formData();

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
    let jobType = clean(form.get("job_type"), 40);

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
      jobType = normalizeJobType(jobType);

      if (!jobType) {
        return json({
          success: false,
          error: "Please select a valid job type."
        }, 400);
      }
    } else {
      jobType = null;
    }

    // The dashboard sends every selected photo under the same
    // FormData field name: "images".
    const selectedImages = form.getAll("images").filter(
      file => isFile(file) && file.size > 0
    );

    if (selectedImages.length > MAX_IMAGES) {
      return json({
        success: false,
        error: `You can upload a maximum of ${MAX_IMAGES} photos.`
      }, 400);
    }

    const imageFiles = [];

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

      imageFiles.push({
        file,
        slot: i + 1
      });
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

    const id = crypto.randomUUID();
    const imageUrls = ["", "", ""];
    let videoUrl = "";

    // Upload photos to R2 and save their public URLs.
    for (const item of imageFiles) {
      const extension = IMAGE_TYPES[item.file.type];
      const key =
        `open-market/${seller.id}/${id}/image-${item.slot}.${extension}`;

      await env.OPEN_MARKET_MEDIA.put(
        key,
        item.file.stream(),
        {
          httpMetadata: {
            contentType: item.file.type
          }
        }
      );

      uploadedKeys.push(key);
      imageUrls[item.slot - 1] = mediaUrl(key);
    }

    // Keep video upload support unchanged.
    if (video) {
      const extension = VIDEO_TYPES[video.type];
      const key = `open-market/${seller.id}/${id}/video.${extension}`;

      await env.OPEN_MARKET_MEDIA.put(
        key,
        video.stream(),
        {
          httpMetadata: {
            contentType: video.type
          }
        }
      );

      uploadedKeys.push(key);
      videoUrl = mediaUrl(key);
    }

    // Keep all five existing database columns.
    // Only the first three are used for uploaded photos.
    await env.OPEN_MARKET_DB.prepare(`
      INSERT INTO open_market_listings (
        id, category, job_type, title, seller_name, contact, price,
        location, country, region, description, delivery,
        image_1, image_2, image_3, image_4, image_5,
        video_url, status, seller_id, created_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?, 'published', ?, CURRENT_TIMESTAMP
      )
    `).bind(
      id,
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
      "",
      "",
      videoUrl,
      seller.id
    ).run();

    return json({
      success: true,
      message: "Listing published successfully.",
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
    }, 201);
  } catch (error) {
    console.error("Open Market publishing error:", error);

    await removeUploaded(env, uploadedKeys);

    return json({
      success: false,
      error: "Unable to publish the listing.",
      diagnostic: String(error?.message || error)
    }, 500);
  }
    }
  
