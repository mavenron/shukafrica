const SESSION_COOKIE = "shuk_open_market_session";
const SESSION_SECRET_NAME = "OPEN_MARKET_SESSION_SECRET";
const MEDIA_BASE_URL = "https://market-media.shukafrica.com";

const MAX_LISTINGS = 5;
const MAX_IMAGES = 5;
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

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

function clean(value, max = 2000) {
  return String(value ?? "").trim().slice(0, max);
}

function base64UrlToBytes(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
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

async function verifySession(request, secret) {
  try {
    const token = getCookie(request, SESSION_COOKIE);
    if (!token || !secret) return null;

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

    if (!payload.sub || !payload.exp || payload.exp <= Math.floor(Date.now() / 1000)) {
      return null;
    }

    return payload.sub;
  } catch {
    return null;
  }
}

async function getSeller(request, env) {
  const userId = await verifySession(request, env.OPEN_MARKET_SESSION_SECRET);
  if (!userId) return null;

  return env.OPEN_MARKET_DB.prepare(
    "SELECT id, full_name, email FROM open_market_users WHERE id = ?"
  ).bind(userId).first();
}

function validCategory(category) {
  return CATEGORIES.includes(category);
}

function normalizeJobType(value) {
  const type = clean(value, 50).toLowerCase().replace(/_/g, "-");

  if (["workers-needed", "workers needed"].includes(type)) {
    return "workers-needed";
  }

  if (["seeking-work", "seeking work", "looking for work", "looking for a job"].includes(type)) {
    return "seeking-work";
  }

  return "";
}

function mediaUrl(key) {
  return `${MEDIA_BASE_URL}/${key}`;
}

function randomId() {
  return crypto.randomUUID();
}

function safeExtension(type, map) {
  return map[type] || null;
}

async function removeUploaded(bucket, keys) {
  for (const key of keys) {
    try {
      await bucket.delete(key);
    } catch (error) {
      console.error("Media cleanup failed:", key, error);
    }
  }
}

export async function onRequestGet({ request, env }) {
  try {
    const url = new URL(request.url);
    const category = clean(url.searchParams.get("category"), 40).toLowerCase();
    const search = clean(url.searchParams.get("search"), 100);
    const location = clean(url.searchParams.get("location"), 100);
    const limit = Math.min(
      Math.max(Number(url.searchParams.get("limit")) || 30, 1),
      100
    );

    let sql = `
      SELECT id, category, job_type, title, seller_name, contact,
             price, location, country, region, description, delivery,
             image_1, image_2, image_3, image_4, image_5, video_url,
             created_at
      FROM open_market_listings
      WHERE status = 'published'
    `;
    const params = [];

    if (category && validCategory(category)) {
      sql += " AND category = ?";
      params.push(category);
    }

    if (search) {
      sql += " AND (title LIKE ? OR description LIKE ? OR seller_name LIKE ?)";
      const term = `%${search}%`;
      params.push(term, term, term);
    }

    if (location) {
      sql += " AND location LIKE ?";
      params.push(`%${location}%`);
    }

    sql += " ORDER BY created_at DESC LIMIT ?";
    params.push(limit);

    const result = await env.OPEN_MARKET_DB.prepare(sql).bind(...params).all();

    return json({
      success: true,
      listings: result.results || []
    });
  } catch (error) {
    console.error("Open Market listing fetch failed:", error);
    return json({ success: false, error: "Unable to load listings." }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  const uploadedKeys = [];

  try {
    if (!env.OPEN_MARKET_DB || !env.OPEN_MARKET_MEDIA) {
      return json({ success: false, error: "Open Market is not configured correctly." }, 500);
    }

    const seller = await getSeller(request, env);
    if (!seller) {
      return json({
        success: false,
        error: "Please log in to your Open Market account before publishing."
      }, 401);
    }

    const countResult = await env.OPEN_MARKET_DB.prepare(
      "SELECT COUNT(*) AS total FROM open_market_listings WHERE seller_id = ?"
    ).bind(seller.id).first();

    if ((countResult?.total || 0) >= MAX_LISTINGS) {
      return json({
        success: false,
        error: "You have reached the limit of 5 Open Market listings."
      }, 403);
    }

    const form = await request.formData();

    const category = clean(form.get("category"), 40).toLowerCase();
    const title = clean(form.get("title"), 200);
    const sellerName = clean(form.get("seller_name"), 120);
    const contact = clean(form.get("contact"), 80);
    const price = clean(form.get("price"), 80);
    const location = clean(form.get("location"), 200);
    const country = clean(form.get("country"), 100);
    const region = clean(form.get("region"), 100);
    const description = clean(form.get("description"), 5000);
    const delivery = clean(form.get("delivery"), 100);
    let jobType = "";

    if (!validCategory(category)) {
      return json({ success: false, error: "Please choose a valid listing category." }, 400);
    }

    if (!title || !sellerName || !contact || !location || !description) {
      return json({
        success: false,
        error: "Please complete all required listing fields."
      }, 400);
    }

    if (category === "jobs") {
      jobType = normalizeJobType(form.get("job_type"));
      if (!jobType) {
        return json({
          success: false,
          error: "For Jobs, choose Workers Needed or Seeking Work."
        }, 400);
      }
    }

    const imageFiles = form.getAll("images").filter(
      file => file instanceof File && file.size > 0
    );

    if (imageFiles.length > MAX_IMAGES) {
      return json({ success: false, error: "You can upload up to 5 photos." }, 400);
    }

    for (const file of imageFiles) {
      if (!safeExtension(file.type, IMAGE_TYPES)) {
        return json({
          success: false,
          error: "Photos must be JPG, PNG, or WebP."
        }, 400);
      }

      if (file.size > MAX_IMAGE_SIZE) {
        return json({
          success: false,
          error: "Each photo must be 5 MB or smaller."
        }, 400);
      }
    }

    const videoEntries = form.getAll("video").filter(
      file => file instanceof File && file.size > 0
    );

    if (videoEntries.length > 1) {
      return json({ success: false, error: "Upload only one video per listing." }, 400);
    }

    const videoFile = videoEntries[0] || null;

    if (videoFile) {
      if (!safeExtension(videoFile.type, VIDEO_TYPES)) {
        return json({
          success: false,
          error: "Video must be MP4, WebM, or MOV."
        }, 400);
      }

      if (videoFile.size > MAX_VIDEO_SIZE) {
        return json({
          success: false,
          error: "The video must be 10 MB or smaller."
        }, 400);
      }
    }

    const id = randomId();
    const imageUrls = ["", "", "", "", ""];
    let videoUrl = "";

    for (let i = 0; i < imageFiles.length; i++) {
      const file = imageFiles[i];
      const ext = safeExtension(file.type, IMAGE_TYPES);
      const key = `open-market/${seller.id}/${id}/image-${i + 1}.${ext}`;

      await env.OPEN_MARKET_MEDIA.put(key, file.stream(), {
        httpMetadata: { contentType: file.type }
      });

      uploadedKeys.push(key);
      imageUrls[i] = mediaUrl(key);
    }

    if (videoFile) {
      const ext = safeExtension(videoFile.type, VIDEO_TYPES);
      const key = `open-market/${seller.id}/${id}/video.${ext}`;

      await env.OPEN_MARKET_MEDIA.put(key, videoFile.stream(), {
        httpMetadata: { contentType: videoFile.type }
      });

      uploadedKeys.push(key);
      videoUrl = mediaUrl(key);
    }

    const insert = await env.OPEN_MARKET_DB.prepare(`
      INSERT INTO open_market_listings (
        id, category, job_type, title, seller_name, contact, price,
        location, country, region, description, delivery,
        image_1, image_2, image_3, image_4, image_5, video_url,
        status, seller_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'published', ?)
    `).bind(
      id, category, jobType || null, title, sellerName, contact, price,
      location, country, region, description, delivery,
      imageUrls[0], imageUrls[1], imageUrls[2], imageUrls[3], imageUrls[4],
      videoUrl, seller.id
    ).run();

    if (!insert.success) {
      throw new Error("Listing insert failed.");
    }

    return json({
      success: true,
      message: "Your listing has been published.",
      listing: {
        id,
        category,
        job_type: jobType || null,
        title,
        seller_name: sellerName,
        contact,
        price,
        location,
        country,
        region,
        description,
        delivery,
        image_1: imageUrls[0] || null,
        image_2: imageUrls[1] || null,
        image_3: imageUrls[2] || null,
        image_4: imageUrls[3] || null,
        image_5: imageUrls[4] || null,
        video_url: videoUrl || null
      }
    }, 201);
  } catch (error) {
    console.error("Open Market publish failed:", error);
    if (env.OPEN_MARKET_MEDIA) {
      await removeUploaded(env.OPEN_MARKET_MEDIA, uploadedKeys);
    }

    return json({
      success: false,
      error: "Unable to publish the listing. Please try again."
    }, 500);
  }
      }
