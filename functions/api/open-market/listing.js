function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

const CATEGORIES = new Set([
  "shop",
  "store",
  "home-service",
  "jobs"
]);

const MAX_IMAGES = 3;
const MAX_IMAGE_SIZE = 5 * 1024 * 1024;
const MAX_VIDEO_SIZE = 30 * 1024 * 1024;
const MAX_VIDEO_SECONDS = 15;

const MEDIA_BASE_URL = "https://market-media.shukafrica.com";

const IMAGE_TYPES = new Map([
  ["image/jpeg", "jpg"],
  ["image/png", "png"],
  ["image/webp", "webp"]
]);

const VIDEO_TYPES = new Map([
  ["video/mp4", "mp4"],
  ["video/webm", "webm"],
  ["video/quicktime", "mov"]
]);

function clean(value, maxLength = 200) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

function validCategory(value) {
  return typeof value === "string" && CATEGORIES.has(value);
}

function normalizeJobType(value) {
  const job = clean(value, 40).toLowerCase();

  if (
    job === "workers-needed" ||
    job === "workers needed"
  ) {
    return "workers-needed";
  }

  if (
    job === "seeking-work" ||
    job === "looking for work"
  ) {
    return "seeking-work";
  }

  return "";
}

function validFile(file) {
  return typeof File !== "undefined" && file instanceof File;
}

function getExtension(file, allowedTypes) {
  return allowedTypes.get(
    (file.type || "").toLowerCase()
  ) || "";
}

function mediaUrl(key) {
  return `${MEDIA_BASE_URL}/${key}`;
}

/*
 * GET
 * Return published Open Market listings.
 */
export async function onRequestGet({ request, env }) {
  try {
    if (!env.OPEN_MARKET_DB) {
      return json({
        success: false,
        error: "Open Market database binding is missing."
      }, 500);
    }

    const url = new URL(request.url);

    const category = clean(
      url.searchParams.get("category"),
      30
    );

    const search = clean(
      url.searchParams.get("q"),
      100
    );

    const location = clean(
      url.searchParams.get("location"),
      100
    );

    if (
      category &&
      category !== "all" &&
      !validCategory(category)
    ) {
      return json({
        success: false,
        error: "Invalid category."
      }, 400);
    }

    let sql = `
      SELECT
        id,
        category,
        job_type,
        title,
        seller_name,
        price,
        location,
        country,
        region,
        description,
        delivery,
        image_1,
        image_2,
        image_3,
        video_url,
        created_at
      FROM open_market_listings
      WHERE status = 'published'
    `;

    const params = [];

    if (category && category !== "all") {
      sql += " AND category = ?";
      params.push(category);
    }

    if (search) {
      sql += `
        AND (
          title LIKE ? OR
          price LIKE ? OR
          description LIKE ?
        )
      `;

      const term = `%${search.replace(/[%_\\]/g, "\\$&")}%`;

      params.push(term, term, term);
    }

    if (location) {
      sql += `
        AND (
          location LIKE ? OR
          country LIKE ? OR
          region LIKE ?
        )
      `;

      const term = `%${location.replace(/[%_\\]/g, "\\$&")}%`;

      params.push(term, term, term);
    }

    sql += " ORDER BY created_at DESC LIMIT 100";

    const result = await env.OPEN_MARKET_DB
      .prepare(sql)
      .bind(...params)
      .all();

    return json({
      success: true,
      listings: result.results || []
    });
  } catch (error) {
    console.error("Open Market GET error:", error);

    return json({
      success: false,
      error: "Unable to load Open Market listings."
    }, 500);
  }
}

/*
 * POST
 * Publish a listing and upload its media to R2.
 *
 * Expected multipart fields:
 * category, job_type, title, seller_name, contact,
 * price, location, country, region, description,
 * delivery, images (repeated up to 3 times), video.
 */
export async function onRequestPost({ request, env }) {
  const uploadedKeys = [];

  try {
    if (!env.OPEN_MARKET_DB) {
      return json({
        success: false,
        error: "Open Market database binding is missing."
      }, 500);
    }

    if (!env.OPEN_MARKET_MEDIA) {
      return json({
        success: false,
        error: "Open Market media bucket binding is missing."
      }, 500);
    }

    const contentType =
      request.headers.get("Content-Type") || "";

    if (
      !contentType.toLowerCase().includes("multipart/form-data")
    ) {
      return json({
        success: false,
        error: "Please submit the listing using the listing form."
      }, 415);
    }

    const form = await request.formData();

    // Honeypot: bots filling this field receive a fake success.
    if (clean(form.get("website"), 200)) {
      return json({
        success: true,
        message: "Listing received."
      });
    }

    const category = clean(form.get("category"), 30);

    const title = clean(form.get("title"), 120);

    const sellerName = clean(
      form.get("seller_name"),
      100
    );

    const contact = clean(form.get("contact"), 40);

    const price = clean(form.get("price"), 60);

    const location = clean(form.get("location"), 120);

    const country = clean(form.get("country"), 80);

    const region = clean(form.get("region"), 80);

    const description = clean(
      form.get("description"),
      3000
    );

    let delivery = clean(form.get("delivery"), 20);

    let jobType = "";

    if (category === "jobs") {
      jobType = normalizeJobType(form.get("job_type"));

      if (!jobType) {
        return json({
          success: false,
          error: "Choose Workers Needed or Looking for Work."
        }, 400);
      }
    } else if (clean(form.get("job_type"), 40)) {
      return json({
        success: false,
        error: "Job type is only valid for Jobs listings."
      }, 400);
    }

    if (!validCategory(category)) {
      return json({
        success: false,
        error: "Choose Shop, Store, Home Service or Jobs."
      }, 400);
    }

    if (
      !title ||
      !sellerName ||
      !contact ||
      !location ||
      !description
    ) {
      return json({
        success: false,
        error: "Title, name, contact, location and description are required."
      }, 400);
    }

    if (
      title.length < 2 ||
      sellerName.length < 2 ||
      contact.length < 5 ||
      description.length < 5
    ) {
      return json({
        success: false,
        error: "Please provide more complete listing details."
      }, 400);
    }

    if (category === "shop" || category === "store") {
      if (!["Yes", "No", ""].includes(delivery)) {
        return json({
          success: false,
          error: "Invalid delivery selection."
        }, 400);
      }

      delivery = delivery || "No";
    } else {
      delivery = "";
    }

    // Collect and validate images before uploading anything.
    const imageEntries = form.getAll("images");

console.log("Open Market image diagnostic:", {
  count: imageEntries.length,
  files: imageEntries.map(file => ({
    isFile: validFile(file),
    name: file && file.name,
    type: file && file.type,
    size: file && file.size
  }))
});

console.log("Open Market image diagnostic:", {
  count: imageEntries.length,
  files: imageEntries.map(file => ({
    isFile: validFile(file),
    name: file?.name ?? null,
    type: file?.type ?? null,
    size: file?.size ?? null
  }))
});

const images = imageEntries.filter(file =>
  validFile(file) && file.size > 0
);

    if (images.length > MAX_IMAGES) {
      return json({
        success: false,
        error: "You can upload a maximum of 3 images."
      }, 400);
    }

    for (const file of images) {
      if (file.size > MAX_IMAGE_SIZE) {
        return json({
          success: false,
          error: "Each image must be 5 MB or smaller."
        }, 400);
      }

      if (!getExtension(file, IMAGE_TYPES)) {
        return json({
          success: false,
          error: "Images must be JPG, PNG or WebP."
        }, 400);
      }
    }

    const videoEntry = form.get("video");

    const video =
      validFile(videoEntry) && videoEntry.size > 0
        ? videoEntry
        : null;

    if (video) {
      if (video.size > MAX_VIDEO_SIZE) {
        return json({
          success: false,
          error: "The video must be 30 MB or smaller."
        }, 400);
      }

      if (!getExtension(video, VIDEO_TYPES)) {
        return json({
          success: false,
          error: "The video must be MP4, WebM or MOV."
        }, 400);
      }
    }

    const id = crypto.randomUUID();

    const imageUrls = [null, null, null];
    let videoUrl = null;

    /*
     * Upload images to the dedicated Open Market bucket.
     * Random keys prevent user-controlled filenames.
     */
    for (let i = 0; i < images.length; i++) {
      const file = images[i];

      const extension = getExtension(file, IMAGE_TYPES);

      const key =
        `listings/${id}/${crypto.randomUUID()}.${extension}`;

      await env.OPEN_MARKET_MEDIA.put(key, file, {
        httpMetadata: {
          contentType: file.type.toLowerCase(),
          cacheControl: "public, max-age=31536000, immutable"
        }
      });

      uploadedKeys.push(key);
      imageUrls[i] = mediaUrl(key);
    }

    if (video) {
      const extension = getExtension(video, VIDEO_TYPES);

      const key =
        `listings/${id}/${crypto.randomUUID()}.${extension}`;

      await env.OPEN_MARKET_MEDIA.put(key, video, {
        httpMetadata: {
          contentType: video.type.toLowerCase(),
          cacheControl: "public, max-age=31536000, immutable"
        }
      });

      uploadedKeys.push(key);
      videoUrl = mediaUrl(key);
    }

    /*
     * Store the listing and its public media URLs in D1.
     */
    await env.OPEN_MARKET_DB.prepare(`
      INSERT INTO open_market_listings (
        id,
        category,
        job_type,
        title,
        seller_name,
        contact,
        price,
        location,
        country,
        region,
        description,
        delivery,
        image_1,
        image_2,
        image_3,
        video_url,
        status
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'published'
      )
    `).bind(
      id,
      category,
      jobType || null,
      title,
      sellerName,
      contact,
      price || null,
      location,
      country || null,
      region || null,
      description,
      delivery || null,
      imageUrls[0],
      imageUrls[1],
      imageUrls[2],
      videoUrl
    ).run();

    return json({
      success: true,
      message: "Your listing has been published.",
      listing: {
        id,
        category,
        job_type: jobType || null,
        title,
        seller_name: sellerName,
        price: price || null,
        location,
        country: country || null,
        region: region || null,
        description,
        delivery: delivery || null,
        image_1: imageUrls[0],
        image_2: imageUrls[1],
        image_3: imageUrls[2],
        video_url: videoUrl,
        status: "published"
      }
    }, 201);

  } catch (error) {
    console.error("Open Market POST error:", error);

    // Best-effort cleanup if an upload succeeded but publishing failed.
    if (env.OPEN_MARKET_MEDIA) {
      await Promise.all(
        uploadedKeys.map(async key => {
          try {
            await env.OPEN_MARKET_MEDIA.delete(key);
          } catch (cleanupError) {
            console.error(
              "Open Market media cleanup failed:",
              cleanupError
            );
          }
        })
      );
    }

    return json({
      success: false,
      error: "Unable to publish the listing. Please try again."
    }, 500);
  }
  }
        
