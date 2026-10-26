
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

function clean(value, maxLength = 200) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

function validCategory(value) {
  return typeof value === "string" && CATEGORIES.has(value);
}

/* GET: Publicly display published Open Market listings */
export async function onRequestGet({ request, env }) {
  try {
    if (!env.OPEN_MARKET_DB) {
      return json({
        success: false,
        error: "Open Market database binding is missing."
      }, 500);
    }

    const url = new URL(request.url);
    const category = clean(url.searchParams.get("category"), 30);
    const search = clean(url.searchParams.get("q"), 100);
    const location = clean(url.searchParams.get("location"), 100);

    if (category && category !== "all" && !validCategory(category)) {
      return json({
        success: false,
        error: "Invalid category."
      }, 400);
    }

    let sql = `
      SELECT
        id, category, job_type, title, seller_name,
        price, location, country, region, description,
        delivery, image_1, image_2, image_3,
        image_4, image_5, video_url, created_at
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
    return json({
      success: false,
      error: "Unable to load Open Market listings."
    }, 500);
  }
}

/* POST: Publish a listing immediately */
export async function onRequestPost({ request, env }) {
  try {
    if (!env.OPEN_MARKET_DB) {
      return json({
        success: false,
        error: "Open Market database binding is missing."
      }, 500);
    }

    const contentType = request.headers.get("Content-Type") || "";

    if (!contentType.toLowerCase().includes("application/json")) {
      return json({
        success: false,
        error: "Send listing details as JSON. Media upload will be connected separately."
      }, 415);
    }

    const data = await request.json();

    if (!data || typeof data !== "object" || Array.isArray(data)) {
      return json({
        success: false,
        error: "Invalid listing data."
      }, 400);
    }

    // Honeypot field: normal users should leave this empty.
    if (clean(data.website, 200)) {
      return json({ success: true, message: "Listing received." });
    }

    const category = clean(data.category, 30);
    const jobType = clean(data.job_type, 30);
    const title = clean(data.title, 120);
    const sellerName = clean(data.seller_name, 100);
    const contact = clean(data.contact, 40);
    const price = clean(data.price, 60);
    const location = clean(data.location, 120);
    const country = clean(data.country, 80);
    const region = clean(data.region, 80);
    const description = clean(data.description, 3000);
    const delivery = clean(data.delivery, 20);

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

    if (
      category === "jobs" &&
      !["workers-needed", "seeking-work"].includes(jobType)
    ) {
      return json({
        success: false,
        error: "For Jobs, choose Workers Needed or Looking for Work."
      }, 400);
    }

    if (
      category !== "jobs" &&
      jobType
    ) {
      return json({
        success: false,
        error: "Job type is only valid for Jobs listings."
      }, 400);
    }

    const id = crypto.randomUUID();

    await env.OPEN_MARKET_DB.prepare(`
      INSERT INTO open_market_listings (
        id, category, job_type, title, seller_name,
        contact, price, location, country, region,
        description, delivery, status
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'published'
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
      delivery || null
    ).run();

    return json({
      success: true,
      message: "Your listing has been published.",
      listing: {
        id,
        category,
        job_type: jobType || null,
        title,
        price: price || null,
        location,
        country: country || null,
        region: region || null
      }
    }, 201);
  } catch (error) {
    return json({
      success: false,
      error: "Unable to publish the listing. Please try again."
    }, 500);
  }
        }
    
