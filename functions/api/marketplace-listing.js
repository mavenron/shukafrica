
function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

export async function onRequestGet({ request, env }) {
  try {
    const url = new URL(request.url);
    const id = (url.searchParams.get("id") || "").trim();

    if (!id || id.length > 100) {
      return json({
        success: false,
        error: "A valid listing ID is required."
      }, 400);
    }

    const result = await env.DB.prepare(`
      SELECT
        id,
        seller_name,
        seller_phone,
        item_name,
        category,
        price_ghs,
        location,
        description,
        image_1,
        image_2,
        image_3,
        status,
        created_at
      FROM marketplace_listings
      WHERE id = ? AND status = 'published'
      LIMIT 1
    `).bind(id).first();

    if (!result) {
      return json({
        success: false,
        error: "Listing not found or not available."
      }, 404);
    }

    return json({
      success: true,
      listing: result
    });
  } catch (error) {
    return json({
      success: false,
      error: "Unable to load this listing."
    }, 500);
  }
}

