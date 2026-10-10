
export async function onRequestGet({ env, request }) {
  try {
    const url = new URL(request.url);
    const category = url.searchParams.get("category");
    const search = url.searchParams.get("search");

    let sql = `
      SELECT id, category, item_name, price_ghs,
        description, condition, availability, warranty,
        image_1, image_2, image_3, video_url
      FROM global_products
      WHERE is_published = 1
    `;

    const params = [];

    if (category) {
      sql += " AND category = ?";
      params.push(category);
    }

    if (search) {
      sql += " AND (item_name LIKE ? OR description LIKE ?)";
      params.push(`%${search}%`, `%${search}%`);
    }

    sql += " ORDER BY created_at DESC LIMIT 100";

    const result = await env.DB
      .prepare(sql)
      .bind(...params)
      .all();

    return Response.json({
      success: true,
      products: result.results || []
    });
  } catch (error) {
    return Response.json(
      { success: false, error: "Unable to load products." },
      { status: 500 }
    );
  }
}
