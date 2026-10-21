
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

export async function onRequest({ request, env }) {
  if (request.method !== "GET") {
    return json(
      { success: false, error: "Method not allowed." },
      405
    );
  }

  if (!env.DB) {
    return json(
      { success: false, error: "Rentals database unavailable." },
      503
    );
  }

  try {
    const result = await env.DB.prepare(`
      SELECT
        id,
        title,
        description,
        price,
        availability,
        condition,
        terms,
        location,
        contact,
        image_1,
        image_2,
        image_3,
        video_key,
        created_at,
        updated_at
      FROM rentals
      WHERE status = 'published'
      ORDER BY created_at DESC
      LIMIT 100
    `).all();

    return json({
      success: true,
      listings: Array.isArray(result.results)
        ? result.results
        : []
    });
  } catch (error) {
    console.error("Rentals listings query failed:", error);

    return json(
      { success: false, error: "Unable to load rental listings." },
      500
    );
  }
}
