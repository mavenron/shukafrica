
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

export async function onRequest({ request, env }) {
  if (request.method !== "GET") {
    return json({ error: "Method not allowed." }, 405);
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
      listings: result.results || []
    });
  } catch (error) {
    return json({
      error: "Unable to load rental listings."
    }, 500);
  }
}

