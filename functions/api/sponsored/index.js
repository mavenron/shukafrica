export async function onRequestGet({ env }) {
  try {
    const { results } = await env.SPONSORED_DB
      .prepare(`
        SELECT
          id,
          title,
          short_description,
          full_description,
          placement,
          main_media_key,
          extra_media_key,
          start_date,
          end_date
        FROM sponsored_ads
        WHERE published = 1
          AND date(start_date) <= date('now')
          AND date(end_date) >= date('now')
        ORDER BY display_order ASC, id DESC
      `)
      .all();

    return Response.json({
      success: true,
      ads: results
    });

  } catch (error) {
    return Response.json({
      success: false,
      message: "Unable to load sponsored ads."
    }, { status: 500 });
  }
}
