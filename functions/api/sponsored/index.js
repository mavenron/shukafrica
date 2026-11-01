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

    const ads = results.map(ad => ({
      id: ad.id,
      title: ad.title,
      short_description: ad.short_description,
      full_description: ad.full_description,
      placement: ad.placement,
      main_media_url: ad.main_media_key
        ? `/api/sponsored/media?key=${encodeURIComponent(ad.main_media_key)}`
        : null,
      extra_media_url: ad.extra_media_key
        ? `/api/sponsored/media?key=${encodeURIComponent(ad.extra_media_key)}`
        : null,
      start_date: ad.start_date,
      end_date: ad.end_date
    }));

    return Response.json({
      success: true,
      ads
    });

  } catch (error) {
    return Response.json({
      success: false,
      message: "Unable to load sponsored ads."
    }, { status: 500 });
  }
}
