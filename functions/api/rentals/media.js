const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

const ALLOWED_TYPES = new Set([
  "image/jpeg",
  "image/png",
  "image/webp",
  "video/mp4",
  "video/x-msvideo",
  "video/webm"
]);

function responseHeaders(origin = "") {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Vary": "Origin"
  };

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Methods"] = "GET, HEAD, OPTIONS";
  }

  return headers;
}

function json(data, status = 200, origin = "") {
  return new Response(JSON.stringify(data), {
    status,
    headers: responseHeaders(origin)
  });
}

function validKey(key) {
  return (
    typeof key === "string" &&
    key.length <= 200 &&
    /^rentals\/[^/]+\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(jpg|png|webp|mp4|avi|webm)$/i.test(key)
  );
}

export async function onRequest({ request, env }) {
  const origin = request.headers.get("Origin") || "";

  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return json({ error: "Origin not allowed." }, 403);
  }

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: responseHeaders(origin)
    });
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    return json({ error: "Method not allowed." }, 405, origin);
  }

  if (!env.DB || !env.RENTAL_MEDIA) {
    return json(
      { error: "Rentals media is not configured." },
      503,
      origin
    );
  }

  const url = new URL(request.url);
  const key = url.searchParams.get("key");

  if (!validKey(key)) {
    return json({ error: "Invalid media key." }, 400, origin);
  }

  try {
    const listing = await env.DB.prepare(`
      SELECT id
      FROM rentals
      WHERE status = 'published'
        AND (
          image_1 = ? OR image_2 = ?
          OR image_3 = ? OR video_key = ?
        )
      LIMIT 1
    `).bind(key, key, key, key).first();

    if (!listing) {
      return json({ error: "Media not found." }, 404, origin);
    }

    const object = await env.RENTAL_MEDIA.get(key);

    if (!object) {
      return json({ error: "Media file not found." }, 404, origin);
    }

    const contentType = (
      object.httpMetadata?.contentType || ""
    ).toLowerCase();

    if (!ALLOWED_TYPES.has(contentType)) {
      return json({ error: "Unsupported media type." }, 415, origin);
    }

    const headers = new Headers({
      "Content-Type": contentType,
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "public, max-age=300",
      "Content-Disposition": "inline",
      "Accept-Ranges": "none",
      "Vary": "Origin"
    });

    if (origin && ALLOWED_ORIGINS.has(origin)) {
      headers.set("Access-Control-Allow-Origin", origin);
    }

    if (object.httpEtag) {
      headers.set("ETag", object.httpEtag);
    }

    if (request.method === "HEAD") {
      return new Response(null, {
        status: 200,
        headers
      });
    }

    return new Response(object.body, {
      status: 200,
      headers
    });

  } catch (error) {
    console.error("Rental media retrieval failed:", error);

    return json(
      { error: "Unable to load media." },
      500,
      origin
    );
  }
}
