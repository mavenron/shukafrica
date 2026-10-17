function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "https://shukafrica.com"
    }
  });
}

const ALLOWED_TYPES = {
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/webp": "webp"
};

export async function onRequestPost({ request, env }) {
  try {
    if (request.headers.get("Origin") !== "https://shukafrica.com") {
      return json({ success: false, error: "Request not allowed." }, 403);
    }

    const contentType = (request.headers.get("Content-Type") || "")
      .split(";")[0]
      .trim()
      .toLowerCase();

    const extension = ALLOWED_TYPES[contentType];

    if (!extension) {
      return json({
        success: false,
        error: "Only JPG, PNG and WebP images are accepted."
      }, 415);
    }

    const contentLength = Number(request.headers.get("Content-Length") || 0);

    if (contentLength > 2 * 1024 * 1024) {
      return json({
        success: false,
        error: "Each image must be no larger than 2 MB."
      }, 413);
    }

    const bytes = await request.arrayBuffer();

    if (bytes.byteLength < 1 || bytes.byteLength > 2 * 1024 * 1024) {
      return json({
        success: false,
        error: "Each image must be no larger than 2 MB and cannot be empty."
      }, 413);
    }

    if (!env.MEDIA) {
      return json({
        success: false,
        error: "Image storage is not configured."
      }, 500);
    }

    const id = crypto.randomUUID();
    const key = `marketplace/${id}.${extension}`;

    await env.MEDIA.put(key, bytes, {
      httpMetadata: {
        contentType,
        cacheControl: "public, max-age=31536000, immutable"
      }
    });

    return json({
      success: true,
      url: `https://media.shukafrica.com/${key}`
    }, 201);

  } catch (error) {
    console.error("Image upload failed:", error);
    return json({
      success: false,
      error: "Image upload failed. Please try again."
    }, 500);
  }
}
