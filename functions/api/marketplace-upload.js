
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

    const contentType = request.headers.get("Content-Type") || "";
    if (!contentType.toLowerCase().startsWith("multipart/form-data;")) {
      return json({ success: false, error: "Upload must use a form." }, 415);
    }

    const form = await request.formData();
    const file = form.get("file");

    if (!(file instanceof File)) {
      return json({ success: false, error: "Please select an image." }, 400);
    }

    const extension = ALLOWED_TYPES[file.type];
    if (!extension) {
      return json({
        success: false,
        error: "Only JPG, PNG and WebP images are accepted."
      }, 415);
    }

    if (file.size < 1 || file.size > 2 * 1024 * 1024) {
      return json({
        success: false,
        error: "Each image must be no larger than 2 MB."
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

    await env.MEDIA.put(key, file.stream(), {
      httpMetadata: {
        contentType: file.type,
        cacheControl: "public, max-age=31536000, immutable"
      }
    });

    const imageUrl = `https://media.shukafrica.com/${key}`;

    return json({
      success: true,
      url: imageUrl
    }, 201);

  } catch (error) {
    return json({
      success: false,
      error: "Image upload failed. Please try again."
    }, 500);
  }
}

