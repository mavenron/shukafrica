function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function authorised(request, env) {
  const supplied = request.headers.get("X-Shuk-Admin-Key");
  const expected = env.SHUK_ADMIN_KEY;

  if (!supplied || !expected || supplied.length !== expected.length) {
    return false;
  }

  let difference = 0;
  for (let i = 0; i < supplied.length; i++) {
    difference |= supplied.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return difference === 0;
}

function requireAdmin(request, env) {
  return authorised(request, env)
    ? null
    : json({ success: false, error: "Unauthorised" }, 401);
}

const MAX_SIZE = 5 * 1024 * 1024;
const ALLOWED_TYPES = new Set([
  "image/jpeg",
  "image/png",
  "image/webp"
]);

export async function onRequestPost({ request, env }) {
  const denied = requireAdmin(request, env);
  if (denied) return denied;

  if (!env.MEDIA) {
    return json({
      success: false,
      error: "R2 MEDIA binding is not available."
    }, 500);
  }

  const contentType = request.headers.get("Content-Type") || "";
  if (!contentType.toLowerCase().startsWith("multipart/form-data;")) {
    return json({
      success: false,
      error: "Send the picture as multipart form data."
    }, 400);
  }

  let form;
  try {
    form = await request.formData();
  } catch {
    return json({
      success: false,
      error: "Could not read the upload."
    }, 400);
  }
console.log("Upload diagnostic:", {
  contentType: request.headers.get("Content-Type"),
  formKeys: [...form.keys()]
});
  return json({
  success: false,
  error: "Choose an image file.",
  diagnostic: {
    formKeys: [...form.keys()]
  }
}, 400);

  if (!ALLOWED_TYPES.has(file.type)) {
    return json({
      success: false,
      error: "Use a JPG, PNG or WebP image."
    }, 400);
  }

  if (file.size < 1 || file.size > MAX_SIZE) {
    return json({
      success: false,
      error: "Image must be smaller than 5 MB."
    }, 400);
  }

  const extension = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp"
  }[file.type];

  const id = crypto.randomUUID();
  const key = `products/${id}.${extension}`;

  try {
    await env.MEDIA.put(key, file.stream(), {
      httpMetadata: {
        contentType: file.type,
        cacheControl: "public, max-age=31536000, immutable"
      },
      customMetadata: {
        uploadedAt: new Date().toISOString()
      }
    });

    const imageUrl =
      `https://media.shukafrica.com/${key}`;

    return json({
      success: true,
      key,
      url: imageUrl,
      message: "Image uploaded successfully."
    }, 201);
  } catch {
    return json({
      success: false,
      error: "Image upload failed. Please try again."
    }, 500);
  }
      }


