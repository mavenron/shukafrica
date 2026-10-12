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

const IMAGE_TYPES = {
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/webp": "webp"
};

const VIDEO_TYPES = {
  "video/mp4": "mp4",
  "video/webm": "webm"
};

const MAX_IMAGE = 5 * 1024 * 1024;
const MAX_VIDEO = 50 * 1024 * 1024;

export async function onRequestPost({ request, env }) {
  const denied = requireAdmin(request, env);
  if (denied) return denied;

  if (!env.MEDIA) {
    return json({
      success: false,
      error: "R2 MEDIA binding is not available."
    }, 500);
  }

  let form;

  try {
    const contentType = request.headers.get("Content-Type") || "";

    if (!contentType.toLowerCase().startsWith("multipart/form-data")) {
      return json({
        success: false,
        error: "Upload must use multipart/form-data."
      }, 400);
    }

    form = await request.formData();
  } catch {
    return json({
      success: false,
      error: "Could not read the uploaded file. Please try again."
    }, 400);
  }

  

const file = form.get("file");

return json({
  success: false,
  debug: {
    contentType: request.headers.get("Content-Type"),
    fieldNames: Array.from(form.keys()),
    valueType: typeof file,
    isString: typeof file === "string",
    constructorName: file?.constructor?.name,
    fileSize: file?.size ?? null,
    fileType: file?.type ?? null
  }
}, 400);
  

if (!file) {
  return json({
    success: false,
    error: "No file value received."
  }, 400);
}

if (typeof file === "string") {
  return json({
    success: false,
    error: "The file arrived as text, not a file."
  }, 400);
}

if (typeof file.size !== "number") {
  return json({
    success: false,
    error: "File size is missing. Type: " + typeof file
  }, 400);
}

if (file.size < 1) {
  return json({
    success: false,
    error: "The server received a zero-byte file."
  }, 400);
}

const type = (file.type || "").toLowerCase();
const extension = IMAGE_TYPES[type] || VIDEO_TYPES[type];

if (!extension) {
  return json({
    success: false,
    error: "Unsupported file type: " + (type || "unknown")
  }, 400);
}

const isVideo = type in VIDEO_TYPES;
const limit = isVideo ? MAX_VIDEO : MAX_IMAGE;

if (file.size > limit) {
  return json({
    success: false,
    error: isVideo
      ? "Video must be smaller than 50 MB."
      : "Image must be smaller than 5 MB."
  }, 400);
}


  const key = `${
    isVideo ? "videos" : "products"
  }/${crypto.randomUUID()}.${extension}`;

  try {
    const fileData = await file.arrayBuffer();

await env.MEDIA.put(key, fileData, {
      httpMetadata: {
        contentType: type,
        cacheControl: "public, max-age=31536000, immutable"
      },
      customMetadata: {
        uploadedAt: new Date().toISOString()
      }
    });

    return json({
      success: true,
      key,
      url: `https://media.shukafrica.com/${key}`,
      message: "Upload successful."
    }, 201);
  } catch {
    return json({
      success: false,
      error: "Upload failed. Please try again."
    }, 500);
  }
}
