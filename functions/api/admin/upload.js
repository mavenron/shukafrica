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
  if (!supplied || !expected || supplied.length !== expected.length) return false;
  let difference = 0;
  for (let i = 0; i < supplied.length; i++) {
    difference |= supplied.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return difference === 0;
}

function requireAdmin(request, env) {
  return authorised(request, env) ? null : json({ success: false, error: "Unauthorised" }, 401);
}

const MAX_SIZE = 50 * 1024 * 1024; // 50MB
const ALLOWED_TYPES = new Set([
  "image/jpeg",
  "image/png",
  "image/webp",
  "video/mp4",
  "video/webm",
  "video/quicktime"
]);

export async function onRequestPost({ request, env }) {
  const denied = requireAdmin(request, env);
  if (denied) return denied;

  if (!env.MEDIA) {
    return json({ success: false, error: "R2 MEDIA binding is not available." }, 500);
  }

  let form;
  try {
    form = await request.formData();
  } catch {
    return json({ success: false, error: "Could not read form data." }, 400);
  }

  let file = form.get("file");

  // If someone passed a string filename instead of a file object, reject clearly
  if (!file || typeof file === "string" || typeof file.stream !== "function") {
    return json({ success: false, error: "Choose a valid image or video file." }, 400);
  }

  const fileType = file.type || "image/jpeg";
  if (!ALLOWED_TYPES.has(fileType)) {
    return json({ success: false, error: "Unsupported file format." }, 400);
  }

  if (file.size > MAX_SIZE) {
    return json({ success: false, error: "File must be smaller than 50 MB." }, 400);
  }

  const extension = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
    "video/mp4": "mp4",
    "video/webm": "webm",
    "video/quicktime": "mov"
  }[fileType] || "jpg";

  const folder = fileType.startsWith("video/") ? "videos" : "products";
  const id = crypto.randomUUID();
  const key = `${folder}/${id}.${extension}`;

  try {
    await env.MEDIA.put(key, file.stream(), {
      httpMetadata: {
        contentType: fileType,
        cacheControl: "public, max-age=31536000, immutable"
      }
    });

    return json({
      success: true,
      url: `https://media.shukafrica.com/${key}`,
      message: "File uploaded successfully."
    }, 201);
  } catch {
    return json({ success: false, error: "Upload failed. Please try again." }, 500);
  }
}
