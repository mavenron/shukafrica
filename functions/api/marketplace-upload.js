
const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

const ALLOWED_TYPES = {
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/webp": "webp"
};

const MAX_IMAGE_SIZE = 2 * 1024 * 1024;

function json(data, status = 200, origin = "") {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Vary": "Origin"
  };

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Credentials"] = "true";
  }

  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";

  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");

    if (separator === -1) continue;

    const key = part.slice(0, separator).trim();

    if (key === name) {
      try {
        return decodeURIComponent(
          part.slice(separator + 1).trim()
        );
      } catch {
        return "";
      }
    }
  }

  return "";
}

async function authenticateSeller(request, env) {
  const token = getCookie(request, "shuk_seller_session");

  if (!token || token.length > 500) {
    return null;
  }

  const tokenHash = await sha256(token);

  const session = await env.DB.prepare(`
    SELECT phone, expires_at
    FROM seller_sessions
    WHERE token_hash = ?
    LIMIT 1
  `).bind(tokenHash).first();

  if (!session) {
    return null;
  }

  const expiry = Date.parse(session.expires_at);

  if (!Number.isFinite(expiry) || expiry <= Date.now()) {
    return null;
  }

  // Email-based seller accounts must have a verified email.
  if (session.phone.startsWith("email:")) {
    const sellerId = session.phone.slice(6);

    if (!sellerId) {
      return null;
    }

    const seller = await env.DB.prepare(`
      SELECT id, email_verified
      FROM sellers
      WHERE id = ?
      LIMIT 1
    `).bind(sellerId).first();

    if (!seller || seller.email_verified !== 1) {
      return null;
    }

    return {
      type: "email",
      sellerId: seller.id
    };
  }

  // Temporary compatibility for existing SMS-based sessions.
  return {
    type: "legacy"
  };
}

function validImageSignature(bytes, contentType) {
  const data = new Uint8Array(bytes);

  if (contentType === "image/jpeg") {
    return (
      data.length >= 3 &&
      data[0] === 0xFF &&
      data[1] === 0xD8 &&
      data[2] === 0xFF
    );
  }

  if (contentType === "image/png") {
    return (
      data.length >= 8 &&
      data[0] === 0x89 &&
      data[1] === 0x50 &&
      data[2] === 0x4E &&
      data[3] === 0x47 &&
      data[4] === 0x0D &&
      data[5] === 0x0A &&
      data[6] === 0x1A &&
      data[7] === 0x0A
    );
  }

  if (contentType === "image/webp") {
    return (
      data.length >= 12 &&
      String.fromCharCode(...data.slice(0, 4)) === "RIFF" &&
      String.fromCharCode(...data.slice(8, 12)) === "WEBP"
    );
  }

  return false;
}

export async function onRequestPost({ request, env }) {
  const origin = request.headers.get("Origin") || "";

  try {
    if (!env.DB || !env.MEDIA) {
      return json({
        success: false,
        error: "Upload service is not configured."
      }, 503, origin);
    }

    if (!origin || !ALLOWED_ORIGINS.has(origin)) {
      return json({
        success: false,
        error: "Request not allowed."
      }, 403, origin);
    }

    const seller = await authenticateSeller(request, env);

    if (!seller) {
      return json({
        success: false,
        error: "Please log in with a verified seller account before uploading."
      }, 401, origin);
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
      }, 415, origin);
    }

    const contentLengthHeader = request.headers.get("Content-Length");

    if (contentLengthHeader !== null) {
      const contentLength = Number(contentLengthHeader);

      if (
        !Number.isFinite(contentLength) ||
        contentLength < 1 ||
        contentLength > MAX_IMAGE_SIZE
      ) {
        return json({
          success: false,
          error: "Each image must be no larger than 2 MB."
        }, 413, origin);
      }
    }

    const bytes = await request.arrayBuffer();

    if (
      bytes.byteLength < 1 ||
      bytes.byteLength > MAX_IMAGE_SIZE
    ) {
      return json({
        success: false,
        error: "Each image must be no larger than 2 MB and cannot be empty."
      }, 413, origin);
    }

    if (!validImageSignature(bytes, contentType)) {
      return json({
        success: false,
        error: "The uploaded file does not match its image format."
      }, 415, origin);
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
    }, 201, origin);

  } catch (error) {
    console.error("Image upload failed:", error);

    return json({
      success: false,
      error: "Image upload failed. Please try again."
    }, 500, origin);
  }
  }
