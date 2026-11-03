
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

async function verifyAccessToken(request) {
  const token = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!token) return false;

  try {
    const parts = token.split(".");
    if (parts.length !== 3) return false;

    const decode = value => {
      const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
      const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
      const binary = atob(padded);
      const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
      return JSON.parse(new TextDecoder().decode(bytes));
    };

    const header = decode(parts[0]);
    const payload = decode(parts[1]);

    const issuer = "https://fancy-hat-29f2.cloudflareaccess.com";
    const audience = "a593424efda69151151cac5d734c32169cf878de0a55d0555649d20a48531bc3";

    if (header.alg !== "RS256" || !header.kid) return false;
    if (payload.iss !== issuer) return false;
    if (!Array.isArray(payload.aud) || !payload.aud.includes(audience)) return false;

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp <= now || payload.iat > now + 60) return false;
    if (payload.nbf && payload.nbf > now) return false;

    const certResponse = await fetch(`${issuer}/cdn-cgi/access/certs`);
    if (!certResponse.ok) return false;

    const certData = await certResponse.json();
    const jwk = certData.keys.find(key => key.kid === header.kid);
    if (!jwk) return false;

    const publicKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const signatureBase64 = parts[2].replace(/-/g, "+").replace(/_/g, "/");
    const paddedSignature = signatureBase64 + "=".repeat((4 - signatureBase64.length % 4) % 4);
    const signature = Uint8Array.from(atob(paddedSignature), c => c.charCodeAt(0));

    return await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      signature,
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
    );
  } catch (error) {
    console.error("Sponsored authentication error:", error);
    return false;
  }
}

const IMAGE_TYPES = {
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/webp": "webp",
  "image/gif": "gif"
};

const VIDEO_TYPES = {
  "video/mp4": "mp4",
  "video/webm": "webm"
};

function validImageSignature(bytes, type) {
  if (type === "image/jpeg") {
    return bytes.length >= 3 &&
      bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF;
  }

  if (type === "image/png") {
    return bytes.length >= 8 &&
      bytes[0] === 0x89 && bytes[1] === 0x50 &&
      bytes[2] === 0x4E && bytes[3] === 0x47 &&
      bytes[4] === 0x0D && bytes[5] === 0x0A &&
      bytes[6] === 0x1A && bytes[7] === 0x0A;
  }

  if (type === "image/webp") {
    return bytes.length >= 12 &&
      String.fromCharCode(...bytes.slice(0, 4)) === "RIFF" &&
      String.fromCharCode(...bytes.slice(8, 12)) === "WEBP";
  }

  if (type === "image/gif") {
    const signature = String.fromCharCode(...bytes.slice(0, 6));
    return signature === "GIF87a" || signature === "GIF89a";
  }

  return false;
}

function validVideoSignature(bytes, type) {
  if (type === "video/mp4") {
    return bytes.length >= 12 &&
      String.fromCharCode(...bytes.slice(4, 8)) === "ftyp";
  }

  if (type === "video/webm") {
    return bytes.length >= 4 &&
      bytes[0] === 0x1A && bytes[1] === 0x45 &&
      bytes[2] === 0xDF && bytes[3] === 0xA3;
  }

  return false;
}

export async function onRequestPost({ request, env }) {
  try {
    if (!await verifyAccessToken(request)) {
      return json({ success: false, message: "Authentication required." }, 401);
    }

    if (!env.SPONSORED_MEDIA) {
      return json({ success: false, message: "Sponsored media storage is unavailable." }, 500);
    }

    const role = (request.headers.get("X-Upload-Role") || "").trim().toLowerCase();

    if (!["main", "extra"].includes(role)) {
      return json({ success: false, message: "Invalid media role." }, 400);
    }

    const type = (request.headers.get("Content-Type") || "")
      .split(";")[0].trim().toLowerCase();

    const isVideo = type.startsWith("video/");
    const allowedTypes = isVideo ? VIDEO_TYPES : IMAGE_TYPES;
    const maxSize = isVideo ? 30 * 1024 * 1024 : 5 * 1024 * 1024;

    if (!Object.prototype.hasOwnProperty.call(allowedTypes, type)) {
      return json({ success: false, message: "File type not supported." }, 400);
    }

    const declaredLength = Number(request.headers.get("Content-Length") || 0);

    if (declaredLength > maxSize) {
      return json({ success: false, message: "File exceeds the permitted size." }, 413);
    }

    const bytes = new Uint8Array(await request.arrayBuffer());

    if (!bytes.length || bytes.length > maxSize) {
      return json({
        success: false,
        message: isVideo ? "Video must not exceed 30 MB." : "Image must not exceed 5 MB."
      }, bytes.length > maxSize ? 413 : 400);
    }

    const valid = isVideo
      ? validVideoSignature(bytes, type)
      : validImageSignature(bytes, type);

    if (!valid) {
      return json({ success: false, message: "File content does not match its file type." }, 400);
    }

    const extension = allowedTypes[type];
    const key = `sponsored-${crypto.randomUUID()}.${extension}`;

    await env.SPONSORED_MEDIA.put(key, bytes, {
      httpMetadata: {
        contentType: type,
        cacheControl: "public, max-age=31536000, immutable"
      },
      customMetadata: {
        role,
        uploadedAt: new Date().toISOString()
      }
    });

    return json({
      success: true,
      key,
      mediaType: isVideo ? "video" : "image"
    }, 201);

  } catch (error) {
    console.error("Sponsored upload error:", error);

    return json({
      success: false,
      message: "Unable to upload sponsored media.",
      diagnostic: String(error?.message || error)
    }, 500);
  }
      }
        export async function onRequestGet() {
  return json({
    success: true,
    message: "Sponsored upload endpoint is reachable."
  });
        }
