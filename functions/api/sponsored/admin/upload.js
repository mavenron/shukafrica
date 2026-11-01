function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json"
    }
  });
}

async function verifyAccessToken(request) {
  const token = request.headers.get("Cf-Access-Jwt-Assertion");

  if (!token) return false;

  try {
    const parts = token.split(".");
    if (parts.length !== 3) return false;

    const decode = (value) => {
      const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
      const binary = atob(normalized);
      const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
      return JSON.parse(new TextDecoder().decode(bytes));
    };

    const header = decode(parts[0]);
    const payload = decode(parts[1]);

    const issuer = "https://fancy-hat-29f2.cloudflareaccess.com";
    const audience = "0fd0b431-dd59-4d58-a460-215742885ea4";

    if (header.alg !== "RS256" || !header.kid) return false;
    if (payload.iss !== issuer) return false;
    if (!Array.isArray(payload.aud) || !payload.aud.includes(audience)) {
      return false;
    }

    const now = Math.floor(Date.now() / 1000);

    if (payload.exp <= now) return false;
    if (payload.iat > now + 60) return false;
    if (payload.nbf && payload.nbf > now) return false;

    const certResponse = await fetch(`${issuer}/cdn-cgi/access/certs`);
    if (!certResponse.ok) return false;

    const certData = await certResponse.json();
    const jwk = certData.keys.find(key => key.kid === header.kid);

    if (!jwk) return false;

    const publicKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
      },
      false,
      ["verify"]
    );

    const signature = Uint8Array.from(
      atob(parts[2].replace(/-/g, "+").replace(/_/g, "/")),
      c => c.charCodeAt(0)
    );

    const valid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      signature,
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
    );

    return valid;
  } catch {
    return false;
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const authenticated = await verifyAccessToken(request);

    if (!authenticated) {
      return json({
        success: false,
        message: "Authentication required."
      }, 401);
    }

    const formData = await request.formData();
    const file = formData.get("file");
    const role = formData.get("role");

    if (!file || typeof file === "string" || typeof file.stream !== "function") {
      return json({
        success: false,
        message: "Please select a valid file."
      }, 400);
    }

    const allowedTypes = {
      "image/jpeg": "jpg",
      "image/png": "png",
      "image/webp": "webp",
      "image/gif": "gif",
      "video/mp4": "mp4",
      "video/webm": "webm"
    };

    const extension = allowedTypes[file.type];

    if (!extension) {
      return json({
        success: false,
        message: "File type not supported."
      }, 400);
    }

    const isVideo = file.type.startsWith("video/");
    const maxSize = isVideo ? 30 * 1024 * 1024 : 5 * 1024 * 1024;

    if (file.size <= 0 || file.size > maxSize) {
      return json({
        success: false,
        message: isVideo
          ? "Video must not exceed 30 MB."
          : "Image must not exceed 5 MB."
      }, 400);
    }

    if (!["main", "extra"].includes(role)) {
      return json({
        success: false,
        message: "Invalid media role."
      }, 400);
    }

    if (!env.SPONSORED_MEDIA) {
      return json({
        success: false,
        message: "Sponsored media storage is unavailable."
      }, 500);
    }

    const key = `sponsored-${crypto.randomUUID()}.${extension}`;

    await env.SPONSORED_MEDIA.put(key, file.stream(), {
      httpMetadata: {
        contentType: file.type,
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
    });

  } catch (error) {
    return json({
      success: false,
      message: "Unable to upload sponsored media."
    }, 500);
  }
      }
