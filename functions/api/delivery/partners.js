const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

const MAX_FILE_SIZE = 2 * 1024 * 1024;

const ALLOWED_TYPES = {
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/webp": "webp"
};

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

  return new Response(JSON.stringify(data), { status, headers });
}

function getOrigin(request) {
  const origin = request.headers.get("Origin") || "";
  return ALLOWED_ORIGINS.has(origin) ? origin : null;
}

function getToken(request) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)shuk_seller_session=([^;]+)/);
  if (!match) return "";

  try {
    return decodeURIComponent(match[1]);
  } catch {
    return match[1];
  }
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

async function getSeller(request, env) {
  const token = getToken(request);
  if (!token || token.length > 200) return null;

  const session = await env.DB.prepare(`
    SELECT phone, expires_at
    FROM seller_sessions
    WHERE token_hash = ?
    LIMIT 1
  `).bind(await sha256(token)).first();

  if (
    !session ||
    !session.phone ||
    !session.phone.startsWith("email:") ||
    !session.expires_at ||
    !Number.isFinite(Date.parse(session.expires_at)) ||
    Date.parse(session.expires_at) <= Date.now()
  ) {
    return null;
  }

  return env.DB.prepare(`
    SELECT id, name
    FROM sellers
    WHERE id = ?
    LIMIT 1
  `).bind(session.phone.slice(6)).first();
}

function validText(value, maxLength) {
  return typeof value === "string" &&
    value.trim().length > 0 &&
    value.trim().length <= maxLength;
}

function getImage(form, fieldName) {
  const entries = form.getAll(fieldName);

  if (entries.length !== 1) {
    return { error: `${fieldName} must contain exactly one uploaded image.` };
  }

  const file = entries[0];

  // A genuine browser upload should be represented by a File/Blob-like object,
  // not a text field containing a filename.
  if (
    !(file instanceof File) ||
    !file.name ||
    file.size < 1 ||
    typeof file.arrayBuffer !== "function"
  ) {
    return {
      error: `${fieldName} was not received as an uploaded file. Please reselect the image and try again.`
    };
  }

  if (file.size > MAX_FILE_SIZE) {
    return { error: `${fieldName} must be 2 MB or smaller.` };
  }

  const extension = ALLOWED_TYPES[file.type];

  if (!extension) {
    return { error: `${fieldName} must be JPG, PNG or WebP.` };
  }

  return { file, extension };
}

async function savePrivateImage(env, key, file) {
  await env.PRIVATE_MEDIA.put(key, await file.arrayBuffer(), {
    httpMetadata: {
      contentType: file.type,
      cacheControl: "private, no-store"
    }
  });
}

async function deleteIfPresent(env, key) {
  if (!key) return;

  try {
    await env.PRIVATE_MEDIA.delete(key);
  } catch {
    console.error("Private image cleanup failed.");
  }
}

export async function onRequestOptions({ request }) {
  const origin = getOrigin(request);

  if (!origin) return new Response(null, { status: 403 });

  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    }
  });
}

export async function onRequestGet({ request, env }) {
  const origin = getOrigin(request);

  if (!origin) {
    return json({ success: false, error: "Origin not allowed." }, 403);
  }

  if (!env.DB) {
    return json({ success: false, error: "Database unavailable." }, 503, origin);
  }

  try {
    const seller = await getSeller(request, env);

    if (!seller) {
      return json({
        success: false,
        error: "Please log in with your email account."
      }, 401, origin);
    }

    const application = await env.DB.prepare(`
      SELECT id, status, created_at, updated_at
      FROM delivery_partners
      WHERE seller_id = ?
      ORDER BY created_at DESC
      LIMIT 1
    `).bind(seller.id).first();

    return json({
      success: true,
      application: application || null
    }, 200, origin);
  } catch (error) {
    console.error("Agent application lookup failed:", error);

    return json({
      success: false,
      error: "Unable to check your application."
    }, 500, origin);
  }
}

export async function onRequestPost({ request, env }) {
  const origin = getOrigin(request);

  if (!origin) {
    return json({ success: false, error: "Origin not allowed." }, 403);
  }

  if (!env.DB || !env.PRIVATE_MEDIA) {
    return json({
      success: false,
      error: "Database or private storage is not configured."
    }, 503, origin);
  }

  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().includes("multipart/form-data")) {
    return json({
      success: false,
      error: "The form must be submitted as multipart file data."
    }, 415, origin);
  }

  let insuranceKey = null;
  let selfieKey = null;

  try {
    const seller = await getSeller(request, env);

    if (!seller) {
      return json({
        success: false,
        error: "Please log in with your email account."
      }, 401, origin);
    }

    const form = await request.formData();

    const fullName = String(form.get("fullName") || "").trim();
    const phone = String(form.get("phone") || "").trim();
    const vehicleRegistration =
      String(form.get("vehicleRegistration") || "").trim();
    const alternativeContactName =
      String(form.get("alternativeContactName") || "").trim();
    const alternativeRelationship =
      String(form.get("alternativeRelationship") || "").trim();
    const alternativeContactPhone =
      String(form.get("alternativeContactPhone") || "").trim();

    if (
      !validText(fullName, 120) ||
      !validText(phone, 30) ||
      !validText(vehicleRegistration, 40) ||
      !validText(alternativeContactName, 120) ||
      !validText(alternativeRelationship, 80) ||
      !validText(alternativeContactPhone, 30)
    ) {
      return json({
        success: false,
        error: "Complete all required text fields within the allowed lengths."
      }, 400, origin);
    }

    const insuranceResult = getImage(form, "insuranceDocument");
    if (insuranceResult.error) {
      return json({
        success: false,
        error: insuranceResult.error
      }, 400, origin);
    }

    const selfieResult = getImage(form, "riderSelfie");
    if (selfieResult.error) {
      return json({
        success: false,
        error: selfieResult.error
      }, 400, origin);
    }

    const existing = await env.DB.prepare(`
      SELECT id
      FROM delivery_partners
      WHERE seller_id = ?
        AND status IN ('pending', 'approved', 'suspended')
      LIMIT 1
    `).bind(seller.id).first();

    if (existing) {
      return json({
        success: false,
        error: "You already have a pending or active agent application."
      }, 409, origin);
    }

    const id = crypto.randomUUID();

    insuranceKey =
      `rider-insurance/${seller.id}/${id}.${insuranceResult.extension}`;
    selfieKey =
      `rider-selfies/${seller.id}/${id}.${selfieResult.extension}`;

    await savePrivateImage(env, insuranceKey, insuranceResult.file);
    await savePrivateImage(env, selfieKey, selfieResult.file);

    await env.DB.prepare(`
      INSERT INTO delivery_partners (
        id, seller_id, full_name, phone, vehicle_registration,
        insurance_document_key, rider_selfie_key,
        alternative_contact_name, alternative_relationship,
        alternative_contact_phone, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    `).bind(
      id,
      seller.id,
      fullName,
      phone,
      vehicleRegistration,
      insuranceKey,
      selfieKey,
      alternativeContactName,
      alternativeRelationship,
      alternativeContactPhone
    ).run();

    // The images are stored privately. Do not return their storage keys.
    return json({
      success: true,
      message: "Your agent application has been submitted for admin review.",
      status: "pending"
    }, 201, origin);
  } catch (error) {
    console.error("Agent application submission failed:", error);

    await deleteIfPresent(env, insuranceKey);
    await deleteIfPresent(env, selfieKey);

    return json({
      success: false,
      error: "Unable to submit your application. Please try again."
    }, 500, origin);
  }
}
