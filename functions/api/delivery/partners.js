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
    "X-Content-Type-Options": "nosniff"
  };

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Credentials"] = "true";
    headers["Vary"] = "Origin";
  }

  return new Response(JSON.stringify(data), { status, headers });
}

function checkOrigin(request) {
  const origin = request.headers.get("Origin") || "";
  return ALLOWED_ORIGINS.has(origin) ? origin : null;
}

function getToken(request) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)shuk_seller_session=([^;]+)/);
  return match ? match[1] : "";
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
    !session.expires_at ||
    !Number.isFinite(Date.parse(session.expires_at)) ||
    Date.parse(session.expires_at) <= Date.now()
  ) return null;

  // The current SMS session does not provide a stable seller ID.
  if (!session.phone || !session.phone.startsWith("email:")) {
    return null;
  }

  const sellerId = session.phone.slice(6);

  return await env.DB.prepare(`
    SELECT id, name
    FROM sellers
    WHERE id = ?
    LIMIT 1
  `).bind(sellerId).first();
}

export async function onRequestOptions({ request }) {
  const origin = checkOrigin(request);
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
  const origin = checkOrigin(request);
  if (!origin) {
    return json({ success: false, error: "Origin not allowed." }, 403);
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
    console.error("Rider application lookup failed:", error);
    return json({
      success: false,
      error: "Unable to check application."
    }, 500, origin);
  }
}

export async function onRequestPost({ request, env }) {
  const origin = checkOrigin(request);
  if (!origin) {
    return json({ success: false, error: "Origin not allowed." }, 403);
  }

  let uploadedKey = null;

  try {
    const seller = await getSeller(request, env);
    if (!seller) {
      return json({
        success: false,
        error: "Please log in with your email account."
      }, 401, origin);
    }

    if (!env.DB || !env.PRIVATE_MEDIA) {
      return json({
        success: false,
        error: "Private storage or database is not configured."
      }, 503, origin);
    }

    const contentType = request.headers.get("Content-Type") || "";
    if (!contentType.toLowerCase().startsWith("multipart/form-data;")) {
      return json({
        success: false,
        error: "Please submit the form with an insurance image."
      }, 400, origin);
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

    const file = form.get("insuranceDocument");

    if (
      !fullName || !phone || !vehicleRegistration ||
      !alternativeContactName || !alternativeRelationship ||
      !alternativeContactPhone
    ) {
      return json({
        success: false,
        error: "Please complete all required text fields."
      }, 400, origin);
    }

    if (
      fullName.length > 120 ||
      phone.length > 30 ||
      vehicleRegistration.length > 30 ||
      alternativeContactName.length > 120 ||
      alternativeRelationship.length > 60 ||
      alternativeContactPhone.length > 30
    ) {
      return json({
        success: false,
        error: "One or more fields are too long."
      }, 400, origin);
    }

  
    if (
      !file ||
      typeof file === "string" ||
      typeof file.arrayBuffer !== "function" ||
      typeof file.size !== "number" ||
      file.size < 1
    ) {
      return json({
        success: false,
        error: "Insurance file diagnostic.",
        diagnostic: {
          present: Boolean(file),
          valueType: typeof file,
          hasArrayBuffer: Boolean(file && typeof file.arrayBuffer === "function"),
          sizeType: file ? typeof file.size : "missing",
          size: file && typeof file.size === "number" ? file.size : null,
          fileConstructor: file && file.constructor ? file.constructor.name : null
        }
      }, 400, origin);
    }

    if (file.size > MAX_FILE_SIZE) {
      return json({
        success: false,
        error: "Insurance image must be 2 MB or smaller."
      }, 413, origin);
    }

    const extension = ALLOWED_TYPES[file.type];
    if (!extension) {
      return json({
        success: false,
        error: "Use a JPG, PNG, or WebP insurance image."
      }, 415, origin);
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
        error: "You already have a pending or active rider application."
      }, 409, origin);
    }

    const id = crypto.randomUUID();
    uploadedKey = `rider-insurance/${seller.id}/${id}.${extension}`;

    // Store bytes only in the private R2 bucket.
    const bytes = await file.arrayBuffer();

    await env.PRIVATE_MEDIA.put(uploadedKey, bytes, {
      httpMetadata: { contentType: file.type }
    });

    await env.DB.prepare(`
      INSERT INTO delivery_partners (
        id, seller_id, full_name, phone, vehicle_registration,
        insurance_document_key, alternative_contact_name,
        alternative_relationship, alternative_contact_phone, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    `).bind(
      id,
      seller.id,
      fullName,
      phone,
      vehicleRegistration,
      uploadedKey,
      alternativeContactName,
      alternativeRelationship,
      alternativeContactPhone
    ).run();

    return json({
      success: true,
      message: "Application submitted for private admin review.",
      status: "pending"
    }, 201, origin);
  } catch (error) {
    console.error("Rider application submission failed:", error);

    if (uploadedKey && env.PRIVATE_MEDIA) {
      try {
        await env.PRIVATE_MEDIA.delete(uploadedKey);
      } catch (cleanupError) {
        console.error("Private upload cleanup failed.");
      }
    }

    
    return json({
      success: false,
      error: "Unable to submit rider application. Please try again."
    }, 500, origin);
  }
}

                  
