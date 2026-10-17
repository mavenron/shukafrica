
const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

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

  if (!session.phone.startsWith("email:")) {
    // SMS sessions do not expose a stable seller ID in the current
    // session implementation, so do not allow rider registration yet.
    return null;
  }

  const sellerId = session.phone.slice(6);

  const seller = await env.DB.prepare(`
    SELECT id, name
    FROM sellers
    WHERE id = ?
    LIMIT 1
  `).bind(sellerId).first();

  return seller || null;
}

function checkOrigin(request) {
  const origin = request.headers.get("Origin") || "";
  if (!origin || !ALLOWED_ORIGINS.has(origin)) return null;
  return origin;
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
  if (!origin) return json({ success: false, error: "Origin not allowed." }, 403);

  try {
    const seller = await getSeller(request, env);
    if (!seller) {
      return json({ success: false, error: "Please log in with your email account." }, 401, origin);
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
    return json({ success: false, error: "Unable to check application." }, 500, origin);
  }
}

export async function onRequestPost({ request, env }) {
  const origin = checkOrigin(request);
  if (!origin) return json({ success: false, error: "Origin not allowed." }, 403);

  try {
    const seller = await getSeller(request, env);
    if (!seller) {
      return json({ success: false, error: "Please log in with your email account." }, 401, origin);
    }

    if (!env.PRIVATE_MEDIA) {
      return json({ success: false, error: "Private storage is not configured." }, 503, origin);
    }

    const contentType = request.headers.get("Content-Type") || "";
    if (!contentType.toLowerCase().startsWith("multipart/form-data")) {
      return json({ success: false, error: "Submit the form with a file upload." }, 400, origin);
    }

    const form = await request.formData();

    const fullName = String(form.get("fullName") || "").trim();
    const phone = String(form.get("phone") || "").trim();
    const vehicleRegistration = String(form.get("vehicleRegistration") || "").trim();
    const alternativeContactName = String(form.get("alternativeContactName") || "").trim();
    const alternativeRelationship = String(form.get("alternativeRelationship") || "").trim();
    const alternativeContactPhone = String(form.get("alternativeContactPhone") || "").trim();
    const file = form.get("insuranceDocument");

    if (
      !fullName || !phone || !vehicleRegistration ||
      !alternativeContactName || !alternativeRelationship ||
      !alternativeContactPhone || !(file instanceof File) || file.size === 0
    ) {
      return json({ success: false, error: "Complete all fields and attach the insurance document." }, 400, origin);
    }

    if (
      fullName.length > 120 || phone.length > 30 ||
      vehicleRegistration.length > 30 ||
      alternativeContactName.length > 120 ||
      alternativeRelationship.length > 60 ||
      alternativeContactPhone.length > 30
    ) {
      return json({ success: false, error: "One or more fields are too long." }, 400, origin);
    }

    if (file.size > 2 * 1024 * 1024) {
      return json({ success: false, error: "Insurance image must be 2 MB or smaller." }, 400, origin);
    }

    const extensions = {
      "image/jpeg": "jpg",
      "image/png": "png",
      "image/webp": "webp"
    };

    const extension = extensions[file.type];
    if (!extension) {
      return json({ success: false, error: "Use a JPG, PNG, or WebP insurance image." }, 400, origin);
    }

    const existing = await env.DB.prepare(`
      SELECT id
      FROM delivery_partners
      WHERE seller_id = ? AND status IN ('pending', 'approved', 'suspended')
      LIMIT 1
    `).bind(seller.id).first();

    if (existing) {
      return json({ success: false, error: "You already have a pending or active rider application." }, 409, origin);
    }

    const id = crypto.randomUUID();
    const key = `rider-insurance/${seller.id}/${id}.${extension}`;

    // Store the document in the private bucket. Never return its URL.
    await env.PRIVATE_MEDIA.put(key, await file.arrayBuffer(), {
      httpMetadata: { contentType: file.type }
    });

    try {
      await env.DB.prepare(`
        INSERT INTO delivery_partners (
          id, seller_id, full_name, phone, vehicle_registration,
          insurance_document_key, alternative_contact_name,
          alternative_relationship, alternative_contact_phone, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
      `).bind(
        id, seller.id, fullName, phone, vehicleRegistration,
        key, alternativeContactName, alternativeRelationship,
        alternativeContactPhone
      ).run();
    } catch (dbError) {
      await env.PRIVATE_MEDIA.delete(key);
      throw dbError;
    }

    return json({
      success: true,
      message: "Application submitted for private admin review.",
      status: "pending"
    }, 201, origin);
  } catch (error) {
    console.error("Rider application submission failed:", error);
    return json({ success: false, error: "Unable to submit rider application." }, 500, origin);
  }
    }
                
