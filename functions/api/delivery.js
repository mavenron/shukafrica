const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

const MAX_CUSTOMER_PHOTO = 9 * 1024 * 1024;
const MAX_LOAD_PHOTO = 9 * 1024 * 1024;
const MAX_LOAD_VIDEO = 9 * 1024 * 1024;

const ALLOWED_IMAGE_TYPES = new Set([
  "image/jpeg",
  "image/png",
  "image/webp"
]);

const ALLOWED_VIDEO_TYPES = new Set([
  "video/mp4",
  "video/webm",
  "video/quicktime"
]);

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

function getOrigin(request) {
  return request.headers.get("Origin") || "";
}

function isAllowedOrigin(request) {
  const origin = getOrigin(request);
  return !origin || ALLOWED_ORIGINS.has(origin);
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";

  for (const part of cookieHeader.split(";")) {
    const index = part.indexOf("=");

    if (index < 0) continue;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    if (key === name) {
      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }
    }
  }

  return "";
}

function cleanText(value, maxLength = 500) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

function validateImage(file, maxSize) {
  if (!(file instanceof File)) {
    return "A required image file is missing.";
  }

  if (!ALLOWED_IMAGE_TYPES.has(file.type)) {
    return "Use a JPEG, PNG, or WebP image.";
  }

  if (file.size <= 0) {
    return "The image file is empty.";
  }

  if (file.size > maxSize) {
    return "The image must not exceed 9 MB.";
  }

  return "";
}

function validateVideo(file, maxSize) {
  if (!(file instanceof File)) {
    return "A valid video file is required.";
  }

  if (!ALLOWED_VIDEO_TYPES.has(file.type)) {
    return "Use an MP4, WebM, or QuickTime video.";
  }

  if (file.size <= 0) {
    return "The video file is empty.";
  }

  if (file.size > maxSize) {
    return "The video must not exceed 9 MB.";
  }

  return "";
}

function extensionForType(type) {
  const extensions = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
    "video/mp4": "mp4",
    "video/webm": "webm",
    "video/quicktime": "mov"
  };

  return extensions[type] || "";
}

function makeId() {
  return crypto.randomUUID();
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function savePrivateFile(bucket, file, prefix) {
  const extension = extensionForType(file.type);

  if (!extension) {
    throw new Error("Unsupported file type.");
  }

  const key = `${prefix}/${makeId()}.${extension}`;

  await bucket.put(key, file.stream(), {
    httpMetadata: {
      contentType: file.type,
      cacheControl: "private, no-store"
    },
    customMetadata: {
      originalName: cleanText(file.name, 120)
    }
  });

  return key;
}

async function deletePrivateFiles(bucket, keys) {
  await Promise.all(
    keys.filter(Boolean).map(async key => {
      try {
        await bucket.delete(key);
      } catch (error) {
        console.error("Private file cleanup failed:", error);
      }
    })
  );
}

function getSessionToken(request) {
  // Match this cookie name to the one used by your existing seller login.
  return getCookie(request, "seller_session");
}

async function getAuthenticatedSeller(request, env) {
  const token = getSessionToken(request);

  if (!token || token.length > 2048) {
    return null;
  }

  const tokenHash = await sha256(token);

  // Assumes seller_sessions contains token_hash, seller_id and expires_at.
  // If your existing login uses different column names, adapt this query
  // to the existing schema rather than changing the login system.
  const session = await env.DB.prepare(`
    SELECT seller_id, expires_at
    FROM seller_sessions
    WHERE token_hash = ?
    LIMIT 1
  `).bind(tokenHash).first();

  if (!session || !session.seller_id) {
    return null;
  }

  if (session.expires_at) {
    const expiry = new Date(session.expires_at).getTime();

    if (!Number.isFinite(expiry) || expiry <= Date.now()) {
      return null;
    }
  }

  return {
    sellerId: String(session.seller_id)
  };
}

async function getApprovedDeliveryPartner(request, env) {
  const seller = await getAuthenticatedSeller(request, env);

  if (!seller) return null;

  const partner = await env.DB.prepare(`
    SELECT id, seller_id, full_name, phone, status
    FROM delivery_partners
    WHERE seller_id = ?
    LIMIT 1
  `).bind(seller.sellerId).first();

  if (!partner || String(partner.status).toLowerCase() !== "approved") {
    return null;
  }

  return partner;
}

function parsePositiveNumber(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const number = Number(value);

  if (!Number.isFinite(number) || number < 0) {
    return null;
  }

  return number;
}

function normalizeCategory(value) {
  const category = cleanText(value, 30).toLowerCase();

  const allowed = new Set([
    "delivery",
    "passenger",
    "transport"
  ]);

  return allowed.has(category) ? category : "";
}

function normalizeRequestStatus(value) {
  return cleanText(value, 30).toLowerCase();
}

async function handleCreateRequest(request, env, origin) {
  if (!env.DB || !env.PRIVATE_MEDIA) {
    return json({
      success: false,
      error: "The delivery service is not configured."
    }, 500, origin);
  }

  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().includes("multipart/form-data")) {
    return json({
      success: false,
      error: "Submit the request using multipart form data."
    }, 415, origin);
  }

  let form;

  try {
    form = await request.formData();
  } catch {
    return json({
      success: false,
      error: "The submitted form could not be read."
    }, 400, origin);
  }

  const customerName = cleanText(form.get("customerName"), 120);
  const customerPhone = cleanText(form.get("customerPhone"), 40);
  const pickupLocation = cleanText(form.get("pickupLocation"), 500);
  const destinationLocation = cleanText(form.get("destinationLocation"), 500);
  const packageDetails = cleanText(
    form.get("specialInstructions") || form.get("packageDetails"),
    2000
  );
  const deliveryFor = cleanText(form.get("deliveryFor"), 20).toLowerCase();
  const recipientName = cleanText(form.get("recipientName"), 120);
  const recipientPhone = cleanText(form.get("recipientPhone"), 40);
  const category = normalizeCategory(form.get("category") || "delivery");

  if (
    !customerName ||
    !customerPhone ||
    !pickupLocation ||
    !destinationLocation
  ) {
    return json({
      success: false,
      error: "Enter your name, phone number, pickup location and destination."
    }, 400, origin);
  }

  if (!category) {
    return json({
      success: false,
      error: "Choose a valid delivery or transport category."
    }, 400, origin);
  }

  if (!["self", "other"].includes(deliveryFor)) {
    return json({
      success: false,
      error: "Choose whether the delivery is for yourself or someone else."
    }, 400, origin);
  }

  if (deliveryFor === "other" && (!recipientName || !recipientPhone)) {
    return json({
      success: false,
      error: "Enter the recipient's name and phone number."
    }, 400, origin);
  }

  // The customer selfie is mandatory.
  const customerPhoto = form.get("customerSelfie");
  const customerPhotoError = validateImage(
    customerPhoto,
    MAX_CUSTOMER_PHOTO
  );

  if (customerPhotoError) {
    return json({
      success: false,
      error: "Customer selfie: " + customerPhotoError
    }, 400, origin);
  }

  const offeredFare = parsePositiveNumber(form.get("offeredFare"));
  const agreedFare = parsePositiveNumber(form.get("agreedFare"));

  const passengerCountValue = cleanText(form.get("passengerCount"), 10);
  const passengerCount = passengerCountValue
    ? Number(passengerCountValue)
    : null;

  if (
    passengerCount !== null &&
    (!Number.isInteger(passengerCount) || passengerCount < 1 || passengerCount > 20)
  ) {
    return json({
      success: false,
      error: "Passenger count must be between 1 and 20."
    }, 400, origin);
  }

  const vehicleNeeded = cleanText(form.get("vehicleNeeded"), 100);
  const loadWeight = cleanText(form.get("loadWeight"), 100);
  const loadDimensions = cleanText(form.get("loadDimensions"), 150);

  const loadPhotos = form.getAll("loadPhotos").filter(
    file => file instanceof File && file.size > 0
  );

  const loadVideo = form.get("loadVideo");

  if (loadPhotos.length > 5) {
    return json({
      success: false,
      error: "You can upload a maximum of five load photos."
    }, 400, origin);
  }

  for (const photo of loadPhotos) {
    const error = validateImage(photo, MAX_LOAD_PHOTO);

    if (error) {
      return json({
        success: false,
        error: "Load photo: " + error
      }, 400, origin);
    }
  }

  if (loadVideo instanceof File && loadVideo.size > 0) {
    const error = validateVideo(loadVideo, MAX_LOAD_VIDEO);

    if (error) {
      return json({
        success: false,
        error: "Load video: " + error
      }, 400, origin);
    }
  }

  const uploadedKeys = [];
  const requestId = makeId();
  const now = new Date().toISOString();

  try {
    const customerPhotoKey = await savePrivateFile(
      env.PRIVATE_MEDIA,
      customerPhoto,
      `delivery/customers/${requestId}`
    );

    uploadedKeys.push(customerPhotoKey);

    const loadPhotoKeys = [];

    for (const photo of loadPhotos) {
      const key = await savePrivateFile(
        env.PRIVATE_MEDIA,
        photo,
        `delivery/loads/${requestId}`
      );

      uploadedKeys.push(key);
      loadPhotoKeys.push(key);
    }

    let loadVideoKey = null;

    if (loadVideo instanceof File && loadVideo.size > 0) {
      loadVideoKey = await savePrivateFile(
        env.PRIVATE_MEDIA,
        loadVideo,
        `delivery/loads/${requestId}`
      );

      uploadedKeys.push(loadVideoKey);
    }

    await env.DB.prepare(`
      INSERT INTO delivery_requests (
        id,
        customer_name,
        customer_phone,
        pickup_location,
        destination_location,
        package_details,
        delivery_for,
        recipient_name,
        recipient_phone,
        status,
        partner_id,
        partner_name,
        partner_phone,
        created_at,
        updated_at,
        category,
        customer_photo_key,
        passenger_count,
        vehicle_needed,
        load_weight,
        load_dimensions,
        load_photo_keys,
        load_video_key,
        agreed_fare
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )
    `).bind(
      requestId,
      customerName,
      customerPhone,
      pickupLocation,
      destinationLocation,
      packageDetails,
      deliveryFor,
      deliveryFor === "other" ? recipientName : null,
      deliveryFor === "other" ? recipientPhone : null,
      "pending",
      null,
      null,
      null,
      now,
      now,
      category,
      customerPhotoKey,
      passengerCount,
      vehicleNeeded || null,
      loadWeight || null,
      loadDimensions || null,
      JSON.stringify(loadPhotoKeys),
      loadVideoKey,
      agreedFare ?? offeredFare
    ).run();

    return json({
      success: true,
      message: "Your request has been submitted.",
      requestId
    }, 201, origin);
  } catch (error) {
    console.error("Delivery request creation failed:", error);

    await deletePrivateFiles(env.PRIVATE_MEDIA, uploadedKeys);

    return json({
      success: false,
      error: "Unable to create the delivery request. Please try again."
    }, 500, origin);
  }
}

async function handleGetRequests(request, env, origin) {
  if (!env.DB) {
    return json({
      success: false,
      error: "The delivery service is not configured."
    }, 500, origin);
  }

  const partner = await getApprovedDeliveryPartner(request, env);

  if (!partner) {
    return json({
      success: false,
      error: "Sign in with an approved delivery partner account to view available requests."
    }, 401, origin);
  }

  const url = new URL(request.url);
  const requestedCategory = cleanText(url.searchParams.get("category"), 30);
  const category = requestedCategory ? normalizeCategory(requestedCategory) : "";

  if (requestedCategory && !category) {
    return json({
      success: false,
      error: "Invalid request category."
    }, 400, origin);
  }

  try {
    let result;

    if (category) {
      result = await env.DB.prepare(`
        SELECT
          id,
          pickup_location,
          destination_location,
          package_details,
          status,
          created_at,
          category,
          passenger_count,
          vehicle_needed,
          load_weight,
          load_dimensions,
          agreed_fare
        FROM delivery_requests
        WHERE status = 'pending'
          AND category = ?
        ORDER BY created_at DESC
        LIMIT 100
      `).bind(category).all();
    } else {
      result = await env.DB.prepare(`
        SELECT
          id,
          pickup_location,
          destination_location,
          package_details,
          status,
          created_at,
          category,
          passenger_count,
          vehicle_needed,
          load_weight,
          load_dimensions,
          agreed_fare
        FROM delivery_requests
        WHERE status = 'pending'
        ORDER BY created_at DESC
        LIMIT 100
      `).all();
    }

    return json({
      success: true,
      requests: result.results || []
    }, 200, origin);
  } catch (error) {
    console.error("Loading delivery requests failed:", error);

    return json({
      success: false,
      error: "Unable to load delivery requests."
    }, 500, origin);
  }
}

async function handleUpdateRequest(request, env, origin) {
  if (!env.DB) {
    return json({
      success: false,
      error: "The delivery service is not configured."
    }, 500, origin);
  }

  const partner = await getApprovedDeliveryPartner(request, env);

  if (!partner) {
    return json({
      success: false,
      error: "An authenticated, approved delivery partner account is required."
    }, 401, origin);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json({
      success: false,
      error: "Invalid JSON request."
    }, 400, origin);
  }

  const id = cleanText(body.id, 100);
  const action = cleanText(body.action, 30).toLowerCase();

  if (!id) {
    return json({
      success: false,
      error: "The delivery request ID is required."
    }, 400, origin);
  }

  if (action !== "accept") {
    return json({
      success: false,
      error: "Unsupported request action."
    }, 400, origin);
  }

  const now = new Date().toISOString();

  try {
    // Atomic update prevents two partners from accepting the same request.
    const result = await env.DB.prepare(`
      UPDATE delivery_requests
      SET
        status = 'accepted',
        partner_id = ?,
        partner_name = ?,
        partner_phone = ?,
        updated_at = ?
      WHERE id = ?
        AND status = 'pending'
    `).bind(
      partner.id,
      partner.full_name,
      partner.phone,
      now,
      id
    ).run();

    if (!result.meta || result.meta.changes !== 1) {
      return json({
        success: false,
        error: "This request is no longer available. Refresh the list and try another."
      }, 409, origin);
    }

    return json({
      success: true,
      message: "The request has been assigned to your account."
    }, 200, origin);
  } catch (error) {
    console.error("Accepting delivery request failed:", error);

    return json({
      success: false,
      error: "Unable to accept this request."
    }, 500, origin);
  }
}

export async function onRequestOptions({ request }) {
  const origin = getOrigin(request);

  if (!isAllowedOrigin(request)) {
    return new Response(null, { status: 403 });
  }

  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    }
  });
}

export async function onRequestGet({ request, env }) {
  const origin = getOrigin(request);

  if (!isAllowedOrigin(request)) {
    return json({ success: false, error: "Origin not allowed." }, 403);
  }

  return handleGetRequests(request, env, origin);
}

export async function onRequestPost({ request, env }) {
  const origin = getOrigin(request);

  if (!isAllowedOrigin(request)) {
    return json({ success: false, error: "Origin not allowed." }, 403);
  }

  return handleCreateRequest(request, env, origin);
}

export async function onRequestPatch({ request, env }) {
  const origin = getOrigin(request);

  if (!isAllowedOrigin(request)) {
    return json({ success: false, error: "Origin not allowed." }, 403);
  }

  return handleUpdateRequest(request, env, origin);
    }
  
