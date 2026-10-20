const MAX_CUSTOMER_PHOTO = 9 * 1024 * 1024;
const MAX_LOAD_PHOTO = 9 * 1024 * 1024;
const MAX_LOAD_VIDEO = 20 * 1024 * 1024;
const MAX_LOAD_PHOTOS = 1;

const IMAGE_TYPES = {
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/webp": "webp"
};

const VIDEO_TYPES = {
  "video/mp4": "mp4",
  "video/webm": "webm",
  "video/quicktime": "mov"
};

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

function textValue(form, name, maxLength = 500) {
  const value = form.get(name);
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}


function isUploadedFile(value) {
  return Boolean(
    value &&
    typeof value === "object" &&
    typeof value.name === "string" &&
    value.name.length > 0 &&
    typeof value.arrayBuffer === "function" &&
    typeof value.size === "number" &&
    value.size > 0 &&
    typeof value.type === "string" &&
    value.type.length > 0
  );
}

function isEmptyFileEntry(value) {
  return (
    value == null ||
    value === "" ||
    (
      typeof value === "object" &&
      typeof value.size === "number" &&
      value.size === 0 &&
      (!value.name || value.name === "")
    )
  );
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

async function getApprovedAgent(request, env) {
  const seller = await getSeller(request, env);
  if (!seller) return null;

  const agent = await env.DB.prepare(`
    SELECT id, seller_id, full_name, phone, status
    FROM delivery_partners
    WHERE seller_id = ?
      AND status = 'approved'
    ORDER BY created_at DESC
    LIMIT 1
  `).bind(seller.id).first();

  return agent || null;
}

async function savePrivateFile(env, key, file) {
  await env.PRIVATE_MEDIA.put(key, await file.arrayBuffer(), {
    httpMetadata: {
      contentType: file.type,
      cacheControl: "private, no-store"
    }
  });
}

async function removeUploadedFiles(env, keys) {
  for (const key of keys) {
    try {
      await env.PRIVATE_MEDIA.delete(key);
    } catch (error) {
      console.error("Private media cleanup failed.");
    }
  }
}

function validateImage(file, maxSize) {
  if (!isUploadedFile(file)) {
    return "A required image is missing or was not uploaded as a file.";
  }

  if (file.size > maxSize) {
    return "The image must be 9 MB or smaller.";
  }

  if (!IMAGE_TYPES[file.type]) {
    return "Images must be JPG, PNG or WebP.";
  }

  return null;
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      "Allow": "GET, POST, PATCH, OPTIONS",
      "Cache-Control": "no-store"
    }
  });
}

export async function onRequestGet({ env, request }) {
  if (!env.DB) {
    return json({ success: false, error: "Database unavailable." }, 503);
  }

  try {
    const category = new URL(request.url).searchParams.get("category");
    const allowedCategories = ["delivery", "ride", "haulage"];

    const result = category && allowedCategories.includes(category)
      ? await env.DB.prepare(`
          SELECT
            id, category, pickup_location, destination_location,
            package_details, passenger_count, vehicle_needed,
            load_weight, load_dimensions, status, created_at
          FROM delivery_requests
          WHERE status = 'pending' AND category = ?
          ORDER BY created_at DESC
          LIMIT 100
        `).bind(category).all()
      : await env.DB.prepare(`
          SELECT
            id, category, pickup_location, destination_location,
            package_details, passenger_count, vehicle_needed,
            load_weight, load_dimensions, status, created_at
          FROM delivery_requests
          WHERE status = 'pending'
          ORDER BY created_at DESC
          LIMIT 100
        `).all();

    return json({
      success: true,
      requests: result.results || []
    });
  } catch (error) {
    console.error("Delivery request listing failed:", error);
    return json({
      success: false,
      error: "Unable to load live requests."
    }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  if (!env.DB || !env.PRIVATE_MEDIA) {
    return json({
      success: false,
      error: "Database or private storage is not configured."
    }, 503);
  }

  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().startsWith("multipart/form-data;")) {
    return json({
      success: false,
      error: "Please submit the request with its required photo."
    }, 400);
  }

  const savedKeys = [];

  try {
    const form = await request.formData();

    const customerName = textValue(form, "customerName", 120);
    const customerPhone = textValue(form, "customerPhone", 30);
    const pickup = textValue(form, "pickupLocation", 250);
    const destination = textValue(form, "destinationLocation", 250);
    const packageDetails = textValue(form, "packageDetails", 2000);

    const rawCategory = textValue(form, "category", 20).toLowerCase();
    const category = ["delivery", "ride", "haulage"].includes(rawCategory)
      ? rawCategory
      : "delivery";

    const deliveryFor =
      textValue(form, "deliveryFor", 20) === "other" ? "other" : "myself";

    const recipientName = textValue(form, "recipientName", 120);
    const recipientPhone = textValue(form, "recipientPhone", 30);

    const passengerText = textValue(form, "passengerCount", 5);
    const passengerCount = passengerText ? Number(passengerText) : null;

    const vehicleNeeded = textValue(form, "vehicleNeeded", 120);
    const loadWeight = textValue(form, "loadWeight", 100);
    const loadDimensions = textValue(form, "loadDimensions", 100);

    if (
      !customerName || !customerPhone || !pickup ||
      !destination ||
      (category !== "ride" && !packageDetails)
    ) {
      return json({
        success: false,
        error: "Complete all required request fields."
      }, 400);
    }

    if (
      customerName.length > 120 ||
      customerPhone.length > 30 ||
      pickup.length > 250 ||
      destination.length > 250 ||
      packageDetails.length > 2000
    ) {
      return json({
        success: false,
        error: "One or more fields are too long."
      }, 400);
    }

    if (
      deliveryFor === "other" &&
      (!recipientName || !recipientPhone)
    ) {
      return json({
        success: false,
        error: "Enter the recipient's name and phone number."
      }, 400);
    }

    if (
      category === "ride" &&
      (!Number.isInteger(passengerCount) ||
       passengerCount < 1 ||
       passengerCount > 8)
    ) {
      return json({
        success: false,
        error: "Enter a valid passenger count."
      }, 400);
    }

    if (category === "haulage" && !vehicleNeeded) {
      return json({
        success: false,
        error: "Select the vehicle needed for haulage."
      }, 400);
    }

    if (
      category === "haulage" &&
      !loadWeight &&
      !loadDimensions
    ) {
      return json({
        success: false,
        error: "Provide the estimated load weight or dimensions."
      }, 400);
    }

    const customerPhoto = form.get("customerSelfie");
    const customerPhotoError =
      validateImage(customerPhoto, MAX_CUSTOMER_PHOTO);

    if (customerPhotoError) {
      return json({
        success: false,
        error: "Customer selfie: " + customerPhotoError
      }, 400);
    }

    const rawLoadPhotos = form.getAll("loadPhotos");
    const loadPhotos = rawLoadPhotos.filter(isUploadedFile);
    const rawVideo = form.get("loadVideo");
    const loadVideo = isUploadedFile(rawVideo) ? rawVideo : null;

    if (
      category !== "haulage" &&
      (rawLoadPhotos.some(isUploadedFile) || loadVideo)
    ) {
      return json({
        success: false,
        error: "Load photos and video are only allowed for haulage."
      }, 400);
    }

    if (rawLoadPhotos.some(value =>
  !isEmptyFileEntry(value) && !isUploadedFile(value)
)) {
      return json({
        success: false,
        error: "The haulage photo upload is invalid."
      }, 400);
    }

    if (loadPhotos.length > MAX_LOAD_PHOTOS) {
      return json({
        success: false,
        error: "Upload only one haulage photo."
      }, 400);
    }

    for (const photo of loadPhotos) {
      const error = validateImage(photo, MAX_LOAD_PHOTO);
      if (error) {
        return json({
          success: false,
          error: "Haulage photo: " + error
        }, 400);
      }
    }

    if (!isEmptyFileEntry(rawVideo) && !loadVideo) {
      return json({
        success: false,
        error: "The haulage video upload is invalid."
      }, 400);
    }

    if (loadVideo) {
      if (loadVideo.size > MAX_LOAD_VIDEO) {
        return json({
          success: false,
          error: "The haulage video must be 20 MB or smaller."
        }, 400);
      }

      if (!VIDEO_TYPES[loadVideo.type]) {
        return json({
          success: false,
          error: "The haulage video must be MP4, WebM or MOV."
        }, 400);
      }
    }

    const id = crypto.randomUUID();

    const customerExtension = IMAGE_TYPES[customerPhoto.type];
    const customerKey =
      `customer-requests/${id}/customer.${customerExtension}`;

    await savePrivateFile(env, customerKey, customerPhoto);
    savedKeys.push(customerKey);

    const loadPhotoKeys = [];

    for (let index = 0; index < loadPhotos.length; index++) {
      const photo = loadPhotos[index];
      const extension = IMAGE_TYPES[photo.type];
      const key = `customer-requests/${id}/load-${index + 1}.${extension}`;

      await savePrivateFile(env, key, photo);
      savedKeys.push(key);
      loadPhotoKeys.push(key);
    }

    let videoKey = null;

    if (loadVideo) {
      const extension = VIDEO_TYPES[loadVideo.type];
      videoKey = `customer-requests/${id}/load-video.${extension}`;

      await savePrivateFile(env, videoKey, loadVideo);
      savedKeys.push(videoKey);
    }

    await env.DB.prepare(`
      INSERT INTO delivery_requests (
        id, customer_name, customer_phone,
        pickup_location, destination_location, package_details,
        delivery_for, recipient_name, recipient_phone, status,
        category, customer_photo_key, passenger_count,
        vehicle_needed, load_weight, load_dimensions,
        load_photo_keys, load_video_key
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending',
        ?, ?, ?, ?, ?, ?, ?, ?
      )
    `).bind(
      id,
      customerName,
      customerPhone,
      pickup,
      destination,
      packageDetails,
      deliveryFor,
      deliveryFor === "other" ? recipientName : null,
      deliveryFor === "other" ? recipientPhone : null,
      category,
      customerKey,
      category === "ride" ? passengerCount : null,
      category === "haulage" ? vehicleNeeded || null : null,
      category === "haulage" ? loadWeight || null : null,
      category === "haulage" ? loadDimensions || null : null,
      loadPhotoKeys.length ? JSON.stringify(loadPhotoKeys) : null,
      videoKey
    ).run();

    return json({
      success: true,
      message: "Your request has been submitted successfully.",
      requestId: id,
      status: "pending"
    }, 201);
  } catch (error) {
    console.error("Delivery request creation failed:", error);
    await removeUploadedFiles(env, savedKeys);

    return json({
      success: false,
      error: "Unable to submit the request. Please try again."
    }, 500);
  }
}

export async function onRequestPatch({ request, env }) {
  if (!env.DB) {
    return json({ success: false, error: "Database unavailable." }, 503);
  }

  try {
    const agent = await getApprovedAgent(request, env);

    if (!agent) {
      return json({
        success: false,
        error: "Log in with your email account and obtain agent approval first."
      }, 401);
    }

    const body = await request.json();
    const id = String(body.id || "").trim();
    const action = String(body.action || "").trim();

    if (!id || id.length > 100 || !["accept", "release"].includes(action)) {
      return json({
        success: false,
        error: "Invalid request ID or action."
      }, 400);
    }

    if (action === "accept") {
      const result = await env.DB.prepare(`
        UPDATE delivery_requests
        SET status = 'accepted',
            partner_id = ?,
            partner_name = ?,
            partner_phone = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND status = 'pending'
      `).bind(agent.id, agent.full_name, agent.phone, id).run();

      if (!result.meta || !result.meta.changes) {
        return json({
          success: false,
          error: "This request is no longer available."
        }, 409);
      }

      return json({ success: true, message: "Request accepted." });
    }

    const result = await env.DB.prepare(`
      UPDATE delivery_requests
      SET status = 'pending',
          partner_id = NULL,
          partner_name = NULL,
          partner_phone = NULL,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
        AND status = 'accepted'
        AND partner_id = ?
    `).bind(id, agent.id).run();

    if (!result.meta || !result.meta.changes) {
      return json({
        success: false,
        error: "You cannot release this request."
      }, 403);
    }

    return json({ success: true, message: "Request released." });
  } catch (error) {
    console.error("Delivery request action failed:", error);

    return json({
      success: false,
      error: "Unable to update the request."
    }, 500);
  }
    }
        
