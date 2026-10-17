
function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "https://shukafrica.com",
      "Vary": "Origin"
    }
  });
}

function makeId() {
  return crypto.randomUUID();
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "https://shukafrica.com",
      "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400"
    }
  });
}

export async function onRequestGet({ env }) {
  try {
    const result = await env.DB.prepare(`
      SELECT id, pickup_location, destination_location,
             package_details, status, created_at
      FROM delivery_requests
      WHERE status = 'pending'
      ORDER BY created_at DESC
      LIMIT 100
    `).all();

    return json({ success: true, requests: result.results || [] });
  } catch (error) {
    return json({ success: false, error: "Unable to load delivery requests." }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json();

    const customerName = String(body.customerName || "").trim();
    const customerPhone = String(body.customerPhone || "").trim();
    const pickup = String(body.pickupLocation || "").trim();
    const destination = String(body.destinationLocation || "").trim();
    const packageDetails = String(body.packageDetails || "").trim();
    const deliveryFor = body.deliveryFor === "other" ? "other" : "myself";
    const recipientName = String(body.recipientName || "").trim();
    const recipientPhone = String(body.recipientPhone || "").trim();

    if (
      !customerName || !customerPhone || !pickup ||
      !destination || !packageDetails ||
      (deliveryFor === "other" && (!recipientName || !recipientPhone))
    ) {
      return json({ success: false, error: "Please complete all required fields." }, 400);
    }

    if (
      customerName.length > 120 ||
      customerPhone.length > 30 ||
      pickup.length > 200 ||
      destination.length > 200 ||
      packageDetails.length > 500 ||
      recipientName.length > 120 ||
      recipientPhone.length > 30
    ) {
      return json({ success: false, error: "One or more fields are too long." }, 400);
    }

    const id = makeId();

    await env.DB.prepare(`
      INSERT INTO delivery_requests (
        id, customer_name, customer_phone, pickup_location,
        destination_location, package_details, delivery_for,
        recipient_name, recipient_phone, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    `).bind(
      id, customerName, customerPhone, pickup, destination,
      packageDetails, deliveryFor,
      deliveryFor === "other" ? recipientName : null,
      deliveryFor === "other" ? recipientPhone : null
    ).run();

    return json({
      success: true,
      message: "Delivery request created.",
      requestId: id
    }, 201);
  } catch (error) {
    return json({ success: false, error: "Unable to create delivery request." }, 500);
  }
}

export async function onRequestPatch({ request, env }) {
  try {
    const body = await request.json();
    const id = String(body.id || "").trim();
    const action = String(body.action || "").trim();

    if (!id || !["accept", "release", "cancel"].includes(action)) {
      return json({ success: false, error: "Invalid request ID or action." }, 400);
    }

    if (action === "accept") {
      const partnerId = String(body.partnerId || "").trim();
      const partnerName = String(body.partnerName || "").trim();
      const partnerPhone = String(body.partnerPhone || "").trim();

      if (!partnerId || !partnerName || !partnerPhone) {
        return json({
          success: false,
          error: "Partner details are required."
        }, 400);
      }

      const result = await env.DB.prepare(`
        UPDATE delivery_requests
        SET status = 'accepted',
            partner_id = ?,
            partner_name = ?,
            partner_phone = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND status = 'pending'
      `).bind(partnerId, partnerName, partnerPhone, id).run();

      if (!result.meta.changes) {
        return json({
          success: false,
          error: "This request is no longer available."
        }, 409);
      }

      return json({ success: true, message: "Delivery accepted." });
    }

    if (action === "release") {
      const partnerId = String(body.partnerId || "").trim();

      if (!partnerId) {
        return json({ success: false, error: "Partner ID is required." }, 400);
      }

      const result = await env.DB.prepare(`
        UPDATE delivery_requests
        SET status = 'pending',
            partner_id = NULL,
            partner_name = NULL,
            partner_phone = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND status = 'accepted' AND partner_id = ?
      `).bind(id, partnerId).run();

      if (!result.meta.changes) {
        return json({
          success: false,
          error: "You cannot release this delivery."
        }, 403);
      }

      return json({ success: true, message: "Delivery released." });
    }

    const result = await env.DB.prepare(`
      UPDATE delivery_requests
      SET status = 'cancelled',
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND status = 'pending'
    `).bind(id).run();

    if (!result.meta.changes) {
      return json({
        success: false,
        error: "This request cannot be cancelled in its current state."
      }, 409);
    }

    return json({ success: true, message: "Delivery cancelled." });
  } catch (error) {
    return json({ success: false, error: "Unable to update delivery request." }, 500);
  }
      }
    
