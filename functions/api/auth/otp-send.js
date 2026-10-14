
const ALLOWED_ORIGINS = new Set([
  "https://shukafrica.com",
  "https://www.shukafrica.com",
  "https://shukafrica.pages.dev"
]);

function json(data, status, origin) {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  };

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
  }

  return new Response(JSON.stringify(data), { status, headers });
}

export async function onRequestPost({ request, env }) {
  const origin = request.headers.get("Origin") || "";

  if (!ALLOWED_ORIGINS.has(origin)) {
    return json({ error: "Origin not allowed." }, 403, origin);
  }

  if (!env.AKOMASMS_API_KEY) {
    return json({ error: "Verification service is not configured." }, 500, origin);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON request." }, 400, origin);
  }

  if (!body || typeof body.phone !== "string") {
    return json({ error: "Enter a valid phone number." }, 400, origin);
  }

  let phone = body.phone.trim().replace(/[\s()-]/g, "");

  // Accept Ghanaian local format or international +233 format.
  if (/^0\d{9}$/.test(phone)) {
    phone = "+233" + phone.slice(1);
  }

  if (!/^\+233\d{9}$/.test(phone)) {
    return json({
      error: "Enter a valid Ghana phone number, e.g. +233241234567."
    }, 400, origin);
  }

  try {
    const upstream = await fetch(
      "https://api.akomasms.com/v1/otp/send",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${env.AKOMASMS_API_KEY}`,
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify({
          phone,
          sender_id: "AKOMASMS",
          expires_in: 300,
          length: 6,
          channel: "sms"
        })
      }
    );

    const result = await upstream.json().catch(() => ({}));

    if (!upstream.ok || result.success === false || !result.otp_id) {
      return json({
        error: "AkomaSMS could not start verification. Please try again later."
      }, 502, origin);
    }

    return json({
      success: true,
      otp_id: result.otp_id,
      expires_in: 300
    }, 200, origin);
  } catch {
    return json({
      error: "Verification service is temporarily unavailable."
    }, 502, origin);
  }
}

export async function onRequestOptions({ request }) {
  const origin = request.headers.get("Origin") || "";

  if (!ALLOWED_ORIGINS.has(origin)) {
    return new Response(null, { status: 403 });
  }

  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    }
  });
    }

