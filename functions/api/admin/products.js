function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function authorised(request, env) {
  const supplied = request.headers.get("X-Shuk-Admin-Key");
  const expected = env.SHUK_ADMIN_KEY;

  if (!supplied || !expected || supplied.length !== expected.length) {
    return false;
  }

  let difference = 0;
  for (let i = 0; i < supplied.length; i++) {
    difference |= supplied.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return difference === 0;
}

function requireAdmin(request, env) {
  return authorised(request, env)
    ? null
    : json({ success: false, error: "Unauthorised" }, 401);
}

const fields = [
  "category", "item_name", "price_ghs", "description",
  "condition", "availability", "warranty",
  "image_1", "image_2", "image_3", "video_url"
];

function cleanText(value, max = 2000) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, max);
}

function validMedia(value) {
  if (value === null || value === undefined || value === "") return true;
  if (typeof value !== "string" || value.length > 2000) return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:";
  } catch {
    return false;
  }
}

function validate(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return "A JSON object is required.";
  }

  if (!cleanText(body.category, 100) ||
      !cleanText(body.item_name, 200) ||
      !cleanText(body.description, 5000)) {
    return "Category, product name and description are required.";
  }

  if (body.price_ghs !== null && body.price_ghs !== undefined &&
      body.price_ghs !== "") {
    if (!Number.isFinite(Number(body.price_ghs)) ||
        Number(body.price_ghs) < 0) {
      return "Price must be a valid non-negative number.";
    }
  }

  for (const key of ["image_1", "image_2", "image_3", "video_url"]) {
    if (!validMedia(body[key])) {
      return key + " must be a valid HTTPS URL.";
    }
  }

  return null;
}

function valuesFrom(body) {
  return {
    category: cleanText(body.category, 100),
    item_name: cleanText(body.item_name, 200),
    price_ghs: body.price_ghs === "" ||
      body.price_ghs === undefined ||
      body.price_ghs === null ? null : Number(body.price_ghs),
    description: cleanText(body.description, 5000),
    condition: cleanText(body.condition, 100) || "Not specified",
    availability: cleanText(body.availability, 200) ||
      "Confirm before ordering",
    warranty: cleanText(body.warranty, 200) ||
      "Confirm before ordering",
    image_1: cleanText(body.image_1, 2000) || null,
    image_2: cleanText(body.image_2, 2000) || null,
    image_3: cleanText(body.image_3, 2000) || null,
    video_url: cleanText(body.video_url, 2000) || null
  };
}

export async function onRequestGet({ request, env }) {
  const denied = requireAdmin(request, env);
  if (denied) return denied;

  const result = await env.DB.prepare(`
    SELECT id, category, item_name, price_ghs, description,
      condition, availability, warranty, image_1, image_2,
      image_3, video_url, is_published, created_at, updated_at
    FROM global_products
    ORDER BY created_at DESC
    LIMIT 200
  `).all();

  return json({ success: true, products: result.results || [] });
}

export async function onRequestPost({ request, env }) {
  const denied = requireAdmin(request, env);
  if (denied) return denied;

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, error: "Invalid JSON." }, 400);
  }

  const problem = validate(body);
  if (problem) return json({ success: false, error: problem }, 400);

  const p = valuesFrom(body);
  const id = crypto.randomUUID();

  await env.DB.prepare(`
    INSERT INTO global_products (
      id, category, item_name, price_ghs, description,
      condition, availability, warranty, image_1, image_2,
      image_3, video_url, is_published
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
  `).bind(
    id, p.category, p.item_name, p.price_ghs, p.description,
    p.condition, p.availability, p.warranty, p.image_1,
    p.image_2, p.image_3, p.video_url
  ).run();

  return json({ success: true, id, message: "Product saved as unpublished." }, 201);
}

export async function onRequestPatch({ request, env }) {
  const denied = requireAdmin(request, env);
  if (denied) return denied;

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, error: "Invalid JSON." }, 400);
  }

  if (!body || typeof body.id !== "string" || !body.id.trim()) {
    return json({ success: false, error: "Product ID is required." }, 400);
  }

  const id = body.id.trim();

  if (typeof body.is_published === "boolean" &&
      Object.keys(body).every(k => ["id", "is_published"].includes(k))) {
    const result = await env.DB.prepare(`
      UPDATE global_products
      SET is_published = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(body.is_published ? 1 : 0, id).run();

    if (!result.meta.changes) {
      return json({ success: false, error: "Product not found." }, 404);
    }

    return json({ success: true, message: "Publication status updated." });
  }

  const problem = validate(body);
  if (problem) return json({ success: false, error: problem }, 400);

  const p = valuesFrom(body);
  const result = await env.DB.prepare(`
    UPDATE global_products SET
      category = ?, item_name = ?, price_ghs = ?, description = ?,
      condition = ?, availability = ?, warranty = ?, image_1 = ?,
      image_2 = ?, image_3 = ?, video_url = ?,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).bind(
    p.category, p.item_name, p.price_ghs, p.description,
    p.condition, p.availability, p.warranty, p.image_1,
    p.image_2, p.image_3, p.video_url, id
  ).run();

  if (!result.meta.changes) {
    return json({ success: false, error: "Product not found." }, 404);
  }

  return json({ success: true, message: "Product updated." });
}

export async function onRequestDelete({ request, env }) {
  const denied = requireAdmin(request, env);
  if (denied) return denied;

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, error: "Invalid JSON." }, 400);
  }

  if (!body || typeof body.id !== "string" || !body.id.trim()) {
    return json({ success: false, error: "Product ID is required." }, 400);
  }

  const result = await env.DB.prepare(
    "DELETE FROM global_products WHERE id = ?"
  ).bind(body.id.trim()).run();

  if (!result.meta.changes) {
    return json({ success: false, error: "Product not found." }, 404);
  }

  return json({ success: true, message: "Product deleted." });
}
