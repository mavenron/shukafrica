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
  if (!supplied || !expected || supplied.length !== expected.length) return false;
  let difference = 0;
  for (let i = 0; i < supplied.length; i++) {
    difference |= supplied.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return difference === 0;
}

function requireAdmin(request, env) {
  return authorised(request, env) ? null : json({ success: false, error: "Unauthorised" }, 401);
}

export async function onRequestPost({ request, env }) {
  const denied = requireAdmin(request, env);
  if (denied) return denied;

  const contentType = request.headers.get("Content-Type") || "";
  let formKeys = [];
  let fileInfo = "None";

  try {
    const form = await request.formData();
    formKeys = [...form.keys()];
    const file = form.get("file");
    if (file) {
      fileInfo = {
        name: file.name,
        size: file.size,
        type: file.type,
        isString: typeof file === "string",
        hasStream: typeof file.stream === "function"
      };
    } else {
      // Check if any other key exists
      for (const [k, v] of form.entries()) {
        if (v && typeof v === "object") {
          fileInfo = `Found under key '${k}': size=${v.size}, type=${v.type}`;
          break;
        }
      }
    }
  } catch (err) {
    fileInfo = "Error reading form: " + err.message;
  }

  // This will display the full JSON diagnostic right on your screen!
  return json({
    success: false,
    error: JSON.stringify({ contentType, formKeys, fileInfo }, null, 2)
  }, 400);
}
