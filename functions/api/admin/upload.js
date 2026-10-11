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
    }
  } catch (err) {
    fileInfo = "Error reading form: " + err.message;
  }

  // This will return a 400 error displaying exactly what keys and file info reached the server!
  return json({
    success: false,
    error: "DIAGNOSTIC INFO",
    diagnostic: {
      contentType,
      formKeys,
      fileInfo
    }
  }, 400);
}
