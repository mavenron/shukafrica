
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

  if (!supplied || !expected) return false;

  if (supplied.length !== expected.length) return false;

  let difference = 0;

  for (let i = 0; i < supplied.length; i++) {
    difference |= supplied.charCodeAt(i) ^ expected.charCodeAt(i);
  }

  return difference === 0;
}

export async function onRequestGet({ request, env }) {
  if (!authorised(request, env)) {
    return json({ success: false, error: "Unauthorised" }, 401);
  }

  return json({
    success: true,
    message: "ShukAfrica admin authentication is working."
  });
}
