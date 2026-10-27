
const SESSION_COOKIE = "shuk_open_market_session";

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Set-Cookie": [
        `${SESSION_COOKIE}=`,
        "Path=/",
        "Max-Age=0",
        "HttpOnly",
        "Secure",
        "SameSite=Lax"
      ].join("; ")
    }
  });
}

export async function onRequestPost() {
  return json({
    success: true,
    message: "You have been logged out."
  });
}
