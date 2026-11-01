export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "GET") {
    return new Response("Method not allowed", {
      status: 405
    });
  }

  const url = new URL(request.url);

  if (url.pathname.endsWith("/health")) {
    return Response.json({
      success: true,
      service: "ShukAfrica Sponsored Ads API",
      database: Boolean(env.SPONSORED_DB),
      media: Boolean(env.SPONSORED_MEDIA)
    });
  }

  return Response.json({
    success: true,
    message: "Sponsored Ads API is running."
  });
}
