
const SESSION_COOKIE = "shuk_open_market_session";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";

  for (const part of cookie.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;

    if (part.slice(0, index).trim() === name) {
      return part.slice(index + 1).trim();
    }
  }

  return null;
}

function base64UrlToBytes(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);

  return Uint8Array.from(
    binary,
    character => character.charCodeAt(0)
  );
}

async function verifySession(request, secret) {
  try {
    if (!secret) return null;

    const token = getCookie(request, SESSION_COOKIE);
    if (!token) return null;

    const parts = token.split(".");
    if (parts.length !== 2) return null;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlToBytes(parts[1]),
      new TextEncoder().encode(parts[0])
    );

    if (!valid) return null;

    const payload = JSON.parse(
      new TextDecoder().decode(base64UrlToBytes(parts[0]))
    );

    if (
      !payload.sub ||
      !payload.exp ||
      payload.exp <= Math.floor(Date.now() / 1000)
    ) {
      return null;
    }

    return payload.sub;
  } catch (error) {
    console.error("Open Market session verification failed:", error);
    return null;
  }
}

function getMediaKey(value, sellerId, listingId) {
  if (!value || typeof value !== "string") return null;

  try {
    const url = new URL(value);

    // Only allow media belonging to this seller and listing.
    const expectedPrefix =
      `/open-market/${sellerId}/${listingId}/`;

    if (!url.pathname.startsWith(expectedPrefix)) {
      return null;
    }

    return url.pathname.slice(1);
  } catch {
    return null;
  }
}

/*
 * DELETE /api/open-market/delete
 * JSON body: { "id": "listing-id" }
 */
export async function onRequestDelete({ request, env }) {
  try {
    if (!env.OPEN_MARKET_DB) {
      return json({
        success: false,
        error: "Open Market database is not configured."
      }, 500);
    }

    if (!env.OPEN_MARKET_SESSION_SECRET) {
      return json({
        success: false,
        error: "Open Market session security is not configured."
      }, 500);
    }

    const sellerId = await verifySession(
      request,
      env.OPEN_MARKET_SESSION_SECRET
    );

    if (!sellerId) {
      return json({
        success: false,
        error: "Please log in again before deleting a listing."
      }, 401);
    }

    let body;

    try {
      body = await request.json();
    } catch {
      return json({
        success: false,
        error: "Invalid deletion request."
      }, 400);
    }

    const listingId = String(body?.id || "").trim();

    if (!listingId || listingId.length > 100) {
      return json({
        success: false,
        error: "A valid listing ID is required."
      }, 400);
    }

    // Find the listing only if it belongs to the logged-in seller.
    const listing = await env.OPEN_MARKET_DB.prepare(`
      SELECT
        id, seller_id, image_1, image_2, image_3,
        image_4, image_5, video_url
      FROM open_market_listings
      WHERE id = ? AND seller_id = ?
      LIMIT 1
    `).bind(listingId, sellerId).first();

    if (!listing) {
      return json({
        success: false,
        error: "Listing not found, or it does not belong to your account."
      }, 404);
    }

    // Delete the database record first. This frees the listing slot.
    const result = await env.OPEN_MARKET_DB.prepare(`
      DELETE FROM open_market_listings
      WHERE id = ? AND seller_id = ?
    `).bind(listingId, sellerId).run();

    if (!result.meta || result.meta.changes !== 1) {
      return json({
        success: false,
        error: "The listing could not be deleted. Please refresh and try again."
      }, 500);
    }

    // Clean up only this listing's own Open Market media.
    // If storage cleanup fails, the listing is still deleted.
    if (env.OPEN_MARKET_MEDIA) {
      const mediaValues = [
        listing.image_1,
        listing.image_2,
        listing.image_3,
        listing.image_4,
        listing.image_5,
        listing.video_url
      ];

      const keys = [
        ...new Set(
          mediaValues
            .map(value => getMediaKey(value, sellerId, listingId))
            .filter(Boolean)
        )
      ];

      for (const key of keys) {
        try {
          await env.OPEN_MARKET_MEDIA.delete(key);
        } catch (error) {
          console.error("Open Market media cleanup failed:", error);
        }
      }
    }

    return json({
      success: true,
      message: "Listing deleted successfully."
    });
  } catch (error) {
    console.error("Open Market listing deletion error:", error);

    return json({
      success: false,
      error: "Unable to delete the listing."
    }, 500);
  }
  }
    
