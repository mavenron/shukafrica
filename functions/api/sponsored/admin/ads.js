const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });

const today = () => new Date().toISOString().slice(0, 10);

const ACCESS_TEAM_DOMAIN =
  "fancy-hat-29f2.cloudflareaccess.com";

const audience = "a593424efda69151151cac5d734c32169cf878de0a55d0555649d20a48531bc3";

// ------------------------------
// DATE VALIDATION
// ------------------------------

function isValidDate(value) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}$/.test(value)
  ) {
    return false;
  }

  const date = new Date(`${value}T00:00:00Z`);

  return (
    !Number.isNaN(date.getTime()) &&
    date.toISOString().slice(0, 10) === value
  );
}

function isValidRedirectUrl(value) {
  if (value === undefined || value === null || value === "") {
    return true;
  }

  if (typeof value !== "string" || value.length > 2000) {
    return false;
  }

  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}

// ------------------------------
// ADVERTISEMENT VALIDATION
// ------------------------------

function validAdData(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return false;
  }

  const validMediaKey = value =>
    value === undefined ||
    value === null ||
    (
      typeof value === "string" &&
      value.length <= 500
    );

  return (
    typeof data.title === "string" &&
    data.title.trim().length >= 1 &&
    data.title.trim().length <= 70 &&

    typeof data.shortDescription === "string" &&
    data.shortDescription.trim().length >= 1 &&
    data.shortDescription.trim().length <= 120 &&

    (
      data.fullDescription === undefined ||
      (
        typeof data.fullDescription === "string" &&
        data.fullDescription.length <= 3000
      )
    ) &&

    ["card", "video"].includes(data.placement) &&

    isValidDate(data.startDate) &&
    isValidDate(data.endDate) &&
    data.endDate >= data.startDate &&

    validMediaKey(data.mainMediaKey) &&
    validMediaKey(data.extraMediaKey) && 
    isValidRedirectUrl(data.redirectUrl)
  );
}

// ------------------------------
// BASE64URL DECODER
// ------------------------------

function decodeBase64Url(value) {
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded = base64 +
    "=".repeat((4 - base64.length % 4) % 4);

  return Uint8Array.from(
    atob(padded),
    character => character.charCodeAt(0)
  );
}

// ------------------------------
// CLOUDFLARE ACCESS JWT CHECK
// ------------------------------

async function verifyAccessToken(request) {
  try {
    const token = request.headers.get(
      "Cf-Access-Jwt-Assertion"
    );

    if (!token) return false;

    const parts = token.split(".");

    if (parts.length !== 3) return false;

    const header = JSON.parse(
      new TextDecoder().decode(
        decodeBase64Url(parts[0])
      )
    );

    const payload = JSON.parse(
      new TextDecoder().decode(
        decodeBase64Url(parts[1])
      )
    );

    if (
      header.alg !== "RS256" ||
      typeof header.kid !== "string"
    ) {
      return false;
    }

    const issuer =
      `https://${ACCESS_TEAM_DOMAIN}`;

    if (payload.iss !== issuer) return false;

    const audiences = Array.isArray(payload.aud)
      ? payload.aud
      : [payload.aud];

    if (!audiences.includes(audience)) {
  return false;
}

const now = Math.floor(Date.now() / 1000);

    if (
      typeof payload.exp !== "number" ||
      payload.exp <= now
    ) {
      return false;
    }

    if (
      typeof payload.iat !== "number" ||
      payload.iat > now + 60
    ) {
      return false;
    }

    if (
      payload.nbf !== undefined &&
      (
        typeof payload.nbf !== "number" ||
        payload.nbf > now + 60
      )
    ) {
      return false;
    }

    // Retrieve Cloudflare Access public signing keys.
    const response = await fetch(
      `${issuer}/cdn-cgi/access/certs`
    );

    if (!response.ok) return false;

    const jwks = await response.json();

    if (!Array.isArray(jwks.keys)) return false;

    const jwk = jwks.keys.find(
      key =>
        key.kid === header.kid &&
        key.kty === "RSA" &&
        (!key.alg || key.alg === "RS256") &&
        (!key.use || key.use === "sig")
    );

    if (!jwk) return false;

    const publicKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
      },
      false,
      ["verify"]
    );

    const validSignature = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      decodeBase64Url(parts[2]),
      new TextEncoder().encode(
        `${parts[0]}.${parts[1]}`
      )
    );

    return validSignature;

  } catch (error) {
    return false;
  }
}

// ------------------------------
// MAIN SPONSORED ADS API
// ------------------------------

export async function onRequest({ request, env }) {

  // Authenticate every request first.
  const authenticated = await verifyAccessToken(request);

  if (!authenticated) {
    return json({
      success: false,
      message: "Unauthorized access."
    }, 401);
  }

  try {
    const db = env.SPONSORED_DB;

    if (!db) {
      return json({
        success: false,
        message: "Sponsored database unavailable."
      }, 500);
    }

    // --------------------------
    // GET: LOAD ALL ADS
    // --------------------------

    if (request.method === "GET") {
      const { results } = await db.prepare(`
        SELECT *
        FROM sponsored_ads
        ORDER BY display_order ASC, id DESC
      `).all();

      return json({
        success: true,
        ads: results
      });
    }

    // --------------------------
    // POST: CREATE AD
    // --------------------------

    if (request.method === "POST") {
      const data = await request.json();

      if (!validAdData(data)) {
        return json({
          success: false,
          message: "Invalid advertisement details. Check all fields and dates."
        }, 400);
      }

      const result = await db.prepare(`
        INSERT INTO sponsored_ads (
          title,
          short_description,
          full_description,
          placement,
          main_media_key,
          extra_media_key,
          start_date,
          end_date,
          redirect_url,
          published,
          display_order
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0,
          COALESCE(
            (SELECT MAX(display_order) + 1 FROM sponsored_ads),
            0
          )
        )
      `).bind(
        data.title.trim(),
        data.shortDescription.trim(),
        data.fullDescription || "",
        data.placement,
        data.mainMediaKey || null,
        data.extraMediaKey || null,
        data.startDate,
        data.endDate
      ).run();

      return json({
        success: true,
        id: result.meta.last_row_id
      }, 201);
    }

    // --------------------------
    // PATCH: EDIT AD
    // --------------------------

    if (request.method === "PATCH") {
      const data = await request.json();

      if (
        !Number.isSafeInteger(Number(data.id)) ||
        Number(data.id) <= 0
      ) {
        return json({
          success: false,
          message: "Valid advertisement ID required."
        }, 400);
      }

      if (!validAdData(data)) {
        return json({
          success: false,
          message: "Invalid advertisement details. Check all fields and dates."
        }, 400);
      }

      const result = await db.prepare(`
        UPDATE sponsored_ads
        SET
          title = ?,
          short_description = ?,
          full_description = ?,
          placement = ?,
          start_date = ?,
          end_date = ?,
          main_media_key = ?,
          extra_media_key = ?,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(
        data.title.trim(),
        data.shortDescription.trim(),
        data.fullDescription || "",
        data.placement,
        data.startDate,
        data.endDate,
        data.mainMediaKey || null,
        data.extraMediaKey || null,
        Number(data.id)
      ).run();

      if (!result.meta.changes) {
        return json({
          success: false,
          message: "Advertisement not found."
        }, 404);
      }

      return json({
        success: true,
        message: "Advertisement updated."
      });
    }

    // --------------------------
    // PUT: ADMIN ACTIONS
    // --------------------------

    if (request.method === "PUT") {
      const data = await request.json();
      const id = Number(data.id);

      if (
        !Number.isSafeInteger(id) ||
        id <= 0 ||
        !["publish", "unpublish", "reorder", "extend"]
          .includes(data.action)
      ) {
        return json({
          success: false,
          message: "Invalid action."
        }, 400);
      }

      // PUBLISH
      if (data.action === "publish") {
        const ad = await db.prepare(`
          SELECT start_date, end_date
          FROM sponsored_ads
          WHERE id = ?
        `).bind(id).first();

        if (!ad) {
          return json({
            success: false,
            message: "Advertisement not found."
          }, 404);
        }

        if (
          !isValidDate(ad.start_date) ||
          !isValidDate(ad.end_date)
        ) {
          return json({
            success: false,
            message: "Advertisement has invalid dates."
          }, 400);
        }

        if (ad.end_date < today()) {
          return json({
            success: false,
            message: "Advertisement has expired."
          }, 400);
        }

        if (ad.start_date > today()) {
          return json({
            success: false,
            message: "Advertisement has not started yet."
          }, 400);
        }

        await db.prepare(`
          UPDATE sponsored_ads
          SET published = 1,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).bind(id).run();
      }

      // UNPUBLISH
      if (data.action === "unpublish") {
        const result = await db.prepare(`
          UPDATE sponsored_ads
          SET published = 0,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).bind(id).run();

        if (!result.meta.changes) {
          return json({
            success: false,
            message: "Advertisement not found."
          }, 404);
        }
      }

      // EXTEND EXPIRY
      if (data.action === "extend") {
        if (!isValidDate(data.endDate)) {
          return json({
            success: false,
            message: "Valid expiry date required."
          }, 400);
        }

        const ad = await db.prepare(`
          SELECT start_date
          FROM sponsored_ads
          WHERE id = ?
        `).bind(id).first();

        if (!ad) {
          return json({
            success: false,
            message: "Advertisement not found."
          }, 404);
        }

        if (
          data.endDate < ad.start_date ||
          data.endDate <= today()
        ) {
          return json({
            success: false,
            message: "Expiry date must be after today and not before the start date."
          }, 400);
        }

        await db.prepare(`
          UPDATE sponsored_ads
          SET end_date = ?,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).bind(data.endDate, id).run();
      }

      // REORDER
      if (data.action === "reorder") {
        const direction = Number(data.direction);

        if (![1, -1].includes(direction)) {
          return json({
            success: false,
            message: "Invalid reorder direction."
          }, 400);
        }

        const current = await db.prepare(`
          SELECT id, display_order
          FROM sponsored_ads
          WHERE id = ?
        `).bind(id).first();

        if (!current) {
          return json({
            success: false,
            message: "Advertisement not found."
          }, 404);
        }

        const other = await db.prepare(`
          SELECT id, display_order
          FROM sponsored_ads
          WHERE display_order
            ${direction < 0 ? "<" : ">"} ?
          ORDER BY display_order
            ${direction < 0 ? "DESC" : "ASC"}
          LIMIT 1
        `).bind(current.display_order).first();

        if (other) {
          await db.batch([
            db.prepare(`
              UPDATE sponsored_ads
              SET display_order = ?
              WHERE id = ?
            `).bind(other.display_order, id),

            db.prepare(`
              UPDATE sponsored_ads
              SET display_order = ?
              WHERE id = ?
            `).bind(current.display_order, other.id)
          ]);
        }
      }

      return json({
        success: true,
        message: "Advertisement action completed."
      });
    }

    // --------------------------
    // DELETE: REMOVE AD
    // --------------------------

    if (request.method === "DELETE") {
      const id = Number(
        new URL(request.url).searchParams.get("id")
      );

      if (!Number.isSafeInteger(id) || id <= 0) {
        return json({
          success: false,
          message: "Valid advertisement ID required."
        }, 400);
      }

      const ad = await db.prepare(`
        SELECT id
        FROM sponsored_ads
        WHERE id = ?
      `).bind(id).first();

      if (!ad) {
        return json({
          success: false,
          message: "Advertisement not found."
        }, 404);
      }

      await db.prepare(`
        DELETE FROM sponsored_media
        WHERE ad_id = ?
      `).bind(id).run();

      await db.prepare(`
        DELETE FROM sponsored_placements
        WHERE ad_id = ?
      `).bind(id).run();

      await db.prepare(`
        DELETE FROM sponsored_ads
        WHERE id = ?
      `).bind(id).run();

      return json({
        success: true,
        message: "Advertisement deleted."
      });
    }

    return json({
      success: false,
      message: "Method not allowed."
    }, 405);

  } catch (error) {
    return json({
      success: false,
      message: "Sponsored API error."
    }, 500);
  }
}
