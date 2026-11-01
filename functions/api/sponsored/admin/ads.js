
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });

const today = () => new Date().toISOString().slice(0, 10);

function validAdData(data) {
  return (
    typeof data.title === "string" &&
    data.title.trim().length >= 1 &&
    data.title.trim().length <= 70 &&
    typeof data.shortDescription === "string" &&
    data.shortDescription.trim().length >= 1 &&
    data.shortDescription.trim().length <= 120 &&
    (data.fullDescription === undefined ||
      (typeof data.fullDescription === "string" &&
       data.fullDescription.length <= 3000)) &&
    ["card", "video"].includes(data.placement) &&
    /^\d{4}-\d{2}-\d{2}$/.test(data.startDate) &&
    /^\d{4}-\d{2}-\d{2}$/.test(data.endDate) &&
    data.endDate >= data.startDate
  );
}

const ACCESS_TEAM_DOMAIN = "fancy-hat-29f2.cloudflareaccess.com";
const ACCESS_AUD = "0fd0b431-dd59-4d58-a460-215742885ea4";

async function verifyAccessToken(request) {
  try {
    const token = request.headers.get("Cf-Access-Jwt-Assertion");

    if (!token) return false;

    const parts = token.split(".");
    if (parts.length !== 3) return false;

    const decode = (value) => {
      const base64 = value
        .replace(/-/g, "+")
        .replace(/_/g, "/");
      return Uint8Array.from(
        atob(base64 + "=".repeat((4 - base64.length % 4) % 4)),
        c => c.charCodeAt(0)
      );
    };

    const header = JSON.parse(
      new TextDecoder().decode(decode(parts[0]))
    );

    const payload = JSON.parse(
      new TextDecoder().decode(decode(parts[1]))
    );

    if (header.alg !== "RS256" || !header.kid) return false;

    const issuer = `https://${ACCESS_TEAM_DOMAIN}`;

    if (payload.iss !== issuer) return false;

    const audiences = Array.isArray(payload.aud)
      ? payload.aud
      : [payload.aud];

    if (!audiences.includes(ACCESS_AUD)) return false;

    const now = Math.floor(Date.now() / 1000);

    if (!payload.exp || payload.exp <= now) return false;
if (!payload.iat || payload.iat > now + 60) return false;
if (payload.nbf && payload.nbf > now + 60) return false;

    const response = await fetch(
      `${issuer}/cdn-cgi/access/certs`
    );

    if (!response.ok) return false;

    const jwks = await response.json();

    const jwk = jwks.keys.find(
      key => key.kid === header.kid
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

    return await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      decode(parts[2]),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
    );

  } catch (error) {
    return false;
  }
}

export async function onRequest({ request, env }) {
  const authenticated = await verifyAccessToken(request);

  if (!authenticated) {
    return Response.json({
      success: false,
      message: "Unauthorized access."
    }, { status: 401 });
  }

  try {
    const db = env.SPONSORED_DB;

    if (!db) {
      return json({ success: false, message: "Sponsored database unavailable." }, 500);
    }

    if (request.method === "GET") {
      const { results } = await db.prepare(
        "SELECT * FROM sponsored_ads ORDER BY display_order ASC, id DESC"
      ).all();

      return json({ success: true, ads: results });
    }

    if (request.method === "POST") {
      const data = await request.json();

      const required = [
        "title", "shortDescription", "placement",
        "startDate", "endDate"
      ];

      if (required.some(key => !data[key])) {
        return json({ success: false, message: "Required fields are missing." }, 400);
      }

      if (!["card", "video"].includes(data.placement)) {
        return json({ success: false, message: "Invalid placement." }, 400);
      }

      if (data.endDate < data.startDate) {
        return json({ success: false, message: "Expiry date cannot be before start date." }, 400);
      }

      const result = await db.prepare(`
        INSERT INTO sponsored_ads
        (title, short_description, full_description, placement,
         main_media_key, extra_media_key, start_date, end_date,
         published, display_order)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0,
          COALESCE((SELECT MAX(display_order) + 1 FROM sponsored_ads), 0))
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

      return json({ success: true, id: result.meta.last_row_id }, 201);
    }

    if (request.method === "PATCH") {
      const data = await request.json();

      if (!Number.isInteger(Number(data.id))) {
        return json({ success: false, message: "Valid advertisement ID required." }, 400);
      }

      const allowed = ["title", "shortDescription", "fullDescription",
        "placement", "startDate", "endDate", "mainMediaKey", "extraMediaKey"];

      const values = [];
      const columns = {
        title: "title",
        shortDescription: "short_description",
        fullDescription: "full_description",
        placement: "placement",
        startDate: "start_date",
        endDate: "end_date",
        mainMediaKey: "main_media_key",
        extraMediaKey: "extra_media_key"
      };

      for (const key of allowed) {
        if (Object.hasOwn(data, key)) {
          if (key === "placement" && !["card", "video"].includes(data[key])) {
            return json({ success: false, message: "Invalid placement." }, 400);
          }
          values.push({ column: columns[key], value: data[key] });
        }
      }

      if (!values.length) {
        return json({ success: false, message: "No changes supplied." }, 400);
      }

      const sets = values.map(item => `${item.column} = ?`).join(", ");

      await db.prepare(`
        UPDATE sponsored_ads
        SET ${sets}, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(...values.map(item => item.value), Number(data.id)).run();

      return json({ success: true });
    }

    if (request.method === "PUT") {
      const data = await request.json();
      const id = Number(data.id);

      if (!Number.isInteger(id) || !["publish", "unpublish", "reorder", "extend"].includes(data.action)) {
        return json({ success: false, message: "Invalid action." }, 400);
      }

      if (data.action === "publish") {
        const ad = await db.prepare(
          "SELECT start_date, end_date FROM sponsored_ads WHERE id = ?"
        ).bind(id).first();

        if (!ad) return json({ success: false, message: "Advertisement not found." }, 404);
        if (ad.end_date < today()) return json({ success: false, message: "Advertisement has expired." }, 400);
        if (ad.start_date > today()) return json({ success: false, message: "Advertisement has not started yet." }, 400);

        await db.prepare(
          "UPDATE sponsored_ads SET published = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        ).bind(id).run();
      }

      if (data.action === "unpublish") {
        await db.prepare(
          "UPDATE sponsored_ads SET published = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        ).bind(id).run();
      }

      if (data.action === "extend") {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(data.endDate || "")) {
          return json({ success: false, message: "Valid expiry date required." }, 400);
        }
        await db.prepare(
          "UPDATE sponsored_ads SET end_date = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        ).bind(data.endDate, id).run();
      }

      if (data.action === "reorder") {
        const direction = Number(data.direction);
        if (![1, -1].includes(direction)) {
          return json({ success: false, message: "Invalid reorder direction." }, 400);
        }

        const current = await db.prepare(
          "SELECT id, display_order FROM sponsored_ads WHERE id = ?"
        ).bind(id).first();

        if (!current) return json({ success: false, message: "Advertisement not found." }, 404);

        const other = await db.prepare(`
          SELECT id, display_order FROM sponsored_ads
          WHERE display_order ${direction < 0 ? "<" : ">"} ?
          ORDER BY display_order ${direction < 0 ? "DESC" : "ASC"}
          LIMIT 1
        `).bind(current.display_order).first();

        if (other) {
          await db.batch([
            db.prepare("UPDATE sponsored_ads SET display_order = ? WHERE id = ?")
              .bind(other.display_order, id),
            db.prepare("UPDATE sponsored_ads SET display_order = ? WHERE id = ?")
              .bind(current.display_order, other.id)
          ]);
        }
      }

      return json({ success: true });
    }

    if (request.method === "DELETE") {
      const id = Number(new URL(request.url).searchParams.get("id"));

      if (!Number.isInteger(id)) {
        return json({ success: false, message: "Valid advertisement ID required." }, 400);
      }

      await db.prepare("DELETE FROM sponsored_media WHERE ad_id = ?").bind(id).run();
      await db.prepare("DELETE FROM sponsored_placements WHERE ad_id = ?").bind(id).run();
      await db.prepare("DELETE FROM sponsored_ads WHERE id = ?").bind(id).run();

      return json({ success: true });
    }

    return json({ success: false, message: "Method not allowed." }, 405);

  } catch (error) {
    return json({ success: false, message: "Sponsored API error." }, 500);
  }
    }
          
