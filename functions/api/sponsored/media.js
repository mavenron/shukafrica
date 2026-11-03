const MEDIA_TYPES = {
  jpg: "image/jpeg",
  png: "image/png",
  webp: "image/webp",
  gif: "image/gif",
  mp4: "video/mp4",
  webm: "video/webm"
};

export async function onRequestGet({ request, env }) {
  try {
    const url = new URL(request.url);
    const key = url.searchParams.get("key");

    const validKey =
      /^sponsored-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(jpg|png|webp|gif|mp4|webm)$/i;

    if (!key || !validKey.test(key)) {
      return new Response("Media not found.", { status: 404 });
    }

    if (!env.SPONSORED_MEDIA) {
      return new Response("Media service unavailable.", { status: 500 });
    }

    const extension = key.split(".").pop().toLowerCase();
    const contentType = MEDIA_TYPES[extension];

    const rangeHeader = request.headers.get("Range");
    let object;

    if (rangeHeader) {
      const match = rangeHeader.match(/^bytes=(\d*)-(\d*)$/);

      if (!match) {
        return new Response(null, { status: 416 });
      }

      const head = await env.SPONSORED_MEDIA.head(key);

      if (!head) {
        return new Response("Media not found.", { status: 404 });
      }

      const size = head.size;
      let start;
      let end;

      if (match[1] === "") {
        const suffixLength = Number(match[2]);

        if (!suffixLength || size === 0) {
          return new Response(null, { status: 416 });
        }

        start = Math.max(0, size - suffixLength);
        end = size - 1;
      } else {
        start = Number(match[1]);
        end = match[2] === "" ? size - 1 : Number(match[2]);
      }

      if (
        !Number.isSafeInteger(start) ||
        !Number.isSafeInteger(end) ||
        start < 0 ||
        start >= size ||
        end < start
      ) {
        return new Response(null, {
          status: 416,
          headers: {
            "Content-Range": `bytes */${size}`
          }
        });
      }

      end = Math.min(end, size - 1);

      object = await env.SPONSORED_MEDIA.get(key, {
        range: {
          offset: start,
          length: end - start + 1
        }
      });

      if (!object) {
        return new Response("Media not found.", { status: 404 });
      }

      return new Response(object.body, {
        status: 206,
        headers: {
          "Content-Type": contentType,
          "Content-Length": String(end - start + 1),
          "Content-Range": `bytes ${start}-${end}/${size}`,
          "Accept-Ranges": "bytes",
          "Cache-Control": "public, max-age=31536000, immutable",
          "X-Content-Type-Options": "nosniff"
        }
      });
    }

    object = await env.SPONSORED_MEDIA.get(key);

    if (!object) {
      return new Response("Media not found.", { status: 404 });
    }

    return new Response(object.body, {
      status: 200,
      headers: {
        "Content-Type": contentType,
        "Content-Length": String(object.size),
        "Accept-Ranges": "bytes",
        "Cache-Control": "public, max-age=31536000, immutable",
        "X-Content-Type-Options": "nosniff"
      }
    });

  } catch (error) {
    console.error("Sponsored media error:", error);

    return new Response("Unable to load media.", {
      status: 500
    });
  }
          }
