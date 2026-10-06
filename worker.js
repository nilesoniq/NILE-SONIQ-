export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: corsHeaders()
        });
      }

      // Health check
      if (url.pathname === "/api/health") {
        return json({
          ok: true,
          service: "NileSoniq Cloudflare Worker"
        });
      }

      // Authentication
      if (url.pathname.startsWith("/api/auth/")) {
        return await handleAuth(request, env, url);
      }

      // Database API
      if (url.pathname.startsWith("/api/db/")) {
        return await handleDatabase(request, env, url);
      }

      // RPC API
      if (url.pathname.startsWith("/api/rpc/")) {
        return await handleRpc(request, env, url);
      }

      // Storage
      if (url.pathname.startsWith("/api/storage/")) {
        return await handleStorage(request, env, url);
      }

      // PesaJet
      if (url.pathname === "/api/payments/pesajet-collection") {
        return await handlePesaJet(request, env, "collection");
      }

      if (url.pathname === "/api/payments/pesajet-disbursement") {
        return await handlePesaJet(request, env, "disbursement");
      }

      // Serve frontend through Cloudflare Assets
      if (env.ASSETS) {
        return await env.ASSETS.fetch(request);
      }

      return new Response("NileSoniq Worker is running.", {
        status: 404
      });

    } catch (error) {
      console.error(error);

      return json({
        error: error?.message || "Internal server error"
      }, 500);
    }
  }
};


/* =========================================================
   GENERAL HELPERS
========================================================= */

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Credentials": "true"
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders()
    }
  });
}

function text(value, status = 200) {
  return new Response(String(value), {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      ...corsHeaders()
    }
  });
}

function randomId(prefix = "") {
  return prefix +
    crypto.randomUUID().replaceAll("-", "");
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";

  const parts = cookie.split(";");

  for (const part of parts) {
    const index = part.indexOf("=");

    if (index === -1) continue;

    const key = part.slice(0, index).trim();

    if (key === name) {
      return decodeURIComponent(
        part.slice(index + 1).trim()
      );
    }
  }

  return null;
}

function sessionCookie(token) {
  return [
    `nilesoniq_session=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=2592000"
  ].join("; ");
}

function clearSessionCookie() {
  return [
    "nilesoniq_session=",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0"
  ].join("; ");
}

function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}


/* =========================================================
   PASSWORD HASHING
========================================================= */

function bytesToBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);

  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

async function hashPassword(password, saltBase64) {
  const encoder = new TextEncoder();

  const passwordBytes =
    encoder.encode(String(password));

  const salt =
    saltBase64
      ? base64ToBytes(saltBase64)
      : crypto.getRandomValues(new Uint8Array(16));

  const keyMaterial =
    await crypto.subtle.importKey(
      "raw",
      passwordBytes,
      "PBKDF2",
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256"
      },
      keyMaterial,
      256
    );

  return {
    hash: bytesToBase64(new Uint8Array(bits)),
    salt: bytesToBase64(salt)
  };
}

async function verifyPassword(password, hash, salt) {
  const result =
    await hashPassword(password, salt);

  return timingSafeEqual(
    base64ToBytes(result.hash),
    base64ToBytes(hash)
  );
}


/* =========================================================
   AUTHENTICATION
========================================================= */

async function getCurrentUser(request, env) {
  const token =
    getCookie(request, "nilesoniq_session");

  if (!token) return null;

  const result =
    await env.DB.prepare(`
      SELECT
        u.id,
        u.email,
        u.artist_name,
        u.created_at,
        s.token,
        s.expires_at
      FROM auth_sessions s
      JOIN auth_users u
        ON u.id = s.user_id
      WHERE s.token = ?
        AND datetime(s.expires_at) > datetime('now')
      LIMIT 1
    `)
    .bind(token)
    .first();

  if (!result) return null;

  return {
    id: result.id,
    email: result.email,
    artist_name: result.artist_name,
    created_at: result.created_at
  };
}

async function handleAuth(request, env, url) {
  const path =
    url.pathname.replace("/api/auth", "");

  if (request.method === "POST" &&
      path === "/register") {
    return await registerUser(request, env);
  }

  if (request.method === "POST" &&
      path === "/login") {
    return await loginUser(request, env);
  }

  if (request.method === "POST" &&
      path === "/logout") {
    return await logoutUser(request, env);
  }

  if (request.method === "GET" &&
      path === "/me") {
    return await currentUserResponse(request, env);
  }

  return json({
    error: "Unknown authentication route"
  }, 404);
}

async function registerUser(request, env) {
  const body = await request.json();

  const email =
    normalizeEmail(body.email);

  const password =
    String(body.password || "");

  const artistName =
    String(body.artist_name || "").trim();

  if (!email || !password) {
    return json({
      error: "Email and password are required."
    }, 400);
  }

  if (password.length < 6) {
    return json({
      error: "Password must contain at least 6 characters."
    }, 400);
  }

  const existing =
    await env.DB.prepare(`
      SELECT id
      FROM auth_users
      WHERE email = ?
      LIMIT 1
    `)
    .bind(email)
    .first();

  if (existing) {
    return json({
      error: "An account with this email already exists."
    }, 409);
  }

  const id = randomId("user_");

  const passwordData =
    await hashPassword(password);

  await env.DB.prepare(`
    INSERT INTO auth_users
      (
        id,
        email,
        password_hash,
        password_salt,
        artist_name
      )
    VALUES (?, ?, ?, ?, ?)
  `)
  .bind(
    id,
    email,
    passwordData.hash,
    passwordData.salt,
    artistName || null
  )
  .run();

  const token = randomId("sess_");

  await env.DB.prepare(`
    INSERT INTO auth_sessions
      (
        token,
        user_id,
        expires_at
      )
    VALUES (
      ?,
      ?,
      datetime('now', '+30 days')
    )
  `)
  .bind(token, id)
  .run();

  const user = {
    id,
    email,
    artist_name: artistName || null
  };

  return new Response(
    JSON.stringify({
      success: true,
      user,
      session: {
        user
      }
    }),
    {
      status: 201,
      headers: {
        "Content-Type": "application/json",
        "Set-Cookie": sessionCookie(token),
        ...corsHeaders()
      }
    }
  );
}

async function loginUser(request, env) {
  const body = await request.json();

  const email =
    normalizeEmail(body.email);

  const password =
    String(body.password || "");

  if (!email || !password) {
    return json({
      error: "Email and password are required."
    }, 400);
  }

  const user =
    await env.DB.prepare(`
      SELECT
        id,
        email,
        password_hash,
        password_salt,
        artist_name,
        created_at
      FROM auth_users
      WHERE email = ?
      LIMIT 1
    `)
    .bind(email)
    .first();

  if (!user) {
    return json({
      error: "Invalid email or password."
    }, 401);
  }

  const valid =
    await verifyPassword(
      password,
      user.password_hash,
      user.password_salt
    );

  if (!valid) {
    return json({
      error: "Invalid email or password."
    }, 401);
  }

  const token = randomId("sess_");

  await env.DB.prepare(`
    INSERT INTO auth_sessions
      (
        token,
        user_id,
        expires_at
      )
    VALUES (
      ?,
      ?,
      datetime('now', '+30 days')
    )
  `)
  .bind(token, user.id)
  .run();

  const safeUser = {
    id: user.id,
    email: user.email,
    artist_name: user.artist_name,
    created_at: user.created_at
  };

  return new Response(
    JSON.stringify({
      success: true,
      user: safeUser,
      session: {
        user: safeUser
      }
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Set-Cookie": sessionCookie(token),
        ...corsHeaders()
      }
    }
  );
}

async function logoutUser(request, env) {
  const token =
    getCookie(request, "nilesoniq_session");

  if (token) {
    await env.DB.prepare(`
      DELETE FROM auth_sessions
      WHERE token = ?
    `)
    .bind(token)
    .run();
  }

  return new Response(
    JSON.stringify({
      success: true
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Set-Cookie": clearSessionCookie(),
        ...corsHeaders()
      }
    }
  );
}

async function currentUserResponse(request, env) {
  const user =
    await getCurrentUser(request, env);

  if (!user) {
    return json({
      authenticated: false,
      user: null,
      admin: null,
      artist: null
    });
  }

  return json({
    authenticated: true,
    user,
    admin: null,
    artist: null
  });
}


/* =========================================================
   DATABASE API
========================================================= */

const BLOCKED_TABLES = new Set([
  "auth_users",
  "auth_sessions"
]);

function validIdentifier(value) {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(value);
}

function tableAllowed(table) {
  return (
    validIdentifier(table) &&
    !BLOCKED_TABLES.has(table.toLowerCase())
  );
}

function getTableName(url) {
  const prefix = "/api/db/";

  return decodeURIComponent(
    url.pathname.slice(prefix.length)
  ).replace(/\/+$/, "");
}

async function handleDatabase(request, env, url) {
  const table = getTableName(url);

  if (!tableAllowed(table)) {
    return json({
      error: "Invalid or restricted table."
    }, 403);
  }

  if (request.method === "GET") {
    return await databaseSelect(request, env, table, url);
  }

  if (request.method === "POST") {
    return await databaseInsert(request, env, table);
  }

  if (request.method === "PATCH" ||
      request.method === "PUT") {
    return await databaseUpdate(request, env, table, url);
  }

  if (request.method === "DELETE") {
    return await databaseDelete(request, env, table, url);
  }

  return json({
    error: "Unsupported database method."
  }, 405);
}

function buildFilters(url, startIndex = 1) {
  const filters = [];

  let index = startIndex;

  for (const [key, value] of url.searchParams.entries()) {
    if (!key.startsWith("eq.")) continue;

    const column = key.slice(3);

    if (!validIdentifier(column)) continue;

    filters.push({
      sql: `"${column}" = ?`,
      value
    });

    index++;
  }

  return filters;
}

async function databaseSelect(request, env, table, url) {
  const filters =
    buildFilters(url);

  const where =
    filters.length
      ? " WHERE " +
        filters.map(x => x.sql).join(" AND ")
      : "";

  const limit =
    Math.min(
      Math.max(
        Number(url.searchParams.get("limit") || 100),
        1
      ),
      500
    );

  const params =
    filters.map(x => x.value);

  const query =
    `SELECT * FROM "${table}"${where} LIMIT ${limit}`;

  const result =
    await env.DB.prepare(query)
      .bind(...params)
      .all();

  return json({
    data: result.results || [],
    error: null
  });
}

async function databaseInsert(request, env, table) {
  const body = await request.json();

  const rows =
    Array.isArray(body)
      ? body
      : [body];

  if (!rows.length) {
    return json({
      data: [],
      error: null
    });
  }

  const results = [];

  for (const row of rows) {
    if (!row || typeof row !== "object") {
      return json({
        error: "Invalid insert data."
      }, 400);
    }

    const keys =
      Object.keys(row)
        .filter(validIdentifier);

    if (!keys.length) {
      return json({
        error: "No valid columns supplied."
      }, 400);
    }

    const columns =
      keys.map(k => `"${k}"`).join(", ");

    const placeholders =
      keys.map(() => "?").join(", ");

    const values =
      keys.map(k => row[k]);

    const result =
      await env.DB.prepare(`
        INSERT INTO "${table}"
          (${columns})
        VALUES
          (${placeholders})
      `)
      .bind(...values)
      .run();

    results.push({
      success: result.success,
      ...row
    });
  }

  return json({
    data: results,
    error: null
  }, 201);
}

async function databaseUpdate(request, env, table, url) {
  const body = await request.json();

  const keys =
    Object.keys(body || {})
      .filter(validIdentifier);

  if (!keys.length) {
    return json({
      error: "No update fields supplied."
    }, 400);
  }

  const filters =
    buildFilters(url);

  if (!filters.length) {
    return json({
      error: "Update requires at least one eq.* filter."
    }, 400);
  }

  const assignments =
    keys.map(k => `"${k}" = ?`).join(", ");

  const values =
    keys.map(k => body[k]);

  const filterValues =
    filters.map(x => x.value);

  const query =
    `UPDATE "${table}"
     SET ${assignments}
     WHERE ${filters.map(x => x.sql).join(" AND ")}`;

  const result =
    await env.DB.prepare(query)
      .bind(...values, ...filterValues)
      .run();

  return json({
    data: {
      success: result.success,
      changes: result.meta?.changes || 0
    },
    error: null
  });
}

async function databaseDelete(request, env, table, url) {
  const filters =
    buildFilters(url);

  if (!filters.length) {
    return json({
      error: "Delete requires at least one eq.* filter."
    }, 400);
  }

  const query =
    `DELETE FROM "${table}"
     WHERE ${filters.map(x => x.sql).join(" AND ")}`;

  const result =
    await env.DB.prepare(query)
      .bind(...filters.map(x => x.value))
      .run();

  return json({
    data: {
      success: result.success,
      changes: result.meta?.changes || 0
    },
    error: null
  });
}


/* =========================================================
   RPC
========================================================= */

async function handleRpc(request, env, url) {
  const name =
    decodeURIComponent(
      url.pathname.slice("/api/rpc/".length)
    );

  if (name === "record_song_play") {
    const body = await request.json();

    const songId =
      body.song_id ||
      body.songId ||
      body.id;

    if (!songId) {
      return json({
        error: "song_id is required."
      }, 400);
    }

    try {
      await env.DB.prepare(`
        UPDATE songs
        SET play_count =
          COALESCE(play_count, 0) + 1
        WHERE id = ?
      `)
      .bind(songId)
      .run();

      return json({
        data: true,
        error: null
      });

    } catch (error) {
      return json({
        data: null,
        error: error.message
      }, 400);
    }
  }

  if (name === "get_platform_completed_total") {
    try {
      const result =
        await env.DB.prepare(`
          SELECT
            COALESCE(
              SUM(
                CASE
                  WHEN status = 'completed'
                  THEN amount
                  ELSE 0
                END
              ),
              0
            ) AS total
          FROM payments
        `)
        .first();

      return json({
        data: result?.total || 0,
        error: null
      });

    } catch {
      return json({
        data: 0,
        error: null
      });
    }
  }

  return json({
    error: `Unknown RPC: ${name}`
  }, 404);
}


/* =========================================================
   R2 STORAGE
========================================================= */

async function handleStorage(request, env, url) {
  if (!env.MEDIA_BUCKET) {
    return json({
      error: "R2 MEDIA_BUCKET binding is not configured."
    }, 500);
  }

  const path =
    url.pathname
      .replace("/api/storage/", "")
      .replace(/^\/+/, "");

  if (path.startsWith("public/")) {
    return await storagePublic(
      request,
      env,
      path.slice("public/".length)
    );
  }

  if (path === "upload" &&
      request.method === "POST") {
    return await storageUpload(
      request,
      env
    );
  }

  return json({
    error: "Unknown storage route."
  }, 404);
}

async function storageUpload(request, env) {
  const form =
    await request.formData();

  const bucket =
    String(form.get("bucket") || "audio");

  const file =
    form.get("file");

  const requestedPath =
    String(
      form.get("path") ||
      form.get("filename") ||
      ""
    );

  if (!file || typeof file.arrayBuffer !== "function") {
    return json({
      error: "No file supplied."
    }, 400);
  }

  if (!requestedPath) {
    return json({
      error: "File path is required."
    }, 400);
  }

  const cleanBucket =
    bucket
      .replace(/[^a-zA-Z0-9_-]/g, "");

  const cleanPath =
    requestedPath
      .replace(/^\/+/, "")
      .replace(/\.\./g, "");

  const key =
    `${cleanBucket}/${cleanPath}`;

  const metadata = {
    contentType:
      file.type ||
      "application/octet-stream"
  };

  await env.MEDIA_BUCKET.put(
    key,
    await file.arrayBuffer(),
    {
      httpMetadata: metadata
    }
  );

  return json({
    success: true,
    path: key,
    bucket: cleanBucket,
    publicUrl:
      `/api/storage/public/${encodeURIComponent(cleanBucket)}/${cleanPath}`
  });
}

async function storagePublic(request, env, path) {
  const key =
    decodeURIComponent(path);

  const object =
    await env.MEDIA_BUCKET.get(key);

  if (!object) {
    return text("File not found.", 404);
  }

  const headers =
    new Headers();

  object.writeHttpMetadata(headers);

  headers.set(
    "ETag",
    object.httpEtag
  );

  headers.set(
    "Cache-Control",
    "public, max-age=31536000, immutable"
  );

  return new Response(
    object.body,
    {
      headers
    }
  );
}


/* =========================================================
   PESAJET
========================================================= */

async function handlePesaJet(request, env, type) {
  if (request.method !== "POST") {
    return json({
      error: "POST required."
    }, 405);
  }

  const body =
    await request.json();

  const endpoint =
    type === "collection"
      ? env.PESAJET_COLLECTION_URL
      : env.PESAJET_DISBURSEMENT_URL;

  const token =
    env.PESAJET_TOKEN;

  if (!endpoint) {
    return json({
      error:
        "PesaJet endpoint is not configured in Cloudflare."
    }, 503);
  }

  const headers = {
    "Content-Type": "application/json",
    "Accept": "application/json"
  };

  if (token) {
    headers.Authorization =
      `Bearer ${token}`;
  }

  const response =
    await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(body)
    });

  const responseText =
    await response.text();

  let responseData;

  try {
    responseData =
      JSON.parse(responseText);
  } catch {
    responseData =
      {
        response: responseText
      };
  }

  return json(
    responseData,
    response.status
  );
                            }
