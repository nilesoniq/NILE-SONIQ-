// NILE SONIQ AUTH WORKER - REGISTRATION ROUTE

const ALLOWED_ORIGINS = [
  "https://nilesoniq.com",
  "https://www.nilesoniq.com",
  "https://nile-soniq-auth.nilesoniq.workers.dev",
];

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin)
    ? origin
    : "https://nilesoniq.com";

  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "86400",
  };
}

function json(data, status = 200, origin = "") {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(origin),
    },
  });
}

function text(data, status = 200, origin = "") {
  return new Response(data, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      ...corsHeaders(origin),
    },
  });
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";

  for (const part of cookie.split(";")) {
    const item = part.trim();
    const index = item.indexOf("=");

    if (index === -1) continue;

    const key = item.slice(0, index);
    const value = item.slice(index + 1);

    if (key === name) {
      return decodeURIComponent(value);
    }
  }

  return null;
}

function randomToken(bytes = 32) {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);

  return Array.from(array)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function base64FromBytes(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function bytesFromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    key,
    256
  );

  return `pbkdf2_sha256$100000$${base64FromBytes(
    salt
  )}$${base64FromBytes(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  try {
    if (!stored || !stored.startsWith("pbkdf2_sha256$")) {
      return false;
    }

    const parts = stored.split("$");

    if (parts.length !== 4) {
      return false;
    }

    const iterations = Number(parts[1]);
    const salt = bytesFromBase64(parts[2]);
    const expected = bytesFromBase64(parts[3]);

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256",
      },
      key,
      256
    );

    const actual = new Uint8Array(bits);

    if (actual.length !== expected.length) {
      return false;
    }

    let difference = 0;

    for (let i = 0; i < actual.length; i++) {
      difference |= actual[i] ^ expected[i];
    }

    return difference === 0;
  } catch {
    return false;
  }
}

async function readBody(request) {
  const contentType = (
    request.headers.get("content-type") || ""
  ).toLowerCase();

  if (contentType.includes("application/json")) {
    return await request.json();
  }

  if (
    contentType.includes("application/x-www-form-urlencoded") ||
    contentType.includes("multipart/form-data")
  ) {
    const form = await request.formData();
    const body = {};

    for (const [key, value] of form.entries()) {
      if (typeof value === "string") {
        body[key] = value;
      }
    }

    return body;
  }

  const raw = await request.text();

  if (!raw) {
    return {};
  }

  try {
    return JSON.parse(raw);
  } catch {
    const params = new URLSearchParams(raw);
    const body = {};

    for (const [key, value] of params.entries()) {
      body[key] = value;
    }

    return body;
  }
}

async function ensureAuthTables(env) {
  await env.DB.batch([
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS auth_local_credentials (
        user_id TEXT PRIMARY KEY NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `),

    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS auth_sessions (
        token TEXT PRIMARY KEY NOT NULL,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      )
    `),
  ]);
}

async function createSession(env, userId) {
  const token = randomToken(32);
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(
    Date.now() + 30 * 24 * 60 * 60 * 1000
  ).toISOString();

  await env.DB.prepare(`
    INSERT INTO auth_sessions (
      token,
      user_id,
      created_at,
      expires_at
    )
    VALUES (?, ?, ?, ?)
  `)
    .bind(token, userId, createdAt, expiresAt)
    .run();

  return {
    access_token: token,
    token,
    expires_at: expiresAt,
  };
}

async function getCurrentUser(request, env) {
  await ensureAuthTables(env);

  const authorization =
    request.headers.get("Authorization") || "";

  let token = null;

  if (authorization.toLowerCase().startsWith("bearer ")) {
    token = authorization.slice(7).trim();
  }

  if (!token) {
    token = getCookie(request, "nile_session");
  }

  if (!token) {
    return null;
  }

  return await env.DB.prepare(`
    SELECT
      u.*,
      s.expires_at AS session_expires_at
    FROM auth_sessions s
    JOIN auth_users u
      ON u.id = s.user_id
    WHERE s.token = ?
      AND datetime(s.expires_at) > datetime('now')
      AND u.deleted_at IS NULL
    LIMIT 1
  `)
    .bind(token)
    .first();
}

async function register(request, env, origin) {
  try {
    await ensureAuthTables(env);

    const body = await readBody(request);

    const artistName = String(
      body?.artistName ||
      body?.artist_name ||
      body?.name ||
      body?.artist ||
      ""
    ).trim();

    const email = String(
      body?.email ||
      body?.emailAddress ||
      body?.email_address ||
      ""
    )
      .trim()
      .toLowerCase();

    const password = String(
      body?.password ||
      body?.pass ||
      body?.userPassword ||
      ""
    );

    if (!artistName) {
      return json(
        {
          error: "Artist name is required.",
          code: "ARTIST_NAME_REQUIRED",
        },
        400,
        origin
      );
    }

    if (!email) {
      return json(
        {
          error: "Email is required.",
          code: "EMAIL_REQUIRED",
        },
        400,
        origin
      );
    }

    if (!email.includes("@")) {
      return json(
        {
          error: "Please enter a valid email address.",
          code: "INVALID_EMAIL",
        },
        400,
        origin
      );
    }

    if (!password || password.length < 6) {
      return json(
        {
          error: "Password must be at least 6 characters.",
          code: "PASSWORD_TOO_SHORT",
        },
        400,
        origin
      );
    }

    const existing = await env.DB.prepare(`
      SELECT id, email
      FROM auth_users
      WHERE lower(email) = ?
      LIMIT 1
    `)
      .bind(email)
      .first();

    if (existing) {
      return json(
        {
          error: "An account with this email already exists.",
          code: "EMAIL_EXISTS",
        },
        409,
        origin
      );
    }

    const userId = crypto.randomUUID();
    const now = new Date().toISOString();

    const passwordHash = await hashPassword(password);

    await env.DB.batch([
      env.DB.prepare(`
        INSERT INTO auth_users (
          id,
          email,
          encrypted_password,
          email_confirmed_at,
          raw_app_meta_data,
          raw_user_meta_data,
          created_at,
          updated_at,
          is_sso_user,
          is_anonymous
        )
        VALUES (
          ?,
          ?,
          NULL,
          ?,
          ?,
          ?,
          ?,
          ?,
          0,
          0
        )
      `).bind(
        userId,
        email,
        now,
        JSON.stringify({
          provider: "email",
          providers: ["email"],
        }),
        JSON.stringify({
          artist_name: artistName,
        }),
        now,
        now
      ),

      env.DB.prepare(`
        INSERT INTO auth_local_credentials (
          user_id,
          password_hash,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?)
      `).bind(
        userId,
        passwordHash,
        now,
        now
      ),
    ]);

    let artistCreated = true;

    try {
      await env.DB.prepare(`
        INSERT INTO artists (
          user_id,
          name,
          bio,
          avatar_url,
          location,
          total_plays,
          earnings,
          verified,
          created_at
        )
        VALUES (
          ?,
          ?,
          NULL,
          NULL,
          'Uganda',
          0,
          0,
          0,
          CURRENT_TIMESTAMP
        )
      `)
        .bind(userId, artistName)
        .run();
    } catch (artistError) {
      artistCreated = false;

      console.error(
        "ARTIST_PROFILE_CREATE_FAILED",
        artistError?.message || String(artistError)
      );
    }

    const session = await createSession(env, userId);

    return json(
      {
        ok: true,
        message: "Account created successfully.",
        user: {
          id: userId,
          email,
          artist_name: artistName,
        },
        artist_created: artistCreated,
        session,
        access_token: session.access_token,
      },
      201,
      origin
    );
  } catch (error) {
    console.error(
      "REGISTER_FAILED",
      error?.message || String(error)
    );

    return json(
      {
        error: "Account creation failed.",
        details: error?.message || String(error),
        code: "REGISTER_FAILED",
      },
      500,
      origin
    );
  }
}

async function login(request, env, origin) {
  try {
    await ensureAuthTables(env);

    const body = await readBody(request);

    const email = String(
      body?.email ||
      body?.emailAddress ||
      body?.email_address ||
      ""
    )
      .trim()
      .toLowerCase();

    const password = String(
      body?.password ||
      body?.pass ||
      body?.userPassword ||
      ""
    );

    if (!email || !password) {
      return json(
        {
          error: "Email and password are required.",
        },
        400,
        origin
      );
    }

    const user = await env.DB.prepare(`
      SELECT id, email
      FROM auth_users
      WHERE lower(email) = ?
        AND deleted_at IS NULL
      LIMIT 1
    `)
      .bind(email)
      .first();

    if (!user) {
      return json(
        {
          error: "Invalid email or password.",
        },
        401,
        origin
      );
    }

    const credential = await env.DB.prepare(`
      SELECT password_hash
      FROM auth_local_credentials
      WHERE user_id = ?
      LIMIT 1
    `)
      .bind(user.id)
      .first();

    if (!credential) {
      return json(
        {
          error: "This account has not been migrated to local login yet.",
        },
        401,
        origin
      );
    }

    const valid = await verifyPassword(
      password,
      credential.password_hash
    );

    if (!valid) {
      return json(
        {
          error: "Invalid email or password.",
        },
        401,
        origin
      );
    }

    const session = await createSession(env, user.id);

    return json(
      {
        ok: true,
        user: {
          id: user.id,
          email: user.email,
        },
        session,
        access_token: session.access_token,
      },
      200,
      origin
    );
  } catch (error) {
    console.error(
      "LOGIN_FAILED",
      error?.message || String(error)
    );

    return json(
      {
        error: "Login failed.",
        details: error?.message || String(error),
      },
      500,
      origin
    );
  }
}

async function logout(request, env, origin) {
  try {
    const authorization =
      request.headers.get("Authorization") || "";

    let token = null;

    if (authorization.toLowerCase().startsWith("bearer ")) {
      token = authorization.slice(7).trim();
    }

    if (!token) {
      token = getCookie(request, "nile_session");
    }

    if (token) {
      await env.DB.prepare(`
        DELETE FROM auth_sessions
        WHERE token = ?
      `)
        .bind(token)
        .run();
    }

    return json(
      {
        ok: true,
        message: "Logged out.",
      },
      200,
      origin
    );
  } catch (error) {
    return json(
      {
        error: "Logout failed.",
        details: error?.message || String(error),
      },
      500,
      origin
    );
  }
}

async function me(request, env, origin) {
  try {
    const user = await getCurrentUser(request, env);

    if (!user) {
      return json(
        {
          user: null,
        },
        401,
        origin
      );
    }

    return json(
      {
        user: {
          id: user.id,
          email: user.email,
        },
      },
      200,
      origin
    );
  } catch (error) {
    return json(
      {
        error: "Unable to read current user.",
        details: error?.message || String(error),
      },
      500,
      origin
    );
  }
}

async function health(env, origin) {
  let database = false;
  let storage = false;

  try {
    await env.DB.prepare("SELECT 1 AS ok").first();
    database = true;
  } catch {}

  try {
    if (env.MEDIA_BUCKET) {
      await env.MEDIA_BUCKET.list({
        limit: 1,
      });
      storage = true;
    }
  } catch {}

  return json(
    {
      ok: true,
      service: "nile-soniq",
      database,
      storage,
      time: new Date().toISOString(),
    },
    200,
    origin
  );
}

async function uploadMedia(request, env, origin) {
  if (!env.MEDIA_BUCKET) {
    return json(
      {
        error: "Media storage is not configured.",
      },
      500,
      origin
    );
  }

  const url = new URL(request.url);

  let key = url.searchParams.get("key");

  if (!key) {
    key = `media/${Date.now()}-${randomToken(8)}`;
  }

  const contentType =
    request.headers.get("Content-Type") ||
    "application/octet-stream";

  await env.MEDIA_BUCKET.put(key, request.body, {
    httpMetadata: {
      contentType,
    },
  });

  return json(
    {
      ok: true,
      key,
      url: `/media/${encodeURIComponent(key)}`,
    },
    200,
    origin
  );
}

async function getMedia(request, env, origin) {
  if (!env.MEDIA_BUCKET) {
    return text("Storage unavailable.", 500, origin);
  }

  const url = new URL(request.url);

  const key = decodeURIComponent(
    url.pathname.replace(/^\/media\//, "")
  );

  if (!key) {
    return text("Missing media key.", 400, origin);
  }

  const object = await env.MEDIA_BUCKET.get(key);

  if (!object) {
    return text("Media not found.", 404, origin);
  }

  const headers = new Headers(corsHeaders(origin));

  object.writeHttpMetadata(headers);
  headers.set("ETag", object.httpEtag);

  return new Response(object.body, {
    headers,
  });
}

async function databaseApi(request, env, origin) {
  try {
    const body = await readBody(request);

    const sql = String(
      body?.sql ||
      body?.query ||
      ""
    ).trim();

    const params =
      Array.isArray(body?.params)
        ? body.params
        : Array.isArray(body?.parameters)
        ? body.parameters
        : [];

    if (!sql) {
      return json(
        {
          error: "SQL query is required.",
        },
        400,
        origin
      );
    }

    const result = await env.DB
      .prepare(sql)
      .bind(...params)
      .all();

    return json(
      {
        ok: true,
        data: result.results || [],
        results: result.results || [],
        meta: result.meta || null,
      },
      200,
      origin
    );
  } catch (error) {
    return json(
      {
        error: "Database request failed.",
        details: error?.message || String(error),
      },
      500,
      origin
    );
  }
}

async function rpcApi(request, env, origin) {
  try {
    const body = await readBody(request);

    const functionName = String(
      body?.function ||
      body?.fn ||
      body?.name ||
      ""
    ).trim();

    if (!functionName) {
      return json(
        {
          error: "RPC function name is required.",
        },
        400,
        origin
      );
    }

    return json(
      {
        error: `RPC function '${functionName}' is not available in the local D1 migration yet.`,
      },
      404,
      origin
    );
  } catch (error) {
    return json(
      {
        error: "RPC request failed.",
        details: error?.message || String(error),
      },
      500,
      origin
    );
  }
}

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const origin = request.headers.get("Origin") || "";

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders(origin),
    });
  }

  if (
    path === "/api/health" &&
    request.method === "GET"
  ) {
    return health(env, origin);
  }

  if (
    path === "/api/auth/register" &&
    request.method === "POST"
  ) {
    return register(request, env, origin);
  }

  if (
    path === "/api/auth/login" &&
    request.method === "POST"
  ) {
    return login(request, env, origin);
  }

  if (
    path === "/api/auth/logout" &&
    request.method === "POST"
  ) {
    return logout(request, env, origin);
  }

  if (
    path === "/api/auth/me" &&
    request.method === "GET"
  ) {
    return me(request, env, origin);
  }

  if (
    path === "/api/media/upload" &&
    request.method === "POST"
  ) {
    return uploadMedia(request, env, origin);
  }

  if (
    path.startsWith("/media/") &&
    request.method === "GET"
  ) {
    return getMedia(request, env, origin);
  }

  if (
    path === "/api/db" &&
    request.method === "POST"
  ) {
    return databaseApi(request, env, origin);
  }

  if (
    path === "/api/rpc" &&
    request.method === "POST"
  ) {
    return rpcApi(request, env, origin);
  }

  if (env.ASSETS) {
    return env.ASSETS.fetch(request);
  }

  return json(
    {
      error: "Not found.",
      path,
    },
    404,
    origin
  );
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      const origin =
        request.headers.get("Origin") || "";

      console.error(
        "WORKER_UNHANDLED_ERROR",
        error?.message || String(error)
      );

      return json(
        {
          error: "Internal server error.",
          details: error?.message || String(error),
        },
        500,
        origin
      );
    }
  },
};
