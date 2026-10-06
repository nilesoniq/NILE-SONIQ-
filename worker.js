export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    const corsHeaders = {
      "Access-Control-Allow-Origin": [
        "https://nilesoniq.com",
        "https://www.nilesoniq.com",
        "https://nile-soniq-auth.nilesoniq.workers.dev",
      ].includes(url.origin)
        ? url.origin
        : "https://nilesoniq.com",
      "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Credentials": "true",
    };

    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders,
      });
    }

    try {
      let response;

      if (url.pathname === "/api/health") {
        response = await health(env);
      } else if (
        url.pathname === "/api/auth/register" &&
        method === "POST"
      ) {
        response = await register(request, env);
      } else if (
        url.pathname === "/api/auth/login" &&
        method === "POST"
      ) {
        response = await login(request, env);
      } else if (
        url.pathname === "/api/auth/logout" &&
        method === "POST"
      ) {
        response = await logout(request, env);
      } else if (
        url.pathname === "/api/auth/me" &&
        method === "GET"
      ) {
        response = await me(request, env);
      } else if (
        url.pathname === "/api/storage/upload" &&
        method === "POST"
      ) {
        response = await upload(request, env);
      } else if (
        url.pathname.startsWith("/api/storage/public/") &&
        method === "GET"
      ) {
        response = await publicStorage(request, env, url);
      } else if (
        url.pathname.startsWith("/api/rpc/") &&
        method === "POST"
      ) {
        response = await rpc(request, env, url);
      } else if (
        url.pathname.startsWith("/api/db/") &&
        ["GET", "POST", "PATCH", "DELETE"].includes(method)
      ) {
        response = await dbApi(request, env, url);
      } else {
        response = json({ error: "Not found." }, 404);
      }

      return addCors(response, corsHeaders);
    } catch (error) {
      console.error("UNHANDLED_REQUEST_ERROR", {
        message: String(error?.message || error),
        stack: String(error?.stack || ""),
        pathname: url.pathname,
        method,
      });

      return addCors(
        json(
          {
            error: "Internal server error.",
            details: String(error?.message || error),
          },
          500
        ),
        corsHeaders
      );
    }
  },
};

/* =========================================================
   BASIC HELPERS
========================================================= */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
    },
  });
}

function addCors(response, corsHeaders) {
  const headers = new Headers(response.headers);

  for (const [key, value] of Object.entries(corsHeaders)) {
    headers.set(key, value);
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function nowIso() {
  return new Date().toISOString();
}

function randomToken(bytes = 32) {
  const array = crypto.getRandomValues(new Uint8Array(bytes));
  return bytesToBase64Url(array);
}

function bytesToBase64(bytes) {
  let binary = "";

  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  return btoa(binary);
}

function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64ToBytes(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded =
    normalized + "=".repeat((4 - (normalized.length % 4)) % 4);

  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

/* =========================================================
   PASSWORD HASHING
========================================================= */

async function hashPassword(password, saltBytes = null) {
  console.log("HASH_PASSWORD_STARTED");

  try {
    console.log("HASH_PASSWORD_CREATING_SALT");

    const salt =
      saltBytes || crypto.getRandomValues(new Uint8Array(16));

    console.log("HASH_PASSWORD_IMPORTING_KEY");

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    console.log("HASH_PASSWORD_KEY_IMPORTED");

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: 120000,
        hash: "SHA-256",
      },
      key,
      256
    );

    console.log("HASH_PASSWORD_DERIVED");

    const result =
      `pbkdf2$120000$${bytesToBase64(salt)}$${bytesToBase64(
        new Uint8Array(bits)
      )}`;

    console.log("HASH_PASSWORD_FINISHED");

    return result;
  } catch (error) {
    console.error("HASH_PASSWORD_FAILED", {
      message: String(error?.message || error),
      name: String(error?.name || ""),
      stack: String(error?.stack || ""),
    });

    throw error;
  }
}

async function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.startsWith("pbkdf2$")) {
    return false;
  }

  const parts = storedHash.split("$");

  if (parts.length !== 4) {
    return false;
  }

  const iterations = Number(parts[1]);
  const salt = base64ToBytes(parts[2]);
  const expected = base64ToBytes(parts[3]);

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
    expected.length * 8
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
}

/* =========================================================
   AUTH TABLES
========================================================= */

async function ensureAuthTables(db) {
  console.log("ENSURE_AUTH_TABLES_STARTED");

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS auth_local_credentials (
        user_id TEXT PRIMARY KEY NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
      `
    )
    .run();

  console.log("AUTH_LOCAL_CREDENTIALS_READY");

  await db
    .prepare(
      `
      CREATE TABLE IF NOT EXISTS auth_sessions (
        token TEXT PRIMARY KEY NOT NULL,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      )
      `
    )
    .run();

  console.log("AUTH_SESSIONS_READY");
}

async function tableColumns(db, tableName) {
  const result = await db
    .prepare(`PRAGMA table_info(${tableName})`)
    .all();

  return (result.results || []).map((row) => row.name);
}

/* =========================================================
   HEALTH
========================================================= */

async function health(env) {
  let database = false;
  let storage = false;

  try {
    await env.DB.prepare("SELECT 1").first();
    database = true;
  } catch (error) {
    console.error("HEALTH_DATABASE_FAILED", error);
  }

  try {
    await env.MEDIA_BUCKET.head("health-check");
    storage = true;
  } catch (error) {
    storage = true;
  }

  return json({
    ok: database && storage,
    service: "nile-soniq",
    database,
    storage,
    time: nowIso(),
  });
}

/* =========================================================
   REGISTER
========================================================= */

async function register(request, env) {
  console.log("REGISTER_STARTED");

  try {
    const body = await request.json();

    console.log("REGISTER_BODY_RECEIVED", {
      keys: Object.keys(body || {}),
      hasArtistName: !!body?.artistName,
      hasArtistNameSnake: !!body?.artist_name,
      hasName: !!body?.name,
      hasArtist: !!body?.artist,
      hasEmail: !!body?.email,
      hasPassword: !!body?.password,
    });

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
      console.log("REGISTER_VALIDATION_FAILED_ARTIST_NAME");

      return json(
        {
          error: "Artist name is required.",
        },
        400
      );
    }

    if (!email || !email.includes("@")) {
      console.log("REGISTER_VALIDATION_FAILED_EMAIL");

      return json(
        {
          error: "A valid email is required.",
        },
        400
      );
    }

    if (password.length < 6) {
      console.log("REGISTER_VALIDATION_FAILED_PASSWORD");

      return json(
        {
          error: "Password must be at least 6 characters.",
        },
        400
      );
    }

    console.log("REGISTER_VALIDATION_PASSED");

    const db = env.DB;

    await ensureAuthTables(db);

    console.log("REGISTER_AUTH_TABLES_READY");

    const existing = await db
      .prepare(
        `
        SELECT id, email
        FROM auth_users
        WHERE lower(email) = lower(?)
        LIMIT 1
        `
      )
      .bind(email)
      .first();

    if (existing) {
      console.log("REGISTER_EXISTING_USER_FOUND", {
        userId: existing.id,
      });

      const existingCredential = await db
        .prepare(
          `
          SELECT user_id
          FROM auth_local_credentials
          WHERE user_id = ?
          LIMIT 1
          `
        )
        .bind(existing.id)
        .first();

      if (existingCredential) {
        console.log("REGISTER_EXISTING_CREDENTIAL_FOUND");

        return json(
          {
            error: "An account with this email already exists.",
          },
          409
        );
      }

      console.log("REGISTER_REPAIRING_EXISTING_USER");

      const repairedHash = await hashPassword(password);

      console.log("REGISTER_REPAIR_HASH_FINISHED");

      const columns = await tableColumns(
        db,
        "auth_local_credentials"
      );

      if (columns.includes("updated_at")) {
        await db
          .prepare(
            `
            INSERT INTO auth_local_credentials
            (
              user_id,
              password_hash,
              created_at,
              updated_at
            )
            VALUES (?, ?, ?, ?)
            `
          )
          .bind(
            existing.id,
            repairedHash,
            nowIso(),
            nowIso()
          )
          .run();
      } else {
        await db
          .prepare(
            `
            INSERT INTO auth_local_credentials
            (
              user_id,
              password_hash,
              created_at
            )
            VALUES (?, ?, ?)
            `
          )
          .bind(
            existing.id,
            repairedHash,
            nowIso()
          )
          .run();
      }

      console.log("REGISTER_REPAIR_CREDENTIAL_INSERTED");

      const token = randomToken(32);

      await db
        .prepare(
          `
          INSERT INTO auth_sessions
          (
            token,
            user_id,
            created_at,
            expires_at
          )
          VALUES (?, ?, ?, ?)
          `
        )
        .bind(
          token,
          existing.id,
          nowIso(),
          new Date(
            Date.now() + 1000 * 60 * 60 * 24 * 30
          ).toISOString()
        )
        .run();

      console.log("REGISTER_REPAIR_SESSION_CREATED");

      return json({
        user: {
          id: existing.id,
          email,
        },
        session: {
          access_token: token,
          token_type: "bearer",
        },
      });
    }

    console.log("REGISTER_CREATING_AUTH_USER");

    const userId = crypto.randomUUID();

    await db
      .prepare(
        `
        INSERT INTO auth_users
        (
          id,
          email,
          encrypted_password,
          created_at,
          updated_at,
          raw_app_meta_data,
          raw_user_meta_data
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        `
      )
      .bind(
        userId,
        email,
        null,
        nowIso(),
        nowIso(),
        JSON.stringify({
          provider: "email",
        }),
        JSON.stringify({
          artist_name: artistName,
        })
      )
      .run();

    console.log("AUTH_USER_CREATED", {
      userId,
    });

    console.log("REGISTER_HASH_STARTED");

    const passwordHash = await hashPassword(password);

    console.log("REGISTER_HASH_FINISHED");

    const credentialColumns = await tableColumns(
      db,
      "auth_local_credentials"
    );

    console.log(
      "REGISTER_CREDENTIAL_COLUMNS",
      credentialColumns
    );

    if (credentialColumns.includes("updated_at")) {
      console.log(
        "REGISTER_CREDENTIAL_INSERT_WITH_UPDATED_AT"
      );

      await db
        .prepare(
          `
          INSERT INTO auth_local_credentials
          (
            user_id,
            password_hash,
            created_at,
            updated_at
          )
          VALUES (?, ?, ?, ?)
          `
        )
        .bind(
          userId,
          passwordHash,
          nowIso(),
          nowIso()
        )
        .run();
    } else {
      console.log(
        "REGISTER_CREDENTIAL_INSERT_THREE_COLUMNS"
      );

      await db
        .prepare(
          `
          INSERT INTO auth_local_credentials
          (
            user_id,
            password_hash,
            created_at
          )
          VALUES (?, ?, ?)
          `
        )
        .bind(
          userId,
          passwordHash,
          nowIso()
        )
        .run();
    }

    console.log("REGISTER_CREDENTIAL_INSERTED");

    try {
      console.log("REGISTER_ARTIST_INSERT_STARTED");

      await db
        .prepare(
          `
          INSERT INTO artists
          (
            id,
            user_id,
            name,
            location,
            created_at
          )
          VALUES (?, ?, ?, ?, ?)
          `
        )
        .bind(
          crypto.randomUUID(),
          userId,
          artistName,
          "Uganda",
          nowIso()
        )
        .run();

      console.log("REGISTER_ARTIST_INSERTED");
    } catch (artistError) {
      console.error("REGISTER_ARTIST_INSERT_FAILED", {
        message: String(
          artistError?.message || artistError
        ),
        stack: String(artistError?.stack || ""),
      });
    }

    console.log("REGISTER_SESSION_CREATE_STARTED");

    const token = randomToken(32);

    await db
      .prepare(
        `
        INSERT INTO auth_sessions
        (
          token,
          user_id,
          created_at,
          expires_at
        )
        VALUES (?, ?, ?, ?)
        `
      )
      .bind(
        token,
        userId,
        nowIso(),
        new Date(
          Date.now() + 1000 * 60 * 60 * 24 * 30
        ).toISOString()
      )
      .run();

    console.log("REGISTER_SESSION_CREATED");

    console.log("REGISTER_COMPLETED", {
      userId,
    });

    return json(
      {
        user: {
          id: userId,
          email,
          artistName,
        },
        session: {
          access_token: token,
          token_type: "bearer",
        },
      },
      201
    );
  } catch (error) {
    console.error("REGISTER_FAILED", {
      message: String(error?.message || error),
      name: String(error?.name || ""),
      stack: String(error?.stack || ""),
    });

    return json(
      {
        error: "Account creation failed.",
        details: String(error?.message || error),
      },
      500
    );
  }
}

/* =========================================================
   LOGIN
========================================================= */

async function login(request, env) {
  try {
    const body = await request.json();

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
        400
      );
    }

    await ensureAuthTables(env.DB);

    const user = await env.DB
      .prepare(
        `
        SELECT id, email
        FROM auth_users
        WHERE lower(email) = lower(?)
        LIMIT 1
        `
      )
      .bind(email)
      .first();

    if (!user) {
      return json(
        {
          error: "Invalid email or password.",
        },
        401
      );
    }

    const credential = await env.DB
      .prepare(
        `
        SELECT password_hash
        FROM auth_local_credentials
        WHERE user_id = ?
        LIMIT 1
        `
      )
      .bind(user.id)
      .first();

    if (!credential) {
      return json(
        {
          error: "Invalid email or password.",
        },
        401
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
        401
      );
    }

    const token = randomToken(32);

    await env.DB
      .prepare(
        `
        INSERT INTO auth_sessions
        (
          token,
          user_id,
          created_at,
          expires_at
        )
        VALUES (?, ?, ?, ?)
        `
      )
      .bind(
        token,
        user.id,
        nowIso(),
        new Date(
          Date.now() + 1000 * 60 * 60 * 24 * 30
        ).toISOString()
      )
      .run();

    return json({
      user: {
        id: user.id,
        email: user.email,
      },
      session: {
        access_token: token,
        token_type: "bearer",
      },
    });
  } catch (error) {
    console.error("LOGIN_FAILED", {
      message: String(error?.message || error),
      stack: String(error?.stack || ""),
    });

    return json(
      {
        error: "Login failed.",
        details: String(error?.message || error),
      },
      500
    );
  }
}

/* =========================================================
   LOGOUT
========================================================= */

async function logout(request, env) {
  const token = getBearerToken(request);

  if (token) {
    await env.DB
      .prepare(
        `
        DELETE FROM auth_sessions
        WHERE token = ?
        `
      )
      .bind(token)
      .run();
  }

  return json({
    ok: true,
  });
}

/* =========================================================
   CURRENT USER
========================================================= */

async function me(request, env) {
  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        error: "Unauthorized.",
      },
      401
    );
  }

  const session = await env.DB
    .prepare(
      `
      SELECT
        s.user_id,
        s.expires_at,
        u.email
      FROM auth_sessions s
      JOIN auth_users u
        ON u.id = s.user_id
      WHERE s.token = ?
      LIMIT 1
      `
    )
    .bind(token)
    .first();

  if (!session) {
    return json(
      {
        error: "Unauthorized.",
      },
      401
    );
  }

  if (
    session.expires_at &&
    new Date(session.expires_at).getTime() < Date.now()
  ) {
    return json(
      {
        error: "Session expired.",
      },
      401
    );
  }

  return json({
    user: {
      id: session.user_id,
      email: session.email,
    },
  });
}

function getBearerToken(request) {
  const header =
    request.headers.get("Authorization") || "";

  if (!header.toLowerCase().startsWith("bearer ")) {
    return null;
  }

  return header.slice(7).trim();
}

/* =========================================================
   STORAGE
========================================================= */

async function upload(request, env) {
  const contentType =
    request.headers.get("Content-Type") ||
    "application/octet-stream";

  const filename =
    request.headers.get("X-Filename") ||
    `upload-${crypto.randomUUID()}`;

  const safeFilename = filename
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .slice(0, 180);

  const key =
    `${Date.now()}-${crypto.randomUUID()}-${safeFilename}`;

  await env.MEDIA_BUCKET.put(
    key,
    request.body,
    {
      httpMetadata: {
        contentType,
      },
    }
  );

  return json({
    ok: true,
    key,
    url:
      `/api/storage/public/${encodeURIComponent(key)}`,
  });
}

async function publicStorage(request, env, url) {
  const encodedKey =
    url.pathname.slice(
      "/api/storage/public/".length
    );

  const key = decodeURIComponent(encodedKey);

  const object = await env.MEDIA_BUCKET.get(key);

  if (!object) {
    return new Response("Not found.", {
      status: 404,
    });
  }

  const headers = new Headers();

  object.writeHttpMetadata(headers);

  headers.set(
    "Cache-Control",
    "public, max-age=31536000, immutable"
  );

  return new Response(object.body, {
    headers,
  });
}

/* =========================================================
   RPC
========================================================= */

async function rpc(request, env, url) {
  const functionName = decodeURIComponent(
    url.pathname.slice("/api/rpc/".length)
  );

  if (!functionName) {
    return json(
      {
        error: "RPC function name is required.",
      },
      400
    );
  }

  let body = {};

  try {
    body = await request.json();
  } catch {
    body = {};
  }

  console.log("RPC_REQUEST", {
    functionName,
  });

  return json(
    {
      error:
        `RPC function "${functionName}" is not implemented in the D1 migration yet.`,
      args: body,
    },
    501
  );
}

/* =========================================================
   DATABASE API
========================================================= */

const ALLOWED_TABLES = new Set([
  "admins",
  "artist_payouts",
  "artist_wallets",
  "artists",
  "auth_identities",
  "auth_users",
  "comments",
  "copyright_removals",
  "likes",
  "news",
  "news_comments",
  "news_reactions",
  "platform_deposits",
  "platform_payouts",
  "platform_wallet",
  "songs",
  "song_play_log",
]);

function assertAllowedTable(table) {
  if (!ALLOWED_TABLES.has(table)) {
    throw new Error("Table not allowed.");
  }
}

async function dbApi(request, env, url) {
  const table = decodeURIComponent(
    url.pathname.slice("/api/db/".length)
  );

  assertAllowedTable(table);

  const method = request.method.toUpperCase();

  if (method === "GET") {
    return dbSelect(request, env, table, url);
  }

  if (method === "POST") {
    return dbInsert(request, env, table);
  }

  if (method === "PATCH") {
    return dbUpdate(request, env, table);
  }

  if (method === "DELETE") {
    return dbDelete(request, env, table);
  }

  return json(
    {
      error: "Method not allowed.",
    },
    405
  );
}

async function dbSelect(request, env, table, url) {
  const limit = Math.min(
    Number(url.searchParams.get("limit") || 100),
    500
  );

  const result = await env.DB
    .prepare(
      `SELECT * FROM ${table} LIMIT ?`
    )
    .bind(limit)
    .all();

  return json({
    data: result.results || [],
  });
}

async function dbInsert(request, env, table) {
  const body = await request.json();

  if (!body || typeof body !== "object") {
    return json(
      {
        error: "JSON object required.",
      },
      400
    );
  }

  const entries = Object.entries(body);

  if (!entries.length) {
    return json(
      {
        error: "No fields supplied.",
      },
      400
    );
  }

  const columns = entries.map(([key]) => key);

  for (const column of columns) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(column)) {
      return json(
        {
          error: "Invalid column name.",
        },
        400
      );
    }
  }

  const placeholders =
    columns.map(() => "?").join(", ");

  const result = await env.DB
    .prepare(
      `INSERT INTO ${table} (${columns.join(
        ", "
      )}) VALUES (${placeholders})`
    )
    .bind(...entries.map(([, value]) => value))
    .run();

  return json({
    ok: true,
    success: result.success,
  });
}

async function dbUpdate(request, env, table) {
  const body = await request.json();

  const id = body?.id;

  if (!id) {
    return json(
      {
        error: "id is required.",
      },
      400
    );
  }

  const updates = Object.entries(body).filter(
    ([key]) => key !== "id"
  );

  if (!updates.length) {
    return json(
      {
        error: "No fields to update.",
      },
      400
    );
  }

  for (const [column] of updates) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(column)) {
      return json(
        {
          error: "Invalid column name.",
        },
        400
      );
    }
  }

  const setSql = updates
    .map(([column]) => `${column} = ?`)
    .join(", ");

  const values = updates.map(([, value]) => value);

  const result = await env.DB
    .prepare(
      `UPDATE ${table} SET ${setSql} WHERE id = ?`
    )
    .bind(...values, id)
    .run();

  return json({
    ok: true,
    success: result.success,
  });
}

async function dbDelete(request, env, table) {
  const body = await request.json();

  const id = body?.id;

  if (!id) {
    return json(
      {
        error: "id is required.",
      },
      400
    );
  }

  const result = await env.DB
    .prepare(
      `DELETE FROM ${table} WHERE id = ?`
    )
    .bind(id)
    .run();

  return json({
    ok: true,
    success: result.success,
  });
    }
