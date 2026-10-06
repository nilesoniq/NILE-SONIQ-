export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      if (request.method === "OPTIONS") {
        return cors(new Response(null, { status: 204 }));
      }

      // Health check
      if (path === "/api/health") {
        return json({
          ok: true,
          service: "nile-soniq-auth",
          database: !!env.DB,
          storage: !!env.MEDIA_BUCKET
        });
      }

      // ---------------------------------------------------------
      // AUTH
      // ---------------------------------------------------------

      if (path === "/api/auth/register" && request.method === "POST") {
        return register(request, env);
      }

      if (path === "/api/auth/login" && request.method === "POST") {
        return login(request, env);
      }

      if (path === "/api/auth/logout" && request.method === "POST") {
        return logout(request, env);
      }

      if (path === "/api/auth/me" && request.method === "GET") {
        return me(request, env);
      }

      // ---------------------------------------------------------
      // DATABASE API
      // ---------------------------------------------------------

      if (path.startsWith("/api/db/")) {
        return databaseApi(request, env);
      }

      // ---------------------------------------------------------
      // RPC
      // ---------------------------------------------------------

      if (path.startsWith("/api/rpc/")) {
        return rpcApi(request, env);
      }

      // ---------------------------------------------------------
      // R2 STORAGE
      // ---------------------------------------------------------

      if (path === "/api/storage/upload" && request.method === "POST") {
        return storageUpload(request, env);
      }

      if (
        path.startsWith("/api/storage/public/") &&
        request.method === "GET"
      ) {
        return storagePublic(request, env);
      }

      // ---------------------------------------------------------
      // PAYMENT PLACEHOLDERS
      // ---------------------------------------------------------

      if (
        path === "/api/payments/pesajet-collection" &&
        request.method === "POST"
      ) {
        return paymentProxy(
          request,
          env,
          env.PESAJET_COLLECTION_URL
        );
      }

      if (
        path === "/api/payments/pesajet-disbursement" &&
        request.method === "POST"
      ) {
        return paymentProxy(
          request,
          env,
          env.PESAJET_DISBURSEMENT_URL
        );
      }

      // ---------------------------------------------------------
      // CLOUDFLARE ASSETS
      // ---------------------------------------------------------

      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return json(
        {
          error: "Not found"
        },
        404
      );
    } catch (error) {
      console.error("Worker error:", error);

      return json(
        {
          error: error?.message || "Internal server error"
        },
        500
      );
    }
  }
};


// =============================================================
// RESPONSE HELPERS
// =============================================================

function cors(response) {
  const headers = new Headers(response.headers);

  headers.set("Access-Control-Allow-Origin", "*");
  headers.set(
    "Access-Control-Allow-Methods",
    "GET,POST,PATCH,PUT,DELETE,OPTIONS"
  );
  headers.set(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );
  headers.set("Access-Control-Allow-Credentials", "true");

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}


function json(data, status = 200, extraHeaders = {}) {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });

  for (const [key, value] of Object.entries(extraHeaders)) {
    headers.set(key, value);
  }

  return cors(
    new Response(JSON.stringify(data), {
      status,
      headers
    })
  );
}


// =============================================================
// AUTH CONFIG
// =============================================================

const SUPABASE_URL =
  "https://nxiygxnzlusasgzdknft.supabase.co";

const SUPABASE_PUBLISHABLE_KEY =
  "sb_publishable_MJYDrg3qcgynvoRTWHQvAA_qt7nRTDw";


// =============================================================
// DATABASE BOOTSTRAP
// =============================================================

async function ensureAuthTables(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS auth_local_credentials (
      user_id TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS auth_sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `).run();
}


// =============================================================
// PASSWORD HASHING
// =============================================================

const PBKDF2_ITERATIONS = 120000;


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


function randomBase64(bytes = 16) {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return bytesToBase64(array);
}


async function derivePassword(password, saltBase64) {
  const salt = base64ToBytes(saltBase64);

  const keyMaterial =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      {
        name: "PBKDF2"
      },
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      keyMaterial,
      256
    );

  return bytesToBase64(
    new Uint8Array(bits)
  );
}


function safeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |=
      a.charCodeAt(i) ^
      b.charCodeAt(i);
  }

  return result === 0;
}


async function hashPassword(password) {
  const salt = randomBase64(16);

  const hash =
    await derivePassword(
      password,
      salt
    );

  return {
    hash,
    salt
  };
}


async function verifyLocalPassword(
  password,
  hash,
  salt
) {
  const calculated =
    await derivePassword(
      password,
      salt
    );

  return safeEqual(
    calculated,
    hash
  );
}


// =============================================================
// SESSION
// =============================================================

function sessionCookie(id) {
  return [
    "nile_session=" + encodeURIComponent(id),
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=2592000"
  ].join("; ");
}


function clearSessionCookie() {
  return [
    "nile_session=",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0"
  ].join("; ");
}


function getCookie(request, name) {
  const cookieHeader =
    request.headers.get("Cookie") || "";

  const parts =
    cookieHeader.split(";");

  for (const part of parts) {
    const [key, ...rest] =
      part.trim().split("=");

    if (key === name) {
      return decodeURIComponent(
        rest.join("=")
      );
    }
  }

  return null;
}


async function createSession(userId, env) {
  await ensureAuthTables(env);

  const id = crypto.randomUUID();

  const now =
    new Date();

  const expires =
    new Date(
      now.getTime() +
      30 * 24 * 60 * 60 * 1000
    );

  await env.DB.prepare(`
    INSERT INTO auth_sessions
      (id, user_id, expires_at, created_at)
    VALUES (?, ?, ?, ?)
  `)
    .bind(
      id,
      userId,
      expires.toISOString(),
      now.toISOString()
    )
    .run();

  return id;
}


async function getSessionUser(request, env) {
  await ensureAuthTables(env);

  const sessionId =
    getCookie(
      request,
      "nile_session"
    );

  if (!sessionId) {
    return null;
  }

  const row =
    await env.DB.prepare(`
      SELECT
        s.id AS session_id,
        s.user_id,
        s.expires_at,
        u.id,
        u.email,
        u.raw_user_meta_data,
        u.created_at
      FROM auth_sessions s
      JOIN auth_users u
        ON u.id = s.user_id
      WHERE s.id = ?
      LIMIT 1
    `)
      .bind(sessionId)
      .first();

  if (!row) {
    return null;
  }

  if (
    row.expires_at &&
    new Date(row.expires_at) <= new Date()
  ) {
    await env.DB.prepare(
      "DELETE FROM auth_sessions WHERE id = ?"
    )
      .bind(sessionId)
      .run();

    return null;
  }

  return row;
}


// =============================================================
// USER / ARTIST HELPERS
// =============================================================

async function getArtistForUser(userId, env) {
  try {
    const row =
      await env.DB.prepare(`
        SELECT *
        FROM artists
        WHERE user_id = ?
        LIMIT 1
      `)
        .bind(userId)
        .first();

    return row || null;
  } catch {
    return null;
  }
}


async function getAdminForUser(userId, env) {
  try {
    const row =
      await env.DB.prepare(`
        SELECT *
        FROM admins
        WHERE user_id = ?
        LIMIT 1
      `)
        .bind(userId)
        .first();

    return row || null;
  } catch {
    return null;
  }
}


async function publicUser(row, env) {
  if (!row) {
    return null;
  }

  let metadata = {};

  try {
    metadata =
      row.raw_user_meta_data
        ? JSON.parse(
            row.raw_user_meta_data
          )
        : {};
  } catch {
    metadata = {};
  }

  return {
    id: row.id,
    email: row.email || null,
    artist_name:
      metadata.artist_name ||
      metadata.name ||
      null,
    created_at:
      row.created_at || null
  };
}


// =============================================================
// AUTH: LOGIN
// =============================================================

async function login(request, env) {
  const body =
    await request.json().catch(
      () => ({})
    );

  const email =
    String(body.email || "")
      .trim()
      .toLowerCase();

  const password =
    String(body.password || "");

  if (!email || !password) {
    return json(
      {
        success: false,
        error:
          "Email and password are required."
      },
      400
    );
  }

  await ensureAuthTables(env);

  const user =
    await env.DB.prepare(`
      SELECT *
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
        success: false,
        error: "Invalid credentials"
      },
      401
    );
  }

  let authenticated = false;

  // -----------------------------------------------------------
  // FIRST: locally migrated password
  // -----------------------------------------------------------

  const local =
    await env.DB.prepare(`
      SELECT
        password_hash,
        password_salt
      FROM auth_local_credentials
      WHERE user_id = ?
      LIMIT 1
    `)
      .bind(user.id)
      .first();

  if (local) {
    authenticated =
      await verifyLocalPassword(
        password,
        local.password_hash,
        local.password_salt
      );
  }

  // -----------------------------------------------------------
  // SECOND: legacy Supabase password
  // -----------------------------------------------------------

  if (
    !authenticated &&
    user.encrypted_password
  ) {
    authenticated =
      await verifyLegacySupabasePassword(
        email,
        password
      );

    // Migrate password verification
    // to D1 after successful legacy login.
    if (authenticated) {
      const credentials =
        await hashPassword(password);

      const now =
        new Date().toISOString();

      await env.DB.prepare(`
        INSERT INTO auth_local_credentials
          (
            user_id,
            password_hash,
            password_salt,
            created_at,
            updated_at
          )
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(user_id)
        DO UPDATE SET
          password_hash = excluded.password_hash,
          password_salt = excluded.password_salt,
          updated_at = excluded.updated_at
      `)
        .bind(
          user.id,
          credentials.hash,
          credentials.salt,
          now,
          now
        )
        .run();
    }
  }

  if (!authenticated) {
    return json(
      {
        success: false,
        error: "Invalid credentials"
      },
      401
    );
  }

  const sessionId =
    await createSession(
      user.id,
      env
    );

  const artist =
    await getArtistForUser(
      user.id,
      env
    );

  const admin =
    await getAdminForUser(
      user.id,
      env
    );

  return json(
    {
      success: true,
      user:
        await publicUser(
          user,
          env
        ),
      artist,
      admin
    },
    200,
    {
      "Set-Cookie":
        sessionCookie(sessionId)
    }
  );
}


// =============================================================
// LEGACY SUPABASE PASSWORD VERIFICATION
// =============================================================

async function verifyLegacySupabasePassword(
  email,
  password
) {
  try {
    const response =
      await fetch(
        `${SUPABASE_URL}/auth/v1/token?grant_type=password`,
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json",
            "apikey":
              SUPABASE_PUBLISHABLE_KEY
          },
          body: JSON.stringify({
            email,
            password
          })
        }
      );

    return response.ok;
  } catch (error) {
    console.error(
      "Legacy password verification error:",
      error
    );

    return false;
  }
}


// =============================================================
// AUTH: REGISTER
// =============================================================

async function register(request, env) {
  const body =
    await request.json().catch(
      () => ({})
    );

  const email =
    String(body.email || "")
      .trim()
      .toLowerCase();

  const password =
    String(body.password || "");

  const artistName =
    String(
      body.artist_name || ""
    ).trim();

  if (!email || !password) {
    return json(
      {
        success: false,
        error:
          "Email and password are required."
      },
      400
    );
  }

  if (password.length < 8) {
    return json(
      {
        success: false,
        error:
          "Password must be at least 8 characters."
      },
      400
    );
  }

  await ensureAuthTables(env);

  const existing =
    await env.DB.prepare(`
      SELECT id
      FROM auth_users
      WHERE lower(email) = ?
      LIMIT 1
    `)
      .bind(email)
      .first();

  if (existing) {
    return json(
      {
        success: false,
        error:
          "An account with this email already exists."
      },
      409
    );
  }

  const userId =
    crypto.randomUUID();

  const credentials =
    await hashPassword(password);

  const now =
    new Date().toISOString();

  // Existing auth_users table is a migrated
  // Supabase Auth table. Only populate fields
  // that are actually required by its schema.
  await env.DB.prepare(`
    INSERT INTO auth_users
      (
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
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
  `)
    .bind(
      userId,
      email,
      "",
      now,
      JSON.stringify({
        provider: "email",
        providers: ["email"]
      }),
      JSON.stringify({
        artist_name:
          artistName || null
      }),
      now,
      now
    )
    .run();

  await env.DB.prepare(`
    INSERT INTO auth_local_credentials
      (
        user_id,
        password_hash,
        password_salt,
        created_at,
        updated_at
      )
    VALUES (?, ?, ?, ?, ?)
  `)
    .bind(
      userId,
      credentials.hash,
      credentials.salt,
      now,
      now
    )
    .run();

  // Create an artist record when the artists
  // table contains the expected user_id column.
  try {
    const artistColumns =
      await env.DB.prepare(
        "PRAGMA table_info(artists)"
      ).all();

    const names =
      (artistColumns.results || [])
        .map(row => row.name);

    if (
      names.includes("user_id") &&
      names.includes("name")
    ) {
      const artistId =
        crypto.randomUUID();

      await env.DB.prepare(`
        INSERT INTO artists
          (id, user_id, name)
        VALUES (?, ?, ?)
      `)
        .bind(
          artistId,
          userId,
          artistName || email.split("@")[0]
        )
        .run();
    }
  } catch (error) {
    console.error(
      "Artist creation skipped:",
      error
    );
  }

  const sessionId =
    await createSession(
      userId,
      env
    );

  const user =
    await env.DB.prepare(`
      SELECT *
      FROM auth_users
      WHERE id = ?
      LIMIT 1
    `)
      .bind(userId)
      .first();

  const artist =
    await getArtistForUser(
      userId,
      env
    );

  return json(
    {
      success: true,
      user:
        await publicUser(
          user,
          env
        ),
      artist,
      admin: null
    },
    201,
    {
      "Set-Cookie":
        sessionCookie(sessionId)
    }
  );
}


// =============================================================
// AUTH: ME
// =============================================================

async function me(request, env) {
  const session =
    await getSessionUser(
      request,
      env
    );

  if (!session) {
    return json({
      authenticated: false,
      user: null,
      artist: null,
      admin: null
    });
  }

  const artist =
    await getArtistForUser(
      session.user_id,
      env
    );

  const admin =
    await getAdminForUser(
      session.user_id,
      env
    );

  return json({
    authenticated: true,
    user:
      await publicUser(
        session,
        env
      ),
    artist,
    admin
  });
}


// =============================================================
// AUTH: LOGOUT
// =============================================================

async function logout(request, env) {
  const sessionId =
    getCookie(
      request,
      "nile_session"
    );

  if (sessionId) {
    await ensureAuthTables(env);

    await env.DB.prepare(
      "DELETE FROM auth_sessions WHERE id = ?"
    )
      .bind(sessionId)
      .run();
  }

  return json(
    {
      success: true
    },
    200,
    {
      "Set-Cookie":
        clearSessionCookie()
    }
  );
}


// =============================================================
// DATABASE API
// =============================================================

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
  "song_play_log",
  "songs"
]);


function validateTable(name) {
  return (
    ALLOWED_TABLES.has(name)
  );
}


function parseJsonValue(value) {
  if (value === null || value === undefined) {
    return null;
  }

  if (
    value === "true"
  ) {
    return true;
  }

  if (
    value === "false"
  ) {
    return false;
  }

  if (
    value === "null"
  ) {
    return null;
  }

  if (
    /^-?\d+(\.\d+)?$/.test(value)
  ) {
    return Number(value);
  }

  return value;
}


async function databaseApi(request, env) {
  const path =
    new URL(request.url).pathname;

  const table =
    path.replace(
      "/api/db/",
      ""
    ).replace(
      /\/+$/,
      ""
    );

  if (!validateTable(table)) {
    return json(
      {
        error: "Table not allowed."
      },
      400
    );
  }

  const url =
    new URL(request.url);

  if (request.method === "GET") {
    return dbSelect(
      request,
      env,
      table,
      url
    );
  }

  if (
    request.method === "POST"
  ) {
    return dbInsert(
      request,
      env,
      table
    );
  }

  if (
    request.method === "PATCH" ||
    request.method === "PUT"
  ) {
    return dbUpdate(
      request,
      env,
      table,
      url
    );
  }

  if (
    request.method === "DELETE"
  ) {
    return dbDelete(
      request,
      env,
      table,
      url
    );
  }

  return json(
    {
      error:
        "Method not supported."
    },
    405
  );
}


// -------------------------------------------------------------
// SELECT
// -------------------------------------------------------------

async function dbSelect(
  request,
  env,
  table,
  url
) {
  let columns =
    url.searchParams.get(
      "select"
    ) || "*";

  // Keep the API safe by allowing only
  // simple column selections.
  if (
    !/^[A-Za-z0-9_*,\s]+$/.test(
      columns
    )
  ) {
    columns = "*";
  }

  const where = [];
  const values = [];

  for (
    const [key, value]
    of url.searchParams.entries()
  ) {
    if (
      key === "select" ||
      key === "order" ||
      key === "limit" ||
      key === "offset"
    ) {
      continue;
    }

    const match =
      key.match(
        /^([A-Za-z0-9_]+)\.(eq|neq|gt|gte|lt|lte|like|ilike|is)$/
      );

    if (!match) {
      continue;
    }

    const column =
      match[1];

    const operator =
      match[2];

    if (
      operator === "eq"
    ) {
      where.push(
        `"${column}" = ?`
      );
      values.push(
        parseJsonValue(value)
      );
    }

    if (
      operator === "neq"
    ) {
      where.push(
        `"${column}" != ?`
      );
      values.push(
        parseJsonValue(value)
      );
    }

    if (
      operator === "gt"
    ) {
      where.push(
        `"${column}" > ?`
      );
      values.push(
        parseJsonValue(value)
      );
    }

    if (
      operator === "gte"
    ) {
      where.push(
        `"${column}" >= ?`
      );
      values.push(
        parseJsonValue(value)
      );
    }

    if (
      operator === "lt"
    ) {
      where.push(
        `"${column}" < ?`
      );
      values.push(
        parseJsonValue(value)
      );
    }

    if (
      operator === "lte"
    ) {
      where.push(
        `"${column}" <= ?`
      );
      values.push(
        parseJsonValue(value)
      );
    }

    if (
      operator === "like"
    ) {
      where.push(
        `"${column}" LIKE ?`
      );
      values.push(value);
    }

    if (
      operator === "ilike"
    ) {
      where.push(
        `LOWER("${column}") LIKE LOWER(?)`
      );
      values.push(value);
    }

    if (
      operator === "is"
    ) {
      if (value === "null") {
        where.push(
          `"${column}" IS NULL`
        );
      }

      if (
        value === "not.null"
      ) {
        where.push(
          `"${column}" IS NOT NULL`
        );
      }
    }
  }

  let sql =
    `SELECT ${columns} FROM "${table}"`;

  if (where.length) {
    sql +=
      " WHERE " +
      where.join(" AND ");
  }

  const order =
    url.searchParams.get(
      "order"
    );

  if (order) {
    const parts =
      order.split(",");

    const orderParts = [];

    for (
      const part
      of parts
    ) {
      const pieces =
        part.split(".");

      const column =
        pieces[0];

      if (
        !/^[A-Za-z0-9_]+$/.test(
          column
        )
      ) {
        continue;
      }

      const direction =
        pieces[1] === "desc"
          ? "DESC"
          : "ASC";

      orderParts.push(
        `"${column}" ${direction}`
      );
    }

    if (orderParts.length) {
      sql +=
        " ORDER BY " +
        orderParts.join(", ");
    }
  }

  const limit =
    Number(
      url.searchParams.get(
        "limit"
      ) || 100
    );

  const offset =
    Number(
      url.searchParams.get(
        "offset"
      ) || 0
    );

  sql +=
    ` LIMIT ${Math.min(
      Math.max(limit, 1),
      500
    )}`;

  if (offset > 0) {
    sql +=
      ` OFFSET ${Math.max(
        offset,
        0
      )}`;
  }

  const statement =
    env.DB.prepare(sql);

  const result =
    values.length
      ? await statement.bind(
          ...values
        ).all()
      : await statement.all();

  return json({
    data:
      result.results || []
  });
}


// -------------------------------------------------------------
// INSERT
// -------------------------------------------------------------

async function dbInsert(
  request,
  env,
  table
) {
  const body =
    await request.json().catch(
      () => null
    );

  if (
    !body ||
    typeof body !== "object"
  ) {
    return json(
      {
        error:
          "Invalid JSON body."
      },
      400
    );
  }

  const rows =
    Array.isArray(body)
      ? body
      : [body];

  if (!rows.length) {
    return json({
      data: []
    });
  }

  const first =
    rows[0];

  const columns =
    Object.keys(first)
      .filter(
        key =>
          /^[A-Za-z0-9_]+$/.test(
            key
          )
      );

  if (!columns.length) {
    return json(
      {
        error:
          "No valid columns."
      },
      400
    );
  }

  const placeholders =
    columns
      .map(() => "?")
      .join(", ");

  const sql =
    `INSERT INTO "${table}" (${columns
      .map(c => `"${c}"`)
      .join(", ")})
     VALUES (${placeholders})`;

  const statements =
    rows.map(row =>
      env.DB.prepare(sql).bind(
        ...columns.map(
          column =>
            row[column] ?? null
        )
      )
    );

  await env.DB.batch(
    statements
  );

  return json(
    {
      success: true
    },
    201
  );
}


// -------------------------------------------------------------
// UPDATE
// -------------------------------------------------------------

async function dbUpdate(
  request,
  env,
  table,
  url
) {
  const body =
    await request.json().catch(
      () => null
    );

  if (
    !body ||
    typeof body !== "object"
  ) {
    return json(
      {
        error:
          "Invalid JSON body."
      },
      400
    );
  }

  const columns =
    Object.keys(body)
      .filter(
        key =>
          /^[A-Za-z0-9_]+$/.test(
            key
          )
      );

  if (!columns.length) {
    return json(
      {
        error:
          "No valid columns."
      },
      400
    );
  }

  const where = [];
  const values = [];

  for (
    const [key, value]
    of url.searchParams.entries()
  ) {
    const match =
      key.match(
        /^([A-Za-z0-9_]+)\.eq$/
      );

    if (!match) {
      continue;
    }

    where.push(
      `"${match[1]}" = ?`
    );

    values.push(
      parseJsonValue(value)
    );
  }

  if (!where.length) {
    return json(
      {
        error:
          "Update requires a filter."
      },
      400
    );
  }

  const setSql =
    columns
      .map(
        column =>
          `"${column}" = ?`
      )
      .join(", ");

  const sql =
    `UPDATE "${table}"
     SET ${setSql}
     WHERE ${where.join(
       " AND "
     )}`;

  const params = [
    ...columns.map(
      column =>
        body[column] ?? null
    ),
    ...values
  ];

  await env.DB.prepare(sql)
    .bind(...params)
    .run();

  return json({
    success: true
  });
}


// -------------------------------------------------------------
// DELETE
// -------------------------------------------------------------

async function dbDelete(
  request,
  env,
  table,
  url
) {
  const where = [];
  const values = [];

  for (
    const [key, value]
    of url.searchParams.entries()
  ) {
    const match =
      key.match(
        /^([A-Za-z0-9_]+)\.eq$/
      );

    if (!match) {
      continue;
    }

    where.push(
      `"${match[1]}" = ?`
    );

    values.push(
      parseJsonValue(value)
    );
  }

  if (!where.length) {
    return json(
      {
        error:
          "Delete requires a filter."
      },
      400
    );
  }

  const sql =
    `DELETE FROM "${table}"
     WHERE ${where.join(
       " AND "
     )}`;

  await env.DB.prepare(sql)
    .bind(...values)
    .run();

  return json({
    success: true
  });
}


// =============================================================
// RPC API
// =============================================================

async function rpcApi(request, env) {
  const path =
    new URL(request.url).pathname;

  const name =
    path.replace(
      "/api/rpc/",
      ""
    );

  const body =
    await request.json().catch(
      () => ({})
    );

  if (
    name ===
    "record_song_play"
  ) {
    return recordSongPlay(
      body,
      env
    );
  }

  if (
    name ===
    "get_platform_completed_total"
  ) {
    return getPlatformCompletedTotal(
      env
    );
  }

  return json(
    {
      error:
        "RPC not found."
    },
    404
  );
}


async function recordSongPlay(
  body,
  env
) {
  const songId =
    body.p_song_id ||
    body.song_id;

  if (!songId) {
    return json(
      {
        error:
          "Song ID is required."
      },
      400
    );
  }

  try {
    await env.DB.prepare(`
      UPDATE songs
      SET plays =
        COALESCE(plays, 0) + 1
      WHERE id = ?
    `)
      .bind(songId)
      .run();
  } catch (error) {
    console.error(
      "Song play update:",
      error
    );
  }

  try {
    const user =
      await getSessionUser(
        new Request(
          "https://internal",
          {
            headers: {}
          }
        ),
        env
      );

    await env.DB.prepare(`
      INSERT INTO song_play_log
        (
          id,
          song_id,
          user_id,
          played_at
        )
      VALUES (?, ?, ?, ?)
    `)
      .bind(
        crypto.randomUUID(),
        songId,
        user?.user_id || null,
        new Date().toISOString()
      )
      .run();
  } catch (error) {
    console.error(
      "Play log:",
      error
    );
  }

  return json({
    success: true
  });
}


async function getPlatformCompletedTotal(
  env
) {
  try {
    const row =
      await env.DB.prepare(`
        SELECT
          COALESCE(
            SUM(amount),
            0
          ) AS total
        FROM platform_deposits
      `).first();

    return json({
      data: row?.total || 0
    });
  } catch {
    return json({
      data: 0
    });
  }
}


// =============================================================
// R2 UPLOAD
// =============================================================

async function storageUpload(
  request,
  env
) {
  if (!env.MEDIA_BUCKET) {
    return json(
      {
        error:
          "R2 storage is not configured."
      },
      500
    );
  }

  const contentType =
    request.headers.get(
      "Content-Type"
    ) ||
    "application/octet-stream";

  const filename =
    request.headers.get(
      "X-File-Name"
    ) ||
    crypto.randomUUID();

  const folder =
    request.headers.get(
      "X-Storage-Folder"
    ) ||
    "uploads";

  const safeFolder =
    folder.replace(
      /[^A-Za-z0-9/_-]/g,
      ""
    );

  const safeFilename =
    filename.replace(
      /[^A-Za-z0-9._-]/g,
      "_"
    );

  const key =
    `${safeFolder}/${crypto.randomUUID()}-${safeFilename}`;

  const body =
    await request.arrayBuffer();

  await env.MEDIA_BUCKET.put(
    key,
    body,
    {
      httpMetadata: {
        contentType
      }
    }
  );

  return json({
    success: true,
    path: key,
    key
  });
}


// =============================================================
// R2 PUBLIC FILE
// =============================================================

async function storagePublic(
  request,
  env
) {
  if (!env.MEDIA_BUCKET) {
    return new Response(
      "Storage unavailable",
      {
        status: 500
      }
    );
  }

  const url =
    new URL(request.url);

  const prefix =
    "/api/storage/public/";

  const path =
    decodeURIComponent(
      url.pathname.slice(
        prefix.length
      )
    );

  const parts =
    path.split("/");

  // First part is the bucket name.
  parts.shift();

  const key =
    parts.join("/");

  if (!key) {
    return new Response(
      "File not found",
      {
        status: 404
      }
    );
  }

  const object =
    await env.MEDIA_BUCKET.get(
      key
    );

  if (!object) {
    return new Response(
      "File not found",
      {
        status: 404
      }
    );
  }

  const headers =
    new Headers();

  object.writeHttpMetadata(
    headers
  );

  headers.set(
    "ETag",
    object.httpEtag
  );

  headers.set(
    "Cache-Control",
    "public, max-age=31536000, immutable"
  );

  return cors(
    new Response(
      object.body,
      {
        headers
      }
    )
  );
}


// =============================================================
// PESAjet PROXY
// =============================================================

async function paymentProxy(
  request,
  env,
  endpoint
) {
  if (!endpoint) {
    return json(
      {
        success: false,
        error:
          "PesaJet endpoint is not configured yet."
      },
      503
    );
  }

  const body =
    await request.text();

  const response =
    await fetch(
      endpoint,
      {
        method: "POST",
        headers: {
          "Content-Type":
            request.headers.get(
              "Content-Type"
            ) ||
            "application/json",
          "Authorization":
            request.headers.get(
              "Authorization"
            ) || ""
        },
        body
      }
    );

  const text =
    await response.text();

  return cors(
    new Response(
      text,
      {
        status:
          response.status,
        headers: {
          "Content-Type":
            response.headers.get(
              "Content-Type"
            ) ||
            "application/json"
        }
      }
    )
  );
        }
