const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store"
};

const ALLOWED_TABLES = new Set([
  "admins",
  "artist_payouts",
  "artist_wallets",
  "artists",
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
  "auth_users",
  "auth_identities"
]);

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...JSON_HEADERS,
      ...extraHeaders
    }
  });
}

function corsHeaders(request) {
  const origin = request.headers.get("Origin");

  const allowed = [
    "https://nilesoniq.com",
    "https://www.nilesoniq.com",
    "https://nile-soniq-auth.nilesoniq.workers.dev"
  ];

  return {
    "Access-Control-Allow-Origin":
      origin && allowed.includes(origin)
        ? origin
        : "https://nile-soniq-auth.nilesoniq.workers.dev",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, X-Requested-With",
    "Access-Control-Allow-Methods":
      "GET, POST, PUT, PATCH, DELETE, OPTIONS"
  };
}

function withCors(response, request) {
  const headers = new Headers(response.headers);

  for (const [key, value] of Object.entries(
    corsHeaders(request)
  )) {
    headers.set(key, value);
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function cleanEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function nowIso() {
  return new Date().toISOString();
}

function makeId() {
  return crypto.randomUUID();
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";

  for (const part of cookieHeader.split(";")) {
    const trimmed = part.trim();

    if (!trimmed) continue;

    const eq = trimmed.indexOf("=");

    if (eq === -1) continue;

    const key = trimmed.slice(0, eq);
    const value = trimmed.slice(eq + 1);

    if (key === name) {
      return decodeURIComponent(value);
    }
  }

  return null;
}

function sessionCookie(token) {
  return [
    `nile_session=${encodeURIComponent(token)}`,
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

/* =======================================================
   PASSWORD HASHING
======================================================= */

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

async function hashPassword(password, saltBytes = null) {
  const salt =
    saltBytes ||
    crypto.getRandomValues(new Uint8Array(16));

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
      iterations: 120000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return `pbkdf2$120000$${bytesToBase64(
    salt
  )}$${bytesToBase64(
    new Uint8Array(bits)
  )}`;
}

async function verifyPassword(password, stored) {
  if (!stored || !stored.startsWith("pbkdf2$")) {
    return false;
  }

  const parts = stored.split("$");

  if (parts.length !== 4) {
    return false;
  }

  const iterations = Number(parts[1]);

  if (!Number.isFinite(iterations)) {
    return false;
  }

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
      hash: "SHA-256"
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
}

/* =======================================================
   AUTH TABLES
======================================================= */

async function tableColumns(db, tableName) {
  const result = await db
    .prepare(`PRAGMA table_info(${tableName})`)
    .all();

  return new Set(
    (result.results || []).map(row => row.name)
  );
}

async function ensureAuthTables(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS auth_local_credentials (
      user_id TEXT PRIMARY KEY NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  let credentialColumns =
    await tableColumns(
      db,
      "auth_local_credentials"
    );

  if (!credentialColumns.has("updated_at")) {
    await db.prepare(`
      ALTER TABLE auth_local_credentials
      ADD COLUMN updated_at TEXT NOT NULL
      DEFAULT CURRENT_TIMESTAMP
    `).run();
  }

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS auth_sessions (
      token TEXT PRIMARY KEY NOT NULL,
      user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    )
  `).run();

  credentialColumns =
    await tableColumns(
      db,
      "auth_local_credentials"
    );

  return credentialColumns;
}

/* =======================================================
   AUTH - REGISTER
======================================================= */

async function register(request, env) {
  let body;

  try {
    body = await request.json();
  } catch (error) {
    return json(
      {
        error: "Invalid JSON request.",
        details: String(error?.message || error)
      },
      400
    );
  }

  const artistName = String(
    body.artist_name ||
    body.artistName ||
    body.name ||
    ""
  ).trim();

  const email = cleanEmail(body.email);
  const password = String(body.password || "");

  if (!artistName) {
    return json(
      { error: "Artist name is required." },
      400
    );
  }

  if (!email) {
    return json(
      { error: "Email is required." },
      400
    );
  }

  if (password.length < 8) {
    return json(
      {
        error:
          "Password must be at least 8 characters."
      },
      400
    );
  }

  try {
    /*
      Make absolutely sure the local auth tables exist
      before attempting registration.
    */

    const credentialColumns =
      await ensureAuthTables(env.DB);

    console.log(
      "AUTH_CREDENTIAL_COLUMNS",
      [...credentialColumns]
    );

    const existing = await env.DB
      .prepare(`
        SELECT id
        FROM auth_users
        WHERE lower(email) = ?
        LIMIT 1
      `)
      .bind(email)
      .first();

    if (existing) {
      /*
        If an earlier failed registration created the
        auth_users row but not credentials, repair that
        account instead of permanently blocking the email.
      */

      const existingCredential =
        await env.DB
          .prepare(`
            SELECT user_id
            FROM auth_local_credentials
            WHERE user_id = ?
            LIMIT 1
          `)
          .bind(existing.id)
          .first();

      if (existingCredential) {
        return json(
          {
            error:
              "An account with this email already exists."
          },
          409
        );
      }

      /*
        Orphaned auth_users row detected.
        Continue using that existing user ID and create
        the missing credential/profile/session.
      */

      const userId = existing.id;
      const timestamp = nowIso();

      const passwordHash =
        await hashPassword(password);

      const credentialColumnsNow =
        await tableColumns(
          env.DB,
          "auth_local_credentials"
        );

      if (
        credentialColumnsNow.has("updated_at")
      ) {
        await env.DB
          .prepare(`
            INSERT INTO auth_local_credentials (
              user_id,
              password_hash,
              created_at,
              updated_at
            )
            VALUES (?, ?, ?, ?)
          `)
          .bind(
            userId,
            passwordHash,
            timestamp,
            timestamp
          )
          .run();
      } else {
        await env.DB
          .prepare(`
            INSERT INTO auth_local_credentials (
              user_id,
              password_hash,
              created_at
            )
            VALUES (?, ?, ?)
          `)
          .bind(
            userId,
            passwordHash,
            timestamp
          )
          .run();
      }

      const token = crypto.randomUUID();

      const expires =
        new Date(
          Date.now() +
          30 * 24 * 60 * 60 * 1000
        ).toISOString();

      await env.DB
        .prepare(`
          INSERT INTO auth_sessions (
            token,
            user_id,
            created_at,
            expires_at
          )
          VALUES (?, ?, ?, ?)
        `)
        .bind(
          token,
          userId,
          timestamp,
          expires
        )
        .run();

      return json(
        {
          success: true,
          repaired: true,
          user: {
            id: userId,
            email,
            artist_name: artistName
          }
        },
        201,
        {
          "Set-Cookie":
            sessionCookie(token)
        }
      );
    }

    const userId = makeId();
    const timestamp = nowIso();

    /*
      Create the auth_users record.
    */

    await env.DB
      .prepare(`
        INSERT INTO auth_users (
          id,
          email,
          encrypted_password,
          email_confirmed_at,
          created_at,
          updated_at,
          is_sso_user,
          is_anonymous
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        userId,
        email,
        "",
        timestamp,
        timestamp,
        timestamp,
        0,
        0
      )
      .run();

    console.log(
      "AUTH_USER_CREATED",
      userId
    );

    /*
      Create password credentials.
    */

    const passwordHash =
      await hashPassword(password);

    const currentColumns =
      await tableColumns(
        env.DB,
        "auth_local_credentials"
      );

    console.log(
      "AUTH_LOCAL_COLUMNS",
      [...currentColumns]
    );

    if (currentColumns.has("updated_at")) {
      await env.DB
        .prepare(`
          INSERT INTO auth_local_credentials (
            user_id,
            password_hash,
            created_at,
            updated_at
          )
          VALUES (?, ?, ?, ?)
        `)
        .bind(
          userId,
          passwordHash,
          timestamp,
          timestamp
        )
        .run();
    } else {
      await env.DB
        .prepare(`
          INSERT INTO auth_local_credentials (
            user_id,
            password_hash,
            created_at
          )
          VALUES (?, ?, ?)
        `)
        .bind(
          userId,
          passwordHash,
          timestamp
        )
        .run();
    }

    console.log(
      "AUTH_CREDENTIAL_CREATED",
      userId
    );

    /*
      Create artist profile.
    */

    try {
      const columns =
        await env.DB
          .prepare(
            `PRAGMA table_info(artists)`
          )
          .all();

      const names = new Set(
        (columns.results || [])
          .map(row => row.name)
      );

      const insertColumns = [];
      const insertValues = [];

      if (names.has("id")) {
        insertColumns.push("id");
        insertValues.push(makeId());
      }

      if (names.has("user_id")) {
        insertColumns.push("user_id");
        insertValues.push(userId);
      }

      if (names.has("name")) {
        insertColumns.push("name");
        insertValues.push(artistName);
      }

      if (names.has("artist_name")) {
        insertColumns.push("artist_name");
        insertValues.push(artistName);
      }

      if (names.has("email")) {
        insertColumns.push("email");
        insertValues.push(email);
      }

      if (names.has("created_at")) {
        insertColumns.push("created_at");
        insertValues.push(timestamp);
      }

      if (names.has("updated_at")) {
        insertColumns.push("updated_at");
        insertValues.push(timestamp);
      }

      if (insertColumns.length) {
        const placeholders =
          insertColumns
            .map(() => "?")
            .join(", ");

        await env.DB
          .prepare(`
            INSERT INTO artists (
              ${insertColumns.join(", ")}
            )
            VALUES (${placeholders})
          `)
          .bind(...insertValues)
          .run();

        console.log(
          "ARTIST_CREATED",
          userId
        );
      }
    } catch (artistError) {
      console.error(
        "ARTIST_PROFILE_WARNING",
        artistError
      );
    }

    /*
      Create login session.
    */

    const token =
      crypto.randomUUID();

    const expires =
      new Date(
        Date.now() +
        30 * 24 * 60 * 60 * 1000
      ).toISOString();

    await env.DB
      .prepare(`
        INSERT INTO auth_sessions (
          token,
          user_id,
          created_at,
          expires_at
        )
        VALUES (?, ?, ?, ?)
      `)
      .bind(
        token,
        userId,
        timestamp,
        expires
      )
      .run();

    console.log(
      "AUTH_SESSION_CREATED",
      userId
    );

    return json(
      {
        success: true,
        user: {
          id: userId,
          email,
          artist_name: artistName
        }
      },
      201,
      {
        "Set-Cookie":
          sessionCookie(token)
      }
    );

  } catch (error) {
    console.error(
      "REGISTER_ERROR",
      error
    );

    return json(
      {
        error:
          "Account creation failed.",
        details:
          String(
            error?.message || error
          ),
        stack:
          String(
            error?.stack || ""
          )
      },
      500
    );
  }
}

/* =======================================================
   AUTH - LOGIN
======================================================= */

async function login(request, env) {
  let body;

  try {
    body = await request.json();
  } catch (error) {
    return json(
      {
        error: "Invalid JSON request.",
        details:
          String(
            error?.message || error
          )
      },
      400
    );
  }

  const email =
    cleanEmail(body.email);

  const password =
    String(body.password || "");

  if (!email || !password) {
    return json(
      {
        error:
          "Email and password are required."
      },
      400
    );
  }

  try {
    await ensureAuthTables(
      env.DB
    );

    const user =
      await env.DB
        .prepare(`
          SELECT
            id,
            email,
            raw_user_meta_data
          FROM auth_users
          WHERE lower(email) = ?
          LIMIT 1
        `)
        .bind(email)
        .first();

    if (!user) {
      return json(
        {
          error:
            "Invalid credentials."
        },
        401
      );
    }

    const credential =
      await env.DB
        .prepare(`
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
          error:
            "This account has not yet been migrated to Cloudflare login."
        },
        401
      );
    }

    const valid =
      await verifyPassword(
        password,
        credential.password_hash
      );

    if (!valid) {
      return json(
        {
          error:
            "Invalid credentials."
        },
        401
      );
    }

    const token =
      crypto.randomUUID();

    const created =
      nowIso();

    const expires =
      new Date(
        Date.now() +
        30 * 24 * 60 * 60 * 1000
      ).toISOString();

    await env.DB
      .prepare(`
        INSERT INTO auth_sessions (
          token,
          user_id,
          created_at,
          expires_at
        )
        VALUES (?, ?, ?, ?)
      `)
      .bind(
        token,
        user.id,
        created,
        expires
      )
      .run();

    return json(
      {
        success: true,
        user: {
          id: user.id,
          email: user.email
        }
      },
      200,
      {
        "Set-Cookie":
          sessionCookie(token)
      }
    );

  } catch (error) {
    console.error(
      "LOGIN_ERROR",
      error
    );

    return json(
      {
        error:
          "Login failed.",
        details:
          String(
            error?.message || error
          ),
        stack:
          String(
            error?.stack || ""
          )
      },
      500
    );
  }
}

/* =======================================================
   CURRENT USER
======================================================= */

async function currentUser(
  request,
  env
) {
  try {
    await ensureAuthTables(
      env.DB
    );

    const token =
      getCookie(
        request,
        "nile_session"
      );

    if (!token) {
      return json({
        user: null
      });
    }

    const row =
      await env.DB
        .prepare(`
          SELECT
            s.user_id,
            s.expires_at,
            u.id,
            u.email,
            u.raw_user_meta_data
          FROM auth_sessions s
          JOIN auth_users u
            ON u.id = s.user_id
          WHERE s.token = ?
          LIMIT 1
        `)
        .bind(token)
        .first();

    if (!row) {
      return json({
        user: null
      });
    }

    if (
      row.expires_at &&
      new Date(
        row.expires_at
      ).getTime() < Date.now()
    ) {
      await env.DB
        .prepare(`
          DELETE FROM auth_sessions
          WHERE token = ?
        `)
        .bind(token)
        .run();

      return json({
        user: null
      });
    }

    return json({
      user: {
        id: row.id,
        email: row.email,
        raw_user_meta_data:
          row.raw_user_meta_data ||
          null
      }
    });

  } catch (error) {
    console.error(
      "ME_ERROR",
      error
    );

    return json(
      {
        error:
          "Unable to load current user.",
        details:
          String(
            error?.message || error
          )
      },
      500
    );
  }
}

/* =======================================================
   LOGOUT
======================================================= */

async function logout(
  request,
  env
) {
  try {
    await ensureAuthTables(
      env.DB
    );

    const token =
      getCookie(
        request,
        "nile_session"
      );

    if (token) {
      await env.DB
        .prepare(`
          DELETE FROM auth_sessions
          WHERE token = ?
        `)
        .bind(token)
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

  } catch (error) {
    return json(
      {
        error:
          "Logout failed.",
        details:
          String(
            error?.message || error
          )
      },
      500
    );
  }
}

/* =======================================================
   DATABASE HELPERS
======================================================= */

function safeTable(value) {
  const table =
    String(value || "");

  if (!ALLOWED_TABLES.has(table)) {
    throw new Error(
      `Table not allowed: ${table}`
    );
  }

  return table;
}

function parseSelectColumns(value) {
  if (!value || value === "*") {
    return "*";
  }

  const columns =
    String(value)
      .split(",")
      .map(x => x.trim())
      .filter(Boolean);

  if (!columns.length) {
    return "*";
  }

  for (const column of columns) {
    if (
      !/^[A-Za-z_][A-Za-z0-9_]*$/.test(
        column
      )
    ) {
      throw new Error(
        "Invalid column name."
      );
    }
  }

  return columns.join(", ");
}

function buildFilters(url) {
  const clauses = [];
  const bindings = [];

  for (const [
    key,
    value
  ] of url.searchParams.entries()) {

    if (
      key === "select" ||
      key === "order" ||
      key === "limit" ||
      key === "offset"
    ) {
      continue;
    }

    if (
      !/^[A-Za-z_][A-Za-z0-9_]*$/.test(
        key
      )
    ) {
      continue;
    }

    if (value.startsWith("eq.")) {
      clauses.push(`${key} = ?`);
      bindings.push(
        value.slice(3)
      );
    } else if (
      value.startsWith("neq.")
    ) {
      clauses.push(`${key} != ?`);
      bindings.push(
        value.slice(4)
      );
    } else if (
      value.startsWith("gt.")
    ) {
      clauses.push(`${key} > ?`);
      bindings.push(
        value.slice(3)
      );
    } else if (
      value.startsWith("gte.")
    ) {
      clauses.push(`${key} >= ?`);
      bindings.push(
        value.slice(4)
      );
    } else if (
      value.startsWith("lt.")
    ) {
      clauses.push(`${key} < ?`);
      bindings.push(
        value.slice(3)
      );
    } else if (
      value.startsWith("lte.")
    ) {
      clauses.push(`${key} <= ?`);
      bindings.push(
        value.slice(4)
      );
    } else if (
      value === "is.null"
    ) {
      clauses.push(
        `${key} IS NULL`
      );
    } else if (
      value === "not.is.null"
    ) {
      clauses.push(
        `${key} IS NOT NULL`
      );
    } else if (
      value.startsWith("like.")
    ) {
      clauses.push(
        `${key} LIKE ?`
      );
      bindings.push(
        value.slice(5)
      );
    } else {
      clauses.push(`${key} = ?`);
      bindings.push(value);
    }
  }

  return {
    clauses,
    bindings
  };
}

/* =======================================================
   DATABASE GET
======================================================= */

async function dbGet(
  request,
  env,
  table
) {
  table = safeTable(table);

  const url =
    new URL(request.url);

  const columns =
    parseSelectColumns(
      url.searchParams.get(
        "select"
      )
    );

  const filters =
    buildFilters(url);

  let sql = `
    SELECT ${columns}
    FROM ${table}
  `;

  if (filters.clauses.length) {
    sql += `
      WHERE ${filters.clauses.join(
        " AND "
      )}
    `;
  }

  const order =
    url.searchParams.get(
      "order"
    );

  if (order) {
    const safeParts = [];

    for (
      const part of
      order.split(",")
    ) {
      const bits =
        part.trim().split(".");

      const column =
        bits[0];

      if (
        !/^[A-Za-z_][A-Za-z0-9_]*$/.test(
          column
        )
      ) {
        continue;
      }

      const direction =
        bits[1] === "desc"
          ? "DESC"
          : "ASC";

      safeParts.push(
        `${column} ${direction}`
      );
    }

    if (safeParts.length) {
      sql += `
        ORDER BY ${safeParts.join(
          ", "
        )}
      `;
    }
  }

  const limit =
    Number(
      url.searchParams.get(
        "limit"
      )
    );

  const offset =
    Number(
      url.searchParams.get(
        "offset"
      )
    );

  if (
    Number.isFinite(limit) &&
    limit > 0
  ) {
    sql += `
      LIMIT ${Math.min(
        limit,
        500
      )}
    `;

    if (
      Number.isFinite(offset) &&
      offset >= 0
    ) {
      sql += `
        OFFSET ${Math.min(
          offset,
          5000
        )}
      `;
    }
  } else {
    sql += ` LIMIT 500`;
  }

  const result =
    await env.DB
      .prepare(sql)
      .bind(...filters.bindings)
      .all();

  return json(
    result.results || []
  );
}

/* =======================================================
   DATABASE INSERT
======================================================= */

async function dbInsert(
  request,
  env,
  table
) {
  table = safeTable(table);

  const body =
    await request.json();

  const rows =
    Array.isArray(body)
      ? body
      : Array.isArray(body?.rows)
        ? body.rows
        : [body];

  if (!rows.length) {
    return json([]);
  }

  const statements = [];

  for (const row of rows) {
    const keys =
      Object.keys(row)
        .filter(key =>
          /^[A-Za-z_][A-Za-z0-9_]*$/.test(
            key
          )
        );

    if (!keys.length) {
      continue;
    }

    const placeholders =
      keys.map(() => "?")
        .join(", ");

    const values =
      keys.map(
        key => row[key]
      );

    statements.push(
      env.DB
        .prepare(`
          INSERT INTO ${table} (
            ${keys.join(", ")}
          )
          VALUES (${placeholders})
        `)
        .bind(...values)
    );
  }

  if (!statements.length) {
    return json([]);
  }

  const result =
    await env.DB.batch(
      statements
    );

  return json(
    {
      success: true,
      count: result.length
    },
    201
  );
}

/* =======================================================
   DATABASE PATCH
======================================================= */

async function dbPatch(
  request,
  env,
  table
) {
  table = safeTable(table);

  const body =
    await request.json();

  const values =
    body?.values || body;

  if (
    !values ||
    typeof values !== "object" ||
    Array.isArray(values)
  ) {
    return json(
      {
        error:
          "Invalid update body."
      },
      400
    );
  }

  const url =
    new URL(request.url);

  const filters =
    buildFilters(url);

  if (!filters.clauses.length) {
    return json(
      {
        error:
          "An update requires a filter."
      },
      400
    );
  }

  const keys =
    Object.keys(values)
      .filter(key =>
        /^[A-Za-z_][A-Za-z0-9_]*$/.test(
          key
        )
      );

  if (!keys.length) {
    return json(
      {
        error:
          "Nothing to update."
      },
      400
    );
  }

  const assignments =
    keys
      .map(
        key =>
          `${key} = ?`
      )
      .join(", ");

  const bindings = [
    ...keys.map(
      key => values[key]
    ),
    ...filters.bindings
  ];

  const result =
    await env.DB
      .prepare(`
        UPDATE ${table}
        SET ${assignments}
        WHERE ${filters.clauses.join(
          " AND "
        )}
      `)
      .bind(...bindings)
      .run();

  return json({
    success: true,
    changes:
      result.meta?.changes || 0
  });
}

/* =======================================================
   DATABASE DELETE
======================================================= */

async function dbDelete(
  request,
  env,
  table
) {
  table = safeTable(table);

  const url =
    new URL(request.url);

  const filters =
    buildFilters(url);

  if (!filters.clauses.length) {
    return json(
      {
        error:
          "A delete requires a filter."
      },
      400
    );
  }

  const result =
    await env.DB
      .prepare(`
        DELETE FROM ${table}
        WHERE ${filters.clauses.join(
          " AND "
        )}
      `)
      .bind(...filters.bindings)
      .run();

  return json({
    success: true,
    changes:
      result.meta?.changes || 0
  });
}

/* =======================================================
   RPC - RECORD PLAY
======================================================= */

async function rpcRecordSongPlay(
  request,
  env
) {
  const body =
    await request.json();

  const songId =
    body.song_id ||
    body.songId;

  if (!songId) {
    return json(
      {
        error:
          "song_id is required."
      },
      400
    );
  }

  let userId = null;

  const token =
    getCookie(
      request,
      "nile_session"
    );

  if (token) {
    try {
      await ensureAuthTables(
        env.DB
      );

      const session =
        await env.DB
          .prepare(`
            SELECT user_id
            FROM auth_sessions
            WHERE token = ?
            LIMIT 1
          `)
          .bind(token)
          .first();

      userId =
        session?.user_id ||
        null;
    } catch (error) {
      console.error(
        "SESSION_LOOKUP_ERROR",
        error
      );
    }
  }

  try {
    await env.DB
      .prepare(`
        INSERT INTO song_play_log (
          id,
          song_id,
          user_id,
          played_at
        )
        VALUES (?, ?, ?, ?)
      `)
      .bind(
        makeId(),
        songId,
        userId,
        nowIso()
      )
      .run();
  } catch (error) {
    console.error(
      "SONG_PLAY_LOG_ERROR",
      error
    );

    try {
      await env.DB
        .prepare(`
          INSERT INTO song_play_log (
            id,
            song_id,
            user_id
          )
          VALUES (?, ?, ?)
        `)
        .bind(
          makeId(),
          songId,
          userId
        )
        .run();
    } catch (secondError) {
      console.error(
        "SONG_PLAY_LOG_SECOND_ERROR",
        secondError
      );
    }
  }

  try {
    const columns =
      await env.DB
        .prepare(
          `PRAGMA table_info(songs)`
        )
        .all();

    const names =
      new Set(
        (columns.results || [])
          .map(row => row.name)
      );

    if (names.has("play_count")) {
      await env.DB
        .prepare(`
          UPDATE songs
          SET play_count =
            COALESCE(play_count, 0) + 1
          WHERE id = ?
        `)
        .bind(songId)
        .run();
    } else if (
      names.has("plays")
    ) {
      await env.DB
        .prepare(`
          UPDATE songs
          SET plays =
            COALESCE(plays, 0) + 1
          WHERE id = ?
        `)
        .bind(songId)
        .run();
    }
  } catch (error) {
    console.error(
      "SONG_COUNT_ERROR",
      error
    );
  }

  return json({
    success: true
  });
}

/* =======================================================
   RPC - PLATFORM TOTAL
======================================================= */

async function rpcPlatformCompletedTotal(
  env
) {
  try {
    const result =
      await env.DB
        .prepare(`
          SELECT
            COALESCE(
              SUM(amount),
              0
            ) AS total
          FROM platform_payouts
        `)
        .first();

    return json({
      total:
        Number(
          result?.total || 0
        )
    });
  } catch (error) {
    console.error(
      "PLATFORM_TOTAL_ERROR",
      error
    );

    return json({
      total: 0
    });
  }
}

/* =======================================================
   R2 UPLOAD
======================================================= */

async function storageUpload(
  request,
  env
) {
  if (!env.MEDIA_BUCKET) {
    return json(
      {
        error:
          "R2 bucket is not configured."
      },
      500
    );
  }

  const url =
    new URL(request.url);

  let key =
    url.searchParams.get(
      "key"
    ) ||
    request.headers.get(
      "X-File-Key"
    );

  if (!key) {
    return json(
      {
        error:
          "File key is required."
      },
      400
    );
  }

  key =
    key.replace(
      /^\/+/,
      ""
    );

  if (
    !key.startsWith("audio/") &&
    !key.startsWith("covers/")
  ) {
    return json(
      {
        error:
          "Files must be stored under audio/ or covers/."
      },
      400
    );
  }

  const contentType =
    request.headers.get(
      "Content-Type"
    ) ||
    "application/octet-stream";

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
    key
  });
}

/* =======================================================
   R2 PUBLIC
======================================================= */

async function storagePublic(
  request,
  env,
  key
) {
  if (!env.MEDIA_BUCKET) {
    return new Response(
      "R2 bucket is not configured.",
      {
        status: 500
      }
    );
  }

  key =
    decodeURIComponent(key)
      .replace(/^\/+/, "");

  const object =
    await env.MEDIA_BUCKET.get(
      key
    );

  if (!object) {
    return new Response(
      "Not found",
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
    "Cache-Control",
    "public, max-age=31536000, immutable"
  );

  headers.set(
    "ETag",
    object.httpEtag
  );

  return new Response(
    object.body,
    {
      headers
    }
  );
}

/* =======================================================
   API ROUTER
======================================================= */

async function api(
  request,
  env
) {
  const url =
    new URL(request.url);

  const path =
    url.pathname;

  if (
    path ===
    "/api/health"
  ) {
    return json({
      ok: true,
      service: "nile-soniq",
      database:
        Boolean(env.DB),
      storage:
        Boolean(
          env.MEDIA_BUCKET
        ),
      time: nowIso()
    });
  }

  if (
    path ===
    "/api/auth/register"
  ) {
    if (
      request.method !==
      "POST"
    ) {
      return json(
        {
          error:
            "Method not allowed."
        },
        405
      );
    }

    return register(
      request,
      env
    );
  }

  if (
    path ===
    "/api/auth/login"
  ) {
    if (
      request.method !==
      "POST"
    ) {
      return json(
        {
          error:
            "Method not allowed."
        },
        405
      );
    }

    return login(
      request,
      env
    );
  }

  if (
    path ===
    "/api/auth/logout"
  ) {
    return logout(
      request,
      env
    );
  }

  if (
    path ===
    "/api/auth/me"
  ) {
    return currentUser(
      request,
      env
    );
  }

  if (
    path ===
    "/api/storage/upload"
  ) {
    if (
      request.method !==
      "POST"
    ) {
      return json(
        {
          error:
            "Method not allowed."
        },
        405
      );
    }

    return storageUpload(
      request,
      env
    );
  }

  if (
    path.startsWith(
      "/api/storage/public/"
    )
  ) {
    const key =
      path.replace(
        "/api/storage/public/",
        ""
      );

    return storagePublic(
      request,
      env,
      key
    );
  }

  if (
    path.startsWith(
      "/api/rpc/"
    )
  ) {
    const rpcName =
      path.replace(
        "/api/rpc/",
        ""
      );

    if (
      rpcName ===
      "record_song_play"
    ) {
      return rpcRecordSongPlay(
        request,
        env
      );
    }

    if (
      rpcName ===
      "get_platform_completed_total"
    ) {
      return rpcPlatformCompletedTotal(
        env
      );
    }

    return json(
      {
        error:
          `Unknown RPC: ${rpcName}`
      },
      404
    );
  }

  if (
    path.startsWith(
      "/api/db/"
    )
  ) {
    const table =
      decodeURIComponent(
        path.replace(
          "/api/db/",
          ""
        )
      );

    try {
      if (
        request.method ===
        "GET"
      ) {
        return dbGet(
          request,
          env,
          table
        );
      }

      if (
        request.method ===
        "POST"
      ) {
        return dbInsert(
          request,
          env,
          table
        );
      }

      if (
        request.method ===
          "PATCH" ||
        request.method ===
          "PUT"
      ) {
        return dbPatch(
          request,
          env,
          table
        );
      }

      if (
        request.method ===
        "DELETE"
      ) {
        return dbDelete(
          request,
          env,
          table
        );
      }

      return json(
        {
          error:
            "Method not allowed."
        },
        405
      );

    } catch (error) {
      console.error(
        "DATABASE_ERROR",
        error
      );

      return json(
        {
          error:
            "Database request failed.",
          details:
            String(
              error?.message ||
              error
            ),
          stack:
            String(
              error?.stack ||
              ""
            )
        },
        500
      );
    }
  }

  return null;
}

/* =======================================================
   MAIN WORKER
======================================================= */

export default {
  async fetch(
    request,
    env
  ) {
    try {
      if (
        request.method ===
        "OPTIONS"
      ) {
        return withCors(
          new Response(
            null,
            {
              status: 204,
              headers:
                corsHeaders(
                  request
                )
            }
          ),
          request
        );
      }

      const url =
        new URL(
          request.url
        );

      if (
        url.pathname.startsWith(
          "/api/"
        )
      ) {
        const response =
          await api(
            request,
            env
          );

        if (response) {
          return withCors(
            response,
            request
          );
        }
      }

      if (env.ASSETS) {
        return env.ASSETS.fetch(
          request
        );
      }

      return new Response(
        "NILE SONIQ Worker is running.",
        {
          status: 200,
          headers: {
            "Content-Type":
              "text/plain; charset=utf-8"
          }
        }
      );

    } catch (error) {
      console.error(
        "WORKER_FATAL_ERROR",
        error
      );

      return withCors(
        json(
          {
            error:
              "Internal server error.",
            details:
              String(
                error?.message ||
                error
              ),
            stack:
              String(
                error?.stack ||
                ""
              )
          },
          500
        ),
        request
      );
    }
  }
};
