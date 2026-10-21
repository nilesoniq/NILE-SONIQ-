import bcrypt from "bcryptjs";

const COOKIE_NAME = "nile_session";
const SESSION_SECONDS = 30 * 24 * 60 * 60;

const PUBLIC_READ_TABLES = new Set([
  "songs", "artists", "comments", "likes",
  "news", "news_comments", "news_reactions"
]);

const APP_TABLES = new Set([
  "songs", "artists", "comments", "likes",
  "news", "news_comments", "news_reactions",
  "copyright_removals", "song_play_log",
  "artist_payouts", "artist_wallets", "platform_deposits",
  "platform_payouts", "platform_wallet",
  "withdrawal_requests", "withdrawals"
]);

const ADMIN_TABLES = new Set([
  "admins", "copyright_removals", "artist_payouts",
  "artist_wallets", "platform_deposits",
  "platform_payouts", "platform_wallet",
  "withdrawal_requests", "withdrawals"
]);

const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store"
};

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...headers }
  });
}

function error(message, status = 400) {
  return json({ error: message }, status);
}

function makeCookie(token, maxAge) {
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function readCookie(request) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(/(?:^|;\s*)nile_session=([^;]*)/);

  if (!match) return null;

  try {
    return decodeURIComponent(match[1]);
  } catch {
    return null;
  }
}

function allowedOrigin(origin) {
  return origin === "https://nilesoniq.com" ||
    origin === "https://www.nilesoniq.com" ||
    /^https:\/\/[a-z0-9-]+\.nile-soniq-[a-z0-9-]+\.pages\.dev$/i.test(origin);
}

function withCors(request, response) {
  const headers = new Headers(response.headers);
  const origin = request.headers.get("Origin");

  if (origin && allowedOrigin(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }

  headers.set(
    "Access-Control-Allow-Methods",
    "GET, POST, PATCH, PUT, DELETE, OPTIONS"
  );

  headers.set(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );

  return new Response(response.body, {
    status: response.status,
    headers
  });
}

async function readBody(request) {
  try {
    const body = await request.json();
    return body && typeof body === "object" ? body : {};
  } catch {
    return {};
  }
}

function safeIdentifier(value) {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(value || "");
}

async function currentUser(request, env) {
  const token = readCookie(request);

  if (!token) return null;

  return env.DB.prepare(`
    SELECT u.id, u.email, u.phone, u.raw_user_meta_data
    FROM auth_sessions s
    JOIN auth_users u ON u.id = s.user_id
    WHERE s.token = ?
      AND datetime(s.expires_at) > datetime('now')
      AND u.deleted_at IS NULL
      AND (
        u.banned_until IS NULL
        OR datetime(u.banned_until) <= datetime('now')
      )
    LIMIT 1
  `).bind(token).first();
}

/*
 * Check the administrator record directly in D1.
 * Accept integer 1 and text "true" for the active field.
 * This does not grant administrator access based on email alone.
 */
async function isAdmin(env, user) {
  if (!user || !user.id) return false;

  const row = await env.DB.prepare(`
    SELECT id, user_id, email, role, active
    FROM admins
    WHERE user_id = ?
      AND (
        active = 1
        OR LOWER(CAST(active AS TEXT)) = 'true'
      )
    LIMIT 1
  `).bind(user.id).first();

  return Boolean(row);
}

async function createSession(env, userId) {
  const token = crypto.randomUUID();

  await env.DB.prepare(`
    INSERT INTO auth_sessions (
      token, user_id, created_at, expires_at
    )
    VALUES (?, ?, datetime('now'), datetime('now', '+30 days'))
  `).bind(token, userId).run();

  return token;
}

async function authRoute(request, env, path) {
  if (request.method === "GET" && path === "/api/auth/me") {
    const user = await currentUser(request, env);

    if (!user) {
      return json({ authenticated: false });
    }

    let artist = null;
    let admin = null;
    let metadata = {};

    try {
      artist = await env.DB.prepare(
        "SELECT * FROM artists WHERE user_id = ? LIMIT 1"
      ).bind(user.id).first();
    } catch (e) {
      console.error("Artist lookup failed:", e.message);
    }

    try {
      admin = await env.DB.prepare(`
        SELECT id, user_id, email, role, active
        FROM admins
        WHERE user_id = ?
          AND (
            active = 1
            OR LOWER(CAST(active AS TEXT)) = 'true'
          )
        LIMIT 1
      `).bind(user.id).first();
    } catch (e) {
      console.error("Admin lookup failed:", e.message);
    }

    try {
      metadata = JSON.parse(user.raw_user_meta_data || "{}");
    } catch {}

    return json({
      authenticated: true,
      user: {
        id: user.id,
        email: user.email,
        phone: user.phone,
        artist_name: metadata.artist_name || artist?.name || null
      },
      artist,
      admin
    });
  }

  if (request.method === "POST" && path === "/api/auth/logout") {
    const token = readCookie(request);

    if (token) {
      await env.DB.prepare(
        "DELETE FROM auth_sessions WHERE token = ?"
      ).bind(token).run();
    }

    return json(
      { success: true },
      200,
      { "Set-Cookie": makeCookie("", 0) }
    );
  }

  if (request.method !== "POST") {
    return error("Method not allowed", 405);
  }

  const body = await readBody(request);
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (path === "/api/auth/register") {
    const phone = String(body.phone || "").trim();
    const artistName = String(
      body.artist_name || body.name || ""
    ).trim();

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return error("Please enter a valid email address.", 422);
    }

    if (password.length < 6 || password.length > 128) {
      return error(
        "Password must be between 6 and 128 characters.",
        422
      );
    }

    try {
      const existing = await env.DB.prepare(
        "SELECT id FROM auth_users WHERE LOWER(email) = ? LIMIT 1"
      ).bind(email).first();

      if (existing) {
        return error(
          "An account with that email already exists.",
          409
        );
      }

      const id = crypto.randomUUID();
      const passwordHash = await bcrypt.hash(password, 10);

      const metadata = JSON.stringify({
        artist_name: artistName || email.split("@")[0]
      });

      await env.DB.prepare(`
        INSERT INTO auth_users (
          id, email, encrypted_password, phone, raw_user_meta_data,
          created_at, updated_at, is_anonymous, is_sso_user
        )
        VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'), 0, 0)
      `).bind(
        id,
        email,
        passwordHash,
        phone || null,
        metadata
      ).run();

      try {
        await env.DB.prepare(
          "INSERT INTO artists (id, user_id, name) VALUES (?, ?, ?)"
        ).bind(
          crypto.randomUUID(),
          id,
          artistName || email.split("@")[0]
        ).run();
      } catch (e) {
        console.error("Artist profile creation failed:", e.message);
      }

      const token = await createSession(env, id);

      return json({
        success: true,
        user: {
          id,
          email,
          artist_name: artistName || email.split("@")[0]
        }
      }, 201, {
        "Set-Cookie": makeCookie(token, SESSION_SECONDS)
      });
    } catch (e) {
      console.error("Registration failed:", e.message);
      return error("Account creation failed. Please try again.", 500);
    }
  }

  if (path === "/api/auth/login") {
    if (!email || !password) {
      return error("Email and password are required.", 422);
    }

    try {
      const user = await env.DB.prepare(`
        SELECT id, email, encrypted_password, phone,
               raw_user_meta_data, deleted_at, banned_until
        FROM auth_users
        WHERE LOWER(email) = ?
        LIMIT 1
      `).bind(email).first();

      if (
        !user ||
        !user.encrypted_password ||
        user.deleted_at ||
        (
          user.banned_until &&
          new Date(user.banned_until).getTime() > Date.now()
        )
      ) {
        return error("Invalid email or password.", 401);
      }

      if (!/^\$2[aby]\$\d\d\$/.test(user.encrypted_password)) {
        return error(
          "This account's password format is not supported.",
          401
        );
      }

      const valid = await bcrypt.compare(
        password,
        user.encrypted_password
      );

      if (!valid) {
        return error("Invalid email or password.", 401);
      }

      await env.DB.prepare(
        "UPDATE auth_users SET last_sign_in_at = datetime('now') WHERE id = ?"
      ).bind(user.id).run();

      const token = await createSession(env, user.id);
      let metadata = {};

      try {
        metadata = JSON.parse(user.raw_user_meta_data || "{}");
      } catch {}

      return json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          phone: user.phone,
          artist_name: metadata.artist_name || null
        }
      }, 200, {
        "Set-Cookie": makeCookie(token, SESSION_SECONDS)
      });
    } catch (e) {
      console.error("Login failed:", e.message);
      return error("Login failed. Please try again.", 500);
    }
  }

  return error("Not found", 404);
}

/*
 * Supports both query formats:
 *   user_id=eq.UUID
 *   eq.user_id=UUID
 *
 * Also converts active=true/false to SQLite integer values.
 */
function parseFilters(url) {
  const filters = [];
  const values = [];

  const operators = {
    eq: "=",
    neq: "!=",
    gt: ">",
    gte: ">=",
    lt: "<",
    lte: "<="
  };

  for (const [key, rawValue] of url.searchParams.entries()) {
    if ([
      "select", "order", "limit", "offset",
      "on_conflict", "upsert"
    ].includes(key)) {
      continue;
    }

    // Standard Supabase query style: column=eq.value
    const match = String(rawValue).match(
      /^(eq|neq|gt|gte|lt|lte)\.(.*)$/s
    );

    if (match && safeIdentifier(key)) {
      const op = match[1];
      let value = match[2];

      if (!operators[op]) continue;

      if (key === "active") {
        if (value === "true") value = 1;
        if (value === "false") value = 0;
      }

      filters.push(`${key} ${operators[op]} ?`);
      values.push(value);
      continue;
    }

    // Legacy query style: eq.column=value
    const dot = key.indexOf(".");

    if (dot > 0) {
      const op = key.slice(0, dot);
      const column = key.slice(dot + 1);

      if (!operators[op] || !safeIdentifier(column)) {
        continue;
      }

      let value = rawValue;

      if (column === "active") {
        if (value === "true") value = 1;
        if (value === "false") value = 0;
      }

      filters.push(`${column} ${operators[op]} ?`);
      values.push(value);
    }
  }

  return {
    sql: filters.length
      ? ` WHERE ${filters.join(" AND ")}`
      : "",
    values,
    count: filters.length
  };
}

async function dbRoute(request, env, path) {
  const table = path.split("/")[3];

  if (!safeIdentifier(table) || !APP_TABLES.has(table)) {
    return error("Table not available", 404);
  }

  const method = request.method;
  const url = new URL(request.url);
  const user = await currentUser(request, env);
  const admin = user ? await isAdmin(env, user) : false;

  /*
   * An authenticated user may look up only their own admin record.
   * The query must explicitly filter by that user's own ID.
   * Ordinary users cannot read the full admins table.
   */
  const ownAdminLookup =
    method === "GET" &&
    table === "admins" &&
    Boolean(user) &&
    (
      url.searchParams.get("user_id") === `eq.${user.id}` ||
      url.searchParams.get("eq.user_id") === user.id
    );

  if (ADMIN_TABLES.has(table) && !admin && !ownAdminLookup) {
    return error("Admin access required", user ? 403 : 401);
  }

  if (method === "GET") {
    if (!PUBLIC_READ_TABLES.has(table) && !user) {
      return error("Authentication required", 401);
    }

    const selectInput = url.searchParams.get("select") || "*";
    const columns = selectInput.split(",").map(x => x.trim());

    if (!columns.length || columns.some(
      c => c !== "*" && !safeIdentifier(c)
    )) {
      return error("Invalid select columns", 400);
    }

    const { sql: where, values } = parseFilters(url);

    let query = `SELECT ${columns.join(",")} FROM ${table}${where}`;
    const order = url.searchParams.get("order");

    if (order) {
      const [column, direction] = order.split(".");

      if (safeIdentifier(column)) {
        query += ` ORDER BY ${column} ${
          direction === "desc" ? "DESC" : "ASC"
        }`;
      }
    }

    const limit = Number(url.searchParams.get("limit") || 100);
    query += ` LIMIT ${Math.min(Math.max(limit || 100, 1), 500)}`;

    try {
      const result = await env.DB.prepare(query).bind(...values).all();

      return json({
        data: result.results || [],
        error: null
      });
    } catch (e) {
      console.error("Database read failed:", e.message);
      return error("Database request failed", 500);
    }
  }

  if (!user) {
    return error("Authentication required", 401);
  }

  const interactionTables = new Set([
    "likes", "comments", "news_comments", "news_reactions"
  ]);

  if (
    !interactionTables.has(table) &&
    table !== "artists" &&
    table !== "songs" &&
    !admin
  ) {
    return error("Admin access required for this operation", 403);
  }

  const { sql: where, values, count } = parseFilters(url);

  if (
    ["PATCH", "PUT", "DELETE"].includes(method) &&
    count === 0
  ) {
    return error("A filter is required for this operation", 422);
  }

  try {
    if (method === "POST") {
      const body = await readBody(request);
      const rows = Array.isArray(body) ? body : [body];

      if (!rows.length || rows.length > 50) {
        return error("Invalid number of rows", 422);
      }

      const output = [];
      const wantsUpsert = url.searchParams.get("upsert") === "true";

      for (const input of rows) {
        const row = input &&
          typeof input === "object" &&
          !Array.isArray(input)
          ? input
          : null;

        if (!row) {
          return error("Invalid row supplied", 422);
        }

        const keys = Object.keys(row);

        if (!keys.length || keys.some(k => !safeIdentifier(k))) {
          return error("Invalid fields supplied", 422);
        }

        if (table === "artists") {
          if (row.user_id !== user.id) {
            return error(
              "You may only edit your own artist profile",
              403
            );
          }

          const allowed = new Set([
            "user_id", "name", "bio", "location", "avatar_url"
          ]);

          if (keys.some(k => !allowed.has(k))) {
            return error("Invalid artist profile fields", 422);
          }

          const existing = await env.DB.prepare(
            "SELECT id FROM artists WHERE user_id = ? LIMIT 1"
          ).bind(user.id).first();

          if (existing) {
            const updateKeys = keys.filter(k => k !== "user_id");

            if (updateKeys.length) {
              await env.DB.prepare(
                `UPDATE artists SET ${
                  updateKeys.map(k => `${k} = ?`).join(", ")
                } WHERE user_id = ?`
              ).bind(
                ...updateKeys.map(k => row[k] ?? null),
                user.id
              ).run();
            }
          } else {
            const insertRow = {
              id: crypto.randomUUID(),
              ...row,
              user_id: user.id
            };

            const insertKeys = Object.keys(insertRow);

            await env.DB.prepare(
              `INSERT INTO artists (${insertKeys.join(",")}) VALUES (${
                insertKeys.map(() => "?").join(",")
              })`
            ).bind(
              ...insertKeys.map(k => insertRow[k] ?? null)
            ).run();
          }

          output.push(await env.DB.prepare(
            "SELECT * FROM artists WHERE user_id = ? LIMIT 1"
          ).bind(user.id).first());

          continue;
        }

        if (!admin && table === "songs") {
          if (row.artist_id !== user.id) {
            return error(
              "You may only submit songs for your own account",
              403
            );
          }

          const allowed = new Set([
            "title", "artist", "artist_id", "file_url", "audio_url",
            "cover_url", "description", "genre", "release_date",
            "producer", "featured_artists", "label", "location",
            "terms_accepted", "terms_accepted_at", "plays", "likes",
            "approved"
          ]);

          if (keys.some(k => !allowed.has(k))) {
            return error("Invalid song fields", 422);
          }

          const accepted =
            row.terms_accepted === true ||
            row.terms_accepted === 1 ||
            row.terms_accepted === "true";

          const safeRow = {
            ...row,
            id: crypto.randomUUID(),
            artist_id: user.id,
            terms_accepted: accepted ? 1 : 0,
            terms_accepted_at: accepted
              ? (row.terms_accepted_at || new Date().toISOString())
              : null,
            plays: 0,
            likes: 0,
            approved: 0,
            review_status: "pending"
          };

          const insertKeys = Object.keys(safeRow);

          await env.DB.prepare(
            `INSERT INTO songs (${insertKeys.join(",")}) VALUES (${
              insertKeys.map(() => "?").join(",")
            })`
          ).bind(
            ...insertKeys.map(k => safeRow[k] ?? null)
          ).run();

          output.push(await env.DB.prepare(
            "SELECT * FROM songs WHERE id = ? LIMIT 1"
          ).bind(safeRow.id).first());

          continue;
        }

        if (!admin && !interactionTables.has(table)) {
          return error("Admin access required for this operation", 403);
        }

        if (wantsUpsert && table !== "artists") {
          return error("Upsert is not supported for this table", 422);
        }

        const sql = `INSERT INTO ${table} (${keys.join(",")}) VALUES (${
          keys.map(() => "?").join(",")
        })`;

        await env.DB.prepare(sql).bind(
          ...keys.map(k => row[k] ?? null)
        ).run();

        output.push(row);
      }

      return json({
        data: Array.isArray(body) ? output : output[0],
        error: null
      }, 201);
    }

    if (method === "PATCH" || method === "PUT") {
      if (
        !admin &&
        !["likes", "comments", "news_comments", "news_reactions"].includes(table)
      ) {
        return error("Admin access required for this operation", 403);
      }

      const body = await readBody(request);
      const keys = Object.keys(body || {});

      if (!keys.length || keys.some(k => !safeIdentifier(k))) {
        return error("Invalid fields supplied", 422);
      }

      const sql = `UPDATE ${table} SET ${
        keys.map(k => `${k} = ?`).join(", ")
      }${where}`;

      await env.DB.prepare(sql).bind(
        ...keys.map(k => body[k] ?? null),
        ...values
      ).run();

      return json({ data: body, error: null });
    }

    if (method === "DELETE") {
      if (
        !admin &&
        !["likes", "comments", "news_comments", "news_reactions"].includes(table)
      ) {
        return error("Admin access required for this operation", 403);
      }

      await env.DB.prepare(
        `DELETE FROM ${table}${where}`
      ).bind(...values).run();

      return json({ data: null, error: null });
    }

    return error("Method not allowed", 405);
  } catch (e) {
    console.error("Database write failed:", e.message);
    return error("Database request failed", 500);
  }
}

async function rpcRoute(request, env, name) {
  const body = await readBody(request);
  const user = await currentUser(request, env);
  const admin = user ? await isAdmin(env, user) : false;

  try {
    if (name === "get_platform_completed_total") {
      if (!admin) {
        return error("Admin access required", user ? 403 : 401);
      }

      const result = await env.DB.prepare(
        "SELECT COALESCE(SUM(amount), 0) AS total FROM withdrawal_requests WHERE status = 'completed'"
      ).first();

      return json({
        data: result?.total || 0,
        error: null
      });
    }

    if (name === "record_song_play") {
      const id = body.song_id;

      if (!id) {
        return error("song_id is required", 422);
      }

      await env.DB.prepare(
        "UPDATE songs SET plays = COALESCE(plays, 0) + 1 WHERE id = ?"
      ).bind(id).run();

      return json({ data: true, error: null });
    }

    if (name === "add_admin_by_email") {
      if (!admin) {
        return error("Admin access required", user ? 403 : 401);
      }

      const target = String(
        body.target_email || ""
      ).trim().toLowerCase();

      const role = String(body.target_role || "admin");

      if (!target || !["admin", "super_admin"].includes(role)) {
        return error("Invalid admin details", 422);
      }

      const targetUser = await env.DB.prepare(
        "SELECT id, email FROM auth_users WHERE LOWER(email) = ? LIMIT 1"
      ).bind(target).first();

      if (!targetUser) {
        return error("User not found", 404);
      }

      await env.DB.prepare(`
        INSERT INTO admins (
          id, user_id, email, role, active, created_at
        )
        VALUES (?, ?, ?, ?, 1, datetime('now'))
      `).bind(
        crypto.randomUUID(),
        targetUser.id,
        targetUser.email,
        role
      ).run();

      return json({ data: true, error: null });
    }

    if (
      name === "remove_copyright_song" ||
      name === "remove_copyright_artist"
    ) {
      if (!admin) {
        return error("Admin access required", user ? 403 : 401);
      }

      return error(
        "This RPC needs its original implementation restored before use.",
        501
      );
    }

    return error("RPC not implemented", 404);
  } catch (e) {
    console.error("RPC failed:", e.message);
    return error("RPC request failed", 500);
  }
}

async function storageRoute(request, env, path) {
  const parts = path.split("/");
  const bucket = parts[3];
  let objectPath = parts.slice(4).join("/");

  try {
    objectPath = objectPath.split("/").map(
      part => decodeURIComponent(part)
    ).join("/");
  } catch {
    return error("Invalid storage path", 400);
  }

  if (
    !bucket ||
    !objectPath ||
    objectPath.split("/").some(
      part => part === ".." || part === "."
    )
  ) {
    return error("Storage path missing or invalid", 400);
  }

  if (!["audio", "covers", "avatars", "news"].includes(bucket)) {
    return error("Bucket not allowed", 403);
  }

  if (request.method === "GET") {
    const object = await env.MEDIA_BUCKET.get(
      `${bucket}/${objectPath}`
    );

    if (!object) {
      return error("File not found", 404);
    }

    return new Response(object.body, {
      headers: {
        "Content-Type": object.httpMetadata?.contentType ||
          "application/octet-stream",
        "Cache-Control": "public, max-age=31536000"
      }
    });
  }

  if (request.method === "POST" || request.method === "PUT") {
    const user = await currentUser(request, env);

    if (!user) {
      return error("Authentication required", 401);
    }

    const admin = await isAdmin(env, user);

    if (bucket === "news" && !admin) {
      return error("Admin access required", 403);
    }

    if (!admin && !["audio", "covers", "avatars"].includes(bucket)) {
      return error("Upload not allowed", 403);
    }

    if (!admin && !objectPath.startsWith(`${user.id}/`)) {
      return error(
        "You may only upload files to your own folder",
        403
      );
    }

    const bytes = await request.arrayBuffer();

    await env.MEDIA_BUCKET.put(
      `${bucket}/${objectPath}`,
      bytes,
      {
        httpMetadata: {
          contentType: request.headers.get("Content-Type") ||
            "application/octet-stream"
        }
      }
    );

    return json({
      data: { path: objectPath },
      error: null
    });
  }

  return error("Method not allowed", 405);
}

async function paymentRoute(request, env, type) {
  const user = await currentUser(request, env);

  if (!user) {
    return error("Authentication required", 401);
  }

  if (type === "disbursement" && !(await isAdmin(env, user))) {
    return error("Admin access required", 403);
  }

  const body = await readBody(request);

  const endpoint = type === "collection"
    ? env.PESAJET_COLLECTION_URL
    : env.PESAJET_DISBURSEMENT_URL;

  const token = env.PESAJET_TOKEN;

  if (!endpoint || !token) {
    return error("Payment service is not configured.", 503);
  }

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
      },
      body: JSON.stringify(body)
    });

    const result = await response.json().catch(() => ({}));

    return json(result, response.status);
  } catch (e) {
    console.error("Payment request failed:", e.message);
    return error("Payment service request failed", 502);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (request.method === "OPTIONS") {
        return withCors(
          request,
          new Response(null, { status: 204 })
        );
      }

      let response;

      if (url.pathname.startsWith("/api/auth/")) {
        response = await authRoute(
          request,
          env,
          url.pathname
        );
      } else if (url.pathname.startsWith("/api/db/")) {
        response = await dbRoute(
          request,
          env,
          url.pathname
        );
      } else if (url.pathname.startsWith("/api/rpc/")) {
        response = await rpcRoute(
          request,
          env,
          url.pathname.split("/")[3]
        );
      } else if (
        url.pathname === "/api/payments/pesajet-collection"
      ) {
        response = await paymentRoute(
          request,
          env,
          "collection"
        );
      } else if (
        url.pathname === "/api/payments/pesajet-disbursement"
      ) {
        response = await paymentRoute(
          request,
          env,
          "disbursement"
        );
      } else if (
        url.pathname.startsWith("/api/storage/public/")
      ) {
        response = await storageRoute(
          request,
          env,
          url.pathname.replace(
            "/api/storage/public",
            "/api/storage"
          )
        );
      } else if (url.pathname === "/api/storage/upload") {
        const bucket = url.searchParams.get("bucket") || "audio";
        const objectPath = url.searchParams.get("path") || "file";

        response = await storageRoute(
          request,
          env,
          `/api/storage/${bucket}/${objectPath}`
        );
      } else if (url.pathname === "/api/health") {
        response = json({
          ok: true,
          service: "nilesoniq"
        });
      } else if (env.ASSETS) {
        response = await env.ASSETS.fetch(request);
      } else {
        response = error("Not found", 404);
      }

      return withCors(request, response);
    } catch (e) {
      console.error("Worker error:", e.message);

      return withCors(
        request,
        error("Internal server error", 500)
      );
    }
  }
};
