
import bcrypt from "bcryptjs";

const COOKIE_NAME = "nile_session";
const SESSION_SECONDS = 30 * 24 * 60 * 60;
const EARNINGS_PER_PLAY = 0.5;
const WITHDRAWAL_MINIMUM = 10000;

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

const ARTIST_OWNED_FINANCIAL_TABLES = new Set([
  "artist_wallets", "artist_payouts",
  "withdrawal_requests", "withdrawals"
]);

const INTERACTION_TABLES = new Set([
  "likes", "comments", "news_comments", "news_reactions"
]);

// Never expose these fields through ordinary, non-admin database reads.
const SENSITIVE_COLUMNS = new Set([
  "encrypted_password",
  "password",
  "password_hash",
  "token",
  "access_token",
  "refresh_token",
  "raw_user_meta_data",
  "secret",
  "api_key",
  "private_key"
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
    "GET, HEAD, POST, PATCH, PUT, DELETE, OPTIONS"
  );

  headers.set(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, Range, If-Range"
  );

  headers.set(
    "Access-Control-Expose-Headers",
    "Accept-Ranges, Content-Range, Content-Length, Content-Type"
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

function isTruthyDb(value) {
  return value === true ||
    value === 1 ||
    value === "1" ||
    (
      typeof value === "string" &&
      value.toLowerCase() === "true"
    );
}

function redactSensitiveColumns(rows) {
  return rows.map(row => {
    const copy = { ...row };

    for (const key of Object.keys(copy)) {
      if (SENSITIVE_COLUMNS.has(key.toLowerCase())) {
        delete copy[key];
      }
    }

    return copy;
  });
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

async function getAdmin(env, user) {
  if (!user) return null;

  return env.DB.prepare(`
    SELECT id, user_id, email, role, active
    FROM admins
    WHERE user_id = ? AND active = 1
    LIMIT 1
  `).bind(user.id).first();
}

async function isAdmin(env, user) {
  return Boolean(await getAdmin(env, user));
}

async function isSuperAdmin(env, user) {
  const admin = await getAdmin(env, user);
  return Boolean(admin && admin.role === "super_admin");
}

async function createSession(env, userId) {
  const token = crypto.randomUUID();

  await env.DB.prepare(`
    INSERT INTO auth_sessions (
      token, user_id, created_at, expires_at
    )
    VALUES (
      ?, ?, datetime('now'), datetime('now', '+30 days')
    )
  `).bind(token, userId).run();

  return token;
}

async function authRoute(request, env, path) {
  if (request.method === "GET" && path === "/api/auth/me") {
    const user = await currentUser(request, env);

    if (!user) return json({ authenticated: false });

    let artist = null;
    let admin = null;
    let metadata = {};

    try {
      artist = await env.DB.prepare(
        "SELECT * FROM artists WHERE user_id = ? LIMIT 1"
      ).bind(user.id).first();

      if (artist) {
        artist = redactSensitiveColumns([artist])[0];
      }
    } catch {}

    try {
      admin = await getAdmin(env, user);
    } catch {}

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
        "SELECT id FROM auth_users WHERE lower(email) = ? LIMIT 1"
      ).bind(email).first();

      if (existing) {
        return error(
          "An account with that email already exists.",
          409
        );
      }

      const id = crypto.randomUUID();
      const passwordHash = await bcrypt.hash(password, 10);
      const displayName = artistName || email.split("@")[0];
      const metadata = JSON.stringify({
        artist_name: displayName
      });

      await env.DB.prepare(`
        INSERT INTO auth_users (
          id, email, encrypted_password, phone, raw_user_meta_data,
          created_at, updated_at, is_anonymous, is_sso_user
        )
        VALUES (
          ?, ?, ?, ?, ?, datetime('now'), datetime('now'), 0, 0
        )
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
          displayName
        ).run();
      } catch (e) {
        console.error(
          "Artist profile creation failed:",
          e.message
        );
      }

      const token = await createSession(env, id);

      return json({
        success: true,
        user: {
          id,
          email,
          artist_name: displayName
        }
      }, 201, {
        "Set-Cookie": makeCookie(token, SESSION_SECONDS)
      });
    } catch (e) {
      console.error("Registration failed:", e.message);
      return error(
        "Account creation failed. Please try again.",
        500
      );
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
        WHERE lower(email) = ?
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

      if (!(await bcrypt.compare(password, user.encrypted_password))) {
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

  for (const [key, value] of url.searchParams.entries()) {
    const dot = key.indexOf(".");
    if (dot < 1) continue;

    const op = key.slice(0, dot);
    const column = key.slice(dot + 1);

    if (!operators[op] || !safeIdentifier(column)) continue;

    filters.push(`${column} ${operators[op]} ?`);

    const normalizedValue =
      value.toLowerCase() === "true" ? 1 :
      value.toLowerCase() === "false" ? 0 :
      value;

    values.push(normalizedValue);
  }

  return {
    sql: filters.length
      ? ` WHERE ${filters.join(" AND ")}`
      : "",
    values,
    count: filters.length
  };
}

function appendCondition(where, condition) {
  return where
    ? `${where} AND (${condition})`
    : ` WHERE (${condition})`;
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

  const artistFinancialRead =
    ARTIST_OWNED_FINANCIAL_TABLES.has(table) &&
    method === "GET" &&
    Boolean(user);

  const artistWithdrawalCreate =
    table === "withdrawal_requests" &&
    method === "POST" &&
    Boolean(user) &&
    !admin;

  if (
    ADMIN_TABLES.has(table) &&
    !admin &&
    !artistFinancialRead &&
    !artistWithdrawalCreate
  ) {
    return error("Admin access required", user ? 403 : 401);
  }

  if (method === "GET") {
    if (!PUBLIC_READ_TABLES.has(table) && !user) {
      return error("Authentication required", 401);
    }

    const selectInput = url.searchParams.get("select") || "*";
    const columns = selectInput.split(",").map(x => x.trim());

    if (
      !columns.length ||
      columns.some(c => c !== "*" && !safeIdentifier(c))
    ) {
      return error("Invalid select columns", 400);
    }

    let { sql: where, values } = parseFilters(url);

    // Financial rows must always be scoped to the signed-in user.
    if (!admin && artistFinancialRead) {
      const ownerColumn =
        table === "artist_wallets" ||
        table === "artist_payouts"
          ? "user_id"
          : "artist_id";

      where = appendCondition(where, `${ownerColumn} = ?`);
      values = [...values, user.id];
    }

    // Non-admin users may read approved songs and their own submissions.
    if (table === "songs" && !admin) {
      if (user) {
        where = appendCondition(
          where,
          "(approved = 1 OR artist_id = ?)"
        );
        values = [...values, user.id];
      } else {
        where = appendCondition(where, "approved = 1");
      }
    }

    const publicArtistRead = table === "artists" && !admin;

    // Public artist reads may expose only these explicitly approved fields.
    // This applies even when a caller supplies a custom `select` parameter.
    const publicArtistColumns = new Set([
      "id", "name", "bio", "avatar_url", "location",
      "total_plays", "verified", "is_premium", "premium_expiry_date", "created_at"
    ]);

    if (
      publicArtistRead &&
      columns.some(column =>
        column !== "*" && !publicArtistColumns.has(column)
      )
    ) {
      return error("One or more requested artist fields are not public", 403);
    }

    // Copyright takedowns are soft removals: keep the records for audit,
    // but never expose removed songs or artist profiles to ordinary users.
    if (table === "songs" && !admin) {
      where = appendCondition(
        where,
        "NOT EXISTS (SELECT 1 FROM copyright_removals cr WHERE cr.content_type = 'song' AND cr.content_id = songs.id)"
      );
    }

    if (publicArtistRead) {
      where = appendCondition(
        where,
        "NOT EXISTS (SELECT 1 FROM copyright_removals cr WHERE cr.content_type = 'artist' AND (cr.content_id = artists.id OR cr.content_id = artists.user_id))"
      );
    }

    const effectiveColumns =
      publicArtistRead && columns.includes("*")
        ? "id, name, bio, avatar_url, location, total_plays, verified, is_premium, premium_expiry_date, created_at"
        : columns.join(",");

    let query = `SELECT ${effectiveColumns} FROM ${table}${where}`;

    const order = url.searchParams.get("order");

    if (order) {
      const [column, direction] = order.split(".");

      if (safeIdentifier(column)) {
        query += ` ORDER BY ${column} ${
          direction === "desc" ? "DESC" : "ASC"
        }`;
      }
    }

    const requestedLimit = Number(
      url.searchParams.get("limit") || 100
    );

    query += ` LIMIT ${Math.min(
      Math.max(requestedLimit || 100, 1),
      500
    )}`;

    try {
      const result = await env.DB.prepare(query).bind(...values).all();
      let rows = result.results || [];

      if (!admin) {
        rows = redactSensitiveColumns(rows);
      }

      if (publicArtistRead) {
        rows = rows.map(row => {
          const copy = { ...row };

          delete copy.earnings;
          // Never disclose account linkage, even to another signed-in user.
          delete copy.user_id;

          return copy;
        });
      }

      return json({ data: rows, error: null });
    } catch (e) {
      console.error("Database read failed:", e.message);
      return error("Database request failed", 500);
    }
  }

  if (!user) {
    return error("Authentication required", 401);
  }

  // Ordinary users may create interactions, but only for themselves.
  // Editing and deleting database records remains administrator-only.
  if (
    !INTERACTION_TABLES.has(table) &&
    table !== "artists" &&
    table !== "songs" &&
    !admin
  ) {
    return error(
      "Admin access required for this operation",
      403
    );
  }

  const { sql: where, values, count } = parseFilters(url);

  if (
    ["PATCH", "PUT", "DELETE"].includes(method) &&
    count === 0
  ) {
    return error(
      "A filter is required for this operation",
      422
    );
  }

  try {
    if (method === "POST") {
      const body = await readBody(request);
      const rows = Array.isArray(body) ? body : [body];

      if (!rows.length || rows.length > 50) {
        return error("Invalid number of rows", 422);
      }

      const output = [];
      const wantsUpsert =
        url.searchParams.get("upsert") === "true";

      if (wantsUpsert) {
        return error("Upsert is not supported for this table", 422);
      }

      for (const input of rows) {
        let row =
          input &&
          typeof input === "object" &&
          !Array.isArray(input)
            ? { ...input }
            : null;

        if (!row) {
          return error("Invalid row supplied", 422);
        }

        if (
          !Object.keys(row).length ||
          Object.keys(row).some(k => !safeIdentifier(k))
        ) {
          return error("Invalid fields supplied", 422);
        }

        // Never trust a client-supplied author ID or moderation fields.
        if (INTERACTION_TABLES.has(table) && !admin) {
          const serverControlledFields = new Set([
            "approved", "is_approved", "moderation_status", "moderated_by",
            "is_admin", "role", "status", "deleted_at", "is_deleted",
            "hidden", "is_hidden", "is_pinned", "pinned",
            "created_by", "like_count", "likes_count", "reaction_count"
          ]);

          if (Object.keys(row).some(key => serverControlledFields.has(key.toLowerCase()))) {
            return error("Moderation and system fields cannot be set by users", 422);
          }

          row.user_id = user.id;
        }

        const keys = Object.keys(row);

        if (table === "artists") {
          if (row.user_id !== user.id) {
            return error(
              "You may only edit your own artist profile",
              403
            );
          }

          // Premium entitlement fields are intentionally excluded: only verified
          // payment handling may change is_premium or premium_expiry_date.
          const allowed = new Set([
            "user_id",
            "name",
            "bio",
            "location",
            "avatar_url"
          ]);

          if (keys.some(k => !allowed.has(k))) {
            return error(
              "Invalid artist profile fields",
              422
            );
          }

          const existing = await env.DB.prepare(
            "SELECT id FROM artists WHERE user_id = ? LIMIT 1"
          ).bind(user.id).first();

          if (existing) {
            const updateKeys = keys.filter(k => k !== "user_id");

            if (updateKeys.length) {
              await env.DB.prepare(`
                UPDATE artists
                SET ${updateKeys.map(k => `${k} = ?`).join(", ")}
                WHERE user_id = ?
              `).bind(
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

            await env.DB.prepare(`
              INSERT INTO artists (${insertKeys.join(",")})
              VALUES (${insertKeys.map(() => "?").join(",")})
            `).bind(
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
            "title",
            "artist",
            "artist_id",
            "file_url",
            "audio_url",
            "cover_url",
            "description",
            "genre",
            "release_date",
            "producer",
            "featured_artists",
            "label",
            "location",
            "terms_accepted",
            "terms_accepted_at",
            "plays",
            "likes",
            "approved",
            "review_status"
          ]);

          if (keys.some(k => !allowed.has(k))) {
            return error("Invalid song fields", 422);
          }

          const accepted =
            row.terms_accepted === true ||
            row.terms_accepted === 1 ||
            row.terms_accepted === "1" ||
            (
              typeof row.terms_accepted === "string" &&
              row.terms_accepted.toLowerCase() === "true"
            );

          // Ignore client-supplied approval, play and like counts.
          const safeRow = {
            ...row,
            id: crypto.randomUUID(),
            artist_id: user.id,
            terms_accepted: accepted ? 1 : 0,
            terms_accepted_at: accepted
              ? (
                  row.terms_accepted_at ||
                  new Date().toISOString()
                )
              : null,
            plays: 0,
            likes: 0,
            approved: 0,
            review_status: "pending"
          };

          const insertKeys = Object.keys(safeRow);

          await env.DB.prepare(`
            INSERT INTO songs (${insertKeys.join(",")})
            VALUES (${insertKeys.map(() => "?").join(",")})
          `).bind(
            ...insertKeys.map(k => safeRow[k] ?? null)
          ).run();

          output.push(await env.DB.prepare(
            "SELECT * FROM songs WHERE id = ? LIMIT 1"
          ).bind(safeRow.id).first());

          continue;
        }

        if (table === "withdrawal_requests" && !admin) {
          // Force ownership server-side, regardless of client input.
          row.artist_id = user.id;

          const amount = Number(row.amount);
          const paymentMethod = String(
            row.payment_method || ""
          ).trim();
          const paymentDetails = String(
            row.payment_details || ""
          ).trim();

          if (
            !Number.isFinite(amount) ||
            amount < WITHDRAWAL_MINIMUM ||
            !paymentMethod ||
            !paymentDetails
          ) {
            return error(
              "A valid amount of at least UGX 10,000, payment method, and payment details are required",
              422
            );
          }

          const newRow = {
            id: crypto.randomUUID(),
            artist_id: user.id,
            amount,
            payment_method: paymentMethod,
            payment_details: paymentDetails,
            status: "pending",
            created_at: new Date().toISOString()
          };

          // Check available earnings and create the reservation in one SQL
          // statement. Concurrent requests cannot both spend the same balance.
          try {
            const inserted = await env.DB.prepare(`
              INSERT INTO withdrawal_requests
                (id, artist_id, amount, payment_method, payment_details, status, created_at)
              SELECT ?, ?, ?, ?, ?, 'pending', ?
              WHERE ? <= MAX(
                0,
                COALESCE((
                  SELECT SUM(COALESCE(plays, 0))
                  FROM songs
                  WHERE artist_id = ? AND approved = 1
                ), 0) * ?
                - COALESCE((
                  SELECT SUM(amount)
                  FROM withdrawal_requests
                  WHERE artist_id = ?
                    AND lower(status) IN (
                      'pending', 'processing', 'paid', 'completed',
                      'success', 'successful'
                    )
                ), 0)
              )
            `).bind(
              newRow.id,
              user.id,
              amount,
              paymentMethod,
              paymentDetails,
              newRow.created_at,
              amount,
              user.id,
              EARNINGS_PER_PLAY,
              user.id
            ).run();

            if (Number(inserted?.meta?.changes || 0) === 0) {
              return error(
                "Insufficient available artist earnings. Refresh your dashboard and try again.",
                409
              );
            }
          } catch (e) {
            console.error(
              "Artist withdrawal request failed:",
              e.message
            );

            return error(
              "Could not create withdrawal request. Please check the withdrawal table schema.",
              500
            );
          }

          return json(
            { data: newRow, error: null },
            201
          );
        }

        if (
          ARTIST_OWNED_FINANCIAL_TABLES.has(table) &&
          !admin
        ) {
          return error(
            "Admin access required for this operation",
            403
          );
        }

        if (!admin && !INTERACTION_TABLES.has(table)) {
          return error(
            "Admin access required for this operation",
            403
          );
        }

        // Return the actual row inserted by SQLite, including generated/default
        // values such as the database-generated id. The frontend relies on this
        // id to confirm uploads and avoid retrying a successful insert.
        const sql = `
          INSERT INTO ${table} (${keys.join(",")})
          VALUES (${keys.map(() => "?").join(",")})
          RETURNING *
        `;

        const insertedResult = await env.DB.prepare(sql).bind(
          ...keys.map(k => row[k] ?? null)
        ).all();
        const insertedRow = insertedResult?.results?.[0];
        if (!insertedRow) {
          return error("The database did not return the inserted record", 500);
        }

        output.push(insertedRow);
      }

      return json({
        data: Array.isArray(body) ? output : output[0],
        error: null
      }, 201);
    }

    if (method === "PATCH" || method === "PUT") {
      if (!admin) {
        return error("Admin access required", 403);
      }

      const body = await readBody(request);
      const keys = Object.keys(body || {});

      if (
        !keys.length ||
        keys.some(k => !safeIdentifier(k))
      ) {
        return error("Invalid fields supplied", 422);
      }

      if (table === "songs") {
        return error(
          "Use the song approval endpoint to change song status.",
          403
        );
      }

      const sql = `
        UPDATE ${table}
        SET ${keys.map(k => `${k} = ?`).join(", ")}
        ${where}
      `;

      await env.DB.prepare(sql).bind(
        ...keys.map(k => body[k] ?? null),
        ...values
      ).run();

      return json({ data: body, error: null });
    }

    if (method === "DELETE") {
      if (!admin) {
        return error("Admin access required", 403);
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

async function removeCopyrightContent(env, user, body) {
  const admin = user ? await getAdmin(env, user) : null;
  if (!admin || admin.role !== "super_admin") {
    return error("Super Admin access required", 403);
  }

  const contentType = String(body.content_type || "").trim().toLowerCase();
  const contentId = String(
    body.content_id || body.song_id || body.artist_id || ""
  ).trim();
  const reason = String(body.reason || "").trim();

  if (!["song", "artist"].includes(contentType) || !contentId || reason.length < 5) {
    return error(
      "Choose a song or artist, and provide a copyright-removal reason of at least 5 characters.",
      422
    );
  }

  try {
    let contentTitle = "";
    let statements = [];

    if (contentType === "song") {
      const song = await env.DB.prepare(
        "SELECT id, title FROM songs WHERE id = ? LIMIT 1"
      ).bind(contentId).first();

      if (!song) {
        return error("Song not found", 404);
      }

      contentTitle = String(song.title || "Untitled song");
      statements = [
        env.DB.prepare(`
          UPDATE songs
          SET approved = 0, review_status = 'rejected', rejection_reason = ?
          WHERE id = ?
        `).bind(`Copyright removal: ${reason}`, song.id),
        env.DB.prepare(`
          INSERT INTO copyright_removals
            (id, removed_by, content_type, content_id, content_title, reason, created_at)
          VALUES (?, ?, 'song', ?, ?, ?, ?)
        `).bind(
          crypto.randomUUID(),
          user.id,
          song.id,
          contentTitle,
          reason,
          new Date().toISOString()
        )
      ];
    } else {
      const artist = await env.DB.prepare(`
        SELECT id, user_id, name
        FROM artists
        WHERE id = ? OR user_id = ?
        LIMIT 1
      `).bind(contentId, contentId).first();

      if (!artist) {
        return error("Artist profile not found", 404);
      }

      const artistUserId = String(artist.user_id || artist.id);
      contentTitle = String(artist.name || "Artist profile");

      statements = [
        env.DB.prepare(`
          UPDATE songs
          SET approved = 0, review_status = 'rejected', rejection_reason = ?
          WHERE artist_id = ?
        `).bind(`Copyright removal: ${reason}`, artistUserId),
        env.DB.prepare(`
          INSERT INTO copyright_removals
            (id, removed_by, content_type, content_id, content_title, reason, created_at)
          VALUES (?, ?, 'artist', ?, ?, ?, ?)
        `).bind(
          crypto.randomUUID(),
          user.id,
          artist.id,
          contentTitle,
          reason,
          new Date().toISOString()
        )
      ];
    }

    await env.DB.batch(statements);

    return json({
      success: true,
      data: {
        content_type: contentType,
        content_id: contentId,
        content_title: contentTitle,
        reason
      },
      error: null
    }, 201);
  } catch (e) {
    console.error("Copyright removal failed:", e.message);
    return error("Could not record the copyright removal", 500);
  }
}

async function adminRoute(request, env, path) {
  const user = await currentUser(request, env);

  if (!user) {
    return error("Authentication required", 401);
  }

  const admin = await getAdmin(env, user);

  if (!admin) {
    return error("Admin access required", 403);
  }

  const superAdmin = admin.role === "super_admin";
  const url = new URL(request.url);

  if (request.method === "GET" && path === "/api/admins") {
    if (!superAdmin) {
      return error("Super Admin access required", 403);
    }

    try {
      const result = await env.DB.prepare(`
        SELECT id, user_id, email, role, active, created_at
        FROM admins
        ORDER BY created_at DESC
      `).all();

      return json({
        data: result.results || [],
        error: null
      });
    } catch (e) {
      console.error("Admin listing failed:", e.message);
      return error("Could not load administrators", 500);
    }
  }

  if (request.method === "POST" && path === "/api/admins") {
    if (!superAdmin) {
      return error("Super Admin access required", 403);
    }

    const body = await readBody(request);
    const targetEmail = String(
      body.email || body.target_email || ""
    ).trim().toLowerCase();

    const role = String(
      body.role || body.target_role || "admin"
    );

    if (
      !targetEmail ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(targetEmail) ||
      !["admin", "super_admin"].includes(role)
    ) {
      return error("Valid email and role are required", 422);
    }

    try {
      const target = await env.DB.prepare(`
        SELECT id, email
        FROM auth_users
        WHERE lower(email) = ? AND deleted_at IS NULL
        LIMIT 1
      `).bind(targetEmail).first();

      if (!target) {
        return error(
          "No registered account exists for that email.",
          404
        );
      }

      const existing = await env.DB.prepare(
        "SELECT id FROM admins WHERE user_id = ? LIMIT 1"
      ).bind(target.id).first();

      if (existing) {
        await env.DB.prepare(`
          UPDATE admins
          SET email = ?, role = ?, active = 1
          WHERE user_id = ?
        `).bind(
          target.email,
          role,
          target.id
        ).run();
      } else {
        await env.DB.prepare(`
          INSERT INTO admins (
            id, user_id, email, role, active, created_at
          )
          VALUES (?, ?, ?, ?, 1, datetime('now'))
        `).bind(
          crypto.randomUUID(),
          target.id,
          target.email,
          role
        ).run();
      }

      return json({ success: true, error: null });
    } catch (e) {
      console.error("Admin creation failed:", e.message);
      return error("Could not update administrator", 500);
    }
  }

  if (
    request.method === "PATCH" &&
    path.startsWith("/api/admins/")
  ) {
    if (!superAdmin) {
      return error("Super Admin access required", 403);
    }

    const adminId = decodeURIComponent(
      path.slice("/api/admins/".length)
    );

    if (!adminId || adminId.includes("/")) {
      return error("Invalid administrator ID", 422);
    }

    const body = await readBody(request);
    const active = body.active;

    if (![true, false, 0, 1, "0", "1"].includes(active)) {
      return error(
        "active must be true, false, 1 or 0",
        422
      );
    }

    try {
      const target = await env.DB.prepare(
        "SELECT id, user_id, role FROM admins WHERE id = ? LIMIT 1"
      ).bind(adminId).first();

      if (!target) {
        return error("Administrator not found", 404);
      }

      if (target.user_id === user.id) {
        return error(
          "You cannot deactivate your own account",
          422
        );
      }

      if (target.role === "super_admin") {
        return error(
          "This endpoint cannot deactivate a Super Admin.",
          403
        );
      }

      await env.DB.prepare(
        "UPDATE admins SET active = ? WHERE id = ?"
      ).bind(
        isTruthyDb(active) ? 1 : 0,
        adminId
      ).run();

      return json({ success: true, error: null });
    } catch (e) {
      console.error("Admin update failed:", e.message);
      return error("Could not update administrator", 500);
    }
  }

  if (request.method === "GET" && path === "/api/admin/copyright-removals") {
    if (!superAdmin) {
      return error("Super Admin access required", 403);
    }

    try {
      const result = await env.DB.prepare(`
        SELECT id, content_type, content_id, content_title, reason, created_at
        FROM copyright_removals
        ORDER BY created_at DESC
        LIMIT 500
      `).all();

      return json({ data: result.results || [], error: null });
    } catch (e) {
      console.error("Copyright removal history failed:", e.message);
      return error("Could not load copyright removal history", 500);
    }
  }

  if (request.method === "POST" && path === "/api/admin/copyright-removals") {
    const body = await readBody(request);
    return removeCopyrightContent(env, user, body);
  }

  if (request.method === "GET" && path === "/api/admin/songs") {
    try {
      const status = url.searchParams.get("status") || "pending";
      let result;

      if (status === "all") {
        result = await env.DB.prepare(
          "SELECT * FROM songs ORDER BY rowid DESC LIMIT 500"
        ).all();
      } else if (status === "approved") {
        result = await env.DB.prepare(
          "SELECT * FROM songs WHERE approved = 1 ORDER BY rowid DESC LIMIT 500"
        ).all();
      } else if (status === "rejected") {
        result = await env.DB.prepare(
          "SELECT * FROM songs WHERE review_status = 'rejected' ORDER BY rowid DESC LIMIT 500"
        ).all();
      } else {
        result = await env.DB.prepare(`
          SELECT * FROM songs
          WHERE COALESCE(approved, 0) = 0
            AND COALESCE(review_status, 'pending') != 'rejected'
          ORDER BY rowid DESC
          LIMIT 500
        `).all();
      }

      return json({
        data: result.results || [],
        error: null
      });
    } catch (e) {
      console.error(
        "Song submissions listing failed:",
        e.message
      );

      return error("Could not load song submissions", 500);
    }
  }

  if (
    request.method === "POST" &&
    path.startsWith("/api/admin/songs/") &&
    path.endsWith("/review")
  ) {
    const prefix = "/api/admin/songs/";

    const songId = decodeURIComponent(
      path.slice(prefix.length, -"/review".length)
    );

    if (!songId || songId.includes("/")) {
      return error("Invalid song ID", 422);
    }

    const body = await readBody(request);
    const status = String(body.status || "").toLowerCase();

    if (!["approved", "rejected", "pending"].includes(status)) {
      return error(
        "Status must be approved, rejected or pending.",
        422
      );
    }

    try {
      const song = await env.DB.prepare(
        "SELECT id FROM songs WHERE id = ? LIMIT 1"
      ).bind(songId).first();

      if (!song) {
        return error("Song not found", 404);
      }

      await env.DB.prepare(`
        UPDATE songs
        SET approved = ?, review_status = ?
        WHERE id = ?
      `).bind(
        status === "approved" ? 1 : 0,
        status,
        songId
      ).run();

      return json({
        success: true,
        song_id: songId,
        approved: status === "approved",
        review_status: status,
        error: null
      });
    } catch (e) {
      console.error("Song review failed:", e.message);
      return error("Could not update song approval", 500);
    }
  }

  return error("Admin endpoint not found", 404);
}

async function rpcRoute(request, env, name) {
  const body = await readBody(request);
  const user = await currentUser(request, env);
  const admin = user ? await getAdmin(env, user) : null;

  try {
    if (name === "get_platform_completed_total") {
      if (!admin || admin.role !== "super_admin") {
        return error("Super Admin access required", 403);
      }

      const columns = await env.DB.prepare(
        "PRAGMA table_info(platform_wallet)"
      ).all();

      const names = new Set(
        (columns.results || []).map(c => c.name)
      );

      if (names.has("balance")) {
        const result = await env.DB.prepare(
          "SELECT COALESCE(SUM(balance), 0) AS total FROM platform_wallet"
        ).first();
        const reserved = await env.DB.prepare(`
          SELECT COALESCE(SUM(amount), 0) AS total
          FROM platform_payouts
          WHERE lower(status) IN ('pending', 'processing')
        `).first();

        return json({
          data: Math.max(
            0,
            Number(result?.total || 0) - Number(reserved?.total || 0)
          ),
          error: null
        });
      }

      const depositColumns = await env.DB.prepare(
        "PRAGMA table_info(platform_deposits)"
      ).all();

      const payoutColumns = await env.DB.prepare(
        "PRAGMA table_info(platform_payouts)"
      ).all();

      const dc = new Set(
        (depositColumns.results || []).map(c => c.name)
      );

      const pc = new Set(
        (payoutColumns.results || []).map(c => c.name)
      );

      let deposits = 0;
      let payouts = 0;

      if (dc.has("amount")) {
        const q = dc.has("status")
          ? "SELECT COALESCE(SUM(amount),0) AS total FROM platform_deposits WHERE lower(status) IN ('completed','success','successful','paid')"
          : "SELECT 0 AS total";

        deposits = Number(
          (await env.DB.prepare(q).first())?.total || 0
        );
      }

      if (pc.has("amount")) {
        const q = pc.has("status")
          ? "SELECT COALESCE(SUM(amount),0) AS total FROM platform_payouts WHERE lower(status) IN ('completed','success','successful','paid')"
          : "SELECT 0 AS total";

        payouts = Number(
          (await env.DB.prepare(q).first())?.total || 0
        );
      }

      return json({
        data: Math.max(0, deposits - payouts),
        error: null
      });
    }

    if (name === "record_song_play") {
      const id = String(body.song_id || "").trim();

      if (!id) {
        return error("song_id is required", 422);
      }

      // Use Cloudflare's client IP header for a basic repeat-play guard.
      // Never trust a client-supplied IP in the JSON body.
      const ip = request.headers.get("CF-Connecting-IP");

      if (!ip) {
        return error(
          "Unable to verify this play request. Please try again.",
          400
        );
      }

      // Insert the play log and increment the song in one D1 batch. The
      // second statement runs only when the first statement inserted a row.
      const results = await env.DB.batch([
        env.DB.prepare(`
          INSERT INTO song_play_log (song_id, ip_address, played_at)
          SELECT ?, ?, datetime('now')
          WHERE EXISTS (
            SELECT 1 FROM songs WHERE id = ? AND approved = 1
          )
          AND NOT EXISTS (
            SELECT 1
            FROM song_play_log
            WHERE song_id = ?
              AND ip_address = ?
              AND datetime(played_at) >= datetime('now', '-10 minutes')
          )
        `).bind(id, ip, id, id, ip),
        env.DB.prepare(`
          UPDATE songs
          SET plays = COALESCE(plays, 0) + 1
          WHERE id = ? AND approved = 1 AND changes() > 0
        `).bind(id)
      ]);

      const inserted = Number(results?.[0]?.meta?.changes || 0) > 0;
      const incremented = Number(results?.[1]?.meta?.changes || 0) > 0;

      return json({
        data: inserted && incremented,
        error: null
      });
    }

    if (name === "add_admin_by_email") {
      if (!admin || admin.role !== "super_admin") {
        return error("Super Admin access required", 403);
      }

      const target = String(
        body.target_email || ""
      ).trim().toLowerCase();

      const role = String(body.target_role || "admin");

      if (
        !target ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(target) ||
        !["admin", "super_admin"].includes(role)
      ) {
        return error("Invalid admin details", 422);
      }

      const targetUser = await env.DB.prepare(`
        SELECT id, email
        FROM auth_users
        WHERE lower(email) = ?
          AND deleted_at IS NULL
        LIMIT 1
      `).bind(target).first();

      if (!targetUser) {
        return error("User not found", 404);
      }

      const existing = await env.DB.prepare(
        "SELECT id FROM admins WHERE user_id = ? LIMIT 1"
      ).bind(targetUser.id).first();

      if (existing) {
        await env.DB.prepare(`
          UPDATE admins
          SET email = ?, role = ?, active = 1
          WHERE user_id = ?
        `).bind(
          targetUser.email,
          role,
          targetUser.id
        ).run();
      } else {
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
      }

      return json({ data: true, error: null });
    }

    if (
      name === "remove_copyright_song" ||
      name === "remove_copyright_artist"
    ) {
      return removeCopyrightContent(env, user, {
        content_type: name === "remove_copyright_song" ? "song" : "artist",
        content_id: body.content_id || body.song_id || body.artist_id,
        reason: body.reason
      });
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
    objectPath = objectPath
      .split("/")
      .map(part => decodeURIComponent(part))
      .join("/");
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

  if (request.method === "GET" || request.method === "HEAD") {
    const key = `${bucket}/${objectPath}`;
    const isHead = request.method === "HEAD";
    const rangeHeader = request.headers.get("Range");
    const metadata = await env.MEDIA_BUCKET.head(key);

    if (!metadata) {
      return error("File not found", 404);
    }

    const size = metadata.size;
    const extension = objectPath.split(".").pop().toLowerCase();
    const mimeTypes = {
      mp3: "audio/mpeg",
      m4a: "audio/mp4",
      mp4: "audio/mp4",
      aac: "audio/aac",
      wav: "audio/wav",
      wave: "audio/wav",
      ogg: "audio/ogg",
      oga: "audio/ogg",
      opus: "audio/ogg",
      flac: "audio/flac",
      webm: "audio/webm",
      jpg: "image/jpeg",
      jpeg: "image/jpeg",
      png: "image/png",
      webp: "image/webp",
      gif: "image/gif",
      svg: "image/svg+xml",
      avif: "image/avif"
    };
    const headers = new Headers({
      "Content-Type": metadata.httpMetadata?.contentType || mimeTypes[extension] || "application/octet-stream",
      "Cache-Control": "public, max-age=31536000",
      "Accept-Ranges": "bytes",
      "Content-Length": String(size)
    });

    if (rangeHeader && !isHead) {
      // Support one byte range, including open-ended and suffix ranges.
      const match = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader.trim());
      if (!match || (!match[1] && !match[2]) || size === 0) {
        headers.set("Content-Range", `bytes */${size}`);
        return new Response(null, { status: 416, headers });
      }

      let offset;
      let length;
      let start;
      let end;
      if (!match[1]) {
        const suffixLength = Number(match[2]);
        if (!Number.isSafeInteger(suffixLength) || suffixLength <= 0) {
          headers.set("Content-Range", `bytes */${size}`);
          return new Response(null, { status: 416, headers });
        }
        length = Math.min(suffixLength, size);
        offset = size - length;
        start = offset;
        end = size - 1;
      } else {
        start = Number(match[1]);
        end = match[2] ? Number(match[2]) : size - 1;
        if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start >= size || end < start) {
          headers.set("Content-Range", `bytes */${size}`);
          return new Response(null, { status: 416, headers });
        }
        end = Math.min(end, size - 1);
        offset = start;
        length = end - start + 1;
      }

      const object = await env.MEDIA_BUCKET.get(key, {
        range: { offset, length }
      });
      if (!object) return error("File not found", 404);
      headers.set("Content-Length", String(length));
      headers.set("Content-Range", `bytes ${start}-${end}/${size}`);
      return new Response(object.body, { status: 206, headers });
    }

    if (isHead) {
      return new Response(null, { headers });
    }

    const object = await env.MEDIA_BUCKET.get(key);
    if (!object) return error("File not found", 404);
    return new Response(object.body, { headers });
  }

  if (
    request.method === "POST" ||
    request.method === "PUT"
  ) {
    const user = await currentUser(request, env);

    if (!user) {
      return error("Authentication required", 401);
    }

    const admin = await isAdmin(env, user);

    if (bucket === "news" && !admin) {
      return error("Admin access required", 403);
    }

    if (
      !admin &&
      !["audio", "covers", "avatars"].includes(bucket)
    ) {
      return error("Upload not allowed", 403);
    }

    if (
      !admin &&
      !objectPath.startsWith(`${user.id}/`)
    ) {
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
          contentType:
            request.headers.get("Content-Type") ||
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

function normalizeUgandanPhone(value) {
  const cleaned = String(value || "").replace(/[\s\-()]/g, "");
  if (cleaned.startsWith("+256")) return cleaned;
  if (cleaned.startsWith("256")) return `+${cleaned}`;
  if (cleaned.startsWith("0")) return `+256${cleaned.slice(1)}`;
  return cleaned;
}

function isSuccessfulPaymentStatus(status) {
  return ["COMPLETED", "SUCCESS", "SUCCESSFUL", "PAID"].includes(
    String(status || "").toUpperCase()
  );
}

async function applyPlatformPaymentStatus(
  env,
  type,
  reference,
  status,
  transactionId = ""
) {
  const normalized = String(status || "").toUpperCase();

  if (type === "collection") {
    await env.DB.batch([
      env.DB.prepare(`
        UPDATE platform_deposits
        SET status = ?
        WHERE reference = ?
          AND lower(status) NOT IN ('completed', 'success', 'successful', 'paid')
      `).bind(normalized.toLowerCase(), reference),
      env.DB.prepare(`
        UPDATE platform_wallet
        SET balance = balance + (
          SELECT amount FROM platform_deposits WHERE reference = ?
        ),
        updated_at = datetime('now')
        WHERE id = (SELECT id FROM platform_wallet ORDER BY created_at LIMIT 1)
          AND changes() > 0
          AND ? IN ('COMPLETED', 'SUCCESS', 'SUCCESSFUL', 'PAID')
      `).bind(reference, normalized)
    ]);
    return;
  }

  await env.DB.batch([
    env.DB.prepare(`
      UPDATE platform_payouts
      SET status = ?,
          pesajet_transaction_id = COALESCE(NULLIF(?, ''), pesajet_transaction_id),
          completed_at = CASE
            WHEN ? IN ('COMPLETED', 'SUCCESS', 'SUCCESSFUL', 'PAID')
            THEN datetime('now') ELSE completed_at END,
          failed_at = CASE
            WHEN ? IN ('FAILED', 'EXPIRED', 'REJECTED')
            THEN datetime('now') ELSE failed_at END
      WHERE reference = ?
        AND lower(status) NOT IN ('completed', 'success', 'successful', 'paid')
    `).bind(normalized, transactionId, normalized, normalized, reference),
    env.DB.prepare(`
      UPDATE platform_wallet
      SET balance = MAX(0, balance - (
        SELECT amount FROM platform_payouts WHERE reference = ?
      )),
      updated_at = datetime('now')
      WHERE id = (SELECT id FROM platform_wallet ORDER BY created_at LIMIT 1)
        AND changes() > 0
        AND ? IN ('COMPLETED', 'SUCCESS', 'SUCCESSFUL', 'PAID')
    `).bind(reference, normalized)
  ]);
}

async function verifyPesaJetWebhook(rawBody, signature, secret) {
  if (typeof signature !== "string" || !signature.trim() || typeof secret !== "string" || !secret) {
    return false;
  }

  // PesaJet documents HMAC-SHA256 with a hex-encoded signature and the
  // signing secret exactly as issued (including its whsec_ prefix, if present).
  // Verify the untouched request body first. Some SDK/reference implementations
  // verify a parsed JSON object, so also try compact JSON serialization as a
  // compatibility fallback. Never process the event until one HMAC matches.
  const bodies = [rawBody];
  let parsedPayload;
  try {
    parsedPayload = JSON.parse(rawBody);
    if (parsedPayload && typeof parsedPayload === "object") {
      const compactBody = JSON.stringify(parsedPayload);
      if (compactBody !== rawBody) bodies.push(compactBody);

      // The PesaJet reference verifier excludes a root-level `signature` field
      // when one is embedded in the payload object.
      if (!Array.isArray(parsedPayload) && Object.prototype.hasOwnProperty.call(parsedPayload, "signature")) {
        const { signature: _embeddedSignature, ...unsignedPayload } = parsedPayload;
        const unsignedBody = JSON.stringify(unsignedPayload);
        if (!bodies.includes(unsignedBody)) bodies.push(unsignedBody);
      }
    }
  } catch {
    // Non-JSON bodies are still checked using their exact raw bytes below.
  }

  const received = String(signature).trim().replace(/^sha256=/i, "").trim();
  if (!received) return false;

  // Normally the exact secret is used. The trimmed fallback only accounts for
  // accidental whitespace around a dashboard secret pasted into an environment
  // variable; it never bypasses HMAC verification.
  const secrets = [secret];
  const trimmedSecret = secret.trim();
  if (trimmedSecret && trimmedSecret !== secret) secrets.push(trimmedSecret);

  const encoder = new TextEncoder();
  for (const candidateSecret of secrets) {
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(candidateSecret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    for (const body of bodies) {
      const digest = new Uint8Array(await crypto.subtle.sign(
        "HMAC",
        key,
        encoder.encode(body)
      ));
      const expectedHex = Array.from(digest)
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
      const expectedBase64 = btoa(String.fromCharCode(...digest));

      for (const expected of [expectedHex, expectedBase64]) {
        const comparison = expected === expectedHex ? received.toLowerCase() : received;
        if (comparison.length !== expected.length) continue;

        let mismatch = 0;
        for (let i = 0; i < expected.length; i++) {
          mismatch |= expected.charCodeAt(i) ^ comparison.charCodeAt(i);
        }
        if (mismatch === 0) return true;
      }
    }
  }

  return false;
}

function premiumPaymentFailureMessage(value) {
  const raw = String(value || "").trim();
  const lower = raw.toLowerCase().replace(/[_-]+/g, " ");
  if (/insufficient|not enough|low balance|wallet balance|balance too low|no funds|insufficient funds/.test(lower)) {
    return "Payment failed: your mobile-money balance is insufficient. Please top up your wallet and try again.";
  }
  if (/limit exceeded|transaction limit|daily limit|limit reached|exceed.*limit/.test(lower)) {
    return "Payment failed because your mobile-money transaction limit was reached. Try again later or contact your mobile-money provider.";
  }
  if (/expired|timed out|time out|timeout/.test(lower)) {
    return "Payment failed because the request expired or timed out. Please check your transaction status before trying again.";
  }
  if (/cancel|declin|reject|fail|error|authorization failed/.test(lower)) {
    return raw ? `Payment failed: ${raw}` : "Mobile-money payment failed. Please check your wallet balance and try again.";
  }
  return raw ? `Payment could not be completed: ${raw}` : "Mobile-money payment failed. Check your wallet balance and transaction limits, then try again.";
}

async function syncArtistPremiumEntitlement(env, userId, preferredArtistId = null) {
  const uid = String(userId || "").trim();
  if (!uid) return { artistFound: false, isPremium: false, expiresAt: null };

  const artist = preferredArtistId
    ? await env.DB.prepare("SELECT id FROM artists WHERE id = ? AND user_id = ? LIMIT 1").bind(preferredArtistId, uid).first()
    : await env.DB.prepare("SELECT id FROM artists WHERE user_id = ? LIMIT 1").bind(uid).first();

  if (!artist) return { artistFound: false, isPremium: false, expiresAt: null };

  // Keep the most recent paid expiry visible, even after it expires. The boolean
  // entitlement is always derived from the database clock, not from a client.
  const latest = await env.DB.prepare(`
    SELECT expires_at,
           CASE WHEN datetime(expires_at) > datetime('now') THEN 1 ELSE 0 END AS currently_active
    FROM premium_subscriptions
    WHERE user_id = ? AND lower(status) = 'active' AND expires_at IS NOT NULL
    ORDER BY datetime(expires_at) DESC
    LIMIT 1
  `).bind(uid).first();

  const expiresAt = latest?.expires_at || null;
  const isPremium = Number(latest?.currently_active || 0) === 1;
  await env.DB.prepare(`
    UPDATE artists
    SET is_premium = ?, premium_expiry_date = ?
    WHERE id = ? AND user_id = ?
  `).bind(isPremium ? 1 : 0, expiresAt, artist.id, uid).run();

  return { artistFound: true, artistId: artist.id, isPremium, expiresAt };
}

async function premiumSubscriptionRoute(request, env) {
  const user = await currentUser(request, env);
  if (!user) return error("Authentication required", 401);

  if (request.method === "GET") {
    const entitlement = await syncArtistPremiumEntitlement(env, user.id);
    const requestedReference = new URL(request.url).searchParams.get("reference");
    if (requestedReference) {
      const payment = await env.DB.prepare(`
        SELECT status, reference, expires_at, failure_message
        FROM premium_subscriptions
        WHERE user_id = ? AND reference = ?
        LIMIT 1
      `).bind(user.id, requestedReference).first();
      if (!payment) return error("Payment reference not found", 404);

      const paymentStatus = String(payment.status || "").toLowerCase();
      const paymentActive = paymentStatus === "active" && !!payment.expires_at && Date.parse(payment.expires_at) > Date.now();
      const paymentPending = paymentStatus === "pending";
      const paymentFailed = paymentStatus === "failed";
      return json({
        active: paymentActive,
        pending: paymentPending,
        status: paymentActive ? "active" : paymentPending ? "pending" : paymentFailed ? "failed" : "free",
        expiresAt: paymentActive ? payment.expires_at : null,
        reference: payment.reference,
        message: paymentFailed ? payment.failure_message || "Mobile-money payment failed. Check your wallet balance and transaction limits, then try again." : null,
        isArtist: entitlement.artistFound,
        artistId: entitlement.artistId || null,
        isPremium: entitlement.isPremium,
        premiumExpiryDate: entitlement.expiresAt
      });
    }

    const row = await env.DB.prepare(`
      SELECT status, expires_at FROM premium_subscriptions
      WHERE user_id = ? AND lower(status) = 'active' AND expires_at IS NOT NULL
        AND datetime(expires_at) > datetime('now')
      ORDER BY datetime(expires_at) DESC LIMIT 1
    `).bind(user.id).first();
    const pendingRow = await env.DB.prepare(`
      SELECT reference FROM premium_subscriptions
      WHERE user_id = ? AND lower(status) = 'pending'
      ORDER BY created_at DESC LIMIT 1
    `).bind(user.id).first();
    const latestRow = await env.DB.prepare(`
      SELECT status, reference, failure_message FROM premium_subscriptions
      WHERE user_id = ? ORDER BY created_at DESC LIMIT 1
    `).bind(user.id).first();
    const active = !!row;
    const pending = !!pendingRow;
    const failed = !active && !pending && String(latestRow?.status || "").toLowerCase() === "failed";
    return json({
      active,
      pending,
      status: active ? "active" : pending ? "pending" : failed ? "failed" : "free",
      expiresAt: active ? row.expires_at : null,
      reference: pending ? pendingRow.reference : failed ? latestRow.reference : null,
      message: failed ? latestRow.failure_message || "Mobile-money payment failed. Check your wallet balance and transaction limits, then try again." : null,
      isArtist: entitlement.artistFound,
      artistId: entitlement.artistId || null,
      isPremium: entitlement.isPremium,
      premiumExpiryDate: entitlement.expiresAt
    });
  }

  if (request.method !== "POST") return error("Method not allowed", 405);
  const artist = await env.DB.prepare(
    "SELECT id FROM artists WHERE user_id = ? LIMIT 1"
  ).bind(user.id).first();
  if (!artist) return error("NileSoniQ Premium is available to artist accounts only", 403);

  const body = await readBody(request);
  const phone = normalizeUgandanPhone(body.phone_number || body.phoneNumber);
  const provider = String(body.provider || "").trim().toLowerCase();
  if (!/^\+256\d{9}$/.test(phone)) return error("Enter a valid Ugandan mobile-money number", 422);
  if (!["mtn", "airtel"].includes(provider)) return error("Provider must be MTN or Airtel", 422);
  const apiKey = env.PESAJET_API_KEY || env.PESAJET_TOKEN;
  const baseUrl = String(env.PESAJET_API_BASE_URL || "https://payments.pesajet.com/api/v1").replace(/\/+$/, "");
  if (!apiKey) return error("Payment service is not configured", 503);

  // Each attempt gets a unique reference. Keep payment initiation behavior unchanged.
  const reference = `NILESONIQ-PREMIUM-${crypto.randomUUID()}`;
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await env.DB.prepare(`
    INSERT INTO premium_subscriptions
      (id,user_id,artist_id,amount,currency,provider,phone_number,reference,status,created_at)
    VALUES (?,?,?,5000,'UGX',?,?,?,'pending',?)
  `).bind(id,user.id,artist.id,provider,phone,reference,now).run();

  let response, result;
  try {
    response = await fetch(`${baseUrl}/payments`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
      body: JSON.stringify({ type: "COLLECTION", amount: 5000, currency: "UGX", phoneNumber: phone, provider, reference, description: "NileSoniQ Premium - 30 days", idempotencyKey: `nilesoniq-${reference}` })
    });
    result = await response.json().catch(() => ({}));
  } catch (e) {
    console.error("Premium payment outcome uncertain:", e.message);
    return error("Payment request outcome is uncertain. It remains pending; check provider status before retrying.", 502);
  }

  const dataObject = result?.data && typeof result.data === "object" ? result.data : {};
  const transaction = result?.transaction && typeof result.transaction === "object"
    ? result.transaction
    : dataObject?.transaction && typeof dataObject.transaction === "object"
      ? dataObject.transaction
      : dataObject;
  const statusCandidates = [
    transaction?.status, transaction?.transactionStatus, transaction?.paymentStatus, transaction?.state,
    dataObject?.status, dataObject?.transactionStatus, dataObject?.paymentStatus, dataObject?.state,
    result?.status, result?.transactionStatus, result?.paymentStatus, result?.state
  ].filter(Boolean).map(value => String(value).trim().toUpperCase().replace(/[\s-]+/g, "_"));
  const status = statusCandidates[0] || "PENDING";
  const providerId = String(transaction?.transactionId || transaction?.transaction_id || dataObject?.transactionId || dataObject?.transaction_id || result?.transactionId || result?.transaction_id || "");
  const providerMessages = [
    result?.message, result?.description, result?.detail, result?.reason, result?.failureReason, result?.failure_reason,
    result?.failureMessage, result?.failure_message, result?.errorCode, result?.error_code, result?.code,
    typeof result?.error === "string" ? result.error : result?.error?.message || result?.error?.description || result?.error?.code,
    dataObject?.message, dataObject?.description, dataObject?.detail, dataObject?.reason, dataObject?.failureReason,
    dataObject?.failure_reason, dataObject?.failureMessage, dataObject?.failure_message, dataObject?.errorCode,
    dataObject?.error_code, dataObject?.code,
    typeof dataObject?.error === "string" ? dataObject.error : dataObject?.error?.message || dataObject?.error?.description || dataObject?.error?.code,
    transaction?.message, transaction?.description, transaction?.detail, transaction?.reason,
    transaction?.failureReason, transaction?.failure_reason, transaction?.failureMessage, transaction?.failure_message,
    transaction?.errorCode, transaction?.error_code, transaction?.code,
    typeof transaction?.error === "string" ? transaction.error : transaction?.error?.message || transaction?.error?.description || transaction?.error?.code,
    ...statusCandidates
  ].filter(value => value !== undefined && value !== null && String(value).trim() !== "").map(value => String(value).trim());
  const providerMessage = providerMessages.join(" | ");
  const failureStatuses = ["FAILED", "FAILURE", "ERROR", "EXPIRED", "REJECTED", "DECLINED", "CANCELLED", "CANCELED", "TIMED_OUT", "TIMEOUT", "TIME_OUT", "INSUFFICIENT_BALANCE", "INSUFFICIENT_FUNDS", "AUTHORIZATION_FAILED", "LIMIT_EXCEEDED"];
  const failureText = /insufficient[ _-]*(balance|funds)|not enough (money|funds|balance)|low balance|balance too low|transaction limit|daily limit|limit exceeded|payment failed|payment declined|request rejected|authorization failed/i.test(providerMessage);
  const hasExplicitError = result?.success === false || dataObject?.success === false || !!result?.error || !!dataObject?.error || !!transaction?.error;
  const providerRejected = !response.ok || hasExplicitError || statusCandidates.some(value => failureStatuses.includes(value)) || failureText;
  if (providerRejected) {
    const rawReason = providerMessage || "Payment provider rejected the request";
    const failureMessage = premiumPaymentFailureMessage(rawReason);
    const definitive = (response.status >= 400 && response.status < 500) || hasExplicitError || statusCandidates.some(value => failureStatuses.includes(value)) || failureText;
    if (definitive) {
      await env.DB.prepare("UPDATE premium_subscriptions SET status='failed', provider_transaction_id=?, failure_message=? WHERE reference=? AND lower(status)='pending'").bind(providerId, failureMessage, reference).run();
    }
    return error(failureMessage, response.status >= 400 && response.status < 500 ? response.status : 502);
  }

  if (statusCandidates.some(value => ["PENDING", "PROCESSING", "INITIATED", "ACCEPTED", "IN_PROGRESS"].includes(value)) || status === "PENDING") {
    // The API accepted the request, but that does not prove the prompt reached the phone.
  } else if (statusCandidates.length && !isSuccessfulPaymentStatus(status)) {
    const failureMessage = premiumPaymentFailureMessage(providerMessage || status);
    await env.DB.prepare("UPDATE premium_subscriptions SET status='failed', provider_transaction_id=?, failure_message=? WHERE reference=? AND lower(status)='pending'").bind(providerId, failureMessage, reference).run();
    return json({ success: false, status: "FAILED", reference, message: failureMessage });
  }

  await env.DB.prepare("UPDATE premium_subscriptions SET provider_transaction_id=? WHERE reference=? AND status='pending'").bind(providerId,reference).run();
  return json({
    success: true,
    status: "PENDING",
    reference,
    message: "Your payment request was accepted by the provider. Check your phone for a mobile-money approval prompt and enter your PIN if it arrives. We will update the status when the provider confirms the outcome."
  });
}

async function applyPremiumPaymentStatus(
  env,
  reference,
  status,
  transactionId = "",
  confirmedAmount = null,
  confirmedCurrency = "",
  failureMessage = ""
) {
  const normalized = String(status || "").toUpperCase();
  const ref = String(reference || "").trim();
  if (!ref) return { matched: false, reason: "missing_reference" };

  const payment = await env.DB.prepare(`
    SELECT id, user_id, artist_id, amount, currency, status, provider_transaction_id
    FROM premium_subscriptions WHERE reference = ? LIMIT 1
  `).bind(ref).first();
  if (!payment) return { matched: false, reason: "unknown_reference" };
  if (String(payment.status || "").toLowerCase() !== "pending") {
    // Webhook retries must never activate twice or extend the subscription twice.
    if (String(payment.status || "").toLowerCase() === "active") {
      await syncArtistPremiumEntitlement(env, payment.user_id, payment.artist_id || null);
    }
    return { matched: true, changed: false, reason: "already_processed" };
  }

  let artistId = String(payment.artist_id || "").trim();
  if (!artistId) {
    const artist = await env.DB.prepare(
      "SELECT id FROM artists WHERE user_id = ? LIMIT 1"
    ).bind(payment.user_id).first();
    artistId = String(artist?.id || "").trim();
    if (artistId) {
      await env.DB.prepare(
        "UPDATE premium_subscriptions SET artist_id = ? WHERE reference = ? AND (artist_id IS NULL OR artist_id = '')"
      ).bind(artistId, ref).run();
    }
  }
  if (!artistId) {
    return { matched: true, changed: false, reason: "artist_account_missing" };
  }
  const linkedArtist = await env.DB.prepare(
    "SELECT id FROM artists WHERE id = ? AND user_id = ? LIMIT 1"
  ).bind(artistId, payment.user_id).first();
  if (!linkedArtist) {
    return { matched: true, changed: false, reason: "artist_account_missing" };
  }

  const incomingTransactionId = String(transactionId || "").trim();
  const storedTransactionId = String(payment.provider_transaction_id || "").trim();
  if (storedTransactionId && incomingTransactionId && storedTransactionId !== incomingTransactionId) {
    return { matched: true, changed: false, reason: "transaction_id_mismatch" };
  }

  if (isSuccessfulPaymentStatus(normalized)) {
    const amount = Number(confirmedAmount);
    const currency = String(confirmedCurrency || "").trim().toUpperCase();
    const expectedAmount = Number(payment.amount);
    const expectedCurrency = String(payment.currency || "").trim().toUpperCase();

    // Never grant a paid subscription unless the signed provider event includes
    // an amount and currency matching the exact pending Premium transaction.
    if (!Number.isFinite(amount) || !currency || amount !== expectedAmount || currency !== expectedCurrency || expectedAmount !== 5000 || expectedCurrency !== "UGX") {
      console.error("Premium payment confirmation failed amount/currency validation", {
        reference: ref,
        receivedAmount: Number.isFinite(amount) ? amount : null,
        receivedCurrency: currency || null,
        expectedAmount,
        expectedCurrency
      });
      return { matched: true, changed: false, reason: "amount_currency_mismatch" };
    }

    const update = await env.DB.prepare(`
      UPDATE premium_subscriptions
      SET status='active',
          provider_transaction_id=COALESCE(NULLIF(?,''),provider_transaction_id),
          paid_at=COALESCE(paid_at,datetime('now')),
          expires_at=CASE
            WHEN (
              SELECT MAX(datetime(existing.expires_at))
              FROM premium_subscriptions AS existing
              WHERE existing.user_id = premium_subscriptions.user_id
                AND lower(existing.status) = 'active'
                AND existing.expires_at IS NOT NULL
                AND datetime(existing.expires_at) > datetime('now')
            ) IS NOT NULL
            THEN datetime((
              SELECT MAX(datetime(existing.expires_at))
              FROM premium_subscriptions AS existing
              WHERE existing.user_id = premium_subscriptions.user_id
                AND lower(existing.status) = 'active'
                AND existing.expires_at IS NOT NULL
                AND datetime(existing.expires_at) > datetime('now')
            ), '+30 days')
            ELSE datetime('now','+30 days')
          END
      WHERE reference=? AND lower(status)='pending'
        AND amount=5000 AND upper(currency)='UGX'
        AND (?='' OR provider_transaction_id IS NULL OR provider_transaction_id='' OR provider_transaction_id=?)
    `).bind(incomingTransactionId, ref, incomingTransactionId, incomingTransactionId).run();
    const changed = Number(update?.meta?.changes || 0) > 0;
    // The artist entitlement mirrors the verified subscription expiry. Re-sync
    // even on a concurrent duplicate callback; activation itself remains idempotent.
    await syncArtistPremiumEntitlement(env, payment.user_id, artistId);
    return { matched: true, changed, reason: "verified_success" };
  }

  if (["FAILED", "FAILURE", "ERROR", "EXPIRED", "REJECTED", "DECLINED", "CANCELLED", "CANCELED", "TIMED_OUT", "TIMEOUT", "TIME_OUT", "INSUFFICIENT_BALANCE", "INSUFFICIENT_FUNDS", "AUTHORIZATION_FAILED", "LIMIT_EXCEEDED"].includes(normalized)) {
    await env.DB.prepare(`
      UPDATE premium_subscriptions
      SET status='failed',
          provider_transaction_id=COALESCE(NULLIF(?,''),provider_transaction_id),
          failure_message=?
      WHERE reference=? AND lower(status)='pending'
        AND (?='' OR provider_transaction_id IS NULL OR provider_transaction_id='' OR provider_transaction_id=?)
    `).bind(
      incomingTransactionId,
      premiumPaymentFailureMessage(failureMessage || normalized),
      ref,
      incomingTransactionId,
      incomingTransactionId
    ).run();
  }
  return { matched: true, changed: false, reason: "non_success_status" };
}

function readPesaJetWebhookPaymentFields(payload) {
  const data = payload?.data && typeof payload.data === "object" ? payload.data : {};
  const transaction = payload?.transaction && typeof payload.transaction === "object"
    ? payload.transaction
    : data?.transaction && typeof data.transaction === "object" ? data.transaction : {};

  const rawAmount = data.amount ?? payload.amount ?? transaction.amount ?? null;
  const amountObject = rawAmount && typeof rawAmount === "object" ? rawAmount : null;
  const amountValue = amountObject ? (amountObject.value ?? amountObject.amount ?? null) : rawAmount;
  const currency = amountObject?.currency ?? data.currency ?? payload.currency ?? transaction.currency ?? "";

  return {
    reference: String(payload?.reference ?? data.reference ?? transaction.reference ?? payload?.merchantReference ?? data.merchantReference ?? "").trim(),
    transactionId: String(payload?.transactionId ?? payload?.transaction_id ?? data.transactionId ?? data.transaction_id ?? transaction.transactionId ?? transaction.transaction_id ?? "").trim(),
    amount: amountValue === null || amountValue === undefined || amountValue === "" ? null : Number(amountValue),
    currency: String(currency || "").trim().toUpperCase()
  };
}


async function paymentWebhookRoute(request, env) {
  if (request.method !== "POST") {
    return error("Method not allowed", 405);
  }

  const secret = env.PESAJET_WEBHOOK_SECRET;
  if (!secret) {
    console.error("PesaJet webhook secret is not configured.");
    return error("Payment webhook verification is not configured.", 503);
  }

  const rawBody = await request.text();
  const signature = request.headers.get("X-Webhook-Signature");

  if (!(await verifyPesaJetWebhook(rawBody, signature, secret))) {
    return error("Invalid PesaJet webhook signature", 401);
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return error("Invalid webhook payload", 400);
  }

  const event = String(payload.event || "").toLowerCase();
  if (event === "webhook.test") {
    return json({ received: true, test: true });
  }

  const eventStatus = {
    "payment.completed": "COMPLETED",
    "payment.succeeded": "COMPLETED",
    "payment.failed": "FAILED",
    "payment.declined": "DECLINED",
    "payment.expired": "EXPIRED",
    "payment.cancelled": "CANCELLED",
    "payment.canceled": "CANCELLED",
    "payment.rejected": "REJECTED"
  };
  const status = eventStatus[event];

  if (!status) {
    return json({ received: true, ignored: true });
  }

  const webhookPayment = readPesaJetWebhookPaymentFields(payload);
  const reference = webhookPayment.reference;
  const transactionId = webhookPayment.transactionId;

  if (!reference) {
    return error("Webhook reference is required", 422);
  }

  try {
    // A reference belongs to one transaction table; the unmatched update is a no-op.
    await applyPlatformPaymentStatus(
      env,
      "collection",
      reference,
      status,
      transactionId
    );
    await applyPlatformPaymentStatus(
      env,
      "disbursement",
      reference,
      status,
      transactionId
    );
    const premiumResult = await applyPremiumPaymentStatus(
      env,
      reference,
      status,
      transactionId,
      webhookPayment.amount,
      webhookPayment.currency,
      payload?.message || payload?.description || payload?.reason || payload?.failureReason || payload?.failure_reason ||
        payload?.failureMessage || payload?.failure_message || payload?.error?.message || payload?.error?.code ||
        payload?.data?.message || payload?.data?.description || payload?.data?.reason || payload?.data?.failureReason ||
        payload?.data?.failure_reason || payload?.data?.failureMessage || payload?.data?.failure_message ||
        payload?.data?.error?.message || payload?.data?.error?.code || ""
    );
    if (premiumResult.reason === "amount_currency_mismatch" || premiumResult.reason === "transaction_id_mismatch") {
      console.error("Premium payment webhook was not applied:", premiumResult.reason, reference);
    }

    return json({ received: true });
  } catch (e) {
    console.error("PesaJet webhook processing failed:", e.message);
    return error("Could not process the payment webhook", 500);
  }
}

async function paymentRoute(request, env, type) {
  if (request.method !== "POST") {
    return error("Method not allowed", 405);
  }

  const user = await currentUser(request, env);
  if (!user) {
    return error("Authentication required", 401);
  }

  if (!(await isSuperAdmin(env, user))) {
    return error("Super Admin access required", 403);
  }

  const body = await readBody(request);
  const amount = Number(body.amount);
  const phone = normalizeUgandanPhone(body.phone_number || body.phoneNumber);
  const provider = String(body.provider || body.network || "").trim().toLowerCase();

  if (
    !Number.isFinite(amount) ||
    amount < 1000 ||
    !/^\+256\d{9}$/.test(phone)
  ) {
    return error(
      "A valid amount of at least UGX 1,000 and a valid Ugandan mobile-money number are required",
      422
    );
  }

  if (!["mtn", "airtel"].includes(provider)) {
    return error("Provider must be MTN or Airtel", 422);
  }

  const apiKey = env.PESAJET_API_KEY || env.PESAJET_TOKEN;
  const baseUrl = String(
    env.PESAJET_API_BASE_URL || "https://payments.pesajet.com/api/v1"
  ).replace(/\/+$/, "");

  if (!apiKey) {
    console.error("PesaJet API key is not configured.");
    return error("Payment service is not configured.", 503);
  }

  const reference = String(
    body.reference || `NILESONIQ-${type.toUpperCase()}-${crypto.randomUUID()}`
  ).trim().slice(0, 120);

  if (!reference) {
    return error("A payment reference is required", 422);
  }

  const transactionId = crypto.randomUUID();
  const description = String(
    body.description ||
    (type === "collection"
      ? "NileSoniq platform wallet deposit"
      : "NileSoniq platform wallet withdrawal")
  ).slice(0, 250);

  try {
    if (type === "collection") {
      await env.DB.prepare(`
        INSERT INTO platform_deposits
          (id, amount, currency, provider, phone_number, reference, status, created_at)
        VALUES (?, ?, 'UGX', ?, ?, ?, 'pending', ?)
      `).bind(
        transactionId,
        amount,
        provider,
        phone,
        reference,
        new Date().toISOString()
      ).run();
    } else {
      // Reserve the amount in the same atomic INSERT that checks the available
      // platform wallet balance, so concurrent requests cannot spend the same funds.
      const reservation = await env.DB.prepare(`
        INSERT INTO platform_payouts
          (id, amount, currency, phone_number, provider, reference, description, status, created_by, created_at)
        SELECT ?, ?, 'UGX', ?, ?, ?, ?, 'PENDING', ?, datetime('now')
        WHERE COALESCE(
          (SELECT SUM(balance) FROM platform_wallet), 0
        ) - COALESCE(
          (SELECT SUM(amount) FROM platform_payouts
           WHERE lower(status) IN ('pending', 'processing')), 0
        ) >= ?
      `).bind(
        transactionId,
        amount,
        phone,
        provider,
        reference,
        description,
        user.id,
        amount
      ).run();

      if (Number(reservation?.meta?.changes || 0) === 0) {
        return error("Insufficient available platform wallet balance", 409);
      }
    }

    const payload = {
      type: type === "collection" ? "COLLECTION" : "DISBURSEMENT",
      amount,
      currency: "UGX",
      phoneNumber: phone,
      provider,
      reference,
      description,
      idempotencyKey: `nilesoniq-${reference}`
    };

    let response;
    let result;

    try {
      response = await fetch(`${baseUrl}/payments`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": apiKey
        },
        body: JSON.stringify(payload)
      });

      result = await response.json().catch(() => ({}));
    } catch (e) {
      // The provider may have received the request even if the response was lost.
      // Leave it pending/reserved so a retry cannot silently double-spend funds.
      console.error("PesaJet request outcome is uncertain:", e.message);
      return error(
        "PesaJet could not confirm the request. The transaction was left pending to prevent duplicate payment. Check the PesaJet dashboard before retrying.",
        502
      );
    }

    const transaction =
      result?.transaction && typeof result.transaction === "object"
        ? result.transaction
        : result?.data && typeof result.data === "object"
          ? result.data
          : result;

    const status = String(transaction?.status || result?.status || "").toUpperCase();
    const providerTransactionId = String(
      transaction?.transactionId ||
      transaction?.transaction_id ||
      result?.transactionId ||
      result?.transaction_id ||
      ""
    );

    if (!response.ok || result?.success === false) {
      const definitiveFailure =
        (response.status >= 400 && response.status < 500) ||
        result?.success === false;

      if (definitiveFailure) {
        await applyPlatformPaymentStatus(
          env,
          type,
          reference,
          "FAILED",
          providerTransactionId
        );
      }

      const message = String(
        result?.error?.message ||
        result?.message ||
        result?.error ||
        "PesaJet rejected the transaction request."
      );

      return error(
        message,
        response.status >= 400 && response.status < 500
          ? response.status
          : 502
      );
    }

    await applyPlatformPaymentStatus(
      env,
      type,
      reference,
      status || "PENDING",
      providerTransactionId
    );

    return json({
      success: true,
      ...transaction,
      transactionId: providerTransactionId || transaction?.transactionId || null,
      status: status || "PENDING",
      reference
    }, response.status);
  } catch (e) {
    console.error("Payment request processing failed:", e.message);
    return error(
      "Could not safely record the payment request. Check the platform wallet and PesaJet dashboard before retrying.",
      500
    );
  }
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (request.method === "OPTIONS") {
        return withCors(
          request,
          new Response(null, { status: 204 })
        );
      }

      let response;

      if (path.startsWith("/api/auth/")) {
        response = await authRoute(request, env, path);
      } else if (path.startsWith("/api/db/")) {
        response = await dbRoute(request, env, path);
      } else if (
        path === "/api/admins" ||
        path.startsWith("/api/admins/") ||
        path === "/api/admin/songs" ||
        path.startsWith("/api/admin/songs/") ||
        path === "/api/admin/copyright-removals"
      ) {
        response = await adminRoute(request, env, path);
      } else if (path.startsWith("/api/rpc/")) {
        response = await rpcRoute(
          request,
          env,
          path.split("/")[3]
        );
      } else if (
        path === "/api/payments/pesajet-webhook"
      ) {
        response = await paymentWebhookRoute(request, env);
      } else if (
        path === "/api/payments/pesajet-collection"
      ) {
        response = await paymentRoute(
          request,
          env,
          "collection"
        );
      } else if (
        path === "/api/payments/pesajet-disbursement"
      ) {
        response = await paymentRoute(
          request,
          env,
          "disbursement"
        );
      } else if (path === "/api/payments/premium-subscription") {
        response = await premiumSubscriptionRoute(request, env);
      } else if (path.startsWith("/api/storage/public/")) {
        response = await storageRoute(
          request,
          env,
          path.replace(
            "/api/storage/public",
            "/api/storage"
          )
        );
      } else if (path === "/api/storage/upload") {
        const bucket = url.searchParams.get("bucket") || "audio";
        const objectPath = url.searchParams.get("path") || "file";

        response = await storageRoute(
          request,
          env,
          `/api/storage/${bucket}/${objectPath}`
        );
      } else if (path === "/api/health") {
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
