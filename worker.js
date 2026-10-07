async function register(request, env, origin) {
  let stage = "starting";

  try {
    stage = "creating auth tables";
    await ensureAuthTables(env);

    stage = "reading request";
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
    ).trim().toLowerCase();

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
          code: "ARTIST_NAME_REQUIRED"
        },
        400,
        origin
      );
    }

    if (!email) {
      return json(
        {
          error: "Email is required.",
          code: "EMAIL_REQUIRED"
        },
        400,
        origin
      );
    }

    if (!email.includes("@")) {
      return json(
        {
          error: "Please enter a valid email address.",
          code: "INVALID_EMAIL"
        },
        400,
        origin
      );
    }

    if (!password || password.length < 6) {
      return json(
        {
          error: "Password must be at least 6 characters.",
          code: "PASSWORD_TOO_SHORT"
        },
        400,
        origin
      );
    }

    stage = "checking existing email";

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
          code: "EMAIL_EXISTS"
        },
        409,
        origin
      );
    }

    stage = "hashing password";

    const userId = crypto.randomUUID();
    const now = new Date().toISOString();
    const passwordHash = await hashPassword(password);

    stage = "creating user account";

    await env.DB.prepare(`
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
      VALUES (?, ?, NULL, ?, ?, ?, ?, ?, 0, 0)
    `)
      .bind(
        userId,
        email,
        now,
        JSON.stringify({
          provider: "email",
          providers: ["email"]
        }),
        JSON.stringify({
          artist_name: artistName
        }),
        now,
        now
      )
      .run();

    stage = "creating password credentials";

    await env.DB.prepare(`
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
        now,
        now
      )
      .run();

    stage = "creating artist profile";

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
      console.error(
        "ARTIST_PROFILE_CREATE_FAILED",
        artistError?.message || String(artistError)
      );
    }

    stage = "creating session";

    const session = await createSession(env, userId);

    return json(
      {
        ok: true,
        message: "Account created successfully.",
        user: {
          id: userId,
          email,
          artist_name: artistName
        },
        session,
        access_token: session.access_token
      },
      201,
      origin
    );

  } catch (error) {
    console.error(
      "REGISTER_FAILED",
      stage,
      error?.message || String(error)
    );

    return json(
      {
        error: "Account creation failed.",
        stage,
        details: error?.message || String(error),
        code: "REGISTER_FAILED"
      },
      500,
      origin
    );
  }
}
