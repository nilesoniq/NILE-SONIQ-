
import bcrypt from "bcryptjs";

const COOKIE_NAME = "nile_session";
const SESSION_SECONDS = 30 * 24 * 60 * 60;
const EARNINGS_PER_PLAY = 0.5;
const ARTIST_COMMISSION_RATE = 0.20;
const ARTIST_TAX_ALLOCATION_RATE = 0.05;
const ARTIST_NET_RATE = 1 - ARTIST_COMMISSION_RATE - ARTIST_TAX_ALLOCATION_RATE;
const ARTIST_FREE_NET_PER_PLAY = EARNINGS_PER_PLAY * ARTIST_NET_RATE;
const WITHDRAWAL_MINIMUM = 10000;
// Rollout cutoff is stored in UTC because SQLite datetime('now') is UTC.
// Songs created before this cutoff remain stored and are excluded from the
// rollout month's upload count. No existing song is deleted or changed.
// 2026-10-29 07:48 UTC = 10:48 AM Uganda time.
const PACKAGE_LIMITS_EFFECTIVE_AT = "2026-10-29 07:48:00";
const ARTIST_PACKAGE_UPLOAD_LIMITS = Object.freeze({
  free: 3,
  premium: 6,
  hustler: 15,
  hit_maker: Number.MAX_SAFE_INTEGER,
  star: Number.MAX_SAFE_INTEGER
});

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

async function sendResendEmail(env, { to, subject, html, text }) {
  if (!env.RESEND_API_KEY) {
    throw new Error("RESEND_API_KEY secret is not configured");
  }

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: env.RESEND_FROM_EMAIL || "NileSoniQ <noreply@nilesoniq.com>",
      to: [to],
      subject,
      html,
      text
    })
  });

  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    console.error("Resend email request failed:", response.status, result?.message || result?.name || "unknown error");
    throw new Error("Email provider rejected the request");
  }
  return result;
}

function authResultPage(title, message, status = 200) {
  const safeTitle = String(title).replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
  const safeMessage = String(message).replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${safeTitle} - NileSoniQ</title><body style="font-family:system-ui,sans-serif;max-width:560px;margin:12vh auto;padding:24px;color:#222"><h1>${safeTitle}</h1><p>${safeMessage}</p><p><a href="https://nilesoniq.com/">Return to NileSoniQ</a></p></body></html>`, { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

async function ensureAuthEmailColumns(env) {
  // Keep this migration limited to auth_users email-verification/reset fields.
  // It does not modify user rows or any payment, song, wallet, or admin tables.
  const requiredColumns = {
    email_confirmed_at: "TEXT",
    confirmation_token: "TEXT",
    confirmation_sent_at: "TEXT",
    recovery_token: "TEXT",
    recovery_sent_at: "TEXT",
    updated_at: "TEXT"
  };

  const getColumns = async () => {
    const result = await env.DB.prepare("PRAGMA table_info(auth_users)").all();
    return new Set((result.results || []).map(column => String(column.name).toLowerCase()));
  };

  let columns = await getColumns();
  if (columns.size === 0) {
    throw new Error("The auth_users table was not found or its schema could not be read");
  }

  for (const [name, type] of Object.entries(requiredColumns)) {
    if (columns.has(name)) continue;
    try {
      await env.DB.prepare(`ALTER TABLE auth_users ADD COLUMN ${name} ${type}`).run();
    } catch (e) {
      // Re-read in case another request added the same column concurrently.
      columns = await getColumns();
      if (!columns.has(name)) throw e;
    }
    columns.add(name);
  }
}

async function ensurePendingArtistSignups(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS pending_artist_signups (
    id TEXT PRIMARY KEY,
    reference TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    artist_name TEXT NOT NULL,
    phone_number TEXT NOT NULL,
    provider TEXT NOT NULL,
    package_code TEXT NOT NULL,
    amount INTEGER NOT NULL,
    currency TEXT NOT NULL DEFAULT 'UGX',
    status TEXT NOT NULL DEFAULT 'pending',
    provider_transaction_id TEXT,
    failure_message TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at TEXT,
    user_id TEXT
  )`).run();
}

async function paidSignupRoute(request, env) {
  await ensurePendingArtistSignups(env);
  if (request.method === "GET") {
    const reference = String(new URL(request.url).searchParams.get("reference") || "").trim();
    if (!/^NILESONIQ-SIGNUP-[A-F0-9-]{20,80}$/i.test(reference)) return error("A valid payment reference is required", 422);
    const row = await env.DB.prepare("SELECT status, failure_message FROM pending_artist_signups WHERE reference = ? LIMIT 1").bind(reference).first();
    if (!row) return error("Payment request not found", 404);
    return json({status: row.status, message: row.status === "completed" ? "Payment confirmed. Your account was created and a verification email was sent if email delivery is available." : row.status === "failed" ? (row.failure_message || "Payment failed.") : "Payment is still pending confirmation."});
  }
  if (request.method !== "POST") return error("Method not allowed", 405);
  const body = await readBody(request);
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  const artistName = String(body.artist_name || body.name || "").trim();
  const packageCode = String(body.package_code || "").trim().toLowerCase();
  const provider = String(body.provider || "").trim().toLowerCase();
  const phone = normalizeUgandanPhone(body.phone_number || body.phoneNumber);
  const prices = {premium:5000,hustler:10000,hit_maker:20000,star:30000};
  const amount = prices[packageCode];
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return error("Please enter a valid email address.", 422);
  if (password.length < 6 || password.length > 128) return error("Password must be between 6 and 128 characters.", 422);
  if (!artistName || artistName.length > 100) return error("Please enter a valid artist name.", 422);
  if (!amount) return error("Choose a valid paid artist package.", 422);
  if (!/^\+256\d{9}$/.test(phone)) return error("Enter a valid Ugandan mobile-money number.", 422);
  if (!["mtn","airtel"].includes(provider)) return error("Provider must be MTN or Airtel.", 422);
  const existing = await env.DB.prepare("SELECT id FROM auth_users WHERE lower(email)=? AND deleted_at IS NULL LIMIT 1").bind(email).first();
  if (existing) return error("An account with that email already exists.", 409);
  const activePending = await env.DB.prepare("SELECT reference FROM pending_artist_signups WHERE lower(email)=? AND status='pending' ORDER BY created_at DESC LIMIT 1").bind(email).first();
  if (activePending) return error(`A payment request is already pending for this email. Reference: ${activePending.reference}. Please do not pay again.`, 409);
  const apiKey = env.PESAJET_API_KEY || env.PESAJET_TOKEN;
  const baseUrl = String(env.PESAJET_API_BASE_URL || "https://payments.pesajet.com/api/v1").replace(/\/+$/, "");
  if (!apiKey) return error("Payment service is not configured.", 503);
  const reference = `NILESONIQ-SIGNUP-${crypto.randomUUID().replace(/-/g, "").toUpperCase()}`;
  const id = crypto.randomUUID();
  const passwordHash = await bcrypt.hash(password, 10);
  await env.DB.prepare(`INSERT INTO pending_artist_signups (id,reference,email,password_hash,artist_name,phone_number,provider,package_code,amount,currency,status) VALUES (?,?,?,?,?,?,?,?,?,'UGX','pending')`)
    .bind(id,reference,email,passwordHash,artistName,phone,provider,packageCode,amount).run();
  let response, result;
  try {
    response = await fetch(`${baseUrl}/payments`, {method:"POST",headers:{"Content-Type":"application/json","X-API-Key":apiKey},body:JSON.stringify({type:"COLLECTION",amount,currency:"UGX",phoneNumber:phone,provider,reference,description:`NileSoniQ ${packageCode} artist signup`,idempotencyKey:`nilesoniq-${reference}`})});
    result = await response.json().catch(()=>({}));
  } catch (e) {
    console.error("Paid signup payment request outcome uncertain:",e.message);
    return error(`Payment request outcome is uncertain. It remains pending; do not pay again. Reference: ${reference}`,502);
  }
  const data = result?.data && typeof result.data === "object" ? result.data : {};
  const tx = result?.transaction && typeof result.transaction === "object" ? result.transaction : (data?.transaction && typeof data.transaction === "object" ? data.transaction : data);
  const statuses = [tx?.status,tx?.transactionStatus,tx?.paymentStatus,data?.status,result?.status].filter(Boolean).map(v=>String(v).toUpperCase().replace(/[\s-]+/g,"_"));
  const providerId = String(tx?.transactionId || tx?.transaction_id || data?.transactionId || result?.transactionId || "");
  const failure = !response.ok || result?.success === false || data?.success === false || result?.error || data?.error || statuses.some(s=>["FAILED","FAILURE","ERROR","EXPIRED","REJECTED","DECLINED","CANCELLED","CANCELED","TIMED_OUT","TIMEOUT"].includes(s));
  if (failure) {
    const reason = String(result?.message || result?.error?.message || data?.message || "Payment provider rejected the request.");
    await env.DB.prepare("UPDATE pending_artist_signups SET status='failed',failure_message=? WHERE reference=? AND status='pending'").bind(reason.slice(0,300),reference).run();
    return error(reason, response.status >= 400 && response.status < 500 ? response.status : 502);
  }
  await env.DB.prepare("UPDATE pending_artist_signups SET provider_transaction_id=? WHERE reference=? AND status='pending'").bind(providerId,reference).run();
  return json({success:true,status:"pending",reference,amount,currency:"UGX",package_code:packageCode,message:`Payment prompt requested for UGX ${amount}. Approve it on your phone. Your account and verification email will be created only after a verified successful payment.`},202);
}

async function completePaidArtistSignup(env, reference, status, transactionId, amount, currency, failureMessage="") {
  await ensurePendingArtistSignups(env);
  const row = await env.DB.prepare("SELECT * FROM pending_artist_signups WHERE reference=? LIMIT 1").bind(reference).first();
  if (!row) return {matched:false};
  if (row.status !== "pending") return {matched:true,changed:false,reason:"already_processed"};
  const incomingTx = String(transactionId || "");
  if (row.provider_transaction_id && incomingTx && row.provider_transaction_id !== incomingTx) return {matched:true,changed:false,reason:"transaction_id_mismatch"};
  if (isSuccessfulPaymentStatus(status)) {
    if (Number(amount) !== Number(row.amount) || String(currency || "").toUpperCase() !== "UGX") {
      console.error("Paid signup payment amount/currency mismatch",{reference,expectedAmount:row.amount,receivedAmount:amount,receivedCurrency:currency});
      return {matched:true,changed:false,reason:"amount_currency_mismatch"};
    }
    // Atomically claim this payment before creating anything. Duplicate/concurrent
    // PesaJet webhooks cannot both create an account for the same reference.
    const claim = await env.DB.prepare("UPDATE pending_artist_signups SET status='processing', provider_transaction_id=COALESCE(NULLIF(?,''),provider_transaction_id) WHERE reference=? AND status='pending'").bind(incomingTx,reference).run();
    if (!claim?.meta || Number(claim.meta.changes || 0) !== 1) {
      return {matched:true,changed:false,reason:"already_processing_or_processed"};
    }
    const existing = await env.DB.prepare("SELECT id FROM auth_users WHERE lower(email)=? AND deleted_at IS NULL LIMIT 1").bind(String(row.email).toLowerCase()).first();
    if (existing) {
      await env.DB.prepare("UPDATE pending_artist_signups SET status='failed',failure_message='An account with this email already exists.' WHERE reference=? AND status='processing'").bind(reference).run();
      return {matched:true,changed:false,reason:"email_already_registered"};
    }
    const userId = crypto.randomUUID();
    const artistId = crypto.randomUUID();
    const metadata = JSON.stringify({artist_name:row.artist_name,package_name:row.package_code});
    const token = crypto.randomUUID()+crypto.randomUUID().replace(/-/g,"");
    const expiry = new Date(Date.now()+30*24*60*60*1000).toISOString();
    const subscriptionId = crypto.randomUUID();
    const subscriptionReference = `NILESONIQ-SIGNUP-SUB-${reference}`;
    // Account, artist, package entitlement record, and payment completion commit together.
    try {
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO auth_users (id,email,encrypted_password,phone,raw_user_meta_data,confirmation_token,confirmation_sent_at,created_at,updated_at,is_anonymous,is_sso_user) VALUES (?,?,?,?,?,?,datetime('now'),datetime('now'),datetime('now'),0,0)`).bind(userId,row.email,row.password_hash,row.phone_number,metadata,token),
        env.DB.prepare("INSERT INTO artists (id,user_id,name) VALUES (?,?,?)").bind(artistId,userId,row.artist_name),
        env.DB.prepare(`INSERT INTO premium_subscriptions (id,user_id,artist_id,amount,currency,provider,phone_number,reference,status,created_at,paid_at,expires_at,provider_transaction_id,package_name) VALUES (?,?,?,?,'UGX',?,?,?,'active',datetime('now'),datetime('now'),?,?,?)`).bind(subscriptionId,userId,artistId,row.amount,row.provider,row.phone_number,subscriptionReference,expiry,incomingTx,row.package_code),
        env.DB.prepare("UPDATE pending_artist_signups SET status='completed',provider_transaction_id=COALESCE(NULLIF(?,''),provider_transaction_id),completed_at=datetime('now'),user_id=? WHERE reference=? AND status='processing'").bind(incomingTx,userId,reference)
      ]);
    } catch (e) {
      // Allow a retry if account/profile creation failed before the batch committed.
      const user = await env.DB.prepare("SELECT id FROM auth_users WHERE lower(email)=? AND deleted_at IS NULL LIMIT 1").bind(String(row.email).toLowerCase()).first().catch(()=>null);
      if (!user) await env.DB.prepare("UPDATE pending_artist_signups SET status='pending' WHERE reference=? AND status='processing'").bind(reference).run().catch(()=>{});
      throw e;
    }
    const verificationUrl = `https://nilesoniq.com/api/auth/verify-email?token=${encodeURIComponent(token)}`;
    try {
      await sendResendEmail(env,{to:row.email,subject:"Verify your NileSoniQ email",text:`Hello ${row.artist_name},\n\nYour payment was confirmed and your NileSoniQ artist account has been created. Verify your email here: ${verificationUrl}\n\nThis link expires in 24 hours.`,html:`<div style="font-family:Arial,sans-serif;line-height:1.6;color:#222"><h2>Payment confirmed — welcome to NileSoniQ</h2><p>Hello ${String(row.artist_name).replace(/[&<>"']/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]))},</p><p>Your payment was confirmed and your artist account has been created. Verify your email address to continue.</p><p><a href="${verificationUrl}" style="display:inline-block;background:#ff7a00;color:#fff;padding:12px 18px;text-decoration:none;border-radius:6px">Verify email address</a></p><p>This link expires in 24 hours.</p></div>`});
    } catch (e) { console.error("Paid signup verification email could not be sent:",e.message); }
    try {
      await syncArtistPremiumEntitlement(env,userId,artistId);
    } catch (e) { console.error("Paid signup subscription was saved, but artist entitlement sync failed:",e.message); }
    return {matched:true,changed:true,reason:"verified_success"};
  }
  if (["FAILED","FAILURE","ERROR","EXPIRED","REJECTED","DECLINED","CANCELLED","CANCELED","TIMED_OUT","TIMEOUT","TIME_OUT","INSUFFICIENT_BALANCE","INSUFFICIENT_FUNDS","AUTHORIZATION_FAILED","LIMIT_EXCEEDED"].includes(String(status||"").toUpperCase())) {
    await env.DB.prepare("UPDATE pending_artist_signups SET status='failed',provider_transaction_id=COALESCE(NULLIF(?,''),provider_transaction_id),failure_message=? WHERE reference=? AND status='pending'").bind(incomingTx,String(failureMessage||status).slice(0,300),reference).run();
  }
  return {matched:true,changed:false,reason:"non_success_status"};
}

async function authRoute(request, env, path) {
  const url = new URL(request.url);

  if ([
    "/api/auth/verify-email",
    "/api/auth/reset-password",
    "/api/auth/forgot-password",
    "/api/auth/register"
  ].includes(path)) {
    try {
      await ensureAuthEmailColumns(env);
    } catch (e) {
      console.error("Auth email schema check failed:", e.message);
      if (request.method === "GET" && path === "/api/auth/verify-email") {
        return authResultPage("Temporarily unavailable", "Email verification is temporarily unavailable. Please try again later.", 503);
      }
      if (request.method === "GET" && path === "/api/auth/reset-password") {
        return authResultPage("Temporarily unavailable", "Password reset is temporarily unavailable. Please try again later.", 503);
      }
      return error("Email verification and password reset are temporarily unavailable. Please try again later.", 503);
    }
  }

  if (request.method === "GET" && path === "/api/auth/verify-email") {
    const token = String(url.searchParams.get("token") || "").trim();
    if (!token || token.length > 200) return authResultPage("Invalid verification link", "This email verification link is invalid or incomplete.", 400);
    try {
      const user = await env.DB.prepare(`
        SELECT id, email_confirmed_at, confirmation_sent_at
        FROM auth_users WHERE confirmation_token = ? LIMIT 1
      `).bind(token).first();
      if (!user) return authResultPage("Link expired or already used", "Please sign in, or create a new verification request if your account still needs verification.", 400);
      if (user.confirmation_sent_at && Date.now() - new Date(user.confirmation_sent_at).getTime() > 24 * 60 * 60 * 1000) {
        return authResultPage("Link expired", "This verification link has expired. Please request a new one.", 400);
      }
      await env.DB.prepare(`UPDATE auth_users SET email_confirmed_at = COALESCE(email_confirmed_at, datetime('now')), confirmation_token = NULL, updated_at = datetime('now') WHERE id = ?`).bind(user.id).run();
      return authResultPage("Email verified", "Your NileSoniQ email address has been verified. You can now return to the website and sign in.");
    } catch (e) {
      console.error("Email verification failed:", e.message);
      return authResultPage("Could not verify email", "Please try again later or contact NileSoniQ support.", 500);
    }
  }

  if (request.method === "GET" && path === "/api/auth/reset-password") {
    const token = String(url.searchParams.get("token") || "").trim();
    if (!token || token.length > 200) return authResultPage("Invalid reset link", "This password reset link is invalid or incomplete.", 400);
    const safeToken = token.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Reset password - NileSoniQ</title><body style="font-family:system-ui,sans-serif;max-width:480px;margin:8vh auto;padding:24px;color:#222"><h1>Reset your password</h1><p>Choose a new password with at least 6 characters.</p><form id="resetForm"><label for="password">New password</label><br><input id="password" type="password" minlength="6" maxlength="128" required autocomplete="new-password" style="box-sizing:border-box;width:100%;padding:12px;margin:8px 0 16px"><button style="background:#ff7a00;color:white;border:0;padding:12px 18px;border-radius:6px" type="submit">Save new password</button></form><p id="message" role="status"></p><script>const token=${JSON.stringify(token)};document.getElementById('resetForm').addEventListener('submit',async e=>{e.preventDefault();const message=document.getElementById('message');const password=document.getElementById('password').value;message.textContent='Saving…';try{const r=await fetch('/api/auth/reset-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,password})});const data=await r.json().catch(()=>({}));message.textContent=r.ok?(data.message||'Password updated. You can sign in now.'):(data.error||'Could not reset password. Request a new link.');if(r.ok)document.getElementById('resetForm').remove();}catch{message.textContent='Network error. Please try again.';}});</script></body></html>`;
    return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
  }

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

  if (path === "/api/auth/forgot-password") {
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return error("Please enter a valid email address.", 422);
    }
    try {
      const user = await env.DB.prepare(`SELECT id, email FROM auth_users WHERE lower(email) = ? AND deleted_at IS NULL LIMIT 1`).bind(email).first();
      // Always use the same public response to avoid revealing whether an email is registered.
      if (user) {
        const recoveryToken = crypto.randomUUID() + crypto.randomUUID().replace(/-/g, "");
        await env.DB.prepare(`UPDATE auth_users SET recovery_token = ?, recovery_sent_at = datetime('now'), updated_at = datetime('now') WHERE id = ?`).bind(recoveryToken, user.id).run();
        const resetUrl = `https://nilesoniq.com/api/auth/reset-password?token=${encodeURIComponent(recoveryToken)}`;
        try {
          await sendResendEmail(env, {
            to: user.email,
            subject: "Reset your NileSoniQ password",
            text: `We received a request to reset your NileSoniQ password. Open this link within one hour: ${resetUrl}\n\nIf you did not request this, ignore this email.`,
            html: `<div style="font-family:Arial,sans-serif;line-height:1.6;color:#222"><h2>Password reset</h2><p>We received a request to reset your NileSoniQ password.</p><p><a href="${resetUrl}" style="display:inline-block;background:#ff7a00;color:#fff;padding:12px 18px;text-decoration:none;border-radius:6px">Reset password</a></p><p>This link expires in one hour. If you did not request this, ignore this email.</p></div>`
          });
        } catch (mailError) {
          console.error("Password reset email could not be sent:", mailError.message);
        }
      }
      return json({ success: true, message: "If an account matches that email, a password reset link will be sent." });
    } catch (e) {
      console.error("Password reset request failed:", e.message);
      return error("Could not process the password reset request. Please try again later.", 500);
    }
  }

  if (path === "/api/auth/reset-password") {
    const recoveryToken = String(body.token || "").trim();
    if (!recoveryToken || recoveryToken.length > 200) return error("A valid password reset token is required.", 422);
    if (password.length < 6 || password.length > 128) return error("Password must be between 6 and 128 characters.", 422);
    try {
      const user = await env.DB.prepare(`SELECT id, recovery_sent_at FROM auth_users WHERE recovery_token = ? LIMIT 1`).bind(recoveryToken).first();
      if (!user) return error("This password reset link is invalid or has already been used.", 400);
      if (!user.recovery_sent_at || Date.now() - new Date(user.recovery_sent_at).getTime() > 60 * 60 * 1000) {
        return error("This password reset link has expired. Please request another one.", 400);
      }
      const passwordHash = await bcrypt.hash(password, 10);
      await env.DB.batch([
        env.DB.prepare(`UPDATE auth_users SET encrypted_password = ?, recovery_token = NULL, recovery_sent_at = NULL, updated_at = datetime('now') WHERE id = ?`).bind(passwordHash, user.id),
        env.DB.prepare(`DELETE FROM auth_sessions WHERE user_id = ?`).bind(user.id)
      ]);
      return json({ success: true, message: "Password reset successfully. Please sign in with your new password." });
    } catch (e) {
      console.error("Password reset failed:", e.message);
      return error("Could not reset the password. Please try again later.", 500);
    }
  }

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

      // Send an email-verification link when Resend is configured. Registration
      // and existing login/session behavior are preserved for compatibility.
      const verificationToken = crypto.randomUUID() + crypto.randomUUID().replace(/-/g, "");
      await env.DB.prepare(`
        UPDATE auth_users
        SET confirmation_token = ?, confirmation_sent_at = datetime('now'), updated_at = datetime('now')
        WHERE id = ?
      `).bind(verificationToken, id).run();

      let verificationEmailSent = false;
      try {
        const verificationUrl = `https://nilesoniq.com/api/auth/verify-email?token=${encodeURIComponent(verificationToken)}`;
        await sendResendEmail(env, {
          to: email,
          subject: "Verify your NileSoniQ email",
          text: `Hello ${displayName},\n\nPlease verify your email address by opening this link: ${verificationUrl}\n\nThis link expires in 24 hours. If you did not create a NileSoniQ account, you can ignore this email.`,
          html: `<div style="font-family:Arial,sans-serif;line-height:1.6;color:#222"><h2>Welcome to NileSoniQ</h2><p>Hello ${String(displayName).replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]))},</p><p>Please confirm your email address to help secure your account.</p><p><a href="${verificationUrl}" style="display:inline-block;background:#ff7a00;color:#fff;padding:12px 18px;text-decoration:none;border-radius:6px">Verify email address</a></p><p>This link expires in 24 hours. If you did not create this account, you can ignore this email.</p></div>`
        });
        verificationEmailSent = true;
      } catch (mailError) {
        // Keep account creation available if email delivery is temporarily down.
        console.error("Verification email could not be sent:", mailError.message);
      }

      const token = await createSession(env, id);

      return json({
        success: true,
        verification_email_sent: verificationEmailSent,
        message: verificationEmailSent
          ? "Account created. Check your email for a verification link."
          : "Account created, but the verification email could not be sent yet.",
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

          // Refresh the artist's server-side entitlement from provider-confirmed,
          // unexpired subscriptions. A database failure must stop the upload; it
          // must never silently downgrade a paid artist to Free.
          let entitlement;
          try {
            entitlement = await syncArtistPremiumEntitlement(env, user.id);
          } catch (entitlementError) {
            console.error("Could not verify artist package before upload:", entitlementError.message);
            return error("We could not verify your artist package right now. No song was uploaded. Please try again shortly.", 503);
          }
          const packageCode = String(entitlement?.packageCode || 'free').toLowerCase();
          const uploadLimit = ARTIST_PACKAGE_UPLOAD_LIMITS[packageCode] ?? ARTIST_PACKAGE_UPLOAD_LIMITS.free;

          // Only approved songs count toward the monthly package limit.
          // Pending and rejected submissions do not consume an allowance.
          // The insert and count remain one SQL statement to handle simultaneous
          // uploads safely. In the rollout month, pre-cutoff songs are
          // grandfathered; later months count from the calendar-month start.
          const insertResult = await env.DB.prepare(`
            INSERT INTO songs (${insertKeys.join(",")})
            SELECT ${insertKeys.map(() => "?").join(",")}
            WHERE (
              SELECT COUNT(*) FROM songs
              WHERE artist_id = ?
                AND approved = 1
                AND datetime(created_at) >= CASE
                  WHEN datetime('now', 'start of month') > datetime(?)
                    THEN datetime('now', 'start of month')
                  ELSE datetime(?)
                END
                AND datetime(created_at) < datetime('now', 'start of month', '+1 month')
            ) < ?
          `).bind(
            ...insertKeys.map(k => safeRow[k] ?? null),
            user.id,
            PACKAGE_LIMITS_EFFECTIVE_AT,
            PACKAGE_LIMITS_EFFECTIVE_AT,
            uploadLimit
          ).run();

          if (Number(insertResult?.meta?.changes || 0) === 0) {
            const limitLabel = uploadLimit >= Number.MAX_SAFE_INTEGER ? 'unlimited' : String(uploadLimit);
            return error(
              `Monthly song upload limit reached for your ${packageCode} package (${limitLabel} songs per month). Upgrade or try again next month.`,
              429
            );
          }

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
                + COALESCE((
                  SELECT SUM(net_amount - ?)
                  FROM artist_earning_ledger
                  WHERE artist_id = ?
                    AND source_type = 'qualified_play'
                    AND status = 'posted'
                ), 0)
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
              ARTIST_FREE_NET_PER_PLAY,
              ARTIST_FREE_NET_PER_PLAY,
              user.id,
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

      let withdrawalRows = [];
      if (table === "withdrawal_requests" && Object.prototype.hasOwnProperty.call(body, "status")) {
        const prior = await env.DB.prepare(`SELECT id, artist_id, amount, status FROM withdrawal_requests${where}`).bind(...values).all();
        withdrawalRows = prior.results || [];
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

      if (table === "withdrawal_requests" && withdrawalRows.length && Object.prototype.hasOwnProperty.call(body, "status")) {
        try {
          await ensureArtistNotificationsTable(env);
          const newStatus = String(body.status || "updated").toLowerCase();
          for (const item of withdrawalRows) {
            const amount = Math.floor(Number(item.amount) || 0).toLocaleString("en-US");
            const message = newStatus === "paid" || newStatus === "completed"
              ? `Your withdrawal of UGX ${amount} has been marked as paid by the NileSoniq admin.`
              : newStatus === "rejected"
                ? `Your withdrawal request for UGX ${amount} was rejected by the NileSoniq admin.`
                : `Your withdrawal request for UGX ${amount} is now ${newStatus}.`;
            await env.DB.prepare(`INSERT INTO artist_notifications (id, artist_id, notification_type, message, related_id, created_at) VALUES (?, ?, 'withdrawal', ?, ?, ?)`)
              .bind(crypto.randomUUID(), item.artist_id, message, item.id, new Date().toISOString()).run();
          }
        } catch (notificationError) {
          console.error("Withdrawal notification could not be saved:", notificationError.message);
        }
      }

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

  if (request.method === "GET" && path === "/api/admin/analytics") {
    if (!superAdmin) return error("Super Admin access required", 403);
    try {
      const [songResult, artistResult] = await Promise.all([
        env.DB.prepare(`
          SELECT id, title, artist, artist_id, plays, likes, approved, review_status, created_at
          FROM songs
          ORDER BY rowid DESC
          LIMIT 5000
        `).all(),
        env.DB.prepare(`
          SELECT id, user_id, name
          FROM artists
          ORDER BY created_at DESC
          LIMIT 5000
        `).all()
      ]);
      const songs = songResult.results || [];
      const artists = artistResult.results || [];
      const approved = songs.filter(song => {
        const status = String(song.review_status || "").toLowerCase();
        return status === "approved" || (!status && Number(song.approved) === 1);
      });
      const pending = songs.filter(song => {
        const status = String(song.review_status || "").toLowerCase();
        return status === "pending" || (!status && Number(song.approved) !== 1);
      });
      const totalPlays = songs.reduce((sum, song) => sum + Math.max(0, Number(song.plays || 0)), 0);
      const totalLikes = songs.reduce((sum, song) => sum + Math.max(0, Number(song.likes || 0)), 0);
      const artistNames = new Map();
      for (const artist of artists) {
        if (artist.id) artistNames.set(String(artist.id), artist.name || "Unknown Artist");
        if (artist.user_id) artistNames.set(String(artist.user_id), artist.name || "Unknown Artist");
      }
      const artistStats = new Map();
      for (const song of songs) {
        const key = String(song.artist_id || song.artist || "unknown");
        if (!artistStats.has(key)) {
          artistStats.set(key, { name: artistNames.get(key) || song.artist || "Unknown Artist", songs: 0, plays: 0 });
        }
        const stat = artistStats.get(key);
        stat.songs += 1;
        stat.plays += Math.max(0, Number(song.plays || 0));
      }
      return json({
        data: {
          totalSongs: songs.length,
          approvedSongs: approved.length,
          pendingSongs: pending.length,
          totalArtists: artists.length,
          totalPlays,
          totalLikes,
          topSongs: [...songs].sort((a, b) => Number(b.plays || 0) - Number(a.plays || 0)).slice(0, 10),
          topArtists: [...artistStats.values()].sort((a, b) => b.plays - a.plays).slice(0, 10)
        },
        error: null
      });
    } catch (e) {
      console.error("Admin analytics load failed:", e.message);
      return error("Could not load admin analytics", 500);
    }
  }

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

  if (request.method === "GET" && path === "/api/admin/copyright-removal-artists") {
    if (!superAdmin) return error("Super Admin access required", 403);
    try {
      const result = await env.DB.prepare(`
        SELECT id, user_id, name
        FROM artists
        ORDER BY name COLLATE NOCASE ASC
        LIMIT 2000
      `).all();
      return json({ data: result.results || [], error: null });
    } catch (e) {
      console.error("Copyright artist list failed:", e.message);
      return error("Could not load artists for copyright removal", 500);
    }
  }

  if (request.method === "GET" && path === "/api/admin/copyright-removal-songs") {
    if (!superAdmin) return error("Super Admin access required", 403);
    const artistId = String(url.searchParams.get("artist_id") || "").trim();
    if (!artistId) return error("Choose an artist first", 422);
    try {
      const artist = await env.DB.prepare(`
        SELECT id, user_id, name
        FROM artists
        WHERE id = ? OR user_id = ?
        LIMIT 1
      `).bind(artistId, artistId).first();
      if (!artist) return error("Artist not found", 404);

      const ownerId = String(artist.user_id || "");
      const profileId = String(artist.id || "");
      const artistName = String(artist.name || "");
      const result = await env.DB.prepare(`
        SELECT id, title, artist, artist_id, approved, review_status, created_at
        FROM songs
        WHERE artist_id = ?
           OR artist_id = ?
           OR LOWER(TRIM(COALESCE(artist, ''))) = LOWER(TRIM(?))
        ORDER BY rowid DESC
        LIMIT 1000
      `).bind(ownerId || profileId, profileId || ownerId, artistName).all();
      return json({ data: result.results || [], error: null });
    } catch (e) {
      console.error("Copyright artist songs failed:", e.message);
      return error("Could not load songs for this artist", 500);
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
        "SELECT id, artist_id, approved FROM songs WHERE id = ? LIMIT 1"
      ).bind(songId).first();

      if (!song) {
        return error("Song not found", 404);
      }

      // Approval is the moment a song starts consuming the artist's monthly
      // allowance. Pending and rejected songs do not count. Keep this check
      // inside the UPDATE statement so two simultaneous approvals cannot
      // both exceed the artist's package limit.
      let uploadLimit = null;
      if (status === "approved" && Number(song.approved) !== 1) {
        let entitlement;
        try {
          entitlement = await syncArtistPremiumEntitlement(env, song.artist_id);
        } catch (entitlementError) {
          console.error("Could not verify artist package before approval:", entitlementError.message);
          return error("Could not verify the artist's package. The song was not approved. Please try again.", 503);
        }

        const packageCode = String(entitlement?.packageCode || "free").toLowerCase();
        uploadLimit = ARTIST_PACKAGE_UPLOAD_LIMITS[packageCode] ?? ARTIST_PACKAGE_UPLOAD_LIMITS.free;

        const updateResult = await env.DB.prepare(`
          UPDATE songs
          SET approved = 1, review_status = 'approved'
          WHERE id = ?
            AND (
              SELECT COUNT(*)
              FROM songs AS counted
              WHERE counted.artist_id = songs.artist_id
                AND counted.approved = 1
                AND counted.id != songs.id
                AND datetime(counted.created_at) >= CASE
                  WHEN datetime('now', 'start of month') > datetime(?)
                    THEN datetime('now', 'start of month')
                  ELSE datetime(?)
                END
                AND datetime(counted.created_at) < datetime('now', 'start of month', '+1 month')
            ) < ?
        `).bind(
          songId,
          PACKAGE_LIMITS_EFFECTIVE_AT,
          PACKAGE_LIMITS_EFFECTIVE_AT,
          uploadLimit
        ).run();

        if (Number(updateResult?.meta?.changes || 0) === 0) {
          const limitLabel = uploadLimit >= Number.MAX_SAFE_INTEGER ? "unlimited" : String(uploadLimit);
          return error(
            `This song cannot be approved because the artist has reached the ${packageCode.replace(/_/g, " ")} package limit (${limitLabel} approved songs this month). Pending and rejected songs do not count.`,
            429
          );
        }
      } else {
        await env.DB.prepare(`
          UPDATE songs
          SET approved = ?, review_status = ?
          WHERE id = ?
        `).bind(
          status === "approved" ? 1 : 0,
          status,
          songId
        ).run();
      }

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
    if (name === "get_artist_earnings_adjustment") {
      if (!user) {
        return error("Authentication required", 401);
      }
      const result = await env.DB.prepare(`
        SELECT COALESCE(SUM(net_amount - ?), 0) AS adjustment
        FROM artist_earning_ledger
        WHERE artist_id = ?
          AND source_type = 'qualified_play'
          AND status = 'posted'
      `).bind(ARTIST_FREE_NET_PER_PLAY, user.id).first();
      return json({ data: Number(result?.adjustment || 0), error: null });
    }

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

    if (name === "get_platform_financial_summary") {
      if (!admin || admin.role !== "super_admin") {
        return error("Super Admin access required", 403);
      }

      const platform = await env.DB.prepare(`
        SELECT
          COALESCE(SUM(CASE WHEN event_type = 'income' THEN amount_signed ELSE 0 END), 0) AS income_total,
          COALESCE(SUM(CASE WHEN event_type = 'payout' THEN -amount_signed ELSE 0 END), 0) AS payout_total,
          COALESCE(SUM(CASE WHEN status = 'posted' THEN pesajet_fee_amount ELSE 0 END), 0) AS verified_fees,
          COALESCE(SUM(CASE WHEN status = 'fee_unverified' THEN 1 ELSE 0 END), 0) AS fee_unverified_count
        FROM platform_financial_ledger
        WHERE currency = 'UGX'
      `).first();

      const artists = await env.DB.prepare(`
        SELECT
          COALESCE(SUM(gross_amount), 0) AS artist_gross,
          COALESCE(SUM(commission_amount), 0) AS artist_commission,
          COALESCE(SUM(tax_amount), 0) AS artist_tax_allocation,
          COALESCE(SUM(net_amount), 0) AS artist_net
        FROM artist_earning_ledger
        WHERE currency = 'UGX' AND status = 'posted'
      `).first();

      return json({
        data: {
          income_total: Number(platform?.income_total || 0),
          payout_total: Number(platform?.payout_total || 0),
          verified_fees: Number(platform?.verified_fees || 0),
          fee_unverified_count: Number(platform?.fee_unverified_count || 0),
          artist_gross: Number(artists?.artist_gross || 0),
          artist_commission: Number(artists?.artist_commission || 0),
          artist_tax_allocation: Number(artists?.artist_tax_allocation || 0),
          artist_net: Number(artists?.artist_net || 0)
        },
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
              AND datetime(played_at) >= datetime('now', '-24 hours')
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

      // Keep a per-qualified-play artist earnings audit trail. The unique event
      // key makes retries safe. The package rate is read from the latest active,
      // unexpired subscription, so an expired package automatically falls back
      // to Free for new plays. Existing historical plays are not rewritten.
      if (inserted && incremented) {
        const playLogId = Number(results?.[0]?.meta?.last_row_id || 0);
        if (playLogId > 0) {
          const song = await env.DB.prepare(
            "SELECT artist_id FROM songs WHERE id = ? AND approved = 1 LIMIT 1"
          ).bind(id).first();
          const artistId = String(song?.artist_id || "").trim();
          if (artistId) {
            const activePackage = await env.DB.prepare(`
              SELECT package_name
              FROM premium_subscriptions
              WHERE user_id = ?
                AND lower(status) = 'active'
                AND expires_at IS NOT NULL
                AND datetime(expires_at) > datetime('now')
              ORDER BY datetime(COALESCE(paid_at, created_at)) DESC,
                       datetime(created_at) DESC,
                       datetime(expires_at) DESC
              LIMIT 1
            `).bind(artistId).first();
            const packageCode = String(activePackage?.package_name || 'free')
              .trim().toLowerCase().replace(/[ -]+/g, '_');
            const earningRates = { free: 0.5, premium: 1, hustler: 1, hit_maker: 2, star: 3 };
            const gross = earningRates[packageCode] ?? EARNINGS_PER_PLAY;
            // Keep mill-UGX precision so Free net earnings remain 0.375 rather
            // than rounding each play down to 0.37 before the balance is summed.
            const commission = Math.round(gross * ARTIST_COMMISSION_RATE * 1000) / 1000;
            const tax = Math.round(gross * ARTIST_TAX_ALLOCATION_RATE * 1000) / 1000;
            const net = Math.round((gross - commission - tax) * 1000) / 1000;
            await env.DB.prepare(`
              INSERT OR IGNORE INTO artist_earning_ledger
                (event_key, artist_id, source_type, source_id, gross_amount,
                 commission_amount, tax_amount, pesajet_fee_amount, net_amount,
                 currency, status, note, occurred_at)
              VALUES (?, ?, 'qualified_play', ?, ?, ?, ?, 0, ?, 'UGX',
                      'posted', 'Package-rate gross per qualified play; 20% commission and 5% tax allocation',
                      datetime('now'))
            `).bind(
              `song-play:${playLogId}`,
              artistId,
              String(playLogId),
              gross,
              commission,
              tax,
              net
            ).run();
          }
        }
      }

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

async function uploadPreflightRoute(request, env) {
  if (request.method !== "POST") return error("Method not allowed", 405);
  const user = await currentUser(request, env);
  if (!user) return error("Authentication required", 401);
  const body = await readBody(request);
  const audioSize = Number(body.audio_size || 0);
  const coverSize = Number(body.cover_size || 0);
  if (!Number.isSafeInteger(audioSize) || audioSize <= 0 || audioSize > 50 * 1024 * 1024) return error("Audio file must be between 1 byte and 50 MB.", 413);
  if (!Number.isSafeInteger(coverSize) || coverSize <= 0 || coverSize > 5 * 1024 * 1024) return error("Cover image must be between 1 byte and 5 MB.", 413);

  try {
    const artist = await env.DB.prepare("SELECT id FROM artists WHERE user_id = ? LIMIT 1").bind(user.id).first();
    if (!artist) return error("Artist profile not found.", 403);

    // Use the same verified subscription source as the actual song insert and
    // keep the artist package/rate fields synchronized with that entitlement.
    const entitlement = await syncArtistPremiumEntitlement(env, user.id, artist.id);
    const packageCode = String(entitlement?.packageCode || "free").toLowerCase();
    const limit = ARTIST_PACKAGE_UPLOAD_LIMITS[packageCode] ?? ARTIST_PACKAGE_UPLOAD_LIMITS.free;
    const count = await env.DB.prepare(`
      SELECT COUNT(*) AS total
      FROM songs
      WHERE artist_id = ?
        AND approved = 1
        AND datetime(created_at) >= CASE
          WHEN datetime('now', 'start of month') > datetime(?)
            THEN datetime('now', 'start of month')
          ELSE datetime(?)
        END
        AND datetime(created_at) < datetime('now', 'start of month', '+1 month')
    `).bind(user.id, PACKAGE_LIMITS_EFFECTIVE_AT, PACKAGE_LIMITS_EFFECTIVE_AT).first();
    if (!count || count.total === undefined || count.total === null) {
      return error("We could not verify your monthly upload count. No files were uploaded. Please try again shortly.", 503);
    }
    const used = Number(count.total);
    if (!Number.isFinite(used)) return error("We could not verify your monthly upload count. No files were uploaded. Please try again shortly.", 503);
    if (used >= limit) {
      const label = limit >= Number.MAX_SAFE_INTEGER ? "unlimited" : String(limit);
      return error(`Your ${packageCode.replace(/_/g, " ")} package upload limit has been reached (${used}/${label} songs this month). No files were uploaded.`, 429);
    }
    return json({
      allowed: true,
      package_code: packageCode,
      used,
      limit: limit >= Number.MAX_SAFE_INTEGER ? null : limit,
      remaining: limit >= Number.MAX_SAFE_INTEGER ? null : limit - used
    });
  } catch (e) {
    console.error("Artist upload preflight failed:", e.message);
    return error("We could not verify your package or upload count. No files were uploaded. Please try again shortly.", 503);
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

    const contentLength = Number(request.headers.get("Content-Length") || 0);
    const maxBytes = bucket === "audio" ? 50*1024*1024 : bucket === "covers" ? 5*1024*1024 : 5*1024*1024;
    if (contentLength > maxBytes) return error(`${bucket === "audio" ? "Audio" : "Image"} file exceeds the ${Math.floor(maxBytes/1024/1024)} MB limit.`,413);
    const bytes = await request.arrayBuffer();
    if (!bytes.byteLength || bytes.byteLength > maxBytes) return error(`${bucket === "audio" ? "Audio" : "Image"} file must be between 1 byte and ${Math.floor(maxBytes/1024/1024)} MB.`,413);

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
  transactionId = "",
  confirmedFee = null
) {
  const normalized = String(status || "").toUpperCase();
  const feeNumber = confirmedFee === null || confirmedFee === undefined || confirmedFee === ""
    ? null
    : Number(confirmedFee);
  const feeKnown = feeNumber !== null && Number.isFinite(feeNumber) && feeNumber >= 0;
  const feeValue = feeKnown ? feeNumber : 0;
  const ledgerStatus = feeKnown ? "posted" : "fee_unverified";

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
        SET balance = MAX(0, balance + (
          SELECT amount - ? FROM platform_deposits WHERE reference = ?
        )),
        updated_at = datetime('now')
        WHERE id = (SELECT id FROM platform_wallet ORDER BY created_at LIMIT 1)
          AND changes() > 0
          AND ? IN ('COMPLETED', 'SUCCESS', 'SUCCESSFUL', 'PAID')
      `).bind(feeValue, reference, normalized),
      env.DB.prepare(`
        INSERT OR IGNORE INTO platform_financial_ledger
          (event_key, event_type, source_type, source_id, reference,
           amount_signed, currency, pesajet_fee_amount, tax_liability_amount,
           status, note, occurred_at)
        SELECT
          'platform-collection:' || id,
          'income',
          'platform_deposit',
          id,
          reference,
          amount,
          COALESCE(currency, 'UGX'),
          ?,
          0,
          ?,
          ?,
          COALESCE(created_at, datetime('now'))
        FROM platform_deposits
        WHERE reference = ?
          AND lower(status) IN ('completed', 'success', 'successful', 'paid')
          AND ? IN ('COMPLETED', 'SUCCESS', 'SUCCESSFUL', 'PAID')
      `).bind(
        feeValue,
        ledgerStatus,
        feeKnown
          ? "Successful collection. Actual PesaJet fee supplied by the confirmed provider event."
          : "Successful collection. Actual PesaJet collection fee was not supplied by the confirmed transaction event; zero here does not mean fee-free.",
        reference,
        normalized
      )
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
      ) - ?),
      updated_at = datetime('now')
      WHERE id = (SELECT id FROM platform_wallet ORDER BY created_at LIMIT 1)
        AND changes() > 0
        AND ? IN ('COMPLETED', 'SUCCESS', 'SUCCESSFUL', 'PAID')
    `).bind(reference, feeKnown ? feeValue : 0, normalized),
    env.DB.prepare(`
      INSERT OR IGNORE INTO platform_financial_ledger
        (event_key, event_type, source_type, source_id, reference,
         amount_signed, currency, pesajet_fee_amount, tax_liability_amount,
         status, note, occurred_at)
      SELECT
        'platform-payout:' || id,
        'payout',
        'platform_payout',
        id,
        reference,
        -amount,
        COALESCE(currency, 'UGX'),
        ?,
        0,
        ?,
        ?,
        COALESCE(completed_at, created_at, datetime('now'))
      FROM platform_payouts
      WHERE reference = ?
        AND lower(status) IN ('completed', 'success', 'successful', 'paid')
        AND ? IN ('COMPLETED', 'SUCCESS', 'SUCCESSFUL', 'PAID')
    `).bind(
      feeValue,
      ledgerStatus,
      feeKnown
        ? "Completed payout amount recorded with the actual PesaJet fee supplied by the confirmed provider event."
        : "Completed payout amount recorded. Actual PesaJet payout fee was not supplied by the confirmed transaction event; zero here does not mean fee-free.",
      reference,
      normalized
    )
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

  // Package entitlement is derived only from provider-confirmed, unexpired rows.
  const latest = await env.DB.prepare(`
    SELECT package_name, expires_at,
           CASE WHEN datetime(expires_at) > datetime('now') THEN 1 ELSE 0 END AS currently_active
    FROM premium_subscriptions
    WHERE user_id = ? AND lower(status) = 'active' AND expires_at IS NOT NULL
      AND datetime(expires_at) > datetime('now')
    ORDER BY datetime(COALESCE(paid_at, created_at)) DESC, datetime(created_at) DESC, datetime(expires_at) DESC LIMIT 1
  `).bind(uid).first();

  const expiresAt = latest?.expires_at || null;
  const packageCode = String(latest?.package_name || 'free').toLowerCase();
  const isPremium = !!latest && packageCode !== 'free';
  const rates = { free: 0.5, premium: 1, hustler: 1, hit_maker: 2, star: 3 };
  const rate = rates[packageCode] ?? 0.5;
  await env.DB.prepare(`
    UPDATE artists
    SET is_premium = ?, premium_expiry_date = ?, package_name = ?,
        package_expiry_date = ?, earnings_rate = ?
    WHERE id = ? AND user_id = ?
  `).bind(isPremium ? 1 : 0, expiresAt, packageCode, expiresAt, rate, artist.id, uid).run();

  return { artistFound: true, artistId: artist.id, isPremium, expiresAt, packageCode, rate };
}

async function premiumSubscriptionRoute(request, env) {
  const user = await currentUser(request, env);
  if (!user) return error("Authentication required", 401);

  if (request.method === "GET") {
    const entitlement = await syncArtistPremiumEntitlement(env, user.id);
    const requestedReference = new URL(request.url).searchParams.get("reference");
    if (requestedReference) {
      const payment = await env.DB.prepare(`
        SELECT status, reference, expires_at, failure_message, package_name
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
        premiumExpiryDate: entitlement.expiresAt,
        packageCode: payment.package_name || entitlement.packageCode || 'free'
      });
    }

    const row = await env.DB.prepare(`
      SELECT status, expires_at, package_name FROM premium_subscriptions
      WHERE user_id = ? AND lower(status) = 'active' AND expires_at IS NOT NULL
        AND datetime(expires_at) > datetime('now')
      ORDER BY datetime(COALESCE(paid_at, created_at)) DESC, datetime(created_at) DESC, datetime(expires_at) DESC LIMIT 1
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
      premiumExpiryDate: entitlement.expiresAt,
      packageCode: active ? (row.package_name || entitlement.packageCode || 'free') : 'free'
    });
  }

  if (request.method !== "POST") return error("Method not allowed", 405);
  const artist = await env.DB.prepare(
    "SELECT id FROM artists WHERE user_id = ? LIMIT 1"
  ).bind(user.id).first();
  if (!artist) return error("NileSoniQ Premium is available to artist accounts only", 403);

  const body = await readBody(request);
  const packageCode = String(body.package_code || body.packageCode || 'premium').trim().toLowerCase();
  const packagePrices = { premium: 5000, hustler: 10000, hit_maker: 20000, star: 30000 };
  const packageAmount = packagePrices[packageCode];
  if (!packageAmount) return error("Choose a valid paid artist package", 422);
  const phone = normalizeUgandanPhone(body.phone_number || body.phoneNumber);
  const provider = String(body.provider || "").trim().toLowerCase();
  if (!/^\+256\d{9}$/.test(phone)) return error("Enter a valid Ugandan mobile-money number", 422);
  if (!["mtn", "airtel"].includes(provider)) return error("Provider must be MTN or Airtel", 422);
  const apiKey = env.PESAJET_API_KEY || env.PESAJET_TOKEN;
  const baseUrl = String(env.PESAJET_API_BASE_URL || "https://payments.pesajet.com/api/v1").replace(/\/+$/, "");
  if (!apiKey) return error("Payment service is not configured", 503);

  // MTN and Airtel continue through the same PesaJet /payments endpoint and webhook.
  // Use a shorter unique reference for Airtel to reduce possible downstream
  // reference truncation/collision. Keep MTN's existing reference format unchanged.
  const reference = provider === "airtel"
    ? `NSPA${Date.now().toString(36).toUpperCase()}${crypto.randomUUID().replace(/-/g, "").slice(0, 8).toUpperCase()}`
    : `NILESONIQ-PREMIUM-${crypto.randomUUID()}`;
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await env.DB.prepare(`
    INSERT INTO premium_subscriptions
      (id,user_id,artist_id,amount,currency,provider,phone_number,reference,status,created_at,package_name)
    VALUES (?,?,?,?,'UGX',?,?,?,'pending',?,?)
  `).bind(id,user.id,artist.id,packageAmount,provider,phone,reference,now,packageCode).run();

  let response, result;
  try {
    response = await fetch(`${baseUrl}/payments`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
      body: JSON.stringify({ type: "COLLECTION", amount: packageAmount, currency: "UGX", phoneNumber: phone, provider, reference, description: `NileSoniQ ${packageCode} package - 30 days`, idempotencyKey: `nilesoniq-${reference}` })
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
    message: `Your UGX ${packageAmount.toLocaleString('en-US')} ${packageCode.replace('_',' ')} payment request was accepted. Approve the mobile-money prompt on your phone; activation waits for provider confirmation.`
  });
}

async function applyPremiumPaymentStatus(
  env,
  reference,
  status,
  transactionId = "",
  confirmedAmount = null,
  confirmedCurrency = "",
  failureMessage = "",
  confirmedFee = null
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

    // PesaJet receipts can show the customer total (package price + collection
    // fee), while the subscription stores only the package price. Prefer the
    // fee in the signed webhook. If PesaJet omits the fee field, accept only the
    // exact 2.5% total pattern confirmed by the reported UGX 5,000 + UGX 125
    // receipt. Do not accept arbitrary overpayments or infer a fee for any
    // other amount pattern.
    const suppliedFeeValue = confirmedFee === null || confirmedFee === undefined || confirmedFee === ""
      ? null
      : Number(confirmedFee);
    const suppliedFeeKnown = suppliedFeeValue !== null && Number.isFinite(suppliedFeeValue) && suppliedFeeValue >= 0;
    const amountMatchesPackage = Number.isFinite(amount) && amount === expectedAmount;
    const inferredFeeValue = Number.isFinite(amount) && Number.isFinite(expectedAmount) && amount > expectedAmount
      ? amount - expectedAmount
      : null;
    const feeMatchesObservedPattern = inferredFeeValue !== null &&
      inferredFeeValue === Math.round(expectedAmount * 0.025) &&
      amount === expectedAmount + Math.round(expectedAmount * 0.025);
    // Some PesaJet events may report fee=0 even when the customer-paid total
    // includes the collection fee. If the total exactly matches the known
    // 2.5% fee pattern, trust that narrowly defined total rather than a zero
    // fee field. Never infer a fee for any other amount pattern.
    const suppliedFeeMatchesTotal = suppliedFeeKnown && suppliedFeeValue > 0 &&
      Number.isFinite(amount) && amount === expectedAmount + suppliedFeeValue;
    const useInferredFee = feeMatchesObservedPattern && !suppliedFeeMatchesTotal &&
      (!suppliedFeeKnown || suppliedFeeValue === 0 || !Number.isFinite(amount) || amount !== expectedAmount + suppliedFeeValue);
    const feeValue = suppliedFeeMatchesTotal ? suppliedFeeValue : (useInferredFee ? inferredFeeValue : (suppliedFeeKnown ? suppliedFeeValue : null));
    const feeKnown = suppliedFeeMatchesTotal || useInferredFee || suppliedFeeKnown;
    const feeInferred = useInferredFee;
    const amountMatchesPackagePlusFee = (suppliedFeeMatchesTotal || useInferredFee) &&
      feeKnown && feeValue > 0 && Number.isFinite(amount) && amount === expectedAmount + feeValue;
    if (
      !Number.isFinite(amount) || !currency ||
      (!amountMatchesPackage && !amountMatchesPackagePlusFee) ||
      currency !== expectedCurrency ||
      ![5000,10000,20000,30000].includes(expectedAmount) || expectedCurrency !== "UGX"
    ) {
      console.error("Premium payment confirmation failed amount/currency validation", {
        reference: ref,
        receivedAmount: Number.isFinite(amount) ? amount : null,
        receivedCurrency: currency || null,
        expectedAmount,
        expectedCurrency,
        feeKnown,
        receivedFee: feeKnown ? feeValue : null
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
        AND amount IN (5000,10000,20000,30000) AND upper(currency)='UGX'
        AND (?='' OR provider_transaction_id IS NULL OR provider_transaction_id='' OR provider_transaction_id=?)
    `).bind(incomingTransactionId, ref, incomingTransactionId, incomingTransactionId).run();
    const changed = Number(update?.meta?.changes || 0) > 0;
    if (changed) {
      // Record Premium revenue once, keyed to the subscription row. Only use
      // a fee explicitly supplied by the signed provider event.
      // The ledger insert is the idempotency gate for crediting the wallet.
      // Keep the provider-reported collection total in the ledger and credit
      // the platform wallet net of the confirmed fee, matching other PesaJet
      // collection handling. For UGX 5,125 less UGX 125, the wallet receives
      // UGX 5,000 while the artist's package price remains UGX 5,000.
      await env.DB.batch([
        env.DB.prepare(`
          INSERT OR IGNORE INTO platform_financial_ledger
            (event_key, event_type, source_type, source_id, reference,
             amount_signed, currency, pesajet_fee_amount, tax_liability_amount,
             status, note, occurred_at)
          VALUES (?, 'income', 'premium_subscription', ?, ?, ?, 'UGX', ?, 0, ?, ?, datetime('now'))
        `).bind(
          `premium-subscription:${payment.id}`,
          payment.id,
          ref,
          amount,
          feeKnown ? feeValue : 0,
          feeKnown ? "posted" : "fee_unverified",
          suppliedFeeKnown
            ? "Premium subscription confirmed. Actual PesaJet fee supplied by the signed provider event."
            : feeInferred
              ? "Premium subscription confirmed. PesaJet webhook omitted the fee; fee inferred only from the observed exact 2.5% receipt pattern."
              : "Premium subscription confirmed. Actual PesaJet collection fee was not supplied by the confirmed transaction event; zero here does not mean fee-free."
        ),
        env.DB.prepare(`
          UPDATE platform_wallet
          SET balance = MAX(0, balance + ? - ?),
              updated_at = datetime('now')
          WHERE id = (SELECT id FROM platform_wallet ORDER BY created_at LIMIT 1)
            AND changes() > 0
        `).bind(amount, feeKnown ? feeValue : 0)
      ]);
    }
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
  const rawFee = data.fee ?? data.feeAmount ?? data.fee_amount ?? data.transactionFee ?? data.transaction_fee ??
    data.collectionFee ?? data.collection_fee ??
    payload.fee ?? payload.feeAmount ?? payload.fee_amount ?? payload.transactionFee ?? payload.transaction_fee ??
    payload.collectionFee ?? payload.collection_fee ??
    transaction.fee ?? transaction.feeAmount ?? transaction.fee_amount ?? transaction.transactionFee ?? transaction.transaction_fee ??
    transaction.collectionFee ?? transaction.collection_fee ?? null;
  const feeObject = rawFee && typeof rawFee === "object" ? rawFee : null;
  const feeValue = feeObject ? (feeObject.value ?? feeObject.amount ?? null) : rawFee;

  return {
    reference: String(payload?.reference ?? data.reference ?? transaction.reference ?? payload?.merchantReference ?? data.merchantReference ?? "").trim(),
    transactionId: String(payload?.transactionId ?? payload?.transaction_id ?? data.transactionId ?? data.transaction_id ?? transaction.transactionId ?? transaction.transaction_id ?? "").trim(),
    amount: amountValue === null || amountValue === undefined || amountValue === "" ? null : Number(amountValue),
    currency: String(currency || "").trim().toUpperCase(),
    fee: feeValue === null || feeValue === undefined || feeValue === "" ? null : Number(feeValue)
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
    // Do not log the raw body or signature; they may contain sensitive data.
    console.error("PesaJet webhook rejected: invalid signature.");
    return error("Invalid PesaJet webhook signature", 401);
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    console.error("PesaJet webhook rejected: invalid JSON payload.");
    return error("Invalid webhook payload", 400);
  }

  const event = String(payload.event || "").toLowerCase();
  if (event === "webhook.test") {
    console.info("PesaJet webhook test accepted.");
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
    console.info("PesaJet webhook event ignored.", { event: event || "(missing)" });
    return json({ received: true, ignored: true });
  }

  const webhookPayment = readPesaJetWebhookPaymentFields(payload);
  const reference = webhookPayment.reference;
  const transactionId = webhookPayment.transactionId;

  if (!reference) {
    console.error("PesaJet webhook rejected: payment reference missing.", { event, status });
    return error("Webhook reference is required", 422);
  }

  try {
    const paidSignupResult = reference.startsWith("NILESONIQ-SIGNUP-")
      ? await completePaidArtistSignup(env, reference, status, transactionId, webhookPayment.amount, webhookPayment.currency,
          payload?.message || payload?.description || payload?.reason || payload?.failureMessage || payload?.failure_message || "")
      : { matched: false };
    if (paidSignupResult.matched) {
      console.info("NileSoniQ paid signup webhook processed.",{reference,status,changed:Boolean(paidSignupResult.changed),reason:paidSignupResult.reason||null});
    }
    // A reference belongs to one transaction table; the unmatched update is a no-op.
    await applyPlatformPaymentStatus(
      env,
      "collection",
      reference,
      status,
      transactionId,
      webhookPayment.fee
    );
    await applyPlatformPaymentStatus(
      env,
      "disbursement",
      reference,
      status,
      transactionId,
      webhookPayment.fee
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
        payload?.data?.error?.message || payload?.data?.error?.code || "",
      webhookPayment.fee
    );

    // Log enough to diagnose Premium activation without logging the signature,
    // raw payload, phone number, or other unnecessary personal information.
    const isPremiumReference =
      reference.startsWith("NILESONIQ-PREMIUM-") || premiumResult.matched;

    if (isPremiumReference) {
      const diagnostic = {
        event,
        status,
        reference,
        transactionIdPresent: Boolean(transactionId),
        amount: webhookPayment.amount,
        currency: webhookPayment.currency || null,
        matchedSubscription: Boolean(premiumResult.matched),
        applied: Boolean(premiumResult.changed),
        reason: premiumResult.reason || "no_reason_returned"
      };

      if (
        premiumResult.reason === "verified_success" &&
        premiumResult.changed
      ) {
        console.info("NileSoniQ Premium activated from verified PesaJet payment.", diagnostic);
      } else if (premiumResult.reason === "already_processed") {
        console.info("NileSoniQ Premium webhook was already processed.", diagnostic);
      } else {
        console.error("NileSoniQ Premium webhook did not activate the subscription.", diagnostic);
      }
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
async function ensureArtistNotificationsTable(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS artist_notifications (
    id TEXT PRIMARY KEY,
    artist_id TEXT NOT NULL,
    notification_type TEXT NOT NULL DEFAULT 'withdrawal',
    message TEXT NOT NULL,
    related_id TEXT,
    read_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
}

async function artistNotificationsRoute(request, env) {
  const user = await currentUser(request, env);
  if (!user) return error("Authentication required", 401);
  if (request.method !== "GET") return error("Method not allowed", 405);
  try {
    await ensureArtistNotificationsTable(env);
    const rows = await env.DB.prepare(`
      SELECT id, notification_type, message, related_id, read_at, created_at
      FROM artist_notifications
      WHERE artist_id = ?
      ORDER BY created_at DESC
      LIMIT 25
    `).bind(user.id).all();
    return json({ data: rows.results || [], error: null });
  } catch (e) {
    console.error("Artist notifications failed:", e.message);
    return error("Could not load artist notifications", 500);
  }
}

async function artistDashboardRoute(request, env) {
  const user = await currentUser(request, env);
  if (!user) return error("Authentication required", 401);
  if (request.method !== "GET") return error("Method not allowed", 405);
  try {
    const artist = await env.DB.prepare(
      "SELECT id FROM artists WHERE user_id = ? LIMIT 1"
    ).bind(user.id).first().catch(() => null);
    const artistId = String(artist?.id || user.id);
    const ids = [...new Set([String(user.id), artistId])];
    const [songResult, ledgerResult, withdrawalResult] = await Promise.all([
      env.DB.prepare(`
        SELECT * FROM songs
        WHERE artist_id IN (?, ?)
        ORDER BY datetime(COALESCE(created_at, '1970-01-01')) DESC
        LIMIT 500
      `).bind(ids[0], ids[1]).all(),
      env.DB.prepare(`
        SELECT COALESCE(SUM(net_amount - ?), 0) AS adjustment
        FROM artist_earning_ledger
        WHERE artist_id IN (?, ?)
          AND source_type = 'qualified_play'
          AND status = 'posted'
      `).bind(ARTIST_FREE_NET_PER_PLAY, ids[0], ids[1]).first(),
      env.DB.prepare(`
        SELECT
          COALESCE(SUM(CASE WHEN lower(status) IN ('pending','processing','paid','completed','success','successful') THEN amount ELSE 0 END), 0) AS reserved,
          COALESCE(SUM(CASE WHEN lower(status) IN ('paid','completed','success','successful') THEN amount ELSE 0 END), 0) AS withdrawn
        FROM withdrawal_requests WHERE artist_id = ?
      `).bind(user.id).first()
    ]);
    const songs = songResult.results || [];
    const totalPlays = songs.reduce((sum, song) => sum + Math.max(0, Number(song.plays || 0)), 0);
    const approvedPlays = songs.filter(song => Number(song.approved) === 1 || String(song.review_status || "").toLowerCase() === "approved").reduce((sum, song) => sum + Math.max(0, Number(song.plays || 0)), 0);
    const earnings = Math.max(0, approvedPlays * ARTIST_FREE_NET_PER_PLAY + Number(ledgerResult?.adjustment || 0));
    const reserved = Math.max(0, Number(withdrawalResult?.reserved || 0));
    const availableBalance = Math.max(0, earnings - reserved);
    return json({
      data: {
        songs,
        stats: {
          totalPlays,
          totalSongs: songs.length,
          approvedPlays,
          earnings,
          availableBalance,
          amountWithdrawn: Math.max(0, Number(withdrawalResult?.withdrawn || 0))
        }
      },
      error: null
    });
  } catch (e) {
    console.error("Artist dashboard load failed:", e.message);
    return error("Could not load artist songs and earnings", 500);
  }
}

function slugForShare(value) {
  return String(value || "")
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .toLowerCase().trim().replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "").substring(0, 70) || "song";
}

function htmlEscape(value) {
  return String(value || "").replace(/[&<>\"']/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
  }[ch]));
}

async function songSharePreview(request, env, url) {
  if (request.method !== "GET" || !env.ASSETS || !/^\/song\/[^/]+\/?$/i.test(url.pathname)) return null;
  const slug = decodeURIComponent(url.pathname.split("/")[2] || "");
  let song = null;
  try {
    const result = await env.DB.prepare(`
      SELECT id, title, artist, description, cover_url
      FROM songs WHERE approved = 1 ORDER BY rowid DESC LIMIT 1000
    `).all();
    song = (result.results || []).find(item => slugForShare(item.title) === slugForShare(slug)) || null;
  } catch (e) {
    console.error("Song share preview lookup failed:", e.message);
  }
  const assetResponse = await env.ASSETS.fetch(new Request(new URL("/", url.origin), { method: "GET", headers: request.headers }));
  const html = await assetResponse.text();
  const title = song ? `${song.title || "Song"} — ${song.artist || "NileSoniq"}` : "NileSoniq — Ugandan Music Platform";
  const description = song ? (song.description || `Listen to ${song.title || "this song"} by ${song.artist || "an artist"} on NileSoniq.`) : "Discover and stream music from Ugandan artists on NileSoniq.";
  const image = song && song.cover_url && /^https:\/\//i.test(song.cover_url)
    ? song.cover_url
    : "https://nilesoniq.com/favicon.png";
  const canonical = `https://nilesoniq.com${url.pathname}`;
  const tags = [
    `<title>${htmlEscape(title)}</title>`,
    `<meta name="description" content="${htmlEscape(description)}">`,
    `<link rel="canonical" href="${htmlEscape(canonical)}">`,
    `<meta property="og:type" content="music.song">`,
    `<meta property="og:site_name" content="NileSoniq">`,
    `<meta property="og:title" content="${htmlEscape(title)}">`,
    `<meta property="og:description" content="${htmlEscape(description)}">`,
    `<meta property="og:url" content="${htmlEscape(canonical)}">`,
    `<meta property="og:image" content="${htmlEscape(image)}">`,
    `<meta name="twitter:card" content="summary_large_image">`,
    `<meta name="twitter:title" content="${htmlEscape(title)}">`,
    `<meta name="twitter:description" content="${htmlEscape(description)}">`,
    `<meta name="twitter:image" content="${htmlEscape(image)}">`
  ].join("\n");
  let updated = html.replace(/<title>[\s\S]*?<\/title>/i, "");
  updated = updated.replace(/<meta\s+name=["']description["'][^>]*>/i, "");
  updated = updated.replace(/<link\s+rel=["']canonical["'][^>]*>/i, "");
  updated = updated.replace(/<meta\s+property=["']og:[^>]*>/gi, "");
  updated = updated.replace(/<meta\s+name=["']twitter:[^>]*>/gi, "");
  updated = updated.replace(/<head[^>]*>/i, match => `${match}\n${tags}`);
  return new Response(updated, { status: assetResponse.status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=300" } });
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

      if (path === "/api/uploads/check") {
        response = await uploadPreflightRoute(request, env);
      } else if (path === "/api/artist/notifications") {
        response = await artistNotificationsRoute(request, env);
      } else if (path === "/api/artist/dashboard") {
        response = await artistDashboardRoute(request, env);
      } else if (path === "/api/auth/register-paid") {
        // Paid artist signup must use the dedicated pending-payment flow.
        // The account and verification email are created only after a verified
        // successful PesaJet webhook, never merely because this request arrived.
        response = await paidSignupRoute(request, env);
      } else if (path.startsWith("/api/auth/")) {
        response = await authRoute(request, env, path);
      } else if (path.startsWith("/api/db/")) {
        response = await dbRoute(request, env, path);
      } else if (
        path === "/api/admins" ||
        path.startsWith("/api/admins/") ||
        path === "/api/admin/songs" ||
        path.startsWith("/api/admin/songs/") ||
        path === "/api/admin/analytics" ||
        path === "/api/admin/copyright-removals" ||
        path === "/api/admin/copyright-removal-artists" ||
        path === "/api/admin/copyright-removal-songs"
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
      } else if (path.startsWith("/song/") && env.ASSETS) {
        response = await songSharePreview(request, env, url);
        if (!response) response = await env.ASSETS.fetch(request);
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
