
import bcrypt from "bcryptjs";

const COOKIE_NAME = "nile_session";
const SESSION_SECONDS = 30 * 24 * 60 * 60;
const EARNINGS_PER_PLAY = 0.5;
const ARTIST_COMMISSION_RATE = 0.20;
const ARTIST_TAX_ALLOCATION_RATE = 0.05;
const ARTIST_NET_RATE = 1 - ARTIST_COMMISSION_RATE - ARTIST_TAX_ALLOCATION_RATE;
const ARTIST_FREE_NET_PER_PLAY = EARNINGS_PER_PLAY * ARTIST_NET_RATE;
const ARTIST_PACKAGE_WITHDRAWAL_MINIMUMS = Object.freeze({
  free: 10000,
  premium: 7000,
  hustler: 5000,
  hit_maker: 3000,
  star: 1000
});
const DEFAULT_WITHDRAWAL_MINIMUM = ARTIST_PACKAGE_WITHDRAWAL_MINIMUMS.free;
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

// Temporary, explicitly labelled CEO test credits are stored separately from
// public song plays and the real artist earnings ledger. They can affect only
// the account's available-balance and withdrawal-limit calculations.
async function ensureArtistTestAdjustmentsTable(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS artist_test_adjustments (
      id TEXT PRIMARY KEY,
      artist_id TEXT NOT NULL,
      amount REAL NOT NULL CHECK (amount > 0),
      note TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT
    )
  `).run();
  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_artist_test_adjustments_artist_status
    ON artist_test_adjustments (artist_id, status)
  `).run();
}


// Referral commissions, admin wallets, ranks and payout controls.
const ADMIN_RANKS = ["junior_admin", "admin", "senior_admin", "admin_manager", "super_admin"];
const ADMIN_PACKAGE_COMMISSION_RATE = 0.20;
const ADMIN_STREAM_COMMISSION_RATE = 0.05;
const ARTIST_STREAM_PLATFORM_RATE = 0.15;

async function ensureAdminReferralSchema(env) {
  const addColumn = async (table, column, definition) => {
    const info = await env.DB.prepare(`PRAGMA table_info(${table})`).all();
    if (!(info.results || []).some(row => row.name === column)) {
      await env.DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`).run();
    }
  };
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_referral_commissions (
    id TEXT PRIMARY KEY, event_key TEXT NOT NULL UNIQUE, admin_id TEXT NOT NULL,
    artist_id TEXT NOT NULL, source_type TEXT NOT NULL, source_id TEXT NOT NULL,
    gross_amount REAL NOT NULL, commission_rate REAL NOT NULL, amount REAL NOT NULL,
    currency TEXT NOT NULL DEFAULT 'UGX', status TEXT NOT NULL DEFAULT 'posted',
    reversal_of TEXT, note TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_admin_referral_commissions_admin ON admin_referral_commissions(admin_id, status, created_at)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_wallets (
    id TEXT PRIMARY KEY, admin_id TEXT NOT NULL UNIQUE, balance REAL NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_withdrawal_requests (
    id TEXT PRIMARY KEY, admin_id TEXT NOT NULL, amount REAL NOT NULL CHECK(amount > 0),
    phone_number TEXT NOT NULL, provider TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
    reviewed_by TEXT, review_note TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')),
    reviewed_at TEXT, paid_at TEXT
  )`).run();
  await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_admin_withdrawals_status ON admin_withdrawal_requests(status, created_at)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_audit_log (
    id TEXT PRIMARY KEY, actor_admin_id TEXT NOT NULL, target_admin_id TEXT,
    action TEXT NOT NULL, details_json TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_rank_policy (
    rank TEXT PRIMARY KEY, referrals_required INTEGER NOT NULL DEFAULT 0,
    package_sales_required INTEGER NOT NULL DEFAULT 0, streams_required INTEGER NOT NULL DEFAULT 0,
    commission_required REAL NOT NULL DEFAULT 0, service_days_required INTEGER NOT NULL DEFAULT 0
  )`).run();
  await env.DB.prepare(`INSERT OR IGNORE INTO admin_rank_policy(rank) VALUES ('junior_admin'),('admin'),('senior_admin'),('admin_manager'),('super_admin')`).run();
  await addColumn('admins', 'rank', "TEXT NOT NULL DEFAULT 'admin'");
  await addColumn('admins', 'referral_code', 'TEXT');
  await addColumn('admins', 'suspended_at', 'TEXT');
  await addColumn('artists', 'referring_admin_id', 'TEXT');
  await addColumn('premium_subscriptions', 'referring_admin_id', 'TEXT');
  await addColumn('premium_subscriptions', 'initiated_by_admin_id', 'TEXT');
  await addColumn('pending_artist_signups', 'referral_code', 'TEXT');
  await env.DB.prepare(`CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_referral_code ON admins(referral_code) WHERE referral_code IS NOT NULL`).run();
  const admins = await env.DB.prepare(`SELECT id, role, rank, referral_code FROM admins`).all();
  for (const row of admins.results || []) {
    const rank = row.role === 'super_admin' ? 'super_admin' : (ADMIN_RANKS.includes(row.rank) ? row.rank : 'admin');
    const code = row.referral_code || `NSQ-${String(row.id).replace(/-/g,'').slice(0,10).toUpperCase()}`;
    await env.DB.prepare(`UPDATE admins SET rank=?, referral_code=? WHERE id=?`).bind(rank, code, row.id).run();
  }
}

async function ensureAdminWallet(env, adminId) {
  await env.DB.prepare(`INSERT OR IGNORE INTO admin_wallets(id,admin_id,balance) VALUES(?,?,0)`).bind(crypto.randomUUID(), adminId).run();
}

async function creditAdminCommission(env, { eventKey, adminId, artistId, sourceType, sourceId, gross, rate, note }) {
  const amount = Math.round(Number(gross) * Number(rate) * 1000) / 1000;
  if (!adminId || !artistId || !eventKey || !Number.isFinite(amount) || amount <= 0) return false;
  await ensureAdminReferralSchema(env);
  await ensureAdminWallet(env, adminId);
  const results = await env.DB.batch([
    env.DB.prepare(`INSERT OR IGNORE INTO admin_referral_commissions
      (id,event_key,admin_id,artist_id,source_type,source_id,gross_amount,commission_rate,amount,currency,status,note)
      SELECT ?,?,?,?,?,?,?,?,?, 'UGX','posted',? WHERE EXISTS (SELECT 1 FROM admins WHERE id=? AND active=1 AND suspended_at IS NULL)`)
      .bind(crypto.randomUUID(),eventKey,adminId,artistId,sourceType,sourceId,Number(gross),Number(rate),amount,note||null,adminId),
    env.DB.prepare(`UPDATE admin_wallets SET balance=balance+?,updated_at=datetime('now') WHERE admin_id=? AND changes()>0`).bind(amount,adminId)
  ]);
  return Number(results?.[0]?.meta?.changes || 0) > 0;
}

async function adminReferralRoute(request, env, path) {
  const user = await currentUser(request, env);
  if (!user) return error('Authentication required',401);
  const admin = await getAdmin(env,user);
  if (!admin) return error('Admin access required',403);
  await ensureAdminReferralSchema(env);
  const superAdmin = admin.role === 'super_admin' || admin.rank === 'super_admin';
  const url = new URL(request.url);
  if (request.method === 'GET' && path === '/api/admin/referrals/artists') {
    // Keep the response deliberately simple and provide aliases for older UI builds.
    // instr() avoids LIKE wildcard escaping problems with artist names.
    const term = String(url.searchParams.get('q') || url.searchParams.get('search') || url.searchParams.get('name') || '').trim();
    let matches;
    if (term) {
      matches = await env.DB.prepare(`
        SELECT id, name, location, package_name
        FROM artists
        WHERE COALESCE(trim(name), '') <> ''
          AND instr(lower(name), lower(?)) > 0
        ORDER BY CASE WHEN lower(name)=lower(?) THEN 0 ELSE 1 END,
                 name COLLATE NOCASE
        LIMIT 100
      `).bind(term, term).all();
    } else {
      matches = await env.DB.prepare(`
        SELECT id, name, location, package_name
        FROM artists
        WHERE COALESCE(trim(name), '') <> ''
        ORDER BY name COLLATE NOCASE
        LIMIT 100
      `).all();
    }
    const artists = (matches.results || []).map(row => ({
      id: String(row.id),
      name: String(row.name || 'Unnamed artist'),
      location: row.location || '',
      package_name: row.package_name || 'free'
    }));
    return json({ success: true, data: artists, artists, results: artists, count: artists.length });
  }
  if (request.method === 'GET' && path === '/api/admin/referrals') {
    await ensureAdminWallet(env,admin.id);
    const wallet = await env.DB.prepare(`SELECT balance FROM admin_wallets WHERE admin_id=?`).bind(admin.id).first();
    const totals = await env.DB.prepare(`SELECT COUNT(DISTINCT artist_id) artists, COALESCE(SUM(amount),0) earnings FROM admin_referral_commissions WHERE admin_id=? AND status='posted'`).bind(admin.id).first();
    const commissions = await env.DB.prepare(`SELECT c.*,a.name artist_name FROM admin_referral_commissions c LEFT JOIN artists a ON a.id=c.artist_id WHERE c.admin_id=? ORDER BY datetime(c.created_at) DESC LIMIT 200`).bind(admin.id).all();
    const referrals = await env.DB.prepare(`SELECT a.id,a.name,a.created_at FROM artists a WHERE a.referring_admin_id=? ORDER BY datetime(a.created_at) DESC LIMIT 500`).bind(admin.id).all();
    const withdrawals = await env.DB.prepare(`SELECT * FROM admin_withdrawal_requests WHERE admin_id=? ORDER BY datetime(created_at) DESC LIMIT 100`).bind(admin.id).all();
    const result = { admin: {...admin, referral_code: (await env.DB.prepare('SELECT referral_code,rank FROM admins WHERE id=?').bind(admin.id).first())?.referral_code}, balance:Number(wallet?.balance||0), referred_artists:Number(totals?.artists||0), total_earnings:Number(totals?.earnings||0), commissions:commissions.results||[], referrals:referrals.results||[], withdrawals:withdrawals.results||[] };
    if (superAdmin) {
      const all = await env.DB.prepare(`SELECT ad.id,ad.user_id,ad.email,ad.role,ad.rank,ad.active,ad.referral_code,COALESCE(w.balance,0) balance,COUNT(DISTINCT c.artist_id) referred_artists,COALESCE(SUM(c.amount),0) total_commission FROM admins ad LEFT JOIN admin_wallets w ON w.admin_id=ad.id LEFT JOIN admin_referral_commissions c ON c.admin_id=ad.id AND c.status='posted' GROUP BY ad.id ORDER BY ad.created_at`).all();
      const pending = await env.DB.prepare(`SELECT r.*,a.email admin_email FROM admin_withdrawal_requests r JOIN admins a ON a.id=r.admin_id WHERE r.status='pending' ORDER BY r.created_at`).all();
      result.all_admins=all.results||[]; result.pending_withdrawals=pending.results||[];
      result.rank_policy=(await env.DB.prepare('SELECT * FROM admin_rank_policy ORDER BY CASE rank WHEN 'junior_admin' THEN 1 WHEN 'admin' THEN 2 WHEN 'senior_admin' THEN 3 WHEN 'admin_manager' THEN 4 ELSE 5 END').all()).results||[];
    }
    return json({data:result,error:null});
  }
  if (request.method === 'POST' && path === '/api/admin/referrals/upgrade') {
    const body = await readBody(request);
    const artistId = String(body.artist_id || '').trim();
    const packageCode = String(body.package_code || '').trim().toLowerCase();
    const packagePrices = { premium: 5000, hustler: 10000, hit_maker: 20000, star: 30000 };
    const amount = packagePrices[packageCode];
    const artist = await env.DB.prepare(`SELECT id,user_id,name,referring_admin_id FROM artists WHERE id=? LIMIT 1`).bind(artistId).first();
    if (!artist || !amount) return error('Choose an existing artist and a valid paid package.', 422);
    const phone = normalizeUgandanPhone(body.phone_number || body.phoneNumber);
    const provider = String(body.provider || '').trim().toLowerCase();
    if (!/^\+256\d{9}$/.test(phone) || !['mtn','airtel'].includes(provider)) return error('Enter the artist’s valid MTN or Airtel mobile-money number.', 422);
    const apiKey = env.PESAJET_API_KEY || env.PESAJET_TOKEN;
    const baseUrl = String(env.PESAJET_API_BASE_URL || 'https://payments.pesajet.com/api/v1').replace(/\/+$/, '');
    if (!apiKey) return error('Payment service is not configured.', 503);
    const reference = `NILESONIQ-PREMIUM-${paymentReferenceName(artist.name)}-${crypto.randomUUID().replace(/-/g,'').slice(0,16).toUpperCase()}`;
    const risk = await checkPesaJetCollectionRisk(request, env, phone, artist.user_id, reference);
    if (risk.blocked) return error(risk.message, 429);
    const id = crypto.randomUUID(), now = new Date().toISOString();
    // Store the artist's existing referral owner. The assisting admin is tracked separately
    // and must not receive the referral commission merely for initiating the prompt.
    await env.DB.prepare(`
      INSERT INTO premium_subscriptions
        (id,user_id,artist_id,amount,currency,provider,phone_number,reference,status,created_at,package_name,initiated_by_admin_id,referring_admin_id)
      SELECT ?,?,?,?,'UGX',?,?,?,'pending',?,?,?,referring_admin_id FROM artists WHERE id=?
    `).bind(id, artist.user_id, artist.id, amount, provider, phone, reference, now, packageCode, admin.id, artist.id).run();

    let response, result;
    try {
      response = await fetch(`${baseUrl}/payments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
        body: JSON.stringify({ type: 'COLLECTION', amount, currency: 'UGX', phoneNumber: phone, provider, reference,
          description: `NileSoniQ artist package upgrade - ${artist.name || 'Artist'} - initiated by admin`.slice(0,250),
          idempotencyKey: `nilesoniq-${reference}` })
      });
      result = await response.json().catch(() => ({}));
    } catch (e) {
      console.error('Admin-assisted package request outcome uncertain:', e.message);
      return error('PesaJet did not return a response. The request is kept pending; check its status before trying again.', 502);
    }
    const data = result?.data && typeof result.data === 'object' ? result.data : {};
    const transaction = result?.transaction && typeof result.transaction === 'object' ? result.transaction : (data?.transaction && typeof data.transaction === 'object' ? data.transaction : data);
    const statusCandidates = [transaction?.status, transaction?.transactionStatus, transaction?.paymentStatus, transaction?.state,
      data?.status, data?.transactionStatus, data?.paymentStatus, data?.state, result?.status, result?.transactionStatus, result?.paymentStatus, result?.state]
      .filter(Boolean).map(v => String(v).trim().toUpperCase().replace(/[\s-]+/g, '_'));
    const providerId = String(transaction?.transactionId || transaction?.transaction_id || data?.transactionId || data?.transaction_id || result?.transactionId || result?.transaction_id || '');
    const messages = [result?.message, result?.description, result?.detail, result?.reason,
      typeof result?.error === 'string' ? result.error : result?.error?.message || result?.error?.description,
      data?.message, data?.description, data?.detail, data?.reason,
      typeof data?.error === 'string' ? data.error : data?.error?.message,
      transaction?.message, transaction?.description, transaction?.detail, transaction?.reason, ...statusCandidates]
      .filter(v => v !== undefined && v !== null && String(v).trim()).map(v => String(v).trim());
    const providerMessage = messages.join(' | ');
    const failureStatuses = ['FAILED','FAILURE','ERROR','EXPIRED','REJECTED','DECLINED','CANCELLED','CANCELED','TIMED_OUT','TIMEOUT','TIME_OUT','INSUFFICIENT_BALANCE','INSUFFICIENT_FUNDS','AUTHORIZATION_FAILED','LIMIT_EXCEEDED'];
    const failureText = /insufficient[ _-]*(balance|funds)|not enough (money|funds|balance)|low balance|balance too low|transaction limit|daily limit|limit exceeded|payment failed|payment declined|request rejected|authorization failed/i.test(providerMessage);
    const explicitError = result?.success === false || data?.success === false || !!result?.error || !!data?.error || !!transaction?.error;
    const rejected = !response.ok || explicitError || statusCandidates.some(s => failureStatuses.includes(s)) || failureText;
    if (rejected) {
      const message = premiumPaymentFailureMessage(providerMessage || 'PesaJet rejected the payment request');
      const definitive = (response.status >= 400 && response.status < 500) || explicitError || statusCandidates.some(s => failureStatuses.includes(s)) || failureText;
      if (definitive) await env.DB.prepare("UPDATE premium_subscriptions SET status='failed',provider_transaction_id=?,failure_message=? WHERE reference=? AND lower(status)='pending'").bind(providerId, message, reference).run();
      return error(message, response.status >= 400 && response.status < 500 ? response.status : 502);
    }
    if (statusCandidates.length && !statusCandidates.some(s => ['PENDING','PROCESSING','INITIATED','ACCEPTED','IN_PROGRESS'].includes(s)) && !isSuccessfulPaymentStatus(statusCandidates[0])) {
      const message = premiumPaymentFailureMessage(providerMessage || statusCandidates[0]);
      await env.DB.prepare("UPDATE premium_subscriptions SET status='failed',provider_transaction_id=?,failure_message=? WHERE reference=? AND lower(status)='pending'").bind(providerId,message,reference).run();
      return error(message, 502);
    }
    await env.DB.prepare("UPDATE premium_subscriptions SET provider_transaction_id=? WHERE reference=? AND status='pending'").bind(providerId, reference).run();
    await env.DB.prepare(`INSERT INTO admin_audit_log(id,actor_admin_id,target_admin_id,action,details_json) VALUES(?,?,?,'assisted_upgrade_started',?)`)
      .bind(crypto.randomUUID(), admin.id, admin.id, JSON.stringify({artist_id:artist.id,package_code:packageCode,reference,amount,provider})).run();
    return json({success:true,status:'PENDING',reference,message:`PesaJet accepted the UGX ${amount.toLocaleString('en-US')} ${packageCode.replace('_',' ')} payment request for ${artist.name || 'the artist'}. Approve the mobile-money prompt; the package and the referring admin’s 20% commission update only after verified provider confirmation.`});
  }
  if (request.method === 'POST' && path === '/api/admin/referrals/withdrawals') {
    const body=await readBody(request), amount=Number(body.amount), phone=normalizeUgandanPhone(body.phone_number||body.phoneNumber), provider=String(body.provider||'').toLowerCase();
    const wallet=await env.DB.prepare('SELECT balance FROM admin_wallets WHERE admin_id=?').bind(admin.id).first();
    if(!Number.isFinite(amount)||amount<10000||amount>Number(wallet?.balance||0)||!/^\+256\d{9}$/.test(phone)||!['mtn','airtel'].includes(provider)) return error('Enter a valid withdrawal of at least UGX 10,000, within your available balance, with a valid MTN or Airtel number.',422);
    const pending=await env.DB.prepare("SELECT id FROM admin_withdrawal_requests WHERE admin_id=? AND status='pending' LIMIT 1").bind(admin.id).first();
    if(pending) return error('You already have a pending admin withdrawal request.',409);
    const id=crypto.randomUUID();
    await env.DB.prepare(`INSERT INTO admin_withdrawal_requests(id,admin_id,amount,phone_number,provider,status) VALUES(?,?,?,?,?,'pending')`).bind(id,admin.id,amount,phone,provider).run();
    await env.DB.prepare(`INSERT INTO admin_audit_log(id,actor_admin_id,target_admin_id,action,details_json) VALUES(?,?,?,'withdrawal_requested',?)`).bind(crypto.randomUUID(),admin.id,admin.id,JSON.stringify({request_id:id,amount})).run();
    return json({success:true,id});
  }
  const reviewMatch=path.match(/^\/api\/admin\/referrals\/withdrawals\/([^/]+)\/review$/);
  if(request.method==='POST' && reviewMatch){
    if(!superAdmin) return error('Only Super Admin can approve or reject admin withdrawals.',403);
    const body=await readBody(request), action=String(body.action||'').toLowerCase(), id=reviewMatch[1];
    if(!['approve','reject'].includes(action)) return error('Choose approve or reject.',422);
    const req=await env.DB.prepare("SELECT * FROM admin_withdrawal_requests WHERE id=? AND status='pending'").bind(id).first();
    if(!req) return error('Pending withdrawal request not found.',404);
    if(req.admin_id===admin.id) return error('You cannot approve your own withdrawal.',403);
    if(action==='approve'){
      const wallet=await env.DB.prepare('SELECT balance FROM admin_wallets WHERE admin_id=?').bind(req.admin_id).first();
      if(Number(wallet?.balance||0)<Number(req.amount)) return error('Insufficient available admin wallet balance.',409);
      await env.DB.batch([
        env.DB.prepare("UPDATE admin_withdrawal_requests SET status='approved',reviewed_by=?,review_note=?,reviewed_at=datetime('now') WHERE id=? AND status='pending'").bind(admin.id,String(body.note||'').slice(0,500),id),
        env.DB.prepare('UPDATE admin_wallets SET balance=balance-?,updated_at=datetime('now') WHERE admin_id=? AND balance>=?').bind(req.amount,req.admin_id,req.amount)
      ]);
    } else await env.DB.prepare("UPDATE admin_withdrawal_requests SET status='rejected',reviewed_by=?,review_note=?,reviewed_at=datetime('now') WHERE id=? AND status='pending'").bind(admin.id,String(body.note||'').slice(0,500),id).run();
    await env.DB.prepare('INSERT INTO admin_audit_log(id,actor_admin_id,target_admin_id,action,details_json) VALUES(?,?,?,?,?)').bind(crypto.randomUUID(),admin.id,req.admin_id,`withdrawal_${action}`,JSON.stringify({request_id:id,amount:req.amount})).run();
    return json({success:true});
  }
  if(request.method==='POST' && path==='/api/admin/referrals/rank'){
    if(!superAdmin) return error('Only Super Admin can change admin ranks.',403);
    const body=await readBody(request);
    const targetKey=String(body.admin_id || body.user_id || body.email || '').trim();
    const rank=String(body.rank || '').trim().toLowerCase();
    if(!targetKey) return error('Choose an administrator first.',422);
    if(!ADMIN_RANKS.includes(rank)) return error('Invalid administrator type.',422);

    // Accept the admin record ID, linked auth user ID, or email. The UI has
    // existed in two versions and they did not always pass the same identifier.
    const target=await env.DB.prepare(`
      SELECT id,user_id,email,role,rank
      FROM admins
      WHERE CAST(id AS TEXT)=?
         OR CAST(user_id AS TEXT)=?
         OR lower(trim(email))=lower(trim(?))
      LIMIT 1
    `).bind(targetKey,targetKey,targetKey).first();
    if(!target) return error('Administrator not found. Refresh the administrator list and try again.',404);
    if(String(target.user_id)===String(user.id) || String(target.id)===String(admin.id)) {
      return error('You cannot change your own administrator rank.',403);
    }
    const previousRank=target.rank || (target.role==='super_admin'?'super_admin':'admin');
    const role=rank==='super_admin'?'super_admin':'admin';
    const update=await env.DB.prepare('UPDATE admins SET rank=?,role=? WHERE id=?').bind(rank,role,target.id).run();
    if(Number(update?.meta?.changes || 0)!==1) return error('The administrator rank was not changed. Please refresh and try again.',409);
    await env.DB.prepare(`
      INSERT INTO admin_audit_log(id,actor_admin_id,target_admin_id,action,details_json)
      VALUES(?,?,?,'rank_changed',?)
    `).bind(crypto.randomUUID(),admin.id,target.id,JSON.stringify({from:previousRank,to:rank,identifier:targetKey})).run();
    return json({success:true,admin_id:target.id,user_id:target.user_id,rank,role});
  }
  if(request.method==='POST' && path==='/api/admin/referrals/assign'){
    if(!superAdmin) return error('Only Super Admin can assign referral ownership.',403);
    const body=await readBody(request), artistId=String(body.artist_id||''), adminId=String(body.admin_id||'');
    const owner=await env.DB.prepare('SELECT id FROM admins WHERE id=? AND active=1 AND suspended_at IS NULL').bind(adminId).first();
    if(!owner||!artistId) return error('Choose an active admin and artist.',422);
    const previous=await env.DB.prepare('SELECT referring_admin_id FROM artists WHERE id=?').bind(artistId).first();
    await env.DB.prepare('UPDATE artists SET referring_admin_id=? WHERE id=?').bind(adminId,artistId).run();
    await env.DB.prepare(`INSERT INTO admin_audit_log(id,actor_admin_id,target_admin_id,action,details_json) VALUES(?,?,?,'referral_owner_assigned',?)`).bind(crypto.randomUUID(),admin.id,adminId,JSON.stringify({artist_id:artistId,previous_admin_id:previous?.referring_admin_id||null,new_admin_id:adminId})).run();
    return json({success:true});
  }
  if(request.method==='POST' && path==='/api/admin/referrals/suspend'){
    if(!superAdmin) return error('Only Super Admin can suspend administrators.',403);
    const body=await readBody(request), targetId=String(body.admin_id||''), suspend=body.suspended!==false;
    if(targetId===admin.id) return error('You cannot suspend your own Super Admin account.',403);
    await env.DB.prepare('UPDATE admins SET active=?,suspended_at=? WHERE id=? AND role<>'super_admin'').bind(suspend?0:1,suspend?new Date().toISOString():null,targetId).run();
    await env.DB.prepare('INSERT INTO admin_audit_log(id,actor_admin_id,target_admin_id,action,details_json) VALUES(?,?,?,?,?)').bind(crypto.randomUUID(),admin.id,targetId,suspend?'admin_suspended':'admin_reactivated','{}').run();
    return json({success:true});
  }
  return error('Admin referral route not found',404);
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
    SELECT id, user_id, email, role, rank, active
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
  return Boolean(admin && (admin.role === "super_admin" || admin.rank === "super_admin"));
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

function paymentReferenceName(value, fallback = "ARTIST") {
  const slug = String(value || fallback)
    .normalize("NFKD")
    .replace(/[\\u0300-\\u036f]/g, "")
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 36);
  return slug || fallback;
}

async function ensurePendingArtistSignups(env) {
  await ensureAdminReferralSchema(env);
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
    user_id TEXT,
    referral_code TEXT
  )`).run();
  const columns = await env.DB.prepare(`PRAGMA table_info(pending_artist_signups)`).all();
  if (!(columns.results || []).some(row => row.name === 'referral_code')) await env.DB.prepare(`ALTER TABLE pending_artist_signups ADD COLUMN referral_code TEXT`).run();
}

async function paidSignupRoute(request, env) {
  await ensurePendingArtistSignups(env);
  if (request.method === "GET") {
    const reference = String(new URL(request.url).searchParams.get("reference") || "").trim();
    if (!/^(?:NILESONIQ-SIGNUP-[A-F0-9-]{20,80}|NILESONIQ-ARTIST-REGISTRATION-[A-Z0-9-]{8,100})$/i.test(reference)) return error("A valid payment reference is required", 422);
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
  const apiKey = env.PESAJET_API_KEY || env.PESAJET_TOKEN;
  const baseUrl = String(env.PESAJET_API_BASE_URL || "https://payments.pesajet.com/api/v1").replace(/\/+$/, "");
  if (!apiKey) return error("Payment service is not configured.", 503);
  const reference = `NILESONIQ-ARTIST-REGISTRATION-${paymentReferenceName(artistName)}-${crypto.randomUUID().replace(/-/g, "").slice(0, 16).toUpperCase()}`;
  const riskCheck = await checkPesaJetCollectionRisk(request, env, phone, null, reference);
  if (riskCheck.blocked) return error(riskCheck.message, 429);
  const description = `NileSoniQ Artist Registration - ${artistName}`.slice(0, 250);
  const id = crypto.randomUUID();
  const passwordHash = await bcrypt.hash(password, 10);
  const referralCode = String(body.referral_code || body.ref || '').trim().toUpperCase().slice(0,40);
  const referralAdmin = referralCode ? await env.DB.prepare(`SELECT id FROM admins WHERE upper(referral_code)=? AND active=1 AND suspended_at IS NULL LIMIT 1`).bind(referralCode).first() : null;
  const safeReferralCode = referralAdmin ? referralCode : null;
  await env.DB.prepare(`INSERT INTO pending_artist_signups (id,reference,email,password_hash,artist_name,phone_number,provider,package_code,amount,currency,status,referral_code) VALUES (?,?,?,?,?,?,?,?,?,'UGX','pending',?)`)
    .bind(id,reference,email,passwordHash,artistName,phone,provider,packageCode,amount,safeReferralCode).run();
  let response, result;
  try {
    response = await fetch(`${baseUrl}/payments`, {method:"POST",headers:{"Content-Type":"application/json","X-API-Key":apiKey},body:JSON.stringify({type:"COLLECTION",amount,currency:"UGX",phoneNumber:phone,provider,reference,description,idempotencyKey:`nilesoniq-${reference}`})});
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
    const confirmedAmount = Number(amount);
    const confirmedCurrency = String(currency || "").trim().toUpperCase();
    const requiredAmount = Number(row.amount);
    if (!Number.isFinite(confirmedAmount) || !Number.isFinite(requiredAmount) || confirmedAmount < requiredAmount || confirmedCurrency !== "UGX") {
      console.error("Paid signup payment amount/currency mismatch",{reference,expectedMinimumAmount:row.amount,receivedAmount:amount,receivedCurrency:currency});
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
        env.DB.prepare("INSERT INTO artists (id,user_id,name,referring_admin_id) VALUES (?,?,?,(SELECT id FROM admins WHERE upper(referral_code)=? AND active=1 AND suspended_at IS NULL LIMIT 1))").bind(artistId,userId,row.artist_name,String(row.referral_code||'')),
        env.DB.prepare(`INSERT INTO premium_subscriptions (id,user_id,artist_id,amount,currency,provider,phone_number,reference,status,created_at,paid_at,expires_at,provider_transaction_id,package_name,referring_admin_id) VALUES (?,?,?,?,'UGX',?,?,?,'active',datetime('now'),datetime('now'),?,?,?,(SELECT id FROM admins WHERE upper(referral_code)=? AND active=1 AND suspended_at IS NULL LIMIT 1))`).bind(subscriptionId,userId,artistId,row.amount,row.provider,row.phone_number,subscriptionReference,expiry,incomingTx,row.package_code,String(row.referral_code||'')),
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
      const referredBy = row.referral_code ? await env.DB.prepare(`SELECT id FROM admins WHERE upper(referral_code)=? AND active=1 AND suspended_at IS NULL LIMIT 1`).bind(String(row.referral_code)).first() : null;
      if (referredBy) await creditAdminCommission(env,{eventKey:`package-signup:${subscriptionId}`,adminId:referredBy.id,artistId,sourceType:'artist_package',sourceId:subscriptionId,gross:Number(row.amount),rate:ADMIN_PACKAGE_COMMISSION_RATE,note:'20% of confirmed initial artist package signup'});
    } catch (e) { console.error("Paid signup referral or entitlement processing failed:",e.message); }
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

      if (ownerColumn === "artist_id") {
        const artistProfile = await env.DB.prepare("SELECT id, name FROM artists WHERE user_id = ? LIMIT 1").bind(user.id).first();
        const artistProfileId = String(artistProfile?.id || user.id);
        where = appendCondition(where, `${ownerColumn} IN (?, ?)`);
        values = [...values, user.id, artistProfileId];
      } else {
        where = appendCondition(where, `${ownerColumn} = ?`);
        values = [...values, user.id];
      }
    }

    // Published news is the only news content available to ordinary visitors.
    // Admins retain access to drafts for editorial management.
    if (table === "news" && !admin) {
      where = appendCondition(where, "published = 1");
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
    !admin &&
    !artistWithdrawalCreate
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

  let withdrawalDiagnosticStage = "before request processing";
  try {
    if (method === "POST") {
      const body = await readBody(request);
      if (table === "withdrawal_requests" && !admin) {
        withdrawalDiagnosticStage = "reading withdrawal request";
      }
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
            "id",
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

          // A stable client-generated UUID makes a retried song submission
          // idempotent: if the first request reached D1 but its response was lost,
          // the retry returns the same song instead of creating a duplicate.
          const requestedSongId = String(row.id || "").trim();
          if (requestedSongId && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(requestedSongId)) {
            return error("Invalid song upload reference.", 422);
          }
          if (requestedSongId) {
            const existingSong = await env.DB.prepare(
              "SELECT * FROM songs WHERE id = ? LIMIT 1"
            ).bind(requestedSongId).first();
            if (existingSong) {
              if (String(existingSong.artist_id) !== String(user.id)) {
                return error("This song upload reference is already in use.", 409);
              }
              output.push(existingSong);
              continue;
            }
          }

          // Ignore client-supplied approval, play and like counts.
          const safeRow = {
            ...row,
            id: requestedSongId || crypto.randomUUID(),
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
          const anchorRow = await env.DB.prepare(`
            SELECT COALESCE(
              (SELECT COALESCE(paid_at, created_at) FROM premium_subscriptions
               WHERE user_id = ? AND lower(status) = 'active' AND expires_at IS NOT NULL
                 AND datetime(expires_at) > datetime('now')
               ORDER BY datetime(COALESCE(paid_at, created_at)) DESC, datetime(created_at) DESC
               LIMIT 1),
              (SELECT created_at FROM auth_users WHERE id = ? LIMIT 1)
            ) AS cycle_anchor
          `).bind(user.id, user.id).first();
          if (!anchorRow?.cycle_anchor) return error("Could not verify your upload-cycle date. No song was uploaded.", 503);
          const uploadCycle = getArtistUploadCycle(anchorRow.cycle_anchor);

          // Submitted songs consume an allowance immediately, including while
          // pending review. Rejected submissions do not consume an allowance.
          // Keep the count and insert in one SQL statement to handle simultaneous
          // uploads safely. Preserve the existing rollout cutoff behavior.
          const insertResult = await env.DB.prepare(`
            INSERT OR IGNORE INTO songs (${insertKeys.join(",")})
            SELECT ${insertKeys.map(() => "?").join(",")}
            WHERE (
              SELECT COUNT(*) FROM songs
              WHERE artist_id = ?
                AND COALESCE(lower(review_status), CASE WHEN approved = 1 THEN 'approved' ELSE 'pending' END) != 'rejected'
                AND datetime(created_at) >= CASE
                  WHEN datetime(?) > datetime(?) THEN datetime(?) ELSE datetime(?) END
                AND datetime(created_at) < datetime(?)
            ) < ?
          `).bind(
            ...insertKeys.map(k => safeRow[k] ?? null),
            user.id,
            uploadCycle.cycleStart, PACKAGE_LIMITS_EFFECTIVE_AT,
            PACKAGE_LIMITS_EFFECTIVE_AT, uploadCycle.cycleStart,
            uploadCycle.nextReset,
            uploadLimit
          ).run();

          if (Number(insertResult?.meta?.changes || 0) === 0) {
            // A simultaneous retry with the same stable ID may have inserted
            // the row first. Return that row instead of treating it as a limit.
            const retrySong = await env.DB.prepare(
              "SELECT * FROM songs WHERE id = ? LIMIT 1"
            ).bind(safeRow.id).first();
            if (retrySong && String(retrySong.artist_id) === String(user.id)) {
              output.push(retrySong);
              continue;
            }
            const limitLabel = uploadLimit >= Number.MAX_SAFE_INTEGER ? 'unlimited' : String(uploadLimit);
            return error(
              `Monthly song submission limit reached for your ${packageCode} package (${limitLabel} submissions per package cycle). Rejected submissions do not count. Upgrade or try again after your next cycle starts.`,
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

          // Determine the withdrawal minimum from the provider-confirmed,
          // currently active package. Never trust a package supplied by the client.
          let packageCode = "free";
          try {
            const entitlement = await syncArtistPremiumEntitlement(env, user.id);
            packageCode = String(entitlement?.packageCode || "free").trim().toLowerCase();
          } catch (entitlementError) {
            console.error("Could not verify artist package before withdrawal:", entitlementError.message);
            return error("We could not verify your artist package right now. Please try again shortly.", 503);
          }
          const withdrawalMinimum =
            ARTIST_PACKAGE_WITHDRAWAL_MINIMUMS[packageCode] ?? DEFAULT_WITHDRAWAL_MINIMUM;
          const artistProfile = await env.DB.prepare("SELECT id FROM artists WHERE user_id = ? LIMIT 1").bind(user.id).first();
          const artistProfileId = String(artistProfile?.id || user.id);

          const amount = Number(row.amount);
          const paymentMethod = String(
            row.payment_method || ""
          ).trim();
          const paymentDetails = String(
            row.payment_details || ""
          ).trim();

          if (
            !Number.isInteger(amount) ||
            amount < withdrawalMinimum ||
            !paymentMethod ||
            !paymentDetails
          ) {
            return error(
              `A valid amount of at least UGX ${withdrawalMinimum.toLocaleString("en-US")}, payment method, and payment details are required for your ${packageCode.replace(/_/g, " ")} package`,
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

          // Test adjustments are separate from real plays and the real earnings ledger.
          withdrawalDiagnosticStage = "checking the test-adjustments table";
          await ensureArtistTestAdjustmentsTable(env);

          // Check available earnings and create the reservation in one SQL
          // statement. Concurrent requests cannot both spend the same balance.
          try {
            withdrawalDiagnosticStage = "inserting the withdrawal request";
            const inserted = await env.DB.prepare(`
              INSERT INTO withdrawal_requests
                (id, artist_id, amount, payment_method, payment_details, status, created_at)
              SELECT ?, ?, ?, ?, ?, 'pending', ?
              WHERE ? <= MAX(
                0,
                COALESCE((
                  SELECT SUM(COALESCE(plays, 0))
                  FROM songs
                  WHERE artist_id IN (?, ?) AND (approved = 1 OR lower(COALESCE(review_status, '')) = 'approved')
                ), 0) * ?
                + COALESCE((
                  SELECT SUM(net_amount - ?)
                  FROM artist_earning_ledger
                  WHERE artist_id IN (?, ?)
                    AND source_type = 'qualified_play'
                    AND status = 'posted'
                ), 0)
                + COALESCE((
                  SELECT SUM(net_amount)
                  FROM artist_earning_ledger
                  WHERE artist_id IN (?, ?)
                    AND source_type = 'qualified_download'
                    AND status = 'posted'
                ), 0)
                + COALESCE((
                  SELECT SUM(amount)
                  FROM artist_test_adjustments
                  WHERE artist_id IN (?, ?)
                    AND status = 'active'
                    AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
                ), 0)
                - COALESCE((
                  SELECT SUM(amount)
                  FROM withdrawal_requests
                  WHERE artist_id IN (?, ?)
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
              artistProfileId,
              ARTIST_FREE_NET_PER_PLAY,
              ARTIST_FREE_NET_PER_PLAY,
              user.id,
              artistProfileId,
              user.id,
              artistProfileId,
              user.id,
              artistProfileId,
              user.id,
              artistProfileId
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

            const detail = String(e?.message || e || "Unknown database error")
              .replace(/[\r\n]+/g, " ")
              .slice(0, 220);
            return error(
              `Withdrawal diagnostic at ${withdrawalDiagnosticStage}: ${detail}`,
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
        const requestedStatus = String(body.status || "").toLowerCase();
        if (["paid", "completed", "success", "successful"].includes(requestedStatus)) {
          return error("A withdrawal can only be marked Paid after PesaJet confirms the artist payout.", 403);
        }
        await ensureArtistWithdrawalPayoutColumns(env);
        const prior = await env.DB.prepare(`SELECT id, artist_id, amount, status, payout_reference FROM withdrawal_requests${where}`).bind(...values).all();
        withdrawalRows = prior.results || [];
        if (withdrawalRows.some(item => item.payout_reference)) {
          return error("This request already has a PesaJet payout in progress. Its status can only be changed by the verified payment result.", 409);
        }
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
    if (table === "withdrawal_requests" && method === "POST" && !admin) {
      const detail = String(e?.message || e || "Unknown error").replace(/[\\r\\n]+/g, " ").slice(0, 220);
      console.error("Artist withdrawal diagnostic:", withdrawalDiagnosticStage, detail);
      return error(`Withdrawal diagnostic at ${withdrawalDiagnosticStage}: ${detail}`, 500);
    }
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

  const superAdmin = admin.role === "super_admin" || admin.rank === "super_admin";
  const url = new URL(request.url);

  if (path === "/api/admin/ads") {
    if (!superAdmin) return error("Super Admin access required", 403);
    try {
      await env.DB.prepare(`CREATE TABLE IF NOT EXISTS homepage_ads (id TEXT PRIMARY KEY, title TEXT NOT NULL, space_id INTEGER NOT NULL CHECK(space_id IN (1,2)), target_url TEXT, image_url TEXT NOT NULL, fit_mode TEXT NOT NULL DEFAULT 'contain', active INTEGER NOT NULL DEFAULT 1, sort_order INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')))`).run();
      if (request.method === "GET") { const rows=await env.DB.prepare("SELECT * FROM homepage_ads ORDER BY space_id, sort_order, datetime(created_at)").all(); return json({data:rows.results||[],error:null}); }
      if (request.method === "POST") {
        const body=await readBody(request);
        if (body.action === "create_many") {
          const items=Array.isArray(body.items)?body.items:[];
          if(!items.length||items.length>3) return error("Choose between 1 and 3 banners to save together",422);
          const space=Number(items[0]?.space_id);
          if(![1,2].includes(space)||items.some(x=>Number(x.space_id)!==space)) return error("All banners in one save must use the same banner space",422);
          const current=await env.DB.prepare("SELECT COUNT(*) AS total FROM homepage_ads WHERE space_id=?").bind(space).first();
          if(Number(current?.total||0)+items.length>3) return error(`Banner Space ${space} can hold only 3 banners`,422);
          const existing=await env.DB.prepare("SELECT COALESCE(MAX(sort_order),0) AS last_order FROM homepage_ads WHERE space_id=?").bind(space).first();
          const statements=[];
          for(let i=0;i<items.length;i++){
            const x=items[i],id=String(x.id||crypto.randomUUID()),title=String(x.title||"").trim().slice(0,120),image=String(x.image_url||"").trim(),target=String(x.target_url||"").trim(),fit=x.fit_mode==="cover"?"cover":"contain";
            if(!title||!image||image.length>2000) return error("Every banner needs a name and image",422);
            if(target&&!/^https:\/\//i.test(target)) return error("Banner link must use HTTPS",422);
            statements.push(env.DB.prepare("INSERT INTO homepage_ads (id,title,space_id,target_url,image_url,fit_mode,active,sort_order,updated_at) VALUES (?,?,?,?,?,?,1,?,datetime('now'))").bind(id,title,space,target||null,image,fit,Number(existing?.last_order||0)+i+1));
          }
          await env.DB.batch(statements);
          return json({success:true,created:items.length});
        }
        if (body.action === "reorder") {
          const space=Number(body.space_id),items=Array.isArray(body.items)?body.items:[];
          if(![1,2].includes(space)||!items.length||items.length>3) return error("Invalid banner order",422);
          const current=await env.DB.prepare("SELECT id FROM homepage_ads WHERE space_id=? ORDER BY sort_order,datetime(created_at)").bind(space).all();
          const expected=(current.results||[]).map(x=>String(x.id)).sort(),received=items.map(x=>String(x.id||"")).sort();
          if(expected.length!==received.length||expected.some((id,i)=>id!==received[i])||new Set(received).size!==received.length) return error("Banner list changed. Refresh the list and try again.",409);
          const statements=items.map((x,i)=>env.DB.prepare("UPDATE homepage_ads SET sort_order=?,updated_at=datetime('now') WHERE id=? AND space_id=?").bind(i+1,String(x.id),space));
          await env.DB.batch(statements);
          return json({success:true,updated:items.length});
        }
        const id=String(body.id||crypto.randomUUID());
        const title=String(body.title||"").trim().slice(0,120), space=Number(body.space_id), image=String(body.image_url||"").trim();
        const target=String(body.target_url||"").trim(); const fit=body.fit_mode==="cover"?"cover":"contain"; const active=body.active===0||body.active===false?0:1; const sort=Number.isFinite(Number(body.sort_order))?Number(body.sort_order):Date.now();
        if(!title||![1,2].includes(space)||!image||image.length>2000) return error("Banner name, valid space and image are required",422);
        if(target && !/^https:\/\//i.test(target)) return error("Banner link must use HTTPS",422);
        if(!body.id){const count=await env.DB.prepare("SELECT COUNT(*) AS total FROM homepage_ads WHERE space_id=?").bind(space).first();if(Number(count?.total||0)>=3)return error(`Banner Space ${space} can hold only 3 banners`,422);}
        else {const old=await env.DB.prepare("SELECT space_id FROM homepage_ads WHERE id=?").bind(id).first();if(old&&Number(old.space_id)!==space){const count=await env.DB.prepare("SELECT COUNT(*) AS total FROM homepage_ads WHERE space_id=?").bind(space).first();if(Number(count?.total||0)>=3)return error(`Banner Space ${space} already has 3 banners`,422);}}
        await env.DB.prepare(`INSERT INTO homepage_ads (id,title,space_id,target_url,image_url,fit_mode,active,sort_order,updated_at) VALUES (?,?,?,?,?,?,?,?,datetime('now')) ON CONFLICT(id) DO UPDATE SET title=excluded.title,space_id=excluded.space_id,target_url=excluded.target_url,image_url=excluded.image_url,fit_mode=excluded.fit_mode,active=excluded.active,sort_order=excluded.sort_order,updated_at=datetime('now')`).bind(id,title,space,target||null,image,fit,active,sort).run();
        return json({success:true,id});
      }
      if (request.method === "DELETE") { const id=String(url.searchParams.get("id")||""); if(!id)return error("Banner ID required",422); await env.DB.prepare("DELETE FROM homepage_ads WHERE id=?").bind(id).run(); return json({success:true}); }
      return error("Method not allowed",405);
    } catch(e) { console.error("Admin banner operation failed:",e.message); return error("Could not manage homepage banners",500); }
  }

  const artistPayoutMatch = path.match(/^\/api\/admin\/withdrawals\/([^/]+)\/pay$/);
  if (request.method === "POST" && artistPayoutMatch) {
    return artistWithdrawalPayoutRoute(env, path);
  }

  if (request.method === "GET" && path === "/api/admin/withdrawals") {
    try {
      await ensureArtistWithdrawalPayoutColumns(env);
      const result = await env.DB.prepare(`
        SELECT
          wr.*,
          COALESCE(
            (SELECT a.name FROM artists AS a WHERE a.user_id = wr.artist_id LIMIT 1),
            (SELECT a.name FROM artists AS a WHERE a.id = wr.artist_id LIMIT 1),
            (SELECT u.email FROM auth_users AS u WHERE u.id = wr.artist_id LIMIT 1),
            'Unknown Artist'
          ) AS artist_name
        FROM withdrawal_requests AS wr
        ORDER BY datetime(wr.created_at) DESC
        LIMIT 1000
      `).all();

      return json({
        data: result.results || [],
        error: null
      });
    } catch (e) {
      console.error("Admin withdrawals load failed:", e.message);
      return error("Could not load withdrawal requests from the database", 500);
    }
  }

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
        SELECT id, user_id, email, role, rank, active, created_at
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
          SET email = ?, role = ?, rank = ?, active = 1
          WHERE user_id = ?
        `).bind(
          target.email,
          role,
          role === "super_admin" ? "super_admin" : "admin",
          target.id
        ).run();
      } else {
        await env.DB.prepare(`
          INSERT INTO admins (
            id, user_id, email, role, rank, active, created_at
          )
          VALUES (?, ?, ?, ?, ?, 1, datetime('now'))
        `).bind(
          crypto.randomUUID(),
          target.id,
          target.email,
          role,
          role === "super_admin" ? "super_admin" : "admin"
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

      // The submission already consumed its package-cycle slot, including
      // while pending review. Approval must not consume a second slot or fail
      // merely because the artist has since filled the rest of the allowance.
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


// Additive, idempotent migrations for download identity and shared-IP fraud
// protection. Existing download history is retained; old rows remain anonymous.
async function ensureSongActivityTrackingSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS song_download_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      song_id TEXT NOT NULL,
      ip_address TEXT NOT NULL,
      downloaded_at TEXT NOT NULL DEFAULT (datetime('now')),
      listener_user_id TEXT
    )
  `).run();

  const columnsResult = await env.DB.prepare("PRAGMA table_info(song_download_log)").all();
  const columns = new Set((columnsResult.results || []).map(column => String(column.name).toLowerCase()));
  if (!columns.has("listener_user_id")) {
    try {
      await env.DB.prepare("ALTER TABLE song_download_log ADD COLUMN listener_user_id TEXT").run();
    } catch (e) {
      const refreshed = await env.DB.prepare("PRAGMA table_info(song_download_log)").all();
      const refreshedColumns = new Set((refreshed.results || []).map(column => String(column.name).toLowerCase()));
      if (!refreshedColumns.has("listener_user_id")) throw e;
    }
  }

  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_song_download_listener_song_time
    ON song_download_log(listener_user_id, song_id, downloaded_at)
  `).run();
  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_song_download_ip_song_time
    ON song_download_log(ip_address, song_id, downloaded_at)
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS song_ip_activity_guard (
      ip_address TEXT PRIMARY KEY,
      last_activity_at TEXT NOT NULL,
      rapid_count INTEGER NOT NULL DEFAULT 1,
      blocked_until TEXT,
      decision_request_id TEXT,
      last_decision INTEGER NOT NULL DEFAULT 1,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `).run();
  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_song_ip_activity_blocked
    ON song_ip_activity_guard(blocked_until)
  `).run();
}

// This SQL is deliberately shared by download and play recording. Five rapid
// qualifying events from one IP are allowed; the sixth starts a 24-hour block.
// An accepted event after at least one quiet hour starts a fresh rapid window.
function songIpActivityGuardStatement(ip, requestId, songId, duplicateSql, duplicateBinds) {
  return {
    statement: `
      INSERT INTO song_ip_activity_guard
        (ip_address, last_activity_at, rapid_count, blocked_until,
         decision_request_id, last_decision, updated_at)
      SELECT ?, datetime('now'), 1, NULL, ?, 1, datetime('now')
      WHERE EXISTS (SELECT 1 FROM songs WHERE id = ? AND approved = 1)
        AND NOT EXISTS (${duplicateSql})
      ON CONFLICT(ip_address) DO UPDATE SET
        rapid_count = CASE
          WHEN song_ip_activity_guard.blocked_until IS NOT NULL
            AND datetime(song_ip_activity_guard.blocked_until) > datetime('now')
            THEN song_ip_activity_guard.rapid_count
          WHEN datetime(song_ip_activity_guard.last_activity_at) <= datetime('now', '-1 hour')
            THEN 1
          WHEN song_ip_activity_guard.rapid_count < 5
            THEN song_ip_activity_guard.rapid_count + 1
          ELSE song_ip_activity_guard.rapid_count
        END,
        blocked_until = CASE
          WHEN song_ip_activity_guard.blocked_until IS NOT NULL
            AND datetime(song_ip_activity_guard.blocked_until) > datetime('now')
            THEN song_ip_activity_guard.blocked_until
          WHEN datetime(song_ip_activity_guard.last_activity_at) <= datetime('now', '-1 hour')
            THEN NULL
          WHEN song_ip_activity_guard.rapid_count < 5
            THEN NULL
          ELSE datetime('now', '+24 hours')
        END,
        last_activity_at = CASE
          WHEN song_ip_activity_guard.blocked_until IS NOT NULL
            AND datetime(song_ip_activity_guard.blocked_until) > datetime('now')
            THEN song_ip_activity_guard.last_activity_at
          WHEN datetime(song_ip_activity_guard.last_activity_at) <= datetime('now', '-1 hour')
            THEN datetime('now')
          WHEN song_ip_activity_guard.rapid_count < 5
            THEN datetime('now')
          ELSE song_ip_activity_guard.last_activity_at
        END,
        decision_request_id = excluded.decision_request_id,
        last_decision = CASE
          WHEN song_ip_activity_guard.blocked_until IS NOT NULL
            AND datetime(song_ip_activity_guard.blocked_until) > datetime('now')
            THEN 0
          WHEN datetime(song_ip_activity_guard.last_activity_at) <= datetime('now', '-1 hour')
            THEN 1
          WHEN song_ip_activity_guard.rapid_count < 5
            THEN 1
          ELSE 0
        END,
        updated_at = datetime('now')
    `,
    binds: [ip, requestId, songId, ...duplicateBinds]
  };
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
      await ensureArtistTestAdjustmentsTable(env);
      const result = await env.DB.prepare(`
        SELECT
          COALESCE((
            SELECT SUM(net_amount - ?)
            FROM artist_earning_ledger
            WHERE artist_id = ?
              AND source_type = 'qualified_play'
              AND status = 'posted'
          ), 0)
          + COALESCE((
            SELECT SUM(net_amount)
            FROM artist_earning_ledger
            WHERE artist_id = ?
              AND source_type = 'qualified_download'
              AND status = 'posted'
          ), 0)
          + COALESCE((
            SELECT SUM(amount)
            FROM artist_test_adjustments
            WHERE artist_id = ?
              AND status = 'active'
              AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
          ), 0) AS adjustment
      `).bind(ARTIST_FREE_NET_PER_PLAY, user.id, user.id, user.id).first();
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
        const reservedRows = await env.DB.prepare(`
          SELECT amount FROM platform_payouts
          WHERE lower(status) IN ('pending', 'processing')
        `).all();
        const reservedTotal = (reservedRows.results || []).reduce((sum, row) => {
          const fee = getPesaJetDisbursementFee(row.amount);
          return sum + Number(row.amount || 0) + Number(fee || 0);
        }, 0);

        return json({
          data: Math.max(0, Number(result?.total || 0) - reservedTotal),
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
        const completedPayoutRows = await env.DB.prepare(`
          SELECT amount FROM platform_payouts
          WHERE lower(status) IN ('completed','success','successful','paid')
        `).all();
        payouts += (completedPayoutRows.results || []).reduce(
          (sum, row) => sum + Number(getPesaJetDisbursementFee(row.amount) || 0), 0
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

    if (name === "record_song_download") {
      const id = String(body.song_id || "").trim();
      if (!id) return error("song_id is required", 422);

      const ip = String(request.headers.get("CF-Connecting-IP") || "").trim();
      if (!ip) return error("Unable to verify this download request. Please try again.", 400);

      await ensureSongActivityTrackingSchema(env);
      const listenerUserId = user?.id ? String(user.id) : null;
      const requestId = crypto.randomUUID();
      const duplicateSql = `
        SELECT 1
        FROM song_download_log
        WHERE song_id = ?
          AND datetime(downloaded_at) >= datetime('now', '-24 hours')
          AND (
            (? IS NOT NULL AND listener_user_id = ?)
            OR
            (? IS NULL AND listener_user_id IS NULL AND ip_address = ?)
          )
      `;
      const guard = songIpActivityGuardStatement(
        ip, requestId, id, duplicateSql,
        [id, listenerUserId, listenerUserId, listenerUserId, ip]
      );

      const results = await env.DB.batch([
        env.DB.prepare(guard.statement).bind(...guard.binds),
        env.DB.prepare(`
          INSERT INTO song_download_log
            (song_id, ip_address, downloaded_at, listener_user_id)
          SELECT ?, ?, datetime('now'), ?
          WHERE EXISTS (
            SELECT 1 FROM song_ip_activity_guard
            WHERE ip_address = ?
              AND decision_request_id = ?
              AND last_decision = 1
          )
        `).bind(id, ip, listenerUserId, ip, requestId),
        env.DB.prepare(`
          UPDATE songs
          SET downloads = COALESCE(downloads, 0) + 1
          WHERE id = ? AND approved = 1 AND changes() > 0
        `).bind(id)
      ]);

      const recorded = Number(results?.[1]?.meta?.changes || 0) > 0;

      // Only a newly inserted, fraud-qualified log row can create earnings.
      // The unique ledger event key makes retries safe.
      if (recorded) {
        const downloadLogId = Number(results?.[1]?.meta?.last_row_id || 0);
        if (downloadLogId > 0) {
          const songOwner = await env.DB.prepare(
            "SELECT artist_id FROM songs WHERE id = ? AND approved = 1 LIMIT 1"
          ).bind(id).first();
          const artistId = String(songOwner?.artist_id || "").trim();
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
            const packageCode = String(activePackage?.package_name || "free")
              .trim().toLowerCase().replace(/[ -]+/g, "_");
            const earningRates = { free: 0.5, premium: 1, hustler: 1, hit_maker: 2, star: 3 };
            let gross = earningRates[packageCode] ?? EARNINGS_PER_PLAY;

            if (listenerUserId) {
              const listenerSub = await env.DB.prepare(`
                SELECT las.id FROM listener_artist_subscriptions las
                JOIN artists a ON a.id = las.artist_id
                WHERE las.listener_user_id = ?
                  AND (a.id = ? OR a.user_id = ?)
                  AND lower(las.status) = 'active'
                  AND las.expires_at IS NOT NULL
                  AND datetime(las.expires_at) > datetime('now')
                ORDER BY datetime(las.expires_at) DESC LIMIT 1
              `).bind(listenerUserId, artistId, artistId).first();
              if (listenerSub) gross *= 2;
            }

            const commission = Math.round(gross * ARTIST_COMMISSION_RATE * 1000) / 1000;
            const tax = Math.round(gross * ARTIST_TAX_ALLOCATION_RATE * 1000) / 1000;
            const net = Math.round((gross - commission - tax) * 1000) / 1000;
            await env.DB.prepare(`
              INSERT OR IGNORE INTO artist_earning_ledger
                (event_key, artist_id, source_type, source_id, gross_amount,
                 commission_amount, tax_amount, pesajet_fee_amount, net_amount,
                 currency, status, note, occurred_at)
              VALUES (?, ?, 'qualified_download', ?, ?, ?, ?, 0, ?, 'UGX',
                      'posted', 'Package-rate gross per qualified download; 20% commission and 5% tax allocation',
                      datetime('now'))
            `).bind(`song-download:${downloadLogId}`,artistId,String(downloadLogId),gross,commission,tax,net).run();
          }
        }
      }

      const song = await env.DB.prepare(
        "SELECT COALESCE(downloads, 0) AS downloads FROM songs WHERE id = ? AND approved = 1 LIMIT 1"
      ).bind(id).first();
      if (!song) return error("Approved song not found", 404);

      return json({
        data: {
          recorded,
          downloads: Number(song.downloads || 0),
          reason: recorded ? "qualified" : "duplicate_or_shared_ip_fraud_limit"
        },
        error: null
      });
    }

    if (name === "record_song_play") {
      await ensureSongActivityTrackingSchema(env);
      const id = String(body.song_id || "").trim();
      if (!id) return error("song_id is required", 422);

      const ip = String(request.headers.get("CF-Connecting-IP") || "").trim();
      if (!ip) return error("Unable to verify this play request. Please try again.", 400);

      const listenerUserId = user?.id ? String(user.id) : null;
      const requestId = crypto.randomUUID();
      const duplicateSql = `
        SELECT 1
        FROM song_play_log
        WHERE song_id = ?
          AND datetime(played_at) >= datetime('now', '-24 hours')
          AND (
            (? IS NOT NULL AND user_id = ?)
            OR
            (? IS NULL AND user_id IS NULL AND ip_address = ?)
          )
      `;
      const guard = songIpActivityGuardStatement(
        ip, requestId, id, duplicateSql,
        [id, listenerUserId, listenerUserId, listenerUserId, ip]
      );

      // The shared IP guard is combined across downloads and qualified plays.
      // Duplicate song events do not consume the shared-IP allowance.
      const results = await env.DB.batch([
        env.DB.prepare(guard.statement).bind(...guard.binds),
        env.DB.prepare(`
          INSERT INTO song_play_log (song_id, ip_address, played_at, user_id)
          SELECT ?, ?, datetime('now'), ?
          WHERE EXISTS (
            SELECT 1 FROM song_ip_activity_guard
            WHERE ip_address = ?
              AND decision_request_id = ?
              AND last_decision = 1
          )
        `).bind(id, ip, listenerUserId, ip, requestId),
        env.DB.prepare(`
          UPDATE songs
          SET plays = COALESCE(plays, 0) + 1
          WHERE id = ? AND approved = 1 AND changes() > 0
        `).bind(id)
      ]);

      const inserted = Number(results?.[1]?.meta?.changes || 0) > 0;
      const incremented = Number(results?.[2]?.meta?.changes || 0) > 0;

      // A newly inserted play log is the sole trigger for the earnings ledger.
      if (inserted && incremented) {
        const playLogId = Number(results?.[1]?.meta?.last_row_id || 0);
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
            const packageCode = String(activePackage?.package_name || "free")
              .trim().toLowerCase().replace(/[ -]+/g, "_");
            const earningRates = { free: 0.5, premium: 1, hustler: 1, hit_maker: 2, star: 3 };
            let gross = earningRates[packageCode] ?? EARNINGS_PER_PLAY;

            if (listenerUserId) {
              const listenerSub = await env.DB.prepare(`
                SELECT las.id FROM listener_artist_subscriptions las
                JOIN artists a ON a.id = las.artist_id
                WHERE las.listener_user_id = ?
                  AND (a.id = ? OR a.user_id = ?)
                  AND lower(las.status) = 'active'
                  AND las.expires_at IS NOT NULL
                  AND datetime(las.expires_at) > datetime('now')
                ORDER BY datetime(las.expires_at) DESC LIMIT 1
              `).bind(listenerUserId, artistId, artistId).first();
              if (listenerSub) gross *= 2;
            }

            // Keep mill-UGX precision so Free net earnings remain 0.375 rather
            // than rounding each play down to 0.37 before the balance is summed.
            const commission = Math.round(gross * ARTIST_COMMISSION_RATE * 1000) / 1000;
            const tax = Math.round(gross * ARTIST_TAX_ALLOCATION_RATE * 1000) / 1000;
            const artistNet = Math.round((gross - commission - tax) * 1000) / 1000;
            const artist = await env.DB.prepare('SELECT referring_admin_id FROM artists WHERE id=? LIMIT 1').bind(artistId).first();
            const referralAdminId = String(artist?.referring_admin_id || '').trim();
            const adminShare = referralAdminId ? Math.round(gross * ADMIN_STREAM_COMMISSION_RATE * 1000) / 1000 : 0;
            const platformShare = Math.round((gross * (referralAdminId ? ARTIST_STREAM_PLATFORM_RATE : ARTIST_COMMISSION_RATE)) * 1000) / 1000;
            const net = Math.round((gross - platformShare - tax - adminShare) * 1000) / 1000;
            await env.DB.prepare(`
              INSERT OR IGNORE INTO artist_earning_ledger
                (event_key, artist_id, source_type, source_id, gross_amount,
                 commission_amount, tax_amount, pesajet_fee_amount, net_amount,
                 currency, status, note, occurred_at)
              VALUES (?, ?, 'qualified_play', ?, ?, ?, ?, 0, ?, 'UGX',
                      'posted', 'Qualified play: 75% artist, 15% platform, 5% referring admin where assigned, 5% tax',
                      datetime('now'))
            `).bind(`song-play:${playLogId}`,artistId,String(playLogId),gross,platformShare,tax,net).run();
            if (referralAdminId) await creditAdminCommission(env,{eventKey:`stream-play:${playLogId}`,adminId:referralAdminId,artistId,sourceType:'qualified_play',sourceId:String(playLogId),gross,rate:ADMIN_STREAM_COMMISSION_RATE,note:'5% of gross qualified streaming earnings'});
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
          SET email = ?, role = ?, rank = ?, active = 1
          WHERE user_id = ?
        `).bind(
          targetUser.email,
          role,
          targetUser.id
        ).run();
      } else {
        await env.DB.prepare(`
          INSERT INTO admins (
            id, user_id, email, role, rank, active, created_at
          )
          VALUES (?, ?, ?, ?, ?, 1, datetime('now'))
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


function getArtistUploadCycle(anchorValue, nowValue = new Date()) {
  const anchor = new Date(anchorValue);
  const now = new Date(nowValue);
  if (!Number.isFinite(anchor.getTime())) throw new Error("Missing upload-cycle anchor");
  const monthIndex = (now.getUTCFullYear() - anchor.getUTCFullYear()) * 12
    + now.getUTCMonth() - anchor.getUTCMonth();
  const makeBoundary = (monthOffset) => {
    const monthStart = new Date(Date.UTC(
      anchor.getUTCFullYear(),
      anchor.getUTCMonth() + monthOffset,
      1,
      anchor.getUTCHours(),
      anchor.getUTCMinutes(),
      anchor.getUTCSeconds(),
      anchor.getUTCMilliseconds()
    ));
    const lastDay = new Date(Date.UTC(
      monthStart.getUTCFullYear(),
      monthStart.getUTCMonth() + 1,
      0
    )).getUTCDate();
    monthStart.setUTCDate(Math.min(anchor.getUTCDate(), lastDay));
    return monthStart;
  };
  let cycleStart = makeBoundary(monthIndex);
  if (cycleStart > now) cycleStart = makeBoundary(monthIndex - 1);
  const nextReset = makeBoundary(monthIndex + (cycleStart.getTime() === makeBoundary(monthIndex).getTime() ? 1 : 0));
  return { cycleStart: cycleStart.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, ""), nextReset: nextReset.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, "") };
}

async function uploadPreflightRoute(request, env) {
  if (!["GET", "POST"].includes(request.method)) return error("Method not allowed", 405);
  const user = await currentUser(request, env);
  if (!user) return error("Authentication required", 401);

  let body = {};
  if (request.method === "POST") {
    body = await readBody(request);
    const audioSize = Number(body.audio_size || 0);
    const coverSize = Number(body.cover_size || 0);
    if (!Number.isSafeInteger(audioSize) || audioSize <= 0 || audioSize > 50 * 1024 * 1024) return error("Audio file must be between 1 byte and 50 MB.", 413);
    if (!Number.isSafeInteger(coverSize) || coverSize <= 0 || coverSize > 5 * 1024 * 1024) return error("Cover image must be between 1 byte and 5 MB.", 413);
  }

  try {
    const artist = await env.DB.prepare("SELECT id FROM artists WHERE user_id = ? LIMIT 1").bind(user.id).first();
    if (!artist) return error("Artist profile not found.", 403);

    const entitlement = await syncArtistPremiumEntitlement(env, user.id, artist.id);
    const packageCode = String(entitlement?.packageCode || "free").toLowerCase();
    const limit = ARTIST_PACKAGE_UPLOAD_LIMITS[packageCode] ?? ARTIST_PACKAGE_UPLOAD_LIMITS.free;

    // Each artist's upload month is anchored to their own package activation
    // date. Free accounts use their account creation date; paid accounts use
    // the confirmed payment date of their current active package.
    const anchorRow = await env.DB.prepare(`
      SELECT COALESCE(
        (SELECT COALESCE(paid_at, created_at) FROM premium_subscriptions
         WHERE user_id = ? AND lower(status) = 'active' AND expires_at IS NOT NULL
           AND datetime(expires_at) > datetime('now')
         ORDER BY datetime(COALESCE(paid_at, created_at)) DESC, datetime(created_at) DESC
         LIMIT 1),
        (SELECT created_at FROM auth_users WHERE id = ? LIMIT 1)
      ) AS cycle_anchor
    `).bind(user.id, user.id).first();
    if (!anchorRow?.cycle_anchor) return error("We could not verify your upload-cycle date. No files were uploaded. Please try again shortly.", 503);
    const cycle = getArtistUploadCycle(anchorRow.cycle_anchor);

    const count = await env.DB.prepare(`
      SELECT COUNT(*) AS total
      FROM songs
      WHERE artist_id = ?
        AND COALESCE(lower(review_status), CASE WHEN approved = 1 THEN 'approved' ELSE 'pending' END) != 'rejected'
        AND datetime(created_at) >= CASE
          WHEN datetime(?) > datetime(?) THEN datetime(?) ELSE datetime(?) END
        AND datetime(created_at) < datetime(?)
    `).bind(
      user.id,
      cycle.cycleStart, PACKAGE_LIMITS_EFFECTIVE_AT,
      PACKAGE_LIMITS_EFFECTIVE_AT, cycle.cycleStart,
      cycle.nextReset
    ).first();

    if (!count || count.total === undefined || count.total === null) {
      return error("We could not verify your monthly upload count. No files were uploaded. Please try again shortly.", 503);
    }
    const used = Number(count.total);
    if (!Number.isFinite(used)) return error("We could not verify your monthly upload count. No files were uploaded. Please try again shortly.", 503);

    const allowed = used < limit;
    const label = limit >= Number.MAX_SAFE_INTEGER ? "unlimited" : String(limit);
    const message = allowed
      ? `${Math.max(0, limit - used)} submission${limit - used === 1 ? "" : "s"} remaining in this package cycle.`
      : `Your ${packageCode.replace(/_/g, " ")} package submission limit has been reached (${used}/${label}). Rejected submissions do not count. You can upgrade your package or submit again after ${cycle.nextReset} UTC.`;

    const result = {
      allowed,
      package_code: packageCode,
      used,
      limit: limit >= Number.MAX_SAFE_INTEGER ? null : limit,
      remaining: limit >= Number.MAX_SAFE_INTEGER ? null : Math.max(0, limit - used),
      cycle_start: cycle.cycleStart,
      reset_at: cycle.nextReset,
      message
    };
    if (!allowed && request.method === "POST") return json({ ...result, error: message }, 429);
    return json(result);
  } catch (e) {
    console.error("Artist upload preflight failed:", e.message);
    return error("We could not verify your package or upload count. No files were uploaded. Please try again shortly.", 503);
  }
}

async function publicAdsRoute(request, env) {
  if(request.method!=="GET") return error("Method not allowed",405);
  try {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS homepage_ads (id TEXT PRIMARY KEY, title TEXT NOT NULL, space_id INTEGER NOT NULL CHECK(space_id IN (1,2)), target_url TEXT, image_url TEXT NOT NULL, fit_mode TEXT NOT NULL DEFAULT 'contain', active INTEGER NOT NULL DEFAULT 1, sort_order INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')))`).run();
    const rows=await env.DB.prepare("SELECT id,title,space_id,target_url,image_url,fit_mode,active,sort_order FROM homepage_ads WHERE active=1 ORDER BY space_id,sort_order,datetime(created_at)").all();
    return json({data:rows.results||[],error:null},200,{"Cache-Control":"no-store, no-cache, must-revalidate"});
  } catch(e) { console.error("Public banners load failed:",e.message); return json({data:[],error:"Could not load homepage banners"},500,{"Cache-Control":"no-store"}); }
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

  if (!["audio", "covers", "avatars", "news", "ads"].includes(bucket)) {
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
    if (bucket === "ads" && !(await isSuperAdmin(env, user))) {
      return error("Super Admin access required", 403);
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

// PesaJet collection-risk safeguard. It detects three distinct Ugandan
// mobile numbers sharing the same first eight subscriber digits and having
// sequential/near-sequential final digits within a rolling 24-hour window.
// Repeating the same number does not count as another distinct number.
let pesajetRiskTableReady = false;
let pesajetRiskTablePromise = null;

async function ensurePesaJetRiskTable(env) {
  if (pesajetRiskTableReady) return;
  if (!pesajetRiskTablePromise) {
    pesajetRiskTablePromise = env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS pesajet_collection_risk_attempts (
        id TEXT PRIMARY KEY,
        reference TEXT NOT NULL,
        actor_key TEXT NOT NULL,
        phone_number TEXT NOT NULL,
        phone_prefix TEXT NOT NULL,
        phone_suffix INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `).run().then(async () => {
      await env.DB.prepare(`
        CREATE INDEX IF NOT EXISTS idx_pesajet_risk_actor_time
        ON pesajet_collection_risk_attempts(actor_key, created_at)
      `).run();
      pesajetRiskTableReady = true;
    }).catch((err) => {
      pesajetRiskTablePromise = null;
      throw err;
    });
  }
  await pesajetRiskTablePromise;
}

async function pesajetRiskHash(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(String(value))
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function checkPesaJetCollectionRisk(request, env, phone, userId, reference) {
  await ensurePesaJetRiskTable(env);
  const normalizedPhone = String(phone || "").replace(/\D/g, "");
  if (!/^256\d{9}$/.test(normalizedPhone)) return { blocked: false };

  const actorKeys = [];
  if (userId !== undefined && userId !== null && String(userId).trim()) {
    actorKeys.push(await pesajetRiskHash(`user:${String(userId).trim()}`));
  }
  const clientIp = String(request.headers.get("CF-Connecting-IP") || "").trim();
  if (clientIp) actorKeys.push(await pesajetRiskHash(`ip:${clientIp}`));

  // Fail open only if the request has neither an authenticated user nor an
  // edge-provided client IP; never group unrelated customers under one key.
  if (!actorKeys.length) return { blocked: false };

  const prefix = normalizedPhone.slice(0, 8);
  const suffix = Number(normalizedPhone.slice(-1));
  const timestamp = new Date().toISOString();
  await env.DB.batch(actorKeys.map((actorKey) =>
    env.DB.prepare(`
      INSERT INTO pesajet_collection_risk_attempts
        (id, reference, actor_key, phone_number, phone_prefix, phone_suffix, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      crypto.randomUUID(), reference, actorKey, `+${normalizedPhone}`,
      prefix, suffix, timestamp
    )
  ));

  await env.DB.prepare(`
    DELETE FROM pesajet_collection_risk_attempts
    WHERE created_at < datetime('now', '-48 hours')
  `).run();

  const placeholders = actorKeys.map(() => "?").join(",");
  const recent = await env.DB.prepare(`
    SELECT DISTINCT phone_number, phone_suffix
    FROM pesajet_collection_risk_attempts
    WHERE actor_key IN (${placeholders})
      AND phone_prefix = ?
      AND datetime(created_at) >= datetime('now', '-24 hours')
  `).bind(...actorKeys, prefix).all();

  const suffixes = [...new Set(
    (recent.results || []).map((row) => Number(row.phone_suffix))
  )];
  if (suffixes.length < 3) return { blocked: false };

  const spread = Math.max(...suffixes) - Math.min(...suffixes);
  const sequentialOrNearSequential = spread <= 2 || spread >= 8;
  if (!sequentialOrNearSequential) return { blocked: false };

  console.warn("PesaJet collection locally blocked by sequential-number safeguard", {
    reference,
    distinctNumbers: suffixes.length,
    windowHours: 24
  });
  return {
    blocked: true,
    message: "For payment security, this request was paused because several similar mobile-money numbers were used within 24 hours. Please wait 24 hours or contact NileSoniQ support if this is a genuine payment."
  };
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

// PesaJet disbursement fee schedule confirmed by the NileSoniQ owner.
// These fees are paid by the platform from its remaining wallet balance.
function getPesaJetDisbursementFee(amount) {
  const value = Number(amount);
  if (!Number.isFinite(value) || value < 500) return null;
  if (value <= 2500) return 330;
  if (value <= 5000) return 440;
  if (value <= 15000) return 700;
  if (value <= 30000) return 880;
  if (value <= 45000) return 1210;
  if (value <= 60000) return 1500;
  if (value <= 125000) return 1925;
  if (value <= 250000) return 3575;
  if (value <= 500000) return 7000;
  if (value <= 1000000) return 12500;
  if (value <= 2000000) return 15000;
  if (value <= 4000000) return 18000;
  if (value <= 7000000) return 20000;
  return null;
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
  const scheduledPayoutFee = type === "disbursement"
    ? getPesaJetDisbursementFee(
        (await env.DB.prepare("SELECT amount FROM platform_payouts WHERE reference = ?").bind(reference).first())?.amount
      )
    : null;
  const effectivePayoutFee = feeKnown ? feeNumber : scheduledPayoutFee;
  const feeValue = feeKnown ? feeNumber : (effectivePayoutFee ?? 0);
  const ledgerStatus = feeKnown || (type === "disbursement" && scheduledPayoutFee !== null) ? "posted" : "fee_unverified";

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
          SELECT amount FROM platform_deposits WHERE reference = ?
        )),
        updated_at = datetime('now')
        WHERE id = (SELECT id FROM platform_wallet ORDER BY created_at LIMIT 1)
          AND changes() > 0
          AND ? IN ('COMPLETED', 'SUCCESS', 'SUCCESSFUL', 'PAID')
      `).bind(reference, normalized),
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
          ? "Successful collection. PesaJet collection fee is charged to the mobile-money balance, not deducted from the platform wallet."
          : "Successful collection. PesaJet collection fee is charged to the mobile-money balance; provider fee detail was not supplied in this event.",
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
    `).bind(reference, feeValue, normalized),
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
        : scheduledPayoutFee !== null
          ? "Completed payout amount recorded with the PesaJet disbursement fee from the confirmed fee schedule."
          : "Completed payout amount recorded. PesaJet disbursement fee is not confirmed and no schedule tier is available; reconcile manually.",
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
  await ensureAdminReferralSchema(env);
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
  const reference = `NILESONIQ-PREMIUM-${paymentReferenceName(artist.name)}-${crypto.randomUUID().replace(/-/g, "").slice(0, 16).toUpperCase()}`;
  const riskCheck = await checkPesaJetCollectionRisk(request, env, phone, user.id, reference);
  if (riskCheck.blocked) return error(riskCheck.message, 429);
  const description = `NileSoniQ Premium Upgrade - ${artist.name || "Artist"}`.slice(0, 250);
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await env.DB.prepare(`
    INSERT INTO premium_subscriptions
      (id,user_id,artist_id,amount,currency,provider,phone_number,reference,status,created_at,package_name,referring_admin_id)
    SELECT ?,?,?,?,'UGX',?,?,?,'pending',?,?,referring_admin_id FROM artists WHERE id=?
  `).bind(id,user.id,artist.id,packageAmount,provider,phone,reference,now,packageCode,artist.id).run();

  let response, result;
  try {
    response = await fetch(`${baseUrl}/payments`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
      body: JSON.stringify({ type: "COLLECTION", amount: packageAmount, currency: "UGX", phoneNumber: phone, provider, reference, description, idempotencyKey: `nilesoniq-${reference}` })
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
    SELECT id, user_id, artist_id, amount, currency, status, provider_transaction_id,
           referring_admin_id, initiated_by_admin_id
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

    // PesaJet may report a customer collection total above the selected
    // package price (for example, UGX 10,350 for a UGX 10,000 package).
    // The package price remains the entitlement amount; any higher confirmed
    // UGX collection is accepted, while the package whitelist and transaction
    // reference checks below continue to protect entitlement activation.
    const feeValue = confirmedFee === null || confirmedFee === undefined || confirmedFee === ""
      ? null
      : Number(confirmedFee);
    const feeSupplied = feeValue !== null;
    const feeValid = !feeSupplied || (Number.isFinite(feeValue) && feeValue >= 0 && feeValue <= amount);
    if (
      !Number.isFinite(amount) || !Number.isFinite(expectedAmount) || amount < expectedAmount || !currency ||
      !feeValid || currency !== expectedCurrency ||
      ![5000,10000,20000,30000].includes(expectedAmount) || expectedCurrency !== "UGX"
    ) {
      console.error("Premium payment confirmation failed amount/currency validation", {
        reference: ref,
        receivedAmount: Number.isFinite(amount) ? amount : null,
        receivedCurrency: currency || null,
        expectedAmount,
        expectedCurrency,
        feeSupplied,
        receivedFee: feeSupplied ? feeValue : null
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
          feeSupplied ? feeValue : 0,
          feeSupplied ? "posted" : "fee_unverified",
          feeSupplied
            ? "Premium subscription confirmed. Actual PesaJet fee supplied by the confirmed provider event."
            : "Premium subscription confirmed. Actual PesaJet collection fee was not supplied by the confirmed transaction event; zero here does not mean fee-free."
        ),
        env.DB.prepare(`
          UPDATE platform_wallet
          SET balance = MAX(0, balance + ? - ?),
              updated_at = datetime('now')
          WHERE id = (SELECT id FROM platform_wallet ORDER BY created_at LIMIT 1)
            AND changes() > 0
        `).bind(amount, feeSupplied ? feeValue : 0)
      ]);
      const packageReferrer = String(payment.referring_admin_id || '').trim();
      if (packageReferrer) await creditAdminCommission(env,{eventKey:`package-payment:${payment.id}`,adminId:packageReferrer,artistId,sourceType:'artist_package',sourceId:payment.id,gross:expectedAmount,rate:ADMIN_PACKAGE_COMMISSION_RATE,note:'20% of confirmed paid artist package transaction'});
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
  const rawFee = data.fee ?? data.transactionFee ?? data.transaction_fee ??
    payload.fee ?? payload.transactionFee ?? payload.transaction_fee ??
    transaction.fee ?? transaction.transactionFee ?? transaction.transaction_fee ?? null;
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
    const featureResult = await applyFeaturePaymentStatus(env, reference, status, transactionId, webhookPayment.amount, webhookPayment.currency, webhookPayment.fee);
    if (featureResult.matched) return json({received:true, featurePayment:true, applied:Boolean(featureResult.changed)});
    const paidSignupResult = (reference.startsWith("NILESONIQ-SIGNUP-") || reference.startsWith("NILESONIQ-ARTIST-REGISTRATION-"))
      ? await completePaidArtistSignup(env, reference, status, transactionId, webhookPayment.amount, webhookPayment.currency,
          payload?.message || payload?.description || payload?.reason || payload?.failureMessage || payload?.failure_message || "")
      : { matched: false };
    if (paidSignupResult.matched) {
      console.info("NileSoniQ paid signup webhook processed.",{reference,status,changed:Boolean(paidSignupResult.changed),reason:paidSignupResult.reason||null});
    }
    const artistWithdrawalResult = reference.startsWith("NILESONIQ-ARTIST-WITHDRAWAL-")
      ? await applyArtistWithdrawalPaymentStatus(
          env,
          reference,
          status,
          transactionId,
          webhookPayment.amount,
          webhookPayment.currency,
          payload?.message || payload?.description || payload?.reason || payload?.failureMessage || payload?.failure_message || ""
        )
      : { matched: false, changed: false };
    if (artistWithdrawalResult.matched) {
      console.info("NileSoniQ artist withdrawal webhook processed.", { reference, status, changed: Boolean(artistWithdrawalResult.changed), reason: artistWithdrawalResult.reason || null });
    }

    // A reference belongs to one transaction table; unmatched updates are no-ops.
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


async function artistPostsRoute(request, env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS artist_posts (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, artist_id TEXT NOT NULL,
    content TEXT NOT NULL, image_url TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  const user = request.method === 'GET' && new URL(request.url).searchParams.get('mine') === '1'
    ? await currentUser(request, env) : null;
  if (request.method === 'GET') {
    const mine = new URL(request.url).searchParams.get('mine') === '1';
    if (mine && !user) return error('Authentication required',401);
    const rows = mine
      ? await env.DB.prepare(`SELECT p.id,p.user_id,p.artist_id,p.content,p.image_url,p.created_at,COALESCE(a.name,'NileSoniQ Artist') artist_name,a.avatar_url FROM artist_posts p LEFT JOIN artists a ON a.id=p.artist_id WHERE p.user_id=? ORDER BY datetime(p.created_at) DESC LIMIT 100`).bind(user.id).all()
      : await env.DB.prepare(`SELECT p.id,p.user_id,p.artist_id,p.content,p.image_url,p.created_at,COALESCE(a.name,'NileSoniQ Artist') artist_name,a.avatar_url FROM artist_posts p LEFT JOIN artists a ON a.id=p.artist_id ORDER BY datetime(p.created_at) DESC LIMIT 100`).all();
    return json({data: rows.results || []});
  }
  const authenticated = await currentUser(request, env);
  if (!authenticated) return error('Authentication required',401);
  if (request.method === 'POST') {
    const body = await readBody(request);
    const content = String(body.content || '').trim().slice(0,2000);
    const imageUrl = String(body.image_url || '').trim();
    if (!content && !imageUrl) return error('Write something or add a picture before posting.',422);
    if (imageUrl && !/^https:\/\//i.test(imageUrl)) return error('Post picture must use HTTPS.',422);
    const artist = await env.DB.prepare('SELECT id FROM artists WHERE user_id=? LIMIT 1').bind(authenticated.id).first();
    if (!artist) return error('Artist profile not found.',403);
    const id = crypto.randomUUID();
    await env.DB.prepare(`INSERT INTO artist_posts (id,user_id,artist_id,content,image_url,created_at) VALUES (?,?,?,?,?,datetime('now'))`).bind(id,authenticated.id,artist.id,content,imageUrl||null).run();
    const row = await env.DB.prepare(`SELECT p.id,p.user_id,p.artist_id,p.content,p.image_url,p.created_at,COALESCE(a.name,'NileSoniQ Artist') artist_name,a.avatar_url FROM artist_posts p LEFT JOIN artists a ON a.id=p.artist_id WHERE p.id=?`).bind(id).first();
    return json({data:row},201);
  }
  if (request.method === 'DELETE') {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS artist_post_comments (id TEXT PRIMARY KEY, post_id TEXT NOT NULL, user_id TEXT NOT NULL, comment TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))` ).run();
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS artist_post_reactions (id TEXT PRIMARY KEY, post_id TEXT NOT NULL, user_id TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(post_id,user_id))`).run();
    const id = new URL(request.url).searchParams.get('id') || '';
    if (!id) return error('Post ID is required.',422);
    const owned = await env.DB.prepare('SELECT id FROM artist_posts WHERE id=? AND user_id=?').bind(id,authenticated.id).first();
    if (!owned) return error('Post not found or not yours.',404);
    await env.DB.prepare('DELETE FROM artist_post_comments WHERE post_id=?').bind(id).run();
    await env.DB.prepare('DELETE FROM artist_post_reactions WHERE post_id=?').bind(id).run();
    await env.DB.prepare('DELETE FROM artist_posts WHERE id=? AND user_id=?').bind(id,authenticated.id).run();
    return json({success:true});
  }
  return error('Method not allowed',405);
}

async function artistPostInteractionsRoute(request, env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS artist_post_comments (
    id TEXT PRIMARY KEY, post_id TEXT NOT NULL, user_id TEXT NOT NULL, comment TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_artist_post_comments_post ON artist_post_comments(post_id, created_at)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS artist_post_reactions (
    id TEXT PRIMARY KEY, post_id TEXT NOT NULL, user_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(post_id,user_id)
  )`).run();
  const url = new URL(request.url);
  const postId = String(url.searchParams.get('post_id') || '').trim();
  if (!postId) return error('Post ID is required.',422);
  const post = await env.DB.prepare('SELECT id FROM artist_posts WHERE id=?').bind(postId).first();
  if (!post) return error('Post not found.',404);
  if (request.method === 'GET') {
    const user = await currentUser(request, env);
    const comments = await env.DB.prepare(`SELECT c.id,c.post_id,c.user_id,c.comment,c.created_at,COALESCE(a.name,u.email,'NileSoniQ listener') author_name FROM artist_post_comments c LEFT JOIN auth_users u ON u.id=c.user_id LEFT JOIN artists a ON a.user_id=c.user_id WHERE c.post_id=? ORDER BY datetime(c.created_at) ASC LIMIT 100`).bind(postId).all();
    const counts = await env.DB.prepare('SELECT COUNT(*) AS total FROM artist_post_reactions WHERE post_id=?').bind(postId).first();
    let reacted = false;
    if (user) reacted = !!(await env.DB.prepare('SELECT id FROM artist_post_reactions WHERE post_id=? AND user_id=?').bind(postId,user.id).first());
    return json({comments:comments.results||[],reaction_count:Number(counts?.total||0),reacted});
  }
  const user = await currentUser(request, env);
  if (!user) return error('Sign in to comment or react.',401);
  if (request.method === 'POST') {
    const body = await readBody(request);
    if (String(body.action||'') === 'comment') {
      const comment = String(body.comment||'').trim().slice(0,1000);
      if (!comment) return error('Write a comment first.',422);
      const id=crypto.randomUUID();
      await env.DB.prepare('INSERT INTO artist_post_comments (id,post_id,user_id,comment) VALUES (?,?,?,?)').bind(id,postId,user.id,comment).run();
      return json({success:true,id},201);
    }
    if (String(body.action||'') === 'react') {
      const existing=await env.DB.prepare('SELECT id FROM artist_post_reactions WHERE post_id=? AND user_id=?').bind(postId,user.id).first();
      if (existing) await env.DB.prepare('DELETE FROM artist_post_reactions WHERE id=?').bind(existing.id).run();
      else await env.DB.prepare('INSERT INTO artist_post_reactions (id,post_id,user_id) VALUES (?,?,?)').bind(crypto.randomUUID(),postId,user.id).run();
      const count=await env.DB.prepare('SELECT COUNT(*) AS total FROM artist_post_reactions WHERE post_id=?').bind(postId).first();
      return json({success:true,reacted:!existing,reaction_count:Number(count?.total||0)});
    }
    return error('Unsupported interaction.',422);
  }
  if (request.method === 'DELETE') {
    const commentId=String(url.searchParams.get('comment_id')||'');
    if (!commentId) return error('Comment ID is required.',422);
    const result=await env.DB.prepare('DELETE FROM artist_post_comments WHERE id=? AND user_id=?').bind(commentId,user.id).run();
    return Number(result?.meta?.changes||0)?json({success:true}):error('Comment not found or not yours.',404);
  }
  return error('Method not allowed',405);
}

async function artistMessagesRoute(request, env) {
  const user = await currentUser(request, env);
  if (!user) return error("Authentication required", 401);
  const myArtist = await env.DB.prepare("SELECT id FROM artists WHERE user_id=? LIMIT 1").bind(user.id).first();
  if (!myArtist) return error("Only artist accounts can use artist messaging.", 403);
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS artist_messages (
    id TEXT PRIMARY KEY,
    sender_user_id TEXT NOT NULL,
    recipient_user_id TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    read_at TEXT
  )`).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_artist_messages_pair ON artist_messages(sender_user_id,recipient_user_id,created_at)").run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_artist_messages_recipient ON artist_messages(recipient_user_id,read_at)").run();
  const url = new URL(request.url);
  if (request.method === "GET") {
    const otherId = String(url.searchParams.get("with_user_id") || "").trim();
    if (otherId) {
      if (otherId === user.id) return error("You cannot message your own account.", 422);
      const other = await env.DB.prepare("SELECT user_id,name,location FROM artists WHERE user_id=? LIMIT 1").bind(otherId).first();
      if (!other) return error("Artist not found.", 404);
      const rows = await env.DB.prepare(`SELECT id,sender_user_id,recipient_user_id,message,created_at FROM artist_messages
        WHERE (sender_user_id=? AND recipient_user_id=?) OR (sender_user_id=? AND recipient_user_id=?)
        ORDER BY datetime(created_at) ASC LIMIT 300`).bind(user.id,otherId,otherId,user.id).all();
      await env.DB.prepare("UPDATE artist_messages SET read_at=datetime('now') WHERE sender_user_id=? AND recipient_user_id=? AND read_at IS NULL").bind(otherId,user.id).run();
      return json({artist:other,messages:(rows.results||[]).map(m=>({...m,is_mine:m.sender_user_id===user.id}))});
    }
    const artists = await env.DB.prepare(`SELECT user_id,name,location,avatar_url FROM artists
      WHERE user_id<>? AND user_id IS NOT NULL AND COALESCE(name,'')<>'' ORDER BY name COLLATE NOCASE LIMIT 300`).bind(user.id).all();
    return json({artists:artists.results||[]});
  }
  if (request.method === "POST") {
    const body = await readBody(request);
    const recipient = String(body.recipient_user_id||"").trim();
    const message = String(body.message||"").trim().slice(0,3000);
    if (!recipient || recipient===user.id) return error("Choose another artist to message.",422);
    if (!message) return error("Write a message first.",422);
    const other = await env.DB.prepare("SELECT user_id FROM artists WHERE user_id=? LIMIT 1").bind(recipient).first();
    if (!other) return error("The recipient must be an artist account.",404);
    const id=crypto.randomUUID();
    await env.DB.prepare("INSERT INTO artist_messages (id,sender_user_id,recipient_user_id,message) VALUES (?,?,?,?)").bind(id,user.id,recipient,message).run();
    return json({success:true,id},201);
  }
  return error("Method not allowed",405);
}

async function artistFollowsRoute(request, env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS artist_follows (
    id TEXT PRIMARY KEY, follower_user_id TEXT NOT NULL, artist_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(follower_user_id,artist_id)
  )`).run();
  const user = await currentUser(request, env);
  if (!user) return error('Authentication required',401);
  const url = new URL(request.url);
  if (request.method === 'GET') {
    const artistId = String(url.searchParams.get('artist_id') || '').trim();
    if (artistId) {
      const row = await env.DB.prepare('SELECT id FROM artist_follows WHERE follower_user_id=? AND artist_id=?').bind(user.id,artistId).first();
      return json({following:!!row});
    }
    const rows = await env.DB.prepare('SELECT artist_id FROM artist_follows WHERE follower_user_id=? ORDER BY created_at DESC').bind(user.id).all();
    return json({data:rows.results || []});
  }
  const body = request.method === 'POST' ? await readBody(request) : {};
  const artistId = String(body.artist_id || url.searchParams.get('artist_id') || '').trim();
  if (!artistId) return error('Artist ID is required.',422);
  const artist = await env.DB.prepare('SELECT id,user_id FROM artists WHERE id=? LIMIT 1').bind(artistId).first();
  if (!artist) return error('Artist not found.',404);
  if (String(artist.user_id) === String(user.id)) return error('You cannot follow your own artist account.',422);
  if (request.method === 'POST') {
    await env.DB.prepare('INSERT OR IGNORE INTO artist_follows (id,follower_user_id,artist_id) VALUES (?,?,?)').bind(crypto.randomUUID(),user.id,artistId).run();
    return json({success:true,following:true});
  }
  if (request.method === 'DELETE') {
    await env.DB.prepare('DELETE FROM artist_follows WHERE follower_user_id=? AND artist_id=?').bind(user.id,artistId).run();
    return json({success:true,following:false});
  }
  return error('Method not allowed',405);
}

async function discoverRoute(request, env) {
  if (request.method !== 'GET') return error('Method not allowed',405);
  try {
    await settleExpiredBoostCampaigns(env);
    const artists = await env.DB.prepare(`SELECT a.id,a.user_id,a.name,a.bio,a.location,a.avatar_url,a.verified,
      p.package_name,p.expires_at
      FROM artists a JOIN premium_subscriptions p ON p.user_id=a.user_id
      WHERE lower(p.status)='active' AND p.expires_at IS NOT NULL AND datetime(p.expires_at)>datetime('now')
      AND lower(COALESCE(p.package_name,'free'))<>'free'
      AND p.id=(SELECT p2.id FROM premium_subscriptions p2 WHERE p2.user_id=a.user_id AND lower(p2.status)='active' AND p2.expires_at IS NOT NULL AND datetime(p2.expires_at)>datetime('now') ORDER BY datetime(COALESCE(p2.paid_at,p2.created_at)) DESC LIMIT 1)
      ORDER BY datetime(p.paid_at) DESC LIMIT 100`).all();
    const songs = await env.DB.prepare(`SELECT DISTINCT s.id,s.title,s.artist,s.artist_id,s.genre,s.plays,s.cover_url,s.audio_url,s.file_url,s.created_at,
      CASE WHEN EXISTS(SELECT 1 FROM premium_subscriptions p JOIN artists a ON a.user_id=p.user_id WHERE (s.artist_id=a.user_id OR s.artist_id=a.id) AND lower(p.status)='active' AND p.expires_at IS NOT NULL AND datetime(p.expires_at)>datetime('now') AND lower(COALESCE(p.package_name,'free'))<>'free') THEN 1 ELSE 0 END upgraded_artist,
      CASE WHEN EXISTS(SELECT 1 FROM song_boost_campaign_songs bs JOIN nilesoniq_feature_payments fp ON fp.id=bs.campaign_id WHERE bs.song_id=s.id AND lower(fp.status)='active' AND datetime(fp.expires_at)>datetime('now')) THEN 1 ELSE 0 END boosted
      FROM songs s WHERE s.approved=1 AND (
        EXISTS(SELECT 1 FROM premium_subscriptions p JOIN artists a ON a.user_id=p.user_id WHERE (s.artist_id=a.user_id OR s.artist_id=a.id) AND lower(p.status)='active' AND p.expires_at IS NOT NULL AND datetime(p.expires_at)>datetime('now') AND lower(COALESCE(p.package_name,'free'))<>'free')
        OR EXISTS(SELECT 1 FROM song_boost_campaign_songs bs JOIN nilesoniq_feature_payments fp ON fp.id=bs.campaign_id WHERE bs.song_id=s.id AND lower(fp.status)='active' AND datetime(fp.expires_at)>datetime('now'))
      ) ORDER BY boosted DESC, plays DESC, datetime(created_at) DESC LIMIT 200`).all();
    return json({data:{artists:artists.results||[],songs:songs.results||[]}});
  } catch(e) {
    console.error('Discover feed failed:',e.message);
    return error('Could not load featured artists and songs.',500);
  }
}

async function publicArtistStatsRoute(request, env) {
  const url=new URL(request.url);
  const artistId=String(url.searchParams.get("artist_id")||"").trim();
  if(!artistId) return error("Artist ID is required",422);
  const artist=await env.DB.prepare("SELECT id FROM artists WHERE id=? LIMIT 1").bind(artistId).first();
  if(!artist) return error("Artist not found",404);
  if(request.method==="POST"){
    const ip=request.headers.get("CF-Connecting-IP")||"unknown";
    const bytes=new TextEncoder().encode(`${artistId}:${ip}`);
    const digest=await crypto.subtle.digest("SHA-256",bytes);
    const visitorKey=[...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,"0")).join("");
    await env.DB.prepare("INSERT OR IGNORE INTO artist_profile_view_log (artist_id,visitor_key,viewed_on) VALUES (?,?,date('now'))").bind(artistId,visitorKey).run();
  } else if(request.method!=="GET") return error("Method not allowed",405);
  const views=await env.DB.prepare("SELECT COUNT(*) AS total FROM artist_profile_view_log WHERE artist_id=?").bind(artistId).first();
  const subs=await env.DB.prepare("SELECT COUNT(DISTINCT listener_user_id) AS total FROM listener_artist_subscriptions WHERE artist_id=? AND lower(status)='active' AND datetime(expires_at)>datetime('now')").bind(artistId).first();
  return json({views:Number(views?.total||0),monthly_subscribers:Number(subs?.total||0)});
}

async function settleExpiredBoostCampaigns(env) {
  const campaigns=await env.DB.prepare(`SELECT * FROM nilesoniq_feature_payments WHERE payment_type='boost' AND lower(status)='active' AND expires_at IS NOT NULL AND datetime(expires_at)<=datetime('now')`).all();
  for(const campaign of campaigns.results||[]) {
    const songs=await env.DB.prepare(`SELECT bs.*,COALESCE(s.plays,0) current_plays,COALESCE(s.downloads,0) current_downloads FROM song_boost_campaign_songs bs JOIN songs s ON s.id=bs.song_id WHERE bs.campaign_id=?`).bind(campaign.id).all();
    for(const row of songs.results||[]) {
      const deliveredPlays=Math.max(0,Number(row.current_plays)-Number(row.baseline_plays));
      const deliveredDownloads=Math.max(0,Number(row.current_downloads)-Number(row.baseline_downloads));
      const playCredit=Math.max(0,Number(row.allocated_play_guarantee)-deliveredPlays);
      const downloadCredit=Math.max(0,Number(row.allocated_download_guarantee)-deliveredDownloads);
      if(playCredit>0) await env.DB.batch([
        env.DB.prepare(`INSERT OR IGNORE INTO song_promo_credit_ledger (event_key,campaign_id,song_id,credit_type,amount) VALUES (?, ?, ?, 'plays', ?)` ).bind(`boost-expiry:${campaign.id}:${row.song_id}:plays`,campaign.id,row.song_id,playCredit),
        env.DB.prepare(`UPDATE songs SET plays=COALESCE(plays,0)+? WHERE id=? AND changes()>0`).bind(playCredit,row.song_id)
      ]);
      if(downloadCredit>0) await env.DB.batch([
        env.DB.prepare(`INSERT OR IGNORE INTO song_promo_credit_ledger (event_key,campaign_id,song_id,credit_type,amount) VALUES (?, ?, ?, 'downloads', ?)` ).bind(`boost-expiry:${campaign.id}:${row.song_id}:downloads`,campaign.id,row.song_id,downloadCredit),
        env.DB.prepare(`UPDATE songs SET downloads=COALESCE(downloads,0)+? WHERE id=? AND changes()>0`).bind(downloadCredit,row.song_id)
      ]);
    }
    await env.DB.prepare(`UPDATE nilesoniq_feature_payments SET status='completed' WHERE id=? AND lower(status)='active'`).bind(campaign.id).run();
  }
}

async function featurePaymentRoute(request, env) {
  const url = new URL(request.url);
  if (request.method === "GET" && url.searchParams.get("public") === "boosted") {
    await settleExpiredBoostCampaigns(env);
    const rows = await env.DB.prepare(`SELECT DISTINCT bs.song_id FROM song_boost_campaign_songs bs JOIN nilesoniq_feature_payments p ON p.id=bs.campaign_id WHERE lower(p.status)='active' AND datetime(p.expires_at)>datetime('now')`).all();
    return json({data:(rows.results||[]).map(x=>String(x.song_id))});
  }
  const user = await currentUser(request, env);
  if (!user) return error("Authentication required", 401);
  const body = await readBody(request);
  if (request.method === "GET") {
    await settleExpiredBoostCampaigns(env);
    const rows = await env.DB.prepare(`
      SELECT id, reference, payment_type, artist_id, amount, status, package_code,
             play_guarantee, download_guarantee, created_at, paid_at, expires_at, failure_message
      FROM nilesoniq_feature_payments WHERE payer_user_id = ?
      ORDER BY created_at DESC LIMIT 50
    `).bind(user.id).all();
    return json({data: rows.results || []});
  }
  if (request.method !== "POST") return error("Method not allowed",405);
  const type = String(body.payment_type || "");
  const phone = normalizeUgandanPhone(body.phone_number || body.phoneNumber);
  const provider = String(body.provider || "").trim().toLowerCase();
  if (!/^\+256\d{9}$/.test(phone)) return error("Enter a valid Ugandan mobile-money number",422);
  if (!["mtn","airtel"].includes(provider)) return error("Provider must be MTN or Airtel",422);
  const artist = await env.DB.prepare("SELECT id,user_id,name FROM artists WHERE id = ? LIMIT 1").bind(String(body.artist_id||"")).first();
  if (!artist) return error("Artist not found",404);
  let amount=0, packageCode="", days=0, plays=0, downloads=0, songIds=[];
  if (type === "boost") {
    if (String(artist.user_id) !== String(user.id)) return error("You can only boost your own songs",403);
    const packages = {
      starter: {amount:5000,days:30,plays:1000,downloads:1000},
      growth: {amount:10000,days:60,plays:3000,downloads:2000},
      premium: {amount:15000,days:120,plays:5000,downloads:3000}
    };
    packageCode = String(body.package_code||"").toLowerCase();
    const pkg=packages[packageCode]; if(!pkg) return error("Choose a valid Boost package",422);
    songIds=[...new Set((Array.isArray(body.song_ids)?body.song_ids:[]).map(x=>String(x).trim()).filter(Boolean))];
    if(!songIds.length || songIds.length>20) return error("Select between 1 and 20 songs",422);
    const placeholders=songIds.map(()=>"?").join(",");
    const owned=await env.DB.prepare(`SELECT id FROM songs WHERE id IN (${placeholders}) AND approved=1 AND artist_id IN (?,?)`).bind(...songIds,artist.id,artist.user_id).all();
    if((owned.results||[]).length!==songIds.length) return error("Every selected song must be an approved song belonging to your artist account",403);
    ({amount,days,plays,downloads}=pkg);
  } else if (type === "listener_subscription") {
    if (String(artist.user_id) === String(user.id)) return error("You cannot subscribe to your own artist account",422);
    amount=5000; days=30; packageCode="listener_30d";
    const active=await env.DB.prepare(`SELECT id FROM listener_artist_subscriptions WHERE listener_user_id=? AND artist_id=? AND lower(status)='active' AND datetime(expires_at)>datetime('now') LIMIT 1`).bind(user.id,artist.id).first();
    if(active) return error("Your artist subscription is already active",409);
  } else return error("Invalid payment type",422);
  const apiKey=env.PESAJET_API_KEY||env.PESAJET_TOKEN;
  const baseUrl=String(env.PESAJET_API_BASE_URL||"https://payments.pesajet.com/api/v1").replace(/\/+$/,"");
  if(!apiKey) return error("Payment service is not configured",503);
  const id=crypto.randomUUID();
  const artistLabel = paymentReferenceName(artist.name);
  const reference = `NILESONIQ-${type === "boost" ? "SONG-BOOST" : "LISTENER-SUBSCRIPTION"}-${artistLabel}-${crypto.randomUUID().replace(/-/g, "").slice(0, 16).toUpperCase()}`;
  const description = (type === "boost"
    ? `NileSoniQ Song Boost - ${artist.name || "Artist"} - ${packageCode}`
    : `NileSoniQ Listener Subscription - ${artist.name || "Artist"} - 30 days`).slice(0, 250);
  const riskCheck = await checkPesaJetCollectionRisk(request, env, phone, user.id, reference);
  if (riskCheck.blocked) return error(riskCheck.message, 429);
  await env.DB.prepare(`INSERT INTO nilesoniq_feature_payments (id,reference,payment_type,payer_user_id,artist_id,amount,currency,provider,phone_number,status,package_code,duration_days,play_guarantee,download_guarantee,song_ids_json) VALUES (?,?, ?,?,?,?,'UGX',?,?,'pending',?,?,?,?,?)`).bind(id,reference,type,user.id,artist.id,amount,provider,phone,packageCode,days,plays,downloads,JSON.stringify(songIds)).run();
  if(type==='listener_subscription') await env.DB.prepare(`INSERT INTO listener_artist_subscriptions (id,payment_id,listener_user_id,artist_id,status) VALUES (?,?,?,?,'pending')`).bind(crypto.randomUUID(),id,user.id,artist.id).run();
  let response,result;
  try { response=await fetch(`${baseUrl}/payments`,{method:'POST',headers:{'Content-Type':'application/json','X-API-Key':apiKey},body:JSON.stringify({type:'COLLECTION',amount,currency:'UGX',phoneNumber:phone,provider,reference,description,idempotencyKey:`nilesoniq-${reference}`})}); result=await response.json().catch(()=>({})); }
  catch(e){ console.error('Feature payment request uncertain:',e.message); return error('Payment request outcome is uncertain; it remains pending.',502); }
  if(!response.ok || result?.success===false || result?.error){
    const msg=String(result?.message||result?.error?.message||'PesaJet rejected the payment request');
    await env.DB.prepare("UPDATE nilesoniq_feature_payments SET status='failed',failure_message=? WHERE id=? AND status='pending'").bind(msg,id).run();
    if(type==='listener_subscription') await env.DB.prepare("UPDATE listener_artist_subscriptions SET status='failed' WHERE payment_id=? AND status='pending'").bind(id).run();
    return error(msg,response.status>=400&&response.status<500?response.status:502);
  }
  return json({success:true,status:'PENDING',reference,message:`Approve the UGX ${amount.toLocaleString('en-US')} mobile-money prompt. The feature activates only after PesaJet confirms payment.`});
}

async function applyFeaturePaymentStatus(env, reference, status, transactionId, amount, currency, fee) {
  const payment=await env.DB.prepare("SELECT * FROM nilesoniq_feature_payments WHERE reference=? LIMIT 1").bind(reference).first();
  if(!payment) return {matched:false};
  if(isSuccessfulPaymentStatus(status)) {
    const confirmedAmount = Number(amount);
    const expectedAmount = Number(payment.amount);
    const confirmedCurrency = String(currency || '').trim().toUpperCase();
    const feeValue = fee === null || fee === undefined || fee === '' ? null : Number(fee);
    const feeSupplied = feeValue !== null;
    const feeValid = !feeSupplied || (Number.isFinite(feeValue) && feeValue >= 0 && feeValue <= confirmedAmount);
    const allowedAmounts = payment.payment_type === 'boost'
      ? [5000, 10000, 15000]
      : payment.payment_type === 'listener_subscription' ? [5000] : [];

    // PesaJet may confirm a customer collection total above the advertised
    // package price because of its transaction fee/tax. This applies to BOTH
    // Song Boost and Listener Artist Subscription payments. Keep each feature
    // entitlement fixed at payment.amount (including the listener's 30-day
    // subscription), but accept a higher confirmed UGX collection. The signed
    // webhook reference and successful status remain mandatory, and any
    // reported fee must be a valid non-negative amount no greater than the
    // confirmed collection.
    if (
      !Number.isFinite(confirmedAmount) || !Number.isFinite(expectedAmount) ||
      confirmedAmount < expectedAmount || confirmedCurrency !== 'UGX' || !feeValid ||
      !allowedAmounts.includes(expectedAmount)
    ) {
      console.error('Feature payment confirmation failed amount/currency validation', {
        reference, paymentType: payment.payment_type,
        receivedAmount: Number.isFinite(confirmedAmount) ? confirmedAmount : null,
        receivedCurrency: confirmedCurrency || null,
        expectedAmount, feeSupplied, receivedFee: feeSupplied ? feeValue : null
      });
      return {matched:true,changed:false,reason:'amount_or_currency_mismatch'};
    }
    const now=new Date().toISOString();
    const expires=new Date(Date.now()+Number(payment.duration_days||0)*86400000).toISOString();
    const upd=await env.DB.prepare(`UPDATE nilesoniq_feature_payments SET status='active',provider_transaction_id=?,paid_at=?,expires_at=? WHERE reference=? AND lower(status)='pending'`).bind(transactionId||'',now,expires,reference).run();
    const changed=Number(upd?.meta?.changes||0)>0;
    if(changed && payment.payment_type==='boost') {
      const ids=JSON.parse(payment.song_ids_json||'[]');
      const placeholders=ids.map(()=>'?').join(',');
      const rows=await env.DB.prepare(`SELECT id,COALESCE(plays,0) plays,COALESCE(downloads,0) downloads FROM songs WHERE id IN (${placeholders})`).bind(...ids).all();
      const n=ids.length, pbase=Math.floor(Number(payment.play_guarantee)/n), prem=Number(payment.play_guarantee)%n, dbase=Math.floor(Number(payment.download_guarantee)/n), drem=Number(payment.download_guarantee)%n;
      for(let i=0;i<ids.length;i++){const row=(rows.results||[]).find(x=>String(x.id)===String(ids[i])); if(!row)continue; await env.DB.prepare(`INSERT OR IGNORE INTO song_boost_campaign_songs (campaign_id,song_id,baseline_plays,baseline_downloads,allocated_play_guarantee,allocated_download_guarantee) VALUES (?,?,?,?,?,?)`).bind(payment.id,ids[i],row.plays,row.downloads,pbase+(i<prem?1:0),dbase+(i<drem?1:0)).run();}
    } else if(changed && payment.payment_type==='listener_subscription') {
      await env.DB.prepare(`UPDATE listener_artist_subscriptions SET status='active',started_at=?,expires_at=? WHERE payment_id=?`).bind(now,expires,payment.id).run();
    }
    if(changed) {
      const feeKnown=feeSupplied && feeValid;
      const feeAmount=feeKnown?feeValue:0;
      const sourceType=payment.payment_type==='listener_subscription'?'listener_subscription':'song_boost';
      const note=payment.payment_type==='listener_subscription'?'Verified listener subscription fee retained by NileSoniQ; no artist share.':'Verified Song Boost campaign payment; package entitlement remains at its advertised fixed price.';
      await env.DB.batch([
        env.DB.prepare(`INSERT OR IGNORE INTO platform_financial_ledger (event_key,event_type,source_type,source_id,reference,amount_signed,currency,pesajet_fee_amount,tax_liability_amount,status,note,occurred_at) VALUES (?,'income',?,?,?,?,'UGX',?,0,?,?,?)`).bind(`${sourceType}:${payment.id}`,sourceType,payment.id,reference,confirmedAmount,feeAmount,feeKnown?'posted':'fee_unverified',note,now),
        env.DB.prepare(`UPDATE platform_wallet SET balance=MAX(0,balance+?-?),updated_at=datetime('now') WHERE id=(SELECT id FROM platform_wallet ORDER BY created_at LIMIT 1)`).bind(confirmedAmount,feeAmount)
      ]);
    }
    return {matched:true,changed,reason:changed?'verified_success':'already_processed'};
  }
  if(['FAILED','FAILURE','ERROR','EXPIRED','REJECTED','DECLINED','CANCELLED','CANCELED','TIMED_OUT','TIMEOUT'].includes(String(status).toUpperCase())) {
    await env.DB.prepare("UPDATE nilesoniq_feature_payments SET status='failed',provider_transaction_id=?,failure_message=? WHERE reference=? AND lower(status)='pending'").bind(transactionId||'',String(status),reference).run();
    await env.DB.prepare("UPDATE listener_artist_subscriptions SET status='failed' WHERE payment_id=? AND status='pending'").bind(payment.id).run();
  }
  return {matched:true,changed:false,reason:'non_success_status'};
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

  const generatedReference = type === "collection"
    ? `NILESONIQ-PLATFORM-WALLET-DEPOSIT-${crypto.randomUUID().replace(/-/g, "").slice(0, 16).toUpperCase()}`
    : `NILESONIQ-PLATFORM-WALLET-WITHDRAWAL-${crypto.randomUUID().replace(/-/g, "").slice(0, 16).toUpperCase()}`;
  const reference = String(body.reference || generatedReference).trim().slice(0, 120);
  if (type === "collection") {
    const riskCheck = await checkPesaJetCollectionRisk(request, env, phone, user.id, reference);
    if (riskCheck.blocked) return error(riskCheck.message, 429);
  }

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
      // Reserve the transfer amount plus the platform-paid PesaJet disbursement fee.
      // PesaJet still sends the exact requested amount to the destination number.
      const expectedDisbursementFee = getPesaJetDisbursementFee(amount);
      if (expectedDisbursementFee === null) {
        return error("PesaJet disbursement fee is not configured for this amount. Maximum supported amount is UGX 7,000,000.", 422);
      }
      const requiredWalletBalance = amount + expectedDisbursementFee;
      const reservation = await env.DB.prepare(`
        INSERT INTO platform_payouts
          (id, amount, currency, phone_number, provider, reference, description, status, created_by, created_at)
        SELECT ?, ?, 'UGX', ?, ?, ?, ?, 'PENDING', ?, datetime('now')
        WHERE COALESCE(
          (SELECT SUM(balance) FROM platform_wallet), 0
        ) - COALESCE(
          (SELECT SUM(amount + CASE
             WHEN amount <= 2500 THEN 330
             WHEN amount <= 5000 THEN 440
             WHEN amount <= 15000 THEN 700
             WHEN amount <= 30000 THEN 880
             WHEN amount <= 45000 THEN 1210
             WHEN amount <= 60000 THEN 1500
             WHEN amount <= 125000 THEN 1925
             WHEN amount <= 250000 THEN 3575
             WHEN amount <= 500000 THEN 7000
             WHEN amount <= 1000000 THEN 12500
             WHEN amount <= 2000000 THEN 15000
             WHEN amount <= 4000000 THEN 18000
             WHEN amount <= 7000000 THEN 20000
             ELSE 0 END) FROM platform_payouts
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
        requiredWalletBalance
      ).run();

      if (Number(reservation?.meta?.changes || 0) === 0) {
        return error(`Insufficient available platform wallet balance. Required including PesaJet fee: UGX ${requiredWalletBalance.toLocaleString("en-US")}.`, 409);
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

async function ensureArtistWithdrawalPayoutColumns(env) {
  const result = await env.DB.prepare("PRAGMA table_info(withdrawal_requests)").all();
  const columns = new Set((result.results || []).map(column => String(column.name).toLowerCase()));
  if (!columns.size) throw new Error("withdrawal_requests table is unavailable");
  const required = {
    payout_reference: "TEXT",
    pesajet_transaction_id: "TEXT",
    payout_failure_message: "TEXT"
  };
  for (const [name, type] of Object.entries(required)) {
    if (columns.has(name)) continue;
    try {
      await env.DB.prepare(`ALTER TABLE withdrawal_requests ADD COLUMN ${name} ${type}`).run();
    } catch (e) {
      const refreshed = await env.DB.prepare("PRAGMA table_info(withdrawal_requests)").all();
      const now = new Set((refreshed.results || []).map(column => String(column.name).toLowerCase()));
      if (!now.has(name)) throw e;
    }
  }
}

async function notifyArtistWithdrawalStatus(env, row, status, detail = "") {
  try {
    await ensureArtistNotificationsTable(env);
    const amount = Math.floor(Number(row.amount) || 0).toLocaleString("en-US");
    const message = status === "paid"
      ? `Your withdrawal of UGX ${amount} has been paid successfully.`
      : status === "failed"
        ? `Your withdrawal of UGX ${amount} could not be completed. ${detail || "The payment failed; your available balance has been released."}`
        : `Your withdrawal of UGX ${amount} is now ${status}.`;
    await env.DB.prepare(`INSERT INTO artist_notifications (id, artist_id, notification_type, message, related_id, created_at) VALUES (?, ?, 'withdrawal', ?, ?, ?)`)
      .bind(crypto.randomUUID(), row.artist_id, message, row.id, new Date().toISOString()).run();
  } catch (e) {
    console.error("Artist withdrawal notification could not be saved:", e.message);
  }
}

async function applyArtistWithdrawalPaymentStatus(env, reference, status, transactionId = "", amount = null, currency = "", failureMessage = "") {
  await ensureArtistWithdrawalPayoutColumns(env);
  const row = await env.DB.prepare(`
    SELECT id, artist_id, amount, status, payout_reference
    FROM withdrawal_requests WHERE payout_reference = ? LIMIT 1
  `).bind(reference).first();
  if (!row) return { matched: false, changed: false };

  const normalized = String(status || "").toUpperCase();
  if (isSuccessfulPaymentStatus(normalized)) {
    if (amount === null || !Number.isFinite(Number(amount)) || Number(amount) !== Number(row.amount) || String(currency || "").toUpperCase() !== "UGX") {
      console.error("Artist withdrawal payout confirmation did not match the requested amount/currency.", { reference, expectedAmount: Number(row.amount), receivedAmount: amount, receivedCurrency: currency });
      return { matched: true, changed: false, reason: "amount_currency_mismatch" };
    }
    const updated = await env.DB.prepare(`
      UPDATE withdrawal_requests
      SET status='paid', processed_at=datetime('now'),
          pesajet_transaction_id=COALESCE(NULLIF(?,''),pesajet_transaction_id),
          payout_failure_message=NULL
      WHERE id=? AND payout_reference=? AND lower(status)='processing'
    `).bind(String(transactionId || ""), row.id, reference).run();
    const changed = Number(updated?.meta?.changes || 0) === 1;
    if (changed) await notifyArtistWithdrawalStatus(env, row, "paid");
    return { matched: true, changed, reason: changed ? "paid" : "already_processed" };
  }

  if (["FAILED", "FAILURE", "ERROR", "EXPIRED", "REJECTED", "DECLINED", "CANCELLED", "CANCELED", "TIMED_OUT", "TIMEOUT", "TIME_OUT", "INSUFFICIENT_BALANCE", "INSUFFICIENT_FUNDS", "AUTHORIZATION_FAILED", "LIMIT_EXCEEDED"].includes(normalized)) {
    const detail = String(failureMessage || normalized).slice(0, 300);
    const updated = await env.DB.prepare(`
      UPDATE withdrawal_requests
      SET status='failed', processed_at=datetime('now'),
          pesajet_transaction_id=COALESCE(NULLIF(?,''),pesajet_transaction_id),
          payout_failure_message=?
      WHERE id=? AND payout_reference=? AND lower(status)='processing'
    `).bind(String(transactionId || ""), detail, row.id, reference).run();
    const changed = Number(updated?.meta?.changes || 0) === 1;
    if (changed) await notifyArtistWithdrawalStatus(env, row, "failed", "Your available balance has been released.");
    return { matched: true, changed, reason: changed ? "failed" : "already_processed" };
  }
  return { matched: true, changed: false, reason: "non_terminal_status" };
}

async function artistWithdrawalPayoutRoute(env, path) {
  await ensureArtistWithdrawalPayoutColumns(env);
  const match = path.match(/^\/api\/admin\/withdrawals\/([^/]+)\/pay$/);
  if (!match) return error("Invalid artist withdrawal payout route", 404);
  const requestId = decodeURIComponent(match[1]);
  const row = await env.DB.prepare(`
    SELECT id, artist_id, amount, payment_method, payment_details, status, payout_reference
    FROM withdrawal_requests WHERE id=? LIMIT 1
  `).bind(requestId).first();
  if (!row) return error("Artist withdrawal request not found", 404);
  if (String(row.status || "").toLowerCase() !== "processing") {
    return error("Move this request to Processing before approving the payout.", 409);
  }
  if (row.payout_reference) {
    return error("A PesaJet payout has already been submitted for this request. Check its status before taking any further action.", 409);
  }

  const amount = Number(row.amount);
  const phone = normalizeUgandanPhone(row.payment_details);
  const method = String(row.payment_method || "").toLowerCase();
  const provider = method.includes("airtel") ? "airtel" : method.includes("mtn") ? "mtn" : "";
  if (!Number.isInteger(amount) || amount < 1000 || !/^\+256\d{9}$/.test(phone) || !provider) {
    return error("The saved withdrawal amount, mobile-money number, or network is invalid. Correct the request before paying.", 422);
  }
  const apiKey = env.PESAJET_API_KEY || env.PESAJET_TOKEN;
  const baseUrl = String(env.PESAJET_API_BASE_URL || "https://payments.pesajet.com/api/v1").replace(/\/+$/, "");
  if (!apiKey) return error("Payment service is not configured.", 503);

  const reference = `NILESONIQ-ARTIST-WITHDRAWAL-${row.id}`;
  const claimed = await env.DB.prepare(`
    UPDATE withdrawal_requests
    SET payout_reference=?, payout_failure_message=NULL
    WHERE id=? AND lower(status)='processing' AND (payout_reference IS NULL OR payout_reference='')
  `).bind(reference, row.id).run();
  if (Number(claimed?.meta?.changes || 0) !== 1) {
    return error("This withdrawal has already been submitted or is being processed. Refresh the admin dashboard.", 409);
  }

  let response, result;
  try {
    response = await fetch(`${baseUrl}/payments`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
      body: JSON.stringify({
        type: "DISBURSEMENT", amount, currency: "UGX", phoneNumber: phone, provider,
        reference, description: `NileSoniQ artist withdrawal ${row.id}`,
        idempotencyKey: `nilesoniq-${reference}`
      })
    });
    result = await response.json().catch(() => ({}));
  } catch (e) {
    console.error("Artist PesaJet payout outcome uncertain:", e.message);
    return error("PesaJet could not confirm the payout request. The request remains Processing to prevent a duplicate payment. Check the PesaJet dashboard before retrying.", 502);
  }

  const transaction = result?.transaction && typeof result.transaction === "object"
    ? result.transaction
    : result?.data && typeof result.data === "object" ? result.data : result;
  const status = String(transaction?.status || transaction?.transactionStatus || result?.status || "PENDING").toUpperCase().replace(/[\s-]+/g, "_");
  const transactionId = String(transaction?.transactionId || transaction?.transaction_id || result?.transactionId || result?.transaction_id || "");
  const explicitFailure = !response.ok || result?.success === false || ["FAILED", "FAILURE", "ERROR", "EXPIRED", "REJECTED", "DECLINED", "CANCELLED", "CANCELED", "TIMED_OUT", "TIMEOUT", "INSUFFICIENT_BALANCE", "INSUFFICIENT_FUNDS", "LIMIT_EXCEEDED"].includes(status);
  if (explicitFailure) {
    const definitive = (response.status >= 400 && response.status < 500) || result?.success === false || ["FAILED", "FAILURE", "ERROR", "EXPIRED", "REJECTED", "DECLINED", "CANCELLED", "CANCELED", "TIMED_OUT", "TIMEOUT", "INSUFFICIENT_BALANCE", "INSUFFICIENT_FUNDS", "LIMIT_EXCEEDED"].includes(status);
    if (definitive) {
      await applyArtistWithdrawalPaymentStatus(env, reference, "FAILED", transactionId, amount, "UGX", String(result?.message || result?.error?.message || result?.error || status));
      return error(String(result?.message || result?.error?.message || result?.error || "PesaJet rejected the payout."), response.status >= 400 && response.status < 500 ? response.status : 502);
    }
    return error("PesaJet's response is uncertain. The request remains Processing; check PesaJet before retrying.", 502);
  }

  if (isSuccessfulPaymentStatus(status)) {
    const applied = await applyArtistWithdrawalPaymentStatus(env, reference, status, transactionId, amount, "UGX");
    if (!applied.changed && applied.reason !== "already_processed") {
      return error("PesaJet reported success, but the payment confirmation could not be matched safely. Please contact support before taking further action.", 502);
    }
    return json({ success: true, status: "PAID", reference, transactionId, message: "PesaJet confirmed the artist payout." });
  }

  await env.DB.prepare(`UPDATE withdrawal_requests SET pesajet_transaction_id=COALESCE(NULLIF(?,''),pesajet_transaction_id) WHERE id=? AND payout_reference=? AND lower(status)='processing'`).bind(transactionId, row.id, reference).run();
  return json({ success: true, status: "PROCESSING", reference, transactionId: transactionId || null, message: "PesaJet accepted the artist payout request. The artist's balance will be deducted only after payment confirmation." }, 202);
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
    await ensureArtistTestAdjustmentsTable(env);
    const [songResult, ledgerResult, withdrawalResult] = await Promise.all([
      env.DB.prepare(`
        SELECT * FROM songs
        WHERE artist_id IN (?, ?)
        ORDER BY datetime(COALESCE(created_at, '1970-01-01')) DESC
        LIMIT 500
      `).bind(ids[0], ids[1]).all(),
      env.DB.prepare(`
        SELECT
          COALESCE((
            SELECT SUM(net_amount - ?)
            FROM artist_earning_ledger
            WHERE artist_id IN (?, ?)
              AND source_type = 'qualified_play'
              AND status = 'posted'
          ), 0)
          + COALESCE((
            SELECT SUM(net_amount)
            FROM artist_earning_ledger
            WHERE artist_id IN (?, ?)
              AND source_type = 'qualified_download'
              AND status = 'posted'
          ), 0)
          + COALESCE((
            SELECT SUM(amount)
            FROM artist_test_adjustments
            WHERE artist_id IN (?, ?)
              AND status = 'active'
              AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
          ), 0) AS adjustment
      `).bind(ARTIST_FREE_NET_PER_PLAY, ids[0], ids[1], ids[0], ids[1], ids[0], ids[1]).first(),
      env.DB.prepare(`
        SELECT
          COALESCE(SUM(CASE WHEN lower(status) IN ('pending','processing','paid','completed','success','successful') THEN amount ELSE 0 END), 0) AS reserved,
          COALESCE(SUM(CASE WHEN lower(status) IN ('paid','completed','success','successful') THEN amount ELSE 0 END), 0) AS withdrawn
        FROM withdrawal_requests WHERE artist_id IN (?, ?)
      `).bind(ids[0], ids[1]).first()
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

function songSlugForShare(song) {
  const title = slugForShare(song?.title || "song").substring(0, 44).replace(/-+$/g, "");
  const artist = slugForShare(song?.artist || "artist").substring(0, 25).replace(/-+$/g, "");
  return `${title}-${artist}`.replace(/-+$/g, "");
}

function htmlEscape(value) {
  return String(value || "").replace(/[&<>\"']/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
  }[ch]));
}


function artistSlugForShare(value) {
  return slugForShare(value || "artist");
}

function absolutePublicImage(value) {
  try {
    const candidate = new URL(String(value || "").trim(), "https://nilesoniq.com");
    return candidate.protocol === "https:" ? candidate.href : "https://nilesoniq.com/favicon.png";
  } catch {
    return "https://nilesoniq.com/favicon.png";
  }
}

function replaceSeoHead(html, tags) {
  let updated = html.replace(/<title>[\s\S]*?<\/title>/i, "");
  updated = updated.replace(/<meta\s+name=["']description["'][^>]*>/i, "");
  updated = updated.replace(/<link\s+rel=["']canonical["'][^>]*>/i, "");
  updated = updated.replace(/<meta\s+property=["']og:[^>]*>/gi, "");
  updated = updated.replace(/<meta\s+name=["']twitter:[^>]*>/gi, "");
  return updated.replace(/<head[^>]*>/i, match => `${match}\n${tags}`);
}

// The site shell is hosted by Vercel. This Worker is routed only for SEO
// paths, so fetching "/" does not re-enter this Worker route.
async function fetchVercelSiteShell(request, url) {
  const headers = new Headers({ "Accept": "text/html" });
  const response = await fetch(new Request(new URL("/", url.origin), {
    method: "GET",
    headers,
    redirect: "follow"
  }));
  if (!response.ok) {
    console.error("Vercel site shell fetch failed:", response.status);
  }
  return response;
}

function notFoundHtml() {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,follow"><title>Page not found | NileSoniq</title><meta name="description" content="The requested NileSoniq page could not be found."></head><body style="font-family:Arial,sans-serif;max-width:680px;margin:12vh auto;padding:24px;line-height:1.6"><h1>Page not found</h1><p>This artist or song page may have been removed, or its link may be incorrect.</p><p><a href="https://nilesoniq.com/">Return to NileSoniq</a></p></body></html>`;
}

async function artistSharePreview(request, env, url) {
  if (request.method !== "GET" || !/^\/artist\/[^/]+\/?$/i.test(url.pathname)) return null;
  let requestedSlug = "";
  try { requestedSlug = decodeURIComponent(url.pathname.split("/")[2] || ""); }
  catch { return new Response(notFoundHtml(), { status: 404, headers: { "Content-Type": "text/html; charset=utf-8", "X-Robots-Tag": "noindex, follow" } }); }

  let artist = null;
  let lookupFailed = false;
  try {
    const result = await env.DB.prepare(`
      SELECT id, name, bio, avatar_url, location, verified, is_premium, created_at
      FROM artists
      WHERE NOT EXISTS (
        SELECT 1 FROM copyright_removals cr
        WHERE cr.content_type = 'artist'
          AND (cr.content_id = artists.id OR cr.content_id = artists.user_id)
      )
      ORDER BY created_at DESC, rowid DESC LIMIT 1000
    `).all();
    const wanted = artistSlugForShare(requestedSlug);
    artist = (result.results || []).find(item => artistSlugForShare(item.name) === wanted) || null;
  } catch (e) {
    lookupFailed = true;
    console.error("Artist share preview lookup failed:", e.message);
  }

  if (lookupFailed) {
    return new Response("Artist page temporarily unavailable", {
      status: 503,
      headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
    });
  }

  if (!artist) {
    return new Response(notFoundHtml(), { status: 404, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=60", "X-Robots-Tag": "noindex, follow" } });
  }

  const assetResponse = await fetchVercelSiteShell(request, url);
  if (!assetResponse.ok) {
    return new Response("NileSoniq website temporarily unavailable", {
      status: 502,
      headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
    });
  }
  const html = await assetResponse.text();
  const name = String(artist.name || "Artist").trim();
  const title = `${name} | Artist Profile on NileSoniq`;
  const description = String(artist.bio || `Discover music and songs by ${name} on NileSoniq.`).replace(/\s+/g, " ").trim().slice(0, 155);
  const canonical = `https://nilesoniq.com/artist/${artistSlugForShare(name)}`;
  const image = absolutePublicImage(artist.avatar_url);
  const tags = [
    `<title>${htmlEscape(title)}</title>`,
    `<meta name="description" content="${htmlEscape(description)}">`,
    `<link rel="canonical" href="${htmlEscape(canonical)}">`,
    `<meta property="og:type" content="profile">`,
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
  return new Response(replaceSeoHead(html, tags), { status: assetResponse.status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=300" } });
}

async function dynamicSitemap(request, env, url) {
  if (request.method !== "GET" || url.pathname !== "/sitemap.xml") return null;
  const base = "https://nilesoniq.com";
  const urls = new Map();
  const add = (path, lastmod) => {
    if (!path || !path.startsWith("/")) return;
    const loc = `${base}${path}`;
    if (!urls.has(loc)) urls.set(loc, lastmod ? String(lastmod).slice(0, 10) : "");
  };
  add("/");
  try {
    const [artists, songs, news] = await Promise.all([
      env.DB.prepare(`SELECT id, name, created_at FROM artists WHERE NOT EXISTS (SELECT 1 FROM copyright_removals cr WHERE cr.content_type = 'artist' AND (cr.content_id = artists.id OR cr.content_id = artists.user_id)) ORDER BY created_at DESC, rowid DESC LIMIT 2000`).all(),
      env.DB.prepare(`SELECT id, title, artist, created_at FROM songs WHERE approved = 1 AND NOT EXISTS (SELECT 1 FROM copyright_removals cr WHERE cr.content_type = 'song' AND cr.content_id = songs.id) ORDER BY rowid DESC LIMIT 5000`).all(),
      env.DB.prepare(`SELECT id, slug, updated_at, published_at, created_at FROM news WHERE published = 1 AND slug IS NOT NULL AND TRIM(slug) <> '' ORDER BY rowid DESC LIMIT 2000`).all()
    ]);
    const artistSlugs = new Set();
    for (const a of artists.results || []) {
      const slug = artistSlugForShare(a.name);
      if (artistSlugs.has(slug)) continue;
      artistSlugs.add(slug);
      add(`/artist/${slug}`, a.created_at);
    }
    for (const song of songs.results || []) add(`/song/${songSlugForShare(song)}`, song.created_at);
    for (const article of news.results || []) add(`/news/${slugForShare(article.slug)}`, article.updated_at || article.published_at || article.created_at);
  } catch (e) {
    console.error("Dynamic sitemap generation failed:", e.message);
    return new Response("Sitemap temporarily unavailable", { status: 503, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
  }
  const body = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${Array.from(urls.entries()).map(([loc, lastmod]) => `<url><loc>${htmlEscape(loc)}</loc>${/^\d{4}-\d{2}-\d{2}$/.test(lastmod) ? `<lastmod>${lastmod}</lastmod>` : ""}</url>`).join("")}\n</urlset>`;
  return new Response(body, { status: 200, headers: { "Content-Type": "application/xml; charset=utf-8", "Cache-Control": "public, max-age=900" } });
}

async function songSharePreview(request, env, url) {
  if (request.method !== "GET" || !/^\/song\/[^/]+\/?$/i.test(url.pathname)) return null;
  let slug = "";
  try {
    slug = decodeURIComponent(url.pathname.split("/")[2] || "");
  } catch {
    return null;
  }
  let song = null;
  let lookupFailed = false;
  try {
    const result = await env.DB.prepare(`
      SELECT id, title, artist, description, cover_url
      FROM songs WHERE approved = 1
        AND NOT EXISTS (
          SELECT 1 FROM copyright_removals cr
          WHERE cr.content_type = 'song' AND cr.content_id = songs.id
        )
      ORDER BY rowid DESC LIMIT 2000
    `).all();
    const requestedSlug = slugForShare(slug);
    song = (result.results || []).find(item =>
      songSlugForShare(item) === requestedSlug ||
      slugForShare(item.title) === requestedSlug
    ) || null;
  } catch (e) {
    lookupFailed = true;
    console.error("Song share preview lookup failed:", e.message);
  }

  if (lookupFailed) {
    return new Response("Song page temporarily unavailable", {
      status: 503,
      headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
    });
  }
  if (!song) {
    return new Response(notFoundHtml(), {
      status: 404,
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=60", "X-Robots-Tag": "noindex, follow" }
    });
  }

  const assetResponse = await fetchVercelSiteShell(request, url);
  if (!assetResponse.ok) {
    return new Response("NileSoniq website temporarily unavailable", {
      status: 502,
      headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
    });
  }
  const html = await assetResponse.text();
  const title = `${song.title || "Song"} — ${song.artist || "NileSoniq"}`;
  const description = `Listen to ${song.title || "this song"} by ${song.artist || "this artist"} on NileSoniq.`;
  // Artwork URLs may be stored as absolute URLs or site-relative R2/API paths.
  // Resolve relative paths to absolute HTTPS URLs so WhatsApp can fetch them.
  const image = song ? absolutePublicImage(song.cover_url) : "https://nilesoniq.com/favicon.png";
  const canonical = `https://nilesoniq.com/song/${songSlugForShare(song)}`;
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
    `<meta property="og:image:secure_url" content="${htmlEscape(image)}">`,
    `<meta property="og:image:width" content="500">`,
    `<meta property="og:image:height" content="500">`,
    `<meta property="og:image:alt" content="${htmlEscape(title)} artwork">`,
    `<meta name="twitter:card" content="summary_large_image">`,
    `<meta name="twitter:title" content="${htmlEscape(title)}">`,
    `<meta name="twitter:description" content="${htmlEscape(description)}">`,
    `<meta name="twitter:image" content="${htmlEscape(image)}">`
  ].join("\n");
  const updated = replaceSeoHead(html, tags);
  return new Response(updated, { status: assetResponse.status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=300" } });
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(settleExpiredBoostCampaigns(env));
  },
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
      } else if (path === "/api/artist/posts") {
        response = await artistPostsRoute(request, env);
      } else if (path === "/api/artist/messages") {
        response = await artistMessagesRoute(request, env);
      } else if (path === "/api/artist/post-interactions") {
        response = await artistPostInteractionsRoute(request, env);
      } else if (path === "/api/artist/post-interactions") {
        response = await artistPostInteractionsRoute(request, env);
      } else if (path === "/api/artist/follows") {
        response = await artistFollowsRoute(request, env);
      } else if (path === "/api/discover") {
        response = await discoverRoute(request, env);
      } else if (path === "/api/artist/public-stats") {
        response = await publicArtistStatsRoute(request, env);
      } else if (path === "/api/auth/register-paid") {
        // Paid artist signup must use the dedicated pending-payment flow.
        // The account and verification email are created only after a verified
        // successful PesaJet webhook, never merely because this request arrived.
        response = await paidSignupRoute(request, env);
      } else if (path.startsWith("/api/auth/")) {
        response = await authRoute(request, env, path);
      } else if (path.startsWith("/api/db/")) {
        response = await dbRoute(request, env, path);
      } else if (path === "/api/admin/referrals" || path.startsWith("/api/admin/referrals/")) {
        response = await adminReferralRoute(request, env, path);
      } else if (
        path === "/api/admins" ||
        path.startsWith("/api/admins/") ||
        path === "/api/admin/songs" ||
        path.startsWith("/api/admin/songs/") ||
        path === "/api/admin/withdrawals" ||
        path.startsWith("/api/admin/withdrawals/") ||
        path === "/api/admin/analytics" ||
        path === "/api/admin/ads" ||
        path === "/api/admin/copyright-removals" ||
        path === "/api/admin/copyright-removal-artists" ||
        path === "/api/admin/copyright-removal-songs"
      ) {
        response = await adminRoute(request, env, path);
      } else if (path === "/api/ads") {
        response = await publicAdsRoute(request, env);
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
      } else if (path === "/api/payments/feature-payment") {
        response = await featurePaymentRoute(request, env);
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
      } else if (path === "/sitemap.xml") {
        response = await dynamicSitemap(request, env, url);
        if (!response) response = error("Method not allowed", 405);
      } else if (path.startsWith("/artist/")) {
        response = await artistSharePreview(request, env, url);
        if (!response) response = error("Method not allowed", 405);
      } else if (path.startsWith("/song/")) {
        response = await songSharePreview(request, env, url);
        if (!response) response = error("Method not allowed", 405);
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
