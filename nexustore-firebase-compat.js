/**
 * NexusStore Firebase-compat shim — v2, direct-to-Supabase
 * ==========================================================
 * Drop-in replacement for the firebase-app/auth/database *compat* SDK
 * scripts. Implements only the subset of the Firebase JS API this app
 * actually calls, backed by:
 *   - Supabase Auth for everything under firebase.auth()
 *   - Supabase Postgres DIRECTLY (via supabase-js, protected by Row Level
 *     Security policies — see prisma/enable-rls.sql) for everything under
 *     firebase.database(), EXCEPT orders/payments/secure-downloads/trash,
 *     which still go through nexustore-backend (they need real server-side
 *     logic — price re-validation, gateway calls, rate limiting — that
 *     can't safely live in a client-writable table even with RLS).
 *
 * This removes the backend entirely from the critical path for browsing,
 * login, profile, wishlist, messages, and (for admins) product/category/
 * settings management — the things that broke whenever Render was slow to
 * wake up or briefly unreachable. Only checkout and downloading a paid/free
 * file still need the backend to be up.
 *
 * HOW TO USE
 * ----------
 *   <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
 *   <script src="nexustore-firebase-compat.js"></script>
 *   <script>
 *     const firebaseConfig = {
 *       supabaseUrl: "https://xxxx.supabase.co",
 *       supabaseAnonKey: "eyJ...",   // Settings > API > anon/public key
 *       apiBase: "https://your-api-host/api", // still needed for orders/downloads
 *     };
 *     firebase.initializeApp(firebaseConfig);
 *   </script>
 * Everything else in both index.html files — every db.ref(...), auth.*
 * call, function name, DOM id — stays exactly as-is.
 *
 * REQUIRES prisma/enable-rls.sql to have been run in Supabase's SQL Editor
 * — without RLS policies, every direct table access below is blocked by
 * default (Postgres denies all access once RLS is enabled with no matching
 * policy), which is the safe failure direction but means nothing will load.
 *
 * KNOWN LIMITATIONS (read before deploying)
 * ------------------------------------------
 * - "value" listeners still poll every 3s rather than pushing instantly
 *   (Supabase Realtime could remove this later, but polling is simpler and
 *   was kept on purpose to minimize new risk in this rewrite).
 * - .orderByChild()/.equalTo()/.limitToLast() are special-cased for the
 *   exact queries this app uses. A new query pattern added later won't be
 *   understood without extending buildHandler() below.
 * - site_settings/pages/* page types are assumed to be about/privacy/terms/refund.
 */
(function (global) {
  const PAGE_TYPES = ['about', 'privacy', 'terms', 'refund'];
  let API_BASE = '/api';
  let supabase = null;
  let currentSession = null;
  const authStateListeners = [];
  const bannerShownForPath = new Map(); // path -> true while a banner is showing; cleared automatically once that path recovers
  let lastNotifiedUid; // undefined = never notified yet (distinct from null = "known logged out")

  function notifyAuthListeners() {
    const user = sessionToFirebaseUser(currentSession);
    const uid = user ? user.uid : null;
    // Supabase's client fires onAuthStateChange for far more than just
    // "user logged in or out" — token refreshes, tab-focus revalidation,
    // and its own initial-session check on page load all trigger it too,
    // and each one used to re-run every registered onAuthStateChanged
    // callback in full. That's what was showing "Signed In" (and
    // re-registering listeners like attachOrdersListener, each of which
    // tears down and restarts its own polling from scratch) two or three
    // times per page load — once per redundant re-fire, all for the exact
    // same already-logged-in user. Only forward it when the signed-in
    // identity has actually changed.
    if (uid === lastNotifiedUid) return;
    lastNotifiedUid = uid;
    authStateListeners.forEach((cb) => cb(user));
  }

  function sessionToFirebaseUser(session) {
    if (!session || !session.user) return null;
    const u = session.user;
    return {
      uid: u.id,
      email: u.email,
      displayName: u.user_metadata?.name || u.user_metadata?.full_name || null,
      getIdToken: async () => (await supabase.auth.getSession()).data.session?.access_token,
    };
  }

  // A raw network failure (not an HTTP error response — this is a plain
  // fetch() rejection, before any status code exists) almost always means
  // the backend host is mid cold-start: free-tier hosts like Render's free
  // plan spin a sleeping instance down after inactivity and take anywhere
  // from a few seconds to ~60s to wake back up, during which connections
  // get refused or time out. One retry after a pause gives it a real
  // chance to finish waking up instead of immediately surfacing a scary
  // "failed" banner for what is, on a free host, completely normal
  // first-request latency. This does NOT retry on an actual HTTP error
  // response (401, 403, 500, etc.) — those got a real answer from a
  // reachable server and retrying won't change that answer.
  async function fetchWithColdStartRetry(url, opts) {
    try {
      return await fetch(url, opts);
    } catch (e) {
      await new Promise((r) => setTimeout(r, 4000));
      return fetch(url, opts);
    }
  }

  async function apiFetch(path, { method = 'GET', body } = {}) {
    if (!supabase) throw new Error('App failed to start — reload the page.');
    const session = (await supabase.auth.getSession()).data.session;
    const headers = { 'Content-Type': 'application/json' };
    if (session) headers.Authorization = 'Bearer ' + session.access_token;
    const res = await fetchWithColdStartRetry(API_BASE + path, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error((err.error || 'Request failed') + ` (HTTP ${res.status})`);
    }
    if (res.status === 204) return null;
    return res.json();
  }

  // ---- Direct-Supabase table helpers ------------------------------------
  // Used for everything except orders/payments/secure-downloads/trash (see
  // file header). Every RLS denial surfaces here as a normal thrown Error
  // with Postgres's real message, same as apiFetch does for the backend.

  function sb() {
    if (!supabase) throw new Error('App failed to start — reload the page.');
    return supabase;
  }

  function toEpoch(dateStr) {
    return dateStr ? new Date(dateStr).getTime() : null;
  }

  // Anime/cartoon-character style avatar, deterministic per seed (so the
  // same user always gets the same picture without storing an image
  // anywhere). avatarSeed lets a user "pick a new one" from the profile
  // page's gallery (see index.html) without ever needing real file
  // storage — shuffling just picks a new random seed string and saves
  // that, and this function regenerates the same picture from it forever
  // after. A real uploaded photo (avatarUrl, via Supabase Storage — see
  // uploadAvatarFile below) always takes priority over both when present.
  // Falls back to the user's name/id if they've never picked or uploaded one.
  function avatarUrl(user) {
    if (user && user.avatarUrl) return user.avatarUrl;
    const seed = (user && (user.avatarSeed || user.name || user.id)) || 'guest';
    return `https://api.dicebear.com/9.x/adventurer/svg?seed=${encodeURIComponent(seed)}`;
  }

  const AVATAR_MAX_BYTES = 3 * 1024 * 1024; // matches the Storage bucket's file_size_limit in the setup SQL
  const AVATAR_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];

  // Uploads a real photo to the "avatars" Storage bucket (see
  // prisma/migration-003-avatar-upload.sql), at a path scoped to the
  // uploading user's own folder — RLS policies on storage.objects enforce
  // that server-side too, this check is just for a fast, friendly error
  // instead of waiting on a round trip. Saves the resulting public URL onto
  // the User row and returns it so the caller can update the UI immediately.
  async function uploadAvatarFile(uid, file) {
    if (!file || !AVATAR_MIME_TYPES.includes(file.type)) {
      throw new Error('Please choose a JPG, PNG, WEBP, or GIF image.');
    }
    if (file.size > AVATAR_MAX_BYTES) {
      throw new Error('Image is too large — please choose one under 3MB.');
    }
    const ext = (file.name.split('.').pop() || 'jpg').toLowerCase().replace(/[^a-z0-9]/g, '') || 'jpg';
    const path = `${uid}/avatar-${Date.now()}.${ext}`;
    const { error: upErr } = await sb().storage.from('avatars').upload(path, file, {
      upsert: true,
      cacheControl: '3600',
      contentType: file.type,
    });
    if (upErr) throw new Error(upErr.message);
    const { data } = sb().storage.from('avatars').getPublicUrl(path);
    const publicUrl = data.publicUrl;
    await sbUpdate('User', 'id', uid, { avatarUrl: publicUrl });
    return publicUrl;
  }

  // Deletes the stored file too, not just the DB reference, so the bucket
  // doesn't quietly accumulate orphaned images every time someone changes
  // their photo or reverts to a generated avatar.
  async function removeAvatarFile(uid, currentUrl) {
    await sbUpdate('User', 'id', uid, { avatarUrl: null });
    if (!currentUrl) return;
    try {
      const marker = '/avatars/';
      const idx = currentUrl.indexOf(marker);
      if (idx === -1) return;
      const path = decodeURIComponent(currentUrl.slice(idx + marker.length).split('?')[0]);
      await sb().storage.from('avatars').remove([path]);
    } catch (e) {
      console.error('[nexustore-compat] could not remove old avatar file (non-fatal):', e);
    }
  }

  async function sbSelect(table, build, columns) {
    let q = sb().from(table).select(columns || '*');
    if (build) q = build(q);
    const { data, error } = await q;
    if (error) throw new Error(error.message);
    return data;
  }

  async function sbSelectOne(table, build) {
    let q = sb().from(table).select('*');
    if (build) q = build(q);
    const { data, error } = await q.maybeSingle();
    if (error) throw new Error(error.message);
    return data;
  }

  // The app throughout was written in Firebase/RTDB style, where any field
  // is normally just `Date.now()` — a plain number. Real Postgres
  // `timestamp` columns reject a raw number outright (a type error, not a
  // graceful coercion), so any write carrying e.g. `createdAt: Date.now()`
  // was failing at the database level. Rather than hunt down and fix every
  // individual `Date.now()` call site across two large HTML files (an
  // easy one to miss and reintroduce later), every write goes through
  // sbInsert/sbUpdate/sbUpsert, so normalizing it once here covers all of
  // them, including future ones.
  function normalizeTimestamps(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    const out = { ...obj };
    for (const key of Object.keys(out)) {
      if (/(At|Time|Date)$/.test(key) && typeof out[key] === 'number') {
        out[key] = new Date(out[key]).toISOString();
      }
    }
    return out;
  }

  async function sbInsert(table, row) {
    const { data, error } = await sb().from(table).insert(normalizeTimestamps(row)).select().single();
    if (error) throw new Error(error.message);
    return data;
  }

  async function sbUpdate(table, matchCol, matchVal, patch) {
    const { error } = await sb().from(table).update(normalizeTimestamps(patch)).eq(matchCol, matchVal);
    if (error) throw new Error(error.message);
  }

  async function sbDelete(table, matchCol, matchVal) {
    const { error } = await sb().from(table).delete().eq(matchCol, matchVal);
    if (error) throw new Error(error.message);
  }

  async function sbUpsert(table, row, conflictCol) {
    const { error } = await sb().from(table).upsert(normalizeTimestamps(row), { onConflict: conflictCol });
    if (error) throw new Error(error.message);
  }

  function makeSnapshot(key, val) {
    return {
      key,
      val: () => val,
      exists: () => val !== null && val !== undefined,
      forEach: (cb) => {
        if (val && typeof val === 'object') {
          Object.entries(val).forEach(([k, v]) => cb(makeSnapshot(k, v)));
        }
      },
      // Firebase snapshots support these too — several places in the app
      // call them, and a missing method throws inside a poll/once callback,
      // which was failing SILENTLY (caught by the shim's own try/catch) and
      // looked like "nothing happens" with no visible error.
      numChildren: () => (val && typeof val === 'object' ? Object.keys(val).length : 0),
      hasChild: (childKey) => !!(val && typeof val === 'object' && Object.prototype.hasOwnProperty.call(val, childKey)),
      child: (childKey) => makeSnapshot(childKey, val && typeof val === 'object' ? val[childKey] : undefined),
    };
  }

  // Firebase RTDB returns lists as {id1: {...}, id2: {...}} — the app code
  // relies on that shape everywhere (Object.entries(snap.val()), snap.forEach
  // giving the real id as .key, delete-by-key, etc.). The REST API returns
  // plain arrays instead (normal for REST), so every list-returning handler
  // below converts through this — without it, "keys" extracted from an array
  // are just indices ("0","1","2") instead of real ids, silently breaking
  // every delete/edit/lookup that depends on the key being real.
  function keyedObject(arr) {
    if (!Array.isArray(arr)) return arr;
    const out = {};
    for (const item of arr) {
      if (item && item.id !== undefined) out[item.id] = item;
    }
    return out;
  }

  // ---- Path -> API handler resolution -------------------------------

  function currentUid() {
    return currentSession?.user?.id || null;
  }

  function buildHandler(path, query) {
    let m;

    // config/{key} -> AppConfig table
    if ((m = path.match(/^config\/(.+)$/))) {
      const key = m[1];
      return {
        get: () => sbSelectOne('AppConfig', (q) => q.eq('key', key)).then((r) => r?.value ?? null),
        setVal: (v) => sbUpsert('AppConfig', { key, value: v }, 'key'),
        updateVal: async (v) => {
          const cur = (await sbSelectOne('AppConfig', (q) => q.eq('key', key)).then((r) => r?.value)) || {};
          return sbUpsert('AppConfig', { key, value: { ...cur, ...v } }, 'key');
        },
        removeVal: () => sbDelete('AppConfig', 'key', key),
      };
    }

    // site_settings/pages/{type}, socials, popup -> SiteSetting table
    if ((m = path.match(/^site_settings\/pages\/(.+)$/))) {
      const key = `pages.${m[1]}`;
      return {
        get: () => sbSelectOne('SiteSetting', (q) => q.eq('key', key)).then((r) => r?.value ?? null),
        setVal: (v) => sbUpsert('SiteSetting', { key, value: v }, 'key'),
        updateVal: (v) => sbUpsert('SiteSetting', { key, value: v }, 'key'),
      };
    }
    if (path === 'site_settings/socials' || path === 'site_settings/popup') {
      const key = path.split('/')[1];
      return {
        get: () => sbSelectOne('SiteSetting', (q) => q.eq('key', key)).then((r) => r?.value ?? null),
        setVal: (v) => sbUpsert('SiteSetting', { key, value: v }, 'key'),
        updateVal: async (v) => {
          const cur = (await sbSelectOne('SiteSetting', (q) => q.eq('key', key)).then((r) => r?.value)) || {};
          return sbUpsert('SiteSetting', { key, value: { ...cur, ...v } }, 'key');
        },
      };
    }
    if (path === 'site_settings') {
      return {
        get: async () => {
          const pages = {};
          for (const t of PAGE_TYPES) {
            pages[t] = await sbSelectOne('SiteSetting', (q) => q.eq('key', `pages.${t}`)).then((r) => r?.value ?? null);
          }
          const socials = await sbSelectOne('SiteSetting', (q) => q.eq('key', 'socials')).then((r) => r?.value ?? null);
          const popup = await sbSelectOne('SiteSetting', (q) => q.eq('key', 'popup')).then((r) => r?.value ?? null);
          return { pages, socials, popup };
        },
      };
    }

    // categories -> Category table. RLS handles the public-vs-admin
    // visibility split automatically (active=true OR is_admin()) — no more
    // guessing which endpoint to call based on which page you're on.
    if (path === 'categories') {
      return {
        get: async () => keyedObject(await sbSelect('Category', (q) => q.order('position'))),
        push: (v) => sbInsert('Category', v),
      };
    }
    if ((m = path.match(/^categories\/(.+)$/))) {
      const id = m[1];
      return {
        setVal: (v) => sbUpdate('Category', 'id', id, v),
        updateVal: (v) => sbUpdate('Category', 'id', id, v),
        removeVal: async () => {
          // Soft-delete + trash record, done as two direct calls instead of
          // one backend transaction — acceptable here (low-stakes admin
          // action, not financial data); RLS still fully protects both.
          const row = await sbSelectOne('Category', (q) => q.eq('id', id));
          if (row) await sbInsert('Trash', { id: row.id, entityType: 'category', entityId: row.id, payload: row });
          await sbUpdate('Category', 'id', id, { active: false, deletedAt: new Date().toISOString() });
        },
      };
    }

    // apps (products) -> Product table
    if (path === 'apps') {
      return {
        get: async () => keyedObject(await sbSelect('Product', (q) => q.order('position'))),
        pushKeyOnly: () => crypto.randomUUID(),
      };
    }
    if ((m = path.match(/^apps\/(.+)$/))) {
      const id = m[1];
      return {
        get: () => sbSelectOne('Product', (q) => q.eq('id', id)),
        setVal: (v) => sbInsert('Product', { id, ...v }),
        updateVal: (v) => sbUpdate('Product', 'id', id, v),
        removeVal: async () => {
          const row = await sbSelectOne('Product', (q) => q.eq('id', id));
          if (row) await sbInsert('Trash', { id: row.id, entityType: 'product', entityId: row.id, payload: row });
          await sbUpdate('Product', 'id', id, { active: false, deletedAt: new Date().toISOString() });
        },
      };
    }

    // orders — deliberately still via the backend: order creation and
    // payment need server-side price re-validation and gateway calls, not
    // something a client-writable table should do even behind RLS.
    if (path === 'orders') {
      if (query.orderField === 'userId' && query.equalValue) {
        const uid = query.equalValue;
        return {
          get: async () => {
            if (uid === currentUid()) return keyedObject(await apiFetch('/me/orders'));
            const all = await apiFetch('/admin/orders');
            return keyedObject(all.filter((o) => o.userId === uid));
          },
        };
      }
      return { get: async () => keyedObject(await apiFetch('/admin/orders')) };
    }
    if ((m = path.match(/^orders\/(.+)$/))) {
      const id = m[1];
      return {
        get: () => apiFetch(`/orders/${id}`).catch(() => null),
        updateVal: (v) =>
          v && v.status === 'cancelled'
            ? apiFetch(`/orders/${id}/cancel`, { method: 'PATCH' })
            : Promise.reject(new Error('Only status:"cancelled" updates are supported client-side for orders')),
        removeVal: () => apiFetch(`/orders/${id}/cancel`, { method: 'PATCH' }).catch(() => {}),
      };
    }

    // users -> User table (+ Wishlist for the embedded array, matching the
    // old app's currentUser.wishlist shape)
    if (path === 'users') {
      return {
        get: async () => {
          const rows = await sbSelect('User');
          // Every row gets an avatar synthesized the same way the single-
          // user handler below does — previously this bulk list (used by
          // the admin panel's Manage Users / VIP / Online-Now pages) never
          // set one at all, so every avatar there silently fell back to
          // via.placeholder.com — a service that's no longer reliable —
          // and showed as a broken/blank image everywhere.
          return keyedObject(rows.map((u) => ({ ...u, avatar: avatarUrl(u) })));
        },
      };
    }
    if ((m = path.match(/^users\/([^/]+)\/avatarSeed$/))) {
      const uid = m[1];
      return { setVal: (v) => sbUpdate('User', 'id', uid, { avatarSeed: v, avatarUrl: null }) };
    }
    if ((m = path.match(/^users\/([^/]+)\/avatarUrl$/))) {
      const uid = m[1];
      return { setVal: (v) => sbUpdate('User', 'id', uid, { avatarUrl: v }) };
    }
    if ((m = path.match(/^users\/([^/]+)\/lastActive$/))) {
      const uid = m[1];
      // No error surfaced to the UI on failure on purpose — a missed
      // heartbeat (e.g. one poll cycle overlapping a token refresh) isn't
      // worth bothering the user about; it'll just try again on the next tick.
      return { setVal: (v) => sbUpdate('User', 'id', uid, { lastActive: v }).catch(() => {}) };
    }
    if ((m = path.match(/^users\/([^/]+)\/wishlist$/))) {
      const uid = m[1];
      return {
        setVal: async (arr) => {
          await sbDelete('Wishlist', 'userId', uid);
          if (Array.isArray(arr) && arr.length) {
            const { error } = await sb().from('Wishlist').insert(arr.map((productId) => ({ userId: uid, productId })));
            if (error) throw new Error(error.message);
          }
        },
      };
    }
    if ((m = path.match(/^users\/([^/]+)\/status$/))) {
      const uid = m[1];
      return { get: () => sbSelectOne('User', (q) => q.eq('id', uid)).then((u) => u?.status ?? null) };
    }
    // Google OAuth sessions carry the account's Google profile picture in
    // user_metadata (Supabase populates both avatar_url and picture from
    // Google's own OAuth response — check both since the exact field has
    // varied across supabase-js versions).
    function googleAvatarFromSession() {
      const meta = currentSession?.user?.user_metadata;
      return meta?.avatar_url || meta?.picture || null;
    }

    if ((m = path.match(/^users\/([^/]+)$/))) {
      const uid = m[1];
      return {
        get: async () => {
          let user = await sbSelectOne('User', (q) => q.eq('id', uid));
          if (!user && uid === currentUid()) {
            // First login — create the row (replaces the old /me/ensure
            // upsert). RLS's insert policy only allows creating your own row.
            const u = sessionToFirebaseUser(currentSession);
            user = await sbInsert('User', {
              id: uid,
              email: u?.email || null,
              name: u?.displayName || u?.email?.split('@')[0] || null,
              avatarUrl: googleAvatarFromSession(), // null for email/password signups — falls back to a generated avatar as usual
            });
          } else if (user && uid === currentUid() && !user.avatarUrl && !user.avatarSeed) {
            // Existing account, no photo/generated-avatar choice made yet
            // (e.g. signed up with email/password originally, then later
            // signed in with Google — or signed up with Google before this
            // feature existed). Backfill their Google picture once; never
            // overwrites a photo they uploaded or a gallery pick they made.
            const googleAvatar = googleAvatarFromSession();
            if (googleAvatar) {
              await sbUpdate('User', 'id', uid, { avatarUrl: googleAvatar });
              user = { ...user, avatarUrl: googleAvatar };
            }
          }
          if (!user) return null;
          const wishRows = await sbSelect('Wishlist', (q) => q.eq('userId', uid));
          return {
            ...user,
            wishlist: (wishRows || []).map((r) => r.productId),
            avatar: avatarUrl(user),
          };
        },
        setVal: (v) => sbUpdate('User', 'id', uid, { name: v.name }),
        updateVal: (v) => sbUpdate('User', 'id', uid, uid === currentUid() ? { name: v.name } : v),
        removeVal: () => sbDelete('User', 'id', uid),
      };
    }

    // messages (support tickets) -> Message table. RLS restricts a regular
    // user's SELECT to their own rows automatically, so the same query
    // works for both "my tickets" and "admin sees everyone" — no separate
    // endpoint needed.
    function serializeMessageRow(m) {
      return {
        id: m.id,
        user: m.userId,
        userName: m.User?.name ?? null,
        userEmail: m.User?.email ?? null,
        title: m.title,
        body: m.body,
        category: m.category,
        status: m.status || 'open',
        imageData: m.imageData,
        reply: m.reply,
        replyTime: toEpoch(m.replyTime),
        timestamp: toEpoch(m.createdAt),
      };
    }
    if (path === 'messages') {
      const isOwnThread = query.orderField === 'user' && query.equalValue;
      return {
        get: async () => {
          const rows = await sbSelect(
            'Message',
            (q) => {
              q = q.order('createdAt', { ascending: false });
              if (isOwnThread) q = q.eq('userId', query.equalValue);
              return q;
            },
            '*, User(name, email)'
          );
          return keyedObject(rows.map(serializeMessageRow));
        },
        push: (v) =>
          sbInsert('Message', {
            userId: currentUid(),
            title: v.title,
            body: v.body,
            category: v.category || null,
            imageData: v.imageData,
            status: 'open',
          }),
      };
    }
    if ((m = path.match(/^messages\/(.+)$/))) {
      const id = m[1];
      return {
        // Replying auto-resolves the ticket; admin can also flip status on
        // its own (reopen, or resolve without replying) via updateVal with
        // just { status }.
        updateVal: (v) => {
          const patch = {};
          if (v.reply !== undefined) {
            patch.reply = v.reply;
            patch.replyTime = new Date().toISOString();
            patch.status = 'resolved';
          }
          if (v.status !== undefined) patch.status = v.status;
          return sbUpdate('Message', 'id', id, patch);
        },
        removeVal: () => sbDelete('Message', 'id', id),
      };
    }

    // notifications -> Notification table
    if (path === 'notifications') {
      return {
        get: async () => {
          const rows = await sbSelect('Notification', (q) => q.eq('active', true).order('createdAt', { ascending: false }));
          return keyedObject(rows.map((n) => ({ id: n.id, title: n.title, msg: n.msg, timestamp: toEpoch(n.createdAt) })));
        },
        push: (v) => sbInsert('Notification', { title: v.title, msg: v.msg }),
      };
    }
    if ((m = path.match(/^notifications\/(.+)$/))) {
      const id = m[1];
      return { removeVal: () => sbUpdate('Notification', 'id', id, { active: false }) };
    }

    // downloads_log — stays backend-only: entries are written server-side
    // as part of the secure download flow, admin just reads the log.
    if (path === 'downloads_log') {
      return { get: async () => keyedObject(await apiFetch('/admin/downloads-log')) };
    }

    // trash — stays backend-only: restore/purge touches two tables and is
    // simplest to keep atomic server-side.
    if (path === 'trash') {
      return { get: async () => keyedObject(await apiFetch('/admin/trash')) };
    }
    if ((m = path.match(/^trash\/(.+)$/))) {
      const id = m[1];
      return { removeVal: () => apiFetch(`/admin/trash/${id}`, { method: 'DELETE' }) };
    }

    // secureDownloads — stays backend-only on purpose: RLS has zero
    // policies for this table (see enable-rls.sql), so it's genuinely
    // unreachable from the browser no matter what. Only the backend's
    // service-role key can read/write it.
    if ((m = path.match(/^secureDownloads\/(.+)$/))) {
      const id = m[1];
      return {
        get: async () => (await apiFetch(`/admin/downloads/${id}/link`)).downloadLink,
        setVal: (v) => apiFetch(`/admin/downloads/${id}/link`, { method: 'PUT', body: { downloadLink: v } }),
      };
    }

    if (path === '.info/connected') {
      return { get: () => Promise.resolve(true) }; // presence system not implemented — always report connected
    }

    console.warn('[nexustore-compat] Unmapped path:', path, query);
    return {
      get: () => Promise.resolve(null),
      setVal: () => Promise.resolve(null),
      updateVal: () => Promise.resolve(null),
      removeVal: () => Promise.resolve(null),
      push: () => Promise.resolve(null),
    };
  }

  // ---- Ref implementation ---------------------------------------------

  class RefShim {
    constructor(path, query = {}) {
      this.path = path.replace(/^\/+|\/+$/g, '');
      this.query = query;
      this._listeners = new Map(); // event -> Set of {cb, intervalId, prevJson}
    }

    get key() {
      const parts = this.path.split('/');
      return parts[parts.length - 1] || null;
    }

    child(sub) {
      return new RefShim(`${this.path}/${sub}`, this.query);
    }

    orderByChild(field) {
      return new RefShim(this.path, { ...this.query, orderField: field });
    }

    equalTo(value) {
      return new RefShim(this.path, { ...this.query, equalValue: value });
    }

    limitToLast(n) {
      return new RefShim(this.path, { ...this.query, limit: n });
    }

    once(event, successCallback, failureCallback) {
      const handler = buildHandler(this.path, this.query);
      const promise = handler.get().then(
        (val) => makeSnapshot(this.key, val),
        (err) => { throw err; }
      );
      if (typeof successCallback === 'function') {
        // Firebase supports once(event, cb) as well as once(event) returning
        // a promise — the app uses both forms throughout. Support both.
        promise.then(successCallback, failureCallback || ((e) => console.error('[nexustore-compat] once() error for', this.path, e)));
      }
      return promise;
    }

    on(event, cb) {
      const handler = buildHandler(this.path, this.query);
      let prevJson = null;
      let consecutiveFailures = 0;
      const poll = async () => {
        try {
          const val = await handler.get();
          if (consecutiveFailures > 0 && bannerShownForPath.has(this.path)) {
            // Recovered after showing an error — clear it rather than
            // leaving a stale "couldn't load" message for something that
            // just worked. This is what a transient network blip on a
            // mobile connection looks like: fails a couple times, then
            // loads fine — previously that left a permanent-looking red
            // banner on screen even though the data was actually current.
            bannerShownForPath.delete(this.path);
            clearBanner(this.path);
          }
          consecutiveFailures = 0;
          const json = JSON.stringify(val);
          if (event === 'value') {
            if (json !== prevJson) {
              prevJson = json;
              cb(makeSnapshot(this.key, val));
            }
          } else if (event === 'child_changed') {
            // Special-cased for the one real usage (support-reply notification).
            // Handlers now return a keyed object ({id: item, ...}), matching
            // Firebase's real shape — normalize both that and a bare array so
            // this keeps working regardless of which a given handler returns.
            const items = Array.isArray(val) ? val : (val && typeof val === 'object' ? Object.values(val) : []);
            if (items.length && prevJson !== null) {
              const prevRaw = JSON.parse(prevJson);
              const prevItems = Array.isArray(prevRaw) ? prevRaw : (prevRaw && typeof prevRaw === 'object' ? Object.values(prevRaw) : []);
              items.forEach((item) => {
                const prevItem = prevItems.find((p) => p.id === item.id);
                if (prevItem && JSON.stringify(prevItem) !== JSON.stringify(item)) {
                  cb(makeSnapshot(item.id, item));
                }
              });
            }
            prevJson = json;
          }
        } catch (e) {
          console.error('[nexustore-compat] poll error for', this.path, e);
          consecutiveFailures++;
          // Before this fix, a failing query here (bad table name, missing
          // RLS policy, wrong Supabase URL/key, etc.) failed silently —
          // console.error only — forever, every 3s, with the page stuck
          // showing its initial loading skeleton and no visible sign
          // anything was wrong. Surfacing it after several failed attempts
          // in a row (~12s) turns that into a readable, actionable error
          // instead of an unexplained infinite spinner, while giving a
          // single slow/dropped request or two on a shaky mobile
          // connection room to just... work on the next try, which is by
          // far the most common case and shouldn't alarm anyone. Shown
          // once per path, and auto-cleared above the moment it recovers.
          if (consecutiveFailures >= 4 && !bannerShownForPath.has(this.path)) {
            bannerShownForPath.set(this.path, true);
            showFatalBanner(`Couldn't load "${this.path}" from ${describeFailedSource(this.path)}: ${e.message}`, this.path);
          }
        }
      };
      retryHandlers.set(this.path, poll);
      poll();
      const intervalId = setInterval(poll, 3000);
      if (!this._listeners.has(event)) this._listeners.set(event, new Set());
      this._listeners.get(event).add({ cb, intervalId });
      return cb;
    }

    off(event, cb) {
      const set = this._listeners.get(event);
      if (!set) return;
      set.forEach((entry) => {
        if (!cb || entry.cb === cb) {
          clearInterval(entry.intervalId);
          set.delete(entry);
        }
      });
    }

    async set(value) {
      const handler = buildHandler(this.path, this.query);
      return handler.setVal ? handler.setVal(value) : Promise.reject(new Error(`set() not supported at ${this.path}`));
    }

    async update(value) {
      const handler = buildHandler(this.path, this.query);
      return handler.updateVal ? handler.updateVal(value) : Promise.reject(new Error(`update() not supported at ${this.path}`));
    }

    async remove() {
      // "apps/{id}" and "categories/{id}" removes are intentionally rare —
      // the app almost always uses the soft-delete admin endpoints instead
      // (see delApp/delCat), which land here via removeVal.
      const handler = buildHandler(this.path, this.query);
      return handler.removeVal ? handler.removeVal() : Promise.reject(new Error(`remove() not supported at ${this.path}`));
    }

    push(value) {
      const handler = buildHandler(this.path, this.query);
      if (value === undefined) {
        // Firebase generates the key client-side and returns synchronously —
        // used to pre-generate a product id before a separate save step.
        const key = handler.pushKeyOnly ? handler.pushKeyOnly() : crypto.randomUUID();
        return { key };
      }
      const promise = (handler.push ? handler.push(value) : Promise.reject(new Error(`push() not supported at ${this.path}`)))
        .then((created) => ({ key: created?.id || created?.key || null }));
      promise.key = null; // not known synchronously when the server assigns it
      return promise;
    }
  }

  // ---- Public firebase.* surface ---------------------------------------

  function auth() {
    return {
      onAuthStateChanged(cb) {
        authStateListeners.push(cb);
        // Real Firebase NEVER calls this synchronously, even for cached
        // state — it always fires on a later tick. Calling it synchronously
        // here was a bug: it ran this callback before the rest of the
        // page's own <script> had finished executing top-to-bottom, which
        // could hit "Cannot access 'X' before initialization" for any
        // variable the callback references that's declared further down
        // the same file (exactly what happened with ordersQueryRef).
        Promise.resolve().then(() => cb(sessionToFirebaseUser(currentSession)));
        return () => {
          const i = authStateListeners.indexOf(cb);
          if (i >= 0) authStateListeners.splice(i, 1);
        };
      },
      get currentUser() {
        return sessionToFirebaseUser(currentSession);
      },
      setPersistence: async () => {}, // Supabase persists sessions by default; no-op
      signOut: () => supabase.auth.signOut(),
      // Supabase auth calls resolve normally even on failure (wrong password,
      // unconfirmed email, etc.) — the failure is just an `error` field on
      // the result. Firebase instead REJECTS the promise on failure and
      // resolves with a {user: {...}} shape on success. Without this
      // translation, app code's .catch() never fires on real auth errors,
      // and .then(cred => cred.user.uid) crashes on success because the
      // shape doesn't match — which is what was actually breaking login/signup.
      signInWithEmailAndPassword: async (email, password) => {
        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
        return { user: sessionToFirebaseUser({ user: data.user }) };
      },
      createUserWithEmailAndPassword: async (email, password) => {
        const { data, error } = await supabase.auth.signUp({ email, password });
        if (error) throw error;
        if (!data.session) {
          // Account was created, but Supabase's "Confirm email" setting is
          // gating the session until the user clicks a link in their inbox —
          // unlike Firebase, which logs a new user in immediately. To match
          // the old app's instant-login-after-signup behavior, disable
          // "Confirm email" in Supabase → Authentication → Providers → Email.
          throw new Error('Account created — check your email to confirm it, then log in.');
        }
        return { user: sessionToFirebaseUser({ user: data.user }) };
      },
      sendPasswordResetEmail: async (email) => {
        const { error } = await supabase.auth.resetPasswordForEmail(email);
        if (error) throw error;
      },
      signInWithPopup: async () => {
        const { error } = await supabase.auth.signInWithOAuth({ provider: 'google' }); // Supabase OAuth always redirects; no true popup
        if (error) throw error;
      },
      signInWithRedirect: async () => {
        const { error } = await supabase.auth.signInWithOAuth({ provider: 'google' });
        if (error) throw error;
      },
      getRedirectResult: async () => {
        // Supabase bounces the browser back here with any failure appended
        // as either a query string or (implicit-flow) hash fragment — e.g.
        // ?error=server_error&error_description=... or
        // #error=access_denied&error_description=Unsupported+provider....
        // Real Firebase surfaces this by rejecting getRedirectResult().
        // Without translating it here, a disabled/misconfigured Google
        // provider in Supabase just silently bounces the user back to the
        // page with no visible error at all — clicking "Continue with
        // Google" LOOKS like it does nothing, when it's actually failing
        // one step later, after the redirect.
        const parseParams = (str) => new URLSearchParams(str.replace(/^[?#]/, ''));
        const qp = parseParams(window.location.search);
        const hp = parseParams(window.location.hash);
        const errorDesc =
          qp.get('error_description') || hp.get('error_description') || qp.get('error') || hp.get('error');
        if (errorDesc) {
          // Strip it out of the URL so refreshing or going back doesn't
          // keep re-showing the same stale error.
          const url = new URL(window.location.href);
          url.search = '';
          url.hash = '';
          window.history.replaceState({}, '', url.toString());
          const err = new Error(decodeURIComponent(errorDesc).replace(/\+/g, ' '));
          err.code = 'auth/redirect-error';
          throw err;
        }
        return { user: sessionToFirebaseUser(currentSession) };
      },
    };
  }
  auth.GoogleAuthProvider = function GoogleAuthProvider() {};
  // admin.html reads firebase.auth.Auth.Persistence.LOCAL/.SESSION when you
  // tap Login — without this object it throws immediately (before signing
  // in at all), which is why login got stuck on "Authenticating...".
  // Supabase persists sessions in localStorage by default either way, so
  // these values are accepted but don't change behavior.
  auth.Auth = { Persistence: { LOCAL: 'LOCAL', SESSION: 'SESSION', NONE: 'NONE' } };

  function database() {
    return { ref: (path) => new RefShim(path) };
  }

  // These paths are served by nexustore-backend (Express), not queried
  // from Supabase directly — order creation/verification, secure download
  // links, and admin logs all need real server-side logic. A failure here
  // means the BACKEND is unreachable, which is a completely different
  // thing to check than a Supabase problem, so the banner says so instead
  // of blaming Supabase for something Supabase had no part in.
  const BACKEND_ROUTED_PATH = /^(orders(\/|$)|downloads_log$|trash(\/|$))/;

  function describeFailedSource(path) {
    return BACKEND_ROUTED_PATH.test(path) ? `your backend server (${API_BASE})` : 'Supabase';
  }

  const retryHandlers = new Map(); // path -> its poll() function, so the banner's Retry button can trigger an immediate re-check

  function showFatalBanner(message, id) {
    const banner = document.createElement('div');
    banner.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:999999;background:#dc2626;color:#fff;padding:12px;text-align:center;font-family:sans-serif;font-size:14px;word-break:break-all;';
    const text = document.createElement('span');
    text.textContent = message;
    banner.appendChild(text);
    if (id && retryHandlers.has(id)) {
      const retryBtn = document.createElement('button');
      retryBtn.textContent = 'Retry now';
      retryBtn.style.cssText = 'margin-left:12px;background:#fff;color:#dc2626;border:none;border-radius:6px;padding:4px 12px;font-weight:600;cursor:pointer;font-size:13px;';
      retryBtn.onclick = () => {
        // Give explicit feedback on click — previously this called poll()
        // with zero visible response, so if the retry ALSO failed (the
        // underlying issue hadn't actually cleared yet), it looked
        // indistinguishable from the button not working at all. Success
        // still auto-clears this whole banner from the poll() success path;
        // this just guarantees the click itself is never ambiguous either way.
        retryBtn.disabled = true;
        retryBtn.textContent = 'Retrying...';
        const fn = retryHandlers.get(id);
        Promise.resolve(fn ? fn() : null).finally(() => {
          // If it succeeded, poll() already removed this banner from the DOM
          // — these lines only run if the banner (and this button) still exist.
          if (retryBtn.isConnected) {
            retryBtn.disabled = false;
            retryBtn.textContent = 'Retry now';
          }
        });
      };
      banner.appendChild(retryBtn);
    }
    if (id) banner.dataset.bannerId = id;
    const attach = () => document.body.prepend(banner);
    document.body ? attach() : window.addEventListener('DOMContentLoaded', attach);
    console.error('[nexustore-compat] ' + message);
    return banner;
  }

  // Removes a banner previously shown with a given id — used to auto-clear
  // a transient-failure banner once that same path successfully loads
  // again, instead of leaving a stale "couldn't load" message on screen
  // for something that's actually working now.
  function clearBanner(id) {
    document.querySelectorAll(`[data-banner-id="${CSS && CSS.escape ? CSS.escape(id) : id}"]`).forEach((el) => el.remove());
  }

  function validateConfig(config) {
    const problems = [];
    if (!config.supabaseUrl || !/^https:\/\/[a-z0-9-]+\.supabase\.co\/?$/i.test(config.supabaseUrl.trim())) {
      problems.push(`supabaseUrl looks wrong: "${config.supabaseUrl}" — should look like https://xxxxxxxx.supabase.co with no trailing slash, no spaces, no /rest or /auth suffix.`);
    }
    if (!config.supabaseAnonKey || config.supabaseAnonKey.trim().length < 20 || /your-anon|placeholder|xxxx/i.test(config.supabaseAnonKey)) {
      problems.push(`supabaseAnonKey looks wrong or still a placeholder: "${config.supabaseAnonKey}".`);
    }
    if (!config.apiBase || !/^https?:\/\/.+\/api\/?$/i.test(config.apiBase.trim())) {
      problems.push(`apiBase looks wrong: "${config.apiBase}" — should end in /api, e.g. https://your-backend.onrender.com/api.`);
    }
    return problems;
  }

  global.firebase = {
    initializeApp(config) {
      const problems = validateConfig(config);
      if (problems.length) {
        showFatalBanner('Config problem — ' + problems.join(' | '));
        return;
      }
      API_BASE = config.apiBase || API_BASE;
      if (!global.supabase || typeof global.supabase.createClient !== 'function') {
        showFatalBanner('Could not load required libraries (Supabase). Check your internet connection and reload the page.');
        return;
      }
      try {
        supabase = global.supabase.createClient(config.supabaseUrl.trim(), config.supabaseAnonKey.trim());
      } catch (e) {
        showFatalBanner('Supabase client failed to start: ' + e.message);
        return;
      }
      supabase.auth.getSession().catch((e) => showFatalBanner('Could not reach Supabase: ' + e.message));
      // Deliberately NOT also calling notifyAuthListeners() here — Supabase's
      // client already fires onAuthStateChange immediately upon subscribing
      // below, with whatever the current session is (event: INITIAL_SESSION),
      // so doing it again here was the other half of the duplicate-fire bug
      // described above. getSession() above is kept only so a genuinely
      // broken connection still surfaces as a banner even if that first
      // onAuthStateChange callback never arrives at all.
      supabase.auth.onAuthStateChange((_event, session) => {
        currentSession = session;
        notifyAuthListeners();
      });
    },
    auth,
    database,
    storage: {
      uploadAvatar: uploadAvatarFile,
      removeAvatar: removeAvatarFile,
    },
  };
})(window);
