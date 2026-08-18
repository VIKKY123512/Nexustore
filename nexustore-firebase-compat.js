/**
 * NexusStore Firebase-compat shim — v3, direct-to-Neon
 * ==========================================================
 * Drop-in replacement for the firebase-app/auth/database *compat* SDK
 * scripts. Implements only the subset of the Firebase JS API this app
 * actually calls, backed by:
 *   - Neon's Managed Better Auth (via @neondatabase/neon-js's
 *     SupabaseAuthAdapter, which mirrors the supabase-js auth API) for
 *     everything under firebase.auth()
 *   - Neon's Data API (PostgREST-compatible) DIRECTLY, protected by Row
 *     Level Security policies — see prisma/enable-rls.sql — for everything
 *     under firebase.database(), EXCEPT orders/payments/secure-downloads/
 *     trash, which still go through nexustore-backend (they need real
 *     server-side logic — price re-validation, gateway calls, rate
 *     limiting — that can't safely live in a client-writable table even
 *     with RLS).
 *
 * This removes the backend entirely from the critical path for browsing,
 * login, profile, wishlist, messages, and (for admins) product/category/
 * settings management — the things that broke whenever Render was slow to
 * wake up or briefly unreachable. Only checkout and downloading a paid/free
 * file still need the backend to be up.
 *
 * HOW TO USE
 * ----------
 *   <script src="nexustore-firebase-compat.js"></script>
 *   <script>
 *     const firebaseConfig = {
 *       neonUrl: "https://ep-xxxx.c-2.us-east-1.aws.neon.tech/neondb", // Neon Console > Connect (HTTPS form, no credentials)
 *       apiBase: "https://your-api-host/api", // still needed for orders/downloads
 *     };
 *     firebase.initializeApp(firebaseConfig);
 *   </script>
 * Everything else in both index.html files — every db.ref(...), auth.*
 * call, function name, DOM id — stays exactly as-is. The old
 * <script src=".../@supabase/supabase-js@2"></script> tag should be
 * removed entirely; it's no longer needed (this file fetches
 * @neondatabase/neon-js itself, from a CDN, via a dynamic import() — this
 * file stays a plain classic script on purpose, NOT type="module", so the
 * rest of index.html's inline <script> blocks keep running in the exact
 * same order/timing they always have).
 *
 * REQUIRES prisma/enable-rls.sql (Neon edition) to have been run in the
 * Neon SQL Editor, AND the Data API to be enabled with Managed Better Auth
 * — without RLS policies, every direct table access below is blocked by
 * default (Postgres denies all access once RLS is enabled with no matching
 * policy), which is the safe failure direction but means nothing will load.
 *
 * KNOWN LIMITATIONS (read before deploying)
 * ------------------------------------------
 * - "value" listeners still poll every 3s rather than pushing instantly.
 * - .orderByChild()/.equalTo()/.limitToLast() are special-cased for the
 *   exact queries this app uses. A new query pattern added later won't be
 *   understood without extending buildHandler() below.
 * - site_settings/pages/* page types are assumed to be about/privacy/terms/refund.
 * - The very first read after a page load can be up to ~1s slower than
 *   before: the old supabase-js CDN script was a blocking <script src>, so
 *   the client library was already loaded by the time firebase.initializeApp()
 *   ran. @neondatabase/neon-js is ESM-only, so it's fetched here via a
 *   dynamic import() instead, which is inherently async — every function
 *   that talks to the database now awaits a shared "ready" promise first.
 * - Neon's Managed Better Auth is in Beta as of this writing. If an auth
 *   method below throws something unexpected, check
 *   https://neon.com/docs/reference/javascript-sdk for the current API
 *   surface of SupabaseAuthAdapter.
 */
(function (global) {
  const PAGE_TYPES = ['about', 'privacy', 'terms', 'refund'];
  const NEON_JS_CDN_URL = 'https://cdn.jsdelivr.net/npm/@neondatabase/neon-js@latest/+esm';
  let API_BASE = '/api';
  let supabase = null;
  let currentSession = null;
  let readyPromise = null; // resolves once @neondatabase/neon-js has loaded and the client is created
  const authStateListeners = [];

  // Every function below that touches the database or auth awaits this
  // first. Resolves once the dynamically-imported client is ready;
  // rejects (without throwing here) if init failed, so callers still get
  // a normal, catchable Error instead of an unhandled rejection.
  async function ready() {
    if (readyPromise) await readyPromise.catch(() => {});
    if (!supabase) throw new Error('App failed to start — reload the page.');
    return supabase;
  }

  function notifyAuthListeners() {
    const user = sessionToFirebaseUser(currentSession);
    authStateListeners.forEach((cb) => cb(user));
  }

  function sessionToFirebaseUser(session) {
    if (!session || !session.user) return null;
    const u = session.user;
    return {
      uid: u.id,
      email: u.email,
      displayName: u.user_metadata?.name || u.user_metadata?.full_name || null,
      getIdToken: async () => (await (await ready()).auth.getSession()).data.session?.access_token,
    };
  }

  async function apiFetch(path, { method = 'GET', body } = {}) {
    const sbClient = await ready();
    const session = (await sbClient.auth.getSession()).data.session;
    let accessToken = session?.access_token;
    if (session && !accessToken && typeof sbClient.auth.token === 'function') {
      // Some Managed Better Auth adapter versions don't put a bearer token
      // on the session object itself (browser sessions are cookie-based by
      // default) — auth.token() is Neon's documented way to get a raw JWT
      // for calling an external API like this backend from a different
      // origin. Falls back to this only if the Supabase-shaped session
      // didn't already include one.
      const { data } = await sbClient.auth.token();
      accessToken = data?.token;
    }
    const headers = { 'Content-Type': 'application/json' };
    if (accessToken) headers.Authorization = 'Bearer ' + accessToken;
    const res = await fetch(API_BASE + path, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || 'Request failed');
    }
    if (res.status === 204) return null;
    return res.json();
  }

  // ---- Direct-Supabase table helpers ------------------------------------
  // Used for everything except orders/payments/secure-downloads/trash (see
  // file header). Every RLS denial surfaces here as a normal thrown Error
  // with Postgres's real message, same as apiFetch does for the backend.

  function toEpoch(dateStr) {
    return dateStr ? new Date(dateStr).getTime() : null;
  }

  async function sbSelect(table, build, columns) {
    const sbClient = await ready();
    let q = sbClient.from(table).select(columns || '*');
    if (build) q = build(q);
    const { data, error } = await q;
    if (error) throw new Error(error.message);
    return data;
  }

  async function sbSelectOne(table, build) {
    const sbClient = await ready();
    let q = sbClient.from(table).select('*');
    if (build) q = build(q);
    const { data, error } = await q.maybeSingle();
    if (error) throw new Error(error.message);
    return data;
  }

  async function sbInsert(table, row) {
    const sbClient = await ready();
    const { data, error } = await sbClient.from(table).insert(row).select().single();
    if (error) throw new Error(error.message);
    return data;
  }

  async function sbUpdate(table, matchCol, matchVal, patch) {
    const sbClient = await ready();
    const { error } = await sbClient.from(table).update(patch).eq(matchCol, matchVal);
    if (error) throw new Error(error.message);
  }

  async function sbDelete(table, matchCol, matchVal) {
    const sbClient = await ready();
    const { error } = await sbClient.from(table).delete().eq(matchCol, matchVal);
    if (error) throw new Error(error.message);
  }

  async function sbUpsert(table, row, conflictCol) {
    const sbClient = await ready();
    const { error } = await sbClient.from(table).upsert(row, { onConflict: conflictCol });
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
      return { get: async () => keyedObject(await sbSelect('User')) };
    }
    if ((m = path.match(/^users\/([^/]+)\/wishlist$/))) {
      const uid = m[1];
      return {
        setVal: async (arr) => {
          await sbDelete('Wishlist', 'userId', uid);
          if (Array.isArray(arr) && arr.length) {
            const sbClient = await ready();
            const { error } = await sbClient.from('Wishlist').insert(arr.map((productId) => ({ userId: uid, productId })));
            if (error) throw new Error(error.message);
          }
        },
      };
    }
    if ((m = path.match(/^users\/([^/]+)\/status$/))) {
      const uid = m[1];
      return { get: () => sbSelectOne('User', (q) => q.eq('id', uid)).then((u) => u?.status ?? null) };
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
            });
          }
          if (!user) return null;
          const wishRows = await sbSelect('Wishlist', (q) => q.eq('userId', uid));
          return {
            ...user,
            wishlist: (wishRows || []).map((r) => r.productId),
            avatar: `https://api.dicebear.com/9.x/bottts-neutral/svg?seed=${encodeURIComponent(user.name || user.id)}`,
          };
        },
        setVal: (v) => sbUpdate('User', 'id', uid, { name: v.name }),
        updateVal: (v) => sbUpdate('User', 'id', uid, uid === currentUid() ? { name: v.name } : v),
        removeVal: () => sbDelete('User', 'id', uid),
      };
    }

    // messages (support ticket thread) -> Message table. RLS restricts a
    // regular user's SELECT to their own rows automatically, so the same
    // query works for both "my thread" and "admin sees everyone" — no
    // separate endpoint needed.
    function serializeMessageRow(m) {
      return {
        id: m.id,
        user: m.userId,
        userName: m.User?.name ?? null,
        userEmail: m.User?.email ?? null,
        title: m.title,
        body: m.body,
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
        push: (v) => sbInsert('Message', { userId: currentUid(), title: v.title, body: v.body, imageData: v.imageData }),
      };
    }
    if ((m = path.match(/^messages\/(.+)$/))) {
      const id = m[1];
      return {
        updateVal: (v) => sbUpdate('Message', 'id', id, { reply: v.reply, replyTime: new Date().toISOString() }),
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
      const poll = async () => {
        try {
          const val = await handler.get();
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
        }
      };
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
      setPersistence: async () => {}, // Session persistence is handled by the client by default; no-op
      signOut: async () => (await ready()).auth.signOut(),
      // Auth calls resolve normally even on failure (wrong password,
      // unconfirmed email, etc.) — the failure is just an `error` field on
      // the result. Firebase instead REJECTS the promise on failure and
      // resolves with a {user: {...}} shape on success. Without this
      // translation, app code's .catch() never fires on real auth errors,
      // and .then(cred => cred.user.uid) crashes on success because the
      // shape doesn't match — which is what was actually breaking login/signup.
      signInWithEmailAndPassword: async (email, password) => {
        const sbClient = await ready();
        const { data, error } = await sbClient.auth.signInWithPassword({ email, password });
        if (error) throw error;
        return { user: sessionToFirebaseUser({ user: data.user }) };
      },
      createUserWithEmailAndPassword: async (email, password) => {
        const sbClient = await ready();
        const { data, error } = await sbClient.auth.signUp({ email, password });
        if (error) throw error;
        if (!data.session) {
          // Account was created, but email confirmation is gating the
          // session until the user clicks a link in their inbox — unlike
          // Firebase, which logs a new user in immediately. To match the
          // old app's instant-login-after-signup behavior, look for the
          // equivalent of "Confirm email" in Neon Auth's settings and
          // disable it if you want signup to log the user straight in.
          throw new Error('Account created — check your email to confirm it, then log in.');
        }
        return { user: sessionToFirebaseUser({ user: data.user }) };
      },
      sendPasswordResetEmail: async (email) => {
        const sbClient = await ready();
        const { error } = await sbClient.auth.resetPasswordForEmail(email);
        if (error) throw error;
      },
      signInWithPopup: async () => {
        const sbClient = await ready();
        const { error } = await sbClient.auth.signInWithOAuth({ provider: 'google' }); // OAuth always redirects; no true popup
        if (error) throw error;
      },
      signInWithRedirect: async () => {
        const sbClient = await ready();
        const { error } = await sbClient.auth.signInWithOAuth({ provider: 'google' });
        if (error) throw error;
      },
      getRedirectResult: async () => ({ user: sessionToFirebaseUser(currentSession) }),
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

  function showFatalBanner(message) {
    const banner = document.createElement('div');
    banner.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:999999;background:#dc2626;color:#fff;padding:12px;text-align:center;font-family:sans-serif;font-size:14px;word-break:break-all;';
    banner.textContent = message;
    const attach = () => document.body.prepend(banner);
    document.body ? attach() : window.addEventListener('DOMContentLoaded', attach);
    console.error('[nexustore-compat] ' + message);
  }

  function validateConfig(config) {
    const problems = [];
    if (
      !config.neonUrl ||
      !/^https:\/\/[a-z0-9-]+(\.[a-z0-9-]+)*\.neon\.(tech|build)\/.+/i.test(config.neonUrl.trim())
    ) {
      problems.push(`neonUrl looks wrong: "${config.neonUrl}" — should look like https://ep-xxxx.c-2.us-east-1.aws.neon.tech/neondb (the HTTPS form from Neon Console > Connect, no credentials, no query params, no trailing /rest/v1 or /auth).`);
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
      readyPromise = (async () => {
        let createClient, SupabaseAuthAdapter;
        try {
          ({ createClient, SupabaseAuthAdapter } = await import(NEON_JS_CDN_URL));
        } catch (e) {
          showFatalBanner('Could not load required libraries (Neon). Check your internet connection and reload the page.');
          throw e;
        }
        try {
          supabase = createClient(config.neonUrl.trim(), {
            auth: { adapter: SupabaseAuthAdapter() },
          });
        } catch (e) {
          showFatalBanner('Neon client failed to start: ' + e.message);
          throw e;
        }
        const { data } = await supabase.auth.getSession();
        currentSession = data.session;
        notifyAuthListeners();
        supabase.auth.onAuthStateChange((_event, session) => {
          currentSession = session;
          notifyAuthListeners();
        });
      })();
      readyPromise.catch((e) => console.error('[nexustore-compat] init failed:', e));
    },
    auth,
    database,
  };
})(window);
