/**
 * NexusStore Firebase-compat shim
 * ================================
 * Drop-in replacement for the firebase-app/auth/database *compat* SDK
 * scripts. Implements only the subset of the Firebase JS API this app
 * actually calls (verified against both index.html files), backed by:
 *   - Supabase Auth for everything under firebase.auth()
 *   - The NexusStore REST API (nexustore-backend) for everything under
 *     firebase.database()
 *
 * HOW TO USE
 * ----------
 * Replace these three lines in <head>/before your inline <script>:
 *   <script src=".../firebase-app-compat.js"></script>
 *   <script src=".../firebase-auth-compat.js"></script>
 *   <script src=".../firebase-database-compat.js"></script>
 * with:
 *   <script src="https://unpkg.com/@supabase/supabase-js@2"></script>
 *   <script src="nexustore-firebase-compat.js"></script>
 *
 * And replace the firebaseConfig object + firebase.initializeApp(...) call
 * with:
 *   const firebaseConfig = {
 *     supabaseUrl: "https://xxxx.supabase.co",
 *     supabaseAnonKey: "eyJ...",   // Settings > API > anon/public key
 *     apiBase: "https://your-api-host/api",
 *   };
 *   firebase.initializeApp(firebaseConfig);
 * Everything else in both index.html files — every db.ref(...), auth.*
 * call, function name, DOM id — stays exactly as-is.
 *
 * KNOWN LIMITATIONS (read before deploying)
 * ------------------------------------------
 * - "value" listeners poll every 3s instead of pushing instantly. For a
 *   store this size that's imperceptible for catalog/config data; for the
 *   support-reply notification it means up to ~3s delay instead of instant.
 * - .orderByChild()/.equalTo()/.limitToLast() are special-cased for the
 *   exact queries this app uses (orders by userId, messages by user
 *   thread). A new query pattern added later won't be understood by this
 *   shim without extending PATH_HANDLERS below.
 * - site_settings/pages/* page types are assumed to be about/privacy/terms/refund.
 *   If you add a new footer page type in admin.html, add it to PAGE_TYPES below.
 */
(function (global) {
  const PAGE_TYPES = ['about', 'privacy', 'terms', 'refund'];
  let API_BASE = '/api';
  let supabase = null;
  let currentSession = null;
  const authStateListeners = [];

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
      getIdToken: async () => (await supabase.auth.getSession()).data.session?.access_token,
    };
  }

  async function apiFetch(path, { method = 'GET', body } = {}) {
    if (!supabase) throw new Error('App failed to start — reload the page.');
    const session = (await supabase.auth.getSession()).data.session;
    const headers = { 'Content-Type': 'application/json' };
    if (session) headers.Authorization = 'Bearer ' + session.access_token;
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

  // Only admin.html defines window.ADMIN_WHITELIST — used purely to avoid
  // firing a doomed /admin/* request (and a console 403) for every regular
  // logged-in storefront user on every 3s poll. The real authorization
  // check always happens server-side (requireAdmin), this is just routing.
  function isAdminPage() {
    const email = currentSession?.user?.email?.toLowerCase();
    return typeof global.ADMIN_WHITELIST !== 'undefined' && email && global.ADMIN_WHITELIST.map((e) => e.toLowerCase()).includes(email);
  }

  function buildHandler(path, query) {
    let m;

    // config/{key}
    if ((m = path.match(/^config\/(.+)$/))) {
      const key = m[1];
      return {
        get: () => apiFetch(`/config/${key}`),
        setVal: (v) => apiFetch(`/admin/config/${key}`, { method: 'PUT', body: v }),
        updateVal: async (v) => {
          const cur = (await apiFetch(`/config/${key}`)) || {};
          return apiFetch(`/admin/config/${key}`, { method: 'PUT', body: { ...cur, ...v } });
        },
        removeVal: () => apiFetch(`/admin/config/${key}`, { method: 'DELETE' }),
      };
    }

    // site_settings/pages/{type}
    if ((m = path.match(/^site_settings\/pages\/(.+)$/))) {
      const key = `pages.${m[1]}`;
      return {
        get: () => apiFetch(`/settings/${key}`),
        setVal: (v) => apiFetch(`/admin/settings/${key}`, { method: 'PUT', body: v }),
        updateVal: (v) => apiFetch(`/admin/settings/${key}`, { method: 'PUT', body: v }),
      };
    }
    if (path === 'site_settings/socials' || path === 'site_settings/popup') {
      const key = path.split('/')[1];
      return {
        get: () => apiFetch(`/settings/${key}`),
        setVal: (v) => apiFetch(`/admin/settings/${key}`, { method: 'PUT', body: v }),
        updateVal: async (v) => {
          const cur = (await apiFetch(`/settings/${key}`)) || {};
          return apiFetch(`/admin/settings/${key}`, { method: 'PUT', body: { ...cur, ...v } });
        },
      };
    }
    if (path === 'site_settings') {
      return {
        get: async () => {
          const pages = {};
          for (const t of PAGE_TYPES) pages[t] = await apiFetch(`/settings/pages.${t}`);
          const socials = await apiFetch('/settings/socials');
          const popup = await apiFetch('/settings/popup');
          return { pages, socials, popup };
        },
      };
    }

    // categories
    if (path === 'categories') {
      return {
        get: async () => keyedObject(await apiFetch(isAdminPage() ? '/admin/categories' : '/categories')),
        push: (v) => apiFetch('/admin/categories', { method: 'POST', body: v }),
      };
    }
    if ((m = path.match(/^categories\/(.+)$/))) {
      const id = m[1];
      return {
        setVal: (v) => apiFetch(`/admin/categories/${id}`, { method: 'PUT', body: v }),
        updateVal: (v) => apiFetch(`/admin/categories/${id}`, { method: 'PUT', body: v }), // admin always sends full object
        removeVal: () => apiFetch(`/admin/categories/${id}`, { method: 'DELETE' }),
      };
    }

    // apps (products)
    if (path === 'apps') {
      return {
        get: async () => keyedObject(await apiFetch(isAdminPage() ? '/admin/products' : '/products')),
        pushKeyOnly: () => crypto.randomUUID(),
      };
    }
    if ((m = path.match(/^apps\/(.+)$/))) {
      const id = m[1];
      return {
        get: () => apiFetch(`/products/${id}`).catch(() => null),
        setVal: (v) => apiFetch('/admin/products', { method: 'POST', body: { id, ...v } }),
        updateVal: (v) => apiFetch(`/admin/products/${id}`, { method: 'PUT', body: v }),
        removeVal: () => apiFetch(`/admin/products/${id}`, { method: 'DELETE' }),
      };
    }

    // orders
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
        // Stale-pending-order cleanup (attachOrdersListener) calls .remove()
        // directly — same effect as cancelling, so route it there.
        removeVal: () => apiFetch(`/orders/${id}/cancel`, { method: 'PATCH' }).catch(() => {}),
      };
    }

    // users
    if (path === 'users') {
      return { get: async () => keyedObject(await apiFetch('/admin/users')) };
    }
    // users/{uid}/wishlist — a plain array of product ids, written as a
    // whole (currentUser.wishlist is mutated locally then .set() back),
    // not added/removed one product at a time.
    if ((m = path.match(/^users\/([^/]+)\/wishlist$/))) {
      return {
        setVal: (arr) => apiFetch('/me/wishlist', { method: 'PUT', body: arr }),
      };
    }
    if ((m = path.match(/^users\/([^/]+)\/status$/))) {
      const uid = m[1];
      return {
        get: async () => {
          if (uid === currentUid()) return (await apiFetch('/me')).status;
          const all = await apiFetch('/admin/users');
          return all.find((u) => u.id === uid)?.status ?? null;
        },
      };
    }
    if ((m = path.match(/^users\/([^/]+)$/))) {
      const uid = m[1];
      return {
        get: async () => {
          if (uid === currentUid()) {
            const u = sessionToFirebaseUser(currentSession);
            return apiFetch('/me/ensure', { method: 'POST', body: { name: u?.displayName || u?.email?.split('@')[0] || null } });
          }
          const all = await apiFetch('/admin/users');
          return all.find((u) => u.id === uid) || null;
        },
        setVal: (v) => (uid === currentUid() ? apiFetch('/me', { method: 'PATCH', body: v }) : null),
        updateVal: (v) =>
          uid === currentUid()
            ? apiFetch('/me', { method: 'PATCH', body: v })
            : apiFetch(`/admin/users/${uid}/status`, { method: 'PATCH', body: v }),
        removeVal: () => apiFetch(`/admin/users/${uid}`, { method: 'DELETE' }),
      };
    }

    // messages (support ticket thread)
    if (path === 'messages') {
      if (query.orderField === 'user' && query.equalValue) {
        return { get: async () => keyedObject(await apiFetch('/me/messages')) };
      }
      return {
        get: async () => keyedObject(await apiFetch('/admin/messages')),
        push: (v) => apiFetch('/messages', { method: 'POST', body: { title: v.title, msg: v.msg } }),
      };
    }
    if ((m = path.match(/^messages\/(.+)$/))) {
      const id = m[1];
      return {
        updateVal: (v) => apiFetch(`/admin/messages/${id}`, { method: 'PATCH', body: { reply: v.reply } }),
        removeVal: () => apiFetch(`/admin/messages/${id}`, { method: 'DELETE' }),
      };
    }

    // notifications
    if (path === 'notifications') {
      return {
        get: async () => keyedObject(await apiFetch('/notifications')),
        push: (v) => apiFetch('/admin/notifications', { method: 'POST', body: { title: v.title, body: v.msg } }),
      };
    }
    if ((m = path.match(/^notifications\/(.+)$/))) {
      const id = m[1];
      return { removeVal: () => apiFetch(`/admin/notifications/${id}`, { method: 'DELETE' }) };
    }

    // downloads_log (read-only from the client — entries are written server-side)
    if (path === 'downloads_log') {
      return { get: async () => keyedObject(await apiFetch('/admin/downloads-log')) };
    }

    // trash
    if (path === 'trash') {
      return { get: async () => keyedObject(await apiFetch('/admin/trash')) };
    }
    if ((m = path.match(/^trash\/(.+)$/))) {
      const id = m[1];
      return { removeVal: () => apiFetch(`/admin/trash/${id}`, { method: 'DELETE' }) };
    }

    // secureDownloads (admin download-link management)
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
            // Special-cased for the one real usage (support-reply notification):
            // val is expected to be an array; fire once per item whose reply changed.
            if (Array.isArray(val) && prevJson !== null) {
              const prevArr = JSON.parse(prevJson);
              val.forEach((item) => {
                const prevItem = prevArr.find((p) => p.id === item.id);
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
      supabase.auth.getSession().then(({ data }) => {
        currentSession = data.session;
        notifyAuthListeners();
      }).catch((e) => showFatalBanner('Could not reach Supabase: ' + e.message));
      supabase.auth.onAuthStateChange((_event, session) => {
        currentSession = session;
        notifyAuthListeners();
      });
    },
    auth,
    database,
  };
})(window);
