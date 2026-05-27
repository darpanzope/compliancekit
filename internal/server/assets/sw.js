// compliancekit service worker — v1.16 phase 1.
//
// Three caching strategies, no Workbox build step:
//
//   /assets/*   stale-while-revalidate (cache first, refresh in
//               background; cached assets survive offline boot)
//   /api/v1/*   network-first (always try the daemon; fall back to
//               cache if offline so the explorer doesn't blank)
//   navigation  network-first with /offline fallback page when both
//               the network AND the cache miss
//
// Cache name pins the daemon version (window.ck.version is written
// into base.html). Bumping the version invalidates every cache on
// the next install — no stale assets after a deploy. The activate
// handler deletes any older cache.
//
// Registration happens in app.js (v1.16 phase 1 amendment); the SW
// is served at the root scope by /sw.js so it controls every page.

const VERSION = 'ck-cache-v1.16.0';
const ASSET_CACHE = `${VERSION}-assets`;
const API_CACHE = `${VERSION}-api`;
const PAGE_CACHE = `${VERSION}-pages`;

const OFFLINE_PAGE = '/offline';

// Assets we pre-cache during install so the first offline launch
// has the shell, the icon set, and the offline page available.
const PRECACHE = [
  '/manifest.webmanifest',
  '/assets/app.css',
  '/assets/app.js',
  '/assets/a11y.js',
  '/assets/htmx.min.js',
  '/assets/alpine.min.js',
  '/assets/preline.js',
  '/assets/icon-192.png',
  '/assets/icon-512.png',
  '/assets/favicon-32.png',
  '/assets/apple-touch-icon.png',
  OFFLINE_PAGE,
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(ASSET_CACHE).then((cache) =>
      // Best-effort precache — a single 404 should not abort the
      // install (e.g. /offline 404s during a partial deploy). Map
      // each fetch through addAll's contract by individual put.
      Promise.all(
        PRECACHE.map((url) =>
          fetch(url, { credentials: 'same-origin' })
            .then((res) => (res.ok ? cache.put(url, res) : null))
            .catch(() => null),
        ),
      ),
    ),
  );
  // Activate the new worker as soon as install resolves rather than
  // waiting for every tab to close. Combined with clients.claim() in
  // activate, this gives an upgraded daemon a clean cache state on
  // first reload.
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => !k.startsWith(VERSION))
          .map((k) => caches.delete(k)),
      ),
    ),
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // never intercept cross-origin

  // Navigation requests — network-first with /offline fallback.
  if (req.mode === 'navigate') {
    event.respondWith(handleNavigate(req));
    return;
  }

  // Static asset bundle — stale-while-revalidate.
  if (url.pathname.startsWith('/assets/') || url.pathname === '/manifest.webmanifest') {
    event.respondWith(staleWhileRevalidate(req, ASSET_CACHE));
    return;
  }

  // API — network-first with cache fallback for the read paths
  // (writes never hit the worker because of the method gate above).
  if (url.pathname.startsWith('/api/v1/')) {
    event.respondWith(networkFirst(req, API_CACHE));
    return;
  }
});

async function staleWhileRevalidate(req, cacheName) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(req);
  const fetchPromise = fetch(req)
    .then((res) => {
      if (res.ok) cache.put(req, res.clone());
      return res;
    })
    .catch(() => cached);
  return cached || fetchPromise;
}

async function networkFirst(req, cacheName) {
  const cache = await caches.open(cacheName);
  try {
    const res = await fetch(req);
    if (res.ok) cache.put(req, res.clone());
    return res;
  } catch (err) {
    const cached = await cache.match(req);
    if (cached) return cached;
    return new Response(JSON.stringify({ error: 'offline', cached: false }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

async function handleNavigate(req) {
  const cache = await caches.open(PAGE_CACHE);
  try {
    const res = await fetch(req);
    if (res.ok) cache.put(req, res.clone());
    return res;
  } catch (err) {
    const cached = await cache.match(req);
    if (cached) {
      // v1.16 phase 7 — notify all controlled pages that this
      // navigation is being served from cache so they can surface
      // the "Showing cached" banner. broadcast to every controlled
      // client (not just the one making the request) so cross-tab
      // operators see the banner consistently.
      broadcast({ type: 'ck:offline', url: req.url, at: Date.now() });
      return cached;
    }
    const offline = await caches.match(OFFLINE_PAGE);
    if (offline) {
      broadcast({ type: 'ck:offline', url: req.url, at: Date.now() });
      return offline;
    }
    return new Response('offline', { status: 503, headers: { 'Content-Type': 'text/plain' } });
  }
}

// broadcast posts a message to every controlled client. Used for
// the v1.16 phase 7 "showing cached" banner — operators see it
// across tabs without each tab having to poll navigator.onLine.
async function broadcast(msg) {
  try {
    const all = await self.clients.matchAll({ includeUncontrolled: true });
    all.forEach((c) => {
      try { c.postMessage(msg); } catch (e) {}
    });
  } catch (e) {}
}

// v1.16 phase 4 — Web Push event handler. Browsers wake the SW
// when a VAPID-signed push arrives; we decrypt the payload (the
// browser handles that automatically because the keys were
// provisioned during subscribe()) and surface it as a system
// notification. Tag dedupes repeat alerts so a stuck monitor
// doesn't fill the notification shade.
self.addEventListener('push', (event) => {
  let payload = { title: 'compliancekit', body: '', url: '/' };
  if (event.data) {
    try {
      payload = Object.assign(payload, event.data.json());
    } catch (e) {
      payload.body = event.data.text();
    }
  }
  const opts = {
    body: payload.body,
    icon: '/assets/icon-192.png',
    badge: '/assets/icon-192.png',
    tag: payload.tag || 'compliancekit-' + (payload.severity || 'info'),
    data: { url: payload.url || '/' },
    renotify: false,
  };
  event.waitUntil(self.registration.showNotification(payload.title, opts));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const targetURL = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((all) => {
      // Focus an existing tab on the same origin if one is open, else open new.
      for (const c of all) {
        if (c.url.indexOf(self.location.origin) === 0 && 'focus' in c) {
          c.navigate(targetURL);
          return c.focus();
        }
      }
      if (clients.openWindow) return clients.openWindow(targetURL);
    }),
  );
});

// v1.16 phase 7 may extend handleNavigate to surface a "showing
// cached" banner via clients.postMessage when the cached fallback
// fires.
