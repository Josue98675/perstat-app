// sw-version: 2025-08-10-1


// ---- Install / Activate ----
self.addEventListener('install', (event) => {
  console.log('[SW] installing');
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  console.log('[SW] activating');
  clients.claim();
});

// ---- (Optional) very simple cache passthrough ----
self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request))
  );
});

// ---- Push (single, consolidated handler) ----
self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    // If not JSON, fall back to text
    data = { title: 'PERSTAT', body: event.data ? event.data.text() : 'New notification' };
  }

  const title = data.title || 'PERSTAT';
  const options = {
    body: data.body || 'New notification',
    icon: '/static/icons/icon-192.png',   // update path if different
    badge: '/static/icons/badge-72.png',  // update path if different
    vibrate: [200, 100, 200],
    data: {
      url: data.url || '/',               // where to open on tap
    }
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

// ---- Open the app when user taps the notification ----
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const targetUrl = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      // Focus an open tab if we have one
      for (const client of clientList) {
        const url = new URL(client.url);
        if (url.pathname === targetUrl || url.pathname === '/') {
          return client.focus();
        }
      }
      // Otherwise open a new tab
      return clients.openWindow(targetUrl);
    })
  );
});
