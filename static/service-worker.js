self.addEventListener('install', event => {
  console.log('Service Worker installing.');
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  console.log('Service Worker activating.');
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => response || fetch(event.request))
  );
});

self.addEventListener('push', function(event) {
  const data = event.data.json();
  const title = data.title || "PERSTAT Notification";
  const options = {
    body: data.body,
    icon: '/static/icon.png', // optional icon
    badge: '/static/badge.png' // optional badge
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("push", function(event) {
  const data = event.data.json();
  const options = {
    body: data.body,
    icon: "/static/icon.png",  // Optional icon
    vibrate: [200, 100, 200],
  };

  event.waitUntil(
    self.registration.showNotification(data.title, options)
  );
});

self.addEventListener("push", (event) => {
  let data = {};
  try { data = event.data.json(); } catch {}
  const title = data.title || "PERSTAT";
  const body = data.body || "New notification";
  event.waitUntil(self.registration.showNotification(title, { body, icon: "/static/icon-192.png" }));
});

