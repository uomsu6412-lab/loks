const CACHE_NAME = 'l0ks-v2';
const urlsToCache = [
  '/L0Ks.html',
  '/video.html',
  '/profile.html',
  '/manifest.json',
  // 可根据需要缓存更多资源
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(urlsToCache))
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request).then(response => response || fetch(event.request))
  );
});