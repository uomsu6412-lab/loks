// ==================== Service Worker（优化版） ====================

const CACHE_NAME = 'l0ks-v3';  // 版本号，更新 SW 时递增

// 安装时缓存核心静态资源
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll([
        '/L0Ks.html',
        '/video.html',
        '/profile.html',
        '/manifest.json'
      ]);
    })
  );
  // 立即激活新的 SW，不等待旧 SW 释放
  self.skipWaiting();
});

// 激活时清理旧版本缓存
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.filter(name => name !== CACHE_NAME).map(name => caches.delete(name))
      );
    })
  );
  // 让新 SW 立即接管所有页面
  self.clients.claim();
});

// 请求拦截：优先尝试网络，网络失败时才用缓存（缓存后备策略）
self.addEventListener('fetch', event => {
  // 对 HTML 页面使用 "网络优先" 策略（确保动态内容最新）
  if (event.request.headers.get('accept').includes('text/html')) {
    event.respondWith(
      fetch(event.request)
        .then(response => {
          // 网络请求成功时，更新缓存
          const responseClone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, responseClone));
          return response;
        })
        .catch(() => {
          // 网络失败时，使用缓存
          return caches.match(event.request);
        })
    );
    return;
  }

  // 对非 HTML 资源（CSS、JS、图片等）使用 "缓存优先" 策略
  event.respondWith(
    caches.match(event.request).then(cachedResponse => {
      return cachedResponse || fetch(event.request).then(response => {
        // 网络请求成功时，更新缓存
        const responseClone = response.clone();
        caches.open(CACHE_NAME).then(cache => cache.put(event.request, responseClone));
        return response;
      });
    })
  );
});