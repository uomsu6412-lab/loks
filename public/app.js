// ========== 工具函数 ==========
function getCsrfToken() {
  var match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]*)/);
  return match ? match[1] : '';
}

function fillCsrf() {
  var token = getCsrfToken();
  document.getElementById('csrfInputLogin').value = token;
  document.getElementById('csrfInputReg').value = token;
  document.getElementById('csrfInputUpload').value = token;
}

// ========== 页面初始化 ==========
window.addEventListener('DOMContentLoaded', function() {
  fillCsrf();
  checkLogin();
  loadVideos();
});

// ========== 检查登录状态 ==========
async function checkLogin() {
  var response = await fetch('/api/user');
  var data = await response.json();
  if (data.username) {
    document.getElementById('userArea').textContent = '👤 ' + data.username + ' 已登录';
    document.getElementById('uploadBox').style.display = 'block';
    document.getElementById('authBox').style.display = 'none';
  } else {
    document.getElementById('userArea').textContent = '未登录';
    document.getElementById('uploadBox').style.display = 'none';
    document.getElementById('authBox').style.display = 'block';
  }
}

// ========== 加载视频列表 ==========
async function loadVideos() {
  var response = await fetch('/api/videos');
  var videos = await response.json();
  var container = document.getElementById('videoContainer');
  container.innerHTML = '';
  if (videos.length === 0) {
    container.innerHTML = '<p style="color: white;">还没有人分享片源，成为第一个吧！</p>';
    return;
  }
  videos.forEach(function(v) {
    var card = document.createElement('div');
    card.className = 'card';
card.innerHTML = '<video controls src="' + v.filename + '"></video>' +
                     '<h3>' + v.title + '</h3>' +
                     '<div class="meta">上传者：' + v.uploaded_by + '</div>';
    container.appendChild(card);
  });
}

// ========== 登录 ==========
document.getElementById('loginForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  var username = document.getElementById('loginUsername').value;
  var password = document.getElementById('loginPassword').value;
  var csrfToken = document.getElementById('csrfInputLogin').value;
  var response = await fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username, password, _csrf: csrfToken }).toString()
  });
  var msg = await response.text();
  document.getElementById('loginMsg').textContent = msg;
  if (msg === '登录成功！') {
    checkLogin();
    loadVideos();
  }
});

// ========== 注册 ==========
document.getElementById('registerForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  var username = document.getElementById('regUsername').value;
  var password = document.getElementById('regPassword').value;
  var csrfToken = document.getElementById('csrfInputReg').value;
  var response = await fetch('/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username, password, _csrf: csrfToken }).toString()
  });
  document.getElementById('registerMsg').textContent = await response.text();
});

// ========== 上传视频 ==========
document.getElementById('uploadForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  var formData = new FormData();
  formData.append('title', document.getElementById('videoTitle').value);
  formData.append('video', document.getElementById('videoFile').files[0]);
  formData.append('_csrf', document.getElementById('csrfInputUpload').value);
  var response = await fetch('/api/upload', { method: 'POST', body: formData });
  if (response.redirected) {
    window.location.href = response.url;
  } else {
    document.getElementById('uploadMsg').textContent = await response.text();
  }
});
