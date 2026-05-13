const express = require('express');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();

// ---- 初始化数据库（持久化文件） ----
const db = new Database('data.db');
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    filename TEXT NOT NULL,
    uploaded_by TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ---- 托管前端静态文件 ----
app.use(express.static('public'));

// ---- CSP 响应头 ----
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; media-src 'self'; img-src 'self' data: https:; connect-src 'self';");
  next();
});

// ---- 文件上传配置 ----
const storage = multer.diskStorage({
  destination: 'public/videos/',
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, uuidv4() + ext);
  }
});
const upload = multer({ storage });

// ---- 中间件 ----
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// ---- CSRF 令牌 ----
function generateCsrfToken() {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}
const tokenStore = new Map();
app.use((req, res, next) => {
  if (!req.cookies.csrf_token) {
    const token = generateCsrfToken();
    res.cookie('csrf_token', token, { httpOnly: false, sameSite: 'lax' });
    tokenStore.set(token, true);
  }
  res.locals.csrfToken = req.cookies.csrf_token || '';
  next();
});

function csrfProtection(req, res, next) {
  const cookieToken = req.cookies.csrf_token;
  const bodyToken = req.body._csrf;
  if (!cookieToken || !bodyToken || cookieToken !== bodyToken) {
    return res.status(403).send('CSRF 令牌无效');
  }
  next();
}

// ---- 路由 ----
app.get('/', (req, res) => res.redirect('/L0Ks.html'));

// 注册
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.send('用户名和密码不能为空');
  }
  try {
    const hashedPassword = bcrypt.hashSync(password, 10);
    const check = db.prepare('SELECT * FROM users WHERE username = ?');
    const existing = check.get(username);
    if (existing) {
      db.prepare('DELETE FROM users WHERE username = ?').run(username);
    }
    db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hashedPassword);
    res.send('注册成功！');
  } catch (err) {
    console.error('注册出错:', err.message);
    res.send('注册失败，请稍后重试');
  }
});

// 登录
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.send('用户名或密码不能为空');
  }
  try {
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user || !user.password) {
      return res.send('用户名或密码错误');
    }
    const match = bcrypt.compareSync(password, user.password);
    if (match) {
      res.cookie('user', username, { httpOnly: true, sameSite: 'lax' });
      res.send('登录成功！');
    } else {
      res.send('用户名或密码错误');
    }
  } catch (err) {
    console.error('登录出错:', err.message);
    res.send('登录失败，请稍后重试');
  }
});

app.get('/api/user', (req, res) => {
  res.json({ username: req.cookies.user || null });
});

// 视频列表
app.get('/api/videos', (req, res) => {
  try {
    db.exec(`CREATE TABLE IF NOT EXISTS videos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      filename TEXT NOT NULL,
      uploaded_by TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`);
    const videos = db.prepare('SELECT * FROM videos ORDER BY created_at DESC').all();
    res.json(videos);
  } catch (err) {
    console.error('获取视频列表失败:', err.message);
    res.json([]);
  }
});

// 上传视频
app.post('/api/upload', csrfProtection, upload.single('video'), (req, res) => {
  if (!req.cookies.user) return res.status(401).send('请先登录');
  const { title } = req.body;
  const filename = req.file.filename;
  db.prepare('INSERT INTO videos (title, filename, uploaded_by) VALUES (?, ?, ?)').run(title, filename, req.cookies.user);
  res.redirect('/L0Ks.html');
});

app.listen(3000, () => {
  console.log('私人番剧站已启动 → http://localhost:3000');
});