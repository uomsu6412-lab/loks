const express = require('express');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { Readable } = require('stream');
const { v4: uuidv4 } = require('uuid');

const app = express();

// ---- Cloudinary 凭据（从环境变量读取，但不依赖全局配置） ----
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY;
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET;

// ---- 数据库连接（PostgreSQL） ----
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

(async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS videos (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        filename TEXT NOT NULL,
        uploaded_by TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    console.log('PostgreSQL 数据库已连接');
  } catch (err) {
    console.error('数据库初始化失败:', err.message);
  }
})();

// ---- 托管前端静态文件 ----
app.use(express.static('public'));

// ---- CSP 响应头 ----
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; media-src 'self'; img-src 'self' data: https:; connect-src 'self';");
  next();
});

// ---- multer 内存存储 ----
const upload = multer({ storage: multer.memoryStorage() });

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

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.send('用户名和密码不能为空');
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const existing = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) {
      await pool.query('DELETE FROM users WHERE username = $1', [username]);
    }
    await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);
    res.send('注册成功！');
  } catch (err) {
    console.error('注册出错:', err.message);
    res.send('注册失败，请稍后重试');
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.send('用户名或密码不能为空');
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user || !user.password) return res.send('用户名或密码错误');
    const match = await bcrypt.compare(password, user.password);
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

app.get('/api/videos', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM videos ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('获取视频列表失败:', err.message);
    res.json([]);
  }
});

// 上传视频（base64 直传，硬编码凭据）
app.post('/api/upload', upload.single('video'), async (req, res) => {
  const cookieToken = req.cookies.csrf_token;
  const bodyToken = req.body._csrf;
  if (!cookieToken || !bodyToken || cookieToken !== bodyToken) {
    return res.status(403).send('CSRF 令牌无效');
  }
  if (!req.cookies.user) return res.status(401).send('请先登录');
  if (!req.file) return res.status(400).send('未接收到视频文件');

  const { title } = req.body;

  try {
    const base64Video = req.file.buffer.toString('base64');
    const dataUri = `data:${req.file.mimetype};base64,${base64Video}`;

    const uploaded = await cloudinary.uploader.upload(dataUri, {
      resource_type: 'video',
      folder: 'loks-videos',
      transformation: [{ quality: 'auto' }],
      public_id: uuidv4(),
      api_key: CLOUDINARY_API_KEY,        // ← 新增
      api_secret: CLOUDINARY_API_SECRET,  // ← 新增
      cloud_name: CLOUDINARY_CLOUD_NAME,  // ← 新增
    });
    const videoUrl = uploaded.secure_url;

    await pool.query(
      'INSERT INTO videos (title, filename, uploaded_by) VALUES ($1, $2, $3)',
      [title, videoUrl, req.cookies.user]
    );

    res.redirect('/L0Ks.html');
  } catch (err) {
    console.error('上传失败 - 完整错误:', JSON.stringify(err, Object.getOwnPropertyNames(err), 2));
    if (err.error) console.error('Cloudinary 原始错误:', JSON.stringify(err.error));
    res.send('上传失败，请稍后重试');
  }
});

// ---- 全局错误捕获 ----
process.on('uncaughtException', (err) => {
  console.error('未捕获的异常:', err.message, err.stack);
});
process.on('unhandledRejection', (reason) => {
  console.error('未处理的 Promise 拒绝:', reason);
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log('私人番剧站已启动 → 端口 ' + port);
});