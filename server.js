// ==================== 引入依赖 ====================
const express = require('express');
const bcrypt = require('bcrypt');                         // 密码加密
const cookieParser = require('cookie-parser');           // 解析 Cookie
const { Pool } = require('pg');                          // PostgreSQL 数据库
const multer = require('multer');                        // 处理文件上传
const cloudinary = require('cloudinary').v2;             // 云存储
const { v4: uuidv4 } = require('uuid');                 // 生成唯一ID
const helmet = require('helmet');                        // 安全防护

const app = express();

// ==================== 1. 安全防护 (helmet) ====================
app.use(helmet({
  contentSecurityPolicy: false,       // 我们已自定义 CSP，关闭 helmet 的 CSP
  crossOriginEmbedderPolicy: false,
}));

// ==================== 2. Cloudinary 凭据 ====================
// 从 Render 环境变量中读取，不写死在代码里
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY;
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET;

// ==================== 3. 数据库连接 (PostgreSQL) ====================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }    // Render 上需要 SSL
});

// 初始化数据库表结构
(async () => {
  try {
    // 创建用户表
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
    `);
    // 创建视频表
    await pool.query(`
      CREATE TABLE IF NOT EXISTS videos (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        filename TEXT NOT NULL,
        uploaded_by TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // 动态追加新列，避免旧数据丢失
    await pool.query('ALTER TABLE videos ADD COLUMN IF NOT EXISTS thumbnail TEXT;');
    await pool.query('ALTER TABLE videos ADD COLUMN IF NOT EXISTS public_id TEXT;');
    await pool.query("ALTER TABLE videos ADD COLUMN IF NOT EXISTS category TEXT DEFAULT '其他';");
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS nickname TEXT;');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT;');

    console.log('PostgreSQL 数据库已连接');
  } catch (err) {
    console.error('数据库初始化失败:', err.message);
  }
})();

// ==================== 4. 静态文件托管 ====================
app.use(express.static('public'));

// ==================== 5. 自定义 CSP 响应头 ====================
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://www.googletagmanager.com; style-src 'self' 'unsafe-inline'; media-src 'self'; img-src 'self' data: https:; connect-src 'self' https://www.google-analytics.com;");
  next();
});

// ==================== 6. multer 配置 ====================
// 使用内存存储，直接拿到文件 buffer，然后传给 Cloudinary
const upload = multer({ storage: multer.memoryStorage() });
const uploadAvatar = multer({ storage: multer.memoryStorage() });

// ==================== 7. 中间件 ====================
app.use(express.urlencoded({ extended: false }));   // 解析表单数据
app.use(cookieParser());                            // 解析 Cookie

// ==================== 8. CSRF 保护 ====================
function generateCsrfToken() {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}
const tokenStore = new Map();

// 为每个请求分配 CSRF Token
app.use((req, res, next) => {
  if (!req.cookies.csrf_token) {
    const token = generateCsrfToken();
    res.cookie('csrf_token', token, { httpOnly: false, sameSite: 'lax' });
    tokenStore.set(token, true);
  }
  res.locals.csrfToken = req.cookies.csrf_token || '';
  next();
});

// 验证 CSRF Token 的中间件
function csrfProtection(req, res, next) {
  const cookieToken = req.cookies.csrf_token;
  const bodyToken = req.body._csrf;
  if (!cookieToken || !bodyToken || cookieToken !== bodyToken) {
    return res.status(403).send('CSRF 令牌无效');
  }
  next();
}

// ==================== 路由 ====================

// --- 首页重定向 ---
app.get('/', (req, res) => res.redirect('/L0Ks.html'));

// --- 注册 ---
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
  // ==================== 用户资料相关路由 ====================

// 获取当前登录用户的详细资料
app.get('/api/profile', async (req, res) => {
  if (!req.cookies.user) return res.status(401).json({ error: '未登录' });
  try {
    const result = await pool.query('SELECT username, nickname, avatar FROM users WHERE username = $1', [req.cookies.user]);
    if (result.rows.length === 0) return res.status(404).json({ error: '用户不存在' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('获取用户资料失败:', err.message);
    res.status(500).json({ error: '服务器错误' });
  }
});

// 更新昵称
app.post('/api/profile/nickname', csrfProtection, async (req, res) => {
  if (!req.cookies.user) return res.status(401).send('请先登录');
  const { nickname } = req.body;
  if (!nickname) return res.send('昵称不能为空');
  try {
    await pool.query('UPDATE users SET nickname = $1 WHERE username = $2', [nickname, req.cookies.user]);
    res.send('昵称已更新');
  } catch (err) {
    console.error('更新昵称失败:', err.message);
    res.status(500).send('更新失败');
  }
});

// 上传头像（base64 格式，存储到 Cloudinary，然后更新数据库）
app.post('/api/profile/avatar', upload.single('avatar'), async (req, res) => {
  if (!req.cookies.user) return res.status(401).send('请先登录');
  if (!req.file) return res.status(400).send('未收到图片');
  // 手动 CSRF 验证
  const cookieToken = req.cookies.csrf_token;
  const bodyToken = req.body._csrf;
  if (!cookieToken || !bodyToken || cookieToken !== bodyToken) {
    return res.status(403).send('CSRF 令牌无效');
  }
  try {
    const base64Image = req.file.buffer.toString('base64');
    const dataUri = `data:${req.file.mimetype};base64,${base64Image}`;
    const uploaded = await cloudinary.uploader.upload(dataUri, {
      folder: 'loks-avatars',
      transformation: [{ width: 150, height: 150, crop: 'fill', quality: 'auto' }],
      public_id: 'avatar_' + req.cookies.user,
      api_key: CLOUDINARY_API_KEY,
      api_secret: CLOUDINARY_API_SECRET,
      cloud_name: CLOUDINARY_CLOUD_NAME,
    });
    const avatarUrl = uploaded.secure_url;
    await pool.query('UPDATE users SET avatar = $1 WHERE username = $2', [avatarUrl, req.cookies.user]);
    res.send('头像已更新');
  } catch (err) {
    console.error('头像上传失败:', err.message);
    res.status(500).send('头像上传失败');
  }
});

// 修改密码
app.post('/api/profile/password', csrfProtection, async (req, res) => {
  if (!req.cookies.user) return res.status(401).send('请先登录');
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) return res.send('旧密码和新密码不能为空');
  try {
    const result = await pool.query('SELECT password FROM users WHERE username = $1', [req.cookies.user]);
    const user = result.rows[0];
    if (!user) return res.send('用户不存在');
    const match = await bcrypt.compare(oldPassword, user.password);
    if (!match) return res.send('旧密码错误');
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE username = $2', [hashedPassword, req.cookies.user]);
    res.send('密码已修改');
  } catch (err) {
    console.error('修改密码失败:', err.message);
    res.status(500).send('修改失败');
  }
});
});

// --- 登录 ---
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

// --- 获取当前登录用户 ---
app.get('/api/user', (req, res) => {
  res.json({ username: req.cookies.user || null });
});

// --- 视频列表（支持分类筛选） ---
app.get('/api/videos', async (req, res) => {
  try {
    const { category } = req.query;
    let query = 'SELECT * FROM videos';
    const params = [];
    if (category && category !== '全部') {
      query += ' WHERE category = $1';
      params.push(category);
    }
    query += ' ORDER BY created_at DESC';
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('获取视频列表失败:', err.message);
    res.json([]);
  }
});

// --- 视频详情 ---
app.get('/api/videos/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM videos WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).send('视频不存在');
    res.json(result.rows[0]);
  } catch (err) {
    console.error('获取视频详情失败:', err.message);
    res.status(500).send('服务器错误');
  }
});

// --- 删除视频（仅上传者本人） ---
app.post('/api/videos/:id/delete', csrfProtection, async (req, res) => {
  if (!req.cookies.user) return res.status(401).send('请先登录');
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM videos WHERE id = $1', [id]);
    const video = result.rows[0];
    if (!video) return res.status(404).send('视频不存在');
    if (video.uploaded_by !== req.cookies.user) {
      return res.status(403).send('无权删除他人视频');
    }

    // 如果存有 Cloudinary 的 public_id，同步删除云端文件
    if (video.public_id) {
      try {
        await cloudinary.uploader.destroy(video.public_id, {
          resource_type: 'video',
          api_key: CLOUDINARY_API_KEY,
          api_secret: CLOUDINARY_API_SECRET,
          cloud_name: CLOUDINARY_CLOUD_NAME,
        });
        console.log('Cloudinary 删除成功:', video.public_id);
      } catch (cloudErr) {
        console.error('Cloudinary 删除失败:', cloudErr);
      }
    } else {
      console.warn('视频缺少 public_id，跳过 Cloudinary 删除:', id);
    }

    await pool.query('DELETE FROM videos WHERE id = $1', [id]);
    res.send('删除成功');
  } catch (err) {
    console.error('删除失败 - 完整错误:', err);
    res.status(500).send('删除失败');
  }
});

// --- 上传视频 ---
app.post('/api/upload', upload.single('video'), async (req, res) => {
  // 手动验证 CSRF（因为 multer 解析问题，不能直接在路由上使用中间件）
  const cookieToken = req.cookies.csrf_token;
  const bodyToken = req.body._csrf;
  if (!cookieToken || !bodyToken || cookieToken !== bodyToken) {
    return res.status(403).send('CSRF 令牌无效');
  }
  if (!req.cookies.user) return res.status(401).send('请先登录');
  if (!req.file) return res.status(400).send('未接收到视频文件');

  const { title, category } = req.body;
  const safeCategory = category || '其他';

  try {
    const base64Video = req.file.buffer.toString('base64');
    const dataUri = `data:${req.file.mimetype};base64,${base64Video}`;

    // 上传至 Cloudinary，并启用自动优化和分块
    const uploaded = await cloudinary.uploader.upload(dataUri, {
      resource_type: 'video',
      folder: 'loks-videos',
      transformation: [{ quality: 'auto' }],
      public_id: uuidv4(),
      api_key: CLOUDINARY_API_KEY,
      api_secret: CLOUDINARY_API_SECRET,
      cloud_name: CLOUDINARY_CLOUD_NAME,
      chunk_size: 6000000,  // 6MB 一个分块，适合大文件
      eager: [{ format: 'jpg', width: 320, height: 180, crop: 'fill' }],
      eager_async: false,
    });

    const videoUrl = uploaded.secure_url;
    const thumbnailUrl = uploaded.eager[0].secure_url;

    await pool.query(
      'INSERT INTO videos (title, filename, thumbnail, public_id, category, uploaded_by) VALUES ($1, $2, $3, $4, $5, $6)',
      [title, videoUrl, thumbnailUrl, uploaded.public_id, safeCategory, req.cookies.user]
    );

    res.redirect('/L0Ks.html');
  } catch (err) {
    console.error('上传失败 - 完整错误:', JSON.stringify(err, Object.getOwnPropertyNames(err), 2));
    res.send('上传失败，请稍后重试');
  }
});

// ==================== 全局错误捕获 ====================
process.on('uncaughtException', (err) => {
  console.error('未捕获的异常:', err.message, err.stack);
});
process.on('unhandledRejection', (reason) => {
  console.error('未处理的 Promise 拒绝:', reason);
});

// ==================== 启动服务器 ====================
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log('私人番剧站已启动 → 端口 ' + port);
});