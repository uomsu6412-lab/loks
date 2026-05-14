// ==================== 1. 引入依赖 ====================
const express = require('express');           // Web 框架
const bcrypt = require('bcrypt');             // 密码加密
const cookieParser = require('cookie-parser'); // 解析 Cookie
const { Pool } = require('pg');              // PostgreSQL 数据库
const multer = require('multer');            // 处理文件上传
const cloudinary = require('cloudinary').v2; // 云存储
const { v4: uuidv4 } = require('uuid');     // 生成唯一ID
const helmet = require('helmet');            // 安全防护

const app = express();

// ==================== 2. 安全防护 ====================
app.use(helmet({
  contentSecurityPolicy: false,      // 我们自定义 CSP
  crossOriginEmbedderPolicy: false,
}));

// ==================== 3. Cloudinary 凭据 ====================
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY;
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET;

// ==================== 4. 数据库连接 ====================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

(async () => {
  try {
    // 创建表
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
    // 动态追加列
    await pool.query('ALTER TABLE videos ADD COLUMN IF NOT EXISTS thumbnail TEXT;');
    await pool.query('ALTER TABLE videos ADD COLUMN IF NOT EXISTS public_id TEXT;');
    await pool.query("ALTER TABLE videos ADD COLUMN IF NOT EXISTS category TEXT DEFAULT '其他';");
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS nickname TEXT;');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT;');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT false;');
    console.log('数据库已连接');
  } catch (err) {
    console.error('数据库初始化失败:', err.message);
  }
})();

// ==================== 5. 静态文件托管 ====================
app.use(express.static('public'));

// ==================== 6. CSP 响应头 ====================
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://www.googletagmanager.com; style-src 'self' 'unsafe-inline'; media-src 'self'; img-src 'self' data: https:; connect-src 'self' https://www.google-analytics.com;");
  next();
});

// ==================== 7. multer 配置 ====================
const upload = multer({ storage: multer.memoryStorage() });
const uploadAvatar = multer({ storage: multer.memoryStorage() });

// ==================== 8. 中间件 ====================
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// ==================== 9. CSRF 保护 ====================
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
// ==================== 管理员验证中间件 ====================
async function adminRequired(req, res, next) {
  if (!req.cookies.user) return res.status(401).send('请先登录');
  try {
    const result = await pool.query('SELECT is_admin FROM users WHERE username = $1', [req.cookies.user]);
    if (result.rows.length === 0 || !result.rows[0].is_admin) {
      return res.status(403).send('需要管理员权限');
    }
    next();
  } catch (err) {
    console.error('管理员验证失败:', err.message);
    res.status(500).send('服务器错误');
  }
}

// ==================== 10. 首页重定向 ====================
app.get('/', (req, res) => res.redirect('/L0Ks.html'));

// ==================== 11. 用户系统 ====================
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

// ==================== 12. 用户资料 ====================
app.get('/api/profile', async (req, res) => {
  if (!req.cookies.user) return res.status(401).json({ error: '未登录' });
  try {
    const result = await pool.query('SELECT username, nickname, avatar FROM users WHERE username = $1', [req.cookies.user]);
    if (result.rows.length === 0) return res.status(404).json({ error: '用户不存在' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('获取资料失败:', err.message);
    res.status(500).json({ error: '服务器错误' });
  }
});

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

app.post('/api/profile/avatar', uploadAvatar.single('avatar'), async (req, res) => {
  if (!req.cookies.user) return res.status(401).send('请先登录');
  if (!req.file) return res.status(400).send('未收到图片');
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
    await pool.query('UPDATE users SET avatar = $1 WHERE username = $2', [uploaded.secure_url, req.cookies.user]);
    res.send('头像已更新');
  } catch (err) {
    console.error('头像上传失败:', err.message);
    res.status(500).send('头像上传失败');
  }
});

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

// ==================== 13. 视频管理 ====================
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
    if (video.public_id) {
      try {
        await cloudinary.uploader.destroy(video.public_id, {
          resource_type: 'video',
          api_key: CLOUDINARY_API_KEY,
          api_secret: CLOUDINARY_API_SECRET,
          cloud_name: CLOUDINARY_CLOUD_NAME,
        });
      } catch (cloudErr) {
        console.error('Cloudinary 删除失败:', cloudErr);
      }
    }
    await pool.query('DELETE FROM videos WHERE id = $1', [id]);
    res.send('删除成功');
  } catch (err) {
    console.error('删除失败:', err);
    res.status(500).send('删除失败');
  }
});
// ==================== 临时：将当前登录用户设为管理员 ====================
app.get('/make-me-admin', async (req, res) => {
  if (!req.cookies.user) return res.send('请先登录');
  try {
    await pool.query('UPDATE users SET is_admin = true WHERE username = $1', [req.cookies.user]);
    res.send('管理员权限已开启！你现在可以访问 /admin.html 了。');
  } catch (err) {
    console.error('设置管理员失败:', err.message);
    res.send('设置失败，请重试');
  }
});
// ==================== 管理后台 API ====================

// 获取所有用户（管理员专属）
app.get('/api/admin/users', adminRequired, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, nickname, avatar, is_admin, created_at FROM users ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('获取用户列表失败:', err.message);
    res.status(500).json({ error: '获取用户列表失败' });
  }
});

// 获取所有视频（管理员专属）
app.get('/api/admin/videos', adminRequired, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM videos ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('获取视频列表失败:', err.message);
    res.status(500).json({ error: '获取视频列表失败' });
  }
});

// 强制删除视频（管理员专属）
app.delete('/api/admin/videos/:id', adminRequired, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM videos WHERE id = $1', [id]);
    const video = result.rows[0];
    if (!video) return res.status(404).send('视频不存在');

    if (video.public_id) {
      try {
        await cloudinary.uploader.destroy(video.public_id, {
          resource_type: 'video',
          api_key: CLOUDINARY_API_KEY,
          api_secret: CLOUDINARY_API_SECRET,
          cloud_name: CLOUDINARY_CLOUD_NAME,
        });
        console.log('管理员已删除 Cloudinary 视频:', video.public_id);
      } catch (cloudErr) {
        console.error('Cloudinary 删除失败:', cloudErr);
      }
    }

    await pool.query('DELETE FROM videos WHERE id = $1', [id]);
    res.send('删除成功');
  } catch (err) {
    console.error('管理员删除失败:', err.message);
    res.status(500).send('删除失败');
  }
});
// --- 上传视频 ---
app.post('/api/upload', upload.single('video'), async (req, res) => {
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

    const uploaded = await cloudinary.uploader.upload(dataUri, {
      resource_type: 'video',
      folder: 'loks-videos',
      transformation: [{ quality: 'auto' }],
      public_id: uuidv4(),
      api_key: CLOUDINARY_API_KEY,
      api_secret: CLOUDINARY_API_SECRET,
      cloud_name: CLOUDINARY_CLOUD_NAME,
      chunk_size: 6000000,
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
    console.error('上传失败:', JSON.stringify(err, Object.getOwnPropertyNames(err), 2));
    res.send('上传失败，请稍后重试');
  }
});

    const videoUrl = uploaded.secure_url;
    const thumbnailUrl = uploaded.eager[0].secure_url;

    await pool.query(
      'INSERT INTO videos (title, filename, thumbnail, public_id, category, uploaded_by) VALUES ($1, $2, $3, $4, $5, $6)',
      [title, videoUrl, thumbnailUrl, uploaded.public_id, safeCategory, req.cookies.user]
    );

    res.redirect('/L0Ks.html');
  } catch (err) {
    console.error('上传失败:', JSON.stringify(err, Object.getOwnPropertyNames(err), 2));
    res.send('上传失败，请稍后重试');
  }
});

    const videoUrl = uploaded.secure_url;
    const thumbnailUrl = uploaded.eager[0].secure_url;

    await pool.query(
      'INSERT INTO videos (title, filename, thumbnail, public_id, category, uploaded_by) VALUES ($1, $2, $3, $4, $5, $6)',
      [title, videoUrl, thumbnailUrl, uploaded.public_id, safeCategory, req.cookies.user]
    );

    res.redirect('/L0Ks.html');
  } catch (err) {
    console.error('上传失败:', JSON.stringify(err, Object.getOwnPropertyNames(err), 2));
    res.send('上传失败，请稍后重试');
  }
});

// ==================== 14. 全局错误捕获 ====================
process.on('uncaughtException', (err) => {
  console.error('未捕获的异常:', err.message, err.stack);
});
process.on('unhandledRejection', (reason) => {
  console.error('未处理的 Promise 拒绝:', reason);
});

// ==================== 15. 启动服务器 ====================
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log('私人番剧站已启动 → 端口 ' + port);
});