const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const { marked } = require('marked');
const { JSDOM } = require('jsdom');
const createDOMPurify = require('dompurify');
const SQLiteStore = require('connect-sqlite3')(session);

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Setup directories ────────────────────────────────────────────────────────
const DATA_DIR = path.join(__dirname, '..', 'data');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
[DATA_DIR, UPLOADS_DIR].forEach(d => fs.mkdirSync(d, { recursive: true }));

// ─── Database ─────────────────────────────────────────────────────────────────
const db = new Database(path.join(DATA_DIR, 'blog.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER,
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
  );
`);

// ─── Seed default admin if not exists ────────────────────────────────────────
// Default: admin / changeme123  — change via ADMIN_USER and ADMIN_PASS env vars
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'changeme123';
const existing = db.prepare('SELECT id FROM admin LIMIT 1').get();
if (!existing) {
  const hash = bcrypt.hashSync(ADMIN_PASS, 12);
  db.prepare('INSERT INTO admin (username, password_hash) VALUES (?, ?)').run(ADMIN_USER, hash);
  console.log(`[init] Admin created: ${ADMIN_USER} / ${ADMIN_PASS}`);
  console.log('[init] ⚠️  Change ADMIN_PASS env var before production!');
}

// ─── DOMPurify (server-side) ──────────────────────────────────────────────────
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// ─── Security Middleware ──────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  referrerPolicy: { policy: 'no-referrer' },
}));

// Rate limiter — all routes
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false }));

// Strict rate limiter for login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts. Try again in 15 minutes.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));

// ─── Session ──────────────────────────────────────────────────────────────────
const SESSION_SECRET = process.env.SESSION_SECRET || require('crypto').randomBytes(64).toString('hex');
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: DATA_DIR }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'sid',
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 2 * 60 * 60 * 1000, // 2 hours
  },
}));

// ─── File Upload ──────────────────────────────────────────────────────────────
const ALLOWED_TYPES = ['image/jpeg','image/png','image/gif','image/webp','application/pdf','text/plain'];
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

const storage = multer.diskStorage({
  destination: UPLOADS_DIR,
  filename: (req, file, cb) => {
    const safe = Date.now() + '-' + Math.random().toString(36).slice(2);
    const ext = path.extname(file.originalname).toLowerCase().replace(/[^a-z0-9.]/g, '');
    cb(null, safe + ext);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE, files: 5 },
  fileFilter: (req, file, cb) => {
    if (ALLOWED_TYPES.includes(file.mimetype)) cb(null, true);
    else cb(new Error('File type not allowed'));
  },
});

// ─── Static files ─────────────────────────────────────────────────────────────
app.use('/public', express.static(path.join(__dirname, '..', 'public'), { index: false }));
app.use('/uploads', express.static(UPLOADS_DIR, { index: false }));

// ─── Auth helpers ─────────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  res.redirect('/login');
}

// ─── HTML helpers ─────────────────────────────────────────────────────────────
function layout(title, body, isAdmin = false) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} — My Blog</title>
<link rel="stylesheet" href="/public/style.css">
</head>
<body>
<header>
  <a href="/" class="site-title">My Blog</a>
  <nav>
    ${isAdmin ? '<a href="/admin">Dashboard</a> <a href="/logout">Logout</a>' : '<a href="/login">Admin</a>'}
  </nav>
</header>
<main>${body}</main>
<footer><p>A simple blog.</p></footer>
</body>
</html>`;
}

function esc(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// Home — list posts
app.get('/', (req, res) => {
  const posts = db.prepare('SELECT id, title, created_at FROM posts ORDER BY created_at DESC').all();
  const listItems = posts.length
    ? posts.map(p => `
        <article class="post-preview">
          <h2><a href="/post/${p.id}">${esc(p.title)}</a></h2>
          <time>${new Date(p.created_at).toLocaleDateString('en-GB', {year:'numeric',month:'long',day:'numeric'})}</time>
        </article>`).join('')
    : '<p class="empty">No posts yet.</p>';
  res.send(layout('Home', `<section class="post-list">${listItems}</section>`, req.session.isAdmin));
});

// Single post
app.get('/post/:id', (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).send(layout('Not Found', '<p>Post not found.</p>'));
  const attachments = db.prepare('SELECT * FROM attachments WHERE post_id = ?').all(post.id);
  const safeHtml = DOMPurify.sanitize(marked.parse(post.content));
  const files = attachments.length
    ? `<div class="attachments"><h3>Attachments</h3><ul>${attachments.map(a =>
        `<li><a href="/uploads/${esc(a.filename)}" target="_blank" rel="noopener noreferrer">${esc(a.original_name)}</a></li>`
      ).join('')}</ul></div>` : '';
  const editBtn = req.session.isAdmin
    ? `<div class="admin-bar"><a href="/admin/edit/${post.id}">Edit</a>
       <form method="POST" action="/admin/delete/${post.id}" style="display:inline" onsubmit="return confirm('Delete this post?')">
         <button type="submit" class="btn-danger">Delete</button>
       </form></div>` : '';
  res.send(layout(post.title, `
    <article class="post-full">
      ${editBtn}
      <h1>${esc(post.title)}</h1>
      <time>${new Date(post.created_at).toLocaleDateString('en-GB',{year:'numeric',month:'long',day:'numeric'})}</time>
      <div class="post-body">${safeHtml}</div>
      ${files}
    </article>
  `, req.session.isAdmin));
});

// Login page
app.get('/login', (req, res) => {
  if (req.session.isAdmin) return res.redirect('/admin');
  const err = req.session.loginError || '';
  delete req.session.loginError;
  res.send(layout('Login', `
    <div class="form-box">
      <h1>Admin Login</h1>
      ${err ? `<p class="error">${esc(err)}</p>` : ''}
      <form method="POST" action="/login">
        <label>Username<input type="text" name="username" autocomplete="username" required></label>
        <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
        <button type="submit">Login</button>
      </form>
    </div>
  `));
});

// Login POST
app.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    req.session.loginError = 'Invalid input.';
    return res.redirect('/login');
  }
  const admin = db.prepare('SELECT * FROM admin WHERE username = ?').get(username.trim());
  // Always run bcrypt to prevent timing attacks
  const hash = admin ? admin.password_hash : '$2a$12$invalidhashpadding000000000000000000000000000000000000';
  const valid = bcrypt.compareSync(password, hash);
  if (!admin || !valid) {
    req.session.loginError = 'Invalid credentials.';
    return res.redirect('/login');
  }
  req.session.regenerate(err => {
    if (err) return res.redirect('/login');
    req.session.isAdmin = true;
    req.session.username = admin.username;
    res.redirect('/admin');
  });
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// Admin dashboard
app.get('/admin', requireAdmin, (req, res) => {
  const posts = db.prepare('SELECT id, title, created_at FROM posts ORDER BY created_at DESC').all();
  const rows = posts.length
    ? posts.map(p => `
        <tr>
          <td><a href="/post/${p.id}">${esc(p.title)}</a></td>
          <td>${new Date(p.created_at).toLocaleDateString()}</td>
          <td>
            <a href="/admin/edit/${p.id}">Edit</a>
            <form method="POST" action="/admin/delete/${p.id}" style="display:inline" onsubmit="return confirm('Delete?')">
              <button type="submit" class="btn-danger btn-sm">Del</button>
            </form>
          </td>
        </tr>`).join('') : '<tr><td colspan="3">No posts yet.</td></tr>';
  res.send(layout('Dashboard', `
    <div class="dashboard">
      <div class="dash-header">
        <h1>Dashboard</h1>
        <a href="/admin/new" class="btn">New Post</a>
      </div>
      <table>
        <thead><tr><th>Title</th><th>Date</th><th>Actions</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `, true));
});

// New post form
app.get('/admin/new', requireAdmin, (req, res) => {
  res.send(layout('New Post', postForm('New Post', {title:'',content:''}), true));
});

// New post POST
app.post('/admin/new', requireAdmin, upload.array('files', 5), (req, res) => {
  const { title, content } = req.body;
  if (!title || !content || title.trim().length < 1 || content.trim().length < 1) {
    return res.status(400).send(layout('Error', '<p>Title and content required.</p>', true));
  }
  const result = db.prepare('INSERT INTO posts (title, content) VALUES (?, ?)').run(title.trim().slice(0,300), content.trim().slice(0,100000));
  const postId = result.lastInsertRowid;
  if (req.files && req.files.length) {
    const stmt = db.prepare('INSERT INTO attachments (post_id, filename, original_name) VALUES (?, ?, ?)');
    req.files.forEach(f => stmt.run(postId, f.filename, f.originalname.slice(0,255)));
  }
  res.redirect(`/post/${postId}`);
});

// Edit form
app.get('/admin/edit/:id', requireAdmin, (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).send(layout('Not Found', '<p>Post not found.</p>', true));
  const attachments = db.prepare('SELECT * FROM attachments WHERE post_id = ?').all(post.id);
  const fileList = attachments.length
    ? `<div class="existing-files"><h3>Existing files</h3><ul>${attachments.map(a =>
        `<li>${esc(a.original_name)}
          <form method="POST" action="/admin/delete-file/${a.id}" style="display:inline">
            <button type="submit" class="btn-danger btn-sm">Remove</button>
          </form>
        </li>`).join('')}</ul></div>` : '';
  res.send(layout('Edit Post', postForm('Edit Post', post, post.id) + fileList, true));
});

// Edit POST
app.post('/admin/edit/:id', requireAdmin, upload.array('files', 5), (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) return res.status(400).send(layout('Error','<p>Title and content required.</p>',true));
  db.prepare('UPDATE posts SET title=?, content=?, updated_at=CURRENT_TIMESTAMP WHERE id=?')
    .run(title.trim().slice(0,300), content.trim().slice(0,100000), req.params.id);
  if (req.files && req.files.length) {
    const stmt = db.prepare('INSERT INTO attachments (post_id, filename, original_name) VALUES (?, ?, ?)');
    req.files.forEach(f => stmt.run(req.params.id, f.filename, f.originalname.slice(0,255)));
  }
  res.redirect(`/post/${req.params.id}`);
});

// Delete post
app.post('/admin/delete/:id', requireAdmin, (req, res) => {
  const atts = db.prepare('SELECT filename FROM attachments WHERE post_id = ?').all(req.params.id);
  atts.forEach(a => {
    const fp = path.join(UPLOADS_DIR, a.filename);
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
  });
  db.prepare('DELETE FROM posts WHERE id = ?').run(req.params.id);
  res.redirect('/admin');
});

// Delete file
app.post('/admin/delete-file/:id', requireAdmin, (req, res) => {
  const att = db.prepare('SELECT * FROM attachments WHERE id = ?').get(req.params.id);
  if (att) {
    const fp = path.join(UPLOADS_DIR, att.filename);
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
    db.prepare('DELETE FROM attachments WHERE id = ?').run(att.id);
    return res.redirect(`/admin/edit/${att.post_id}`);
  }
  res.redirect('/admin');
});

// ─── Post form helper ─────────────────────────────────────────────────────────
function postForm(heading, post, editId = null) {
  const action = editId ? `/admin/edit/${editId}` : '/admin/new';
  return `
    <div class="form-box wide">
      <h1>${heading}</h1>
      <form method="POST" action="${action}" enctype="multipart/form-data">
        <label>Title<input type="text" name="title" value="${esc(post.title)}" required maxlength="300"></label>
        <label>Content (Markdown supported)
          <textarea name="content" rows="16" required maxlength="100000">${esc(post.content)}</textarea>
        </label>
        <label>Attach files (images, PDF, txt — max 10MB each, up to 5)
          <input type="file" name="files" multiple accept=".jpg,.jpeg,.png,.gif,.webp,.pdf,.txt">
        </label>
        <button type="submit">Save</button>
        <a href="/admin" class="btn-secondary">Cancel</a>
      </form>
    </div>`;
}

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).send(layout('Not Found', '<p>Page not found.</p>')));

// ─── Error handler ────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error(err);
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).send(layout('Error','<p>File too large (max 10MB).</p>'));
  res.status(500).send(layout('Error', '<p>Something went wrong.</p>'));
});

app.listen(PORT, () => console.log(`Blog running on http://localhost:${PORT}`));
