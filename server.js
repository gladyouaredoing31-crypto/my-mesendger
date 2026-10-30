const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'chat.json');

// ---------- Простая JSON-база ----------
let db = { users: [], messages: [], nextUserId: 1, nextMsgId: 1 };
if (fs.existsSync(DB_FILE)) {
  try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch {}
}
const saveDB = () => fs.writeFileSync(DB_FILE, JSON.stringify(db));
const saveDBSoon = (() => {
  let t;
  return () => { clearTimeout(t); t = setTimeout(saveDB, 300); };
})();

// ---------- Middleware ----------
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- REST API ----------
app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Заполни ник и пароль' });
  if (username.length < 2 || username.length > 20) return res.status(400).json({ error: 'Ник 2–20 символов' });
  if (password.length < 4) return res.status(400).json({ error: 'Пароль минимум 4 символа' });
  if (db.users.find(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.status(400).json({ error: 'Этот ник уже занят' });

  const user = {
    id: db.nextUserId++,
    username,
    password: bcrypt.hashSync(password, 10),
    createdAt: Date.now()
  };
  db.users.push(user);
  saveDBSoon();

  const token = jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: '30d' });
  res.json({ token, username: user.username });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = db.users.find(u => u.username.toLowerCase() === (username || '').toLowerCase());
  if (!user || !bcrypt.compareSync(password || '', user.password))
    return res.status(401).json({ error: 'Неверный ник или пароль' });

  const token = jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: '30d' });
  res.json({ token, username: user.username });
});

app.get('/api/messages', (req, res) => {
  const limit = Math.min(+req.query.limit || 200, 500);
  res.json(db.messages.slice(-limit));
});

app.get('/api/online', (req, res) => {
  res.json({ count: io.engine.clientsCount });
});

app.get('/api/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

// ---------- WebSocket ----------
io.use((socket, next) => {
  try {
    const token = socket.handshake.auth && socket.handshake.auth.token;
    const data = jwt.verify(token, SECRET);
    socket.user = data;
    next();
  } catch {
    next(new Error('auth'));
  }
});

io.on('connection', socket => {
  // отправим историю только что подключившемуся
  socket.emit('history', db.messages.slice(-100));
  io.emit('online', io.engine.clientsCount);

  socket.on('message', text => {
    if (typeof text !== 'string') return;
    const t = text.trim();
    if (!t || t.length > 2000) return;
    const msg = {
      id: db.nextMsgId++,
      username: socket.user.username,
      userId: socket.user.id,
      text: t,
      ts: Date.now()
    };
    db.messages.push(msg);
    if (db.messages.length > 5000) db.messages = db.messages.slice(-5000);
    saveDBSoon();
    io.emit('message', msg);
  });

  socket.on('typing', () => {
    socket.broadcast.emit('typing', { username: socket.user.username });
  });

  socket.on('disconnect', () => {
    io.emit('online', io.engine.clientsCount);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('✅ Server running on port ' + PORT);
});
