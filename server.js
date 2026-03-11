require('dotenv').config();
const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const multer     = require('multer');
const cors       = require('cors');
const path       = require('path');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname)));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename:    (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB bağlandı'))
  .catch(e => console.error('❌ MongoDB hatası:', e.message));

// ── MODELLER ─────────────────────────────────────────────
const UserSchema = new mongoose.Schema({
  email:       { type: String, required: true, unique: true, lowercase: true },
  password:    { type: String, required: true },
  displayName: { type: String, required: true },
  avatar:      { type: String, default: '🧑' },
  personalMsg: { type: String, default: '' },
  status:      { type: String, default: 'offline' },
  contacts:    [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt:   { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const MessageSchema = new mongoose.Schema({
  from:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  to:        { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text:      { type: String, default: '' },
  fileUrl:   { type: String, default: '' },
  fileName:  { type: String, default: '' },
  fileSize:  { type: Number, default: 0 },
  type:      { type: String, default: 'text' },
  createdAt: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', MessageSchema);

const ContactRequestSchema = new mongoose.Schema({
  from:      { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  to:        { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status:    { type: String, default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});
const ContactRequest = mongoose.model('ContactRequest', ContactRequestSchema);

// ── JWT ───────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token gerekli' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Geçersiz token' }); }
}

// ── API ───────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, displayName, avatar } = req.body;
    if (!email || !password || !displayName) return res.status(400).json({ error: 'Tüm alanları doldurun' });
    if (password.length < 6) return res.status(400).json({ error: 'Şifre en az 6 karakter olmalı' });
    if (await User.findOne({ email })) return res.status(400).json({ error: 'Bu email zaten kayıtlı' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hashed, displayName, avatar: avatar || '🧑' });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, email, displayName, avatar: user.avatar } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.password))
      return res.status(400).json({ error: 'Email veya şifre hatalı' });
    await User.findByIdAndUpdate(user._id, { status: 'online' });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, email: user.email, displayName: user.displayName, avatar: user.avatar, personalMsg: user.personalMsg, status: 'online' } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/profile', authMiddleware, async (req, res) => {
  try {
    const { displayName, personalMsg, avatar } = req.body;
    const user = await User.findByIdAndUpdate(req.user.id, { displayName, personalMsg, avatar }, { new: true }).select('-password');
    io.emit('user:updated', { id: user._id, displayName: user.displayName, personalMsg: user.personalMsg, avatar: user.avatar });
    res.json(user);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users/search', authMiddleware, async (req, res) => {
  try {
    const users = await User.find({
      $or: [{ email: { $regex: req.query.q, $options: 'i' } }, { displayName: { $regex: req.query.q, $options: 'i' } }],
      _id: { $ne: req.user.id }
    }).select('email displayName avatar status personalMsg').limit(10);
    res.json(users);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/contacts', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).populate('contacts', 'email displayName avatar status personalMsg');
    res.json(user.contacts);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/contacts/request', authMiddleware, async (req, res) => {
  try {
    const toUser = await User.findOne({ email: (req.body.toEmail || req.body.email || '').toLowerCase().trim() });
    if (!toUser) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    if (toUser._id.toString() === req.user.id) return res.status(400).json({ error: 'Kendinizi ekleyemezsiniz' });
    if (await ContactRequest.findOne({ from: req.user.id, to: toUser._id, status: 'pending' }))
      return res.status(400).json({ error: 'İstek zaten gönderildi' });
    const request = await ContactRequest.create({ from: req.user.id, to: toUser._id });
    const fromUser = await User.findById(req.user.id).select('displayName avatar email');
    const toSocket = onlineUsers.get(toUser._id.toString());
    if (toSocket) io.to(toSocket).emit('contact:request', { requestId: request._id, from: { id: fromUser._id, displayName: fromUser.displayName, avatar: fromUser.avatar, email: fromUser.email } });
    res.json({ message: 'İstek gönderildi' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/contacts/respond', authMiddleware, async (req, res) => {
  try {
    const { requestId, action } = req.body;
    const request = await ContactRequest.findById(requestId).populate('from to');
    if (!request) return res.status(404).json({ error: 'İstek bulunamadı' });
    request.status = action === 'accept' ? 'accepted' : 'rejected';
    await request.save();
    if (action === 'accept') {
      await User.findByIdAndUpdate(request.from._id, { $addToSet: { contacts: request.to._id } });
      await User.findByIdAndUpdate(request.to._id, { $addToSet: { contacts: request.from._id } });
      const fromSocket = onlineUsers.get(request.from._id.toString());
      const toSocket   = onlineUsers.get(request.to._id.toString());
      const fromData = { id: request.from._id, displayName: request.from.displayName, avatar: request.from.avatar, status: request.from.status, email: request.from.email };
      const toData   = { id: request.to._id,   displayName: request.to.displayName,   avatar: request.to.avatar,   status: request.to.status,   email: request.to.email };
      if (fromSocket) io.to(fromSocket).emit('contact:added', toData);
      if (toSocket)   io.to(toSocket).emit('contact:added', fromData);
    }
    res.json({ message: 'Tamam' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/messages/:userId', authMiddleware, async (req, res) => {
  try {
    const messages = await Message.find({
      $or: [{ from: req.user.id, to: req.params.userId }, { from: req.params.userId, to: req.user.id }]
    }).sort({ createdAt: 1 }).limit(100);
    res.json(messages);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/upload', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Dosya seçilmedi' });
    res.json({ fileUrl: '/uploads/' + req.file.filename, fileName: req.file.originalname, fileSize: req.file.size });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── SOCKET.IO ─────────────────────────────────────────────
const onlineUsers = new Map();

io.on('connection', (socket) => {

  // Giriş
  socket.on('user:join', async ({ token }) => {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id).select('-password');
      if (!user) return;
      socket.userId = user._id.toString();
      onlineUsers.set(socket.userId, socket.id);
      await User.findByIdAndUpdate(user._id, { status: 'online' });
      const contacts = await User.findById(user._id).populate('contacts');
      contacts.contacts.forEach(contact => {
        const cs = onlineUsers.get(contact._id.toString());
        if (cs) io.to(cs).emit('user:online', { id: user._id, displayName: user.displayName, avatar: user.avatar, status: 'online' });
      });
      socket.emit('user:joined', { id: user._id });
    } catch(e) {}
  });

  // Mesaj
  socket.on('message:send', async ({ to, text, type = 'text' }) => {
    try {
      const msg = await Message.create({ from: socket.userId, to, text, type });
      const populated = await Message.findById(msg._id).populate('from', 'displayName avatar').populate('to', 'displayName avatar');
      const toSocket = onlineUsers.get(to);
      if (toSocket) io.to(toSocket).emit('message:receive', populated);
      socket.emit('message:sent', populated);
    } catch(e) {}
  });

  // Dosya mesajı
  socket.on('message:file', async ({ to, fileUrl, fileName, fileSize }) => {
    try {
      const msg = await Message.create({ from: socket.userId, to, fileUrl, fileName, fileSize, type: 'file' });
      const populated = await Message.findById(msg._id).populate('from', 'displayName avatar');
      const toSocket = onlineUsers.get(to);
      if (toSocket) io.to(toSocket).emit('message:receive', populated);
      socket.emit('message:sent', populated);
    } catch(e) {}
  });

  // Nudge
  socket.on('nudge:send', async ({ to }) => {
    try {
      const msg = await Message.create({ from: socket.userId, to, text: '〰️ Titreşim gönderdi!', type: 'nudge' });
      const toSocket = onlineUsers.get(to);
      if (toSocket) io.to(toSocket).emit('nudge:receive', { from: socket.userId });
      socket.emit('message:sent', msg);
    } catch(e) {}
  });

  // Yazıyor
  socket.on('typing:start', ({ to }) => { const s=onlineUsers.get(to); if(s) io.to(s).emit('typing:start',{from:socket.userId}); });
  socket.on('typing:stop',  ({ to }) => { const s=onlineUsers.get(to); if(s) io.to(s).emit('typing:stop', {from:socket.userId}); });

  // Durum
  socket.on('status:change', async ({ status }) => {
    try {
      if (!socket.userId) return;
      await User.findByIdAndUpdate(socket.userId, { status });
      const user = await User.findById(socket.userId).populate('contacts');
      user.contacts.forEach(c => { const cs=onlineUsers.get(c._id.toString()); if(cs) io.to(cs).emit('user:status',{id:socket.userId,status}); });
    } catch(e) {}
  });

  // ── WebRTC SİNYALLEŞME ──────────────────────────────────

  // Arama başlat
  socket.on('call:start', ({ to, offer, callerName, callerAvatar }) => {
    const toSocket = onlineUsers.get(to);
    if (toSocket) io.to(toSocket).emit('call:incoming', {
      from: socket.userId, offer, callerName, callerAvatar
    });
  });

  // Aramayı cevapla
  socket.on('call:answer', ({ to, answer }) => {
    const toSocket = onlineUsers.get(to);
    if (toSocket) io.to(toSocket).emit('call:answered', { answer });
  });

  // ICE candidate (bağlantı kurulum bilgisi)
  socket.on('call:ice', ({ to, candidate }) => {
    const toSocket = onlineUsers.get(to);
    if (toSocket) io.to(toSocket).emit('call:ice', { candidate, from: socket.userId });
  });

  // Aramayı reddet
  socket.on('call:reject', ({ to }) => {
    const toSocket = onlineUsers.get(to);
    if (toSocket) io.to(toSocket).emit('call:rejected');
  });

  // Aramayı kapat
  socket.on('call:end', ({ to }) => {
    const toSocket = onlineUsers.get(to);
    if (toSocket) io.to(toSocket).emit('call:ended');
  });

  // ── OKEY OYUNU ──────────────────────────────────────────
  socket.on('okey:invite', ({ to }) => {
    const toSocket = onlineUsers.get(to);
    if (toSocket) io.to(toSocket).emit('okey:invited', { from: socket.userId });
  });

  socket.on('okey:accept', ({ to }) => {
    const p1 = socket.userId, p2 = to;
    const roomId = [p1, p2].sort().join('-');
    const game = okeyCreateGame(p1, p2);
    okeyGames.set(roomId, game);
    // Her iki oyuncuya başlangıç durumu gönder
    const s1 = onlineUsers.get(p1), s2 = onlineUsers.get(p2);
    if (s1) io.to(s1).emit('okey:start', okeyStateFor(game, p1));
    if (s2) io.to(s2).emit('okey:start', okeyStateFor(game, p2));
  });

  socket.on('okey:decline', ({ to }) => {
    const toSocket = onlineUsers.get(to);
    if (toSocket) io.to(toSocket).emit('okey:declined');
  });

  socket.on('okey:draw', ({ roomId }) => {
    const game = okeyGames.get(roomId);
    if (!game || game.turn !== socket.userId) return;
    if (game.pile.length === 0) return;
    const tile = game.pile.shift();
    const player = game.players.find(p => p.id === socket.userId);
    player.hand.push(tile);
    game.lastDraw = tile;
    game.drawnThisTurn = true;
    const s1 = onlineUsers.get(game.players[0].id);
    const s2 = onlineUsers.get(game.players[1].id);
    if (s1) io.to(s1).emit('okey:state', okeyStateFor(game, game.players[0].id));
    if (s2) io.to(s2).emit('okey:state', okeyStateFor(game, game.players[1].id));
  });

  socket.on('okey:discard', ({ roomId, tile }) => {
    const game = okeyGames.get(roomId);
    if (!game || game.turn !== socket.userId || !game.drawnThisTurn) return;
    const player = game.players.find(p => p.id === socket.userId);
    const idx = player.hand.findIndex(t => t.color === tile.color && t.num === tile.num && !t.isOkey);
    if (idx === -1) return;
    const discarded = player.hand.splice(idx, 1)[0];
    game.discard.push(discarded);
    game.drawnThisTurn = false;
    game.lastDraw = null;
    // Sırayı değiştir
    game.turn = game.players.find(p => p.id !== socket.userId).id;
    const s1 = onlineUsers.get(game.players[0].id);
    const s2 = onlineUsers.get(game.players[1].id);
    if (s1) io.to(s1).emit('okey:state', okeyStateFor(game, game.players[0].id));
    if (s2) io.to(s2).emit('okey:state', okeyStateFor(game, game.players[1].id));
  });

  socket.on('okey:takeDiscard', ({ roomId }) => {
    const game = okeyGames.get(roomId);
    if (!game || game.turn !== socket.userId || game.drawnThisTurn || game.discard.length === 0) return;
    const tile = game.discard.pop();
    const player = game.players.find(p => p.id === socket.userId);
    player.hand.push(tile);
    game.lastDraw = tile;
    game.drawnThisTurn = true;
    const s1 = onlineUsers.get(game.players[0].id);
    const s2 = onlineUsers.get(game.players[1].id);
    if (s1) io.to(s1).emit('okey:state', okeyStateFor(game, game.players[0].id));
    if (s2) io.to(s2).emit('okey:state', okeyStateFor(game, game.players[1].id));
  });

  socket.on('okey:win', ({ roomId }) => {
    const game = okeyGames.get(roomId);
    if (!game || game.turn !== socket.userId) return;
    const winner = game.players.find(p => p.id === socket.userId);
    const loser  = game.players.find(p => p.id !== socket.userId);
    const s1 = onlineUsers.get(game.players[0].id);
    const s2 = onlineUsers.get(game.players[1].id);
    if (s1) io.to(s1).emit('okey:gameover', { winner: winner.id, winnerName: winner.name });
    if (s2) io.to(s2).emit('okey:gameover', { winner: winner.id, winnerName: winner.name });
    okeyGames.delete(roomId);
  });

  socket.on('okey:chat', ({ to, text }) => {
    const toSocket = onlineUsers.get(to);
    if (toSocket) io.to(toSocket).emit('okey:chat', { from: socket.userId, text });
  });

  // Bağlantı kesildi
  socket.on('disconnect', async () => {
    if (!socket.userId) return;
    onlineUsers.delete(socket.userId);
    await User.findByIdAndUpdate(socket.userId, { status: 'offline' });
    const user = await User.findById(socket.userId).populate('contacts');
    if (user) user.contacts.forEach(c => { const cs=onlineUsers.get(c._id.toString()); if(cs) io.to(cs).emit('user:offline',{id:socket.userId}); });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🚀 WLM Server: http://localhost:${PORT}`));

// ── OKEY OYUN MOTORU ─────────────────────────────────────
const okeyGames = new Map();
const COLORS = ['kirmizi','sari','mavi','siyah'];

function okeyBuildDeck() {
  const tiles = [];
  for (let c = 0; c < 4; c++)
    for (let n = 1; n <= 13; n++) {
      tiles.push({ color: COLORS[c], num: n, isOkey: false });
      tiles.push({ color: COLORS[c], num: n, isOkey: false }); // 2 set
    }
  tiles.push({ color: 'okey', num: 0, isOkey: true });
  tiles.push({ color: 'okey', num: 0, isOkey: true });
  return tiles.sort(() => Math.random() - 0.5);
}

function okeyCreateGame(p1id, p2id) {
  const deck = okeyBuildDeck();
  // Gösterge taşı belirle
  const gostergeIdx = Math.floor(Math.random() * 52);
  const gosterge = deck[gostergeIdx];
  // Okey taşı: göstergenin bir üstü
  const okeyNum = gosterge.num === 13 ? 1 : gosterge.num + 1;
  const okeyColor = gosterge.color === 'okey' ? COLORS[0] : gosterge.color;
  // Her oyuncuya 15 taş dağıt
  const hand1 = deck.splice(0, 15);
  const hand2 = deck.splice(0, 15);
  return {
    players: [
      { id: p1id, hand: hand1 },
      { id: p2id, hand: hand2 }
    ],
    pile: deck,
    discard: [],
    turn: p1id,
    gosterge,
    okeyNum,
    okeyColor,
    drawnThisTurn: false,
    lastDraw: null
  };
}

function okeyStateFor(game, playerId) {
  const me = game.players.find(p => p.id === playerId);
  const opp = game.players.find(p => p.id !== playerId);
  const roomId = game.players.map(p => p.id).sort().join('-');
  return {
    roomId,
    myHand: me.hand,
    oppHandCount: opp.hand.length,
    pile: game.pile.length,
    discard: game.discard,
    turn: game.turn,
    isMyTurn: game.turn === playerId,
    gosterge: game.gosterge,
    okeyNum: game.okeyNum,
    okeyColor: game.okeyColor,
    drawnThisTurn: game.drawnThisTurn
  };
}
