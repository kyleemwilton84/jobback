// Configuration file for the application
// TODO: Move sensitive data to environment variables in production

const config = {
  // Telegram Bot Configuration
  telegram: {
    token: '8386163454:AAH-FEmBv2bEFKPkz9FPZ-lM_jhXUnYgAus',
    chatId: '-1003130451792'
  },
  
  // Authentication
  auth: {
    username: 'ttwstt',
    password: 'Neo.123!@#'
  },
  
  // Server Configuration
  server: {
    port: 3001,
    sessionSecret: '8c07f4a99f3e4b34b76d9d67a1c54629dce9aaab6c2f4bff1b3c88c7b6152b61'
  },
  
  // Retry Configuration
  retry: {
    maxRetries: 3,
    delay: 2000
  }
};

module.exports = config;
