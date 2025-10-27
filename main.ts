// Configuration
const API_KEYS = Deno.env.toObject().GEMINI_API_KEYS?.split(',')?.map(key => key.trim()) || [];
const DEFAULT_BASE = 'https://generativelanguage.googleapis.com/v1beta';
const ACCESS_TOKEN = Deno.env.get('ACCESS_TOKEN');

// Initialize Deno KV
const kv = await Deno.openKv();

// Constants for rate limiting and backoff
// Gemini 2.5 Pro Free Tier Limits:
// RPM: 5 (Request Per Minute)
// TPM: 125k (Token Per Minute)
// RPD: 100 (Request Per Day)
// Note: Requests per day (RPD) quotas reset at midnight Pacific time.
const RPM_LIMIT = 5; // Requests per minute
const RPD_LIMIT = 100; // Requests per day (resets at midnight Pacific)
const TPM_LIMIT = 125000; // Tokens per minute
const MINUTE_MS = 60 * 1000;
const MAX_CONCURRENT_PER_KEY = 2; // Conservative limit to avoid bursting
const BACKOFF_LEVELS = [60 * 1000, 5 * 60 * 1000, 15 * 60 * 1000, 60 * 60 * 1000, 24 * 60 * 60 * 1000]; // 1min, 5min, 15min, 1hr, 24hr
const MAX_AUTH_ATTEMPTS = 10;
const AUTH_WINDOW_MS = 60 * 1000; // 1 minute

// Enhanced state tracking
interface KeyState {
  requestTimestampsMinute: number[];  // Sliding window for RPM (last minute)
  requestCountDay: number;            // Count of requests since last midnight Pacific
  lastDailyReset: number;             // Timestamp of last daily reset (midnight Pacific)
  activeRequests: number;             // Current concurrent requests
  blocked: boolean;
  blockUntil: number;
  failureCount: number;               // Consecutive failures for exponential backoff
}

// KV helper functions
async function getKeyState(key: string): Promise<KeyState> {
  const result = await kv.get<KeyState>(["keyState", key]);
  if (result.value) {
    return result.value;
  }
  // Return default state if not found
  return {
    requestTimestampsMinute: [],
    requestCountDay: 0,
    lastDailyReset: Date.now(),
    activeRequests: 0,
    blocked: false,
    blockUntil: 0,
    failureCount: 0,
  };
}

async function setKeyState(key: string, state: KeyState): Promise<void> {
  await kv.set(["keyState", key], state);
}

async function getAuthAttempts(ip: string): Promise<number[]> {
  const result = await kv.get<number[]>(["authAttempts", ip]);
  return result.value || [];
}

async function setAuthAttempts(ip: string, attempts: number[]): Promise<void> {
  // Set with expiration of 2 minutes
  await kv.set(["authAttempts", ip], attempts, { expireIn: 2 * 60 * 1000 });
}

// Check if daily reset should occur (midnight Pacific has passed)
function shouldResetDaily(lastReset: number): boolean {
  const now = new Date();
  const pacificNow = new Date(now.toLocaleString('en-US', { timeZone: 'America/Los_Angeles' }));
  const lastResetPacific = new Date(new Date(lastReset).toLocaleString('en-US', { timeZone: 'America/Los_Angeles' }));
  
  // Check if we've crossed midnight Pacific
  return pacificNow.getDate() !== lastResetPacific.getDate() || 
         pacificNow.getMonth() !== lastResetPacific.getMonth() ||
         pacificNow.getFullYear() !== lastResetPacific.getFullYear();
}

// Logging helper
function log(level: 'info' | 'warn' | 'error', message: string, meta?: Record<string, unknown>) {
  const timestamp = new Date().toISOString();
  const logEntry = { timestamp, level, message, ...meta };
  console.log(JSON.stringify(logEntry));
}

// Clean up old timestamps from sliding window
function cleanSlidingWindow(timestamps: number[], windowMs: number): number[] {
  const now = Date.now();
  return timestamps.filter(t => now - t < windowMs);
}

// Weighted round-robin with sliding window and concurrency limits
async function getKey(): Promise<string | null> {
  const now = Date.now();
  
  // First pass: unblock keys if their block period has expired
  for (const key of API_KEYS) {
    const state = await getKeyState(key);
    
    if (state.blocked && now >= state.blockUntil) {
      state.blocked = false;
      state.failureCount = 0;
      await setKeyState(key, state);
      log('info', `Key unblocked after backoff period`, { key: key.slice(0, 5) });
    }
    // Clean old timestamps for minute window
    state.requestTimestampsMinute = cleanSlidingWindow(state.requestTimestampsMinute, MINUTE_MS);
    
    // Reset daily counter if midnight Pacific has passed
    if (shouldResetDaily(state.lastDailyReset)) {
      state.requestCountDay = 0;
      state.lastDailyReset = now;
      log('info', `Daily quota reset at midnight Pacific`, { key: key.slice(0, 5) });
    }
    
    await setKeyState(key, state);
  }

  // Find available keys (not blocked, under all limits)
  const availableKeys: string[] = [];
  for (const key of API_KEYS) {
    const state = await getKeyState(key);
    if (!state.blocked && 
        state.activeRequests < MAX_CONCURRENT_PER_KEY &&
        state.requestTimestampsMinute.length < RPM_LIMIT &&
        state.requestCountDay < RPD_LIMIT) {
      availableKeys.push(key);
    }
  }

  if (availableKeys.length === 0) {
    return null;
  }

  // Weighted selection: prefer keys with fewer requests in the day
  const keyStates = await Promise.all(
    availableKeys.map(async (key) => ({ key, state: await getKeyState(key) }))
  );
  
  keyStates.sort((a, b) => {
    // Primary: fewer requests in day
    if (a.state.requestCountDay !== b.state.requestCountDay) {
      return a.state.requestCountDay - b.state.requestCountDay;
    }
    // Secondary: fewer requests in minute window
    if (a.state.requestTimestampsMinute.length !== b.state.requestTimestampsMinute.length) {
      return a.state.requestTimestampsMinute.length - b.state.requestTimestampsMinute.length;
    }
    // Tertiary: fewer active concurrent requests
    return a.state.activeRequests - b.state.activeRequests;
  });

  return keyStates[0].key;
}

// Validate access token with rate limiting
async function validateAccessToken(provided: string | null, clientIp: string): Promise<{ valid: boolean; rateLimited: boolean }> {
  // If no ACCESS_TOKEN is set, allow all
  if (!ACCESS_TOKEN) {
    return { valid: true, rateLimited: false };
  }

  // Check if valid
  if (provided === ACCESS_TOKEN) {
    return { valid: true, rateLimited: false };
  }

  // Failed attempt - track for rate limiting
  const now = Date.now();
  const attempts = await getAuthAttempts(clientIp);
  const recentAttempts = cleanSlidingWindow(attempts, AUTH_WINDOW_MS);
  recentAttempts.push(now);
  await setAuthAttempts(clientIp, recentAttempts);

  // Check if rate limited
  if (recentAttempts.length > MAX_AUTH_ATTEMPTS) {
    log('warn', 'Auth rate limit exceeded', { ip: clientIp, attempts: recentAttempts.length });
    return { valid: false, rateLimited: true };
  }

  return { valid: false, rateLimited: false };
}

// Display key states with sliding window counts
async function printKeyStates(): Promise<string> {
  if (API_KEYS.length === 0) {
    return '⚠️ NO API KEYS CONFIGURED - Please set API_KEYS environment variable';
  }
  
  const states = await Promise.all(
    API_KEYS.map(async (key) => {
      const state = await getKeyState(key);
      const requestsPerMinute = state.requestTimestampsMinute.length;
      const requestsPerDay = state.requestCountDay;
      const blockStatus = state.blocked ? `BLOCKED until ${new Date(state.blockUntil).toLocaleTimeString()}` : 'ACTIVE';
      return `${key.slice(0, 7)}... -> [RPM: ${requestsPerMinute}/${RPM_LIMIT}, RPD: ${requestsPerDay}/${RPD_LIMIT}, active: ${state.activeRequests}/${MAX_CONCURRENT_PER_KEY}, status: ${blockStatus}]`;
    })
  );
  
  return states.join('\n');
}

// HTML response with optional error message
async function printHomeHtml(message?: string): Promise<string> {
  const hasKeys = API_KEYS.length > 0;
  const keyStates = await printKeyStates();
  return `
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🌸 Hakurei Shrine API Gateway 🌸</title>
    <style>
      @import url('https://fonts.googleapis.com/css2?family=Noto+Serif+JP:wght@400;600&display=swap');
      
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }
      
      body {
        font-family: 'Noto Serif JP', serif;
        background: linear-gradient(135deg, #f5e6d3 0%, #e8d5c4 50%, #d4c4b0 100%);
        color: #3d2817;
        min-height: 100vh;
        padding: 20px;
        position: relative;
        overflow-x: hidden;
      }
      
      body::before {
        content: '';
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: 
          radial-gradient(circle at 20% 30%, rgba(255, 182, 193, 0.1) 0%, transparent 50%),
          radial-gradient(circle at 80% 70%, rgba(255, 218, 185, 0.1) 0%, transparent 50%);
        pointer-events: none;
        z-index: 0;
      }
      
      .container {
        max-width: 900px;
        margin: 0 auto;
        position: relative;
        z-index: 1;
      }
      
      .shrine-header {
        text-align: center;
        padding: 30px 20px;
        background: linear-gradient(to bottom, rgba(139, 0, 0, 0.15), transparent);
        border-radius: 15px 15px 0 0;
        border: 3px solid #8b0000;
        border-bottom: none;
        box-shadow: 0 -5px 15px rgba(139, 0, 0, 0.1);
      }
      
      h1 {
        font-size: 2.5em;
        color: #8b0000;
        text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.1);
        margin-bottom: 10px;
        font-weight: 600;
      }
      
      .subtitle {
        color: #654321;
        font-size: 1.1em;
        font-style: italic;
        opacity: 0.9;
      }
      
      .main-content {
        background: rgba(255, 248, 240, 0.95);
        border: 3px solid #8b0000;
        border-radius: 0 0 15px 15px;
        padding: 30px;
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
        backdrop-filter: blur(10px);
      }
      
      .shrine-torii {
        text-align: center;
        font-size: 3em;
        margin: 20px 0;
        color: #8b0000;
        text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.2);
      }
      
      .warning-box, .error-box {
        padding: 15px 20px;
        margin: 20px 0;
        border-radius: 8px;
        border-left: 5px solid;
        background: rgba(255, 255, 255, 0.6);
      }
      
      .warning-box {
        border-left-color: #ff8c00;
        color: #cc6600;
        background: rgba(255, 245, 230, 0.9);
      }
      
      .error-box {
        border-left-color: #dc143c;
        color: #8b0000;
        background: rgba(255, 240, 240, 0.9);
        font-weight: 600;
      }
      
      .status-section {
        margin: 25px 0;
      }
      
      h2, h3 {
        color: #8b0000;
        margin: 20px 0 15px 0;
        padding-bottom: 10px;
        border-bottom: 2px solid rgba(139, 0, 0, 0.2);
        font-weight: 600;
      }
      
      pre {
        background: linear-gradient(135deg, #2d1810 0%, #1a0f0a 100%);
        color: #ffcc99;
        padding: 20px;
        border-radius: 8px;
        overflow-x: auto;
        border: 2px solid #8b4513;
        box-shadow: inset 0 2px 8px rgba(0, 0, 0, 0.3);
        font-family: 'Courier New', monospace;
        line-height: 1.6;
      }
      
      .stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 15px;
        margin: 20px 0;
      }
      
      .stat-card {
        background: linear-gradient(135deg, rgba(255, 255, 255, 0.8), rgba(255, 248, 240, 0.8));
        padding: 20px;
        border-radius: 10px;
        border: 2px solid rgba(139, 0, 0, 0.3);
        box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
        transition: transform 0.2s ease;
      }
      
      .stat-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 6px 15px rgba(0, 0, 0, 0.15);
      }
      
      .stat-label {
        color: #654321;
        font-size: 0.9em;
        margin-bottom: 8px;
        text-transform: uppercase;
        letter-spacing: 1px;
      }
      
      .stat-value {
        color: #8b0000;
        font-size: 2em;
        font-weight: 600;
      }
      
      .cherry-blossoms {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        pointer-events: none;
        z-index: 999;
        overflow: hidden;
      }
      
      .petal {
        position: absolute;
        width: 10px;
        height: 10px;
        background: radial-gradient(circle, #ffb7c5 0%, #ffc0cb 50%, transparent 100%);
        border-radius: 50% 0 50% 0;
        opacity: 0.7;
        animation: fall linear infinite;
      }
      
      @keyframes fall {
        0% {
          transform: translateY(-10vh) rotate(0deg);
          opacity: 0.7;
        }
        100% {
          transform: translateY(110vh) rotate(360deg);
          opacity: 0;
        }
      }
      
      .footer {
        text-align: center;
        margin-top: 30px;
        padding: 20px;
        color: #654321;
        font-style: italic;
        opacity: 0.8;
      }
    </style>
  </head>
  <body>
    <div class="cherry-blossoms">
      <div class="petal" style="left: 10%; animation-duration: 12s; animation-delay: 0s;"></div>
      <div class="petal" style="left: 25%; animation-duration: 15s; animation-delay: 2s;"></div>
      <div class="petal" style="left: 40%; animation-duration: 13s; animation-delay: 4s;"></div>
      <div class="petal" style="left: 55%; animation-duration: 14s; animation-delay: 1s;"></div>
      <div class="petal" style="left: 70%; animation-duration: 16s; animation-delay: 3s;"></div>
      <div class="petal" style="left: 85%; animation-duration: 12s; animation-delay: 5s;"></div>
    </div>
    
    <div class="container">
      <div class="shrine-header">
        <h1>⛩️ 博麗神社 API Gateway ⛩️</h1>
        <div class="subtitle">Hakurei Shrine • Where Boundaries Meet Technology</div>
      </div>
      
      <div class="main-content">
        <div class="shrine-torii">🌸 🏮 🌸</div>
        
        ${!hasKeys ? '<div class="warning-box">⚠️ WARNING: The shrine\'s spiritual barriers are down! No API keys configured. Set API_KEYS environment variable to restore protection.</div>' : ''}
        
        ${message ? `<div class="error-box">⚠️ ${message}</div>` : ''}
        
        <div class="status-section">
          <h2>📜 Spiritual Barrier Status</h2>
          <pre>${keyStates}</pre>
        </div>
        
        <div class="status-section">
          <h3>📊 Shrine Statistics</h3>
          <div class="stats-grid">
            <div class="stat-card">
              <div class="stat-label">🔑 Guardian Keys</div>
              <div class="stat-value">${API_KEYS.length}</div>
            </div>
            <div class="stat-card">
              <div class="stat-label">⚡ Concurrent Requests</div>
              <div class="stat-value">${MAX_CONCURRENT_PER_KEY}</div>
            </div>
            <div class="stat-card">
              <div class="stat-label">🕐 Requests/Minute</div>
              <div class="stat-value">${RPM_LIMIT}</div>
            </div>
            <div class="stat-card">
              <div class="stat-label">📅 Requests/Day</div>
              <div class="stat-value">${RPD_LIMIT}</div>
            </div>
            <div class="stat-card">
              <div class="stat-label">🎴 Tokens/Minute</div>
              <div class="stat-value">${(TPM_LIMIT / 1000).toFixed(0)}k</div>
            </div>
          </div>
        </div>
        
        <div class="footer">
          <p>💫 May your requests find fortune at the shrine 💫</p>
          <p style="font-size: 0.9em; margin-top: 10px;">Maintained by Reimu Hakurei</p>
        </div>
      </div>
    </div>
  </body>
  </html>
  `;
}

// JSON error response
function jsonErrorResponse(message: string, status: number) {
  return new Response(JSON.stringify({
    error: {
      message,
      status,
      timestamp: new Date().toISOString(),
    }
  }), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    }
  });
}

// Send request with specific API key
async function sendRequestWithKey(req: Request, key: string): Promise<Response> {
  const url = new URL(req.url);
  // Remove leading slashes to prevent protocol-relative URL interpretation
  const pathname = url.pathname.replace(/^\/+/, '/');
  const targetUrl = new URL(pathname, DEFAULT_BASE);
  
  // Copy search params from original request, but replace 'key' with our API key
  for (const [k, v] of url.searchParams) {
    if (k !== 'key') {
      targetUrl.searchParams.set(k, v);
    }
  }
  targetUrl.searchParams.set('key', key);

  const fHeaders = new Headers();
  const ignoreHeaders = ['host', 'x-goog-api-key', 'cookie', 'authorization'];
  for (const [k, v] of req.headers) {
    if (!ignoreHeaders.includes(k.toLowerCase())) {
      fHeaders.set(k.toLowerCase(), v);
    }
  }

  if (!fHeaders.has('content-type') && req.headers.has('content-type')) {
    fHeaders.set('content-type', req.headers.get('content-type')!);
  }
  
  const state = await getKeyState(key);
  state.activeRequests++;
  await setKeyState(key, state);
  
  try {
    const response = await fetch(targetUrl.toString(), {
      method: req.method,
      headers: fHeaders,
      body: req.method !== 'GET' && req.method !== 'HEAD' ? req.body : undefined,
    });
    return response;
  } finally {
    const updatedState = await getKeyState(key);
    updatedState.activeRequests--;
    await setKeyState(key, updatedState);
  }
}

// Block a key with exponential backoff
async function blockKey(key: string, errorCode: number): Promise<void> {
  const state = await getKeyState(key);
  state.blocked = true;
  state.failureCount++;
  
  // Cap failure count at backoff levels length
  const backoffIndex = Math.min(state.failureCount - 1, BACKOFF_LEVELS.length - 1);
  const backoffDuration = BACKOFF_LEVELS[backoffIndex];
  state.blockUntil = Date.now() + backoffDuration;
  
  await setKeyState(key, state);
  
  log('warn', `Key blocked with exponential backoff`, {
    key: key.slice(0, 7),
    errorCode,
    failureCount: state.failureCount,
    backoffMinutes: backoffDuration / 60000,
    unblockAt: new Date(state.blockUntil).toISOString(),
  });
}

// Get client IP from request
function getClientIp(req: Request): string {
  return req.headers.get('cf-connecting-ip') || // Cloudflare
         req.headers.get('x-forwarded-for')?.split(',')[0] || // Standard proxy header
         req.headers.get('x-real-ip') || // Nginx
         'unknown';
}

// Check if client wants JSON response
function wantsJson(req: Request): boolean {
  const accept = req.headers.get('accept') || '';
  return accept.includes('application/json') || accept.includes('*/*');
}

// Main request handler
Deno.serve(async (req) => {
  const url = new URL(req.url);
  
  // Homepage - don't send to API
  if (url.pathname === '/' && req.method === 'GET') {
    const html = await printHomeHtml();
    return new Response(html, { 
      status: 200, 
      headers: { 'Content-Type': 'text/html' } 
    });
  }
  
  const clientIp = getClientIp(req);
  const preferJson = wantsJson(req);
  
  // Validate access token with rate limiting
  const accessToken = new URL(req.url).searchParams.get('key');
  const authResult = await validateAccessToken(accessToken, clientIp);
  
  if (authResult.rateLimited) {
    const message = 'Too many failed authentication attempts. Please try again later.';
    log('warn', 'Auth rate limit triggered', { ip: clientIp });
    
    if (preferJson) {
      return jsonErrorResponse(message, 429);
    }
    const html = await printHomeHtml(message);
    return new Response(html, { 
      status: 429, 
      headers: { 'Content-Type': 'text/html' } 
    });
  }
  
  if (!authResult.valid) {
    const message = 'Invalid access token';
    log('warn', 'Invalid auth attempt', { ip: clientIp });
    
    if (preferJson) {
      return jsonErrorResponse(message, 403);
    }
    const html = await printHomeHtml(message);
    return new Response(html, { 
      status: 403, 
      headers: { 'Content-Type': 'text/html' } 
    });
  }

  try {
    const key = await getKey();
    if (!key) {
      const message = 'All API keys are currently blocked due to rate limits. Please try again later.';
      log('error', 'No available keys', { ip: clientIp });
      
      if (preferJson) {
        return jsonErrorResponse(message, 503);
      }
      const html = await printHomeHtml(message);
      return new Response(html, { 
        status: 503, 
        headers: { 'Content-Type': 'text/html' } 
      });
    }

    // Clone request for potential retries
    let currentRequest = req;
    let response = await sendRequestWithKey(currentRequest, key);
    let attempts = 1;
    let currentKey = key;

    const errorCodes = [401, 403, 429];
    while (errorCodes.includes(response.status) && attempts < API_KEYS.length) {
      log('info', 'Retrying with different key', {
        previousKey: currentKey.slice(0, 7),
        errorCode: response.status,
        attempt: attempts,
      });
      
      // Block the failed key with exponential backoff
      await blockKey(currentKey, response.status);
      
      const nextKey = await getKey();
      if (!nextKey) {
        log('warn', 'No more keys available for retry', { attempts });
        break;
      }

      // Clone the original request for retry
      currentRequest = req.clone();
      currentKey = nextKey;
      attempts++;
      response = await sendRequestWithKey(currentRequest, currentKey);
    }

    if (errorCodes.includes(response.status)) {
      const message = 'All API keys are currently blocked. Please try again later.';
      log('error', 'All keys exhausted', { attempts, finalStatus: response.status });
      
      if (preferJson) {
        return jsonErrorResponse(message, 503);
      }
      const html = await printHomeHtml(message);
      return new Response(html, { 
        status: 503, 
        headers: { 'Content-Type': 'text/html' } 
      });
    }

    // Success - track the request in minute window and increment daily counter
    const state = await getKeyState(currentKey);
    const now = Date.now();
    state.requestTimestampsMinute.push(now);
    state.requestCountDay++;
    await setKeyState(currentKey, state);
    
    log('info', 'Request successful', {
      key: currentKey.slice(0, 7),
      attempts,
      status: response.status,
      rpm: state.requestTimestampsMinute.length,
      rpd: state.requestCountDay,
    });

    const resHeaders = new Headers(response.headers);
    resHeaders.set('access-control-allow-origin', '*');

    return new Response(response.body, { status: response.status, headers: resHeaders });
  } catch (err) {
    const message = 'Internal server error occurred.';
    log('error', 'Request processing error', { error: String(err), ip: clientIp });
    
    if (preferJson) {
      return jsonErrorResponse(message, 500);
    }
    const html = await printHomeHtml(message);
    return new Response(html, { 
      status: 500, 
      headers: { 'Content-Type': 'text/html' } 
    });
  }
});

// Startup validation
if (API_KEYS.length === 0) {
  log('warn', 'No API keys configured - service will not function properly', {});
  console.warn('⚠️  WARNING: No API keys found in API_KEYS environment variable');
}

log('info', 'Gemini API Proxy started', {
  totalKeys: API_KEYS.length,
  maxConcurrentPerKey: MAX_CONCURRENT_PER_KEY,
  rpmLimit: RPM_LIMIT,
  rpdLimit: RPD_LIMIT,
  tpmLimit: TPM_LIMIT,
});