// Configuration
const API_KEYS = Deno.env.toObject().GEMINI_API_KEYS?.split(',')?.map(key => key.trim()) || [];
const DEFAULT_BASE = 'https://generativelanguage.googleapis.com/v1beta';
const API_BASE_URL = Deno.env.get('API_BASE_URL') || DEFAULT_BASE;
const ACCESS_TOKEN = Deno.env.get('ACCESS_TOKEN');

// Constants for rate limiting and backoff
const SLIDING_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const MAX_CONCURRENT_PER_KEY = 5;
const BACKOFF_LEVELS = [60 * 1000, 5 * 60 * 1000, 15 * 60 * 1000, 60 * 60 * 1000, 24 * 60 * 60 * 1000]; // 1min, 5min, 15min, 1hr, 24hr
const MAX_AUTH_ATTEMPTS = 10;
const AUTH_WINDOW_MS = 60 * 1000; // 1 minute

// Enhanced state tracking
interface KeyState {
  requestTimestamps: number[];  // Sliding window of request times
  activeRequests: number;       // Current concurrent requests
  blocked: boolean;
  blockUntil: number;
  failureCount: number;         // Consecutive failures for exponential backoff
}

const KEYS_STATES = API_KEYS.reduce((acc, key) => {
  acc[key] = {
    requestTimestamps: [],
    activeRequests: 0,
    blocked: false,
    blockUntil: 0,
    failureCount: 0,
  };
  return acc;
}, {} as Record<string, KeyState>);

// Auth rate limiting (IP -> failed attempt timestamps)
const authAttempts = new Map<string, number[]>();

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
function getKey(): string | null {
  const now = Date.now();
  
  // First pass: unblock keys if their block period has expired
  for (const [key, state] of Object.entries(KEYS_STATES)) {
    if (state.blocked && now >= state.blockUntil) {
      state.blocked = false;
      state.failureCount = 0;
      log('info', `Key unblocked after backoff period`, { key: key.slice(0, 5) });
    }
    // Clean old timestamps
    state.requestTimestamps = cleanSlidingWindow(state.requestTimestamps, SLIDING_WINDOW_MS);
  }

  // Find available keys (not blocked, under concurrency limit)
  const availableKeys = API_KEYS.filter(key => {
    const state = KEYS_STATES[key];
    return !state.blocked && state.activeRequests < MAX_CONCURRENT_PER_KEY;
  });

  if (availableKeys.length === 0) {
    return null;
  }

  // Weighted selection: prefer keys with fewer requests in the sliding window
  availableKeys.sort((a, b) => {
    const stateA = KEYS_STATES[a];
    const stateB = KEYS_STATES[b];
    // Primary: fewer requests in window
    if (stateA.requestTimestamps.length !== stateB.requestTimestamps.length) {
      return stateA.requestTimestamps.length - stateB.requestTimestamps.length;
    }
    // Secondary: fewer active concurrent requests
    return stateA.activeRequests - stateB.activeRequests;
  });

  return availableKeys[0];
}

// Validate access token with rate limiting
function validateAccessToken(provided: string | null, clientIp: string): { valid: boolean; rateLimited: boolean } {
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
  const attempts = authAttempts.get(clientIp) || [];
  const recentAttempts = cleanSlidingWindow(attempts, AUTH_WINDOW_MS);
  recentAttempts.push(now);
  authAttempts.set(clientIp, recentAttempts);

  // Check if rate limited
  if (recentAttempts.length > MAX_AUTH_ATTEMPTS) {
    log('warn', 'Auth rate limit exceeded', { ip: clientIp, attempts: recentAttempts.length });
    return { valid: false, rateLimited: true };
  }

  return { valid: false, rateLimited: false };
}

// Display key states with sliding window counts
function printKeyStates() {
  if (API_KEYS.length === 0) {
    return '⚠️ NO API KEYS CONFIGURED - Please set API_KEYS environment variable';
  }
  
  return Object.entries(KEYS_STATES).map(([key, state]) => {
    const requestsInWindow = state.requestTimestamps.length;
    const blockStatus = state.blocked ? `BLOCKED until ${new Date(state.blockUntil).toLocaleTimeString()}` : 'ACTIVE';
    return `${key.slice(0, 7)}... -> [requests/hour: ${requestsInWindow}, active: ${state.activeRequests}/${MAX_CONCURRENT_PER_KEY}, status: ${blockStatus}]`;
  }).join('\n');
}

// HTML response with optional error message
function printHomeHtml(message?: string) {
  const hasKeys = API_KEYS.length > 0;
  return `
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reimu~ API Proxy</title>
    <style>
      body { font-family: monospace; padding: 20px; background: #1a1a1a; color: #00ff00; }
      h1 { color: #00ff00; }
      pre { background: #000; padding: 15px; border-radius: 5px; overflow-x: auto; }
      .error { color: #ff5555; font-weight: bold; }
      .warning { color: #ffaa00; font-weight: bold; }
      .status { margin: 20px 0; }
    </style>
  </head>
  <body>
    <h1>🌸 Reimu~ API Proxy 🌸</h1>
    ${!hasKeys ? '<div class="warning">⚠️ WARNING: No API keys configured! Set API_KEYS environment variable.</div>' : ''}
    <div class="status">
      <h2>Key Status:</h2>
      <pre>${printKeyStates()}</pre>
    </div>
    ${message ? `<p class="error">${message}</p>` : ''}
    <div>
      <h3>Stats:</h3>
      <ul>
        <li>Total Keys: ${API_KEYS.length}</li>
        <li>Max Concurrent/Key: ${MAX_CONCURRENT_PER_KEY}</li>
        <li>Sliding Window: ${SLIDING_WINDOW_MS / 1000 / 60} minutes</li>
      </ul>
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
  const targetUrl = new URL(url.pathname + url.search, API_BASE_URL);

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

  fHeaders.set('x-goog-api-key', key);
  
  const state = KEYS_STATES[key];
  state.activeRequests++;
  
  try {
    const response = await fetch(targetUrl.toString(), {
      method: req.method,
      headers: fHeaders,
      body: req.method !== 'GET' && req.method !== 'HEAD' ? req.body : undefined,
    });
    return response;
  } finally {
    state.activeRequests--;
  }
}

// Block a key with exponential backoff
function blockKey(key: string, errorCode: number) {
  const state = KEYS_STATES[key];
  state.blocked = true;
  state.failureCount++;
  
  // Cap failure count at backoff levels length
  const backoffIndex = Math.min(state.failureCount - 1, BACKOFF_LEVELS.length - 1);
  const backoffDuration = BACKOFF_LEVELS[backoffIndex];
  state.blockUntil = Date.now() + backoffDuration;
  
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
    return new Response(printHomeHtml(), { 
      status: 200, 
      headers: { 'Content-Type': 'text/html' } 
    });
  }
  
  const clientIp = getClientIp(req);
  const preferJson = wantsJson(req);
  
  // Validate access token with rate limiting
  const accessToken = req.headers.get('x-goog-api-key');
  const authResult = validateAccessToken(accessToken, clientIp);
  
  if (authResult.rateLimited) {
    const message = 'Too many failed authentication attempts. Please try again later.';
    log('warn', 'Auth rate limit triggered', { ip: clientIp });
    
    if (preferJson) {
      return jsonErrorResponse(message, 429);
    }
    return new Response(printHomeHtml(message), { 
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
    return new Response(printHomeHtml(message), { 
      status: 403, 
      headers: { 'Content-Type': 'text/html' } 
    });
  }

  try {
    const key = getKey();
    if (!key) {
      const message = 'All API keys are currently blocked due to rate limits. Please try again later.';
      log('error', 'No available keys', { ip: clientIp });
      
      if (preferJson) {
        return jsonErrorResponse(message, 503);
      }
      return new Response(printHomeHtml(message), { 
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
      blockKey(currentKey, response.status);
      
      const nextKey = getKey();
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
      return new Response(printHomeHtml(message), { 
        status: 503, 
        headers: { 'Content-Type': 'text/html' } 
      });
    }

    // Success - track the request in sliding window
    const state = KEYS_STATES[currentKey];
    state.requestTimestamps.push(Date.now());
    
    log('info', 'Request successful', {
      key: currentKey.slice(0, 7),
      attempts,
      status: response.status,
      requestsInWindow: state.requestTimestamps.length,
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
    return new Response(printHomeHtml(message), { 
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
  slidingWindowMinutes: SLIDING_WINDOW_MS / 60000,
});