const http = require('http');
const fs = require('fs');
const path = require('path');

// === Rate limiting setup ===
const rateLimitWindowMs = 15 * 60 * 1000; // 15 minutes
const rateLimitMaxRequests = 100;
const ipRequestMap = new Map(); // Stores { ip: { count, timestamp } }

// === Rate limiter function ===
function isRateLimited(ip) {
    const currentTime = Date.now();

    if (!ipRequestMap.has(ip)) {
        ipRequestMap.set(ip, { count: 1, startTime: currentTime });
        return false;
    }

    const userData = ipRequestMap.get(ip);

    if (currentTime - userData.startTime < rateLimitWindowMs) {
        // Still in same window
        if (userData.count >= rateLimitMaxRequests) {
            return true;
        } else {
            userData.count++;
            return false;
        }
    } else {
        // Reset window
        ipRequestMap.set(ip, { count: 1, startTime: currentTime });
        return false;
    }
}

// === WHITELIST OF BROWSERS ===
const knownBrowsers = [
    'Chrome',
    'Firefox',
    'Safari',
    'Edg',       // Microsoft Edge
    'Opera',
    'SamsungBrowser',
    'CriOS',     // Chrome on iOS
    'FxiOS',     // Firefox on iOS
];

// === To Check if request is coming from a web browser ===
function isHumanUser(req) {
    const userAgent = req.headers['user-agent'];
    if (!userAgent) return false; // No UA? Suspicious.

    // Check if UA includes any known browser identifiers
    return knownBrowsers.some(browser => userAgent.includes(browser));
}

// === List of ALLOWED Referers ===
const allowedReferers = [
    'http://localhost:3000',   // Local dev
    'http://127.0.0.1:3000'    
];

// === Hotlinking Check Function ===
function isHotlinking(req) {
    const referer = req.headers['referer'];
    if (!referer) {
        // Place to allow requests without a referer (e.g. direct typing, some privacy browsers)
        return false;
    }
    return !allowedReferers.some(allowed => referer.startsWith(allowed));
}

// === MIME types ===
const mimeTypes = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.webm': 'image/webp',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
};

// === HTML route map ===
const routes = {
    '/': 'home.html',
    '/about': 'about.html',
    '/contact': 'contact.html',
};

// No-cache headers for HTML
const htmlHeaders = {
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
    'Pragma': 'no-cache',
    'Expires': '0',
};

setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of ipRequestMap.entries()) {
        if (now - data.startTime > rateLimitWindowMs) {
            ipRequestMap.delete(ip);
        }
    }
}, 60 * 1000); // Cleanup every 1 minute

const server = http.createServer((req, res) => {
    const ip = req.socket.remoteAddress; // Getting IP address for potential rate-limiting

    // 🛡️ Block bots or unknown user-agents
    if (!isHumanUser(req)) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        return res.end('403 Forbidden — Inorganic traffic blocked');
    }

    // Check rate limit
    if (isRateLimited(ip)) {
        res.writeHead(429, { 'Content-Type': 'text/plain' });
        return res.end('429 Too Many Requests - Rate limit exceeded. Please try again later.');
    }

    const url = req.url; // getting path for routing

    // === Serve HTML routes ===
    if (routes[url]) {
        const filePath = `${__dirname}/public/${routes[url]}`;

        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                return res.end('Internal Server Error');
            }

            res.writeHead(200, {
                'Content-Type': 'text/html',
                ...htmlHeaders,
            });
            res.end(data);
        });
    } else {
        // === Serve static assets (CSS, JS, images) ===
        const safePath = path.normalize(path.join(__dirname, 'public', url));
        
        // Prevent path traversal outside public/
        if (!safePath.startsWith(path.join(__dirname, 'public'))) {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            return res.end('Access denied');
        }

        const ext = path.extname(safePath);
        const contentType = mimeTypes[ext] || 'application/octet-stream';

        fs.readFile(safePath, (err, data) => {
            if (err) {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                return res.end('404 Not Found');
            }

            // Block hotlinking of static assets (CSS, images, JS, etc.)
            if (isHotlinking(req)) {
                res.writeHead(403, { 'Content-Type': 'text/plain' });
                return res.end('403 Forbidden — Hotlinking not allowed');
            }

            res.writeHead(200, {
                'Content-Type': contentType,
                // Optional: you can add cache headers here for static assets if desired
                // 'Cache-Control': 'public, max-age=86400' // 1 day
            });
            res.end(data);
        });
    }
});

// Start server
const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});