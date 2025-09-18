const http = require('http');
const fs = require('fs');
const path = require('path');
var blacklist;
var blockedCountryName;

// === Importation of the regional blacklist ===
try {
    blacklist = JSON.parse(fs.readFileSync(path.join(__dirname, 'blacklist.json'), 'utf8'));
} catch (err) {
    console.error('Failed to load or parse blacklist.json:', err.message);
}

// === Rate limiting setup ===
const rateLimitWindowMs = 15 * 60 * 1000; // 15 minutes
const rateLimitMaxRequests = 100;
const ipRequestMap = new Map(); // Stores { ipAddress: { count, timestamp } }

// === Rate limiter function ===
function isRateLimited(ipAddress) {
    const currentTime = Date.now();

    if (!ipRequestMap.has(ipAddress)) {
        ipRequestMap.set(ipAddress, { count: 1, startTime: currentTime });
        return false;
    }

    const userData = ipRequestMap.get(ipAddress);

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
        ipRequestMap.set(ipAddress, { count: 1, startTime: currentTime });
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
function isHumanUser(userAgent) {
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
function isHotlinking(referer) {
    if (!referer) {
        // Place to allow requests without a referer (e.g. direct typing, some privacy browsers)
        return false;
    }
    return !allowedReferers.some(allowed => referer.startsWith(allowed));
}

// === Check if Country is Blocked ===
function isCountryBlocked(regionCode) {
    const regionMatch = blacklist.find(region => region.regionCode === regionCode);
    if (regionMatch.regionBlocked === "Y") {
        blockedCountryName = regionMatch.CountryName;
        return true;
    } else {
        return false;
    }
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
    for (const [ipAddress, data] of ipRequestMap.entries()) {
        if (now - data.startTime > rateLimitWindowMs) {
            ipRequestMap.delete(ipAddress);
        }
    }
}, 60 * 1000); // Cleanup every 1 minute

const server = http.createServer((req, res) => {
    const regionCode = req.headers?.['cf-ipcountry']; // Extracting Geolocation region code added by CloudFlare Reverse Proxy
    const userAgent = req.headers['user-agent']; // Identifying the application of the requesting user agent
    const ipAddress = req.socket['remoteAddress']; // Getting IP address for potential rate-limiting
    const referer = req.headers['referer']; // Identifying referring pages where requested resources are being used
    
    // Inconjunction with CloudFlare's CF-IPCountry header, executes middleware for region blocking (only executes this property is found in the request object) 
    if(regionCode && isCountryBlocked(regionCode)) { 
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end(`403 Forbidden - Due to regional policies, access is restricted from ${blockedCountryName}.`);
    }

    // Block bots or unknown user-agents
    if (!isHumanUser(userAgent)) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        return res.end('403 Forbidden — Inorganic traffic blocked');
    }

    // Checks rate limit
    if (isRateLimited(ipAddress)) {
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
            if (isHotlinking(referer)) {
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