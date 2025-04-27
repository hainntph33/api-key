// server.js - API Key Management Server with SQLite, IP limits and usage limits
const express = require('express');
const morgan = require('morgan');
const crypto = require('crypto');
const dotenv = require('dotenv');
const path = require('path');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const fs = require('fs');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
app.use(express.json());
app.use(morgan('dev'));
app.use(cors());

// Serve static files from the public directory
app.use(express.static('public'));

// Create database directory if it doesn't exist
const dbDir = path.join(__dirname, 'database');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir);
}

// SQLite database connection
const dbPath = path.join(dbDir, 'apikeys.db');
let db;

// Initialize database and create tables if they don't exist
async function initializeDatabase() {
  db = await open({
    filename: dbPath,
    driver: sqlite3.Database
  });

  // Enable foreign keys
  await db.run('PRAGMA foreign_keys = ON');

  // Create tables
  await db.exec(`
    CREATE TABLE IF NOT EXISTS apikeys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      isActive INTEGER DEFAULT 1,
      createdAt TEXT DEFAULT (datetime('now')),
      expiresAt TEXT,
      usageCount INTEGER DEFAULT 0,
      lastUsed TEXT,
      allowAutoRegister INTEGER DEFAULT 1,
      maxIpCount INTEGER DEFAULT 5,
      multipleDevicesPerIp INTEGER DEFAULT 0,
      usageLimit INTEGER DEFAULT 0
    );
    
    CREATE TABLE IF NOT EXISTS allowed_ips (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      apikey_id INTEGER NOT NULL,
      ip TEXT NOT NULL,
      createdAt TEXT DEFAULT (datetime('now')),
      lastUsed TEXT,
      deviceIdentifier TEXT,
      UNIQUE(apikey_id, ip, deviceIdentifier),
      FOREIGN KEY (apikey_id) REFERENCES apikeys(id) ON DELETE CASCADE
    );
  `);
  
  // Cập nhật schema nếu cần (thêm cột cho các bảng cũ)
  try {
    await db.exec(`
      ALTER TABLE apikeys ADD COLUMN allowAutoRegister INTEGER DEFAULT 1;
      ALTER TABLE apikeys ADD COLUMN maxIpCount INTEGER DEFAULT 5;
      ALTER TABLE apikeys ADD COLUMN multipleDevicesPerIp INTEGER DEFAULT 0;
      ALTER TABLE apikeys ADD COLUMN usageLimit INTEGER DEFAULT 0;
      ALTER TABLE allowed_ips ADD COLUMN createdAt TEXT DEFAULT (datetime('now'));
      ALTER TABLE allowed_ips ADD COLUMN lastUsed TEXT;
      ALTER TABLE allowed_ips ADD COLUMN deviceIdentifier TEXT;
    `);
  } catch (error) {
    // Bỏ qua lỗi nếu cột đã tồn tại
    console.log('Some columns may already exist, continuing...');
  }
  
  console.log('Database initialized');
}

// Initialize database on startup
initializeDatabase().catch(err => {
  console.error('Database initialization error:', err);
  process.exit(1);
});

// Function to get real client IP
function getClientIp(req) {
  // Check for X-Forwarded-For header (most proxies)
  const xForwardedFor = req.headers['x-forwarded-for'];
  if (xForwardedFor) {
    // Get the first IP in the list
    const ips = xForwardedFor.split(',').map(ip => ip.trim());
    return ips[0];
  }
  
  // Check for Cloudflare IP
  if (req.headers['cf-connecting-ip']) {
    return req.headers['cf-connecting-ip'];
  }
  
  // Check for X-Real-IP header
  if (req.headers['x-real-ip']) {
    return req.headers['x-real-ip'];
  }
  
  // Use the standard IP from request
  return req.ip || req.connection.remoteAddress;
}

// Function to get device identifier
function getDeviceIdentifier(req) {
  // Ưu tiên sử dụng device-id từ header nếu có
  const deviceId = req.headers['device-id'] || req.query.deviceId;
  if (deviceId) {
    return deviceId;
  }
  
  // Tạo một định danh dựa trên user-agent và thông tin khác
  const userAgent = req.headers['user-agent'] || 'unknown';
  const acceptLanguage = req.headers['accept-language'] || 'unknown';
  
  // Tạo hash từ các thông tin trên để tạo device identifier
  return crypto
    .createHash('md5')
    .update(`${userAgent}|${acceptLanguage}`)
    .digest('hex');
}

// Generate a new API key
function generateApiKey() {
  return crypto.randomBytes(24).toString('hex');
}

// Middleware to verify API key and IP from header
const verifyApiKey = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  const clientIP = getClientIp(req);
  const deviceIdentifier = getDeviceIdentifier(req);
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API key is required' });
  }

  try {
    // Get API key data
    const keyData = await db.get('SELECT * FROM apikeys WHERE key = ?', [apiKey]);
    
    if (!keyData) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    
    if (!keyData.isActive) {
      return res.status(403).json({ error: 'API key is inactive' });
    }
    
    if (keyData.expiresAt && new Date(keyData.expiresAt) < new Date()) {
      return res.status(403).json({ error: 'API key has expired' });
    }
    
    // Kiểm tra giới hạn số lần sử dụng
    if (keyData.usageLimit > 0 && keyData.usageCount >= keyData.usageLimit) {
      return res.status(403).json({ 
        error: 'Usage limit exceeded for this API key',
        usageLimit: keyData.usageLimit,
        currentUsage: keyData.usageCount
      });
    }
    
    // Check if the client IP is in the allowed IPs list for this device
    const allowedIP = await db.get(
      'SELECT * FROM allowed_ips WHERE apikey_id = ? AND ip = ? AND (deviceIdentifier IS NULL OR deviceIdentifier = ? OR ? = "")', 
      [keyData.id, clientIP, deviceIdentifier, deviceIdentifier]
    );
    
    if (!allowedIP) {
      // Check if API key allows auto-register and if we're under the max IP limit
      if (keyData.allowAutoRegister === 1) {
        // Count existing IPs for this key
        const ipCount = await db.get('SELECT COUNT(*) as count FROM allowed_ips WHERE apikey_id = ?', [keyData.id]);
        
        if (ipCount.count >= keyData.maxIpCount) {
          return res.status(403).json({ 
            error: 'Maximum IP limit reached for this API key',
            maxIps: keyData.maxIpCount,
            currentIpCount: ipCount.count 
          });
        }
        
        // Kiểm tra xem IP đã được sử dụng trước đó chưa
        const existingIPCount = await db.get(
          'SELECT COUNT(*) as count FROM allowed_ips WHERE apikey_id = ? AND ip = ?', 
          [keyData.id, clientIP]
        );
        
        // Nếu IP đã tồn tại và không cho phép nhiều thiết bị/IP
        if (existingIPCount.count > 0 && keyData.multipleDevicesPerIp !== 1) {
          return res.status(403).json({ 
            error: 'This IP is already registered with another device and multiple devices per IP is not allowed',
            clientIP: clientIP
          });
        }
        
        // Add the new IP with device identifier
        await db.run(
          'INSERT INTO allowed_ips (apikey_id, ip, deviceIdentifier, lastUsed) VALUES (?, ?, ?, datetime("now"))',
          [keyData.id, clientIP, deviceIdentifier]
        );
        console.log(`Auto-added IP ${clientIP} with device ${deviceIdentifier} for key ${apiKey}`);
      } else {
        return res.status(403).json({ 
          error: 'IP not authorized for this API key and auto-registration is disabled',
          clientIP: clientIP,
          deviceIdentifier: deviceIdentifier
        });
      }
    } else {
      // Update last used timestamp for this IP
      await db.run(
        'UPDATE allowed_ips SET lastUsed = datetime("now") WHERE apikey_id = ? AND ip = ? AND (deviceIdentifier IS NULL OR deviceIdentifier = ? OR ? = "")',
        [keyData.id, clientIP, deviceIdentifier, deviceIdentifier]
      );
    }
    
    // Update usage statistics for the API key
    await db.run(
      'UPDATE apikeys SET usageCount = usageCount + 1, lastUsed = datetime("now") WHERE id = ?',
      [keyData.id]
    );
    
    // Get the updated allowed IPs
    const allowedIPs = await db.all('SELECT ip, deviceIdentifier FROM allowed_ips WHERE apikey_id = ?', [keyData.id]);
    
    // Attach the key data to the request object
    req.apiKeyData = {
      ...keyData,
      allowedIPs: allowedIPs.map(item => ({
        ip: item.ip,
        deviceIdentifier: item.deviceIdentifier
      }))
    };
    
    next();
  } catch (error) {
    console.error('API key verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Middleware để xác thực API key từ URL query parameter với kiểm soát giới hạn IP
const verifyApiKeyFromURL = async (req, res, next) => {
  const apiKey = req.query.key;
  const clientIP = getClientIp(req);
  const deviceIdentifier = getDeviceIdentifier(req);
  
  console.log('API Key from URL:', apiKey);
  console.log('Client IP:', clientIP);
  console.log('Device Identifier:', deviceIdentifier);
  
  if (!apiKey) {
    return res.status(401).send('false:API key is required');
  }

  try {
    // Get API key data
    const keyData = await db.get('SELECT * FROM apikeys WHERE key = ?', [apiKey]);
    
    if (!keyData) {
      return res.status(401).send('false:Invalid API key');
    }
    
    if (!keyData.isActive) {
      return res.status(403).send('false:API key is inactive');
    }
    
    if (keyData.expiresAt && new Date(keyData.expiresAt) < new Date()) {
      return res.status(403).send('false:API key has expired');
    }
    
    // Kiểm tra giới hạn số lần sử dụng
    if (keyData.usageLimit > 0 && keyData.usageCount >= keyData.usageLimit) {
      return res.status(403).send(`false:Usage limit exceeded (${keyData.usageCount}/${keyData.usageLimit})`);
    }
    
    // Check if the client IP is already in the allowed IPs list for this device
    const allowedIP = await db.get(
      'SELECT * FROM allowed_ips WHERE apikey_id = ? AND ip = ? AND (deviceIdentifier IS NULL OR deviceIdentifier = ? OR ? = "")', 
      [keyData.id, clientIP, deviceIdentifier, deviceIdentifier]
    );
    
    if (!allowedIP) {
      // IP not registered yet - auto đăng ký IP cho URL API endpoint
      // Count existing IPs for this key
      const ipCount = await db.get('SELECT COUNT(*) as count FROM allowed_ips WHERE apikey_id = ?', [keyData.id]);
      
      if (ipCount.count >= keyData.maxIpCount) {
        return res.status(403).send(`false:Maximum IP limit reached (${ipCount.count}/${keyData.maxIpCount})`);
      }
      
      // Kiểm tra xem IP đã tồn tại trước đó chưa
      const existingIPCount = await db.get(
        'SELECT COUNT(*) as count FROM allowed_ips WHERE apikey_id = ? AND ip = ?', 
        [keyData.id, clientIP]
      );
      
      // Nếu IP đã tồn tại và không cho phép nhiều thiết bị/IP
      if (existingIPCount.count > 0 && keyData.multipleDevicesPerIp !== 1) {
        return res.status(403).send('false:This IP is already registered with another device');
      }
      
      // Add the new IP with device identifier - luôn đăng ký khi gọi qua URL
      await db.run(
        'INSERT INTO allowed_ips (apikey_id, ip, deviceIdentifier, lastUsed) VALUES (?, ?, ?, datetime("now"))',
        [keyData.id, clientIP, deviceIdentifier]
      );
      console.log(`Auto-registered IP ${clientIP} with device ${deviceIdentifier} for key ${apiKey} via URL endpoint`);
    } else {
      // Update last used timestamp for this IP
      await db.run(
        'UPDATE allowed_ips SET lastUsed = datetime("now") WHERE apikey_id = ? AND ip = ? AND (deviceIdentifier IS NULL OR deviceIdentifier = ? OR ? = "")',
        [keyData.id, clientIP, deviceIdentifier, deviceIdentifier]
      );
    }
    
    // Update usage statistics for the API key
    await db.run(
      'UPDATE apikeys SET usageCount = usageCount + 1, lastUsed = datetime("now") WHERE id = ?',
      [keyData.id]
    );
    
    // Get the updated allowed IPs
    const allowedIPs = await db.all('SELECT ip, deviceIdentifier FROM allowed_ips WHERE apikey_id = ?', [keyData.id]);
    
    // Attach the key data to the request object
    req.apiKeyData = {
      ...keyData,
      allowedIPs: allowedIPs.map(item => ({
        ip: item.ip,
        deviceIdentifier: item.deviceIdentifier
      }))
    };
    
    next();
  } catch (error) {
    console.error('API key verification error:', error);
    res.status(500).send('false:Internal server error');
  }
};

// Route để xác thực API key thông qua URL
app.get('/verify', verifyApiKeyFromURL, (req, res) => {
  res.json({ 
    valid: true,
    message: 'API key is valid',
    key: {
      name: req.apiKeyData.name,
      expiresAt: req.apiKeyData.expiresAt,
      usageCount: req.apiKeyData.usageCount,
      usageLimit: req.apiKeyData.usageLimit,
      allowAutoRegister: req.apiKeyData.allowAutoRegister === 1,
      multipleDevicesPerIp: req.apiKeyData.multipleDevicesPerIp === 1,
      maxIpCount: req.apiKeyData.maxIpCount
    },
    clientIP: getClientIp(req),
    deviceIdentifier: getDeviceIdentifier(req),
    allowedIPs: req.apiKeyData.allowedIPs,
    ipRegistrationUrl: `${req.protocol}://${req.get('host')}/api/data-url?key=${req.query.key}`
  });
});

// API routes với xác thực qua URL parameter - luôn đăng ký IP tự động và trả về true/false
app.get('/api/data-url', verifyApiKeyFromURL, (req, res) => {
  res.send('true');
});

// Admin routes for managing API keys
const adminRouter = express.Router();

// Admin authentication middleware
adminRouter.use((req, res, next) => {
  const adminToken = req.headers['x-admin-token'];
  
  if (!adminToken || adminToken !== process.env.ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Admin authentication required' });
  }
  
  next();
});

// Create a new API key
adminRouter.post('/keys', async (req, res) => {
  try {
    const { name, allowedIPs, expiresAt, allowAutoRegister, maxIpCount, multipleDevicesPerIp, usageLimit } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    
    const key = generateApiKey();
    
    // Start a transaction
    await db.run('BEGIN TRANSACTION');
    
    // Insert the new API key
    const result = await db.run(
      'INSERT INTO apikeys (key, name, expiresAt, allowAutoRegister, maxIpCount, multipleDevicesPerIp, usageLimit) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [
        key, 
        name, 
        expiresAt, 
        allowAutoRegister === false ? 0 : 1,
        maxIpCount || 5,
        multipleDevicesPerIp === true ? 1 : 0,
        usageLimit || 0
      ]
    );
    
    const keyId = result.lastID;
    
    // Insert allowed IPs
    if (allowedIPs && allowedIPs.length > 0) {
      const insertIpStatement = await db.prepare(
        'INSERT INTO allowed_ips (apikey_id, ip) VALUES (?, ?)'
      );
      
      for (const ip of allowedIPs) {
        await insertIpStatement.run(keyId, ip);
      }
      
      await insertIpStatement.finalize();
    }
    
    // Commit the transaction
    await db.run('COMMIT');
    
    // Get the created API key with IPs
    const newKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    const ips = await db.all('SELECT ip, deviceIdentifier FROM allowed_ips WHERE apikey_id = ?', [keyId]);
    
    res.status(201).json({
      ...newKey,
      allowedIPs: ips.map(item => item.ip),
      ipDetails: ips
    });
  } catch (error) {
    await db.run('ROLLBACK');
    console.error('Error creating API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all API keys
adminRouter.get('/keys', async (req, res) => {
  try {
    const keys = await db.all('SELECT * FROM apikeys ORDER BY createdAt DESC');
    
    // Get allowed IPs for each key
    for (const key of keys) {
      const ips = await db.all('SELECT ip, deviceIdentifier, createdAt, lastUsed FROM allowed_ips WHERE apikey_id = ?', [key.id]);
      key.allowedIPs = ips.map(item => item.ip);
      key.ipDetails = ips;
    }
    
    res.json(keys);
  } catch (error) {
    console.error('Error fetching API keys:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get a single API key
adminRouter.get('/keys/:id', async (req, res) => {
  try {
    const key = await db.get('SELECT * FROM apikeys WHERE id = ?', [req.params.id]);
    
    if (!key) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    const ips = await db.all('SELECT ip, deviceIdentifier, createdAt, lastUsed FROM allowed_ips WHERE apikey_id = ?', [key.id]);
    key.allowedIPs = ips.map(item => item.ip);
    key.ipDetails = ips;
    
    res.json(key);
  } catch (error) {
    console.error('Error fetching API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update an API key
adminRouter.put('/keys/:id', async (req, res) => {
  try {
    const { name, allowedIPs, isActive, expiresAt, allowAutoRegister, maxIpCount, multipleDevicesPerIp, usageLimit } = req.body;
    const keyId = req.params.id;
    
    // Check if key exists
    const existingKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    if (!existingKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    // Start a transaction
    await db.run('BEGIN TRANSACTION');
    
    // Update the API key
    await db.run(
      'UPDATE apikeys SET name = ?, isActive = ?, expiresAt = ?, allowAutoRegister = ?, maxIpCount = ?, multipleDevicesPerIp = ?, usageLimit = ? WHERE id = ?',
      [
        name || existingKey.name,
        isActive !== undefined ? isActive : existingKey.isActive,
        expiresAt || existingKey.expiresAt,
        allowAutoRegister !== undefined ? (allowAutoRegister ? 1 : 0) : existingKey.allowAutoRegister,
        maxIpCount || existingKey.maxIpCount,
        multipleDevicesPerIp !== undefined ? (multipleDevicesPerIp ? 1 : 0) : existingKey.multipleDevicesPerIp,
        usageLimit !== undefined ? usageLimit : existingKey.usageLimit,
        keyId
      ]
    );
    
    // Update allowed IPs if provided
    if (allowedIPs) {
      // Delete existing IPs
      await db.run('DELETE FROM allowed_ips WHERE apikey_id = ?', [keyId]);
      
      // Insert new IPs
      if (allowedIPs.length > 0) {
        const insertIpStatement = await db.prepare(
          'INSERT INTO allowed_ips (apikey_id, ip) VALUES (?, ?)'
        );
        
        for (const ip of allowedIPs) {
          await insertIpStatement.run(keyId, ip);
        }
        
        await insertIpStatement.finalize();
      }
    }
    
    // Commit the transaction
    await db.run('COMMIT');
    
    // Get the updated API key
    const updatedKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    const ips = await db.all('SELECT ip, deviceIdentifier, createdAt, lastUsed FROM allowed_ips WHERE apikey_id = ?', [keyId]);
    updatedKey.allowedIPs = ips.map(item => item.ip);
    updatedKey.ipDetails = ips;
    
    res.json(updatedKey);
  } catch (error) {
    await db.run('ROLLBACK');
    console.error('Error updating API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Reset usage count for an API key
adminRouter.post('/keys/:id/reset-usage', async (req, res) => {
  try {
    const keyId = req.params.id;
    
    // Check if key exists
    const existingKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    if (!existingKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    // Reset usage count
    await db.run('UPDATE apikeys SET usageCount = 0 WHERE id = ?', [keyId]);
    
    // Get the updated API key
    const updatedKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    const ips = await db.all('SELECT ip, deviceIdentifier, createdAt, lastUsed FROM allowed_ips WHERE apikey_id = ?', [keyId]);
    updatedKey.allowedIPs = ips.map(item => item.ip);
    updatedKey.ipDetails = ips;
    
    res.json(updatedKey);
  } catch (error) {
    console.error('Error resetting usage count:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete an API key
adminRouter.delete('/keys/:id', async (req, res) => {
  try {
    const keyId = req.params.id;
    
    // Check if key exists
    const existingKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    if (!existingKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    // Delete the key (cascades to allowed_ips due to foreign key constraint)
    await db.run('DELETE FROM apikeys WHERE id = ?', [keyId]);
    
    res.status(204).end();
  } catch (error) {
    console.error('Error deleting API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Lưu trữ tạm thời các IP đã yêu cầu key và thời gian cuối cùng họ nhận được key
const tempKeyRequests = new Map();

// Rate limiter cho các yêu cầu API để ngăn chặn các cuộc tấn công brute force
const apiRateLimiter = new Map();

// Middleware để giới hạn tốc độ cho các yêu cầu API
function rateLimiterMiddleware(req, res, next) {
  const clientIP = getClientIp(req);
  const now = Date.now();
  
  if (apiRateLimiter.has(clientIP)) {
    const requests = apiRateLimiter.get(clientIP);
    
    // Xóa các yêu cầu cũ hơn 1 phút
    const recentRequests = requests.filter(time => now - time < 60000);
    
    // Lưu trữ yêu cầu hiện tại
    recentRequests.push(now);
    apiRateLimiter.set(clientIP, recentRequests);
    
    // Kiểm tra nếu có quá nhiều yêu cầu (hơn 20 trong 1 phút)
    if (recentRequests.length > 20) {
      return res.status(429).send('false:Quá nhiều yêu cầu. Vui lòng thử lại sau.');
    }
  } else {
    // Lần đầu tiên gọi API từ IP này
    apiRateLimiter.set(clientIP, [now]);
  }
  
  next();
}

// Áp dụng rate limiter cho các routes cần bảo vệ
app.use('/api', rateLimiterMiddleware);
app.use('/verify', rateLimiterMiddleware);
app.use('/generate-temp-key', rateLimiterMiddleware);

// Định kỳ dọn dẹp bộ nhớ đệm rate limiter
setInterval(() => {
  const now = Date.now();
  
  // Xóa các IP đã không hoạt động trong 10 phút
  for (const [ip, times] of apiRateLimiter.entries()) {
    const recentRequests = times.filter(time => now - time < 600000);
    if (recentRequests.length === 0) {
      apiRateLimiter.delete(ip);
    } else {
      apiRateLimiter.set(ip, recentRequests);
    }
  }
}, 300000); // Chạy mỗi 5 phút

// Chức năng tạo key tạm thời từ URL
app.get('/generate-temp-key', async (req, res) => {
  const clientIP = getClientIp(req);
  const deviceIdentifier = getDeviceIdentifier(req);
  const now = new Date();
  
  // Kiểm tra nếu IP này đã yêu cầu key trước đó và phải chờ
  if (tempKeyRequests.has(clientIP)) {
    const lastRequest = tempKeyRequests.get(clientIP);
    const timeDifference = now - lastRequest.timestamp;
    
    // Kiểm tra xem đã qua 30 phút chưa (1800000 milliseconds)
    if (timeDifference < 1800000) {
      const remainingTime = Math.ceil((1800000 - timeDifference) / 60000);
      return res.status(429).json({
        error: `Yêu cầu quá nhiều. Vui lòng thử lại sau ${remainingTime} phút.`,
        clientIP: clientIP,
        nextAvailableTime: new Date(lastRequest.timestamp.getTime() + 1800000).toISOString()
      });
    }
  }
  
  try {
    // Tạo tên key dựa trên IP và thời gian
    const keyName = `TempKey_${clientIP.replace(/\./g, '_')}_${Date.now()}`;
    
    // Tạo key mới với các giới hạn
    const key = generateApiKey();
    
    // Lưu thời gian yêu cầu và thông tin vào bộ nhớ tạm thời
    tempKeyRequests.set(clientIP, {
      timestamp: now,
      key: key
    });
    
    // Tính toán thời gian hết hạn (30 phút từ bây giờ)
    const expiryTime = new Date(now.getTime() + 1800000).toISOString();
    
    // Bắt đầu transaction
    await db.run('BEGIN TRANSACTION');
    
    // Thêm key vào database
    const result = await db.run(
      'INSERT INTO apikeys (key, name, expiresAt, allowAutoRegister, maxIpCount, multipleDevicesPerIp, usageLimit) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [
        key,
        keyName,
        expiryTime,
        0, // Không cho phép tự động đăng ký IP
        1, // Chỉ cho phép 1 IP
        0, // Không cho phép nhiều thiết bị/IP
        5  // Giới hạn 5 lần sử dụng
      ]
    );
    
    const keyId = result.lastID;
    
    // Đăng ký IP của client
    await db.run(
      'INSERT INTO allowed_ips (apikey_id, ip, deviceIdentifier, lastUsed) VALUES (?, ?, ?, datetime("now"))',
      [keyId, clientIP, deviceIdentifier]
    );
    
    // Hoàn thành transaction
    await db.run('COMMIT');
    
    // Trả về thông tin key cho client
    res.json({
      success: true,
      message: 'Key tạm thời đã được tạo thành công.',
      apiKey: key,
      usageLimit: 5,
      expiresAt: expiryTime,
      registeredIP: clientIP,
      deviceIdentifier: deviceIdentifier,
      testEndpoint: `${req.protocol}://${req.get('host')}/api/data-url?key=${key}`
    });
    
  } catch (error) {
    await db.run('ROLLBACK');
    console.error('Error creating temporary API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Register IP for an existing API key
adminRouter.post('/keys/:id/ip', async (req, res) => {
  try {
    const { ip, deviceIdentifier } = req.body;
    const keyId = req.params.id;
    
    if (!ip) {
      return res.status(400).json({ error: 'IP address is required' });
    }
    
    // Check if key exists
    const existingKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    if (!existingKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    // Check if we're under the IP limit
    const ipCount = await db.get('SELECT COUNT(*) as count FROM allowed_ips WHERE apikey_id = ?', [keyId]);
    
    if (ipCount.count >= existingKey.maxIpCount) {
      return res.status(403).json({ 
        error: 'Maximum IP limit reached for this API key',
        maxIps: existingKey.maxIpCount,
        currentIpCount: ipCount.count
      });
    }
    
    // Kiểm tra nếu IP đã tồn tại cho thiết bị này
    const existingIp = await db.get(
      'SELECT * FROM allowed_ips WHERE apikey_id = ? AND ip = ? AND (deviceIdentifier = ? OR ? IS NULL)', 
      [keyId, ip, deviceIdentifier, deviceIdentifier]
    );
    
    // Kiểm tra nếu IP đã tồn tại nhưng cho thiết bị khác và không cho phép nhiều thiết bị/IP
    const existingIPForOtherDevice = await db.get(
      'SELECT COUNT(*) as count FROM allowed_ips WHERE apikey_id = ? AND ip = ? AND (deviceIdentifier != ? OR ? IS NULL)', 
      [keyId, ip, deviceIdentifier, deviceIdentifier]
    );
    
    if (!existingIp) {
      if (existingIPForOtherDevice && existingIPForOtherDevice.count > 0 && existingKey.multipleDevicesPerIp !== 1) {
        return res.status(403).json({ 
          error: 'This IP is already registered with another device and multiple devices per IP is not allowed',
          ip: ip
        });
      }
      
      // Add new IP with device identifier
      await db.run(
        'INSERT INTO allowed_ips (apikey_id, ip, deviceIdentifier) VALUES (?, ?, ?)',
        [keyId, ip, deviceIdentifier || null]
      );
    }
    
    // Get updated key with IPs
    const updatedKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    const ips = await db.all('SELECT ip, deviceIdentifier, createdAt, lastUsed FROM allowed_ips WHERE apikey_id = ?', [keyId]);
    updatedKey.allowedIPs = ips.map(item => item.ip);
    updatedKey.ipDetails = ips;
    
    res.json(updatedKey);
  } catch (error) {
    console.error('Error registering IP:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Remove IP from an API key
adminRouter.delete('/keys/:id/ip/:ip', async (req, res) => {
  try {
    const keyId = req.params.id;
    const ip = req.params.ip;
    const deviceIdentifier = req.query.deviceIdentifier;
    
    // Check if key exists
    const existingKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    if (!existingKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    // Delete the IP - if deviceIdentifier is provided, only delete for that device
    let result;
    if (deviceIdentifier) {
      result = await db.run(
        'DELETE FROM allowed_ips WHERE apikey_id = ? AND ip = ? AND deviceIdentifier = ?',
        [keyId, ip, deviceIdentifier]
      );
    } else {
      result = await db.run(
        'DELETE FROM allowed_ips WHERE apikey_id = ? AND ip = ?',
        [keyId, ip]
      );
    }
    
    if (result.changes === 0) {
      return res.status(404).json({ error: 'IP not found for this API key' });
    }
    
    // Get updated key with IPs
    const updatedKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    const ips = await db.all('SELECT ip, deviceIdentifier, createdAt, lastUsed FROM allowed_ips WHERE apikey_id = ?', [keyId]);
    updatedKey.allowedIPs = ips.map(item => item.ip);
    updatedKey.ipDetails = ips;
    
    res.json(updatedKey);
  } catch (error) {
    console.error('Error removing IP:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Register admin routes
app.use('/admin', adminRouter);

// API routes that require API key authentication
const apiRouter = express.Router();
apiRouter.use(verifyApiKey);

// Sample protected API endpoint
apiRouter.get('/data', (req, res) => {
  res.json({ 
    message: 'You have access to protected data',
    keyName: req.apiKeyData.name,
    clientIP: getClientIp(req),
    deviceIdentifier: getDeviceIdentifier(req),
    ipLimit: req.apiKeyData.maxIpCount,
    multipleDevicesPerIp: req.apiKeyData.multipleDevicesPerIp === 1,
    usageCount: req.apiKeyData.usageCount,
    usageLimit: req.apiKeyData.usageLimit > 0 ? req.apiKeyData.usageLimit : 'Unlimited',
    registeredIPs: req.apiKeyData.allowedIPs
  });
});

// Register API routes
app.use('/api', apiRouter);

// Serve the main HTML file for any route not handled by API
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});