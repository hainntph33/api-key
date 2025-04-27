// server.js - API Key Management Server with SQLite
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
      allowAutoRegister INTEGER DEFAULT 1
    );
    
    CREATE TABLE IF NOT EXISTS allowed_ips (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      apikey_id INTEGER NOT NULL,
      ip TEXT NOT NULL,
      UNIQUE(apikey_id, ip),
      FOREIGN KEY (apikey_id) REFERENCES apikeys(id) ON DELETE CASCADE
    );
  `);
  
  // Cập nhật schema nếu cần (thêm cột allowAutoRegister cho các bảng cũ)
  try {
    await db.exec(`ALTER TABLE apikeys ADD COLUMN allowAutoRegister INTEGER DEFAULT 1;`);
  } catch (error) {
    // Bỏ qua lỗi nếu cột đã tồn tại
    if (!error.message.includes('duplicate column name')) {
      console.error('Error adding allowAutoRegister column:', error);
    }
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

// Generate a new API key
function generateApiKey() {
  return crypto.randomBytes(24).toString('hex');
}

// Middleware to verify API key and IP
const verifyApiKey = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  const clientIP = getClientIp(req);
  
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
    
    // Check if the client IP is in the allowed IPs list
    const allowedIPs = await db.all('SELECT ip FROM allowed_ips WHERE apikey_id = ?', [keyData.id]);
    const ipList = allowedIPs.map(item => item.ip);
    
    if (ipList.length > 0 && !ipList.includes(clientIP)) {
      return res.status(403).json({ error: 'IP not authorized for this API key' });
    }
    
    // Update usage statistics
    await db.run(
      'UPDATE apikeys SET usageCount = usageCount + 1, lastUsed = datetime("now") WHERE id = ?',
      [keyData.id]
    );
    
    // Attach the key data to the request object
    req.apiKeyData = {
      ...keyData,
      allowedIPs: ipList
    };
    
    next();
  } catch (error) {
    console.error('API key verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Middleware để xác thực API key từ URL query parameter với kiểm soát tự động đăng ký
const verifyApiKeyFromURL = async (req, res, next) => {
  const apiKey = req.query.key;
  const clientIP = getClientIp(req);
  
  console.log('API Key from URL:', apiKey);
  console.log('Client IP:', clientIP);
  
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
    
    // Lấy danh sách IP được phép của key này
    const allowedIPs = await db.all('SELECT ip FROM allowed_ips WHERE apikey_id = ?', [keyData.id]);
    let ipList = allowedIPs.map(item => item.ip);
    
    // Kiểm tra xem IP đã được đăng ký chưa
    if (ipList.includes(clientIP)) {
      // IP đã đăng ký, cho phép truy cập
    } else if (keyData.allowAutoRegister === 1) {
      // Key cho phép tự động đăng ký và IP chưa đăng ký
      await db.run(
        'INSERT INTO allowed_ips (apikey_id, ip) VALUES (?, ?)',
        [keyData.id, clientIP]
      );
      console.log(`Auto-added IP ${clientIP} for key ${apiKey}`);
      
      // Cập nhật danh sách IP
      const updatedIPs = await db.all('SELECT ip FROM allowed_ips WHERE apikey_id = ?', [keyData.id]);
      ipList = updatedIPs.map(item => item.ip);
    } else {
      // Key không cho phép tự động đăng ký và IP chưa được đăng ký
      return res.status(403).json({ 
        error: 'IP not authorized for this API key and auto-registration is disabled',
        clientIP: clientIP
      });
    }
    
    // Update usage statistics
    await db.run(
      'UPDATE apikeys SET usageCount = usageCount + 1, lastUsed = datetime("now") WHERE id = ?',
      [keyData.id]
    );
    
    // Attach the key data to the request object
    req.apiKeyData = {
      ...keyData,
      allowedIPs: ipList
    };
    
    next();
  } catch (error) {
    console.error('API key verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
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
      allowAutoRegister: req.apiKeyData.allowAutoRegister === 1
    },
    clientIP: getClientIp(req),
    allowedIPs: req.apiKeyData.allowedIPs
  });
});

// API routes với xác thực qua URL parameter
app.get('/api/data-url', verifyApiKeyFromURL, (req, res) => {
  res.json({ 
    message: 'You have access to protected data via URL',
    keyName: req.apiKeyData.name,
    clientIP: getClientIp(req),
    registeredIPs: req.apiKeyData.allowedIPs
  });
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
    const { name, allowedIPs, expiresAt, allowAutoRegister } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    
    const key = generateApiKey();
    
    // Start a transaction
    await db.run('BEGIN TRANSACTION');
    
    // Insert the new API key
    const result = await db.run(
      'INSERT INTO apikeys (key, name, expiresAt, allowAutoRegister) VALUES (?, ?, ?, ?)',
      [key, name, expiresAt, allowAutoRegister === false ? 0 : 1]
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
    const ips = await db.all('SELECT ip FROM allowed_ips WHERE apikey_id = ?', [keyId]);
    
    res.status(201).json({
      ...newKey,
      allowedIPs: ips.map(item => item.ip)
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
      const ips = await db.all('SELECT ip FROM allowed_ips WHERE apikey_id = ?', [key.id]);
      key.allowedIPs = ips.map(item => item.ip);
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
    
    const ips = await db.all('SELECT ip FROM allowed_ips WHERE apikey_id = ?', [key.id]);
    key.allowedIPs = ips.map(item => item.ip);
    
    res.json(key);
  } catch (error) {
    console.error('Error fetching API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update an API key
adminRouter.put('/keys/:id', async (req, res) => {
  try {
    const { name, allowedIPs, isActive, expiresAt, allowAutoRegister } = req.body;
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
      'UPDATE apikeys SET name = ?, isActive = ?, expiresAt = ?, allowAutoRegister = ? WHERE id = ?',
      [
        name || existingKey.name,
        isActive !== undefined ? isActive : existingKey.isActive,
        expiresAt || existingKey.expiresAt,
        allowAutoRegister !== undefined ? (allowAutoRegister ? 1 : 0) : existingKey.allowAutoRegister,
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
    const ips = await db.all('SELECT ip FROM allowed_ips WHERE apikey_id = ?', [keyId]);
    updatedKey.allowedIPs = ips.map(item => item.ip);
    
    res.json(updatedKey);
  } catch (error) {
    await db.run('ROLLBACK');
    console.error('Error updating API key:', error);
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

// Register IP for an existing API key
adminRouter.post('/keys/:id/ip', async (req, res) => {
  try {
    const { ip } = req.body;
    const keyId = req.params.id;
    
    if (!ip) {
      return res.status(400).json({ error: 'IP address is required' });
    }
    
    // Check if key exists
    const existingKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    if (!existingKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    // Check if IP already exists for this key
    const existingIp = await db.get(
      'SELECT * FROM allowed_ips WHERE apikey_id = ? AND ip = ?',
      [keyId, ip]
    );
    
    if (!existingIp) {
      // Add new IP
      await db.run(
        'INSERT INTO allowed_ips (apikey_id, ip) VALUES (?, ?)',
        [keyId, ip]
      );
    }
    
    // Get updated key with IPs
    const updatedKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    const ips = await db.all('SELECT ip FROM allowed_ips WHERE apikey_id = ?', [keyId]);
    updatedKey.allowedIPs = ips.map(item => item.ip);
    
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
    
    // Check if key exists
    const existingKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    if (!existingKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    // Delete the IP
    const result = await db.run(
      'DELETE FROM allowed_ips WHERE apikey_id = ? AND ip = ?',
      [keyId, ip]
    );
    
    if (result.changes === 0) {
      return res.status(404).json({ error: 'IP not found for this API key' });
    }
    
    // Get updated key with IPs
    const updatedKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    const ips = await db.all('SELECT ip FROM allowed_ips WHERE apikey_id = ?', [keyId]);
    updatedKey.allowedIPs = ips.map(item => item.ip);
    
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
    clientIP: getClientIp(req)
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