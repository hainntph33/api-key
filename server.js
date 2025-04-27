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
      maxMachineCount INTEGER DEFAULT 1,
      ipRegistrationStrategy TEXT DEFAULT 'strict'
    );
    
    CREATE TABLE IF NOT EXISTS allowed_ips (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      apikey_id INTEGER NOT NULL,
      ip TEXT NOT NULL,
      machine_identifier TEXT NOT NULL,
      createdAt TEXT DEFAULT (datetime('now')),
      lastUsed TEXT,
      UNIQUE(apikey_id, ip, machine_identifier),
      FOREIGN KEY (apikey_id) REFERENCES apikeys(id) ON DELETE CASCADE
    );
  `);
  
  console.log('Database initialized');
}

// Function to generate API key
function generateApiKey() {
  return crypto.randomBytes(24).toString('hex');
}

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

// Middleware for API key verification from URL
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
    
    // Create unique machine identifier
    const machineIdentifier = crypto.createHash('sha256')
      .update(`${req.headers['user-agent']}:${clientIP}`)
      .digest('hex');
    
    // Check if IP and machine are already registered
    const existingAccess = await db.get(
      'SELECT * FROM allowed_ips WHERE apikey_id = ? AND ip = ?', 
      [keyData.id, clientIP]
    );
    
    // If not registered
    if (!existingAccess) {
      // Check machine count
      const machineCount = await db.get(
        'SELECT COUNT(DISTINCT machine_identifier) as count FROM allowed_ips WHERE apikey_id = ?', 
        [keyData.id]
      );
      
      // Check IP count
      const ipCount = await db.get(
        'SELECT COUNT(*) as count FROM allowed_ips WHERE apikey_id = ?', 
        [keyData.id]
      );
      
      // Check machine limit
      if (machineCount.count >= keyData.maxMachineCount) {
        return res.status(403).json({ 
          error: 'Maximum machine limit reached for this API key',
          maxMachines: keyData.maxMachineCount
        });
      }
      
      // Check IP limit
      if (ipCount.count >= (keyData.maxMachineCount * keyData.maxIpCount)) {
        return res.status(403).json({ 
          error: 'Maximum IP limit reached for this API key',
          maxIPs: keyData.maxMachineCount * keyData.maxIpCount
        });
      }
      
      // Add new IP and machine
      await db.run(
        'INSERT INTO allowed_ips (apikey_id, ip, machine_identifier, lastUsed) VALUES (?, ?, ?, datetime("now"))',
        [keyData.id, clientIP, machineIdentifier]
      );
      
      console.log(`Registered IP ${clientIP} for machine ${machineIdentifier}`);
    } else {
      // If IP exists, check machine
      const machineAccess = await db.get(
        'SELECT * FROM allowed_ips WHERE apikey_id = ? AND ip = ? AND machine_identifier = ?', 
        [keyData.id, clientIP, machineIdentifier]
      );
      
      // If machine doesn't match
      if (!machineAccess) {
        return res.status(403).json({ 
          error: 'IP already registered for a different machine',
          clientIP: clientIP
        });
      }
      
      // Update last used timestamp
      await db.run(
        'UPDATE allowed_ips SET lastUsed = datetime("now") WHERE apikey_id = ? AND ip = ? AND machine_identifier = ?',
        [keyData.id, clientIP, machineIdentifier]
      );
    }
    
    // Update API key usage count
    await db.run(
      'UPDATE apikeys SET usageCount = usageCount + 1, lastUsed = datetime("now") WHERE id = ?',
      [keyData.id]
    );
    
    // Get allowed access list
    const allowedAccess = await db.all(
      'SELECT ip, machine_identifier FROM allowed_ips WHERE apikey_id = ?', 
      [keyData.id]
    );
    
    // Attach key data to request
    req.apiKeyData = {
      ...keyData,
      allowedAccess: allowedAccess
    };
    
    next();
  } catch (error) {
    console.error('API key verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Create Express Router for admin routes
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
    const { 
      name, 
      allowedIPs, 
      expiresAt, 
      allowAutoRegister, 
      maxIpCount, 
      maxMachineCount,
      ipRegistrationStrategy 
    } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    
    const key = generateApiKey();
    
    // Start a transaction
    await db.run('BEGIN TRANSACTION');
    
    // Insert the new API key with machine count and IP strategy
    const result = await db.run(
      'INSERT INTO apikeys (key, name, expiresAt, allowAutoRegister, maxIpCount, maxMachineCount, ipRegistrationStrategy) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [
        key, 
        name, 
        expiresAt, 
        allowAutoRegister === false ? 0 : 1,
        maxIpCount || 5,
        maxMachineCount || 1,
        ipRegistrationStrategy || 'strict'
      ]
    );
    
    const keyId = result.lastID;
    
    // Insert allowed IPs
    if (allowedIPs && allowedIPs.length > 0) {
      const insertIpStatement = await db.prepare(
        'INSERT INTO allowed_ips (apikey_id, ip, machine_identifier) VALUES (?, ?, ?)'
      );
      
      for (const ip of allowedIPs) {
        // Use a default machine identifier for pre-registered IPs
        await insertIpStatement.run(keyId, ip, 'default-machine');
      }
      
      await insertIpStatement.finalize();
    }
    
    // Commit the transaction
    await db.run('COMMIT');
    
    // Get the created API key with IPs
    const newKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    const ips = await db.all('SELECT ip, machine_identifier FROM allowed_ips WHERE apikey_id = ?', [keyId]);
    
    res.status(201).json({
      ...newKey,
      allowedIPs: ips.map(item => ({
        ip: item.ip,
        machineIdentifier: item.machine_identifier
      }))
    });
  } catch (error) {
    await db.run('ROLLBACK');
    console.error('Error creating API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Register admin routes with the main app
app.use('/admin', adminRouter);

// API routes with URL parameter verification
app.get('/api/data-url', verifyApiKeyFromURL, (req, res) => {
  res.json({ 
    message: 'You have access to protected data via URL',
    keyName: req.apiKeyData.name,
    clientIP: getClientIp(req),
    registeredIPs: req.apiKeyData.allowedAccess,
    ipLimit: req.apiKeyData.maxIpCount,
    currentIpCount: req.apiKeyData.allowedAccess.length
  });
});

// Initialize database and start server
initializeDatabase()
  .then(() => {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });

module.exports = app;