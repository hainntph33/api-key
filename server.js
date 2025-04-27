// server.js - API Key Management Server with Enhanced IP and Machine Restrictions
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

  // Create tables with additional columns for machine restrictions
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
      ipRegistrationStrategy TEXT DEFAULT 'strict' -- 'strict' or 'flexible'
    );
    
    CREATE TABLE IF NOT EXISTS allowed_ips (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      apikey_id INTEGER NOT NULL,
      ip TEXT NOT NULL,
      machine_identifier TEXT NOT NULL, -- Unique machine identifier
      createdAt TEXT DEFAULT (datetime('now')),
      lastUsed TEXT,
      UNIQUE(apikey_id, ip, machine_identifier),
      FOREIGN KEY (apikey_id) REFERENCES apikeys(id) ON DELETE CASCADE
    );
  `);
  
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

// Function to generate a unique machine identifier
function generateMachineIdentifier(req) {
  // Combine multiple factors to create a unique machine identifier
  const userAgent = req.headers['user-agent'] || '';
  const clientIp = getClientIp(req);
  const acceptLanguage = req.headers['accept-language'] || '';
  
  // Hash the combined string to create a unique identifier
  return crypto.createHash('sha256')
    .update(`${userAgent}:${clientIp}:${acceptLanguage}`)
    .digest('hex');
}

// Middleware to verify API key from URL with enhanced machine and IP restrictions
const verifyApiKeyFromURL = async (req, res, next) => {
  const apiKey = req.query.key;
  const clientIP = getClientIp(req);
  const machineIdentifier = generateMachineIdentifier(req);
  
  console.log('API Key from URL:', apiKey);
  console.log('Client IP:', clientIP);
  console.log('Machine Identifier:', machineIdentifier);
  
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
    
    // Check IP and machine restrictions
    const existingIP = await db.get(
      'SELECT * FROM allowed_ips WHERE apikey_id = ? AND ip = ? AND machine_identifier = ?', 
      [keyData.id, clientIP, machineIdentifier]
    );
    
    // If no exact match, check further restrictions
    if (!existingIP) {
      // Check machine count restrictions
      const machineCount = await db.get(
        'SELECT COUNT(DISTINCT machine_identifier) as count FROM allowed_ips WHERE apikey_id = ?', 
        [keyData.id]
      );
      
      // Check IP count restrictions
      const ipCount = await db.get(
        'SELECT COUNT(*) as count FROM allowed_ips WHERE apikey_id = ?', 
        [keyData.id]
      );
      
      // Determine if auto-registration is allowed
      if (keyData.allowAutoRegister === 1) {
        // Check machine count limit
        if (machineCount.count >= keyData.maxMachineCount) {
          return res.status(403).json({ 
            error: 'Maximum machine limit reached for this API key',
            maxMachines: keyData.maxMachineCount,
            currentMachineCount: machineCount.count,
            message: 'Please contact the administrator to modify machine access'
          });
        }
        
        // Check IP count limit
        if (ipCount.count >= keyData.maxIpCount) {
          return res.status(403).json({ 
            error: 'Maximum IP limit reached for this API key',
            maxIps: keyData.maxIpCount,
            currentIpCount: ipCount.count,
            message: 'Please contact the administrator to remove unused IPs'
          });
        }
        
        // Auto-register the new IP and machine
        await db.run(
          'INSERT INTO allowed_ips (apikey_id, ip, machine_identifier, lastUsed) VALUES (?, ?, ?, datetime("now"))',
          [keyData.id, clientIP, machineIdentifier]
        );
        console.log(`Auto-added IP ${clientIP} with machine ${machineIdentifier} for key ${apiKey}`);
      } else {
        // Auto-registration disabled
        return res.status(403).json({ 
          error: 'IP or machine not authorized for this API key and auto-registration is disabled',
          clientIP: clientIP,
          machineIdentifier: machineIdentifier
        });
      }
    } else {
      // Update last used timestamp for this IP and machine
      await db.run(
        'UPDATE allowed_ips SET lastUsed = datetime("now") WHERE apikey_id = ? AND ip = ? AND machine_identifier = ?',
        [keyData.id, clientIP, machineIdentifier]
      );
    }
    
    // Update usage statistics for the API key
    await db.run(
      'UPDATE apikeys SET usageCount = usageCount + 1, lastUsed = datetime("now") WHERE id = ?',
      [keyData.id]
    );
    
    // Get the updated allowed IPs and machines
    const allowedAccess = await db.all(
      'SELECT ip, machine_identifier FROM allowed_ips WHERE apikey_id = ?', 
      [keyData.id]
    );
    
    // Attach the key data to the request object
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

// Modify the verification route to show more details
app.get('/verify', verifyApiKeyFromURL, (req, res) => {
  res.json({ 
    valid: true,
    message: 'API key is valid',
    key: {
      name: req.apiKeyData.name,
      expiresAt: req.apiKeyData.expiresAt,
      usageCount: req.apiKeyData.usageCount,
      allowAutoRegister: req.apiKeyData.allowAutoRegister === 1,
      maxIpCount: req.apiKeyData.maxIpCount,
      maxMachineCount: req.apiKeyData.maxMachineCount
    },
    clientIP: getClientIp(req),
    machineIdentifier: generateMachineIdentifier(req),
    allowedAccess: req.apiKeyData.allowedAccess,
    ipRegistrationStrategy: req.apiKeyData.ipRegistrationStrategy
  });
});

// ... (rest of the code remains the same)

// Modify the admin route for creating API keys to include machine count
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

// ... (rest of the code remains the same)

module.exports = app;