// server.js - API Key Management Server
const express = require('express');
const morgan = require('morgan');
const mongoose = require('mongoose');
const crypto = require('crypto');
const dotenv = require('dotenv');
const path = require('path');
const cors = require('cors');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
app.use(express.json());
app.use(morgan('dev'));
app.use(cors());

// Serve static files from the public directory
app.use(express.static('public'));

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/apikeymanager')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define the API key schema
const apiKeySchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  allowedIPs: [{ type: String }],
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date },
  isActive: { type: Boolean, default: true },
  usageCount: { type: Number, default: 0 },
  lastUsed: { type: Date }
});

// Create the model
const ApiKey = mongoose.model('ApiKey', apiKeySchema);

// Middleware to verify API key and IP
const verifyApiKey = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  const clientIP = req.ip || req.connection.remoteAddress;
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API key is required' });
  }

  try {
    const keyData = await ApiKey.findOne({ key: apiKey });
    
    if (!keyData) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    
    if (!keyData.isActive) {
      return res.status(403).json({ error: 'API key is inactive' });
    }
    
    if (keyData.expiresAt && keyData.expiresAt < new Date()) {
      return res.status(403).json({ error: 'API key has expired' });
    }
    
    // Check if the client IP is allowed
    if (keyData.allowedIPs && keyData.allowedIPs.length > 0) {
      if (!keyData.allowedIPs.includes(clientIP)) {
        return res.status(403).json({ error: 'IP not authorized for this API key' });
      }
    }
    
    // Update usage statistics
    keyData.usageCount += 1;
    keyData.lastUsed = new Date();
    await keyData.save();
    
    // Attach the key data to the request object
    req.apiKeyData = keyData;
    next();
  } catch (error) {
    console.error('API key verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Generate a new API key
function generateApiKey() {
  return crypto.randomBytes(24).toString('hex');
}

// Admin routes for managing API keys
const adminRouter = express.Router();

// Admin authentication middleware (simplified - should use proper auth in production)
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
    const { name, allowedIPs, expiresAt } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    
    const newKey = new ApiKey({
      key: generateApiKey(),
      name,
      allowedIPs: allowedIPs || [],
      expiresAt: expiresAt ? new Date(expiresAt) : null
    });
    
    await newKey.save();
    res.status(201).json(newKey);
  } catch (error) {
    console.error('Error creating API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all API keys
adminRouter.get('/keys', async (req, res) => {
  try {
    const keys = await ApiKey.find({});
    res.json(keys);
  } catch (error) {
    console.error('Error fetching API keys:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get a single API key
adminRouter.get('/keys/:id', async (req, res) => {
  try {
    const key = await ApiKey.findById(req.params.id);
    if (!key) {
      return res.status(404).json({ error: 'API key not found' });
    }
    res.json(key);
  } catch (error) {
    console.error('Error fetching API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update an API key
adminRouter.put('/keys/:id', async (req, res) => {
  try {
    const { name, allowedIPs, isActive, expiresAt } = req.body;
    const updatedKey = await ApiKey.findByIdAndUpdate(
      req.params.id,
      { name, allowedIPs, isActive, expiresAt: expiresAt ? new Date(expiresAt) : null },
      { new: true }
    );
    
    if (!updatedKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    res.json(updatedKey);
  } catch (error) {
    console.error('Error updating API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete an API key
adminRouter.delete('/keys/:id', async (req, res) => {
  try {
    const deletedKey = await ApiKey.findByIdAndDelete(req.params.id);
    if (!deletedKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
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
    
    if (!ip) {
      return res.status(400).json({ error: 'IP address is required' });
    }
    
    const key = await ApiKey.findById(req.params.id);
    
    if (!key) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    if (!key.allowedIPs.includes(ip)) {
      key.allowedIPs.push(ip);
      await key.save();
    }
    
    res.json(key);
  } catch (error) {
    console.error('Error registering IP:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Remove IP from an API key
adminRouter.delete('/keys/:id/ip/:ip', async (req, res) => {
  try {
    const key = await ApiKey.findById(req.params.id);
    
    if (!key) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    const ipIndex = key.allowedIPs.indexOf(req.params.ip);
    
    if (ipIndex === -1) {
      return res.status(404).json({ error: 'IP not found for this API key' });
    }
    
    key.allowedIPs.splice(ipIndex, 1);
    await key.save();
    
    res.json(key);
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
    clientIP: req.ip || req.connection.remoteAddress
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