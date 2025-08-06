const express = require('express');
const multer = require('multer');
const { body, validationResult } = require('express-validator');
const router = express.Router();

// Import services
const virusTotalService = require('../services/virusTotal');
const safeBrowsingService = require('../services/safeBrowsing');
const whoisService = require('../services/whois');

// Import models
const ScanResult = require('../models/ScanResult');

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = process.env.UPLOAD_DIR || 'uploads/';
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    const extension = file.originalname.split('.').pop();
    cb(null, `scan_${timestamp}.${extension}`);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024 // 10MB default
  },
  fileFilter: (req, file, cb) => {
    // Allow most file types for security analysis
    const allowedTypes = /\.(exe|dll|pdf|docx|doc|xlsx|xls|zip|rar|7z|tar|gz|js|html|php|py|bat|cmd|ps1|vbs|jar|apk|ipa)$/i;
    const isAllowed = allowedTypes.test(file.originalname) || file.mimetype.startsWith('application/') || file.mimetype.startsWith('text/');
    
    if (isAllowed) {
      cb(null, true);
    } else {
      cb(new Error('File type not supported for security scanning'), false);
    }
  }
});

// File scanning endpoint
router.post('/file', upload.single('file'), [
  body('scanOptions.deepScan').optional().isBoolean(),
  body('scanOptions.heuristicAnalysis').optional().isBoolean()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const scanOptions = req.body.scanOptions || {};
    const startTime = Date.now();

    // Create initial scan result
    const scanResult = new ScanResult({
      scanType: 'file',
      userId: req.user?.id || null,
      target: {
        fileName: req.file.originalname,
        fileSize: req.file.size,
        fileType: req.file.mimetype
      },
      scanStatus: 'scanning',
      metadata: {
        userAgent: req.get('User-Agent'),
        ipAddress: req.ip
      }
    });

    await scanResult.save();

    // Perform parallel scans
    const scanPromises = [];

    // VirusTotal scan
    if (process.env.VIRUSTOTAL_API_KEY) {
      scanPromises.push(
        virusTotalService.scanFile(req.file.path)
          .then(result => ({ virusTotal: result }))
          .catch(error => ({ virusTotal: { error: error.message } }))
      );
    }


    // Wait for all scans to complete
    const results = await Promise.allSettled(scanPromises);
    
    // Combine results
    const analysis = {};
    results.forEach(result => {
      if (result.status === 'fulfilled') {
        Object.assign(analysis, result.value);
      }
    });

    // Update scan result
    scanResult.analysis = analysis;
    scanResult.scanStatus = 'completed';
    scanResult.metadata.scanDuration = Date.now() - startTime;
    
    // Calculate threat score
    scanResult.calculateThreatScore();
    
    // Generate recommendations
    scanResult.recommendations = generateRecommendations(scanResult);
    
    await scanResult.save();

    // Clean up uploaded file
    try {
      require('fs').unlinkSync(req.file.path);
    } catch (error) {
      console.warn('Failed to delete uploaded file:', error);
    }

    res.json({
      scanId: scanResult.scanId,
      status: scanResult.scanStatus,
      threatScore: scanResult.threatScore,
      riskLevel: scanResult.threatLevel,
      analysis: scanResult.analysis,
      recommendations: scanResult.recommendations,
      scanDuration: scanResult.metadata.scanDuration
    });

  } catch (error) {
    console.error('File scan error:', error);
    res.status(500).json({ error: 'Internal server error during file scan' });
  }
});

// URL scanning endpoint
router.post('/url', [
  body('url').isURL().withMessage('Please provide a valid URL'),
  body('scanOptions.deepScan').optional().isBoolean(),
  body('scanOptions.checkSubdomains').optional().isBoolean()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { url, scanOptions = {} } = req.body;
    const startTime = Date.now();

    // Create initial scan result
    const scanResult = new ScanResult({
      scanType: 'url',
      userId: req.user?.id || null,
      target: { url },
      scanStatus: 'scanning',
      metadata: {
        userAgent: req.get('User-Agent'),
        ipAddress: req.ip
      }
    });

    await scanResult.save();

    // Perform parallel scans
    const scanPromises = [];

    // VirusTotal URL scan
    if (process.env.VIRUSTOTAL_API_KEY) {
      scanPromises.push(
        virusTotalService.scanURL(url)
          .then(result => ({ virusTotal: result }))
          .catch(error => ({ virusTotal: { error: error.message } }))
      );
    }

    // Google Safe Browsing
    if (process.env.GOOGLE_SAFEBROWSING_API_KEY) {
      scanPromises.push(
        safeBrowsingService.checkURL(url)
          .then(result => ({ safeBrowsing: result }))
          .catch(error => ({ safeBrowsing: { error: error.message } }))
      );
    }

    // WHOIS lookup for domain information
    const domain = new URL(url).hostname;
    scanPromises.push(
      whoisService.lookupDomain(domain)
        .then(result => ({ whoisData: result }))
        .catch(error => ({ whoisData: { error: error.message } }))
    );


    // Wait for all scans to complete
    const results = await Promise.allSettled(scanPromises);
    
    // Combine results
    const analysis = {};
    results.forEach(result => {
      if (result.status === 'fulfilled') {
        Object.assign(analysis, result.value);
      }
    });

    // Update scan result
    scanResult.analysis = analysis;
    scanResult.scanStatus = 'completed';
    scanResult.metadata.scanDuration = Date.now() - startTime;
    scanResult.target.domain = domain;
    
    // Calculate threat score
    scanResult.calculateThreatScore();
    
    // Generate recommendations
    scanResult.recommendations = generateRecommendations(scanResult);
    
    await scanResult.save();

    res.json({
      scanId: scanResult.scanId,
      status: scanResult.scanStatus,
      threatScore: scanResult.threatScore,
      riskLevel: scanResult.threatLevel,
      analysis: scanResult.analysis,
      recommendations: scanResult.recommendations,
      scanDuration: scanResult.metadata.scanDuration
    });

  } catch (error) {
    console.error('URL scan error:', error);
    res.status(500).json({ error: 'Internal server error during URL scan' });
  }
});

// Bulk scanning endpoint
router.post('/bulk', upload.array('files', 10), [
  body('urls').optional().isArray(),
  body('urls.*').optional().isURL()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const files = req.files || [];
    const urls = req.body.urls || [];
    
    if (files.length === 0 && urls.length === 0) {
      return res.status(400).json({ error: 'No files or URLs provided for scanning' });
    }

    const scanResults = [];
    const scanPromises = [];

    // Process files
    files.forEach(file => {
      const promise = processFileScan(file, req.user?.id, req.get('User-Agent'), req.ip);
      scanPromises.push(promise);
    });

    // Process URLs
    urls.forEach(url => {
      const promise = processURLScan(url, req.user?.id, req.get('User-Agent'), req.ip);
      scanPromises.push(promise);
    });

    // Wait for all scans to complete
    const results = await Promise.allSettled(scanPromises);
    
    results.forEach(result => {
      if (result.status === 'fulfilled') {
        scanResults.push(result.value);
      } else {
        scanResults.push({ error: result.reason.message });
      }
    });

    // Clean up uploaded files
    files.forEach(file => {
      try {
        require('fs').unlinkSync(file.path);
      } catch (error) {
        console.warn('Failed to delete uploaded file:', error);
      }
    });

    res.json({
      totalScans: scanResults.length,
      completedScans: scanResults.filter(r => !r.error).length,
      failedScans: scanResults.filter(r => r.error).length,
      results: scanResults
    });

  } catch (error) {
    console.error('Bulk scan error:', error);
    res.status(500).json({ error: 'Internal server error during bulk scan' });
  }
});

// Get scan result by ID
router.get('/result/:scanId', async (req, res) => {
  try {
    const scanResult = await ScanResult.findOne({ scanId: req.params.scanId });
    
    if (!scanResult) {
      return res.status(404).json({ error: 'Scan result not found' });
    }

    // Check if user has access to this scan
    if (scanResult.userId && req.user?.id !== scanResult.userId.toString() && !scanResult.isPublic) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(scanResult);

  } catch (error) {
    console.error('Error fetching scan result:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Helper functions
async function processFileScan(file, userId, userAgent, ipAddress) {
  const startTime = Date.now();
  
  try {
    // Create initial scan result
    const scanResult = new ScanResult({
      scanType: 'file',
      userId: userId || null,
      target: {
        fileName: file.originalname,
        fileSize: file.size,
        fileType: file.mimetype
      },
      scanStatus: 'scanning',
      metadata: {
        userAgent: userAgent,
        ipAddress: ipAddress
      }
    });

    await scanResult.save();

    // Perform parallel scans
    const scanPromises = [];

    // VirusTotal scan
    if (process.env.VIRUSTOTAL_API_KEY) {
      scanPromises.push(
        virusTotalService.scanFile(file.path)
          .then(result => ({ virusTotal: result }))
          .catch(error => ({ virusTotal: { error: error.message } }))
      );
    }


    // Wait for all scans to complete
    const results = await Promise.allSettled(scanPromises);
    
    // Combine results
    const analysis = {};
    results.forEach(result => {
      if (result.status === 'fulfilled') {
        Object.assign(analysis, result.value);
      }
    });

    // Update scan result
    scanResult.analysis = analysis;
    scanResult.scanStatus = 'completed';
    scanResult.metadata.scanDuration = Date.now() - startTime;
    
    // Calculate threat score
    scanResult.calculateThreatScore();
    
    // Generate recommendations
    scanResult.recommendations = generateRecommendations(scanResult);
    
    await scanResult.save();

    return {
      scanId: scanResult.scanId,
      status: scanResult.scanStatus,
      threatScore: scanResult.threatScore,
      riskLevel: scanResult.threatLevel,
      analysis: scanResult.analysis,
      recommendations: scanResult.recommendations,
      scanDuration: scanResult.metadata.scanDuration
    };
  } catch (error) {
    console.error('Process file scan error:', error);
    throw error;
  }
}

async function processURLScan(url, userId, userAgent, ipAddress) {
  const startTime = Date.now();
  
  try {
    // Create initial scan result
    const scanResult = new ScanResult({
      scanType: 'url',
      userId: userId || null,
      target: { url },
      scanStatus: 'scanning',
      metadata: {
        userAgent: userAgent,
        ipAddress: ipAddress
      }
    });

    await scanResult.save();

    // Perform parallel scans
    const scanPromises = [];

    // VirusTotal URL scan
    if (process.env.VIRUSTOTAL_API_KEY) {
      scanPromises.push(
        virusTotalService.scanURL(url)
          .then(result => ({ virusTotal: result }))
          .catch(error => ({ virusTotal: { error: error.message } }))
      );
    }

    // Google Safe Browsing
    if (process.env.GOOGLE_SAFEBROWSING_API_KEY) {
      scanPromises.push(
        safeBrowsingService.checkURL(url)
          .then(result => ({ safeBrowsing: result }))
          .catch(error => ({ safeBrowsing: { error: error.message } }))
      );
    }

    // WHOIS lookup for domain information
    const domain = new URL(url).hostname;
    scanPromises.push(
      whoisService.lookupDomain(domain)
        .then(result => ({ whoisData: result }))
        .catch(error => ({ whoisData: { error: error.message } }))
    );


    // Wait for all scans to complete
    const results = await Promise.allSettled(scanPromises);
    
    // Combine results
    const analysis = {};
    results.forEach(result => {
      if (result.status === 'fulfilled') {
        Object.assign(analysis, result.value);
      }
    });

    // Update scan result
    scanResult.analysis = analysis;
    scanResult.scanStatus = 'completed';
    scanResult.metadata.scanDuration = Date.now() - startTime;
    scanResult.target.domain = domain;
    
    // Calculate threat score
    scanResult.calculateThreatScore();
    
    // Generate recommendations
    scanResult.recommendations = generateRecommendations(scanResult);
    
    await scanResult.save();

    return {
      scanId: scanResult.scanId,
      status: scanResult.scanStatus,
      threatScore: scanResult.threatScore,
      riskLevel: scanResult.threatLevel,
      analysis: scanResult.analysis,
      recommendations: scanResult.recommendations,
      scanDuration: scanResult.metadata.scanDuration
    };
  } catch (error) {
    console.error('Process URL scan error:', error);
    throw error;
  }
}

function generateRecommendations(scanResult) {
  const recommendations = [];
  
  if (scanResult.threatScore >= 80) {
    recommendations.push({
      severity: 'critical',
      message: 'High threat detected! Do not open or execute this file/visit this URL.',
      action: 'Delete file or avoid URL immediately'
    });
  } else if (scanResult.threatScore >= 40) {
    recommendations.push({
      severity: 'warning',
      message: 'Potential threat detected. Exercise caution.',
      action: 'Scan with additional tools or avoid if possible'
    });
  } else {
    recommendations.push({
      severity: 'info',
      message: 'No significant threats detected.',
      action: 'File/URL appears safe to use'
    });
  }

  return recommendations;
}

module.exports = router;
