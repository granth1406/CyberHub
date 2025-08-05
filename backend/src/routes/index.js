const express = require('express');
const router = express.Router();
const { scanUrl, scanFile, scanEmail, getScanHistory } = require('../controllers');

// Scanning routes
router.post('/scan/url', scanUrl);
router.post('/scan/file', scanFile);
router.post('/scan/email', scanEmail);
router.get('/scan/history', getScanHistory);

// Health check route
router.get('/', (req, res) => {
    res.json({ message: 'CyberGuard API running!' });
});

module.exports = router;
