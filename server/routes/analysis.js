const express = require('express');
const router = express.Router();
const { auth, optionalAuth } = require('../middleware/auth');

// Import services
const whoisService = require('../services/whois');

// Quick URL analysis (no full scan)
router.post('/quick-url', async (req, res) => {
  try {
    const { url } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    // Validate URL format
    try {
      new URL(url);
    } catch (error) {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    const startTime = Date.now();

    // Perform quick analysis
    const whoisResult = await Promise.allSettled([
      whoisService.lookupDomain(new URL(url).hostname)
    ]);

    const analysis = {
      url: url,
      whois: whoisResult[0].status === 'fulfilled' ? whoisResult[0].value : { error: whoisResult[0].reason?.message || 'WHOIS lookup failed' },
      analysisTime: Date.now() - startTime
    };

    // Calculate quick risk score
    let riskScore = 0;

    if (analysis.whois && !analysis.whois.error) {
      const domainAnalysis = whoisService.analyzeDomainRisk(analysis.whois);
      riskScore = (100 - domainAnalysis.trustScore) * 0.5;
    }

    riskScore = Math.min(Math.round(riskScore), 100);

    res.json({
      ...analysis,
      riskScore,
      riskLevel: riskScore >= 80 ? 'critical' : riskScore >= 60 ? 'high' : riskScore >= 40 ? 'medium' : riskScore >= 20 ? 'low' : 'safe'
    });

  } catch (error) {
    console.error('Quick URL analysis error:', error);
    res.status(500).json({ error: 'Internal server error during analysis' });
  }
});

// Domain reputation check
router.get('/domain-reputation/:domain', async (req, res) => {
  try {
    const domain = req.params.domain;
    
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    const startTime = Date.now();

    // Perform domain reputation analysis
    const whoisResult = await Promise.allSettled([
      whoisService.lookupDomain(domain)
    ]);

    const analysis = {
      domain: domain,
      whois: whoisResult[0].status === 'fulfilled' ? whoisResult[0].value : { error: whoisResult[0].reason?.message || 'WHOIS lookup failed' },
      analysisTime: Date.now() - startTime
    };

    // Calculate reputation score
    let reputationScore = 100; // Start with perfect score
    
    if (analysis.whois && !analysis.whois.error) {
      const domainRisk = whoisService.analyzeDomainRisk(analysis.whois);
      reputationScore = domainRisk.trustScore;
      analysis.domainAge = domainRisk.ageInDays;
      analysis.riskFactors = domainRisk.riskFactors;
    }

    reputationScore = Math.max(0, Math.min(100, Math.round(reputationScore)));

    res.json({
      ...analysis,
      reputationScore,
      reputation: reputationScore >= 80 ? 'excellent' : reputationScore >= 60 ? 'good' : reputationScore >= 40 ? 'fair' : reputationScore >= 20 ? 'poor' : 'very poor'
    });

  } catch (error) {
    console.error('Domain reputation error:', error);
    res.status(500).json({ error: 'Internal server error during reputation check' });
  }
});

// Email analysis
router.post('/email', async (req, res) => {
  try {
    const { email, headers, content } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const startTime = Date.now();
    const analysis = {
      email: email,
      riskFactors: [],
      suspiciousPatterns: [],
      analysisTime: 0
    };

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      analysis.riskFactors.push('Invalid email format');
    }

    // Domain extraction and analysis
    const domain = email.split('@')[1];
    if (domain) {
      try {
        const domainInfo = await whoisService.lookupDomain(domain);
        analysis.domainInfo = domainInfo;
        
        const domainRisk = whoisService.analyzeDomainRisk(domainInfo);
        analysis.riskFactors.push(...domainRisk.riskFactors);
        analysis.domainTrustScore = domainRisk.trustScore;
      } catch (error) {
        analysis.domainInfo = { error: error.message };
      }
    }

    // Header analysis (if provided)
    if (headers) {
      const headerAnalysis = analyzeEmailHeaders(headers);
      analysis.headerAnalysis = headerAnalysis;
      analysis.riskFactors.push(...headerAnalysis.riskFactors);
      analysis.suspiciousPatterns.push(...headerAnalysis.suspiciousPatterns);
    }

    // Content analysis (if provided)
    if (content) {
      const contentAnalysis = analyzeEmailContent(content);
      analysis.contentAnalysis = contentAnalysis;
      analysis.riskFactors.push(...contentAnalysis.riskFactors);
      analysis.suspiciousPatterns.push(...contentAnalysis.suspiciousPatterns);
    }

    // Calculate risk score
    let riskScore = 0;
    riskScore += analysis.riskFactors.length * 15;
    riskScore += analysis.suspiciousPatterns.length * 10;
    
    if (analysis.domainTrustScore) {
      riskScore += (100 - analysis.domainTrustScore) * 0.5;
    }

    riskScore = Math.min(Math.round(riskScore), 100);
    analysis.analysisTime = Date.now() - startTime;

    res.json({
      ...analysis,
      riskScore,
      riskLevel: riskScore >= 80 ? 'critical' : riskScore >= 60 ? 'high' : riskScore >= 40 ? 'medium' : riskScore >= 20 ? 'low' : 'safe'
    });

  } catch (error) {
    console.error('Email analysis error:', error);
    res.status(500).json({ error: 'Internal server error during email analysis' });
  }
});

// IP address analysis
router.get('/ip/:ip', async (req, res) => {
  try {
    const ip = req.params.ip;
    
    if (!ip) {
      return res.status(400).json({ error: 'IP address is required' });
    }

    // Validate IP format
    const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (!ipRegex.test(ip)) {
      return res.status(400).json({ error: 'Invalid IP address format' });
    }

    const startTime = Date.now();

    // Basic IP analysis
    let analysis = {
      ip: ip,
      location: analyzeIPLocation(ip),
      type: analyzeIPType(ip),
      analysisTime: 0
    };

    // Calculate risk score
    let riskScore = 0;

    if (analysis.type && analysis.type.isPrivate) {
      riskScore = 0; // Private IPs are generally safe
    } else {
      // For public IPs, we can't determine risk without external services
      riskScore = 20; // Default low risk for public IPs
    }

    analysis.analysisTime = Date.now() - startTime;

    res.json({
      ...analysis,
      riskScore,
      riskLevel: riskScore >= 80 ? 'critical' : riskScore >= 60 ? 'high' : riskScore >= 40 ? 'medium' : riskScore >= 20 ? 'low' : 'safe'
    });

  } catch (error) {
    console.error('IP analysis error:', error);
    res.status(500).json({ error: 'Internal server error during IP analysis' });
  }
});

// Helper functions for email analysis
function analyzeEmailHeaders(headers) {
  const analysis = {
    riskFactors: [],
    suspiciousPatterns: []
  };

  const headersString = typeof headers === 'string' ? headers : JSON.stringify(headers);

  // Check for suspicious patterns in headers
  if (headersString.includes('X-Mailer: ')) {
    const mailerMatch = headersString.match(/X-Mailer:\s*([^\n]+)/i);
    if (mailerMatch && mailerMatch[1]) {
      const mailer = mailerMatch[1].toLowerCase();
      if (mailer.includes('mass') || mailer.includes('bulk') || mailer.includes('spam')) {
        analysis.riskFactors.push('Suspicious mail client detected');
        analysis.suspiciousPatterns.push('suspicious_mailer');
      }
    }
  }

  // Check for multiple received headers (possible forwarding)
  const receivedCount = (headersString.match(/Received:/gi) || []).length;
  if (receivedCount > 5) {
    analysis.riskFactors.push('Multiple mail forwarding detected');
    analysis.suspiciousPatterns.push('multiple_forwarding');
  }

  // Check for missing standard headers
  if (!headersString.includes('Message-ID:')) {
    analysis.riskFactors.push('Missing Message-ID header');
    analysis.suspiciousPatterns.push('missing_message_id');
  }

  return analysis;
}

function analyzeEmailContent(content) {
  const analysis = {
    riskFactors: [],
    suspiciousPatterns: []
  };

  const contentLower = content.toLowerCase();

  // Check for phishing keywords
  const phishingKeywords = [
    'urgent', 'immediate action', 'verify account', 'suspend',
    'click here now', 'limited time', 'act now', 'confirm identity',
    'security alert', 'unusual activity'
  ];

  phishingKeywords.forEach(keyword => {
    if (contentLower.includes(keyword)) {
      analysis.riskFactors.push(`Contains phishing keyword: ${keyword}`);
      analysis.suspiciousPatterns.push('phishing_keyword');
    }
  });

  // Check for suspicious URLs
  const urlRegex = /https?:\/\/[^\s]+/gi;
  const urls = content.match(urlRegex) || [];
  
  urls.forEach(url => {
    try {
      const urlObj = new URL(url);
      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlObj.hostname)) {
        analysis.riskFactors.push('Contains IP-based URL');
        analysis.suspiciousPatterns.push('ip_url');
      }
      
      if (url.length > 100) {
        analysis.riskFactors.push('Contains unusually long URL');
        analysis.suspiciousPatterns.push('long_url');
      }
    } catch (error) {
      // Invalid URL
      analysis.riskFactors.push('Contains malformed URL');
      analysis.suspiciousPatterns.push('malformed_url');
    }
  });

  return analysis;
}

function analyzeIPLocation(ip) {
  // This is a simplified implementation
  // In a real application, you'd use a GeoIP database
  const parts = ip.split('.').map(Number);
  
  if (parts[0] === 127) return { region: 'localhost', country: 'local' };
  if (parts[0] === 10) return { region: 'private', country: 'local' };
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return { region: 'private', country: 'local' };
  if (parts[0] === 192 && parts[1] === 168) return { region: 'private', country: 'local' };
  
  return { region: 'unknown', country: 'unknown' };
}

function analyzeIPType(ip) {
  const parts = ip.split('.').map(Number);
  
  return {
    isPrivate: (
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      parts[0] === 127
    ),
    isLocal: parts[0] === 127,
    class: parts[0] <= 127 ? 'A' : parts[0] <= 191 ? 'B' : 'C'
  };
}

module.exports = router;
