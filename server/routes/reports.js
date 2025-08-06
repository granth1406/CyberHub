const express = require('express');
const router = express.Router();
const { auth, optionalAuth } = require('../middleware/auth');
const ScanResult = require('../models/ScanResult');

// Get public scan statistics
router.get('/stats', async (req, res) => {
  try {
    const stats = await ScanResult.aggregate([
      {
        $group: {
          _id: null,
          totalScans: { $sum: 1 },
          fileScans: {
            $sum: {
              $cond: [{ $eq: ['$scanType', 'file'] }, 1, 0]
            }
          },
          urlScans: {
            $sum: {
              $cond: [{ $eq: ['$scanType', 'url'] }, 1, 0]
            }
          },
          threatsDetected: {
            $sum: {
              $cond: [{ $gte: ['$threatScore', 40] }, 1, 0]
            }
          },
          avgThreatScore: { $avg: '$threatScore' },
          completedScans: {
            $sum: {
              $cond: [{ $eq: ['$scanStatus', 'completed'] }, 1, 0]
            }
          }
        }
      }
    ]);

    // Get threat level distribution
    const threatDistribution = await ScanResult.aggregate([
      {
        $group: {
          _id: '$riskLevel',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { _id: 1 }
      }
    ]);

    // Get recent scan trends (last 30 days)
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const recentTrends = await ScanResult.aggregate([
      {
        $match: {
          createdAt: { $gte: thirtyDaysAgo }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: {
              format: '%Y-%m-%d',
              date: '$createdAt'
            }
          },
          scans: { $sum: 1 },
          threats: {
            $sum: {
              $cond: [{ $gte: ['$threatScore', 40] }, 1, 0]
            }
          }
        }
      },
      {
        $sort: { _id: 1 }
      }
    ]);

    res.json({
      summary: stats[0] || {
        totalScans: 0,
        fileScans: 0,
        urlScans: 0,
        threatsDetected: 0,
        avgThreatScore: 0,
        completedScans: 0
      },
      threatDistribution,
      recentTrends
    });

  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get top threats (public endpoint)
router.get('/top-threats', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;

    const topThreats = await ScanResult.find({
      threatScore: { $gte: 40 },
      isPublic: true
    })
    .select('target.fileName target.url threatScore riskLevel createdAt')
    .sort({ threatScore: -1, createdAt: -1 })
    .limit(limit);

    res.json(topThreats);

  } catch (error) {
    console.error('Top threats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user's scan summary (authenticated)
router.get('/user-summary', auth, async (req, res) => {
  try {
    const userStats = await ScanResult.aggregate([
      {
        $match: { userId: req.user.id }
      },
      {
        $group: {
          _id: null,
          totalScans: { $sum: 1 },
          threatsFound: {
            $sum: {
              $cond: [{ $gte: ['$threatScore', 40] }, 1, 0]
            }
          },
          avgThreatScore: { $avg: '$threatScore' },
          fileScans: {
            $sum: {
              $cond: [{ $eq: ['$scanType', 'file'] }, 1, 0]
            }
          },
          urlScans: {
            $sum: {
              $cond: [{ $eq: ['$scanType', 'url'] }, 1, 0]
            }
          },
          lastScanDate: { $max: '$createdAt' }
        }
      }
    ]);

    // Get user's threat level distribution
    const userThreatDistribution = await ScanResult.aggregate([
      {
        $match: { userId: req.user.id }
      },
      {
        $group: {
          _id: '$riskLevel',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { _id: 1 }
      }
    ]);

    // Get user's recent activity
    const recentActivity = await ScanResult.find({ userId: req.user.id })
      .select('scanType target.fileName target.url threatScore riskLevel createdAt')
      .sort({ createdAt: -1 })
      .limit(10);

    res.json({
      summary: userStats[0] || {
        totalScans: 0,
        threatsFound: 0,
        avgThreatScore: 0,
        fileScans: 0,
        urlScans: 0,
        lastScanDate: null
      },
      threatDistribution: userThreatDistribution,
      recentActivity
    });

  } catch (error) {
    console.error('User summary error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Generate detailed report for a scan
router.get('/detailed/:scanId', optionalAuth, async (req, res) => {
  try {
    const scanResult = await ScanResult.findOne({ scanId: req.params.scanId });
    
    if (!scanResult) {
      return res.status(404).json({ error: 'Scan result not found' });
    }

    // Check access permissions
    if (scanResult.userId && req.user?.id !== scanResult.userId.toString() && !scanResult.isPublic) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Generate detailed analysis report
    const report = {
      scanInfo: {
        scanId: scanResult.scanId,
        scanType: scanResult.scanType,
        scanDate: scanResult.createdAt,
        scanDuration: scanResult.metadata.scanDuration,
        scanStatus: scanResult.scanStatus
      },
      target: scanResult.target,
      threatAssessment: {
        threatScore: scanResult.threatScore,
        riskLevel: scanResult.riskLevel,
        overallStatus: scanResult.threatScore >= 40 ? 'THREAT DETECTED' : 'CLEAN'
      },
      detailedAnalysis: scanResult.analysis,
      detections: scanResult.detections,
      recommendations: scanResult.recommendations,
      metadata: {
        apiVersions: scanResult.metadata.apiVersions,
        scanEngines: Object.keys(scanResult.analysis).length
      }
    };

    res.json(report);

  } catch (error) {
    console.error('Detailed report error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Export scan results (authenticated users only)
router.get('/export/:format', auth, async (req, res) => {
  try {
    const format = req.params.format.toLowerCase();
    
    if (!['json', 'csv'].includes(format)) {
      return res.status(400).json({ error: 'Unsupported export format. Use json or csv.' });
    }

    const scans = await ScanResult.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .limit(1000); // Limit to prevent memory issues

    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', 'attachment; filename="cyberhub-scans.json"');
      res.json(scans);
    } else if (format === 'csv') {
      // Convert to CSV format
      const csvHeaders = [
        'Scan ID',
        'Type',
        'Target',
        'Threat Score',
        'Risk Level',
        'Status',
        'Date'
      ];

      const csvRows = scans.map(scan => [
        scan.scanId,
        scan.scanType,
        scan.target.fileName || scan.target.url || scan.target.email || 'N/A',
        scan.threatScore,
        scan.riskLevel,
        scan.scanStatus,
        scan.createdAt.toISOString()
      ]);

      const csvContent = [
        csvHeaders.join(','),
        ...csvRows.map(row => row.map(cell => `"${cell}"`).join(','))
      ].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="cyberhub-scans.csv"');
      res.send(csvContent);
    }

  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({ error: 'Internal server error during export' });
  }
});

// Get trending threats (public)
router.get('/trending', async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const trending = await ScanResult.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate },
          threatScore: { $gte: 40 },
          isPublic: true
        }
      },
      {
        $group: {
          _id: '$scanType',
          count: { $sum: 1 },
          avgThreatScore: { $avg: '$threatScore' },
          maxThreatScore: { $max: '$threatScore' },
          examples: {
            $push: {
              target: '$target',
              threatScore: '$threatScore',
              date: '$createdAt'
            }
          }
        }
      },
      {
        $addFields: {
          examples: { $slice: ['$examples', 3] }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]);

    res.json({
      period: `${days} days`,
      trending
    });

  } catch (error) {
    console.error('Trending threats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get threat intelligence feed (public)
router.get('/threat-feed', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    
    const threatFeed = await ScanResult.find({
      threatScore: { $gte: 60 },
      isPublic: true,
      scanStatus: 'completed'
    })
    .select('scanType target.fileName target.url target.domain threatScore riskLevel analysis.virusTotal.positives analysis.safeBrowsing.threatType createdAt')
    .sort({ createdAt: -1 })
    .limit(limit);

    const feed = threatFeed.map(scan => ({
      id: scan._id,
      type: scan.scanType,
      target: scan.target.fileName || scan.target.url || scan.target.domain,
      threatScore: scan.threatScore,
      riskLevel: scan.riskLevel,
      detectionRatio: scan.analysis.virusTotal?.positives ? 
        `${scan.analysis.virusTotal.positives}/${scan.analysis.virusTotal.total}` : null,
      threatType: scan.analysis.safeBrowsing?.threatType || null,
      timestamp: scan.createdAt
    }));

    res.json({
      feed,
      count: feed.length,
      lastUpdated: new Date().toISOString()
    });

  } catch (error) {
    console.error('Threat feed error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
