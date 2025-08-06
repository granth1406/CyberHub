const mongoose = require('mongoose');

const scanResultSchema = new mongoose.Schema({
  scanId: {
    type: String,
    unique: true,
    required: true,
    default: () => require('crypto').randomUUID()
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false // Anonymous scans allowed
  },
  scanType: {
    type: String,
    enum: ['file', 'url', 'email', 'darkweb', 'bulk'],
    required: true
  },
  target: {
    fileName: String,
    fileSize: Number,
    fileType: String,
    fileMd5: String,
    fileSha1: String,
    fileSha256: String,
    url: String,
    email: String,
    domain: String
  },
  scanStatus: {
    type: String,
    enum: ['pending', 'scanning', 'completed', 'failed', 'timeout'],
    default: 'pending'
  },
  threatScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 0
  },
  riskLevel: {
    type: String,
    enum: ['safe', 'low', 'medium', 'high', 'critical'],
    default: 'safe'
  },
  detections: [{
    engine: String,
    result: String,
    version: String,
    update: Date
  }],
  analysis: {
    virusTotal: {
      scanId: String,
      positives: Number,
      total: Number,
      permalink: String,
      scannedDate: Date
    },
    safeBrowsing: {
      threatType: String,
      platformType: String,
      threatEntryType: String
    },
    whoisData: {
      domain: String,
      registrar: String,
      creationDate: Date,
      expirationDate: Date,
      nameServers: [String]
    },
  },
  metadata: {
    scanDuration: Number, // in milliseconds
    userAgent: String,
    ipAddress: String,
    apiVersions: {
      virusTotal: String,
      safeBrowsing: String,
      abuseIPDB: String
    }
  },
  recommendations: [{
    severity: {
      type: String,
      enum: ['info', 'warning', 'critical']
    },
    message: String,
    action: String
  }],
  isPublic: {
    type: Boolean,
    default: false
  },
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days from now
  }
}, {
  timestamps: true
});

// Index for efficient queries
scanResultSchema.index({ scanId: 1 });
scanResultSchema.index({ userId: 1, createdAt: -1 });
scanResultSchema.index({ scanType: 1 });
scanResultSchema.index({ threatScore: -1 });
scanResultSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Virtual for formatted threat level
scanResultSchema.virtual('threatLevel').get(function() {
  if (this.threatScore >= 80) return 'critical';
  if (this.threatScore >= 60) return 'high';
  if (this.threatScore >= 40) return 'medium';
  if (this.threatScore >= 20) return 'low';
  return 'safe';
});

// Method to calculate overall threat score
scanResultSchema.methods.calculateThreatScore = function() {
  let score = 0;
  
  // VirusTotal contribution (60% weight)
  if (this.analysis.virusTotal && this.analysis.virusTotal.total > 0) {
    const vtScore = (this.analysis.virusTotal.positives / this.analysis.virusTotal.total) * 100;
    score += vtScore * 0.6;
  }
  
  // Safe Browsing contribution (40% weight)
  if (this.analysis.safeBrowsing && this.analysis.safeBrowsing.threatType) {
    score += 40; // Any threat detected adds 40 points
  }
  
  this.threatScore = Math.min(Math.round(score), 100);
  return this.threatScore;
};

module.exports = mongoose.model('ScanResult', scanResultSchema);
