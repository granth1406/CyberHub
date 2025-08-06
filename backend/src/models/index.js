const mongoose = require('mongoose');

const scanResultSchema = new mongoose.Schema({
    type: {
        type: String,
        enum: ['file', 'url', 'email'],
        required: true
    },
    content: {
        type: String,
        required: true
    },
    safetyScore: {
        type: Number,
        required: true
    },
    threats: [{
        type: String,
        description: String,
        severity: {
            type: String,
            enum: ['low', 'medium', 'high', 'critical']
        }
    }],
    scanDate: {
        type: Date,
        default: Date.now
    },
    metadata: {
        type: Map,
        of: String
    }
});

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },
    scans: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'ScanResult'
    }],
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const ScanResult = mongoose.model('ScanResult', scanResultSchema);
const User = mongoose.model('User', userSchema);

module.exports = {
    ScanResult,
    User
};
