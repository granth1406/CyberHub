const axios = require('axios');
const fs = require('fs');
const crypto = require('crypto');
const FormData = require('form-data');

class VirusTotalService {
  constructor() {
    this.apiKey = process.env.VIRUSTOTAL_API_KEY;
    this.baseUrl = 'https://www.virustotal.com/vtapi/v2';
    this.v3BaseUrl = 'https://www.virustotal.com/api/v3';
  }

  // Calculate file hashes
  async calculateFileHashes(filePath) {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const stream = fs.createReadStream(filePath);
      
      stream.on('data', data => hash.update(data));
      stream.on('end', () => {
        const sha256 = hash.digest('hex');
        
        // Calculate MD5 and SHA1 as well
        const md5Hash = crypto.createHash('md5');
        const sha1Hash = crypto.createHash('sha1');
        const fileBuffer = fs.readFileSync(filePath);
        
        md5Hash.update(fileBuffer);
        sha1Hash.update(fileBuffer);
        
        resolve({
          md5: md5Hash.digest('hex'),
          sha1: sha1Hash.digest('hex'),
          sha256: sha256
        });
      });
      stream.on('error', reject);
    });
  }

  // Scan file using VirusTotal
  async scanFile(filePath) {
    if (!this.apiKey) {
      throw new Error('VirusTotal API key not configured');
    }

    try {
      // First, calculate file hashes
      const hashes = await this.calculateFileHashes(filePath);
      
      // Check if file was already scanned using hash
      const existingResult = await this.getFileReport(hashes.sha256);
      if (existingResult && existingResult.response_code === 1) {
        return {
          scanId: existingResult.scan_id,
          positives: existingResult.positives,
          total: existingResult.total,
          permalink: existingResult.permalink,
          scannedDate: new Date(existingResult.scan_date),
          detections: this.formatDetections(existingResult.scans),
          hashes: hashes
        };
      }

      // Upload file for scanning
      const formData = new FormData();
      formData.append('apikey', this.apiKey);
      formData.append('file', fs.createReadStream(filePath));

      const uploadResponse = await axios.post(`${this.baseUrl}/file/scan`, formData, {
        headers: formData.getHeaders(),
        timeout: 60000 // 1 minute timeout
      });

      if (uploadResponse.data.response_code !== 1) {
        throw new Error('Failed to upload file to VirusTotal');
      }

      // Wait a bit for scan to process
      await this.delay(5000);

      // Get scan results
      const scanResult = await this.getFileReport(uploadResponse.data.resource);
      
      return {
        scanId: uploadResponse.data.scan_id,
        resource: uploadResponse.data.resource,
        positives: scanResult.positives || 0,
        total: scanResult.total || 0,
        permalink: scanResult.permalink,
        scannedDate: scanResult.scan_date ? new Date(scanResult.scan_date) : new Date(),
        detections: scanResult.scans ? this.formatDetections(scanResult.scans) : [],
        hashes: hashes
      };

    } catch (error) {
      console.error('VirusTotal file scan error:', error);
      throw new Error(`VirusTotal scan failed: ${error.message}`);
    }
  }

  // Get file report by hash or resource
  async getFileReport(resource) {
    if (!this.apiKey) {
      throw new Error('VirusTotal API key not configured');
    }

    try {
      const response = await axios.post(`${this.baseUrl}/file/report`, {
        apikey: this.apiKey,
        resource: resource
      });

      return response.data;

    } catch (error) {
      console.error('VirusTotal report error:', error);
      return null;
    }
  }

  // Scan URL using VirusTotal
  async scanURL(url) {
    if (!this.apiKey) {
      throw new Error('VirusTotal API key not configured');
    }

    try {
      // First, check if URL was already scanned
      const existingResult = await this.getURLReport(url);
      if (existingResult && existingResult.response_code === 1) {
        return {
          scanId: existingResult.scan_id,
          positives: existingResult.positives,
          total: existingResult.total,
          permalink: existingResult.permalink,
          scannedDate: new Date(existingResult.scan_date),
          detections: this.formatDetections(existingResult.scans)
        };
      }

      // Submit URL for scanning
      const scanResponse = await axios.post(`${this.baseUrl}/url/scan`, {
        apikey: this.apiKey,
        url: url
      });

      if (scanResponse.data.response_code !== 1) {
        throw new Error('Failed to submit URL to VirusTotal');
      }

      // Wait for scan to process
      await this.delay(10000);

      // Get scan results
      const scanResult = await this.getURLReport(url);
      
      return {
        scanId: scanResponse.data.scan_id,
        resource: scanResponse.data.resource,
        positives: scanResult.positives || 0,
        total: scanResult.total || 0,
        permalink: scanResult.permalink,
        scannedDate: scanResult.scan_date ? new Date(scanResult.scan_date) : new Date(),
        detections: scanResult.scans ? this.formatDetections(scanResult.scans) : []
      };

    } catch (error) {
      console.error('VirusTotal URL scan error:', error);
      throw new Error(`VirusTotal URL scan failed: ${error.message}`);
    }
  }

  // Get URL report
  async getURLReport(url) {
    if (!this.apiKey) {
      throw new Error('VirusTotal API key not configured');
    }

    try {
      const response = await axios.post(`${this.baseUrl}/url/report`, {
        apikey: this.apiKey,
        resource: url
      });

      return response.data;

    } catch (error) {
      console.error('VirusTotal URL report error:', error);
      return null;
    }
  }

  // Format detection results
  formatDetections(scans) {
    if (!scans) return [];

    return Object.entries(scans).map(([engine, result]) => ({
      engine: engine,
      result: result.result || 'Clean',
      version: result.version,
      update: result.update ? new Date(result.update) : null
    }));
  }

  // Utility function to add delay
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Get API quota information
  async getQuotaInfo() {
    if (!this.apiKey) {
      throw new Error('VirusTotal API key not configured');
    }

    try {
      const response = await axios.get(`${this.v3BaseUrl}/users/${this.apiKey}`, {
        headers: {
          'x-apikey': this.apiKey
        }
      });

      return {
        quotas: response.data.data.attributes.quotas
      };

    } catch (error) {
      console.error('VirusTotal quota check error:', error);
      return null;
    }
  }
}

module.exports = new VirusTotalService();
