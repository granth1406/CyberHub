const axios = require('axios');

class SafeBrowsingService {
  constructor() {
    this.apiKey = process.env.GOOGLE_SAFEBROWSING_API_KEY;
    this.baseUrl = 'https://safebrowsing.googleapis.com/v4';
  }

  // Check URL against Google Safe Browsing database
  async checkURL(url) {
    if (!this.apiKey) {
      throw new Error('Google Safe Browsing API key not configured');
    }

    try {
      const requestBody = {
        client: {
          clientId: 'cyberhub',
          clientVersion: '1.0.0'
        },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION'
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [
            { url: url }
          ]
        }
      };

      const response = await axios.post(
        `${this.baseUrl}/threatMatches:find?key=${this.apiKey}`,
        requestBody
      );

      if (response.data.matches && response.data.matches.length > 0) {
        const match = response.data.matches[0];
        return {
          isThreat: true,
          threatType: match.threatType,
          platformType: match.platformType,
          threatEntryType: match.threatEntryType,
          cacheDuration: match.cacheDuration
        };
      }

      return {
        isThreat: false,
        threatType: null,
        platformType: null,
        threatEntryType: null
      };

    } catch (error) {
      console.error('Safe Browsing API error:', error);
      throw new Error(`Safe Browsing check failed: ${error.message}`);
    }
  }

  // Check multiple URLs
  async checkMultipleURLs(urls) {
    if (!this.apiKey) {
      throw new Error('Google Safe Browsing API key not configured');
    }

    try {
      const threatEntries = urls.map(url => ({ url }));
      
      const requestBody = {
        client: {
          clientId: 'cyberhub',
          clientVersion: '1.0.0'
        },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION'
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: threatEntries
        }
      };

      const response = await axios.post(
        `${this.baseUrl}/threatMatches:find?key=${this.apiKey}`,
        requestBody
      );

      const results = {};
      
      // Initialize all URLs as safe
      urls.forEach(url => {
        results[url] = {
          isThreat: false,
          threatType: null,
          platformType: null,
          threatEntryType: null
        };
      });

      // Update with threat information
      if (response.data.matches && response.data.matches.length > 0) {
        response.data.matches.forEach(match => {
          const threatUrl = match.threat.url;
          results[threatUrl] = {
            isThreat: true,
            threatType: match.threatType,
            platformType: match.platformType,
            threatEntryType: match.threatEntryType,
            cacheDuration: match.cacheDuration
          };
        });
      }

      return results;

    } catch (error) {
      console.error('Safe Browsing bulk check error:', error);
      throw new Error(`Safe Browsing bulk check failed: ${error.message}`);
    }
  }

  // Get threat list updates (for advanced implementations)
  async getThreatListUpdates() {
    if (!this.apiKey) {
      throw new Error('Google Safe Browsing API key not configured');
    }

    try {
      const requestBody = {
        client: {
          clientId: 'cyberhub',
          clientVersion: '1.0.0'
        },
        listUpdateRequests: [
          {
            threatType: 'MALWARE',
            platformType: 'ANY_PLATFORM',
            threatEntryType: 'URL',
            state: '',
            constraints: {
              maxUpdateEntries: 1000,
              maxDatabaseEntries: 10000
            }
          }
        ]
      };

      const response = await axios.post(
        `${this.baseUrl}/threatListUpdates:fetch?key=${this.apiKey}`,
        requestBody
      );

      return response.data;

    } catch (error) {
      console.error('Safe Browsing threat list update error:', error);
      throw new Error(`Threat list update failed: ${error.message}`);
    }
  }

  // Format threat type for display
  formatThreatType(threatType) {
    const threatTypes = {
      'MALWARE': 'Malware',
      'SOCIAL_ENGINEERING': 'Phishing/Social Engineering',
      'UNWANTED_SOFTWARE': 'Unwanted Software',
      'POTENTIALLY_HARMFUL_APPLICATION': 'Potentially Harmful Application'
    };

    return threatTypes[threatType] || threatType;
  }

  // Get risk score based on threat type
  getThreatScore(threatType) {
    const threatScores = {
      'MALWARE': 90,
      'SOCIAL_ENGINEERING': 85,
      'UNWANTED_SOFTWARE': 60,
      'POTENTIALLY_HARMFUL_APPLICATION': 70
    };

    return threatScores[threatType] || 0;
  }
}

module.exports = new SafeBrowsingService();
