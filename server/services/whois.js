const whois = require('whois');

class WhoisService {
  constructor() {
    this.timeout = 10000; // 10 seconds timeout
  }

  // Lookup domain information using WHOIS
  async lookupDomain(domain) {
    return new Promise((resolve, reject) => {
      const options = {
        timeout: this.timeout
      };

      whois.lookup(domain, options, (err, data) => {
        if (err) {
          console.error('WHOIS lookup error:', err);
          reject(new Error(`WHOIS lookup failed: ${err.message}`));
          return;
        }

        try {
          const parsed = this.parseWhoisData(data);
          resolve(parsed);
        } catch (parseError) {
          console.error('WHOIS parse error:', parseError);
          resolve({
            domain: domain,
            rawData: data,
            parsed: false,
            error: 'Failed to parse WHOIS data'
          });
        }
      });
    });
  }

  // Parse WHOIS data into structured format
  parseWhoisData(data) {
    const result = {
      domain: null,
      registrar: null,
      registrationDate: null,
      expirationDate: null,
      updatedDate: null,
      nameServers: [],
      status: [],
      registrantCountry: null,
      dnssec: null,
      rawData: data,
      parsed: true
    };

    const lines = data.split('\n');
    
    for (const line of lines) {
      const trimmedLine = line.trim();
      
      if (!trimmedLine || trimmedLine.startsWith('%') || trimmedLine.startsWith('#')) {
        continue;
      }

      // Domain name
      if (this.matchField(trimmedLine, ['Domain Name', 'domain', 'Domain'])) {
        result.domain = this.extractValue(trimmedLine);
      }

      // Registrar
      if (this.matchField(trimmedLine, ['Registrar', 'registrar', 'Registrar Name'])) {
        result.registrar = this.extractValue(trimmedLine);
      }

      // Registration date
      if (this.matchField(trimmedLine, ['Creation Date', 'Created', 'Registration Time', 'registered', 'Registration Date'])) {
        const date = this.parseDate(this.extractValue(trimmedLine));
        if (date) result.registrationDate = date;
      }

      // Expiration date
      if (this.matchField(trimmedLine, ['Expiry Date', 'Expires', 'Expiration Date', 'Registry Expiry Date'])) {
        const date = this.parseDate(this.extractValue(trimmedLine));
        if (date) result.expirationDate = date;
      }

      // Updated date
      if (this.matchField(trimmedLine, ['Updated Date', 'Modified', 'Last Modified', 'Last Updated'])) {
        const date = this.parseDate(this.extractValue(trimmedLine));
        if (date) result.updatedDate = date;
      }

      // Name servers
      if (this.matchField(trimmedLine, ['Name Server', 'nserver', 'DNS', 'Nameserver'])) {
        const nameServer = this.extractValue(trimmedLine).toLowerCase();
        if (nameServer && !result.nameServers.includes(nameServer)) {
          result.nameServers.push(nameServer);
        }
      }

      // Status
      if (this.matchField(trimmedLine, ['Status', 'Domain Status', 'state'])) {
        const status = this.extractValue(trimmedLine);
        if (status && !result.status.includes(status)) {
          result.status.push(status);
        }
      }

      // Registrant country
      if (this.matchField(trimmedLine, ['Registrant Country', 'Country', 'country'])) {
        result.registrantCountry = this.extractValue(trimmedLine);
      }

      // DNSSEC
      if (this.matchField(trimmedLine, ['DNSSEC', 'dnssec'])) {
        result.dnssec = this.extractValue(trimmedLine);
      }
    }

    return result;
  }

  // Helper method to match field names
  matchField(line, fieldNames) {
    const lowerLine = line.toLowerCase();
    return fieldNames.some(field => 
      lowerLine.startsWith(field.toLowerCase() + ':') ||
      lowerLine.startsWith(field.toLowerCase() + ' ')
    );
  }

  // Extract value from WHOIS line
  extractValue(line) {
    const colonIndex = line.indexOf(':');
    if (colonIndex !== -1) {
      return line.substring(colonIndex + 1).trim();
    }
    
    const spaceIndex = line.indexOf(' ');
    if (spaceIndex !== -1) {
      return line.substring(spaceIndex + 1).trim();
    }
    
    return line.trim();
  }

  // Parse date string into Date object
  parseDate(dateString) {
    if (!dateString) return null;
    
    try {
      // Try parsing as ISO date first
      let date = new Date(dateString);
      if (!isNaN(date.getTime())) {
        return date;
      }

      // Try different date formats
      const formats = [
        /(\d{4})-(\d{2})-(\d{2})/, // YYYY-MM-DD
        /(\d{2})\/(\d{2})\/(\d{4})/, // MM/DD/YYYY
        /(\d{2})-(\d{2})-(\d{4})/, // MM-DD-YYYY
        /(\d{4})\.(\d{2})\.(\d{2})/, // YYYY.MM.DD
      ];

      for (const format of formats) {
        const match = dateString.match(format);
        if (match) {
          if (format.source.startsWith('(\\d{4})')) {
            // YYYY-MM-DD format
            date = new Date(match[1], match[2] - 1, match[3]);
          } else {
            // MM-DD-YYYY format
            date = new Date(match[3], match[1] - 1, match[2]);
          }
          
          if (!isNaN(date.getTime())) {
            return date;
          }
        }
      }

    } catch (error) {
      console.error('Date parsing error:', error);
    }

    return null;
  }

  // Analyze domain age and other factors
  analyzeDomainRisk(whoisData) {
    const analysis = {
      riskFactors: [],
      trustScore: 100, // Start with maximum trust
      ageInDays: null
    };

    // Calculate domain age
    if (whoisData.registrationDate) {
      const now = new Date();
      const ageMs = now - whoisData.registrationDate;
      analysis.ageInDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));

      // Young domains are riskier
      if (analysis.ageInDays < 30) {
        analysis.riskFactors.push('Domain is less than 30 days old');
        analysis.trustScore -= 30;
      } else if (analysis.ageInDays < 90) {
        analysis.riskFactors.push('Domain is less than 3 months old');
        analysis.trustScore -= 20;
      } else if (analysis.ageInDays < 365) {
        analysis.riskFactors.push('Domain is less than 1 year old');
        analysis.trustScore -= 10;
      }
    }

    // Check expiration date
    if (whoisData.expirationDate) {
      const now = new Date();
      const daysUntilExpiry = Math.floor((whoisData.expirationDate - now) / (1000 * 60 * 60 * 24));
      
      if (daysUntilExpiry < 30) {
        analysis.riskFactors.push('Domain expires soon');
        analysis.trustScore -= 15;
      }
    }

    // Check for privacy protection
    if (whoisData.rawData.toLowerCase().includes('privacy') || 
        whoisData.rawData.toLowerCase().includes('whoisguard') ||
        whoisData.rawData.toLowerCase().includes('protected')) {
      analysis.riskFactors.push('Domain uses privacy protection service');
      analysis.trustScore -= 5; // Minor deduction as this is common
    }

    // Check registrar reputation
    const suspiciousRegistrars = [
      'namecheap', // Often used for temporary domains
      'godaddy', // High volume, less verification
    ];
    
    if (whoisData.registrar) {
      const registrarLower = whoisData.registrar.toLowerCase();
      if (suspiciousRegistrars.some(suspicious => registrarLower.includes(suspicious))) {
        analysis.trustScore -= 5;
      }
    }

    // Check name servers
    if (whoisData.nameServers.length === 0) {
      analysis.riskFactors.push('No name servers found');
      analysis.trustScore -= 20;
    }

    // Normalize trust score
    analysis.trustScore = Math.max(0, Math.min(100, analysis.trustScore));

    return analysis;
  }

  // Bulk domain lookup
  async lookupMultipleDomains(domains) {
    const results = {};
    const promises = domains.map(async (domain) => {
      try {
        const result = await this.lookupDomain(domain);
        results[domain] = result;
      } catch (error) {
        results[domain] = {
          domain: domain,
          error: error.message,
          parsed: false
        };
      }
    });

    await Promise.allSettled(promises);
    return results;
  }
}

module.exports = new WhoisService();
