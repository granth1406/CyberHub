require('dotenv').config();
const axios = require('axios');

const scanEmail = async (req, res) => {
    try {
        const { email } = req.body;
        const threats = [];
        let safetyScore = 100;

        // 1. Check for phishing patterns
        const phishingPatterns = [
            /urgent.*action.*required/i,
            /verify.*account.*immediately/i,
            /password.*expired/i,
            /suspicious.*activity/i,
            /account.*suspended/i
        ];

        phishingPatterns.forEach(pattern => {
            if (pattern.test(email)) {
                threats.push({
                    type: 'Phishing',
                    description: 'Suspicious phishing patterns detected',
                    severity: 'high'
                });
                safetyScore -= 20;
            }
        });

        // 2. Check links in email using Google Safe Browsing API
        const urlPattern = /(https?:\/\/[^\s]+)/g;
        const urls = email.match(urlPattern) || [];
        
        if (urls.length > 0) {
            try {
                const safeBrowsingResponse = await axios.post(
                    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_BROWSING_KEY}`,
                    {
                        client: {
                            clientId: "CyberGuard",
                            clientVersion: "1.0.0"
                        },
                        threatInfo: {
                            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                            platformTypes: ["ANY_PLATFORM"],
                            threatEntryTypes: ["URL"],
                            threatEntries: urls.map(url => ({ url }))
                        }
                    }
                );

                if (safeBrowsingResponse.data.matches) {
                    threats.push({
                        type: 'Malicious URL',
                        description: 'Email contains potentially dangerous links',
                        severity: 'critical'
                    });
                    safetyScore -= 30;
                }
            } catch (error) {
                console.error('Safe Browsing API error:', error);
            }
        }

        // 3. Check attachments or base64 content using VirusTotal API
        const base64Pattern = /(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)/g;
        const base64Content = email.match(base64Pattern);
        
        if (base64Content) {
            try {
                const vtResponse = await axios.post(
                    'https://www.virustotal.com/vtapi/v2/file/scan',
                    {
                        apikey: process.env.VIRUS_TOTAL_API_KEY,
                        file: base64Content[0]
                    }
                );

                if (vtResponse.data.positives > 0) {
                    threats.push({
                        type: 'Malicious Content',
                        description: 'Suspicious content detected in email',
                        severity: 'high'
                    });
                    safetyScore -= 25;
                }
            } catch (error) {
                console.error('VirusTotal API error:', error);
            }
        }

        // 4. Check sender reputation using SpamHaus or similar
        const emailAddressPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
        const emailAddresses = email.match(emailAddressPattern);

        if (emailAddresses) {
            try {
                const domain = emailAddresses[0].split('@')[1];
                const spamhausResponse = await axios.get(
                    `https://apibl.spamhaus.net/lookup/v1/dbl/${domain}`,
                    {
                        headers: {
                            'Authorization': `Bearer ${process.env.SPAMHAUS_API_KEY}`
                        }
                    }
                );

                if (spamhausResponse.data.listed) {
                    threats.push({
                        type: 'Suspicious Sender',
                        description: 'Email sender domain has poor reputation',
                        severity: 'medium'
                    });
                    safetyScore -= 15;
                }
            } catch (error) {
                console.error('Spamhaus API error:', error);
            }
        }

        // 5. Save scan result to database
        const scanResult = new ScanResult({
            type: 'email',
            content: email,
            safetyScore,
            threats,
            metadata: {
                urlsFound: urls.length.toString(),
                hasAttachments: base64Content ? 'true' : 'false'
            }
        });

        await scanResult.save();

        // Send response
        res.json({
            safetyScore,
            threats,
            metadata: {
                urlsFound: urls.length,
                hasAttachments: !!base64Content
            }
        });

    } catch (error) {
        console.error('Email scanning error:', error);
        res.status(500).json({ 
            message: 'Error scanning email',
            error: error.message 
        });
    }
};

module.exports = {
    scanEmail
};
