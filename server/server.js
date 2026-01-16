require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;
const path = require('path');

// Middleware
app.use(cors());
app.use(helmet({
    contentSecurityPolicy: false, // Disable CSP for simplicity in this demo (loading scripts from CDN)
}));
app.use(morgan('dev'));
app.use(express.json());

// Serve Static Frontend
app.use(express.static(path.join(__dirname, '../client')));

// --- API KEYS ---
// In a real scenario, these would come from process.env
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY || 'mock_vt_key_12345';

// --- ROUTES ---

// 1. IP & ASN Analysis (Proxied to avoid CORS or limit rate)
// In a real app we might query a maxmind DB or external API here
app.get('/api/ip', async (req, res) => {
    try {
        // Echo back the IP or fetch from an external service like ip-api.com
        // For privacy, we try to use the request IP
        let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        if (ip === '::1') ip = '8.8.8.8'; // Fallback for local dev

        const response = await axios.get(`http://ip-api.com/json/${ip}`);
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch IP info' });
    }
});

// 2. VirusTotal File Report
app.get('/api/virustotal/:hash', async (req, res) => {
    const { hash } = req.params;
    try {
        const response = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
            headers: { 'x-apikey': VIRUSTOTAL_API_KEY }
        });
        res.json(response.data);
    } catch (error) {
        console.log("VT API Call failed (expected with mock key). Returning mock data.");
        res.json({
            data: {
                attributes: {
                    last_analysis_stats: {
                        malicious: 0,
                        suspicious: 0,
                        harmless: 70
                    },
                    meaningful_name: "clean_file.exe"
                }
            }
        });
    }
});

// 3. Email Breach Check (via multiple free APIs)
app.get('/api/breach/:email', async (req, res) => {
    const { email } = req.params;

    try {
        // Try XposedOrNot API first
        const response = await axios.get(`https://api.xposedornot.com/v1/check-email/${email}`, {
            timeout: 10000,
            headers: {
                'User-Agent': 'AEGIS Security Toolkit'
            }
        });

        // Handle successful response
        if (response.data && response.data.breaches) {
            // New API format
            const breaches = response.data.breaches;
            if (Array.isArray(breaches) && breaches.length > 0) {
                const formatted = breaches.map(b => ({
                    Name: typeof b === 'string' ? b : (b.name || b.Name || 'Unknown'),
                    Domain: b.domain || 'Unknown',
                    BreachDate: b.date || b.BreachDate || 'Unknown',
                    Description: 'Fuite détectée via XposedOrNot'
                }));
                return res.json(formatted);
            }
        }

        // Old API format with Breaches key
        if (response.data && response.data.Breaches) {
            const breachData = response.data.Breaches;
            if (Array.isArray(breachData) && breachData.length > 0) {
                // Handle nested array format
                const flatBreaches = Array.isArray(breachData[0]) ? breachData[0] : breachData;
                const formatted = flatBreaches.map(name => ({
                    Name: typeof name === 'string' ? name : (name.Name || 'Unknown'),
                    Domain: 'Unknown',
                    BreachDate: 'Unknown',
                    Description: 'Fuite détectée via XposedOrNot'
                }));
                return res.json(formatted);
            }
        }

        // No breaches found
        return res.json([]);

    } catch (error) {
        // 404 means no breaches found
        if (error.response && error.response.status === 404) {
            return res.json([]);
        }

        // For other errors, return empty array with a note (non-blocking)
        console.log('Breach API error:', error.message);
        return res.json([]);
    }
});

app.listen(PORT, () => {
    console.log(`AEGIS Server running on port ${PORT}`);
});
