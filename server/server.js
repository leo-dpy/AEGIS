require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const whois = require('whois');
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

// --- MOCK API KEYS (As requested) ---
// In a real scenario, these would come from process.env
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY || 'mock_vt_key_12345';
const HIBP_API_KEY = process.env.HIBP_API_KEY || 'mock_hibp_key_67890';

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

// 2. WHOIS Lookup
app.get('/api/whois/:domain', (req, res) => {
    const { domain } = req.params;
    whois.lookup(domain, (err, data) => {
        if (err) {
            return res.status(500).json({ error: 'WHOIS lookup failed' });
        }
        res.json({ data });
    });
});

// 3. VirusTotal File/URL Report
app.get('/api/virustotal/:hash', async (req, res) => {
    const { hash } = req.params;
    try {
        // Mocking the proper call structure
        const response = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
            headers: { 'x-apikey': VIRUSTOTAL_API_KEY }
        });
        res.json(response.data);
    } catch (error) {
        // If mock key fails (which it will on real API), return a mock success for demo
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

// 4. URL Reputation / Expansion
app.get('/api/url-info', async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    try {
        const response = await axios.head(url, {
            maxRedirects: 5,
            validateStatus: () => true
        });

        res.json({
            finalUrl: response.request.res.responseUrl || url,
            statusCode: response.status,
            contentType: response.headers['content-type'],
            server: response.headers['server']
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to analyze URL' });
    }
});

// 5. HaveIBeenPwned Breach Check
app.get('/api/breach/:email', async (req, res) => {
    const { email } = req.params;
    try {
        const response = await axios.get(`https://haveibeenpwned.com/api/v3/breachedaccount/${email}`, {
            headers: {
                'hibp-api-key': HIBP_API_KEY,
                'user-agent': 'AEGIS-Security-Tool'
            }
        });
        res.json(response.data);
    } catch (error) {
        if (error.response && error.response.status === 404) {
            return res.json([]); // No breaches found
        }
        // Fallback mock
        res.json([
            { Name: "MockBreachDB", Domain: "mock.com", BreachDate: "2025-01-01", Description: "This is a simulated breach result." }
        ]);
    }
});

app.listen(PORT, () => {
    console.log(`AEGIS Server running on port ${PORT}`);
});
