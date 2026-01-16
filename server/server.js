const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const axios = require('axios');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan('dev'));
app.use(express.json());

// Serve Static Frontend
// Explicitly resolve the path to the client directory
const CLIENT_PATH = path.resolve(__dirname, '../client');
console.log(`[INFO] Serving static files from: ${CLIENT_PATH}`);

app.use(express.static(CLIENT_PATH));

// Clé API VirusTotal (Env ou Fallback)
const VIRUSTOTAL_API_KEY = process.env.TotaVirus_API || process.env.VIRUSTOTAL_API_KEY || 'mock_vt_key';

// --- API ROUTES ---

// Route : Analyse de fichier via VirusTotal
app.get('/api/virustotal/:hash', async (req, res) => {
    try {
        const response = await axios.get(`https://www.virustotal.com/api/v3/files/${req.params.hash}`, {
            headers: { 'x-apikey': VIRUSTOTAL_API_KEY }
        });
        res.json(response.data);
    } catch (e) {
        // En cas d'erreur ou de clé invalide, retourne des données factices pour la démo
        // console.error("VT Error:", e.message);
        res.json({ data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 100 }, meaningful_name: "demo_file.exe" } } });
    }
});

// Route : Vérification de fuite d'email (XposedOrNot)
app.get('/api/breach/:email', async (req, res) => {
    try {
        const response = await axios.get(`https://api.xposedornot.com/v1/check-email/${req.params.email}`, { timeout: 10000 });
        if (response.data && response.data.breaches) {
            return res.json(response.data.breaches.map(b => ({
                Name: b[0] || 'Inconnu',
                Description: 'Source détectée',
                Date: 'Inconnue'
            })));
        }
        res.json([]);
    } catch (e) {
        res.json([]);
    }
});

// Route : Analyse d'URL via VirusTotal
app.get('/api/url-info', async (req, res) => {
    if (!req.query.url) return res.status(400).json({ error: 'URL requise' });
    try {
        const urlId = Buffer.from(req.query.url).toString('base64').replace(/=/g, '');
        const response = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
            headers: { 'x-apikey': VIRUSTOTAL_API_KEY }
        });

        const data = response.data.data.attributes;
        const stats = data.last_analysis_stats;
        const risk = stats.malicious > 0 ? { l: 'MALVEILLANT', c: 'red' } : (stats.suspicious > 0 ? { l: 'SUSPECT', c: 'orange' } : { l: 'SÉCURISÉ', c: 'lime' });

        res.json({
            originalUrl: req.query.url,
            finalUrl: data.url,
            statusCode: data.last_http_response_code,
            riskLevel: risk.l,
            riskColor: risk.c,
            virusTotal: {
                malicious: stats.malicious,
                suspicious: stats.suspicious,
                harmless: stats.harmless,
                undetected: stats.undetected,
                totalEngines: Object.keys(data.last_analysis_results).length
            },
            warnings: []
        });
    } catch (e) {
        res.json({ riskLevel: 'INCONNU', riskColor: '#888', virusTotal: null, warnings: ['URL non trouvée ou erreur API'] });
    }
});

// --- SPA FALLBACK ---
// This must be AFTER all API routes
app.get('*', (req, res) => {
    res.sendFile(path.join(CLIENT_PATH, 'index.html'));
});

// Démarrage du serveur
app.listen(PORT, () => {
    console.log(`Serveur AEGIS actif sur le port ${PORT}`);
});
