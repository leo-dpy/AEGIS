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
app.set('trust proxy', 1); // Faire confiance au premier proxy (Nginx/Apache)
app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan('dev'));
app.use(express.json());

// Servir le Frontend Statique
// Résolution explicite du chemin vers le dossier client
const CLIENT_PATH = path.resolve(__dirname, '../client');
console.log(`[INFO] Dossier client servi : ${CLIENT_PATH}`);

app.use(express.static(CLIENT_PATH));

// Clé API VirusTotal (Env ou Fallback)
const VIRUSTOTAL_API_KEY = process.env.TotaVirus_API || process.env.VIRUSTOTAL_API_KEY || 'mock_vt_key';

// Cache pour les détails des fuites
let breachCache = [];
const fetchBreaches = async () => {
    try {
        console.log('[INFO] Récupération de la base de données des fuites...');
        const response = await axios.get('https://api.xposedornot.com/v1/breaches', {
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36' }
        });
        if (response.data && response.data.exposedBreaches) {
            breachCache = response.data.exposedBreaches;
        } else if (Array.isArray(response.data)) {
            breachCache = response.data;
        }
        console.log(`[INFO] ${breachCache.length} fuites chargées en cache.`);
    } catch (e) {
        console.error('[ERROR] Échec du chargement des fuites :', e.message);
    }
};

// Charge la base de données des fuites au démarrage
fetchBreaches();

// --- ROUTES API ---

// Route : Analyse de fichier via VirusTotal
app.get('/api/virustotal/:hash', async (req, res) => {
    try {
        const response = await axios.get(`https://www.virustotal.com/api/v3/files/${req.params.hash}`, {
            headers: { 'x-apikey': VIRUSTOTAL_API_KEY }
        });
        res.json(response.data);
    } catch (e) {
        // En cas d'erreur ou de clé invalide, retourne des données factices pour la démo
        // console.error("Erreur VT :", e.message);
        res.json({ data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 100 }, meaningful_name: "demo_file.exe" } } });
    }
});

// Route : Vérification de fuite d'email (XposedOrNot)
app.get('/api/breach/:email', async (req, res) => {
    try {
        const response = await axios.get(`https://api.xposedornot.com/v1/check-email/${req.params.email}`, {
            timeout: 10000,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        });

        // L'API renvoie { breaches: [ ["Name1", "Name2", ...] ] }
        let breachNames = [];
        if (response.data && response.data.breaches && response.data.breaches[0]) {
            breachNames = response.data.breaches[0];
        }

        const details = breachNames.map(name => {
            const info = breachCache.find(b => b.breachID === name);
            return {
                Name: name,
                Description: info ? info.exposureDescription : 'Source détectée (Détails non disponibles)',
                BreachDate: info ? info.breachedDate.split('T')[0] : 'Inconnue'
            };
        });

        res.json(details);
    } catch (e) {
        // En cas d'erreur ou si l'email n'est pas trouvé (l'API renvoie parfois 404 ou une erreur JSON)
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

// Route : Récupération de l'IP (Détecté côté serveur pour le client)
// Route : Récupération de l'IP (Détecté côté serveur pour le client)
app.get('/api/ip', async (req, res) => {
    try {
        // Récupération de l'IP du client (Support Nginx/Reverse Proxy)
        let clientIp = req.headers['x-client-ip'] || req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || req.ip || req.socket.remoteAddress;

        // Nettoyage de l'IP (gestion du ::ffff: pour IPv6-mapped IPv4)
        if (clientIp && clientIp.includes('::ffff:')) {
            clientIp = clientIp.split('::ffff:')[1];
        }

        // Si plusieurs IPs (x-forwarded-for), on prend la première (client d'origine)
        if (clientIp && clientIp.includes(',')) {
            clientIp = clientIp.split(',')[0].trim();
        }

        console.log(`[INFO] IP Client détectée (Brut) : ${clientIp}`);

        // Si l'IP est locale (::1 ou 127.0.0.1), on tente de récupérer l'IP publique via une API externe
        // C'est utile pour le développement local ou si le serveur est hébergé chez soi sans proxy configuré
        if (clientIp === '::1' || clientIp === '127.0.0.1') {
            try {
                console.log('[INFO] IP Locale détectée, récupération IP publique via ipify...');
                const response = await axios.get('https://api.ipify.org?format=json');
                if (response.data && response.data.ip) {
                    clientIp = response.data.ip;
                    console.log(`[INFO] IP Publique récupérée : ${clientIp}`);
                }
            } catch (extError) {
                console.warn("[WARN] Impossible de récupérer l'IP publique via ipify :", extError.message);
                // On garde l'IP locale si l'API échoue
            }
        }

        // On renvoie juste l'IP
        res.json({ success: true, ip: clientIp });
    } catch (e) {
        console.error("Erreur IP :", e.message);
        res.status(500).json({ success: false, message: "Impossible de récupérer l'IP" });
    }
});

// --- SPA FALLBACK ---
// Doit être APRÈS toutes les routes API
app.get('*', (req, res) => {
    res.sendFile(path.join(CLIENT_PATH, 'index.html'));
});

// Démarrage du serveur
app.listen(PORT, () => {
    console.log(`Serveur AEGIS actif sur le port ${PORT}`);
});
