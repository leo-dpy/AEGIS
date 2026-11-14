const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const axios = require('axios');
const path = require('path');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY || '';
const HTTP_TIMEOUT = 10000;
const USER_AGENT = 'AEGIS-Toolkit/2.1';

// --- UTILITAIRES ---

// IP réelle du visiteur.
// Derrière un tunnel Cloudflare, l'IP d'origine est dans CF-Connecting-IP (posé par Cloudflare,
// le client ne peut pas le forger tant que l'app n'est joignable QUE via Cloudflare).
// Sinon on retombe sur req.ip, qui respecte le réglage 'trust proxy'.
const getClientIp = (req) => {
    let ip = req.headers['cf-connecting-ip'] || req.ip || req.socket.remoteAddress || '';
    if (ip.startsWith('::ffff:')) ip = ip.slice(7);
    return ip;
};

const isLocalIp = (ip) => /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fc|fd|fe80)/i.test(ip);

// Hash MD5 (32), SHA-1 (40) ou SHA-256 (64) en hexadécimal
const HASH_RE = /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const EMAIL_RE = /^[^\s@/?#]+@[^\s@/?#]+\.[^\s@/?#]+$/;

const vtClient = axios.create({
    baseURL: 'https://www.virustotal.com/api/v3',
    timeout: HTTP_TIMEOUT,
    headers: { 'x-apikey': VIRUSTOTAL_API_KEY }
});

// --- MIDDLEWARE ---

// Un seul proxy devant l'app (cloudflared ou Nginx)
app.set('trust proxy', 1);

// CSP désactivée : le frontend utilise des handlers inline (onclick) et des CDN.
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

// Logs sans query string ni données personnelles (cohérent avec la politique de confidentialité)
morgan.token('safe-path', (req) => (req.originalUrl || req.url).split('?')[0]);
app.use(morgan(':method :safe-path :status :response-time ms'));

app.use(express.json({ limit: '10kb' }));

// Pas de CORS : le frontend est servi par ce même serveur.
// L'ouvrir permettrait à n'importe quel site d'utiliser notre clé VirusTotal.

// Limiteur de requêtes (Protection abus / quota API)
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    limit: 100, // 100 requêtes par IP et par fenêtre
    keyGenerator: (req) => ipKeyGenerator(getClientIp(req)),
    message: { error: 'Trop de requêtes depuis cette IP, veuillez réessayer après 15 minutes.' },
    standardHeaders: 'draft-7',
    legacyHeaders: false,
});
app.use('/api/', apiLimiter);

// Servir le Frontend Statique
const CLIENT_PATH = path.resolve(__dirname, '../client');
console.log(`[INFO] Dossier client servi : ${CLIENT_PATH}`);
app.use(express.static(CLIENT_PATH));

if (!VIRUSTOTAL_API_KEY) {
    console.warn('[WARN] VIRUSTOTAL_API_KEY absente : les analyses de fichier et d\'URL seront indisponibles.');
}

const requireVtKey = (req, res, next) => {
    if (!VIRUSTOTAL_API_KEY) {
        return res.status(503).json({ error: 'Service VirusTotal non configuré sur ce serveur.' });
    }
    next();
};

// --- CACHE DES FUITES (XposedOrNot) ---

let breachCache = [];
const fetchBreaches = async () => {
    try {
        console.log('[INFO] Récupération de la base de données des fuites...');
        const response = await axios.get('https://api.xposedornot.com/v1/breaches', {
            timeout: 30000,
            headers: { 'User-Agent': USER_AGENT }
        });
        if (response.data && Array.isArray(response.data.exposedBreaches)) {
            breachCache = response.data.exposedBreaches;
        } else if (Array.isArray(response.data)) {
            breachCache = response.data;
        }
        console.log(`[INFO] ${breachCache.length} fuites chargées en cache.`);
    } catch (e) {
        console.error('[ERROR] Échec du chargement des fuites :', e.message);
    }
};

fetchBreaches();
setInterval(fetchBreaches, 24 * 60 * 60 * 1000).unref();

// --- ROUTES API ---

// Route : Analyse de fichier via VirusTotal (par hash)
app.get('/api/virustotal/:hash', requireVtKey, async (req, res) => {
    const hash = req.params.hash;
    if (!HASH_RE.test(hash)) {
        return res.status(400).json({ error: 'Hash invalide (MD5, SHA-1 ou SHA-256 attendu).' });
    }

    try {
        const response = await vtClient.get(`/files/${hash}`);
        const attrs = response.data.data.attributes;
        res.json({
            found: true,
            name: attrs.meaningful_name || null,
            stats: attrs.last_analysis_stats
        });
    } catch (e) {
        if (e.response && e.response.status === 404) {
            return res.json({ found: false });
        }
        console.error('[ERROR] VirusTotal (fichier) :', e.response ? e.response.status : e.message);
        res.status(502).json({ error: 'VirusTotal est injoignable ou a refusé la requête. Aucun verdict disponible.' });
    }
});

// Route : Analyse d'URL via VirusTotal
app.get('/api/url-info', requireVtKey, async (req, res) => {
    const target = String(req.query.url || '').trim();
    let parsed;
    try {
        parsed = new URL(target);
    } catch {
        return res.status(400).json({ error: 'URL invalide. Exemple : https://exemple.com' });
    }
    if (!['http:', 'https:'].includes(parsed.protocol) || target.length > 2048) {
        return res.status(400).json({ error: 'Seules les URL http(s) de moins de 2048 caractères sont acceptées.' });
    }

    try {
        // VirusTotal attend l'URL encodée en base64 "URL-safe" sans padding
        const urlId = Buffer.from(target).toString('base64url');
        const response = await vtClient.get(`/urls/${urlId}`);

        const data = response.data.data.attributes;
        const stats = data.last_analysis_stats;
        const risk = stats.malicious > 0 ? { l: 'MALVEILLANT', c: 'red' }
            : (stats.suspicious > 0 ? { l: 'SUSPECT', c: 'orange' } : { l: 'AUCUNE DÉTECTION', c: 'lime' });

        res.json({
            found: true,
            originalUrl: target,
            finalUrl: data.last_final_url || data.url || target,
            statusCode: data.last_http_response_code || null,
            riskLevel: risk.l,
            riskColor: risk.c,
            virusTotal: {
                malicious: stats.malicious,
                suspicious: stats.suspicious,
                harmless: stats.harmless,
                undetected: stats.undetected,
                totalEngines: Object.keys(data.last_analysis_results || {}).length
            }
        });
    } catch (e) {
        if (e.response && e.response.status === 404) {
            return res.json({ found: false, originalUrl: target });
        }
        console.error('[ERROR] VirusTotal (URL) :', e.response ? e.response.status : e.message);
        res.status(502).json({ error: 'VirusTotal est injoignable ou a refusé la requête. Aucun verdict disponible.' });
    }
});

// Route : Vérification de fuite d'email (XposedOrNot)
// En POST pour que l'email n'apparaisse ni dans l'URL ni dans les logs.
app.post('/api/breach', async (req, res) => {
    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    if (!EMAIL_RE.test(email) || email.length > 254) {
        return res.status(400).json({ error: 'Adresse email invalide.' });
    }

    try {
        const response = await axios.get(`https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`, {
            timeout: HTTP_TIMEOUT,
            headers: { 'User-Agent': USER_AGENT }
        });

        // L'API renvoie { breaches: [ ["Name1", "Name2", ...] ] } ou { Error: "Not found" }
        const breachNames = (response.data && Array.isArray(response.data.breaches) && Array.isArray(response.data.breaches[0]))
            ? response.data.breaches[0]
            : [];

        const details = breachNames.map(name => {
            const info = breachCache.find(b => b.breachID === name);
            return {
                Name: name,
                Description: info ? info.exposureDescription : 'Détails non disponibles',
                BreachDate: info && info.breachedDate ? String(info.breachedDate).split('T')[0] : 'Inconnue'
            };
        });

        res.json({ breaches: details });
    } catch (e) {
        // 404 = email absent de toutes les fuites connues
        if (e.response && e.response.status === 404) {
            return res.json({ breaches: [] });
        }
        console.error('[ERROR] XposedOrNot :', e.response ? e.response.status : e.message);
        res.status(502).json({ error: 'Le service de vérification est injoignable. Réessayez plus tard.' });
    }
});

// Route : IP publique du visiteur
app.get('/api/ip', (req, res) => {
    const ip = getClientIp(req);
    if (!ip) {
        return res.status(500).json({ success: false, message: "Impossible de déterminer l'IP" });
    }
    // On ne remplace JAMAIS une IP locale par l'IP publique du serveur :
    // derrière un tunnel, ça afficherait l'IP du homelab à tous les visiteurs.
    res.json({ success: true, ip, local: isLocalIp(ip) });
});

// Routes API inconnues : vraie 404 JSON plutôt que la page HTML
app.use('/api', (req, res) => {
    res.status(404).json({ error: 'Route API inconnue.' });
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
