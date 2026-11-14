/* AEGIS Logic - JavaScript Vanilla */

// Échappe tout texte inséré via innerHTML (noms de fichiers, URL, réponses d'API...)
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[c]));

const formatSize = (bytes) => (bytes >= 1048576) ? (bytes / 1048576).toFixed(2) + ' MB' : (bytes / 1024).toFixed(1) + ' KB';

// Lit la réponse JSON d'une API et lève une erreur lisible si le serveur a répondu en erreur
const readApi = async (res) => {
    let data = null;
    try { data = await res.json(); } catch { /* réponse non JSON */ }
    if (!res.ok) throw new Error((data && data.error) || `Erreur serveur (${res.status})`);
    return data;
};

// État global pour les données partagées
const state = {
    ipData: null,
    isFetchingIp: false
};

// Fonction partagée pour récupérer l'IP (avec cache)
const fetchIpData = async () => {
    if (state.ipData) return state.ipData;
    if (state.isFetchingIp) {
        // Si déjà en cours, attendre
        return new Promise(resolve => {
            const check = setInterval(() => {
                if (state.ipData) { clearInterval(check); resolve(state.ipData); }
                else if (!state.isFetchingIp) { clearInterval(check); resolve(null); } // Échec ou fin
            }, 100);
        });
    }

    state.isFetchingIp = true;
    try {
        // Tentative via notre serveur (Proxy IPv4)
        console.log("Tentative récupération IP...");
        let res = await fetch('/api/ip');
        if (res.ok) {
            let data = await res.json();
            if (data.success) {
                state.ipData = data;
                return data;
            }
        }
    } catch (e) {
        console.error("Erreur récupération IP:", e);
    } finally {
        state.isFetchingIp = false;
    }
    return null;
};

// Formate un nom de plateforme lisible.
const formatPlatformName = (platform) => {
    const value = String(platform || '').trim().toLowerCase();

    if (!value) return '';
    if (value === 'macos' || value === 'mac os' || value === 'macintosh') return 'macOS';
    if (value === 'ios') return 'iOS';
    if (value === 'android') return 'Android';
    if (value === 'linux') return 'Linux';
    if (value === 'cros') return 'ChromeOS';
    if (value === 'windows' || value.startsWith('win')) return 'Windows';

    return platform;
};

// Detecte le systeme avec les Client Hints quand disponibles.
async function getSystemInfo() {
    const highEntropyHints = ['platform', 'architecture', 'bitness', 'wow64'];

    try {
        if (navigator.userAgentData?.getHighEntropyValues) {
            const uaData = await navigator.userAgentData.getHighEntropyValues(highEntropyHints);
            const platform = formatPlatformName(uaData.platform);
            const architecture = String(uaData.architecture || '').toLowerCase();
            const bitness = String(uaData.bitness || '');

            if (platform === 'Windows') {
                const is64Bit = bitness === '64'
                    || uaData.wow64 === true
                    || /(x86_64|x64|amd64|arm64)/i.test(architecture)
                    || (architecture.includes('x86') && bitness !== '32');

                return is64Bit ? 'Windows 64-bit' : 'Windows 32-bit';
            }

            if (platform) return `${platform}${bitness ? ` ${bitness}-bit` : ''}`;
        }
    } catch (error) {
        console.warn('Detection systeme moderne indisponible:', error);
    }

    const userAgent = navigator.userAgent || '';

    // Fallback pour les navigateurs sans User-Agent Client Hints.
    if (/windows|win32|win64|wow64/i.test(userAgent)) {
        return /win64|x64|wow64|amd64/i.test(userAgent) ? 'Windows 64-bit' : 'Windows';
    }
    if (/android/i.test(userAgent)) return 'Android';
    if (/iphone|ipad|ipod/i.test(userAgent)) return 'iOS';
    if (/macintosh|mac os x/i.test(userAgent)) return 'macOS';
    if (/linux/i.test(userAgent)) return /x86_64|x64|amd64|aarch64/i.test(userAgent) ? 'Linux 64-bit' : 'Linux';

    // Dernier recours : navigator.platform peut etre imprecis.
    return navigator.platform || 'Inconnu';
}

// Encode des pixels RGBA en BMP 24 bits (les navigateurs ne savent pas produire du BMP)
const encodeBmp = ({ width, height, data }) => {
    const rowSize = Math.ceil((width * 3) / 4) * 4; // lignes alignées sur 4 octets
    const pixelBytes = rowSize * height;
    const buf = new ArrayBuffer(54 + pixelBytes);
    const v = new DataView(buf);
    v.setUint16(0, 0x4D42, true);          // "BM"
    v.setUint32(2, 54 + pixelBytes, true); // taille du fichier
    v.setUint32(10, 54, true);             // offset des pixels
    v.setUint32(14, 40, true);             // taille de l'en-tête DIB
    v.setInt32(18, width, true);
    v.setInt32(22, height, true);          // positif = lignes du bas vers le haut
    v.setUint16(26, 1, true);              // plans
    v.setUint16(28, 24, true);             // bits par pixel
    v.setUint32(34, pixelBytes, true);
    const out = new Uint8Array(buf);
    for (let y = 0; y < height; y++) {
        const row = 54 + (height - 1 - y) * rowSize;
        for (let x = 0; x < width; x++) {
            const i = (y * width + x) * 4, o = row + x * 3;
            out[o] = data[i + 2]; out[o + 1] = data[i + 1]; out[o + 2] = data[i]; // BGR
        }
    }
    return new Blob([buf], { type: 'image/bmp' });
};

// Emballe un PNG dans un conteneur ICO (format accepté par Windows Vista+ et les navigateurs)
const wrapPngInIco = (pngBlob, width, height) => {
    const header = new DataView(new ArrayBuffer(22));
    header.setUint16(2, 1, true);                     // type : icône
    header.setUint16(4, 1, true);                     // 1 image
    header.setUint8(6, width >= 256 ? 0 : width);     // 0 = 256 px
    header.setUint8(7, height >= 256 ? 0 : height);
    header.setUint16(10, 1, true);                    // plans
    header.setUint16(12, 32, true);                   // bits par pixel
    header.setUint32(14, pngBlob.size, true);         // taille de l'image
    header.setUint32(18, 22, true);                   // offset de l'image
    return new Blob([header.buffer, pngBlob], { type: 'image/x-icon' });
};

// Nom du navigateur (l'ordre compte : Edge et Opera contiennent aussi "Chrome")
const getBrowserName = () => {
    const ua = navigator.userAgent || '';
    if (/Edg\//.test(ua)) return 'Microsoft Edge';
    if (/OPR\//.test(ua)) return 'Opera';
    if (/Firefox\//.test(ua)) return 'Firefox';
    if (/Chrome\//.test(ua)) return 'Chrome / Chromium';
    if (/Safari\//.test(ua)) return 'Safari';
    return 'Inconnu';
};

// Gestion de la navigation et du dock
const app = {
    navigate: (viewName) => {
        document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
        const target = document.getElementById(`view-${viewName}`);
        if (target) {
            target.classList.add('active');
            if (viewName === 'ip') tools.ip.init();
        }

        document.querySelectorAll('.dock-item').forEach(el => el.classList.remove('active'));
        const btns = document.querySelectorAll(`.dock-item[onclick*="'${viewName}'"]`);
        if (btns.length > 0) btns[0].classList.add('active');
    },

    // Initialisation du widget dashboard
    initDashboard: async () => {
        const data = await fetchIpData();
        const dashIp = document.getElementById('dash-ip');
        if (dashIp && data && data.ip) dashIp.textContent = data.ip;
        else if (dashIp) dashIp.textContent = "Non disponible";
    }
};

setTimeout(app.initDashboard, 500);

const API_URL = '/api';

const tools = {
    // Outil 1 : Analyse IP
    ip: {
        init: async () => {
            const container = document.getElementById('ip-results');

            // Si on a déjà les données, on affiche direct, sinon chargement
            if (!state.ipData) {
                container.innerHTML = '<div style="grid-column: 1/-1; text-align:center;">Analyse de votre connexion en cours...</div>';
            }

            const data = await fetchIpData();
            const systemInfo = await getSystemInfo();

            if (!data) {
                container.innerHTML = '<div style="color:red; text-align:center; grid-column: 1/-1;">Impossible de récupérer les données IP.</div>';
                return;
            }

            const fields = [
                { label: data.local ? 'IP (RÉSEAU LOCAL)' : 'VOTRE IP PUBLIQUE', value: data.ip },
                { label: 'Système', value: systemInfo },
                { label: 'Navigateur', value: getBrowserName() },
            ];

            container.innerHTML = fields.map(f => `
                <div style="background:#000; padding:1.5rem; border:1px solid #333; border-radius:6px; position:relative;">
                    <div style="color:#888; font-size:0.75rem; text-transform:uppercase; margin-bottom:0.5rem;">${esc(f.label)}</div>
                    <div style="font-size:1.1rem; color:#fff; font-weight:600; word-break:break-all;">
                        ${esc(f.value || 'N/A')}
                    </div>
                </div>
            `).join('');
        }
    },

    // Outil 2 : Nettoyeur EXIF
    exif: {
        currentFile: null,
        handleFile: (input) => {
            if (input.files[0]) {
                tools.exif.currentFile = input.files[0];
                const resBox = document.getElementById('exif-data');
                const btn = document.getElementById('exif-clean-btn');
                document.getElementById('exif-filename').textContent = "Fichier: " + input.files[0].name;

                EXIF.getData(input.files[0], function () {
                    const allTags = EXIF.getAllTags(this);
                    resBox.style.display = 'block';
                    if (Object.keys(allTags).length > 0) {
                        let txt = '';
                        for (let key in allTags) {
                            if (key !== 'thumbnail') txt += `${key}: ${allTags[key]}\n`;
                        }
                        resBox.textContent = txt;
                    } else {
                        resBox.textContent = "Aucune donnée EXIF trouvée (Image propre ou format non supporté).";
                    }
                    btn.style.display = 'inline-block';
                });
            }
        },
        clean: () => {
            const f = tools.exif.currentFile;
            if (!f) return;
            const img = new Image();
            img.src = URL.createObjectURL(f);
            img.onload = () => {
                const canvas = document.createElement('canvas');
                canvas.width = img.width;
                canvas.height = img.height;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(img, 0, 0);
                canvas.toBlob((blob) => {
                    const url = URL.createObjectURL(blob);
                    document.getElementById('exif-download').innerHTML = `<a href="${url}" download="clean_${esc(f.name)}" class="action-btn" style="text-decoration:none; display:inline-block; margin-top:10px; background:#fff; color:#000;">TÉLÉCHARGER L'IMAGE PROPRE</a>`;
                }, f.type);
            };
        }
    },

    // Outil 3 : Nettoyeur de texte (Sanitizer)
    sanitizer: {
        run: () => {
            const input = document.getElementById('san-input').value;
            // Caract\u00E8res invisibles : espaces de largeur nulle, trait d'union conditionnel, joiners,
            // contr\u00F4les bidirectionnels (attaques "Trojan Source") et caract\u00E8res Tags Unicode
            // (utilis\u00E9s pour cacher du texte, ex. injection de prompt).
            const invisible = /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0]|[\u{E0000}-\u{E007F}]/gu;
            const removed = (input.match(invisible) || []).length;
            const clean = input.replace(invisible, '').normalize('NFKC');
            document.getElementById('san-output').value = clean;
            const info = document.getElementById('san-info');
            if (info) {
                info.textContent = input
                    ? (removed > 0 ? `${removed} caract\u00E8re(s) invisible(s) supprim\u00E9(s).` : 'Aucun caract\u00E8re invisible d\u00E9tect\u00E9.')
                    : '';
                info.style.color = removed > 0 ? 'orange' : '#888';
            }
        },
        copy: () => {
            const txt = document.getElementById('san-output').value;
            if (txt) {
                navigator.clipboard.writeText(txt);
                const btn = document.getElementById('san-copy-btn');
                const original = btn.innerHTML;
                btn.innerHTML = '✓';
                btn.style.borderColor = 'lime';
                btn.style.color = 'lime';
                setTimeout(() => {
                    btn.innerHTML = original;
                    btn.style.borderColor = '#333';
                    btn.style.color = '#ffffff';
                }, 2000);
            }
        }
    },

    // Outil 4 : Compression (Image & PDF)
    compress: {
        run: async () => {
            const file = document.getElementById('compress-file').files[0];
            if (!file) return;

            const resBox = document.getElementById('compress-result');
            resBox.style.display = 'block';

            const mode = document.querySelector('input[name="compress-mode"]:checked')?.value || 'balanced';
            const modeLabels = { 'quality': 'QUALITÉ', 'balanced': 'ÉQUILIBRÉ', 'max': 'MAXIMUM' };
            const isPDF = file.type === 'application/pdf' || file.name.toLowerCase().endsWith('.pdf');
            const fileType = isPDF ? 'PDF' : 'IMAGE';

            resBox.innerHTML = `<div style="text-align:center; padding:20px;"><div>Compression ${fileType}...</div><div style="color:#666; font-size:0.8rem;">${esc(file.name)}</div><div style="color:#ffffff; font-size:0.7rem;">Mode: ${modeLabels[mode]}</div></div>`;

            try {
                let compressed, url;
                const originalSize = file.size;

                if (isPDF) {
                    const arrayBuffer = await file.arrayBuffer();
                    const pdfDoc = await PDFLib.PDFDocument.load(arrayBuffer);
                    pdfDoc.setTitle(''); pdfDoc.setAuthor(''); pdfDoc.setSubject(''); pdfDoc.setKeywords([]); pdfDoc.setProducer('AEGIS Compressor'); pdfDoc.setCreator('');
                    const compressedPdf = await pdfDoc.save({ useObjectStreams: true, addDefaultPage: false, objectsPerTick: 50 });
                    compressed = new Blob([compressedPdf], { type: 'application/pdf' });
                    url = URL.createObjectURL(compressed);
                } else {
                    // Configuration optimisée pour des performances type "iLovePDF"
                    let options = { useWebWorker: true, fileType: file.type };
                    switch (mode) {
                        case 'quality':
                            // Haute Qualité : On garde la résolution, compression légère (Qualité ~90%)
                            options = { ...options, maxSizeMB: 10, initialQuality: 0.9, alwaysKeepResolution: true };
                            break;
                        case 'balanced':
                            // Équilibré : Standard Web (Max 1MB, HD 1920px max, Qualité ~75%)
                            options = { ...options, maxSizeMB: 1, initialQuality: 0.75, maxWidthOrHeight: 1920 };
                            break;
                        case 'max':
                            // Maximum : Compression forte (Max 200KB, 1024px max, Qualité ~50%)
                            options = { ...options, maxSizeMB: 0.2, initialQuality: 0.5, maxWidthOrHeight: 1024 };
                            break;
                    }
                    compressed = await imageCompression(file, options);
                    url = URL.createObjectURL(compressed);
                }

                // Si la "compression" a grossi le fichier, on rend l'original
                if (compressed.size >= originalSize) {
                    URL.revokeObjectURL(url);
                    compressed = file;
                    url = URL.createObjectURL(file);
                }

                const newSize = compressed.size;
                const reduction = ((1 - newSize / originalSize) * 100).toFixed(1);
                const saved = originalSize - newSize;

                let reductionColor = reduction < 10 ? '#888' : (reduction < 30 ? '#00ff80' : 'lime');

                resBox.innerHTML = `
                    <div class="result-container-centered">
                        <div class="result-success-header">COMPRESSION ${fileType} TERMINÉE</div>
                        <div class="stat-grid" style="width:100%;">
                            <div class="stat-box"><div class="stat-label-sm">ORIGINAL</div><div class="stat-value-lg">${formatSize(originalSize)}</div></div>
                            <div class="stat-box"><div class="stat-label-sm">COMPRESSÉ</div><div class="stat-value-lg" style="color:#fff;">${formatSize(newSize)}</div></div>
                            <div class="stat-box highlight" style="border-color:${reductionColor}; background:rgba(0,255,128,0.1);"><div class="stat-label-sm">RÉDUCTION</div><div class="stat-value-lg" style="color:${reductionColor};">-${reduction}%</div></div>
                        </div>
                        <div class="result-file-info">${esc(file.name)} — <span style="color:#fff">${saved > 0 ? formatSize(saved) + ' économisés' : 'Aucun gain : le fichier était déjà optimisé'}</span></div>
                        <a href="${url}" download="compressed_${esc(file.name)}" class="action-btn">TÉLÉCHARGER LE FICHIER</a>
                    </div>`;
                document.getElementById('compress-file').value = '';
            } catch (e) {
                console.error(e);
                resBox.innerHTML = `<div style="text-align:center; color:red;">Erreur de compression</div>`;
                document.getElementById('compress-file').value = '';
            }
        }
    },

    // Outil 5 : Convertisseur Image
    converter: {
        run: async () => {
            const file = document.getElementById('convert-file').files[0];
            if (!file) return;

            const resBox = document.getElementById('convert-result');
            resBox.style.display = 'block';
            const format = document.querySelector('input[name="convert-format"]:checked')?.value || 'jpeg';
            const formatNames = { 'png': 'PNG', 'jpg': 'JPG', 'jpeg': 'JPEG', 'webp': 'WEBP', 'bmp': 'BMP', 'svg': 'SVG', 'ico': 'ICO' };

            resBox.innerHTML = `<div style="text-align:center; padding:20px;"><div>Conversion en ${formatNames[format]}...</div><div style="color:#666; font-size:0.8rem;">${esc(file.name)}</div></div>`;

            const srcUrl = URL.createObjectURL(file);
            try {
                const img = new Image();
                await new Promise((resolve, reject) => {
                    img.onload = resolve;
                    img.onerror = () => reject(new Error('format source non lisible par ce navigateur'));
                    img.src = srcUrl;
                });

                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                if (format === 'ico') {
                    // Icône carrée (max 256 px) : on garde les proportions, fond transparent
                    const size = Math.min(Math.max(img.width, img.height), 256);
                    const scale = size / Math.max(img.width, img.height);
                    const w = Math.round(img.width * scale), h = Math.round(img.height * scale);
                    canvas.width = size; canvas.height = size;
                    ctx.drawImage(img, (size - w) / 2, (size - h) / 2, w, h);
                } else {
                    canvas.width = img.width; canvas.height = img.height;
                    // JPEG et BMP n'ont pas de transparence : fond blanc au lieu de noir
                    if (['jpg', 'jpeg', 'bmp'].includes(format)) {
                        ctx.fillStyle = '#ffffff';
                        ctx.fillRect(0, 0, canvas.width, canvas.height);
                    }
                    ctx.drawImage(img, 0, 0);
                }

                const toBlob = (mime, quality) => new Promise((resolve, reject) => canvas.toBlob(b => {
                    // Un navigateur qui ne sait pas encoder ce format renvoie du PNG en silence
                    if (!b || b.type !== mime) reject(new Error(`ce navigateur ne sait pas produire du ${mime}`));
                    else resolve(b);
                }, mime, quality));

                let blob;
                if (format === 'svg') {
                    blob = new Blob([`<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${canvas.width}" height="${canvas.height}"><image width="${canvas.width}" height="${canvas.height}" href="${canvas.toDataURL('image/png')}" xlink:href="${canvas.toDataURL('image/png')}"/></svg>`], { type: 'image/svg+xml' });
                } else if (format === 'bmp') {
                    blob = encodeBmp(ctx.getImageData(0, 0, canvas.width, canvas.height));
                } else if (format === 'ico') {
                    blob = wrapPngInIco(await toBlob('image/png'), canvas.width, canvas.height);
                } else {
                    const mime = format === 'jpg' ? 'image/jpeg' : `image/${format}`;
                    blob = await toBlob(mime, 0.95);
                }
                const url = URL.createObjectURL(blob);

                const newFileName = `${file.name.replace(/\.[^/.]+$/, '')}.${format}`;

                resBox.innerHTML = `
                    <div class="result-container-centered">
                        <div class="result-success-header">CONVERSION RÉUSSIE</div>
                        <div class="conversion-flow">
                            <div class="stat-box" style="min-width:120px;"><div class="stat-label-sm">SOURCE (${esc(file.type.split('/')[1]?.toUpperCase() || 'UNK')})</div><div class="stat-value-lg">${formatSize(file.size)}</div></div>
                            <div class="flow-arrow">→</div>
                            <div class="stat-box highlight" style="min-width:120px;"><div class="stat-label-sm">SORTIE (${formatNames[format]})</div><div class="stat-value-lg" style="color:var(--accent);">${formatSize(blob.size)}</div></div>
                        </div>
                        <div class="result-file-info">${esc(newFileName)}</div>
                        <a href="${url}" download="${esc(newFileName)}" class="action-btn">TÉLÉCHARGER ${formatNames[format]}</a>
                    </div>`;
            } catch (e) {
                resBox.innerHTML = `<div style="text-align:center; color:red;">Erreur de conversion : ${esc(e.message)}</div>`;
            } finally {
                URL.revokeObjectURL(srcUrl);
                document.getElementById('convert-file').value = '';
            }
        }
    },

    // Outil 6 : Scanner de fichier (VirusTotal)
    scanner: {
        run: async (input) => {
            const file = input.files[0];
            if (!file) return;
            const resBox = document.getElementById('scan-result');
            resBox.style.display = 'block';
            resBox.textContent = 'Calcul du hash SHA-256...';

            const buffer = await file.arrayBuffer();
            const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
            const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

            const header = `Fichier : <span style="color:#fff">${esc(file.name)}</span><br>SHA-256 : <span style="color:#fff; word-break:break-all;">${hashHex}</span><br><br>`;
            resBox.innerHTML = header + 'Interrogation de VirusTotal...';
            try {
                const data = await readApi(await fetch(`${API_URL}/virustotal/${hashHex}`));
                if (data.found) {
                    const s = data.stats;
                    const verdict = s.malicious > 0
                        ? '<b style="color:red">FICHIER DÉTECTÉ COMME MALVEILLANT</b>'
                        : (s.suspicious > 0 ? '<b style="color:orange">FICHIER SUSPECT</b>' : '<b style="color:lime">AUCUN MOTEUR NE LE DÉTECTE</b>');
                    resBox.innerHTML = header + `${verdict}<br><br>Malveillant : <b style="color:red">${s.malicious}</b> | Suspect : <b style="color:orange">${s.suspicious}</b> | Sain : <b style="color:lime">${s.harmless}</b> | Non détecté : <b style="color:#888">${s.undetected}</b>`;
                } else {
                    resBox.innerHTML = header + '<b style="color:orange">Fichier inconnu de VirusTotal.</b><br><span style="color:#888">Cela ne veut PAS dire qu\'il est sûr : il n\'a simplement jamais été analysé. Méfiance s\'il vient d\'une source douteuse.</span>';
                }
            } catch (e) {
                resBox.innerHTML = header + `<b style="color:red">Analyse impossible :</b> ${esc(e.message)}`;
            } finally {
                input.value = '';
            }
        }
    },

    // Outil 7 : Inspecteur d'URL (VirusTotal)
    url: {
        run: async () => {
            let url = document.getElementById('url-input').value.trim();
            const resBox = document.getElementById('url-result');
            if (!url) return;
            if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) url = 'https://' + url; // "exemple.com" -> "https://exemple.com"
            resBox.style.display = 'block';
            resBox.innerHTML = '<div style="text-align:center;">Analyse VirusTotal en cours...</div>';

            try {
                const data = await readApi(await fetch(`${API_URL}/url-info?url=${encodeURIComponent(url)}`));
                if (!data.found) {
                    resBox.innerHTML = `<div style="text-align:center;"><b style="color:orange">URL inconnue de VirusTotal.</b><br><span style="color:#888">Personne ne l'a encore analysée : ce n'est pas une garantie de sécurité. Un lien très récent est souvent un signal de phishing.</span><br><br><span style="color:#fff; word-break:break-all;">${esc(data.originalUrl)}</span></div>`;
                    return;
                }

                let vtGrid = '';
                if (data.virusTotal) {
                    const vt = data.virusTotal;
                    vtGrid = `
                        <div style="width:100%; margin-bottom:8px;">
                            <div class="stat-grid" style="grid-template-columns: repeat(4, 1fr); gap:4px;">
                                <div class="stat-box" style="padding:5px; ${vt.malicious > 0 ? 'border-color:red; background:rgba(255,0,0,0.1);' : ''}">
                                    <div class="stat-label-sm" style="font-size:0.65rem; margin-bottom:2px;">MALVEILLANT</div>
                                    <div class="stat-value-lg" style="font-size:1.1rem; color:${vt.malicious > 0 ? 'red' : '#444'};">${vt.malicious}</div>
                                </div>
                                <div class="stat-box" style="padding:5px; ${vt.suspicious > 0 ? 'border-color:orange; background:rgba(255,165,0,0.1);' : ''}">
                                    <div class="stat-label-sm" style="font-size:0.65rem; margin-bottom:2px;">SUSPECT</div>
                                    <div class="stat-value-lg" style="font-size:1.1rem; color:${vt.suspicious > 0 ? 'orange' : '#444'};">${vt.suspicious}</div>
                                </div>
                                <div class="stat-box" style="padding:5px;">
                                    <div class="stat-label-sm" style="font-size:0.65rem; margin-bottom:2px;">SAIN</div>
                                    <div class="stat-value-lg" style="font-size:1.1rem; color:lime;">${vt.harmless}</div>
                                </div>
                                <div class="stat-box" style="padding:5px;">
                                    <div class="stat-label-sm" style="font-size:0.65rem; margin-bottom:2px;">NON TESTÉ</div>
                                    <div class="stat-value-lg" style="font-size:1.1rem; color:#666;">${vt.undetected}</div>
                                </div>
                            </div>
                        </div>`;
                }

                resBox.innerHTML = `
                    <div class="result-container-centered" style="padding:0;">
                        <div style="margin-bottom:8px; font-weight:bold; letter-spacing:1px; color:${esc(data.riskColor)};">VERDICT : ${esc(data.riskLevel)}</div>
                        ${vtGrid}
                        <div style="background:#111; border:1px solid #333; border-radius:6px; padding:15px; width:100%; margin-top:5px;">
                            <div style="display:grid; grid-template-columns: auto 1fr; gap:8px 15px; font-size:0.95rem; align-items:center;">
                                <div style="color:#888; text-align:right; font-weight:bold; font-size:0.8rem;">CIBLE</div>
                                <div style="color:#fff; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:250px;" title="${esc(data.originalUrl)}">${esc(data.originalUrl)}</div>
                                <div style="color:#888; text-align:right; font-weight:bold; font-size:0.8rem;">DEST.</div>
                                <div style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:250px; color:#fff;" title="${esc(data.finalUrl)}">${esc(data.finalUrl)}</div>
                                <div style="color:#888; text-align:right; font-weight:bold; font-size:0.8rem;">HTTP</div>
                                <div><b style="color:${data.statusCode && data.statusCode < 400 ? 'lime' : 'red'}">${esc(data.statusCode || 'N/A')}</b></div>
                            </div>
                        </div>
                    </div>`;
            } catch (e) {
                resBox.innerHTML = `<div style="text-align:center; color:red;">Analyse impossible : ${esc(e.message)}</div>`;
            }
        }
    },

    // Outil 8 : Générateur de Mot de Passe
    pass: {
        run: () => {
            const len = document.getElementById('pass-len').value;
            const useUpper = document.getElementById('pass-upper').checked;
            const useLower = document.getElementById('pass-lower').checked;
            const useNums = document.getElementById('pass-nums').checked;
            const useSyms = document.getElementById('pass-syms').checked;
            let chars = '';
            if (useUpper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            if (useLower) chars += 'abcdefghijklmnopqrstuvwxyz';
            if (useNums) chars += '0123456789';
            if (useSyms) chars += '!@#$%^&*()_+~`|}{[]:;?><,./-=';

            if (chars === '') {
                document.getElementById('cyber-popup-msg').textContent = 'Impossible : Vous devez cocher au moins une option.';
                document.getElementById('cyber-popup').style.display = 'flex';
                return;
            }

            // Tirage sans biais : on rejette les valeurs au-delà du plus grand multiple de chars.length
            // (un simple modulo favoriserait légèrement les premiers caractères)
            const limit = Math.floor(0x100000000 / chars.length) * chars.length;
            const randomIndex = () => {
                const buf = new Uint32Array(1);
                do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
                return buf[0] % chars.length;
            };
            let res = '';
            for (let i = 0; i < len; i++) {
                res += chars.charAt(randomIndex());
            }

            document.getElementById('pass-result-box').style.display = 'flex';
            document.getElementById('pass-result-text').textContent = res;

            let score = 0;
            if (res.length >= 12) score++;
            if (useUpper && /[A-Z]/.test(res)) score++;
            if (useLower && /[a-z]/.test(res)) score++;
            if (useNums && /[0-9]/.test(res)) score++;
            if (useSyms && /[^A-Za-z0-9]/.test(res)) score++;
            let color = 'red', txt = 'FAIBLE';
            if (score >= 4) { color = 'lime'; txt = 'EXCELLENT'; }
            else if (score >= 3) { color = '#ffffff'; txt = 'FORT'; }
            else if (score >= 2) { color = 'orange'; txt = 'MOYEN'; }
            document.getElementById('pass-gen-strength-label').innerHTML = `<span style="color:${color}">SÉCURITÉ: ${txt}</span>`;
        },
        copy: () => {
            const pwd = document.getElementById('pass-result-text').textContent;
            if (pwd) {
                navigator.clipboard.writeText(pwd);
                const btn = document.querySelector('#pass-result-box button');
                const original = btn.innerHTML;
                btn.innerHTML = '✓'; btn.style.color = '#ffffff';
                setTimeout(() => { btn.innerHTML = original; btn.style.color = ''; }, 2000);
            }
        },
        check: () => {
            const val = document.getElementById('pass-test-input').value;
            const resBox = document.getElementById('pass-test-result');
            if (!val) { resBox.style.display = 'none'; return; }
            resBox.style.display = 'block';
            let score = 0;
            if (val.length >= 8) score++; if (val.length >= 12) score++; if (/[A-Z]/.test(val)) score++; if (/[0-9]/.test(val)) score++; if (/[^A-Za-z0-9]/.test(val)) score++;
            let msg = 'TRÈS FAIBLE', color = 'red';
            if (score >= 5) { msg = 'TRÈS FORT'; color = 'lime'; } else if (score >= 4) { msg = 'FORT'; color = '#ffffff'; } else if (score >= 2) { msg = 'MOYEN'; color = 'orange'; }
            resBox.innerHTML = `<span style="color:${color}">${msg}</span>`;
        }
    },

    // Outil 9 : Vérification de fuite de données
    breach: {
        run: async () => {
            const email = document.getElementById('breach-input').value.trim();
            const resBox = document.getElementById('breach-result');
            if (!email) return;
            resBox.style.display = 'block';
            resBox.textContent = 'Recherche dans les fuites de données...';

            try {
                // POST : l'email ne se retrouve ni dans l'URL, ni dans l'historique, ni dans les logs
                const data = await readApi(await fetch(`${API_URL}/breach`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email })
                }));
                const list = data.breaches || [];
                if (list.length === 0) {
                    resBox.innerHTML = '<b style="color:lime">Aucune fuite connue pour cet email.</b><br><span style="color:#888">Seules les fuites publiques recensées sont vérifiées.</span>';
                } else {
                    resBox.innerHTML = `<b style="color:red">Trouvé dans ${list.length} fuite(s) :</b><br><br>`
                        + list.map(b => `<div>- <b style="color:#fff">${esc(b.Name)}</b> (${esc(b.BreachDate)})<div style="color:#888; font-size:0.85rem; margin:2px 0 8px 12px;">${esc(b.Description)}</div></div>`).join('')
                        + '<br><span style="color:orange">Changez le mot de passe de ces comptes et de tous ceux où vous l\'avez réutilisé, puis activez la double authentification.</span>';
                }
            } catch (e) {
                resBox.innerHTML = `<b style="color:red">Vérification impossible :</b> ${esc(e.message)}`;
            }
        }
    },

    // Outil 10 : Générateur QR Code
    qrcode: {
        run: () => {
            const txt = document.getElementById('qr-input').value;
            const resBox = document.getElementById('qr-result');
            if (!txt) return;
            resBox.innerHTML = ''; resBox.style.display = 'block';
            try {
                new QRCode(resBox, { text: txt, width: 256, height: 256 });
            } catch (e) {
                resBox.innerHTML = '<div style="color:red;">Texte trop long pour un QR code.</div>';
            }
        }
    }
};

window.app = app;
window.tools = tools;

// Listeners pour l'interface utilisateur
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.check-label input[type="checkbox"]').forEach(input => {
        input.addEventListener('change', function () {
            const label = this.closest('.check-label');
            if (label) this.checked ? label.classList.add('checked') : label.classList.remove('checked');
        });
        if (input.checked) input.closest('.check-label')?.classList.add('checked');
    });

    document.querySelectorAll('.check-label input[type="radio"]').forEach(input => {
        input.addEventListener('change', function () {
            document.querySelectorAll(`input[name="${this.name}"]`).forEach(radio => radio.closest('.check-label')?.classList.remove('checked'));
            if (this.checked) this.closest('.check-label')?.classList.add('checked');
        });
        if (input.checked) input.closest('.check-label')?.classList.add('checked');
    });
});
