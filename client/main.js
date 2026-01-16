/* AEGIS Logic - JavaScript Vanilla */

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
        try {
            const res = await fetch('https://ipwho.is/');
            const data = await res.json();
            const dashIp = document.getElementById('dash-ip');
            if (dashIp) dashIp.textContent = data.ip;
        } catch (e) { /* echec silencieux */ }
    }
};

setTimeout(app.initDashboard, 500);

const API_URL = '/api';

const tools = {
    // Outil 1 : Analyse IP (Client-side)
    ip: {
        init: async () => {
            const container = document.getElementById('ip-results');
            container.innerHTML = '<div style="grid-column: 1/-1; text-align:center;">Analyse directe de VOTRE connexion...</div>';
            try {
                const res = await fetch('https://ipwho.is/');
                const data = await res.json();

                if (!data.success) throw new Error(data.message);

                const fields = [
                    { label: 'VOTRE IP PUBLIQUE', value: data.ip },
                    { label: 'Fournisseur (ISP)', value: data.connection.isp },
                    { label: 'Organisation', value: data.connection.org },
                    { label: 'Localisation', value: `${data.city}, ${data.country}` },
                    { label: 'Système', value: navigator.platform },
                    { label: 'Navigateur', value: navigator.userAgent.includes('Chrome') ? 'Chrome/Chromium' : 'Autre (Firefox/Safari)' },
                ];

                container.innerHTML = fields.map(f => `
                    <div style="background:#000; padding:1.5rem; border:1px solid #333; border-radius:6px; position:relative;">
                        <div style="color:#888; font-size:0.75rem; text-transform:uppercase; margin-bottom:0.5rem;">${f.label}</div>
                        <div style="font-size:1.1rem; color:#fff; font-weight:600; word-break:break-all;">
                            ${f.value || 'N/A'}
                            ${f.copy ? `<button onclick="navigator.clipboard.writeText('${f.value}'); alert('IP Copiée !')" style="margin-left:10px; padding:4px 8px; font-size:0.7rem; background:#333; color:#fff; border:none; border-radius:4px; cursor:pointer;">COPIER</button>` : ''}
                        </div>
                    </div>
                `).join('');
            } catch (e) {
                container.innerHTML = '<div style="color:red">Impossible de récupérer les données IP (Bloqueur de pub ?).</div>';
            }
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
                    document.getElementById('exif-download').innerHTML = `<a href="${url}" download="clean_${f.name}" class="action-btn" style="text-decoration:none; display:inline-block; margin-top:10px; background:#fff; color:#000;">TÉLÉCHARGER L'IMAGE PROPRE</a>`;
                }, f.type);
            };
        }
    },

    // Outil 3 : Nettoyeur de texte (Sanitizer)
    sanitizer: {
        run: () => {
            const input = document.getElementById('san-input').value;
            let clean = input.replace(/[\u200B-\u200D\uFEFF]/g, '').normalize('NFKC');
            document.getElementById('san-output').value = clean;
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

            resBox.innerHTML = `<div style="text-align:center; padding:20px;"><div>Compression ${fileType}...</div><div style="color:#666; font-size:0.8rem;">${file.name}</div><div style="color:#ffffff; font-size:0.7rem;">Mode: ${modeLabels[mode]}</div></div>`;

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
                    let options = { useWebWorker: true };
                    switch (mode) {
                        case 'quality': options = { ...options, maxSizeMB: 50, initialQuality: 1, alwaysKeepResolution: true }; break;
                        case 'balanced': options = { ...options, maxSizeMB: 0.5, maxWidthOrHeight: 1600, initialQuality: 0.6 }; break;
                        case 'max': options = { ...options, maxSizeMB: 0.15, maxWidthOrHeight: 800, initialQuality: 0.4 }; break;
                    }
                    compressed = await imageCompression(file, options);
                    url = URL.createObjectURL(compressed);
                }

                const newSize = compressed.size;
                const reduction = ((1 - newSize / originalSize) * 100).toFixed(1);
                const saved = originalSize - newSize;
                const formatSize = (bytes) => (bytes >= 1048576) ? (bytes / 1048576).toFixed(2) + ' MB' : (bytes / 1024).toFixed(1) + ' KB';

                let reductionColor = reduction < 10 ? '#888' : (reduction < 30 ? '#00ff80' : 'lime');

                resBox.innerHTML = `
                    <div class="result-container-centered">
                        <div class="result-success-header">COMPRESSION ${fileType} TERMINÉE</div>
                        <div class="stat-grid" style="width:100%;">
                            <div class="stat-box"><div class="stat-label-sm">ORIGINAL</div><div class="stat-value-lg">${formatSize(originalSize)}</div></div>
                            <div class="stat-box"><div class="stat-label-sm">COMPRESSÉ</div><div class="stat-value-lg" style="color:#fff;">${formatSize(newSize)}</div></div>
                            <div class="stat-box highlight" style="border-color:${reductionColor}; background:rgba(0,255,128,0.1);"><div class="stat-label-sm">RÉDUCTION</div><div class="stat-value-lg" style="color:${reductionColor};">-${reduction}%</div></div>
                        </div>
                        <div class="result-file-info">${file.name} — <span style="color:#fff">${saved > 0 ? formatSize(saved) + ' économisés' : 'Optimisation maximale'}</span></div>
                        <a href="${url}" download="compressed_${file.name}" class="action-btn">TÉLÉCHARGER LE FICHIER</a>
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
            const formatNames = { 'png': 'PNG', 'jpg': 'JPG', 'jpeg': 'JPEG', 'webp': 'WEBP', 'gif': 'GIF', 'bmp': 'BMP', 'svg': 'SVG', 'ico': 'ICO' };
            const formatExtensions = { 'png': 'png', 'jpg': 'jpg', 'jpeg': 'jpeg', 'webp': 'webp', 'gif': 'gif', 'bmp': 'bmp', 'svg': 'svg', 'ico': 'ico' };

            resBox.innerHTML = `<div style="text-align:center; padding:20px;"><div>Conversion en ${formatNames[format]}...</div><div style="color:#666; font-size:0.8rem;">${file.name}</div></div>`;

            try {
                const img = new Image();
                img.src = URL.createObjectURL(file);
                await new Promise((resolve) => { img.onload = resolve; });

                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                if (format === 'ico') {
                    const size = Math.min(img.width, img.height, 256);
                    canvas.width = size; canvas.height = size;
                    ctx.drawImage(img, 0, 0, size, size);
                } else {
                    canvas.width = img.width; canvas.height = img.height;
                    ctx.drawImage(img, 0, 0);
                }

                let blob, url;
                if (format === 'svg') {
                    blob = new Blob([`<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg" width="${canvas.width}" height="${canvas.height}"><image width="${canvas.width}" height="${canvas.height}" xlink:href="${canvas.toDataURL('image/png')}"/></svg>`], { type: 'image/svg+xml' });
                    url = URL.createObjectURL(blob);
                } else {
                    let mime = `image/${format === 'jpg' ? 'jpeg' : (format === 'ico' || format === 'bmp' ? 'png' : format)}`; // fallback mime
                    if (format === 'bmp') mime = 'image/bmp';
                    blob = await new Promise(r => canvas.toBlob(r, mime, 1));
                    if (!blob) throw new Error('Echec blob');
                    url = URL.createObjectURL(blob);
                }

                const newFileName = `${file.name.replace(/\.[^/.]+$/, '')}.${formatExtensions[format]}`;
                const formatSize = (b) => (b >= 1048576) ? (b / 1048576).toFixed(2) + ' MB' : (b / 1024).toFixed(1) + ' KB';

                resBox.innerHTML = `
                    <div class="result-container-centered">
                        <div class="result-success-header">CONVERSION RÉUSSIE</div>
                        <div class="conversion-flow">
                            <div class="stat-box" style="min-width:120px;"><div class="stat-label-sm">SOURCE (${file.type.split('/')[1]?.toUpperCase() || 'UNK'})</div><div class="stat-value-lg">${formatSize(file.size)}</div></div>
                            <div class="flow-arrow">→</div>
                            <div class="stat-box highlight" style="min-width:120px;"><div class="stat-label-sm">SORTIE (${formatNames[format]})</div><div class="stat-value-lg" style="color:var(--accent);">${formatSize(blob.size)}</div></div>
                        </div>
                        <div class="result-file-info">${newFileName}</div>
                        <a href="${url}" download="${newFileName}" class="action-btn">TÉLÉCHARGER ${formatNames[format]}</a>
                    </div>`;
                document.getElementById('convert-file').value = '';
            } catch (e) {
                resBox.innerHTML = `<div style="text-align:center; color:red;">Erreur de conversion : ${e.message}</div>`;
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

            resBox.innerHTML = `SHA-256 : <span style="color:#fff">${hashHex}</span><br><br>Interrogation de VirusTotal...`;
            try {
                const res = await fetch(`${API_URL}/virustotal/${hashHex}`);
                const data = await res.json();
                if (data.data && data.data.attributes) {
                    const stats = data.data.attributes.last_analysis_stats;
                    resBox.innerHTML += `<br><br>Malveillant : <b style="color:red">${stats.malicious}</b> | Suspect : <b style="color:orange">${stats.suspicious}</b> | Sûr : <b style="color:lime">${stats.harmless}</b>`;
                } else {
                    resBox.innerHTML += `<br><br>Fichier inconnu (Probablement sûr).`;
                }
            } catch (e) {
                resBox.innerHTML += `<br>Erreur API VirusTotal`;
            }
        }
    },

    // Outil 7 : Inspecteur d'URL (VirusTotal)
    url: {
        run: async () => {
            const url = document.getElementById('url-input').value;
            const resBox = document.getElementById('url-result');
            if (!url) return;
            resBox.style.display = 'block';
            resBox.innerHTML = '<div style="text-align:center;">Analyse VirusTotal en cours...</div>';

            try {
                const res = await fetch(`${API_URL}/url-info?url=${encodeURIComponent(url)}`);
                const data = await res.json();
                if (data.error) {
                    resBox.innerHTML = `<div style="text-align:center; color:red;">${data.error}</div>`;
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
                                    <div class="stat-label-sm" style="font-size:0.65rem; margin-bottom:2px;">SÛR</div>
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
                        ${vtGrid}
                        <div style="background:#111; border:1px solid #333; border-radius:6px; padding:15px; width:100%; margin-top:5px;">
                            <div style="display:grid; grid-template-columns: auto 1fr; gap:8px 15px; font-size:0.95rem; align-items:center;">
                                <div style="color:#888; text-align:right; font-weight:bold; font-size:0.8rem;">CIBLE</div>
                                <div style="color:#fff; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:250px;" title="${data.originalUrl}">${data.originalUrl}</div>
                                <div style="color:#888; text-align:right; font-weight:bold; font-size:0.8rem;">DEST.</div>
                                <div style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:250px;"><a href="${data.finalUrl}" target="_blank" style="color:#ffffff; text-decoration:underline;" title="${data.finalUrl}">${data.finalUrl}</a></div>
                                <div style="color:#888; text-align:right; font-weight:bold; font-size:0.8rem;">HTTP</div>
                                <div><b style="color:${data.statusCode < 400 ? 'lime' : 'red'}">${data.statusCode}</b></div>
                            </div>
                        </div>
                        ${(data.warnings && data.warnings.length > 0) ? `<div style="margin-top:8px; padding:8px; background:rgba(255,165,0,0.1); border:1px solid orange; border-radius:4px; width:100%;"><div style="color:orange; font-weight:bold; margin-bottom:2px; font-size:0.75rem;">⚠️ ALERTES</div>${data.warnings.map(w => `<div style="color:#ccc; font-size:0.85rem;">${w}</div>`).join('')}</div>` : ''}
                    </div>`;
            } catch (e) {
                resBox.innerHTML = '<div style="text-align:center; color:red;">Erreur lors de l\'analyse de l\'URL</div>';
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

            let res = '';
            for (let i = 0; i < len; i++) {
                res += chars.charAt(window.crypto.getRandomValues(new Uint32Array(1))[0] % chars.length);
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
            const email = document.getElementById('breach-input').value;
            const resBox = document.getElementById('breach-result');
            resBox.style.display = 'block';
            resBox.textContent = 'Recherche dans les fuites de données...';

            try {
                const res = await fetch(`${API_URL}/breach/${email}`);
                const data = await res.json();
                if (data.length === 0) {
                    resBox.innerHTML = '<b style="color:lime">Aucune fuite trouvée pour cet email.</b>';
                } else {
                    resBox.innerHTML = `<b style="color:red">Trouvé dans ${data.length} fuite(s) :</b><br><br>` + data.map(b => `<div>- ${b.Name} (${b.BreachDate})</div>`).join('');
                }
            } catch (e) {
                resBox.textContent = 'Erreur lors de la vérification.';
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
            new QRCode(resBox, { text: txt, width: 256, height: 256 });
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
