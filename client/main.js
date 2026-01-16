/* AEGIS Vanilla JS Logic (FR) */

// App Navigation
const app = {
    navigate: (viewName) => {
        // Hide all views
        document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
        // Show target view
        const target = document.getElementById(`view-${viewName}`);
        if (target) {
            target.classList.add('active');
            // If navigating to IP, auto-run it
            if (viewName === 'ip') tools.ip.init();
        }

        // Update Dock Active State
        document.querySelectorAll('.dock-item').forEach(el => el.classList.remove('active'));
        // Find dock item
        const btns = document.querySelectorAll(`.dock-item[onclick*="'${viewName}'"]`);
        if (btns.length > 0) btns[0].classList.add('active');
    },
    // Init Dashboard Widget
    initDashboard: async () => {
        try {
            const res = await fetch(`${API_URL}/ip`);
            const data = await res.json();
            const dashIp = document.getElementById('dash-ip');
            if (dashIp) dashIp.textContent = data.query;
        } catch (e) { /* silent fail */ }
    }
};

// Auto run dash init
setTimeout(app.initDashboard, 500);

const API_URL = 'http://localhost:3000/api';

// Tool Implementations
const tools = {

    // 1. IP Analyzer
    ip: {
        init: async () => {
            const container = document.getElementById('ip-results');
            container.innerHTML = '<div style="grid-column: 1/-1; text-align:center;">Analyse directe de VOTRE connexion...</div>';
            try {
                // Fetch Client-Side to get User's IP directly
                const res = await fetch('https://ipwho.is/');
                const data = await res.json();

                if (!data.success) throw new Error(data.message);

                const fields = [
                    // Network Identity
                    { label: 'VOTRE IP PUBLIQUE', value: data.ip },
                    { label: 'Fournisseur (ISP)', value: data.connection.isp },
                    { label: 'Organisation', value: data.connection.org },
                    { label: 'Localisation', value: `${data.city}, ${data.country}` },

                    // Local Machine Identity
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

    // 2. WHOIS
    whois: {
        run: async () => {
            const domain = document.getElementById('whois-input').value;
            const resBox = document.getElementById('whois-result');
            if (!domain) return;

            resBox.style.display = 'block';
            resBox.textContent = 'Interrogation du registre...';

            try {
                const res = await fetch(`${API_URL}/whois/${domain}`);
                const data = await res.json();
                resBox.textContent = data.data || JSON.stringify(data, null, 2);
            } catch (e) {
                resBox.textContent = 'Erreur lors de la récupération WHOIS.';
            }
        }
    },

    // 3. EXIF
    exif: {
        currentFile: null,
        handleFile: (input) => {
            if (input.files[0]) {
                tools.exif.currentFile = input.files[0];
                const resBox = document.getElementById('exif-data');
                const btn = document.getElementById('exif-clean-btn');
                const nameDisplay = document.getElementById('exif-filename');

                nameDisplay.textContent = "Fichier: " + input.files[0].name;

                // Read EXIF
                EXIF.getData(input.files[0], function () {
                    const allTags = EXIF.getAllTags(this);
                    resBox.style.display = 'block';
                    if (Object.keys(allTags).length > 0) {
                        let txt = '';
                        // Simple dump
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
                    const dlDiv = document.getElementById('exif-download');
                    dlDiv.innerHTML = `<a href="${url}" download="clean_${f.name}" class="action-btn" style="text-decoration:none; display:inline-block; margin-top:10px; background:#fff; color:#000;">TÉLÉCHARGER L'IMAGE PROPRE</a>`;
                }, f.type);
            };
        }
    },

    // 4. Sanitizer
    sanitizer: {
        run: () => {
            const input = document.getElementById('san-input').value;
            // Remove zero width
            let clean = input.replace(/[\u200B-\u200D\uFEFF]/g, '');
            // Normalize
            clean = clean.normalize('NFKC');
            document.getElementById('san-output').value = clean;
        }
    },

    // 5. Compressor
    compress: {
        run: async () => {
            const file = document.getElementById('compress-file').files[0];
            if (!file) return;

            const resBox = document.getElementById('compress-result');
            resBox.style.display = 'block';
            resBox.textContent = 'Compression en cours...';

            try {
                const options = { maxSizeMB: 1, useWebWorker: true };
                const compressed = await imageCompression(file, options);

                const reduction = ((1 - compressed.size / file.size) * 100).toFixed(1);
                const url = URL.createObjectURL(compressed);

                resBox.innerHTML = `
                    <p>Original : ${(file.size / 1024 / 1024).toFixed(2)} MB</p>
                    <p style="color:#fff">Nouveau : ${(compressed.size / 1024 / 1024).toFixed(2)} MB (-${reduction}%)</p>
                    <br>
                    <a href="${url}" download="min_${file.name}" class="action-btn" style="text-decoration:none; display:inline-block; background:#fff; color:#000;">TÉLÉCHARGER</a>
                `;
            } catch (e) {
                resBox.textContent = 'Erreur: ' + e.message;
            }
        }
    },

    // 6. File Scanner
    scanner: {
        run: async (input) => {
            const file = input.files[0];
            if (!file) return;

            const resBox = document.getElementById('scan-result');
            resBox.style.display = 'block';
            resBox.textContent = 'Calcul du hash SHA-256...';

            // Calc Hash
            const buffer = await file.arrayBuffer();
            const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

            resBox.innerHTML = `SHA-256 : <span style="color:#fff">${hashHex}</span><br><br>Interrogation de VirusTotal...`;

            // API Call
            try {
                const res = await fetch(`${API_URL}/virustotal/${hashHex}`);
                const data = await res.json();

                if (data.data && data.data.attributes) {
                    const stats = data.data.attributes.last_analysis_stats;
                    resBox.innerHTML += `
                        <br><br>
                        Malveillant : <b style="color:red">${stats.malicious}</b> | 
                        Suspect : <b style="color:orange">${stats.suspicious}</b> | 
                        Sûr : <b style="color:lime">${stats.harmless}</b>
                    `;
                } else {
                    resBox.innerHTML += `<br><br>Fichier inconnu de la base de données (Probablement sûr ou trop récent).`;
                }
            } catch (e) {
                resBox.innerHTML += `<br>Erreur de contact avec l'API VirusTotal`;
            }
        }
    },

    // 7. URL Inspector
    url: {
        run: async () => {
            const url = document.getElementById('url-input').value;
            const resBox = document.getElementById('url-result');
            if (!url) return;

            resBox.style.display = 'block';
            resBox.textContent = 'Analyse de la chaîne de redirection...';

            try {
                const res = await fetch(`${API_URL}/url-info?url=${encodeURIComponent(url)}`);
                const data = await res.json();
                resBox.innerHTML = `
                    Status Code : <b>${data.statusCode}</b><br>
                    URL Finale : <a href="${data.finalUrl}" target="_blank" style="color:#fff">${data.finalUrl}</a><br>
                    Serveur : ${data.server}
                `;
            } catch (e) {
                resBox.textContent = 'Erreur lors de l\'analyse de l\'URL';
            }
        }
    },

    // 8. Password
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
                alert('Sélectionnez au moins une option !');
                return;
            }

            let res = '';
            for (let i = 0; i < len; i++) {
                const randomVal = window.crypto.getRandomValues(new Uint32Array(1))[0];
                res += chars.charAt(randomVal % chars.length);
            }

            // UI Updates
            document.getElementById('pass-result-box').style.display = 'flex';
            document.getElementById('pass-result-text').textContent = res;

            // Strength
            let score = 0;
            if (res.length >= 12) score++;
            if (useUpper && /[A-Z]/.test(res)) score++;
            if (useLower && /[a-z]/.test(res)) score++;
            if (useNums && /[0-9]/.test(res)) score++;
            if (useSyms && /[^A-Za-z0-9]/.test(res)) score++;

            let color = 'red';
            let txt = 'FAIBLE';
            if (score >= 4) { color = 'lime'; txt = 'EXCELLENT'; }
            else if (score >= 3) { color = '#00ff80'; txt = 'FORT'; }
            else if (score >= 2) { color = 'orange'; txt = 'MOYEN'; }

            document.getElementById('pass-gen-strength-label').innerHTML = `<span style="color:${color}">SÉCURITÉ: ${txt}</span>`;
        },
        copy: () => {
            const pwd = document.getElementById('pass-result-text').textContent;
            if (pwd) {
                navigator.clipboard.writeText(pwd);
                // Feedback on button
                const btn = document.querySelector('#pass-result-box button');
                const original = btn.innerHTML;
                btn.innerHTML = '✓';
                btn.style.color = '#00ff80';
                setTimeout(() => {
                    btn.innerHTML = original;
                    btn.style.borderColor = ''; // reset to stylesheet
                    btn.style.color = '';
                }, 2000);
            }
        },
        check: () => {
            const val = document.getElementById('pass-test-input').value;
            const resBox = document.getElementById('pass-test-result');
            if (!val) {
                resBox.style.display = 'none';
                return;
            }
            resBox.style.display = 'block';

            let score = 0;
            if (val.length >= 8) score++;
            if (val.length >= 12) score++;
            if (/[A-Z]/.test(val)) score++;
            if (/[0-9]/.test(val)) score++;
            if (/[^A-Za-z0-9]/.test(val)) score++; // Special char

            let msg = '';
            let color = '';

            if (score < 2) { msg = 'TRÈS FAIBLE (Inutilisable)'; color = 'red'; }
            else if (score < 4) { msg = 'MOYEN (Peut mieux faire)'; color = 'orange'; }
            else if (score < 5) { msg = 'FORT (Bon)'; color = '#00ff80'; }
            else { msg = 'TRÈS FORT (Excellent)'; color = 'lime'; }

            resBox.innerHTML = `<span style="color:${color}">${msg}</span>`;
        }
    },

    // 9. Breach
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
                    resBox.innerHTML = `<b style="color:red">Trouvé dans ${data.length} fuite(s) de données :</b><br><br>` +
                        data.map(b => `<div>- ${b.Name} (${b.BreachDate})</div>`).join('');
                }
            } catch (e) {
                resBox.textContent = 'Erreur lors de la vérification.';
            }
        }
    },

    // 10. QR Code
    qrcode: {
        run: () => {
            const txt = document.getElementById('qr-input').value;
            const resBox = document.getElementById('qr-result');

            if (!txt) return;

            resBox.innerHTML = '';
            resBox.style.display = 'block';

            // Generate
            new QRCode(resBox, {
                text: txt,
                width: 256,
                height: 256
            });
        }
    }
};

// Expose to window for HTML onclick handlers
window.app = app;
window.tools = tools;
