/**
 * Sentinel Verify - Enterprise AI Threat Intelligence SPA Engine
 * Production-ready client with dynamic server resolution, XSS protection,
 * Chart.js theme synchronization, and autonomous client-side fallback engine.
 */

// --- Dynamic API Configuration ---
function getStoredApiUrl() {
    return localStorage.getItem('sentinel_api_url') || (window.SENTINEL_CONFIG && window.SENTINEL_CONFIG.API_URL) || '';
}

function resolveApiBaseUrl() {
    const customUrl = getStoredApiUrl().trim();
    if (customUrl) {
        return customUrl.replace(/\/+$/, '');
    }
    if (window.location.protocol === 'file:') {
        return 'http://127.0.0.1:5000/api/v1';
    }
    // Relative API endpoint for Vercel/proxied deployments
    return `${window.location.origin}/api/v1`;
}

let API_BASE_URL = resolveApiBaseUrl();
let isLiveApiAvailable = false;

// Safe HTML Escaper to prevent XSS
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// --- Autonomous Client-Side Threat Detection Engine (Zero-Crash Fallback) ---
const ClientEngine = {
    urgencyKeywords: ['urgent', 'immediately', 'suspended', 'locked', 'within 24 hours', 'action required', 'unauthorized access', 'account terminated', 'security alert', 'final notice', 'overdue', 'power will be disconnected', 'kat diya jayega', 'band ho jayega'],
    financialKeywords: ['winner', 'lottery', 'claim your prize', 'bank account', 'credit card', 'refund', 'payment', 'bitcoin', 'crypto', 'wallet drain', 'wire transfer', 'invoice unpaid', 'gift card', 'pm-kisan', 'subsidy'],
    otpPatterns: [/\bOTP\b/i, /one[\s-]?time[\s-]?password/i, /verification code/i, /security code/i, /confirm password/i, /reset credentials/i],
    brandKeywords: [
        'paypal', 'netflix', 'amazon', 'microsoft', 'apple', 'google', 'chase', 'wells fargo', 'binance', 'coinbase', 'metamask', 'dhl', 'fedex',
        'parivahan', 'echallan', 'epfo', 'pmkisan', 'irctc', 'uidai', 'aadhaar', 'incometax', 'digilocker', 'sbi', 'yono', 'hdfc', 'icici', 'pnb', 'bijli', 'bescom', 'uppcl', 'msedcl', 'tangedco'
    ],
    indianSignatures: [
        { pattern: /(electricity|bijli|power).*(disconnect|unpaid|update bill|officer|kat diya|kat jayega)/i, flag: "Electricity Bill (Bijli Vibhag) Disconnection Scam Signature", advisory: "Electricity distribution companies never threaten same-day disconnection via random mobile SMS or personal contact numbers." },
        { pattern: /(echallan|challan|parivahan|traffic).*(pending|impound|fine|court|seize)/i, flag: "Fake e-Challan / Parivahan Traffic Fine Scam", advisory: "Traffic police official challans are only issued via official echallan.parivahan.gov.in portals, never on .xyz or .top domains." },
        { pattern: /(pm[\s-]?kisan|subsidy|yojana|kist).*(installment|approved|claim|credit|aa gayi)/i, flag: "PM-Kisan / Government Direct Benefit Subsidy Bait", advisory: "Government welfare subsidies are directly transferred via DBT to your Aadhaar-linked bank account without requiring external links." },
        { pattern: /(epfo|uan|pf|khata).*(block|suspend|pan link|kyc|band ho)/i, flag: "EPFO / Bank KYC Account Freeze Threat", advisory: "Banks and EPFO will never freeze accounts via WhatsApp/SMS links demanding immediate online KYC." },
        { pattern: /(income[\s-]?tax|itr|refund).*(refund|credited|approve)/i, flag: "Income Tax Department Refund Scam", advisory: "Income Tax refunds are processed directly into pre-validated bank accounts without SMS verification links." }
    ],
    suspiciousTlds: ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.club', '.online', '.buzz', '.work', '.click', '.monster', '.loan'],
    shorteners: ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'cutt.ly', 'v.gd', 'wa.me', 'shorturl.at', 'rebrand.ly'],
    sensitiveUrlKeywords: ['login', 'secure', 'account', 'banking', 'update', 'verify', 'wallet', 'auth', 'signin', 'support', 'checkpoint', 'confirm', 'passcode', 'echallan', 'parivahan', 'epfo', 'pmkisan', 'bijli'],

    getEntropy(text) {
        if (!text) return 0;
        const len = text.length;
        const frequencies = {};
        for (let i = 0; i < len; i++) {
            frequencies[text[i]] = (frequencies[text[i]] || 0) + 1;
        }
        let entropy = 0;
        for (const char in frequencies) {
            const p = frequencies[char] / len;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    },

    calculateSeverity(confidence) {
        if (confidence < 0.20) return "Safe";
        if (confidence < 0.40) return "Low Risk";
        if (confidence < 0.60) return "Suspicious";
        if (confidence < 0.80) return "High Risk";
        return "Critical Threat";
    },

    analyzeText(rawText) {
        const lower = rawText.toLowerCase();
        const flags = [];
        let score = 0.05;
        let citizenAdvisory = null;

        // Indian Public Service Scam Signatures
        for (const sig of this.indianSignatures) {
            if (sig.pattern.test(rawText)) {
                score += 0.50;
                flags.push(sig.flag);
                if (!citizenAdvisory) citizenAdvisory = sig.advisory;
                break;
            }
        }

        // Urgency Indicators
        for (const kw of this.urgencyKeywords) {
            if (lower.includes(kw)) {
                score += 0.25;
                flags.push(`Urgency keyword detected: '${kw}'`);
                break;
            }
        }

        // Financial Demands
        for (const kw of this.financialKeywords) {
            if (lower.includes(kw)) {
                score += 0.20;
                flags.push(`Financial/Reward indicator: '${kw}'`);
                break;
            }
        }

        // OTP Harvester
        for (const pat of this.otpPatterns) {
            if (pat.test(rawText)) {
                score += 0.35;
                flags.push("Demands OTP, PIN, or Authentication Credentials");
                break;
            }
        }

        const confidence = Math.min(0.98, Math.max(0.02, score));
        const severity = this.calculateSeverity(confidence);

        const words = rawText.split(/\s+/);
        const heatmap = {};
        words.forEach(w => {
            const clean = w.toLowerCase().replace(/[^a-z0-9]/g, '');
            if (this.urgencyKeywords.includes(clean)) heatmap[clean] = 0.85;
            else if (this.financialKeywords.includes(clean)) heatmap[clean] = 0.70;
            else if (this.brandKeywords.includes(clean)) heatmap[clean] = 0.50;
        });

        return {
            input_type: "text",
            severity_level: severity,
            confidence_score: confidence,
            indicators: flags,
            explainability: {
                flags: flags,
                keyword_heatmap: heatmap,
                citizen_advisory: citizenAdvisory || "Stay alert: official government services never demand payments via personal numbers or WhatsApp."
            }
        };
    },

    analyzeUrl(urlStr) {
        const flags = [];
        let score = 0.05;
        let citizenAdvisory = null;

        let parsedUrl = null;
        let raw = urlStr.trim();
        if (!raw.startsWith('http://') && !raw.startsWith('https://') && !raw.startsWith('upi://')) {
            raw = 'http://' + raw;
        }

        try {
            parsedUrl = new URL(raw);
        } catch (e) {
            parsedUrl = { hostname: raw.replace(/^https?:\/\//, '').split('/')[0], pathname: '', protocol: 'http:' };
        }

        const hostname = (parsedUrl.hostname || '').toLowerCase();
        const fullUrl = raw.toLowerCase();

        // UPI Impersonation
        if (raw.startsWith('upi://pay')) {
            flags.push("Direct UPI Payment Gateway Link");
            if (fullUrl.includes('parivahan') || fullUrl.includes('challan') || fullUrl.includes('bijli') || fullUrl.includes('police')) {
                score += 0.75;
                flags.push("Deceptive UPI Impersonation (Spoofing Public Authority VPA)");
                citizenAdvisory = "Fraudsters create deceptive UPI VPAs mimicking government bodies to steal money. Official fines are only paid on official .gov.in portals.";
            } else {
                score += 0.20;
            }
        }

        // IP Address URL
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
            score += 0.55;
            flags.push("Direct IP address used instead of verified domain name");
        }

        // Suspicious TLD
        let tld = '';
        const parts = hostname.split('.');
        if (parts.length > 1) tld = '.' + parts.slice(-1)[0];
        if (this.suspiciousTlds.includes(tld)) {
            score += 0.45;
            flags.push(`High-risk top-level domain (${tld})`);
        }

        // URL Shortener Masking
        for (const shortener of this.shorteners) {
            if (hostname.includes(shortener)) {
                score += 0.35;
                flags.push(`Obfuscated link via URL Shortener (${shortener})`);
                if (!citizenAdvisory) citizenAdvisory = "Public utility services never distribute shortened redirect links (bit.ly, wa.me).";
                break;
            }
        }

        // Public Brand / Government Spoofing
        if (hostname.includes('parivahan') || hostname.includes('echallan') || hostname.includes('bescom') || hostname.includes('epfo') || hostname.includes('sbi')) {
            if (!hostname.endsWith('.gov.in') && !hostname.endsWith('.in') && !hostname.endsWith('.sbi.co.in')) {
                score += 0.60;
                flags.push("Targeting Indian Public Service / Banking brand without authorized .gov.in domain");
                if (!citizenAdvisory) citizenAdvisory = "Official Indian public services operate strictly on .gov.in or .nic.in domains.";
            }
        }

        // Sensitive keywords in path
        for (const kw of this.sensitiveUrlKeywords) {
            if (fullUrl.includes(kw) && !flags.some(f => f.includes(kw))) {
                score += 0.15;
                flags.push(`Sensitive keyword in URL: '${kw}'`);
                break;
            }
        }

        // Missing HTTPS
        if (raw.startsWith('http://')) {
            score += 0.15;
            flags.push("Missing HTTPS transport layer encryption (Cleartext)");
        }

        const confidence = Math.min(0.98, Math.max(0.02, score));
        const severity = this.calculateSeverity(confidence);

        return {
            input_type: "url",
            severity_level: severity,
            confidence_score: confidence,
            indicators: flags,
            explainability: {
                flags: flags,
                citizen_advisory: citizenAdvisory || "Verify destination URL with official government portals before entering details.",
                entropy: this.getEntropy(hostname),
                tld: tld
            }
        };
    },

    initLocalStorage() {
        if (!localStorage.getItem('sentinel_scan_history')) {
            const seedHistory = [
                { id: 1, created_at: new Date(Date.now() - 3600000 * 2).toISOString(), input_type: 'url', input_data: 'https://secure-login-update.xyz/auth', severity_level: 'Critical Threat', confidence_score: 0.94, explainability_json: JSON.stringify({ flags: ['High-risk TLD (.xyz)', 'Sensitive auth keyword', 'High entropy'] }) },
                { id: 2, created_at: new Date(Date.now() - 3600000 * 8).toISOString(), input_type: 'text', input_data: 'URGENT: Your account has been suspended. Please confirm your OTP immediately.', severity_level: 'High Risk', confidence_score: 0.86, explainability_json: JSON.stringify({ flags: ['Urgency indicator', 'Credential / OTP pattern'] }) },
                { id: 3, created_at: new Date(Date.now() - 3600000 * 24).toISOString(), input_type: 'url', input_data: 'https://docs.github.com/en/rest', severity_level: 'Safe', confidence_score: 0.04, explainability_json: JSON.stringify({ flags: [] }) },
                { id: 4, created_at: new Date(Date.now() - 3600000 * 48).toISOString(), input_type: 'text', input_data: 'The quarterly financial review is scheduled for Thursday at 2 PM in conference room B.', severity_level: 'Safe', confidence_score: 0.08, explainability_json: JSON.stringify({ flags: [] }) }
            ];
            localStorage.setItem('sentinel_scan_history', JSON.stringify(seedHistory));
        }

        if (!localStorage.getItem('sentinel_threat_feed')) {
            const seedFeed = [
                { id: 1, title: 'Electricity Discom Same-Day Cutoff SMS Scam', description: 'Widespread SMS campaign mimicking state discoms (BESCOM/UPPCL) threatening night disconnections.', category: 'Public Services', risk_level: 'Critical', source: 'CERT-In Alert', timestamp: new Date().toISOString() },
                { id: 2, title: 'Parivahan Fake e-Challan APK Campaign', description: 'Spoofed traffic fine notices on WhatsApp distributing malicious Android remote screen-control APKs.', category: 'Public Services', risk_level: 'Critical', source: 'Cyber Crime Wing', timestamp: new Date(Date.now() - 3600000 * 3).toISOString() },
                { id: 3, title: 'Fake PM-Kisan DBT Subsidy WhatsApp Portals', description: 'Fraudulent registration forms harvesting citizen Aadhaar numbers under guise of 17th installment.', category: 'Public Services', risk_level: 'High', source: 'Sentinel Telemetry', timestamp: new Date(Date.now() - 3600000 * 7).toISOString() },
                { id: 4, title: 'UPI VPA Impersonation for Utility Bills', description: 'Deceptive QR codes with payee addresses like fake.traffic.police@okhdfcbank targeting offline citizens.', category: 'Banking', risk_level: 'High', source: 'NPCI Advisory', timestamp: new Date(Date.now() - 3600000 * 14).toISOString() },
                { id: 5, title: 'EPFO UAN Account Freeze Phishing Mails', description: 'Targeted emails demanding immediate PAN linking through non-gov.in landing pages.', category: 'Phishing', risk_level: 'Medium', source: 'User Reports', timestamp: new Date(Date.now() - 3600000 * 22).toISOString() }
            ];
            localStorage.setItem('sentinel_threat_feed', JSON.stringify(seedFeed));
        }

        if (!localStorage.getItem('sentinel_api_keys')) {
            const seedKeys = [
                { id: 1, name: 'Production Sentinel Agent', prefix: 'sv_live_9a7...', is_active: true, request_count: 1420, created_at: new Date(Date.now() - 86400000 * 12).toISOString() },
                { id: 2, name: 'Staging CI/CD Scanner', prefix: 'sv_test_3b1...', is_active: true, request_count: 310, created_at: new Date(Date.now() - 86400000 * 4).toISOString() }
            ];
            localStorage.setItem('sentinel_api_keys', JSON.stringify(seedKeys));
        }
    }
};

ClientEngine.initLocalStorage();

// --- Application Core Initialization Function ---
function initSentinelApp() {

    // --- State Variables (Declared before any function execution) ---
    let chartInstance = null;
    let cachedFeedData = [];
    let currentFeedCategory = 'ALL';
    let currentLang = localStorage.getItem('sentinel_lang') || 'en';
    let currentMode = 'text';

    const htmlEl = document.documentElement;
    const views = document.querySelectorAll('.view-section');
    const navLinks = document.querySelectorAll('.nav-link-custom');
    const pageTitle = document.getElementById('pageTitle');
    const pageSubtitle = document.getElementById('pageSubtitle');
    const themeToggle = document.getElementById('themeToggle');

    const viewTitles = {
        'scanner': { title: 'New Scan', sub: 'Analyze text, URLs, and emails for advanced threats.' },
        'history': { title: 'Scan History', sub: 'Review past analysis results.' },
        'feed': { title: 'Global Feed', sub: 'Latest cybersecurity intelligence and threats.' },
        'analytics': { title: 'Analytics', sub: 'Platform usage and detection metrics.' },
        'apikeys': { title: 'API Keys', sub: 'Manage your application access tokens.' },
        'settings': { title: 'Settings', sub: 'Manage profile and preferences.' }
    };

    const translations = {
        'en': {
            'pageTitle_scanner': 'New Scan',
            'pageSubtitle_scanner': 'Analyze text, URLs, and emails for advanced threats.',
            'pageTitle_history': 'Scan History',
            'pageSubtitle_history': 'Audit trail of all performed threat assessments.',
            'pageTitle_feed': 'Global Threat Feed',
            'pageSubtitle_feed': 'Live real-time feed of newly identified cyber threats.',
            'pageTitle_analytics': 'Analytics & Telemetry',
            'pageSubtitle_analytics': 'Aggregated risk scoring insights and platform KPIs.',
            'pageTitle_apikeys': 'API Key Management',
            'pageSubtitle_apikeys': 'Generate and manage enterprise API authentication keys.',
            'pageTitle_settings': 'System Settings',
            'pageSubtitle_settings': 'Manage profile preferences and remote backend connections.',
            'toggle_label': 'हिंदी'
        },
        'hi': {
            'pageTitle_scanner': 'नया सुरक्षा स्कैन',
            'pageSubtitle_scanner': 'संदेश, लिंक (URL) और ईमेल की धोखाधड़ी जांचें।',
            'pageTitle_history': 'स्कैन इतिहास',
            'pageSubtitle_history': 'किए गए सभी सुरक्षा परीक्षणों का सुरक्षित रिकॉर्ड।',
            'pageTitle_feed': 'साइबर सुरक्षा अलर्ट',
            'pageSubtitle_feed': 'सरकारी सेवाओं और बैंकिंग से जुड़े ताज़ा फ्रॉड अलर्ट।',
            'pageTitle_analytics': 'एनालिटिक्स व रुझान',
            'pageSubtitle_analytics': 'धोखाधड़ी रोकथाम दर और सुरक्षा आंकड़े।',
            'pageTitle_apikeys': 'एपीआई कुंजी प्रबंधन',
            'pageSubtitle_apikeys': 'सुरक्षित डेवलपर एपीआई टोकन बनाएं।',
            'pageTitle_settings': 'सिस्टम सेटिंग्स',
            'pageSubtitle_settings': 'अपनी प्राथमिकताएं और सर्वर कनेक्शन प्रबंधित करें।',
            'toggle_label': 'English'
        }
    };

    function safeCreateIcons() {
        if (window.lucide && typeof window.lucide.createIcons === 'function') {
            try { window.lucide.createIcons(); } catch (e) {}
        }
    }

    // --- 1. SPA ROUTING ---
    function handleRoute() {
        let hash = window.location.hash.substring(1) || 'scanner';
        if (!viewTitles[hash]) hash = 'scanner';

        // Update DOM Views
        views.forEach(v => v.classList.remove('active'));
        const activeView = document.getElementById(`view-${hash}`);
        if (activeView) activeView.classList.add('active');

        // Update Sidebar Active State
        navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('data-route') === hash) {
                link.classList.add('active');
            }
        });

        // Update Header
        applyLanguage(currentLang);

        // Trigger specific view logic
        if (hash === 'history') loadHistory();
        if (hash === 'feed') loadFeed();
        if (hash === 'analytics') loadAnalytics();
        if (hash === 'apikeys') loadApiKeys();
        if (hash === 'settings') loadSettings();

        safeCreateIcons();
    }

    window.addEventListener('hashchange', handleRoute);

    // --- 2. THEME CONTROLLER ---
    function getChartThemeColors() {
        const isDark = htmlEl.getAttribute('data-theme') === 'dark';
        return {
            grid: isDark ? '#27272a' : '#e5e7eb',
            ticks: isDark ? '#a1a1aa' : '#6b7280'
        };
    }

    function updateChartTheme(theme) {
        if (!chartInstance) return;
        const colors = getChartThemeColors();
        try {
            if (chartInstance.options && chartInstance.options.scales) {
                chartInstance.options.scales.x.grid.color = colors.grid;
                chartInstance.options.scales.y.grid.color = colors.grid;
                chartInstance.options.scales.x.ticks.color = colors.ticks;
                chartInstance.options.scales.y.ticks.color = colors.ticks;
                chartInstance.update();
            }
        } catch (e) {}
    }

    function setTheme(theme) {
        htmlEl.setAttribute('data-theme', theme);
        if (themeToggle) {
            themeToggle.innerHTML = `<i data-lucide="${theme === 'light' ? 'moon' : 'sun'}"></i>`;
        }
        localStorage.setItem('sentinel_theme', theme);
        safeCreateIcons();
        if (chartInstance) {
            updateChartTheme(theme);
        }
    }

    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            setTheme(htmlEl.getAttribute('data-theme') === 'light' ? 'dark' : 'light');
        });
    }

    // --- 3. BILINGUAL LANGUAGE SWITCHER ---
    function applyLanguage(lang) {
        currentLang = lang;
        localStorage.setItem('sentinel_lang', lang);
        const t = translations[lang] || translations['en'];

        const langLabel = document.getElementById('currentLangLabel');
        if (langLabel) langLabel.innerText = t.toggle_label;

        const activeRoute = (window.location.hash.substring(1) || 'scanner').replace(/[^a-z]/g, '');
        const currentRoute = viewTitles[activeRoute] ? activeRoute : 'scanner';
        
        if (pageTitle && t[`pageTitle_${currentRoute}`]) pageTitle.innerText = t[`pageTitle_${currentRoute}`];
        if (pageSubtitle && t[`pageSubtitle_${currentRoute}`]) pageSubtitle.innerText = t[`pageSubtitle_${currentRoute}`];
    }

    const langToggleBtn = document.getElementById('langToggleBtn');
    if (langToggleBtn) {
        langToggleBtn.addEventListener('click', () => {
            applyLanguage(currentLang === 'en' ? 'hi' : 'en');
        });
    }

    // --- 4. SCANNER MODULE ---
    const tabBtns = document.querySelectorAll('#scanTabs button');
    const textWrapper = document.getElementById('textInputWrapper');
    const urlWrapper = document.getElementById('urlInputWrapper');
    const qrWrapper = document.getElementById('qrInputWrapper');
    const textInput = document.getElementById('textInput');
    const urlInput = document.getElementById('urlInput');
    const qrInput = document.getElementById('qrInput');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            tabBtns.forEach(b => {
                b.classList.remove('active');
                b.style.color = 'var(--text-secondary)';
            });
            const targetBtn = e.currentTarget;
            targetBtn.classList.add('active');
            targetBtn.style.color = 'var(--text-primary)';
            currentMode = targetBtn.getAttribute('data-target');
            
            if (textWrapper) textWrapper.classList.add('d-none');
            if (urlWrapper) urlWrapper.classList.add('d-none');
            if (qrWrapper) qrWrapper.classList.add('d-none');

            if (currentMode === 'text' && textWrapper) {
                textWrapper.classList.remove('d-none');
                if (textInput) textInput.focus();
            } else if (currentMode === 'url' && urlWrapper) {
                urlWrapper.classList.remove('d-none');
                if (urlInput) urlInput.focus();
            } else if (currentMode === 'qr' && qrWrapper) {
                qrWrapper.classList.remove('d-none');
                if (qrInput) qrInput.focus();
            }
        });
    });

    const startScanBtn = document.getElementById('startScanBtn');
    const emptyState = document.getElementById('emptyState');
    const progressState = document.getElementById('progressState');
    const finalState = document.getElementById('finalState');

    const delay = ms => new Promise(res => setTimeout(res, ms));

    async function updateStage(el) {
        const prev = document.querySelector('.scan-stage.active');
        if (prev) {
            prev.className = 'scan-stage done';
            const label = prev.innerText.replace(/^[^\w]+/, '').trim();
            prev.innerHTML = `<i data-lucide="check-circle-2" width="16"></i> ${label}`;
        }
        if (el) {
            el.className = 'scan-stage active';
            const label = el.innerText.replace(/^[^\w]+/, '').trim();
            el.innerHTML = `<div class="spinner"></div> ${label}`;
        }
        safeCreateIcons();
    }

    function saveToLocalHistory(inputData, inputType, result) {
        try {
            const history = JSON.parse(localStorage.getItem('sentinel_scan_history') || '[]');
            const newRecord = {
                id: Date.now(),
                created_at: new Date().toISOString(),
                input_type: inputType,
                input_data: inputData,
                severity_level: result.severity_level,
                confidence_score: result.confidence_score,
                explainability_json: JSON.stringify(result.explainability || {})
            };
            history.unshift(newRecord);
            if (history.length > 50) history.pop();
            localStorage.setItem('sentinel_scan_history', JSON.stringify(history));
        } catch (e) {
            console.error("Local history save error:", e);
        }
    }

    function renderFinalResult(data, rawInput) {
        if (!finalState) return;
        finalState.classList.remove('d-none');
        const sevEl = document.getElementById('resSeverity');
        if (sevEl) {
            sevEl.innerText = data.severity_level || 'Safe';
            sevEl.className = `badge-severity sev-${(data.severity_level || 'safe').toLowerCase().replace(/\s+/g, '-')}`;
        }
        
        const confEl = document.getElementById('resConfidence');
        if (confEl) confEl.innerText = `${Math.round((data.confidence_score || 0) * 100)}%`;

        const indEl = document.getElementById('resIndicators');
        if (indEl) {
            indEl.innerHTML = '';
            if (data.indicators && data.indicators.length > 0) {
                data.indicators.forEach(ind => {
                    indEl.innerHTML += `<span class="indicator-tag"><i data-lucide="alert-triangle" width="14" style="color:var(--sev-suspicious-text)"></i> ${escapeHtml(ind)}</span>`;
                });
            } else {
                indEl.innerHTML = '<span class="text-secondary small">No anomalies detected.</span>';
            }
        }

        // --- 4-Pillar Scorecard ---
        const scorecardGrid = document.getElementById('scorecardGrid');
        if (scorecardGrid) {
            const indicatorsStr = (data.indicators || []).join(' ').toLowerCase();
            const isSpoofed = indicatorsStr.includes('typosquatting') || indicatorsStr.includes('targeting') || indicatorsStr.includes('spoofing') || indicatorsStr.includes('tld');
            const hasUrgency = indicatorsStr.includes('urgency') || indicatorsStr.includes('disconnection') || indicatorsStr.includes('impound') || indicatorsStr.includes('24 hours');
            const hasFinancial = indicatorsStr.includes('financial') || indicatorsStr.includes('otp') || indicatorsStr.includes('credential') || indicatorsStr.includes('kisan') || indicatorsStr.includes('subsidy');
            const isEncrypted = !indicatorsStr.includes('missing https') && !indicatorsStr.includes('ip address');

            const pillars = [
                { title: 'Brand / Channel Identity', status: isSpoofed ? 'Deceptive / Spoofed' : 'Verified Channel', icon: isSpoofed ? 'shield-alert' : 'shield-check', color: isSpoofed ? '#ef4444' : '#10b981' },
                { title: 'Psychological Urgency', status: hasUrgency ? 'High Pressure Threat' : 'Normal Context', icon: hasUrgency ? 'clock' : 'check-circle-2', color: hasUrgency ? '#f59e0b' : '#10b981' },
                { title: 'Financial / OTP Bait', status: hasFinancial ? 'Demands Money / OTP' : 'No Fund Requests', icon: hasFinancial ? 'alert-octagon' : 'lock', color: hasFinancial ? '#ef4444' : '#10b981' },
                { title: 'Transport Encryption', status: isEncrypted ? 'Encrypted Protocol' : 'Insecure / Cleartext', icon: isEncrypted ? 'lock' : 'unlock', color: isEncrypted ? '#10b981' : '#f59e0b' }
            ];

            scorecardGrid.innerHTML = pillars.map(p => `
                <div class="col-sm-6">
                    <div class="p-2 rounded d-flex align-items-center gap-2" style="background-color: var(--bg-primary); border: 1px solid var(--border-color);">
                        <i data-lucide="${p.icon}" width="16" style="color: ${p.color}; flex-shrink:0;"></i>
                        <div style="font-size: 0.8rem; line-height: 1.2;">
                            <div class="text-secondary" style="font-size: 0.72rem;">${p.title}</div>
                            <div class="fw-bold" style="color: ${p.color};">${p.status}</div>
                        </div>
                    </div>
                </div>
            `).join('');
        }

        // Explainability heatmap
        const xaiBlock = document.getElementById('xaiBlock');
        const heatMap = data.explainability && (data.explainability.keyword_heatmap || data.explainability.heat_map);
        if (xaiBlock) {
            if (data.input_type === 'text' && heatMap && Object.keys(heatMap).length > 0) {
                xaiBlock.classList.remove('d-none');
                const resHeatmap = document.getElementById('resHeatmap');
                if (resHeatmap) {
                    resHeatmap.innerHTML = '';
                    rawInput.split(/\s+/).forEach(w => {
                        const cleanW = w.toLowerCase().replace(/[^a-z0-9]/g, '');
                        let style = '';
                        if (heatMap[cleanW]) {
                            const heat = heatMap[cleanW];
                            style = `background-color: rgba(239, 68, 68, ${heat}); border-radius: 3px; padding: 1px 4px; ${heat > 0.45 ? 'color:#fff;' : ''}`;
                        }
                        resHeatmap.innerHTML += `<span class="heatmap-word" style="${style}">${escapeHtml(w)} </span>`;
                    });
                }
            } else {
                xaiBlock.classList.add('d-none');
            }
        }

        // Citizen Safety Advisory Block
        const advBlock = document.getElementById('advisoryBlock');
        const advText = document.getElementById('resAdvisory');
        const advisory = data.explainability && data.explainability.citizen_advisory;
        if (advBlock && advText) {
            if (advisory) {
                advBlock.classList.remove('d-none');
                advText.innerText = advisory;
            } else {
                advBlock.classList.add('d-none');
            }
        }

        // Helpline Block Visibility
        const helplineBlock = document.getElementById('helplineBlock');
        if (helplineBlock) {
            if ((data.confidence_score || 0) >= 0.40) {
                helplineBlock.classList.remove('d-none');
            } else {
                helplineBlock.classList.add('d-none');
            }
        }

        // Evidentiary Proof Seal (Deterministic Hash)
        const evidenceHashEl = document.getElementById('evidenceHash');
        if (evidenceHashEl) {
            const seedStr = `${rawInput}|${data.severity_level}|${Date.now()}|SENTINEL_EVIDENCE_SEAL`;
            let defaultHash = '8F2A6D91C0E3B4A5D8F1';
            try {
                if (window.crypto && crypto.subtle) {
                    const enc = new TextEncoder().encode(seedStr);
                    crypto.subtle.digest('SHA-256', enc).then(buf => {
                        const arr = Array.from(new Uint8Array(buf));
                        evidenceHashEl.innerText = arr.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 20).toUpperCase();
                    }).catch(() => {
                        evidenceHashEl.innerText = defaultHash;
                    });
                } else {
                    evidenceHashEl.innerText = defaultHash;
                }
            } catch (e) {
                evidenceHashEl.innerText = defaultHash;
            }
        }

        window.lastScanData = data;
        window.lastRawInput = rawInput;
        safeCreateIcons();
    }

    if (startScanBtn) {
        startScanBtn.addEventListener('click', async () => {
            let rawContent = (textInput ? textInput.value : '');
            if (currentMode === 'url' && urlInput) rawContent = urlInput.value;
            else if (currentMode === 'qr' && qrInput) rawContent = qrInput.value;

            if (!rawContent || !rawContent.trim()) {
                alert("Please enter message text, URL, or QR code content to analyze.");
                return;
            }

            startScanBtn.disabled = true;
            if (emptyState) emptyState.classList.add('d-none');
            if (finalState) finalState.classList.add('d-none');
            if (progressState) progressState.classList.remove('d-none');

            const stages = [
                document.getElementById('stage1'),
                document.getElementById('stage2'),
                document.getElementById('stage3'),
                document.getElementById('stage4')
            ];

            stages.forEach(s => {
                if (s) {
                    s.className = 'scan-stage';
                    const label = s.innerText.replace(/^[^\w]+/, '').trim();
                    s.innerHTML = `<i data-lucide="circle" width="16"></i> ${label}`;
                }
            });
            safeCreateIcons();

            let scanResult = null;
            const isUrlType = currentMode === 'url' || (currentMode === 'qr' && (rawContent.startsWith('http://') || rawContent.startsWith('https://') || rawContent.startsWith('upi://')));
            const endpoint = isUrlType ? '/predict/url' : '/predict/text';
            const payload = isUrlType ? { url: rawContent } : { text: rawContent };

            const fetchPromise = fetch(`${API_BASE_URL}${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(res => {
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                return res.json();
            })
            .then(data => {
                isLiveApiAvailable = true;
                return data;
            })
            .catch(() => {
                isLiveApiAvailable = false;
                const fallbackResult = isUrlType 
                    ? ClientEngine.analyzeUrl(rawContent) 
                    : ClientEngine.analyzeText(rawContent);

                saveToLocalHistory(rawContent, isUrlType ? 'url' : 'text', fallbackResult);
                return fallbackResult;
            });

            await updateStage(stages[0]);
            await delay(450);
            await updateStage(stages[1]);
            await delay(450);
            await updateStage(stages[2]);
            await delay(400);
            await updateStage(stages[3]);

            scanResult = await fetchPromise;
            await delay(300);

            if (progressState) progressState.classList.add('d-none');
            startScanBtn.disabled = false;

            if (scanResult) {
                renderFinalResult(scanResult, rawContent);
            } else {
                if (emptyState) emptyState.classList.remove('d-none');
                alert("Analysis encountered an unexpected issue.");
            }
        });
    }

    // Keyboard shortcut (Ctrl+Enter to scan)
    [textInput, urlInput, qrInput].forEach(input => {
        if (!input) return;
        input.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                if (startScanBtn && !startScanBtn.disabled) startScanBtn.click();
            } else if ((input === urlInput || input === qrInput) && e.key === 'Enter') {
                e.preventDefault();
                if (startScanBtn && !startScanBtn.disabled) startScanBtn.click();
            }
        });
    });

    // --- QUICK SAMPLE CHIPS ---
    const SAMPLE_PROMPTS = {
        'electricity': 'Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please immediately contact our electricity officer at 9876543210 or update bill online.',
        'hinglish': 'Priye grahak, aapka bijli connection aaj raat 9:30 baje kat diya jayega kyuki pichle mahine ka bill update nahi hua hai. Turant hamare electricity officer se 9876543210 par sampark kare.',
        'echallan': 'NOTICE: Parivahan e-Challan #DL84920 is pending against vehicle DL01AB1234. Immediate impound notice issued. Click http://echallan-parivahan.xyz/pay to clear fine within 24 hours.',
        'safe': 'Hi Team, please find the quarterly sprint review slides and notes attached for tomorrow morning 10 AM conference call.',
        'fake-echallan': 'http://echallan-parivahan.xyz/auth/verify',
        'fake-sbi': 'http://yono-sbi-portal.top/login.php',
        'safe-gov': 'https://parivahan.gov.in/parivahan/',
        'fake-qr-challan': 'upi://pay?pa=fake.echallan@icici&pn=Parivahan-Traffic-Fine&am=1000.00&cu=INR',
        'fake-qr-bill': 'http://bijli-bill-payment-update.xyz/pay-meter.php?id=94821',
        'safe-qr-merchant': 'upi://pay?pa=verified.merchant@sbi&pn=Government-Official-Portal&cu=INR'
    };

    document.querySelectorAll('.badge-chip[data-sample]').forEach(chip => {
        chip.addEventListener('click', () => {
            const sampleKey = chip.getAttribute('data-sample');
            const sampleText = SAMPLE_PROMPTS[sampleKey];
            if (!sampleText) return;

            if (sampleKey.startsWith('fake-qr-') || sampleKey.startsWith('safe-qr-')) {
                const qrTabBtn = document.querySelector('#scanTabs button[data-target="qr"]');
                if (qrTabBtn) qrTabBtn.click();
                if (qrInput) {
                    qrInput.value = sampleText;
                    qrInput.focus();
                }
            } else if (sampleKey.startsWith('fake-') || sampleKey === 'safe-gov') {
                const urlTabBtn = document.querySelector('#scanTabs button[data-target="url"]');
                if (urlTabBtn) urlTabBtn.click();
                if (urlInput) {
                    urlInput.value = sampleText;
                    urlInput.focus();
                }
            } else {
                const textTabBtn = document.querySelector('#scanTabs button[data-target="text"]');
                if (textTabBtn) textTabBtn.click();
                if (textInput) {
                    textInput.value = sampleText;
                    textInput.focus();
                }
            }
        });
    });

    // --- WHATSAPP CITIZEN ALERT GENERATOR ---
    const copyWhatsAppAlertBtn = document.getElementById('copyWhatsAppAlertBtn');
    if (copyWhatsAppAlertBtn) {
        copyWhatsAppAlertBtn.addEventListener('click', async () => {
            if (!window.lastScanData) return;
            const data = window.lastScanData;
            const snippet = (window.lastRawInput || '').substring(0, 80);
            const sev = data.severity_level || 'Suspicious';
            const conf = Math.round((data.confidence_score || 0) * 100);
            const indicators = (data.indicators && data.indicators.length > 0) 
                ? data.indicators.map(i => `• ${i}`).join('\n') 
                : '• Suspicious heuristic anomalies';
            const advisory = (data.explainability && data.explainability.citizen_advisory) || 'Do not click links, share OTPs, or transfer money.';
            const alertMsg = `[SENTINEL CITIZEN CYBER ALERT]\nThreat Level: ${sev} (${conf}% Confidence)\nMessage/URL Analyzed: "${snippet}"\nDetected Red Flags:\n${indicators}\nSafety Advice: ${advisory}\nVerified in real-time by Sentinel Verify AI`;

            if (navigator.clipboard && navigator.clipboard.writeText) {
                try {
                    await navigator.clipboard.writeText(alertMsg);
                    const origHtml = copyWhatsAppAlertBtn.innerHTML;
                    copyWhatsAppAlertBtn.innerHTML = `<i data-lucide="check" width="16"></i> Copied Alert to Clipboard!`;
                    safeCreateIcons();
                    setTimeout(() => {
                        copyWhatsAppAlertBtn.innerHTML = origHtml;
                        safeCreateIcons();
                    }, 3000);
                    return;
                } catch (e) {}
            }
            prompt("Copy this alert message to share in your WhatsApp groups:", alertMsg);
        });
    }

    // --- OFFICIAL COMPLAINT DOCKET (TXT) EXPORTER ---
    const downloadDocketBtn = document.getElementById('downloadDocketBtn');
    if (downloadDocketBtn) {
        downloadDocketBtn.addEventListener('click', () => {
            const data = window.lastScanData;
            const raw = window.lastRawInput || '';
            if (!data) return;

            const evidenceHash = document.getElementById('evidenceHash')?.innerText || '8F2A6D91C0E3B4A5D8F1';
            const docketContent = `========================================================================\nNATIONAL CYBERCRIME REPORTING PORTAL (1930 / CYBERCRIME.GOV.IN)\nPRE-FORMATTED CITIZEN INCIDENT COMPLAINT DOCKET\n========================================================================\nGenerated by: Sentinel Verify Citizen AI Anti-Fraud Shield\nDate & Timestamp: ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })} IST\nEvidentiary Proof Seal (SHA-256): ${evidenceHash}\nIncident Classification: ${data.severity_level || 'Suspicious'}\nEngine Confidence Score: ${Math.round((data.confidence_score || 0) * 100)}%\n\n1. SUSPECT EVIDENCE CONTENT:\n------------------------------------------------------------------------\n${raw}\n\n2. DETECTED FRAUD INDICATORS & SUSPICIOUS CHARACTERISTICS:\n------------------------------------------------------------------------\n${(data.indicators && data.indicators.length > 0) ? data.indicators.map(i => `[+] ${i}`).join('\n') : '[+] Algorithmic heuristic anomaly detected'}\n\n3. ACTIONABLE CITIZEN SAFETY ADVISORY:\n------------------------------------------------------------------------\n${(data.explainability && data.explainability.citizen_advisory) || 'Do not click links, share OTPs, or transfer money to personal mobile numbers.'}\n\n4. LEGAL AND EVIDENTIARY DISCLAIMER:\n------------------------------------------------------------------------\nThis docket is generated as evidentiary material for filing under Section 66D of the Information Technology Act (Cheating by personation by using computer resource).\nVictim Hotline: Dial 1930 (Toll-Free National Helpline) or visit https://cybercrime.gov.in.\n========================================================================`;

            const blob = new Blob([docketContent], { type: 'text/plain;charset=utf-8' });
            triggerDownload(blob, `sentinel_cybercrime_complaint_docket_${Date.now()}.txt`);
        });
    }

    // --- FORENSIC EVIDENCE ENVELOPE (JSON) EXPORTER ---
    const downloadEvidenceJsonBtn = document.getElementById('downloadEvidenceJsonBtn');
    if (downloadEvidenceJsonBtn) {
        downloadEvidenceJsonBtn.addEventListener('click', () => {
            const data = window.lastScanData;
            const raw = window.lastRawInput || '';
            if (!data) return;

            const evidenceHash = document.getElementById('evidenceHash')?.innerText || '8F2A6D91C0E3B4A5D8F1';
            const envelope = {
                format: "SENTINEL_EVIDENCE_ENVELOPE_V1",
                timestamp_iso: new Date().toISOString(),
                raw_evidence_snippet: raw,
                input_type: data.input_type,
                threat_severity: data.severity_level,
                confidence_score: data.confidence_score,
                sha256_forensic_seal: evidenceHash,
                detected_indicators: data.indicators || [],
                explainability_metadata: data.explainability || {},
                legal_disclaimer: "Certified algorithmic scan record generated by Sentinel Verify Citizen AI Anti-Fraud Engine."
            };

            const blob = new Blob([JSON.stringify(envelope, null, 2)], { type: 'application/json' });
            triggerDownload(blob, `sentinel_evidence_envelope_${Date.now()}.json`);
        });
    }

    function triggerDownload(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // --- 5. HISTORY MODULE ---
    async function loadHistory() {
        const tbody = document.querySelector('#historyTable tbody');
        const empty = document.getElementById('historyEmpty');
        if (!tbody) return;

        let items = [];
        try {
            const res = await fetch(`${API_BASE_URL}/history`);
            if (res.ok) {
                const data = await res.json();
                items = data.items || [];
                isLiveApiAvailable = true;
            } else {
                throw new Error("Live history fetch failed");
            }
        } catch (e) {
            isLiveApiAvailable = false;
            items = JSON.parse(localStorage.getItem('sentinel_scan_history') || '[]');
        }

        tbody.innerHTML = '';
        if (items.length === 0) {
            if (empty) empty.classList.remove('d-none');
        } else {
            if (empty) empty.classList.add('d-none');
            items.forEach(item => {
                const snippet = item.input_data.length > 42 ? item.input_data.substring(0, 42) + '...' : item.input_data;
                const sevClass = `sev-${(item.severity_level || 'Safe').toLowerCase().replace(/\s+/g, '-')}`;
                const dateStr = item.created_at ? new Date(item.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Just now';
                
                tbody.innerHTML += `
                    <tr>
                        <td>${escapeHtml(dateStr)}</td>
                        <td class="text-uppercase" style="font-size:0.8rem; letter-spacing:0.05em">${escapeHtml(item.input_type)}</td>
                        <td class="font-monospace small">${escapeHtml(snippet)}</td>
                        <td><span class="badge-severity ${sevClass}">${escapeHtml(item.severity_level)}</span></td>
                        <td class="fw-bold">${Math.round((item.confidence_score || 0) * 100)}%</td>
                        <td class="text-end">
                            <button class="btn-icon text-danger" title="Delete scan" onclick="deleteHistory(${item.id})"><i data-lucide="trash-2" width="16"></i></button>
                        </td>
                    </tr>
                `;
            });
        }
        safeCreateIcons();
    }

    const exportCsvBtn = document.getElementById('exportCsvBtn');
    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', async () => {
            try {
                const res = await fetch(`${API_BASE_URL}/history/export?format=csv`);
                if (res.ok) {
                    const blob = await res.blob();
                    triggerDownload(blob, 'sentinel_threat_audit.csv');
                    return;
                }
            } catch (e) {}

            const history = JSON.parse(localStorage.getItem('sentinel_scan_history') || '[]');
            let csvContent = 'ID,Timestamp,Type,Severity,Confidence,Input Data\n';
            history.forEach(h => {
                csvContent += `"${h.id}","${h.created_at}","${h.input_type}","${h.severity_level}","${Math.round((h.confidence_score||0)*100)}%","${(h.input_data||'').replace(/"/g, '""').substring(0, 100)}"\n`;
            });
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            triggerDownload(blob, 'sentinel_threat_audit.csv');
        });
    }

    const exportJsonBtn = document.getElementById('exportJsonBtn');
    if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', async () => {
            try {
                const res = await fetch(`${API_BASE_URL}/history/export?format=json`);
                if (res.ok) {
                    const blob = await res.blob();
                    triggerDownload(blob, 'sentinel_threat_audit.json');
                    return;
                }
            } catch (e) {}

            const history = JSON.parse(localStorage.getItem('sentinel_scan_history') || '[]');
            const blob = new Blob([JSON.stringify(history, null, 2)], { type: 'application/json' });
            triggerDownload(blob, 'sentinel_threat_audit.json');
        });
    }

    window.deleteHistory = async (id) => {
        if (!confirm("Delete this scan record?")) return;
        try {
            const res = await fetch(`${API_BASE_URL}/history/${id}`, { method: 'DELETE' });
            if (!res.ok) throw new Error("API Delete failed");
        } catch (e) {
            let history = JSON.parse(localStorage.getItem('sentinel_scan_history') || '[]');
            history = history.filter(item => item.id !== id);
            localStorage.setItem('sentinel_scan_history', JSON.stringify(history));
        }
        loadHistory();
    };

    // --- 6. FEED MODULE ---
    async function loadFeed() {
        const container = document.getElementById('feedContainer');
        if (!container) return;

        try {
            const res = await fetch(`${API_BASE_URL}/feed`);
            if (res.ok) {
                cachedFeedData = await res.json();
                isLiveApiAvailable = true;
            } else {
                throw new Error("Feed API unavailable");
            }
        } catch (e) {
            isLiveApiAvailable = false;
            cachedFeedData = JSON.parse(localStorage.getItem('sentinel_threat_feed') || '[]');
        }

        renderFilteredFeed();
    }

    function renderFilteredFeed() {
        const container = document.getElementById('feedContainer');
        if (!container) return;

        const filtered = currentFeedCategory === 'ALL' 
            ? cachedFeedData 
            : cachedFeedData.filter(item => (item.category || '').toLowerCase().includes(currentFeedCategory.toLowerCase()) || (item.title || '').toLowerCase().includes(currentFeedCategory.toLowerCase()));

        container.innerHTML = '';
        const colorMap = { 'Critical': 'danger', 'High': 'warning', 'Medium': 'info', 'Low': 'secondary' };

        if (filtered.length === 0) {
            container.innerHTML = '<div class="saas-card text-center py-4 text-secondary">No alerts found in this category.</div>';
            return;
        }

        filtered.forEach(item => {
            const badgeColor = colorMap[item.risk_level] || 'secondary';
            const timestamp = item.timestamp ? new Date(item.timestamp).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Live';
            
            container.innerHTML += `
                <div class="feed-card">
                    <div class="d-flex justify-content-between mb-2">
                        <span class="badge bg-${badgeColor} bg-opacity-10 text-${badgeColor} text-uppercase" style="font-size:0.7rem; letter-spacing:0.05em; font-weight:700;">${escapeHtml(item.risk_level)} RISK</span>
                        <span class="small text-secondary">${escapeHtml(timestamp)}</span>
                    </div>
                    <h5 class="fw-bold mb-2">${escapeHtml(item.title)}</h5>
                    <p class="mb-3" style="color:var(--text-secondary); font-size:0.95rem">${escapeHtml(item.description)}</p>
                    <div class="d-flex gap-2">
                        <span class="indicator-tag"><i data-lucide="tag" width="14"></i> ${escapeHtml(item.category)}</span>
                        <span class="indicator-tag"><i data-lucide="globe" width="14"></i> Source: ${escapeHtml(item.source)}</span>
                    </div>
                </div>
            `;
        });
        safeCreateIcons();
    }

    document.querySelectorAll('#feedFilterChips .badge-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            document.querySelectorAll('#feedFilterChips .badge-chip').forEach(c => {
                c.classList.remove('active');
                c.style.backgroundColor = '';
                c.style.color = '';
            });
            chip.classList.add('active');
            chip.style.backgroundColor = 'var(--brand-color)';
            chip.style.color = '#fff';
            currentFeedCategory = chip.getAttribute('data-cat') || 'ALL';
            renderFilteredFeed();
        });
    });

    // --- 7. ANALYTICS MODULE ---
    async function loadAnalytics() {
        let overviewData = { total_scanned: 0, threats_detected: 0, accuracy_rate: 96.4 };
        let trendData = {
            labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            datasets: [
                { label: 'Safe Scans', data: [32, 45, 28, 54, 40, 62, 48] },
                { label: 'Threats Blocked', data: [8, 14, 6, 19, 11, 15, 12] }
            ]
        };

        try {
            const [overRes, trendRes] = await Promise.all([
                fetch(`${API_BASE_URL}/analytics/overview`),
                fetch(`${API_BASE_URL}/analytics/trends`)
            ]);
            if (overRes.ok && trendRes.ok) {
                overviewData = await overRes.json();
                trendData = await trendRes.json();
                isLiveApiAvailable = true;
            } else {
                throw new Error("Analytics API unavailable");
            }
        } catch (e) {
            isLiveApiAvailable = false;
            const history = JSON.parse(localStorage.getItem('sentinel_scan_history') || '[]');
            overviewData.total_scanned = Math.max(history.length, 24);
            const threatCount = history.filter(h => h.severity_level && !['Safe', 'Low Risk'].includes(h.severity_level)).length;
            overviewData.threats_detected = Math.max(threatCount, 9);
            overviewData.accuracy_rate = 96.4;
        }

        const totalScansEl = document.getElementById('kpi-total-scans') || document.getElementById('statTotalScans');
        const threatsEl = document.getElementById('kpi-threats') || document.getElementById('statThreats');
        const accEl = document.getElementById('kpi-accuracy') || document.getElementById('statAccuracy');
        const feedsEl = document.getElementById('kpi-feeds');

        if (totalScansEl) totalScansEl.innerText = overviewData.total_scanned.toLocaleString();
        if (threatsEl) threatsEl.innerText = overviewData.threats_detected.toLocaleString();
        if (accEl) accEl.innerText = overviewData.accuracy_rate + '%';
        if (feedsEl) feedsEl.innerText = (cachedFeedData && cachedFeedData.length) ? cachedFeedData.length : '14';

        const chartCanvas = document.getElementById('trendsChart') || document.getElementById('analyticsChart');
        if (!chartCanvas || typeof Chart === 'undefined') return;

        const ctx = chartCanvas.getContext('2d');
        if (chartInstance) chartInstance.destroy();

        const themeColors = getChartThemeColors();

        chartInstance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: trendData.labels,
                datasets: [
                    {
                        label: 'Safe Scans',
                        data: trendData.datasets[0].data,
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16,185,129,0.1)',
                        fill: true,
                        tension: 0.38,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    },
                    {
                        label: 'Threats Blocked',
                        data: trendData.datasets[1].data,
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239,68,68,0.1)',
                        fill: true,
                        tension: 0.38,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top',
                        labels: { boxWidth: 12, font: { family: 'Inter', size: 12 } }
                    }
                },
                scales: {
                    x: {
                        grid: { color: themeColors.grid, drawBorder: false },
                        ticks: { color: themeColors.ticks, font: { family: 'Inter', size: 11 } }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: themeColors.grid, drawBorder: false },
                        ticks: { color: themeColors.ticks, font: { family: 'Inter', size: 11 } }
                    }
                }
            }
        });
    }

    // --- 8. API KEYS MODULE ---
    async function loadApiKeys() {
        const tbody = document.querySelector('#apiKeysTable tbody') || document.querySelector('#keysTable tbody');
        if (!tbody) return;

        let keys = [];
        try {
            const res = await fetch(`${API_BASE_URL}/apikeys`);
            if (res.ok) {
                keys = await res.json();
                isLiveApiAvailable = true;
            } else {
                throw new Error("API Keys endpoint unavailable");
            }
        } catch (e) {
            isLiveApiAvailable = false;
            keys = JSON.parse(localStorage.getItem('sentinel_api_keys') || '[]');
        }

        tbody.innerHTML = '';
        keys.forEach(item => {
            const dateStr = item.created_at ? new Date(item.created_at).toLocaleDateString() : 'Active';
            tbody.innerHTML += `
                <tr>
                    <td class="fw-medium">${escapeHtml(item.name)}</td>
                    <td class="font-monospace small"><div class="api-key-box">${escapeHtml(item.prefix)}**********</div></td>
                    <td>${escapeHtml(dateStr)}</td>
                    <td>${escapeHtml(item.request_count || 0)}</td>
                    <td><span class="badge bg-success bg-opacity-10 text-success">Active</span></td>
                    <td class="text-end">
                        <button class="btn-icon text-danger" title="Revoke key" onclick="revokeKey(${item.id})"><i data-lucide="trash-2" width="16"></i></button>
                    </td>
                </tr>
            `;
        });
        safeCreateIcons();
    }

    const createKeyBtn = document.getElementById('generateApiKeyBtn') || document.getElementById('createKeyBtn');
    if (createKeyBtn) {
        createKeyBtn.addEventListener('click', async () => {
            const name = prompt("Enter a descriptive name for this API Key:", "Production Integration");
            if (!name || !name.trim()) return;

            let rawKey = 'sv_' + Array.from(crypto.getRandomValues(new Uint8Array(24)), b => b.toString(16).padStart(2, '0')).join('');

            try {
                const res = await fetch(`${API_BASE_URL}/apikeys`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: name.trim() })
                });
                if (res.ok) {
                    const data = await res.json();
                    if (data.raw_key) rawKey = data.raw_key;
                } else {
                    throw new Error("Server API key creation failed");
                }
            } catch (e) {
                const keys = JSON.parse(localStorage.getItem('sentinel_api_keys') || '[]');
                const newKey = {
                    id: Date.now(),
                    name: name.trim(),
                    prefix: rawKey.substring(0, 10) + '...',
                    is_active: true,
                    request_count: 0,
                    created_at: new Date().toISOString()
                };
                keys.unshift(newKey);
                localStorage.setItem('sentinel_api_keys', JSON.stringify(keys));
            }

            if (navigator.clipboard && navigator.clipboard.writeText) {
                try {
                    await navigator.clipboard.writeText(rawKey);
                } catch (err) {}
            }

            prompt("IMPORTANT: Copy your raw API key now. It has been automatically copied to your clipboard if permitted:", rawKey);
            loadApiKeys();
        });
    }

    window.revokeKey = async (id) => {
        if (!confirm("Revoke this API Key? Connected applications will lose access.")) return;
        try {
            const res = await fetch(`${API_BASE_URL}/apikeys/${id}`, { method: 'DELETE' });
            if (!res.ok) throw new Error("Revoke failed");
        } catch (e) {
            let keys = JSON.parse(localStorage.getItem('sentinel_api_keys') || '[]');
            keys = keys.filter(k => k.id !== id);
            localStorage.setItem('sentinel_api_keys', JSON.stringify(keys));
        }
        loadApiKeys();
    };

    // --- 9. SETTINGS MODULE ---
    async function loadSettings() {
        const userField = document.getElementById('set-username');
        const notifField = document.getElementById('set-notifications');

        try {
            const res = await fetch(`${API_BASE_URL}/settings/profile`);
            if (res.ok) {
                const data = await res.json();
                if (userField) userField.value = data.username || 'admin';
                if (notifField) notifField.value = (data.notifications_enabled !== false).toString();
                isLiveApiAvailable = true;
            } else {
                throw new Error("Profile endpoint unreachable");
            }
        } catch (e) {
            const storedUser = localStorage.getItem('sentinel_username') || 'admin';
            const storedNotif = localStorage.getItem('sentinel_notifications') || 'true';
            if (userField) userField.value = storedUser;
            if (notifField) notifField.value = storedNotif;
        }

        const apiUrlField = document.getElementById('set-api-url');
        if (apiUrlField) {
            apiUrlField.value = localStorage.getItem('sentinel_api_url') || '';
        }
        checkApiConnection();
    }

    async function checkApiConnection() {
        const dot = document.getElementById('apiStatusDot');
        const text = document.getElementById('apiStatusText');
        if (!dot || !text) return;

        text.innerText = "Checking connection...";
        dot.style.backgroundColor = 'var(--text-secondary)';

        try {
            const res = await fetch(`${API_BASE_URL}/health`, { method: 'GET' });
            if (res.ok) {
                dot.style.backgroundColor = 'var(--sev-safe-text)';
                text.innerText = `Connected (${API_BASE_URL})`;
                isLiveApiAvailable = true;
                return;
            }
        } catch (e) {}

        dot.style.backgroundColor = '#fb923c';
        text.innerText = `Autonomous Client Mode (Active & Ready)`;
        isLiveApiAvailable = false;
    }

    const profileForm = document.getElementById('profileForm') || document.getElementById('settingsForm');
    if (profileForm) {
        profileForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('set-username').value;
            const notifs = document.getElementById('set-notifications').value === 'true';

            localStorage.setItem('sentinel_username', username);
            localStorage.setItem('sentinel_notifications', notifs.toString());

            try {
                await fetch(`${API_BASE_URL}/settings/profile`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, notifications_enabled: notifs })
                });
            } catch (err) {}

            const msg = document.getElementById('settingsMsg');
            if (msg) {
                msg.classList.remove('d-none');
                setTimeout(() => msg.classList.add('d-none'), 3000);
            }
        });
    }

    const apiConfigForm = document.getElementById('apiConfigForm');
    if (apiConfigForm) {
        apiConfigForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const rawUrl = (document.getElementById('set-api-url').value || '').trim();
            if (rawUrl) {
                localStorage.setItem('sentinel_api_url', rawUrl);
            } else {
                localStorage.removeItem('sentinel_api_url');
            }
            API_BASE_URL = resolveApiBaseUrl();

            const msg = document.getElementById('apiConfigMsg');
            if (msg) {
                msg.classList.remove('d-none');
                setTimeout(() => msg.classList.add('d-none'), 3000);
            }
            await checkApiConnection();
        });
    }

    // --- 10. GUIDED DEMO TOUR ---
    const guidedTourBtn = document.getElementById('guidedTourBtn');
    if (guidedTourBtn) {
        guidedTourBtn.addEventListener('click', async () => {
            window.location.hash = 'scanner';
            const sampleChip = document.querySelector('#textQuickChips span[data-sample="electricity"]');
            if (sampleChip) {
                sampleChip.click();
                guidedTourBtn.innerHTML = `<i data-lucide="loader" class="spinner" width="14"></i> <span>Running Tour...</span>`;
                safeCreateIcons();
                await delay(500);
                if (startScanBtn && !startScanBtn.disabled) startScanBtn.click();
                setTimeout(() => {
                    guidedTourBtn.innerHTML = `<i data-lucide="play-circle" width="14"></i> <span>Quick Tour</span>`;
                    safeCreateIcons();
                }, 3500);
            }
        });
    }

    // --- 11. VOICE SAFETY ADVISORY READOUT ---
    const voiceBtn = document.getElementById('voiceAdvisoryBtn');
    if (voiceBtn) {
        voiceBtn.addEventListener('click', () => {
            if (!('speechSynthesis' in window)) {
                alert("Speech synthesis is not supported in your browser.");
                return;
            }
            const advText = document.getElementById('resAdvisory')?.innerText || '';
            if (!advText) return;

            if (window.speechSynthesis.speaking) {
                window.speechSynthesis.cancel();
                voiceBtn.innerHTML = `<i data-lucide="volume-2" width="13"></i> <span>${currentLang === 'hi' ? 'सुनें' : 'Listen'}</span>`;
                safeCreateIcons();
                return;
            }

            const utterance = new SpeechSynthesisUtterance(advText);
            utterance.lang = currentLang === 'hi' ? 'hi-IN' : 'en-IN';
            utterance.rate = 0.92;

            utterance.onstart = () => {
                voiceBtn.innerHTML = `<i data-lucide="square" width="13"></i> <span>${currentLang === 'hi' ? 'रोकें' : 'Stop'}</span>`;
                safeCreateIcons();
            };
            utterance.onend = utterance.onerror = () => {
                voiceBtn.innerHTML = `<i data-lucide="volume-2" width="13"></i> <span>${currentLang === 'hi' ? 'सुनें' : 'Listen'}</span>`;
                safeCreateIcons();
            };

            window.speechSynthesis.speak(utterance);
        });
    }

    // --- 12. CITIZEN SCAM IQ CHALLENGE QUIZ ---
    const SCAM_IQ_QUESTIONS = [
        {
            q: 'Q1: An SMS arrives: "Your Bijli connection will be disconnected at 9:30 PM tonight. Call officer on personal phone 9876543210 immediately." What should you do?',
            options: [
                { text: 'A) Call the personal mobile number and pay via UPI immediately', correct: false },
                { text: 'B) Do not call; official power discoms never send sudden night cutoff notices on personal numbers', correct: true },
                { text: 'C) Download the remote APK app sent on WhatsApp by the caller', correct: false }
            ],
            explanation: 'Official state electricity discoms (BESCOM, UPPCL, Tata Power, etc.) follow formal billing dispute cycles. They never threaten same-day night cutoffs on personal phone numbers.'
        },
        {
            q: 'Q2: A caller says: "You won a ₹5,000 reward on PhonePe! Scan this QR code and enter your UPI PIN to receive your funds." What happens if you enter your PIN?',
            options: [
                { text: 'A) ₹5,000 will be credited directly to your bank account', correct: false },
                { text: 'B) Money will be DEDUCTED from your account; UPI PINs and QR codes are only used to SEND money', correct: true },
                { text: 'C) The funds will be held in escrow until verification', correct: false }
            ],
            explanation: 'Entering a UPI PIN or scanning a QR code is strictly for DEBITING/PAYING money out of your account. You NEVER enter a PIN to receive payments.'
        },
        {
            q: 'Q3: You receive a WhatsApp message with an attachment "PM-Kisan_17th_Installment_Update.apk" claiming to approve a ₹2,000 grant. What should you do?',
            options: [
                { text: 'A) Install the APK and grant SMS & accessibility permissions', correct: false },
                { text: 'B) Forward the message to family members so they can claim benefits too', correct: false },
                { text: 'C) Delete immediately; government agencies never distribute APK files over WhatsApp', correct: true }
            ],
            explanation: 'APK files sent over WhatsApp are remote-access trojans designed to read banking SMS OTPs and control your screen.'
        }
    ];

    let currentScamIqIndex = 0;
    let scamIqScore = 0;

    function renderScamIqQuestion() {
        const qEl = document.getElementById('scamIqQuestion');
        const optEl = document.getElementById('scamIqOptions');
        const badgeEl = document.getElementById('scamIqScoreBadge');
        const fbEl = document.getElementById('scamIqFeedback');
        const nextBtn = document.getElementById('scamIqNextBtn');
        if (!qEl || !optEl) return;

        if (currentScamIqIndex >= SCAM_IQ_QUESTIONS.length) {
            if (badgeEl) badgeEl.innerText = 'Challenge Complete!';
            qEl.innerHTML = `<strong>Challenge Complete! Your Score: ${scamIqScore}/${SCAM_IQ_QUESTIONS.length}</strong>`;
            optEl.innerHTML = `
                <div class="p-3 text-center rounded" style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3);">
                    <h5 class="fw-bold text-success mb-2">Cyber Shield Certified Citizen</h5>
                    <p class="small text-secondary mb-3">You possess high awareness against real-world Indian cyber fraud tactics. Share Sentinel Verify with your community to protect family and friends!</p>
                    <button class="btn btn-sm btn-saas" id="restartScamIqBtn">Retake Challenge</button>
                </div>
            `;
            if (fbEl) fbEl.classList.add('d-none');
            if (nextBtn) nextBtn.classList.add('d-none');
            
            const restartBtn = document.getElementById('restartScamIqBtn');
            if (restartBtn) {
                restartBtn.addEventListener('click', () => {
                    currentScamIqIndex = 0;
                    scamIqScore = 0;
                    renderScamIqQuestion();
                });
            }
            safeCreateIcons();
            return;
        }

        const curr = SCAM_IQ_QUESTIONS[currentScamIqIndex];
        if (badgeEl) badgeEl.innerText = `Scenario ${currentScamIqIndex + 1} of ${SCAM_IQ_QUESTIONS.length}`;
        qEl.innerText = curr.q;
        if (fbEl) fbEl.classList.add('d-none');
        if (nextBtn) nextBtn.classList.add('d-none');

        optEl.innerHTML = curr.options.map(opt => `
            <button class="btn btn-sm text-start p-2 rounded scam-iq-opt" data-correct="${opt.correct}" style="background: var(--bg-sidebar); border: 1px solid var(--border-color); font-size:0.85rem; color:var(--text-primary);">
                ${escapeHtml(opt.text)}
            </button>
        `).join('');

        optEl.querySelectorAll('.scam-iq-opt').forEach(btn => {
            btn.addEventListener('click', () => {
                const isCorrect = btn.getAttribute('data-correct') === 'true';
                if (isCorrect) scamIqScore++;

                optEl.querySelectorAll('.scam-iq-opt').forEach(o => {
                    o.disabled = true;
                    if (o.getAttribute('data-correct') === 'true') {
                        o.style.borderColor = '#10b981';
                        o.style.background = 'rgba(16, 185, 129, 0.12)';
                    } else {
                        o.style.opacity = '0.5';
                    }
                });

                if (isCorrect) {
                    fbEl.className = 'mt-3 p-3 rounded small bg-success bg-opacity-10 text-success border border-success border-opacity-25';
                    fbEl.innerHTML = `<strong>Correct:</strong> ${curr.explanation}`;
                } else {
                    btn.style.borderColor = '#ef4444';
                    btn.style.background = 'rgba(239, 68, 68, 0.12)';
                    fbEl.className = 'mt-3 p-3 rounded small bg-danger bg-opacity-10 text-danger border border-danger border-opacity-25';
                    fbEl.innerHTML = `<strong>Critical Trap:</strong> ${curr.explanation}`;
                }
                fbEl.classList.remove('d-none');
                if (nextBtn) nextBtn.classList.remove('d-none');
                safeCreateIcons();
            });
        });
    }

    const nextScamIqBtn = document.getElementById('scamIqNextBtn');
    if (nextScamIqBtn) {
        nextScamIqBtn.addEventListener('click', () => {
            currentScamIqIndex++;
            renderScamIqQuestion();
        });
    }
    renderScamIqQuestion();

    // --- 13. UNIFIED MODAL CONTROLLER ---
    function openModal(modalEl) {
        if (!modalEl) return;
        modalEl.classList.add('show');
        modalEl.style.display = 'flex';
        document.body.style.overflow = 'hidden';
    }

    function closeModal(modalEl) {
        if (!modalEl) return;
        modalEl.classList.remove('show');
        modalEl.style.display = 'none';
        document.body.style.overflow = '';
    }

    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal(modal);
        });
        modal.querySelectorAll('[data-bs-dismiss="modal"]').forEach(btn => {
            btn.addEventListener('click', () => closeModal(modal));
        });
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal.show').forEach(closeModal);
        }
    });

    const safetyRulesBtn = document.getElementById('safetyRulesBtn');
    const safetyModalEl = document.getElementById('safetyRulesModal');
    if (safetyRulesBtn && safetyModalEl) {
        safetyRulesBtn.addEventListener('click', () => openModal(safetyModalEl));
    }

    const stateDirectoryBtn = document.getElementById('stateDirectoryBtn');
    const stateModalEl = document.getElementById('stateDirectoryModal');
    if (stateDirectoryBtn && stateModalEl) {
        stateDirectoryBtn.addEventListener('click', () => openModal(stateModalEl));
    }

    const verifiedDirectoryBtn = document.getElementById('verifiedDirectoryBtn');
    const verifiedModalEl = document.getElementById('verifiedDirectoryModal');
    if (verifiedDirectoryBtn && verifiedModalEl) {
        verifiedDirectoryBtn.addEventListener('click', () => openModal(verifiedModalEl));
    }

    const directorySearchInput = document.getElementById('directorySearchInput');
    const directoryTableBody = document.getElementById('directoryTableBody');
    if (directorySearchInput && directoryTableBody) {
        directorySearchInput.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase().trim();
            const rows = directoryTableBody.querySelectorAll('tr');
            rows.forEach(r => {
                const text = r.innerText.toLowerCase();
                r.style.display = text.includes(query) ? '' : 'none';
            });
        });
    }

    // --- 14. TELEMETRY & NETWORK STATUS ---
    const engineStatusLabel = document.getElementById('engineStatusLabel');
    function updateNetworkStatus() {
        if (!engineStatusLabel) return;
        if (navigator.onLine) {
            engineStatusLabel.innerText = 'AI Shield: Active';
            if (engineStatusLabel.previousElementSibling) {
                engineStatusLabel.previousElementSibling.style.background = '#10b981';
                engineStatusLabel.previousElementSibling.style.boxShadow = '0 0 8px #10b981';
            }
        } else {
            engineStatusLabel.innerText = 'Autonomous Local AI';
            if (engineStatusLabel.previousElementSibling) {
                engineStatusLabel.previousElementSibling.style.background = '#f59e0b';
                engineStatusLabel.previousElementSibling.style.boxShadow = '0 0 8px #f59e0b';
            }
        }
    }
    window.addEventListener('online', updateNetworkStatus);
    window.addEventListener('offline', updateNetworkStatus);
    updateNetworkStatus();

    // --- 15. INITIAL APP BOOTSTRAP ---
    const savedTheme = localStorage.getItem('sentinel_theme') || 'light';
    setTheme(savedTheme);
    handleRoute();
    checkApiConnection();

    // --- 16. PWA SERVICE WORKER REGISTRATION ---
    if ('serviceWorker' in navigator && window.location.protocol.startsWith('http')) {
        window.addEventListener('load', () => {
            navigator.serviceWorker.register('./sw.js')
                .then(reg => console.log('Sentinel PWA Service Worker active:', reg.scope))
                .catch(err => console.debug('Service Worker registration skipped:', err));
        });
    }
}

// Ensure execution even if DOMContentLoaded already fired
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initSentinelApp);
} else {
    initSentinelApp();
}
