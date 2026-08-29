/**
 * Netlify Serverless Function for Sentinel Verify API
 * Provides native serverless endpoints on Netlify for threat detection,
 * health checks, intelligence feed, and analytics.
 */

const URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'suspended', 'locked', 'within 24 hours',
    'action required', 'unauthorized access', 'account terminated',
    'security alert', 'final notice', 'overdue', 'deactivation'
];

const FINANCIAL_KEYWORDS = [
    'winner', 'lottery', 'claim your prize', 'bank account', 'credit card',
    'refund', 'payment', 'bitcoin', 'crypto', 'wallet drain', 'wire transfer',
    'invoice unpaid', 'gift card', 'compensation'
];

const BRAND_KEYWORDS = [
    'paypal', 'netflix', 'amazon', 'microsoft', 'apple', 'google',
    'chase', 'wells fargo', 'binance', 'coinbase', 'metamask', 'dhl', 'fedex',
    'parivahan', 'echallan', 'epfo', 'pmkisan', 'irctc', 'uidai', 'aadhaar', 'incometax', 'digilocker', 'sbi', 'yono', 'hdfc', 'icici', 'pnb', 'bijli'
];

const INDIAN_SIGNATURES = [
    { pattern: /(electricity|bijli|power).*(disconnect|unpaid|update bill|officer)/i, flag: "Electricity Bill (Bijli Vibhag) Disconnection Scam Signature", advisory: "Electricity companies never threaten same-day disconnection via personal SMS or unofficial payment links." },
    { pattern: /(echallan|challan|parivahan|traffic).*(pending|impound|fine|court)/i, flag: "Fake e-Challan / Parivahan Traffic Fine Scam", advisory: "Official vehicle challans are only processed on parivahan.gov.in, never on .xyz or .top domains." },
    { pattern: /(pm[\s-]?kisan|subsidy|yojana).*(installment|approved|claim|credit)/i, flag: "PM-Kisan / Government Subsidy Bait", advisory: "Government welfare subsidies are directly transferred via DBT to your bank account without external links." },
    { pattern: /(epfo|uan|pf).*(block|suspend|pan link|kyc)/i, flag: "EPFO / UAN KYC Suspension Fraud", advisory: "EPFO updates must only be performed on unifiedportal-mem.epfindia.gov.in." },
    { pattern: /(income[\s-]?tax|itr).*(refund|credited|approve)/i, flag: "Income Tax Department Refund Scam", advisory: "Income Tax refunds are processed directly into pre-validated bank accounts without SMS verification links." }
];

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.club', '.online', '.buzz'];
const SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly'];

function calculateSeverity(confidence) {
    if (confidence < 0.20) return "Safe";
    if (confidence < 0.40) return "Low Risk";
    if (confidence < 0.60) return "Suspicious";
    if (confidence < 0.80) return "High Risk";
    return "Critical Threat";
}

function analyzeText(rawText) {
    const lower = (rawText || '').toLowerCase();
    const flags = [];
    let score = 0.05;
    let advisory = null;

    for (const sig of INDIAN_SIGNATURES) {
        if (sig.pattern.test(rawText)) {
            score += 0.50;
            flags.push(sig.flag);
            if (!advisory) advisory = sig.advisory;
            break;
        }
    }

    for (const kw of URGENCY_KEYWORDS) {
        if (lower.includes(kw)) {
            score += 0.25;
            flags.push(`Urgency indicator: '${kw}'`);
            break;
        }
    }

    for (const kw of FINANCIAL_KEYWORDS) {
        if (lower.includes(kw)) {
            score += 0.30;
            flags.push(`Financial trigger: '${kw}'`);
            break;
        }
    }

    if (/\bOTP\b/i.test(rawText) || /verification code/i.test(rawText)) {
        score += 0.40;
        flags.push("Credential / OTP Harvesting Pattern");
    }

    for (const brand of BRAND_KEYWORDS) {
        if (lower.includes(brand) && (score > 0.2 || lower.includes('verify') || lower.includes('update'))) {
            score += 0.20;
            flags.push(`Brand targeting marker: '${brand.toUpperCase()}'`);
            break;
        }
    }

    const confidence = Math.min(Math.max(score, 0.04), 0.99);
    const severity = calculateSeverity(confidence);

    const heatMap = {};
    (rawText || '').split(/\s+/).forEach(w => {
        const clean = w.toLowerCase().replace(/[^a-z0-9]/g, '');
        if (clean.length > 3) {
            let heat = 0.15;
            if (URGENCY_KEYWORDS.some(k => k.includes(clean))) heat = 0.85;
            else if (FINANCIAL_KEYWORDS.some(k => k.includes(clean))) heat = 0.75;
            else if (BRAND_KEYWORDS.includes(clean)) heat = 0.65;
            heatMap[clean] = heat;
        }
    });

    return {
        input_type: 'text',
        severity_level: severity,
        confidence_score: Math.round(confidence * 100) / 100,
        indicators: flags,
        explainability: {
            flags,
            model: 'Netlify-Serverless-NLP-Engine',
            keyword_heatmap: heatMap,
            citizen_advisory: advisory
        }
    };
}

function analyzeUrl(rawUrl) {
    let url = (rawUrl || '').trim();
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'http://' + url;
    }

    let parsed;
    try {
        parsed = new URL(url);
    } catch (e) {
        return {
            input_type: 'url',
            severity_level: 'Suspicious',
            confidence_score: 0.55,
            indicators: ['Malformed URL syntax'],
            explainability: { flags: ['Malformed URL'], model: 'Netlify-URL-Analyzer' }
        };
    }

    const domain = parsed.hostname.toLowerCase();
    const path = (parsed.pathname + parsed.search).toLowerCase();
    let score = 0.05;
    const flags = [];

    if (!rawUrl.startsWith('https://')) {
        score += 0.20;
        flags.push('Missing HTTPS protocol encryption');
    }

    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
        score += 0.55;
        flags.push('Direct IP address used instead of hostname');
    }

    if (SHORTENERS.includes(domain)) {
        score += 0.35;
        flags.push(`URL Shortener detected (${domain})`);
    }

    const parts = domain.split('.');
    const tld = parts.length > 1 ? '.' + parts[parts.length - 1] : '';
    if (SUSPICIOUS_TLDS.includes(tld)) {
        score += 0.45;
        flags.push(`High-risk TLD (${tld})`);
    }

    const confidence = Math.min(Math.max(score, 0.04), 0.99);
    const severity = calculateSeverity(confidence);

    return {
        input_type: 'url',
        severity_level: severity,
        confidence_score: Math.round(confidence * 100) / 100,
        indicators: flags,
        explainability: {
            flags,
            model: 'Netlify-Serverless-URL-Engine',
            tld
        }
    };
}

exports.handler = async (event) => {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, X-API-Key, Authorization',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Content-Type': 'application/json'
    };

    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    const path = event.path.replace(/\/\.netlify\/functions\/api/, '');

    if (path === '/health' || path === '/api/v1/health' || path === '') {
        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                status: 'healthy',
                service: 'Sentinel Netlify Serverless Engine',
                version: '2.0.0',
                timestamp: new Date().toISOString()
            })
        };
    }

    if (event.httpMethod === 'POST') {
        let body = {};
        try {
            body = JSON.parse(event.body || '{}');
        } catch (e) {}

        if (path.includes('predict/text')) {
            const result = analyzeText(body.text || '');
            return { statusCode: 200, headers, body: JSON.stringify(result) };
        }

        if (path.includes('predict/url')) {
            const result = analyzeUrl(body.url || '');
            return { statusCode: 200, headers, body: JSON.stringify(result) };
        }
    }

    return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ message: 'Sentinel Verify Netlify Serverless Endpoint' })
    };
};
