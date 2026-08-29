import re
import math
from urllib.parse import urlparse, parse_qs

class URLProcessor:
    def __init__(self):
        self.suspicious_tlds = {
            '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc',
            '.club', '.online', '.buzz', '.work', '.click', '.monster', '.icu',
            '.fit', '.rest', '.bar', '.cam', '.sbs', '.cfd', '.quest', '.beauty'
        }
        self.shorteners = {
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'cutt.ly', 'v.gd', 'rb.gy', 'shorte.st',
            'trib.al', 'wa.me', 'shorturl.at', 'rebrand.ly'
        }

        self.sensitive_keywords = [
            'login', 'secure', 'account', 'banking', 'update', 'verify',
            'wallet', 'auth', 'signin', 'support', 'checkpoint', 'confirm',
            'passcode', 'recovery', 'billing', 'paypal', 'metamask', 'binance',
            'security-check', 'authenticate', 're-login', 'claim', 'airdrop',
            'echallan', 'epfo', 'pmkisan', 'incometax', 'aadhaar', 'bijlibill'
        ]
        
        # Monitored Canonical Brands: Global & Indian Public Digital Touchpoints
        self.monitored_brands = [
            # Indian Public Services & Portals
            'parivahan', 'echallan', 'epfo', 'pmkisan', 'irctc',
            'uidai', 'aadhaar', 'incometax', 'digilocker', 'sbi', 'yono',
            'hdfcbank', 'icicibank', 'kotak', 'paytm', 'phonepe', 'gpay',
            'bescom', 'mseb', 'tneb', 'uppcl', 'dhbvn',
            # Global Brands
            'paypal', 'microsoft', 'apple', 'google', 'amazon', 'netflix',
            'chase', 'wellsfargo', 'bankofamerica', 'binance', 'coinbase',
            'metamask', 'facebook', 'instagram', 'whatsapp', 'twitter',
            'linkedin', 'steam', 'discord', 'telegram', 'spotify', 'adobe',
            'dropbox', 'github', 'gitlab', 'cloudflare', 'stripe', 'dhl',
            'fedex', 'usps', 'ups', 'ebay', 'walmart', 'citibank', 'hsbc',
            'barclays', 'kraken', 'kucoin', 'ledger', 'trezor', 'outlook',
            'yahoo', 'icloud', 'protonmail', 'blockchain', 'trustwallet'
        ]
        
        self.trusted_gov_tlds = ('.gov.in', '.nic.in', '.gov', '.mil', '.ac.in', '.edu.in')
        
        self.homoglyph_map = {
            '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
            '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i'
        }

    def get_entropy(self, text):
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        for x in set(text):
            p_x = float(text.count(x)) / length
            entropy -= p_x * math.log(p_x, 2)
        return entropy

    def levenshtein_distance(self, s1, s2):
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def normalize_homoglyphs(self, text):
        normalized = text.lower()
        for char, sub in self.homoglyph_map.items():
            normalized = normalized.replace(char, sub)
        # Normalize double 'v' to 'w' and 'rn' to 'm'
        normalized = normalized.replace('vv', 'w').replace('rn', 'm')
        return normalized

    def detect_typosquatting(self, domain_label):
        normalized_full = self.normalize_homoglyphs(domain_label)
        tokens = re.split(r'[-.]', domain_label.lower())
        
        for brand in self.monitored_brands:
            # Skip if domain label is exactly the brand or brand is root
            if domain_label.lower() == brand or brand in domain_label.lower():
                # Check if it has suspicious prefixes/suffixes with hyphens e.g. echallan-pay.xyz
                if f"{brand}-" in normalized_full or f"-{brand}" in normalized_full:
                    return brand, 0, "Composite Portal / Brand Impersonation"
                continue

            # 1. Exact or composite match in normalized string (e.g. paypa1-security, echallan-pay, sbi-yono)
            if brand != domain_label and (f"{brand}-" in normalized_full or f"-{brand}" in normalized_full or f"{brand}." in normalized_full):
                return brand, 0, "Composite Portal / Brand Impersonation"
            
            # 2. Check each token individually
            for tok in tokens:
                clean_tok = re.sub(r'[^a-z0-9]', '', tok)
                norm_tok = self.normalize_homoglyphs(clean_tok)
                
                # Direct match after homoglyph substitution (e.g. paypa1 -> paypal, micros0ft -> microsoft, sb1 -> sbi)
                if norm_tok == brand and clean_tok != brand:
                    return brand, 1, "Visual Homoglyph Substitution"
                    
                # If token is identical to brand or brand is substring of token, skip
                if clean_tok == brand or brand in clean_tok:
                    continue

                # Levenshtein distance on token
                dist = self.levenshtein_distance(clean_tok, brand)
                norm_dist = self.levenshtein_distance(norm_tok, brand)
                min_dist = min(dist, norm_dist)
                
                if len(brand) >= 3 and min_dist > 0:
                    if len(brand) <= 6 and min_dist == 1 and abs(len(clean_tok) - len(brand)) <= 1:
                        return brand, min_dist, "High-Confidence Typosquatting"
                    elif len(brand) > 6 and min_dist <= 2 and abs(len(clean_tok) - len(brand)) <= 2:
                        return brand, min_dist, "High-Confidence Typosquatting"
                        
        return None, None, None

    def analyze_upi_link(self, raw_url):
        try:
            parsed = urlparse(raw_url)
            query = parse_qs(parsed.query)
            pa = query.get('pa', [''])[0].lower()
            pn = query.get('pn', [''])[0]
            
            score = 0.05
            flags = []
            
            if not pa:
                return 0.55, {
                    "flags": ["Missing Payee Address (VPA) in UPI link"],
                    "model": "UPI-Payment-Security-Engine",
                    "tld": "upi",
                    "entropy": 0.0
                }
                
            personal_psp_handles = ['@okhdfcbank', '@okaxis', '@oksbi', '@okicici', '@paytm', '@ybl', '@ibl', '@apl', '@axl', '@upi']
            gov_keywords = ['parivahan', 'echallan', 'traffic', 'electricity', 'bijli', 'epfo', 'pmkisan', 'tax', 'police', 'challan']
            
            pn_lower = pn.lower()
            is_claiming_gov = any(k in pn_lower for k in gov_keywords) or any(k in pa for k in gov_keywords)
            has_personal_psp = any(pa.endswith(h) for h in personal_psp_handles)
            
            if is_claiming_gov and has_personal_psp:
                score += 0.85
                flags.append(f"Deceptive UPI Impersonation: Individual VPA ('{pa}') posing as '{pn or 'Public Service'}'")
            elif is_claiming_gov and not any(pa.endswith(h) for h in ['@sbi', '@billdesk', '@gov', '@hdfcbank', '@icici']):
                score += 0.45
                flags.append(f"Unverified Public Service VPA Handle ('{pa}')")
                
            if 'fake' in pa or 'fake' in pn_lower:
                score += 0.60
                flags.append("Simulated malicious payment address indicator")
                
            confidence = min(max(score, 0.05), 0.99)
            return round(confidence, 2), {
                "flags": flags,
                "model": "UPI-Payment-Security-Engine",
                "tld": "upi",
                "entropy": round(self.get_entropy(pa), 2),
                "typosquatting": None
            }
        except Exception:
            return 0.60, {"flags": ["Malformed UPI link syntax"], "model": "UPI-Payment-Security-Engine", "tld": "upi", "entropy": 0.0}

    def analyze_url(self, raw_url):
        if not raw_url or not raw_url.strip():
            return 0.0, {"flags": [], "model": "Heuristic-URL-Analyzer", "entropy": 0.0, "tld": ""}
            
        url = raw_url.strip()

        # Check UPI Payment Links
        if url.startswith("upi://") or "upi://pay" in url:
            return self.analyze_upi_link(url)

        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
            
        try:
            parsed_url = urlparse(url)
        except Exception:
            return 0.60, {"flags": ["Malformed URL syntax"], "model": "Heuristic-URL-Analyzer", "entropy": 0.0, "tld": ""}

        domain = parsed_url.netloc.lower()
        domain_without_port = domain.split(':')[0] if ':' in domain else domain
        path = (parsed_url.path + parsed_url.query).lower()

        # 0. Official Trusted Government Portal Exemption
        if domain_without_port.endswith(self.trusted_gov_tlds) and raw_url.startswith("https://"):
            return 0.02, {
                "flags": [],
                "model": "Verified-Official-Government-Portal",
                "entropy": round(self.get_entropy(domain_without_port), 2),
                "tld": "." + domain_without_port.split('.')[-1],
                "typosquatting": None
            }
        
        score = 0.05
        flags = []
        
        # 1. HTTPS Check
        if not raw_url.startswith("https://"):
            score += 0.20
            flags.append("Missing HTTPS protocol encryption")
            
        # 2. IP Address as Domain
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_without_port):
            score += 0.55
            flags.append("Direct IP address used instead of domain name")
            
        # 3. Multiple subdomains
        dot_count = domain_without_port.count('.')
        if dot_count > 3:
            score += 0.30
            flags.append(f"Suspicious subdomain depth ({dot_count} levels)")
            
        # 4. Use of '@' symbol
        if '@' in url:
            score += 0.50
            flags.append("Contains '@' symbol (credential/redirection masking)")
            
        # 5. URL Entropy
        entropy = self.get_entropy(domain_without_port)
        if entropy > 3.8:
            score += 0.30
            flags.append(f"High domain randomness entropy ({entropy:.2f})")
            
        # 6. URL Shortener Detection
        if domain_without_port in self.shorteners:
            score += 0.35
            flags.append(f"URL Shortener detected ({domain_without_port})")
            
        # 7. Suspicious TLDs
        parts = domain_without_port.split('.')
        tld = "." + parts[-1] if len(parts) > 1 else ""
        if tld in self.suspicious_tlds:
            score += 0.45
            flags.append(f"High-risk TLD detected ({tld})")
            
        # 8. Non-ASCII Characters & Punycode (Homograph Attack)
        if not all(ord(c) < 128 for c in domain_without_port) or "xn--" in domain_without_port:
            score += 0.80
            flags.append("IDN / Punycode characters (Homograph attack indicator)")

        # 9. Typosquatting & Brand / Portal Spoofing Check
        main_label = parts[0] if len(parts) > 0 else domain_without_port
        targeted_brand, dist, reason = self.detect_typosquatting(main_label)
        if targeted_brand:
            score += 0.55
            flags.append(f"Typosquatting detected: Spoofing '{targeted_brand.upper()}' ({reason})")
            
        # 10. Sensitive Keywords in Path or Subdomain
        for kw in self.sensitive_keywords:
            if kw in path or kw in domain_without_port.split('.')[0]:
                score += 0.30
                flags.append(f"Sensitive credential keyword targeting: '{kw}'")
                break
                
        # 11. Excessive hyphens
        if domain_without_port.count('-') > 2:
            score += 0.20
            flags.append("Excessive hyphens in hostname")

        # 12. Suspicious non-standard ports
        if ':' in domain:
            port = domain.split(':')[1]
            if port not in ['80', '443', '8000', '5000']:
                score += 0.25
                flags.append(f"Uncommon port connection (:{port})")

        # Normalize score
        confidence = min(max(score, 0.04), 0.99)

        # Generate citizen advisory
        advisory = None
        if targeted_brand:
            advisory = f"Suspected typosquatting targeting '{targeted_brand.upper()}'. Always verify official domains directly on authentic .gov.in or official banking portals."
        elif domain_without_port in self.shorteners:
            advisory = "URL shortener detected. Official Indian public services and electricity discoms never send shortened links for bill payments or notices."
        elif confidence > 0.50:
            advisory = "High-risk link detected. Do not enter credentials, OTPs, or make UPI payments on unverified external websites."


        return round(confidence, 2), {
            "flags": flags,
            "model": "Heuristic-URL-Analyzer",
            "entropy": round(entropy, 2),
            "tld": tld,
            "citizen_advisory": advisory,
            "typosquatting": {
                "detected": targeted_brand is not None,
                "targeted_brand": targeted_brand,
                "distance": dist
            } if targeted_brand else None
        }


url_processor = URLProcessor()
