import re
import math
from urllib.parse import urlparse

class URLProcessor:
    def __init__(self):
        self.suspicious_tlds = {'.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.club', '.online'}
        self.shorteners = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly'}
        self.sensitive_keywords = ['login', 'secure', 'account', 'banking', 'update', 'verify', 'wallet', 'auth', 'signin', 'support']
        
    def get_entropy(self, text):
        if not text:
            return 0
        entropy = 0
        for x in set(text):
            p_x = float(text.count(x)) / len(text)
            entropy += - p_x * math.log(p_x, 2)
        return entropy

    def analyze_url(self, url):
        score = 0.0
        flags = []
        
        if not url.startswith("http"):
            url = "http://" + url
            
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        
        # 1. HTTPS Check
        if not url.startswith("https://"):
            score += 0.2
            flags.append("Missing HTTPS protocol")
            
        # 2. IP Address as Domain
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            score += 0.6
            flags.append("IP address used instead of domain name")
            
        # 3. Multiple subdomains
        if domain.count('.') > 3:
            score += 0.3
            flags.append(f"Suspicious number of subdomains ({domain.count('.')})")
            
        # 4. Use of '@' symbol
        if '@' in url:
            score += 0.5
            flags.append("Contains '@' symbol (credential masking)")
            
        # 5. URL Entropy
        entropy = self.get_entropy(domain)
        if entropy > 4.0:
            score += 0.3
            flags.append(f"High domain entropy ({entropy:.2f})")
            
        # 6. URL Shortener Detection
        if domain in self.shorteners:
            score += 0.4
            flags.append(f"URL Shortener detected ({domain})")
            
        # 7. Suspicious TLDs
        tld = "." + domain.split('.')[-1] if '.' in domain else ""
        if tld in self.suspicious_tlds:
            score += 0.5
            flags.append(f"Suspicious TLD used ({tld})")
            
        # 8. Non-ASCII Characters (Homograph Attack Indicator)
        if not all(ord(c) < 128 for c in domain):
            score += 0.8
            flags.append("Contains non-ASCII characters (Possible Homograph Attack)")
            
        # 9. Sensitive Keywords in Path or Subdomain
        for kw in self.sensitive_keywords:
            if kw in path or kw in domain.split('.')[0]:
                score += 0.4
                flags.append(f"Sensitive keyword targeting: '{kw}'")
                
        # 10. Excessive hyphens
        if domain.count('-') > 2:
            score += 0.2
            flags.append("Excessive hyphens in domain")

        # Normalize score
        confidence = min(score, 0.99)
        
        return confidence, {"flags": flags, "model": "Heuristic-URL-Analyzer", "entropy": round(entropy, 2), "tld": tld}

url_processor = URLProcessor()
