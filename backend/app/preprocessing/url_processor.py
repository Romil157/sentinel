import re
import math
from urllib.parse import urlparse

class URLProcessor:
    def __init__(self):
        pass
        
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
        
        # 1. HTTPS Check
        if not url.startswith("https://"):
            score += 0.3
            flags.append("Missing HTTPS protocol")
            
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # 2. IP Address as Domain
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            score += 0.5
            flags.append("IP address used instead of domain name")
            
        # 3. Multiple subdomains (e.g. www.paypal.com.secure.login.com)
        if domain.count('.') > 3:
            score += 0.2
            flags.append("Suspicious number of subdomains")
            
        # 4. Use of '@' symbol (often used to obscure the actual domain)
        if '@' in url:
            score += 0.4
            flags.append("Contains '@' symbol")
            
        # 5. URL Entropy (high entropy often means randomly generated DGA domains)
        entropy = self.get_entropy(domain)
        if entropy > 4.0:
            score += 0.2
            flags.append(f"High domain entropy ({entropy:.2f})")
            
        # Normalize score
        confidence = min(score, 0.99)
        result = "Phishing/Suspicious" if confidence > 0.5 else "Safe"
        
        return result, confidence, {"flags": flags, "model": "Heuristic-URL-Analyzer"}

url_processor = URLProcessor()
