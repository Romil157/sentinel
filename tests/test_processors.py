import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))

from app.preprocessing.text_processor import text_processor
from app.preprocessing.url_processor import url_processor


def test_text_processor_phishing_detection():
    phishing_text = "URGENT: Your PayPal account has been suspended! Please confirm your OTP and bank account immediately."
    confidence, explain = text_processor.predict(phishing_text)
    
    assert confidence >= 0.50
    flags = explain.get('flags', [])
    assert isinstance(flags, list) and len(flags) > 0
    heatmap = str(explain.get('keyword_heatmap', ''))
    assert "paypal" in heatmap or "urgent" in heatmap

def test_text_processor_safe_text():
    safe_text = "Hi team, please find the minutes of our quarterly sync meeting attached."
    confidence, explain = text_processor.predict(safe_text)
    
    assert confidence < 0.35
    flags = explain.get('flags', [])
    assert isinstance(flags, list) and len(flags) == 0

def test_indian_electricity_disconnection_scam():
    bijli_sms = "Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please immediately contact our electricity officer."
    confidence, explain = text_processor.predict(bijli_sms)
    
    assert confidence >= 0.60
    flags = explain.get('flags', [])
    assert isinstance(flags, list)
    assert any("Electricity Bill" in str(f) for f in flags)
    assert explain.get('citizen_advisory') is not None

def test_hinglish_bijli_disconnection_scam():
    hinglish_sms = "Priye grahak, aapka bijli connection aaj raat 9:30 baje kat diya jayega kyuki bill update nahi hua hai. Turant electricity officer se sampark kare."
    confidence, explain = text_processor.predict(hinglish_sms)
    
    assert confidence >= 0.60
    flags = explain.get('flags', [])
    assert isinstance(flags, list)
    assert any("Electricity Bill" in str(f) for f in flags)
    assert explain.get('citizen_advisory') is not None

def test_hinglish_bank_kyc_freeze_scam():
    hinglish_bank = "Namaskar grahak, aapka khata block ho gaya hai. Turant online pan link aur kyc kare nahi to khata band ho jayega."
    confidence, explain = text_processor.predict(hinglish_bank)
    
    assert confidence >= 0.60
    flags = explain.get('flags', [])
    assert isinstance(flags, list)
    assert any("Account Freeze" in str(f) or "EPFO" in str(f) for f in flags)

def test_indian_echallan_scam():
    challan_text = "Parivahan NOTICE: Pending e-Challan #DL8492 against vehicle. Court summons and vehicle impound order issued. Pay fine immediately."
    confidence, explain = text_processor.predict(challan_text)
    
    assert confidence >= 0.60
    flags = explain.get('flags', [])
    assert isinstance(flags, list)
    assert any("e-Challan" in str(f) for f in flags)
    assert explain.get('citizen_advisory') is not None

def test_indian_pmkisan_subsidy_scam():
    kisan_text = "Congratulations! PM-Kisan 17th installment subsidy grant of Rs 2000 has been approved. Claim your prize and payment now."
    confidence, explain = text_processor.predict(kisan_text)
    
    assert confidence >= 0.60
    flags = explain.get('flags', [])
    assert isinstance(flags, list)
    assert any("PM-Kisan" in str(f) for f in flags)

def test_indian_epfo_kyc_scam():
    epfo_text = "Alert: Your EPFO UAN account is suspended due to missing PAN card link. Update KYC immediately."
    confidence, explain = text_processor.predict(epfo_text)
    
    assert confidence >= 0.60
    flags = explain.get('flags', [])
    assert isinstance(flags, list)
    assert any("EPFO" in str(f) for f in flags)

def test_url_processor_malicious_url():
    bad_url = "http://login-verify-account.xyz/auth?user=victim"
    confidence, explain = url_processor.analyze_url(bad_url)
    
    assert confidence >= 0.50
    flags = explain.get('flags', [])
    assert isinstance(flags, list) and len(flags) >= 2
    assert explain.get('tld') == '.xyz'

def test_url_processor_legit_url():
    safe_url = "https://parivahan.gov.in/parivahan/"
    confidence, explain = url_processor.analyze_url(safe_url)
    
    assert confidence < 0.25
    assert "Missing HTTPS" not in str(explain.get('flags', []))

def test_url_processor_ip_address():
    ip_url = "http://192.168.1.1/admin/login"
    confidence, explain = url_processor.analyze_url(ip_url)
    
    assert confidence >= 0.60
    flags = explain.get('flags', [])
    assert isinstance(flags, list)
    assert any("IP address" in str(f) for f in flags)

def test_url_entropy_calculation():
    low_entropy = url_processor.get_entropy("aaaaaaa")
    high_entropy = url_processor.get_entropy("a8f9x2q7z1m4")
    
    assert low_entropy == 0.0
    assert high_entropy > 3.0

def test_url_typosquatting_detection():
    # Test PayPal homoglyph (paypa1)
    url_paypal = "http://paypa1-security.com/login"
    conf1, explain1 = url_processor.analyze_url(url_paypal)
    assert conf1 >= 0.60
    flags1 = explain1.get('flags', [])
    assert isinstance(flags1, list)
    assert any("Typosquatting detected" in str(f) for f in flags1)

    # Test Microsoft substitution (micros0ft)
    url_ms = "http://micros0ft.xyz/auth"
    conf2, explain2 = url_processor.analyze_url(url_ms)
    assert conf2 >= 0.60
    flags2 = explain2.get('flags', [])
    assert isinstance(flags2, list)
    assert any("Typosquatting detected" in str(f) for f in flags2)

    # Test Indian Public Service Typosquatting (echallan / parivahan)
    url_challan = "http://echallan-parivahan.xyz/pay"
    conf3, explain3 = url_processor.analyze_url(url_challan)
    assert conf3 >= 0.60
    flags3 = explain3.get('flags', [])
    assert isinstance(flags3, list)
    assert any("Typosquatting detected" in str(f) for f in flags3)

def test_levenshtein_distance():
    dist1 = url_processor.levenshtein_distance("paypal", "paypa1")
    assert dist1 == 1
    dist2 = url_processor.levenshtein_distance("parivahan", "par1vahan")
    assert dist2 == 1

def test_qr_and_upi_link_inspection():
    fake_qr_url = "http://bijli-bill-payment-update.xyz/pay-meter.php?id=94821"
    conf, explain = url_processor.analyze_url(fake_qr_url)
    assert conf >= 0.60
    assert explain.get('tld') == '.xyz'
    flags = explain.get('flags', [])
    assert isinstance(flags, list)
    assert any("Sensitive credential keyword" in str(f) or "High-risk TLD" in str(f) for f in flags)

def test_upi_vpa_impersonation():
    fake_upi = "upi://pay?pa=fake.traffic.police@okhdfcbank&pn=Parivahan-eChallan-Fine&am=1500"
    conf, explain = url_processor.analyze_url(fake_upi)
    assert conf >= 0.80
    flags = explain.get('flags', [])
    assert isinstance(flags, list)
    assert any("Deceptive UPI Impersonation" in str(f) for f in flags)

def test_valid_merchant_upi():
    valid_upi = "upi://pay?pa=official@sbi&pn=Government-Portal&am=500"
    conf, explain = url_processor.analyze_url(valid_upi)
    assert conf < 0.30

def test_incometax_refund_phishing_scam():
    it_text = "Income Tax Alert: Your tax refund of Rs 18,450 is approved. Click here to confirm your bank account and OTP immediately."
    conf, explain = text_processor.predict(it_text)
    assert conf >= 0.60
    flags = explain.get('flags', [])
    assert isinstance(flags, list)
    assert any("Income Tax" in str(f) or "Financial Demand" in str(f) for f in flags)

def test_irctc_tatkal_refund_scam():
    irctc_text = "IRCTC Alert: Tatkal ticket refund of Rs 2,400 pending. Confirm UPI pin and OTP to receive instant credit."
    conf, explain = text_processor.predict(irctc_text)
    assert conf >= 0.60
    flags = explain.get('flags', [])
    assert isinstance(flags, list)
    assert any("OTP" in str(f) or "Urgency" in str(f) or "Financial Demand" in str(f) for f in flags)

def test_forensic_evidence_and_threat_scoring():
    suspicious_sms = "BESCOM: Dear customer your power supply will be stopped tonight at 9:30 pm. Pay immediately."
    conf, explain = text_processor.predict(suspicious_sms)
    assert conf >= 0.50
    advisory = str(explain.get("citizen_advisory", ""))
    assert len(advisory) > 10

def test_regional_threat_variations():
    regional_sms = "Aapka Bijli bil bakaya hai. Turant diye gaye number par sampark kare nahi to light kat di jayegi."
    conf, explain = text_processor.predict(regional_sms)
    assert conf >= 0.50
    flags = explain.get('flags', [])
    assert isinstance(flags, list) and len(flags) > 0

def test_url_shortener_masking_detection():
    short_url = "http://bit.ly/echallan-quick-pay"
    conf, explain = url_processor.analyze_url(short_url)
    assert conf >= 0.40
    flags = explain.get('flags', [])
    assert isinstance(flags, list)
    assert any("shortener" in str(f).lower() for f in flags)
    advisory = str(explain.get("citizen_advisory", ""))
    assert "shortener" in advisory.lower() or "discom" in advisory.lower()

def test_verified_directory_integrity():
    gov_url = "https://bescom.karnataka.gov.in/portal"
    conf, explain = url_processor.analyze_url(gov_url)
    assert conf <= 0.20
    flags = explain.get('flags', [])
    assert isinstance(flags, list) and len(flags) == 0
