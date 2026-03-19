import email
import re
import os
import sys
import json
import math
from email import policy
from dataclasses import dataclass, asdict
from typing import List
from urllib.parse import urlparse

# ---------------- CONFIG ---------------- #

SUSPICIOUS_TLDS = {".xyz", ".top", ".bid", ".click", ".ru", ".cn"}

WEIGHTS = {
    "header": 0.4,
    "content": 0.3,
    "url": 0.3
}

# ---------------- DATA STRUCTURE ---------------- #

@dataclass
class Result:
    file: str
    score: float
    classification: str
    confidence: str
    indicators: int
    flags: List[str]

# ---------------- CORE CLASS ---------------- #

class PhishingDetector:

    def __init__(self):
        self.reset()

    def reset(self):
        self.header_score = 0
        self.content_score = 0
        self.url_score = 0
        self.flags = []
        self.indicators = 0

    # ---------------- UTIL ---------------- #

    def extract_urls(self, text):
        return re.findall(r"(https?://[^\s]+|www\.[^\s]+)", text)

    def shannon_entropy(self, domain):
        if not domain:
            return 0
        prob = [float(domain.count(c)) / len(domain) for c in dict.fromkeys(domain)]
        return -sum([p * math.log2(p) for p in prob])

    def extract_domain(self, url):
        try:
            return urlparse(url).netloc.lower()
        except:
            return ""

    # ---------------- HEADER ---------------- #

    def analyze_headers(self, msg):

        auth = msg.get("Authentication-Results", "").lower()
        received_spf = msg.get("Received-SPF", "").lower()
        from_header = msg.get("From", "").lower()

        # SPF
        if "fail" in auth or "fail" in received_spf:
            self.header_score += 40
            self.flags.append("SPF failed")
            self.indicators += 1

        # DKIM
        if "dkim=fail" in auth or "dkim=none" in auth:
            self.header_score += 40
            self.flags.append("DKIM failed or missing")
            self.indicators += 1

        # DMARC
        if "dmarc=fail" in auth:
            self.header_score += 40
            self.flags.append("DMARC failed")
            self.indicators += 1

        # Multiple failure boost
        fail_count = sum([
            "SPF failed" in self.flags,
            "DKIM failed or missing" in self.flags,
            "DMARC failed" in self.flags
        ])
        if fail_count >= 2:
            self.header_score += 20
            self.flags.append("Multiple authentication failures")

        # Display name spoofing
        if "paypal" in from_header and "paypal.com" not in from_header:
            self.header_score += 30
            self.flags.append("Display name spoofing (PayPal)")
            self.indicators += 1

        # Extract Origin IP
        received = msg.get_all("Received", [])
        for r in received:
            ip_match = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", r)
            if ip_match:
                self.flags.append(f"Origin IP: {ip_match.group(1)}")
                break

    # ---------------- CONTENT ---------------- #

    def analyze_content(self, msg, body):

        if not body:
            return

        keywords = ["urgent", "verify", "password", "click", "login"]

        # Subject analysis
        subject = msg.get("Subject", "")
        for word in keywords:
            if word in subject.lower():
                self.content_score += 8
                self.flags.append(f"Suspicious subject keyword: {word}")
                self.indicators += 1

        # Body keywords
        for word in keywords:
            if word in body.lower():
                self.content_score += 5
                self.flags.append(f"Keyword: {word}")
                self.indicators += 1

        # Generic greeting
        if "dear customer" in body.lower() or "dear user" in body.lower():
            self.content_score += 10
            self.flags.append("Generic greeting")
            self.indicators += 1

    # ---------------- URL ---------------- #

    def analyze_urls(self, msg, body):

        urls = self.extract_urls(body)

        from_header = msg.get("From", "")
        sender_domain = ""

        if "@" in from_header:
            sender_domain = from_header.split("@")[-1].replace(">", "").lower()

        for url in urls:

            domain = self.extract_domain(url)

            # HTTP check
            if url.startswith("http://"):
                self.url_score += 15
                self.flags.append("HTTP link")
                self.indicators += 1

            # Suspicious TLD
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    self.url_score += 20
                    self.flags.append(f"Suspicious TLD: {tld}")
                    self.indicators += 1

            # Punycode
            if "xn--" in domain:
                self.url_score += 25
                self.flags.append("Punycode domain")
                self.indicators += 1

            # Entropy
            if self.shannon_entropy(domain) > 3.5:
                self.url_score += 15
                self.flags.append("High entropy domain")
                self.indicators += 1

            # Domain mismatch
            if sender_domain and domain and sender_domain not in domain:
                self.url_score += 20
                self.flags.append(f"Domain mismatch: {sender_domain} vs {domain}")
                self.indicators += 1

    # ---------------- PIPELINE ---------------- #

    def analyze_email(self, path):

        self.reset()

        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            msg = email.message_from_string(f.read(), policy=policy.default)

        # Extract body safely
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                payload = part.get_payload(decode=True)
                if payload:
                    body = payload.decode(errors='ignore')
                    break
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(errors='ignore')

        # Run analysis
        self.analyze_headers(msg)
        self.analyze_content(msg, body)
        self.analyze_urls(msg, body)

        # Normalize scores
        self.header_score = min(self.header_score, 100)
        self.content_score = min(self.content_score, 50)
        self.url_score = min(self.url_score, 50)

        # Final score
        total_score = (
            self.header_score * WEIGHTS["header"] +
            self.content_score * WEIGHTS["content"] +
            self.url_score * WEIGHTS["url"]
        )

        # Classification
        if total_score > 65:
            classification = "High Risk Phishing"
            confidence = "High"
        elif total_score > 40:
            classification = "Suspicious"
            confidence = "Medium"
        else:
            classification = "Likely Legitimate"
            confidence = "Low"

        return Result(
            file=os.path.basename(path),
            score=round(total_score, 2),
            classification=classification,
            confidence=confidence,
            indicators=self.indicators,
            flags=self.flags
        )

# ---------------- MAIN ---------------- #

if __name__ == "__main__":

    detector = PhishingDetector()

    if len(sys.argv) < 2:
        path = input("Enter .eml file path: ").strip()
    else:
        path = sys.argv[1]

    if not os.path.exists(path):
        print("Invalid path")
        sys.exit(1)

    result = detector.analyze_email(path)

    print("\n===== PHISHING ANALYSIS =====")
    print(json.dumps(asdict(result), indent=4))

    with open("report.json", "w") as f:
        json.dump(asdict(result), f, indent=4)