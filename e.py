import re

# 🚨 Common phishing keywords
PHISHING_KEYWORDS = [
    "urgent", "suspended", "verify", "login", "click here", "update", 
    "security alert", "account locked", "free", "winner", "gift", "limited time"
]

# 🚨 Fake domains often used in phishing emails
SUSPICIOUS_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "security-alert.com", "bank-alerts.com"]

# 🚨 Regular expression to detect fake/malicious URLs
SUSPICIOUS_URL_PATTERN = re.compile(r"https?://(?:www\.)?([a-zA-Z0-9.-]+)")

def check_email(sender, subject, body):
    risk_score = 0  # Initialize risk score
    
    # ✅ Step 1: Check the sender's email domain
    sender_domain = sender.split('@')[-1]
    if sender_domain in SUSPICIOUS_DOMAINS:
        risk_score += 2
        print(f"⚠️ Warning: The sender's email domain '{sender_domain}' is suspicious.")
    
    # ✅ Step 2: Check for phishing keywords in subject & body
    for keyword in PHISHING_KEYWORDS:
        if keyword in subject.lower() or keyword in body.lower():
            risk_score += 1
            print(f"⚠️ Warning: The email contains phishing keyword -> '{keyword}'")
    
    # ✅ Step 3: Check for suspicious URLs
    urls = SUSPICIOUS_URL_PATTERN.findall(body)
    for url in urls:
        if not url.endswith(("com", "org", "net")):  # Very basic domain validation
            risk_score += 2
            print(f"⚠️ Warning: Suspicious link detected -> {url}")
    
    # ✅ Step 4: Decision based on risk score
    if risk_score >= 3:
        return "🚨 This email is **MALICIOUS**. Do NOT click any links!"
    else:
        return "✅ This email appears **SAFE**, but always double-check!"

# 🎯 Get user input for email details
sender_email = input("Enter sender's email: ")
subject = input("Enter email subject: ")
body = input("Enter email body: ")

# 🔍 Run the phishing detection
result = check_email(sender_email, subject, body)
print("\n" + result)
