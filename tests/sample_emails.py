"""
Sample Email Test Suite for Phish-Net Testing

This module contains various email samples for testing the phishing detection system:
- Legitimate emails (expected low risk scores 1-3)
- Suspicious emails (expected medium risk scores 4-6) 
- Phishing emails (expected high risk scores 7-10)
- Edge cases and special scenarios
"""

# Legitimate Email Samples (Expected Risk Score: 1-3)
LEGITIMATE_EMAILS = {
    "corporate_newsletter": {
        "content": """From: newsletters@company.com
To: employee@company.com
Subject: Monthly Company Update - September 2025
Date: Fri, 28 Sep 2025 10:30:00 +0000

Dear Team,

We're excited to share this month's company updates and achievements.

Key Highlights:
• Q3 results exceeded expectations by 15%
• New product launch scheduled for October
• Employee recognition ceremony next Friday

Please join us for the all-hands meeting on October 5th at 2 PM in the main conference room.

Best regards,
The Communications Team
Company Inc.
123 Business Ave, City, ST 12345
""",
        "expected_risk": 1,
        "category": "legitimate",
        "description": "Standard corporate newsletter"
    },
    
    "password_reset_legitimate": {
        "content": """From: security@github.com
To: developer@example.com
Subject: Password Reset Confirmation
Date: Fri, 28 Sep 2025 14:22:33 +0000

Hi developer,

Your password has been successfully reset for your GitHub account.

If this wasn't you, please contact our support team immediately at support@github.com.

For security tips, visit: https://docs.github.com/en/authentication

Thanks,
GitHub Security Team
""",
        "expected_risk": 2,
        "category": "legitimate", 
        "description": "Legitimate service notification"
    },
    
    "meeting_invitation": {
        "content": """From: alice.smith@company.com
To: bob.jones@company.com
Subject: Project Review Meeting - October 2nd
Date: Fri, 28 Sep 2025 16:45:12 +0000

Hi Bob,

Could you join us for the quarterly project review meeting?

Details:
- Date: Tuesday, October 2nd
- Time: 10:00 AM - 11:30 AM
- Location: Conference Room B
- Agenda: Q3 deliverables and Q4 planning

Please confirm your attendance.

Best,
Alice Smith
Project Manager
alice.smith@company.com
Extension: 1234
""",
        "expected_risk": 1,
        "category": "legitimate",
        "description": "Internal meeting invitation"
    }
}

# Suspicious Email Samples (Expected Risk Score: 4-6)
SUSPICIOUS_EMAILS = {
    "urgent_verification": {
        "content": """From: security@service-center.com
To: user@example.com
Subject: URGENT: Verify Your Account Within 24 Hours
Date: Fri, 28 Sep 2025 20:15:44 +0000

Dear Valued Customer,

Your account requires immediate verification due to unusual activity detected.

Please click here to verify: https://verify-account.service-center.com/auth/verify

This link expires in 24 hours. Failure to verify may result in account suspension.

Customer Service Team
""",
        "expected_risk": 5,
        "category": "suspicious",
        "description": "Urgency tactics with generic sender"
    },
    
    "lottery_notification": {
        "content": """From: notifications@international-lottery.org
To: winner@example.com
Subject: Congratulations! You've Won $50,000
Date: Fri, 28 Sep 2025 18:30:17 +0000

Dear Lucky Winner,

You have been selected in our monthly international lottery draw!

Winning Amount: $50,000 USD
Reference Number: LOT/2025/WIN/789

To claim your prize, please provide:
1. Full name and address  
2. Phone number
3. Copy of ID

Reply within 7 days to: claims@international-lottery.org

Congratulations again!
International Lottery Commission
""",
        "expected_risk": 6,
        "category": "suspicious", 
        "description": "Unsolicited prize notification"
    }
}

# Phishing Email Samples (Expected Risk Score: 7-10)
PHISHING_EMAILS = {
    "banking_phish": {
        "content": """From: security@bankoamerica-alerts.com
To: customer@email.com
Subject: Account Suspended - Immediate Action Required
Date: Fri, 28 Sep 2025 23:45:01 +0000

SECURITY ALERT: Your Bank of America account has been temporarily suspended.

Reason: Multiple failed login attempts detected from unknown location.

IMMEDIATE ACTION REQUIRED:
Click here to restore access: http://bankoamerica-verify.suspicious-domain.ru/login

You have 2 hours to verify your identity or your account will be permanently closed.

Enter your:
- Username and Password  
- Social Security Number
- Account Number
- PIN

Bank of America Security
""",
        "expected_risk": 9,
        "category": "phishing",
        "description": "Banking phishing with spoofed domain and credential harvesting"
    },
    
    "paypal_scam": {
        "content": """From: service@paypal-security.net
To: user@example.com  
Subject: Your PayPal Account Will Be Closed
Date: Fri, 28 Sep 2025 21:12:38 +0000

Dear PayPal User,

We detected suspicious activity on your account. Your account will be closed in 24 hours unless you verify your information.

Click to verify now: https://paypal-verification.malicious-site.tk/secure

Provide the following:
• Email and password
• Credit card details  
• SSN for verification

Failure to comply will result in permanent account closure and legal action.

PayPal Security Team
Copyright © PayPal Inc.
""",
        "expected_risk": 10,
        "category": "phishing", 
        "description": "Classic PayPal phishing with threats and credential theft"
    },
    
    "microsoft_fake": {
        "content": """From: microsoft-security@outlook.office.com
To: user@company.com
Subject: Microsoft Office License Expired - Action Required
Date: Fri, 28 Sep 2025 19:33:22 +0000

Your Microsoft Office license has expired.

Download the renewal tool immediately: 
http://office-renewal.download-now.tk/install.exe

WARNING: Your computer may be vulnerable to security threats without proper Office licensing.

Install the renewal tool now to maintain security and compliance.

Microsoft Support Team
This email was sent from a Microsoft secured server.
""",
        "expected_risk": 8,
        "category": "phishing",
        "description": "Malware distribution disguised as Microsoft support"
    }
}

# Edge Case Samples  
EDGE_CASE_EMAILS = {
    "very_short": {
        "content": """From: test@test.com
To: user@user.com
Subject: Hi
Date: Fri, 28 Sep 2025 12:00:00 +0000

Hello.
""",
        "expected_risk": 2,
        "category": "edge_case",
        "description": "Extremely short email content"
    },
    
    "no_urls": {
        "content": """From: friend@example.com
To: you@example.com
Subject: Dinner Plans
Date: Fri, 28 Sep 2025 17:00:00 +0000

Hey there!

Want to grab dinner tomorrow at that new Italian place downtown? 
I heard they have amazing pasta.

Let me know if 7 PM works for you.

Talk soon!
Sarah
""",
        "expected_risk": 1,
        "category": "edge_case", 
        "description": "Personal email with no URLs or suspicious elements"
    },
    
    "mixed_languages": {
        "content": """From: support@service.com
To: user@example.com
Subject: Account Verification / Verificación de Cuenta
Date: Fri, 28 Sep 2025 15:20:30 +0000

Dear Customer / Estimado Cliente,

Please verify your account by clicking the link below:
Por favor verifique su cuenta haciendo clic en el enlace a continuación:

https://verify-mixed-lang.suspicious.com/verify

English: Click here to verify
Español: Haga clic aquí para verificar

Support Team / Equipo de Soporte
""",
        "expected_risk": 6,
        "category": "edge_case",
        "description": "Mixed language phishing attempt"
    }
}

# Compile all samples
ALL_EMAIL_SAMPLES = {
    **LEGITIMATE_EMAILS,
    **SUSPICIOUS_EMAILS, 
    **PHISHING_EMAILS,
    **EDGE_CASE_EMAILS
}

def get_samples_by_category(category: str) -> dict:
    """Get all email samples for a specific category"""
    return {k: v for k, v in ALL_EMAIL_SAMPLES.items() if v["category"] == category}

def get_expected_risk_range(email_key: str) -> tuple:
    """Get expected risk range for an email (allows for some variation)"""
    email_data = ALL_EMAIL_SAMPLES[email_key]
    expected = email_data["expected_risk"]
    
    # Allow ±1 point variation for scoring flexibility
    return (max(1, expected - 1), min(10, expected + 1))

def validate_test_results(email_key: str, actual_risk: int) -> dict:
    """Validate if test results are within expected range"""
    expected_min, expected_max = get_expected_risk_range(email_key)
    email_data = ALL_EMAIL_SAMPLES[email_key]
    
    return {
        "email_key": email_key,
        "category": email_data["category"],
        "description": email_data["description"],
        "expected_risk": email_data["expected_risk"],
        "expected_range": (expected_min, expected_max),
        "actual_risk": actual_risk,
        "passed": expected_min <= actual_risk <= expected_max,
        "deviation": abs(actual_risk - email_data["expected_risk"])
    }