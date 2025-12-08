{
  "executives": {
    "_comment": "Add your executive/VIP email addresses here for enhanced BEC protection"
  },
  "company_domains": [],
  "trusted_vendors": [
    "dattobackup.com",
    "apollomx.com"
  ],
  "trusted_domains": [
    "gmail.com",
    "outlook.com",
    "yahoo.com"
  ],
  "thresholds": {
    "high_risk": 0.25,
    "medium_risk": 0.15,
    "low_risk": 0.1
  },
  "financial_keywords": [
    "wire transfer",
    "bank transfer",
    "payment",
    "invoice",
    "gift card",
    "itunes",
    "amazon card",
    "google play",
    "bitcoin",
    "cryptocurrency",
    "paypal",
    "venmo"
  ],
  "urgency_multipliers": {
    "asap": 1.5,
    "urgent": 1.3,
    "immediately": 1.4,
    "emergency": 1.6,
    "time sensitive": 1.4,
    "deadline": 1.3
  },
  "time_zones": {
    "business_hours_start": 8,
    "business_hours_end": 18,
    "suspicious_hours": [22, 23, 0, 1, 2, 3, 4, 5, 6]
  },
  "whitelist": {
    "senders": [
      "noreply@dattobackup.com",
      "reporting@dattobackup.com",
      "crm@yourdomain.com"
    ],
    "subjects": [
      "automated report",
      "system notification",
      "backup report"
    ]
  },
  "detection_patterns": {
    "urgency_keywords": [
      "urgent", "asap", "immediately", "right away", "quickly", 
      "before end of day", "by close of business", "time sensitive",
      "emergency", "deadline"
    ],
    "authority_keywords": [
      "please handle", "need you to", "can you take care", "I need",
      "handle this for me", "take care of this", "please process"
    ],
    "secrecy_keywords": [
      "confidential", "private", "don't discuss", "between us",
      "keep this quiet", "sensitive matter", "discrete"
    ],
    "dating_spam_keywords": [
      "dating", "relationship", "love", "romance", "meet", "single",
      "lonely", "looking for", "companion", "chat", "personal",
      "interested in you", "get to know", "spend time", "coffee",
      "dinner", "date", "beautiful", "handsome", "attractive"
    ],
    "romance_scam_indicators": [
      "widow", "widower", "military", "deployed", "overseas",
      "business trip", "inheritance", "family money", "trust fund",
      "need help", "financial assistance", "temporary loan",
      "travel money", "emergency funds", "hospital bills"
    ],
    "social_engineering": [
      "verify your", "confirm your", "update your", "click here",
      "login to", "reset password", "account suspended",
      "verify identity", "security alert", "unauthorized access"
    ]
  },
  "gmail_specific_patterns": {
    "suspicious_display_names": [
      "Dating Service", "Match Maker", "Romance", "Singles",
      "Meet Local", "Find Love", "Dating App", "Relationship"
    ],
    "common_dating_domains": [
      "match.com", "eharmony.com", "pof.com", "zoosk.com",
      "okcupid.com", "tinder.com", "bumble.com"
    ],
    "fake_profile_indicators": [
      "new to the area", "just moved", "traveling for work",
      "business owner", "self employed", "entrepreneur",
      "recent photos", "profile picture", "verify photos"
    ]
  },
  "authentication_risk_factors": {
    "spf_fail_multiplier": 1.5,
    "dkim_fail_multiplier": 1.3,
    "dmarc_fail_multiplier": 2.0,
    "gmail_auth_fail_high_risk": true
  },
  "geographic_risk": {
    "high_risk_countries": ["NG", "GH", "CI", "ML", "BF", "CN", "RU"],
    "mismatch_detection": true,
    "timezone_analysis": true
  },
  "response_patterns": {
    "high_confidence_action": "quarantine",
    "medium_confidence_action": "flag", 
    "low_confidence_action": "monitor",
    "whitelist_override": true
  },
  "logging": {
    "level": "DEBUG",
    "log_file": "/var/log/spacyserver/bec_detection.log",
    "retention_days": 30
  }
}
