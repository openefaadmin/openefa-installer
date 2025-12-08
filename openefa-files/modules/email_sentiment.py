# /opt/spacyserver/modules/email_sentiment.py
"""
Email Sentiment Analysis Module
Compatible with existing SpaCy email processing system
"""
import logging
import configparser
from pathlib import Path

try:
    from textblob import TextBlob
    TEXTBLOB_AVAILABLE = True
except ImportError:
    TEXTBLOB_AVAILABLE = False
    logging.warning("TextBlob not available. Install with: pip3 install textblob")

class EmailSentimentAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config()
        self.enabled = self._is_enabled()
        
        if self.enabled and not TEXTBLOB_AVAILABLE:
            self.logger.warning("Sentiment analysis disabled - TextBlob not available")
            self.enabled = False
    
    def _load_config(self):
        """Load configuration from modules.ini"""
        config = configparser.RawConfigParser()
        config_file = Path("/opt/spacyserver/config/modules.ini")
        
        if config_file.exists():
            config.read(config_file)
        else:
            # Create default config if it doesn't exist
            self._create_default_config(config_file)
            config.read(config_file)
        
        return config
    
    def _create_default_config(self, config_file):
        """Create default configuration file"""
        config_file.parent.mkdir(exist_ok=True)
        
        default_config = """[module_sentiment]
enabled = true
negative_threshold = -0.3
positive_threshold = 0.3
log_results = true

[module_phishing]
enabled = true
risk_threshold = 0.6
log_suspicious = true
"""
        
        with open(config_file, 'w') as f:
            f.write(default_config)
    
    def _is_enabled(self):
        """Check if sentiment analysis is enabled"""
        try:
            return self.config.getboolean('module_sentiment', 'enabled', fallback=True)
        except:
            return True
    
    def analyze_email_sentiment(self, email_data):
        """
        Analyze sentiment of email content
        
        Args:
            email_data (dict): Email data with 'subject', 'body', etc.
            
        Returns:
            dict: Sentiment analysis results or None if disabled
        """
        if not self.enabled:
            return None
        
        try:
            # Combine subject and body for analysis
            subject = email_data.get('subject', '')
            body = email_data.get('body', '')
            combined_text = f"{subject} {body}".strip()
            
            if not combined_text:
                return None
            
            # Perform sentiment analysis
            blob = TextBlob(combined_text)
            polarity = blob.sentiment.polarity  # -1 to 1
            subjectivity = blob.sentiment.subjectivity  # 0 to 1
            
            # Get thresholds from config
            neg_threshold = self.config.getfloat('module_sentiment', 'negative_threshold', fallback=-0.3)
            pos_threshold = self.config.getfloat('module_sentiment', 'positive_threshold', fallback=0.3)
            
            # Classify sentiment
            if polarity <= neg_threshold:
                sentiment_label = "negative"
            elif polarity >= pos_threshold:
                sentiment_label = "positive"  
            else:
                sentiment_label = "neutral"
            
            # Assess manipulation risk
            manipulation_risk = self._assess_manipulation_risk(polarity, subjectivity)
            
            result = {
                "polarity": round(polarity, 3),
                "subjectivity": round(subjectivity, 3),
                "sentiment": sentiment_label,
                "is_emotional": subjectivity > 0.5,
                "manipulation_risk": manipulation_risk,
                "confidence": round(abs(polarity), 3)
            }
            
            # Log if configured
            if self.config.getboolean('module_sentiment', 'log_results', fallback=False):
                self.logger.info(f"Sentiment analysis: {sentiment_label} (polarity: {polarity:.3f})")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Sentiment analysis failed: {e}")
            return None
    
    def _assess_manipulation_risk(self, polarity, subjectivity):
        """Assess emotional manipulation risk"""
        # High subjectivity + extreme polarity = potential manipulation
        if subjectivity > 0.7 and abs(polarity) > 0.5:
            return "high"
        elif subjectivity > 0.5 and abs(polarity) > 0.3:
            return "medium"
        else:
            return "low"

# Global instance for easy import
sentiment_analyzer = EmailSentimentAnalyzer()

def analyze_sentiment(email_data):
    """Convenience function for sentiment analysis"""
    return sentiment_analyzer.analyze_email_sentiment(email_data)
