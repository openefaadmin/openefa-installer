# /opt/spacyserver/modules/email_security.py (FIXED VERSION)
"""
Email Security Integration Module - FIXED
Integrates sentiment analysis and phishing detection with existing SpaCy system
"""
import logging
import time
import sys
import os
from datetime import datetime

# Add current directory to path for relative imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the security modules with better error handling
try:
    from email_sentiment import analyze_sentiment
    SENTIMENT_AVAILABLE = True
    print("✅ Sentiment module imported successfully")
except ImportError as e:
    SENTIMENT_AVAILABLE = False
    print(f"❌ Sentiment module import failed: {e}")

try:
    from email_phishing import detect_phishing
    PHISHING_AVAILABLE = True
    print("✅ Phishing module imported successfully")
except ImportError as e:
    PHISHING_AVAILABLE = False
    print(f"❌ Phishing module import failed: {e}")

SECURITY_MODULES_AVAILABLE = SENTIMENT_AVAILABLE and PHISHING_AVAILABLE

class EmailSecurityAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.enabled = SECURITY_MODULES_AVAILABLE
        
        if self.enabled:
            self.logger.info("Email security modules loaded successfully")
            print("✅ Email security analyzer initialized")
        else:
            self.logger.warning("Email security modules not available")
            print("❌ Email security analyzer disabled - modules not available")
    
    def analyze_email_security(self, email_data):
        """
        Perform comprehensive security analysis on email
        
        Args:
            email_data (dict): Email data containing sender, subject, body, etc.
            
        Returns:
            dict: Security analysis results
        """
        if not self.enabled:
            return {
                "security_enabled": False,
                "message": "Security modules not available",
                "timestamp": datetime.now().isoformat()
            }
        
        start_time = time.time()
        
        try:
            # Perform sentiment analysis
            sentiment_result = None
            if SENTIMENT_AVAILABLE:
                sentiment_result = analyze_sentiment(email_data)
            
            # Perform phishing detection
            phishing_result = None
            if PHISHING_AVAILABLE:
                phishing_result = detect_phishing(email_data)
            
            # Calculate overall security score
            overall_score = self._calculate_overall_score(sentiment_result, phishing_result)
            
            # Generate security summary
            security_summary = self._generate_security_summary(sentiment_result, phishing_result)
            
            processing_time = round(time.time() - start_time, 3)
            
            result = {
                "timestamp": datetime.now().isoformat(),
                "processing_time_seconds": processing_time,
                "security_enabled": True,
                "sentiment_analysis": sentiment_result,
                "phishing_detection": phishing_result,
                "overall_security": overall_score,
                "summary": security_summary,
                "recommendations": self._get_recommendations(sentiment_result, phishing_result)
            }
            
            # Log high-risk emails
            if overall_score.get("risk_level") in ["high", "critical"]:
                self.logger.warning(f"High-risk email detected: {email_data.get('subject', 'No subject')[:50]}...")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Security analysis failed: {e}")
            return {
                "security_enabled": True,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _calculate_overall_score(self, sentiment_result, phishing_result):
        """Calculate overall security risk score"""
        risk_score = 0.0
        risk_factors = []
        
        # Phishing risk (primary factor)
        if phishing_result and phishing_result.get("is_phishing"):
            phishing_risk = phishing_result.get("risk_score", 0)
            risk_score += phishing_risk * 0.7  # 70% weight for phishing
            risk_factors.append(f"Phishing risk: {phishing_result.get('risk_level', 'unknown')}")
        
        # Sentiment manipulation risk (secondary factor)
        if sentiment_result:
            manipulation_risk = sentiment_result.get("manipulation_risk", "low")
            if manipulation_risk == "high":
                risk_score += 0.3  # 30% additional risk
                risk_factors.append("High emotional manipulation detected")
            elif manipulation_risk == "medium":
                risk_score += 0.15
                risk_factors.append("Medium emotional manipulation detected")
        
        # Determine overall risk level
        if risk_score >= 0.8:
            risk_level = "critical"
        elif risk_score >= 0.6:
            risk_level = "high"
        elif risk_score >= 0.4:
            risk_level = "medium"
        elif risk_score >= 0.2:
            risk_level = "low"
        else:
            risk_level = "minimal"
        
        return {
            "risk_score": round(risk_score, 3),
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "requires_action": risk_level in ["high", "critical"]
        }
    
    def _generate_security_summary(self, sentiment_result, phishing_result):
        """Generate human-readable security summary"""
        summary_parts = []
        
        # Phishing summary
        if phishing_result:
            if phishing_result.get("is_phishing"):
                summary_parts.append(f"🚨 Phishing detected ({phishing_result.get('risk_level', 'unknown')} risk)")
            else:
                summary_parts.append("✅ No phishing indicators")
        
        # Sentiment summary
        if sentiment_result:
            sentiment = sentiment_result.get("sentiment", "unknown")
            manipulation_risk = sentiment_result.get("manipulation_risk", "low")
            
            if manipulation_risk == "high":
                summary_parts.append(f"⚠️ High emotional manipulation ({sentiment} sentiment)")
            elif sentiment_result.get("is_emotional"):
                summary_parts.append(f"😮 Emotional content ({sentiment} sentiment)")
            else:
                summary_parts.append(f"😐 Neutral content ({sentiment} sentiment)")
        
        return " | ".join(summary_parts) if summary_parts else "Analysis completed"
    
    def _get_recommendations(self, sentiment_result, phishing_result):
        """Get actionable recommendations based on analysis"""
        recommendations = []
        
        # Phishing recommendations
        if phishing_result and phishing_result.get("is_phishing"):
            risk_level = phishing_result.get("risk_level", "unknown")
            
            if risk_level == "critical":
                recommendations.append("IMMEDIATE ACTION: Block this email and report to security team")
                recommendations.append("Do not click any links or download attachments")
            elif risk_level == "high":
                recommendations.append("Quarantine email for manual review")
                recommendations.append("Verify sender through alternative communication method")
            elif risk_level == "medium":
                recommendations.append("Exercise caution with links and attachments")
        
        # Sentiment recommendations
        if sentiment_result:
            manipulation_risk = sentiment_result.get("manipulation_risk", "low")
            
            if manipulation_risk == "high":
                recommendations.append("High emotional manipulation detected - verify independently")
            
            if sentiment_result.get("is_emotional"):
                recommendations.append("Email contains emotional content - review carefully")
        
        # Default recommendation if no issues
        if not recommendations:
            recommendations.append("Email appears safe based on automated analysis")
        
        return recommendations

# Global instance for easy import
email_security_analyzer = EmailSecurityAnalyzer()

def analyze_email_security(email_data):
    """Convenience function for email security analysis"""
    return email_security_analyzer.analyze_email_security(email_data)

def create_security_headers(security_analysis):
    """
    Create X-NLP headers for SpamAssassin integration
    """
    headers = {}
    
    if not security_analysis.get("security_enabled"):
        return headers
    
    # Sentiment analysis headers
    if 'sentiment_analysis' in security_analysis:
        sentiment = security_analysis['sentiment_analysis']
        if sentiment:
            headers['X-NLP-SentimentScore'] = str(sentiment.get('polarity', 0))
            headers['X-NLP-SentimentLabel'] = sentiment.get('sentiment', 'unknown')
            headers['X-NLP-ManipulationRisk'] = sentiment.get('manipulation_risk', 'unknown')
    
    # Phishing detection headers
    if 'phishing_detection' in security_analysis:
        phishing = security_analysis['phishing_detection']
        if phishing:
            headers['X-NLP-PhishingScore'] = str(phishing.get('risk_score', 0))
            headers['X-NLP-PhishingLevel'] = phishing.get('risk_level', 'unknown')
            
            # Add indicators if present
            indicators = phishing.get('indicators', [])
            if indicators:
                headers['X-NLP-PhishingIndicators'] = '; '.join(indicators[:3])  # Limit to 3
    
    # Overall security risk headers
    if 'overall_security' in security_analysis:
        overall = security_analysis['overall_security']
        if overall:
            headers['X-NLP-SecurityRisk'] = overall.get('risk_level', 'unknown')
            headers['X-NLP-SecurityScore'] = str(overall.get('risk_score', 0))
    
    # Summary header
    if 'summary' in security_analysis:
        headers['X-NLP-SecuritySummary'] = security_analysis['summary'][:100]  # Limit length
    
    return headers

# Integration function for existing email_filter.py
def add_security_analysis(email_data, existing_analysis=None):
    """
    Add security analysis to existing email analysis
    
    Args:
        email_data (dict): Email data
        existing_analysis (dict): Existing SpaCy analysis results
        
    Returns:
        dict: Combined analysis with security data
    """
    security_analysis = analyze_email_security(email_data)
    
    if existing_analysis:
        # Merge with existing analysis
        existing_analysis["security_analysis"] = security_analysis
        return existing_analysis
    else:
        # Return just security analysis
        return {"security_analysis": security_analysis}
