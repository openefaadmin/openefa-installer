#!/usr/bin/env python3
"""
Content Analysis Module
Handles sentiment analysis, classification, and content processing
Enhanced with vague proposal BEC detection
"""

import re
from textblob import TextBlob
from langdetect import detect, DetectorFactory
from urllib.parse import urlparse
from utils.logging import safe_log, log_sentiment_debug

# Set deterministic results for language detection
DetectorFactory.seed = 0

class ContentAnalyzer:
    """Advanced email content analysis"""
    
    def __init__(self):
        self.spam_keywords = [
            'viagra', 'lottery', 'winner', 'prince', 'inheritance', 'million dollar',
            'bank transfer', 'Nigerian', 'claim your', 'congratulations', 'won',
            'casino', 'free money', 'earn money', 'get rich', 'investment opportunity'
        ]
        
        self.urgent_words = [
            'immediately', 'urgent', 'now', 'asap', 'critical', 'important', 
            'deadline', 'limited time', 'expires', 'act now', 'hurry',
            'action required', 'limited offer', 'don\'t wait', 'before it\'s too late'
        ]
        
        self.bad_tlds = {
            '.xyz', '.top', '.click', '.tk', '.ml', '.ga', '.cf', '.gq', 
            '.info', '.icu', '.loan', '.buzz'
        }
        
        self.tracking_keywords = {
            'utm_', 'trackid', 'ref=', 'redirect', 'click', 'track=', 'tracking='
        }
        
        # Enhanced 419/Advance Fee Fraud patterns
        self.fraud_419_keywords = [
            # Death/tragedy keywords
            'deceased', 'late husband', 'late father', 'plane crash', 'car accident',
            'earthquake', 'tsunami', 'war victim', 'rebel attack', 'died in',
            
            # Banking/financial keywords
            'next of kin', 'beneficiary', 'executor', 'trustee', 'bank account',
            'transfer funds', 'deposit', 'estate', 'will', 'testament',
            'unclaimed funds', 'dormant account', 'abandoned funds',
            
            # African/institutional references
            'ecowas', 'african development bank', 'central bank', 'finance ministry',
            'petroleum corporation', 'mining company', 'oil revenue',
            
            # Emotional manipulation
            'god fearing', 'before i die', 'terminal illness', 'cancer patient',
            'orphanage', 'charity', 'widow', 'refugee',
            
            # Partnership language
            '50/50', 'fifty fifty', 'equal sharing', 'partnership',
            'business partner', 'cooperation', 'collaboration',
            
            # Legal/official sounding
            'attorney', 'barrister', 'solicitor', 'legal documentation',
            'affidavit', 'certificate of deposit', 'power of attorney'
        ]
        
        # Suspicious money amounts (common in 419 scams)
        self.suspicious_amounts = [
            r'\$[\d,]+\.?\d*\s*million',
            r'\$[\d,]+\.?\d*\s*billion', 
            r'USD[\s\$]*[\d,]+',
            r'\([A-Z]{3}\$[\d,\.]+\)',  # (USD$10,500,000.00) format
            r'[\d,]+\s*million\s*dollars?',
            r'[\d,]+\s*billion\s*dollars?'
        ]
        
        # Vague proposal BEC patterns
        self.vague_proposal_keywords = [
            'potential representation', 'business representation',
            'represent you', 'represent your company', 
            'cooperation in your country', 'partnership opportunity',
            'mutually beneficial', 'business proposal',
            'would like to inquire', 'inquire about your availability',
            'will not interfere', 'no interference with',
            'by no means interfere', 'not affect your job',
            'explore potential collaboration', 'discuss a business matter',
            'profitable venture', 'lucrative opportunity',
            'interested in your services', 'business opportunity'
        ]
        
        self.suspicious_titles = [
            'HR Manager', 'Human Resources Manager', 
            'Managing Director', 'Executive Director',
            'Director of Operations', 'International Representative',
            'Regional Manager', 'Export Manager',
            'Business Development Manager'
        ]

    def detect_language(self, text):
        """Detect the language of the text content"""
        try:
            if not text or len(text.strip()) < 20:
                return ('en', 1.0)
            
            language = detect(text)
            confidence = min(1.0, len(text) / 500.0)
            return (language, confidence)
        except Exception as e:
            safe_log(f"Language detection error: {e}", "ERROR")
            return ('en', 0.0)

    def calculate_sentiment(self, text, subject=None, sender=None, recipients=None, is_system_notification=False):
        """
        Calculate comprehensive sentiment metrics including:
        - Overall polarity (-1 to 1)
        - Intensity/strength
        - Emotional manipulation indicators
        - Extremity score
        """
        log_sentiment_debug("calculate_sentiment called", {
            "subject": subject,
            "text_length": len(text) if text else 0,
            "is_system_notification": is_system_notification
        })
        
        try:
            if not text or not isinstance(text, str):
                safe_log(f"Invalid text input for sentiment analysis: {type(text)}", "ERROR")
                text = "" if not text else str(text)
                
            if subject and not isinstance(subject, str):
                safe_log(f"Invalid subject input for sentiment analysis: {type(subject)}", "ERROR")
                subject = str(subject) if subject else ""
            
            # Combine subject and text with subject given more weight
            combined_text = (subject + " " + subject + " " + text) if subject else text
            
            # Basic sentiment analysis with TextBlob
            polarity = 0
            subjectivity = 0
            try:
                blob = TextBlob(combined_text)
                polarity = blob.sentiment.polarity
                subjectivity = blob.sentiment.subjectivity
                safe_log(f"TextBlob sentiment: polarity={polarity}, subjectivity={subjectivity}")
                
                log_sentiment_debug("TextBlob analysis complete", {
                    "polarity": polarity,
                    "subjectivity": subjectivity
                })
            except Exception as blob_err:
                safe_log(f"TextBlob analysis failed: {blob_err}", "ERROR")
                log_sentiment_debug(f"TextBlob error: {blob_err}")
            
            # Manual detection of intensity factors
            all_caps_count = len([word for word in combined_text.split() if word.isupper() and len(word) > 2])
            exclamation_count = combined_text.count('!')
            
            # Filter urgent words for system notifications
            urgent_words = self.urgent_words.copy()
            if is_system_notification:
                technical_urgent_words = ['critical', 'error', 'failed', 'warning', 'alert']
                urgent_words = [w for w in urgent_words if w not in technical_urgent_words]
                
            urgent_count = sum(1 for word in urgent_words if word in combined_text.lower())
            
            # Filter threatening words for system notifications
            threatening_words = ['warning', 'terminate', 'suspended', 'penalties', 'security', 'suspicious']
            if is_system_notification:
                system_normal_words = ['warning', 'suspended', 'security', 'error', 'failed']
                threatening_words = [w for w in threatening_words if w not in system_normal_words]
                
            threatening_count = sum(1 for word in threatening_words if word in combined_text.lower())
            
            # Flattery detection
            flattery_words = ['valued', 'special', 'exclusive', 'selected', 'exceptional']
            flattery_count = sum(1 for word in flattery_words if word in combined_text.lower())
            
            # Calculate manipulation score
            base_manipulation = ((urgent_count * 1.5) + (threatening_count * 2.0) + 
                               (flattery_count * 1.0) + (all_caps_count * 0.5) + 
                               (exclamation_count * 0.8) + (abs(polarity) * 2))
            
            # Reduce manipulation score for system notifications
            if is_system_notification:
                manipulation_score = min(10, base_manipulation * 0.3)
            else:
                manipulation_score = min(10, base_manipulation)
            
            # Calculate extremity score
            base_extremity = (abs(polarity) * 5 + subjectivity * 3 + 
                             (all_caps_count * 0.3) + (exclamation_count * 0.2))
            
            if is_system_notification:
                extremity_score = min(10, base_extremity * 0.4)
            else:
                extremity_score = min(10, base_extremity)
            
            # Determine manipulation indicators
            manipulation_indicators = []
            if urgent_count >= 2 and not is_system_notification:
                manipulation_indicators.append("urgent_positive" if polarity > 0 else "urgent_negative")
            if threatening_count >= 2 and not is_system_notification:
                manipulation_indicators.append("threatening_negative")
            if flattery_count >= 2:
                manipulation_indicators.append("flattery")
            if polarity > 0.6 and subjectivity > 0.6 and not is_system_notification:
                manipulation_indicators.append("excessive_positivity")
            if (all_caps_count > 5 or exclamation_count > 3) and not is_system_notification:
                manipulation_indicators.append("excessive_emphasis")
            
            log_sentiment_debug("Sentiment features calculated", {
                "all_caps_words": all_caps_count,
                "exclamation_marks": exclamation_count,
                "urgent_words": urgent_count,
                "threatening_words": threatening_count,
                "flattery_words": flattery_count,
                "extremity_score": extremity_score,
                "manipulation_score": manipulation_score,
                "indicators": ', '.join(manipulation_indicators) if manipulation_indicators else "none",
                "adjustments_applied": "system_notification" if is_system_notification else "none"
            })
            
            return {
                "polarity": polarity,
                "subjectivity": subjectivity,
                "extremity_score": extremity_score,
                "manipulation_score": manipulation_score,
                "manipulation_indicators": manipulation_indicators
            }
            
        except Exception as e:
            safe_log(f"Enhanced sentiment analysis error: {e}", "ERROR")
            log_sentiment_debug(f"ERROR in sentiment analysis: {e}")
                
            return {
                "polarity": 0,
                "subjectivity": 0,
                "extremity_score": min(5, text.count('!') + text.count('?') + sum(1 for w in text.split() if w.isupper())),
                "manipulation_score": min(5, text.count('urgent') + text.count('URGENT') + text.count('!')),
                "manipulation_indicators": ["error_fallback"]
            }

    def calculate_urgency_score(self, text, sender=None, is_system_notification=False):
        """Calculate how urgent the email appears based on language patterns"""
        try:
            urgent_words = self.urgent_words.copy()
            
            # For system notifications, some urgency is expected
            if is_system_notification:
                urgent_words = [w for w in urgent_words if w not in ['critical', 'important', 'urgent']]
            
            text_lower = text.lower()
            urgent_count = sum(1 for word in urgent_words if word in text_lower)
            
            # Check for time pressure phrases
            time_phrases = ['within 24 hours', 'within 48 hours', 'today only', 'expires today',
                           'by tomorrow', 'last chance', 'final notice', 'closing soon']
            time_pressure_count = sum(1 for phrase in time_phrases if phrase in text_lower)
            
            # Check for exclamation marks
            exclamation_count = min(5, text.count('!'))
            
            # Count ALL CAPS words
            words = text.split()
            all_caps_count = sum(1 for word in words if word.isupper() and len(word) > 2)
            
            # Calculate final score
            urgency_score = min(10.0, urgent_count + (time_pressure_count * 2.0) + 
                               exclamation_count * 0.5 + all_caps_count * 0.3)
            
            # Reduce urgency score for known system notifications
            if is_system_notification:
                urgency_score = urgency_score * 0.5
                
            return urgency_score
        except Exception as e:
            safe_log(f"Error calculating urgency score: {e}", "ERROR")
            return 0.0

    def extract_and_analyze_links(self, text):
        """Extract and analyze URLs in the email content"""
        try:
            url_regex = r'https?://[^\s\)"]+'
            urls = re.findall(url_regex, text)
            suspicious_links = []
            
            for url in urls:
                try:
                    parsed = urlparse(url)
                    tld = '.' + parsed.netloc.split('.')[-1].lower() if parsed.netloc and '.' in parsed.netloc else ''
                    
                    # Check for suspicious TLDs
                    if tld in self.bad_tlds:
                        suspicious_links.append(f"{url} (suspicious TLD)")
                        
                    # Check for tracking parameters
                    elif parsed.query and any(k in parsed.query.lower() for k in self.tracking_keywords):
                        suspicious_links.append(f"{url} (tracking params)")
                        
                    # Check for excessively long domains
                    elif len(parsed.netloc) > 40:
                        suspicious_links.append(f"{url} (long domain)")
                        
                    # Check for numeric-heavy domains
                    elif sum(c.isdigit() for c in parsed.netloc) > len(parsed.netloc) * 0.3:
                        suspicious_links.append(f"{url} (numeric domain)")
                except:
                    suspicious_links.append(f"{url} (malformed URL)")
                    
            return urls, suspicious_links
        except Exception as e:
            safe_log(f"Link analysis error: {e}", "ERROR")
            return [], []

    def extract_text_from_html(self, html_content):
        """Extract plain text from HTML content"""
        try:
            text = re.sub(r'<[^>]+>', ' ', html_content)
            text = re.sub(r'\s+', ' ', text)
            return text.strip()
        except Exception as e:
            safe_log(f"HTML extraction error: {e}", "ERROR")
            return ""

    def extract_topics(self, text, subject, num_topics=5):
        """Extract key topics from the email content"""
        try:
            if len(text.split()) < 10:
                return []
            
            combined_text = subject + " " + subject + " " + text
            
            # Basic stopwords
            stop_words = {'a', 'an', 'the', 'and', 'or', 'but', 'if', 'because', 'as', 'what', 
                         'while', 'of', 'to', 'in', 'for', 'with', 'about', 'against', 'between',
                         'into', 'through', 'during', 'before', 'after', 'above', 'below', 'from',
                         'up', 'down', 'on', 'off', 'over', 'under', 'again', 'further', 'then',
                         'once', 'here', 'there', 'when', 'where', 'why', 'how', 'all', 'any',
                         'both', 'each', 'few', 'more', 'most', 'other', 'some', 'such', 'no',
                         'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too', 'very', 'can',
                         'will', 'just', 'should', 'now'}
            
            words = combined_text.lower().split()
            filtered_words = [word for word in words if word.isalnum() and word not in stop_words and len(word) > 2]
            
            word_counts = {}
            for word in filtered_words:
                word_counts[word] = word_counts.get(word, 0) + 1
            
            sorted_words = sorted(word_counts.items(), key=lambda x: x[1], reverse=True)
            topics = [word for word, count in sorted_words[:num_topics]]
            
            return topics
        except Exception as e:
            safe_log(f"Topic extraction error: {e}", "ERROR")
            return []

    def summarize_content(self, text, max_sentences=3):
        """Create an extractive summary of the email content"""
        try:
            if len(text) < 200:
                return text
            
            sentences = re.split(r'(?<=[.!?])\s+', text)
            
            if len(sentences) <= max_sentences:
                return text
            
            # Simple approach - first, middle, last
            summary_sentences = [sentences[0]]
            
            if len(sentences) > 2:
                middle_idx = len(sentences) // 2
                summary_sentences.append(sentences[middle_idx])
                
            if len(sentences) > 1:
                summary_sentences.append(sentences[-1])
                
            while len(summary_sentences) < max_sentences and len(summary_sentences) < len(sentences):
                idx = len(summary_sentences)
                if idx < len(sentences):
                    summary_sentences.append(sentences[idx])
            
            summary = ' '.join(summary_sentences)
            return summary
        except Exception as e:
            safe_log(f"Summarization error: {e}", "ERROR")
            return text[:200] + "..." if len(text) > 200 else text

    def detect_419_patterns(self, text, subject=""):
        """
        Specific detection for 419/Advance Fee Fraud patterns
        Returns a score from 0-10 indicating likelihood of 419 scam
        """
        try:
            combined_text = (subject + " " + text).lower()
            score = 0
            indicators = []
            
            # Check for 419-specific keywords
            fraud_keyword_count = sum(1 for keyword in self.fraud_419_keywords 
                                     if keyword in combined_text)
            if fraud_keyword_count >= 3:
                score += min(4, fraud_keyword_count * 0.5)
                indicators.append(f"fraud_keywords({fraud_keyword_count})")
            
            # Check for suspicious money amounts
            import re
            for pattern in self.suspicious_amounts:
                if re.search(pattern, text, re.IGNORECASE):
                    score += 2
                    indicators.append("large_money_amounts")
                    break
            
            # Check for tragedy + inheritance combination
            tragedy_words = ['died', 'death', 'deceased', 'killed', 'accident', 
                            'earthquake', 'tsunami', 'plane crash', 'cancer']
            inheritance_words = ['inheritance', 'estate', 'will', 'beneficiary', 
                               'next of kin', 'heir']
            
            has_tragedy = any(word in combined_text for word in tragedy_words)
            has_inheritance = any(word in combined_text for word in inheritance_words)
            
            if has_tragedy and has_inheritance:
                score += 3
                indicators.append("tragedy_inheritance_combo")
            
            # Check for foreign official claims
            official_titles = ['minister', 'director', 'chairman', 'president', 
                              'governor', 'commissioner', 'secretary']
            bank_words = ['bank', 'financial', 'investment', 'corporation']
            
            has_title = any(title in combined_text for title in official_titles)
            has_bank = any(word in combined_text for word in bank_words)
            
            if has_title and has_bank:
                score += 2
                indicators.append("fake_official_position")
            
            # Check for partnership/sharing language
            partnership_phrases = ['50/50', 'fifty fifty', 'share the', 'split the',
                                  'business partner', 'mutual benefit']
            if any(phrase in combined_text for phrase in partnership_phrases):
                score += 2
                indicators.append("partnership_language")
            
            # Check for secrecy/confidentiality emphasis
            secrecy_words = ['confidential', 'secret', 'private', 'discreet',
                            'strictly confidential', 'top secret']
            secrecy_count = sum(1 for word in secrecy_words if word in combined_text)
            if secrecy_count >= 2:
                score += 1.5
                indicators.append("excessive_secrecy")
            
            # Check for religious/emotional manipulation
            religious_words = ['god', 'allah', 'prayer', 'blessing', 'faith']
            if any(word in combined_text for word in religious_words):
                score += 1
                indicators.append("religious_manipulation")
            
            return min(10, score), indicators
            
        except Exception as e:
            safe_log(f"Error in 419 pattern detection: {e}", "ERROR")
            return 0, ["error"]

    def detect_vague_proposal_bec(self, text, subject="", sender=""):
        """
        Detect vague business proposal BEC patterns
        """
        score = 0
        indicators = []
        combined_text = (subject + " " + text).lower()
        
        # Check for vague proposal keywords
        vague_count = sum(1 for keyword in self.vague_proposal_keywords 
                         if keyword.lower() in combined_text)
        
        if vague_count >= 2:
            score += 4
            indicators.append(f"vague_proposal_keywords({vague_count})")
        elif vague_count == 1:
            score += 2
            indicators.append("vague_proposal_keyword")
        
        # Check for "no interference" claims
        no_interference = any(phrase in combined_text for phrase in 
                             ['will not interfere', 'no interference', 'not affect your',
                              'by no means interfere', 'alongside your current'])
        
        if no_interference:
            score += 3
            indicators.append("no_interference_claim")
        
        # Check word count - these scams are typically brief
        word_count = len(text.split())
        if 20 < word_count < 100 and vague_count > 0:
            score += 2
            indicators.append("brief_vague_message")
        
        # Check for suspicious titles
        for title in self.suspicious_titles:
            if title.lower() in combined_text:
                score += 2
                indicators.append(f"suspicious_title({title})")
                break
        
        # Check sender domain
        if '@' in sender:
            domain = sender.split('@')[-1].lower()
            suspicious_tlds = ['.vn', '.ng', '.za', '.my', '.ph', '.pk', '.bd']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                score += 1
                indicators.append(f"suspicious_tld({domain})")
        
        return min(10, score), indicators

    def calculate_spam_score(self, text, subject="", sender=""):
        """
        Enhanced spam scoring that includes 419 and vague proposal detection
        """
        try:
            # Base spam score from keywords
            base_score = 0
            text_lower = text.lower()
            subject_lower = subject.lower()
            combined = text_lower + " " + subject_lower
            
            # Count spam keywords
            spam_count = sum(1 for keyword in self.spam_keywords if keyword in combined)
            base_score += min(spam_count * 0.5, 3)
            
            # Add 419-specific scoring
            fraud_score, fraud_indicators = self.detect_419_patterns(text, subject)
            
            # Add vague proposal scoring
            vague_score, vague_indicators = self.detect_vague_proposal_bec(text, subject, sender)
            
            # Weight the scores
            total_score = base_score + (fraud_score * 1.5) + (vague_score * 1.2)
            
            # Combine indicators
            all_indicators = []
            if spam_count > 0:
                all_indicators.append(f"spam_keywords({spam_count})")
            all_indicators.extend(fraud_indicators)
            all_indicators.extend(vague_indicators)
            
            return min(10, total_score), all_indicators
            
        except Exception as e:
            safe_log(f"Error calculating enhanced spam score: {e}", "ERROR")
            return 0, ["error"]

# Global instance
content_analyzer = ContentAnalyzer()
