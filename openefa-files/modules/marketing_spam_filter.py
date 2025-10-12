#!/usr/bin/env python3
"""
Enhanced Marketing Spam Filter - FIXED PATTERNS
Critical fixes to catch SEO spam that was missed
"""

import re
from utils.logging import safe_log

class MarketingSpamFilter:
    """
    ENHANCED: Fixed pattern matching for better SEO spam detection
    """
    
    def __init__(self):
        # Trusted business domains that can send marketing (whitelist)
        self.TRUSTED_MARKETING_DOMAINS = {
            'dattobackup.com', 'datto.com', 'kaseya.com', 'pax8.com',
            'unitrends.com', 'broadvoice.com', 'zyxel.com',
            'quickbooks.com', 'intuit.com', 'stripe.com', 'paypal.com'
        }

        # Free email services commonly used for spam
        self.FREE_EMAIL_SERVICES = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'live.com', 'msn.com', 'icloud.com', 'protonmail.com', 'zoho.com',
            'mail.com', 'gmx.com', 'yandex.com', 'qq.com'
        }

        # ENHANCED: High-risk spam indicators with better pattern coverage
        self.SPAM_INDICATORS = {
            # SEO/Digital Marketing Spam - ENHANCED PATTERNS
            'seo_spam': {
                'weight': 4.0,
                'patterns': [
                    'SEO services', 'search engine optimization', 'google rankings',
                    'first page results', 'ranking guarantee', 'SERP position',
                    'keyword ranking', 'organic traffic', 'website optimization',
                    'digital marketing expert', 'SEO specialist', 'certified SEO',
                    # NEW: Google first page patterns that were missing
                    'google\'s 1st page', 'google\'s first page', 'google 1st page',
                    'google first page', '1st page of google', 'first page of google',
                    'place your website on google', 'get you on google',
                    'rank on google', 'google page one', 'page 1 of google'
                ]
            },

            # Cold Outreach Patterns - ENHANCED
            'cold_outreach': {
                'weight': 3.5,
                'patterns': [
                    'reaching out to you', 'I came across your', 'I noticed your website',
                    'I specialize in helping', 'would you be interested in',
                    'I can help you', 'our services can help', 'business opportunity',
                    # NEW: Patterns that were missing
                    'going through your website', 'was going through your',
                    'looking at your website', 'browsing your website',
                    'reviewing your website', 'checking your website',
                    'saw your website', 'found your website'
                ]
            },

            # Website/Contact Information Requests
            'info_harvesting': {
                'weight': 4.5,
                'patterns': [
                    'share your website URL', 'provide your website', 'send me your website',
                    'what is your website', 'website address', 'site URL',
                    'domain name', 'company website', 'business website'
                ]
            },

            # Unrealistic Promises - ENHANCED
            'false_promises': {
                'weight': 3.8,
                'patterns': [
                    'guarantee first page', 'guaranteed results', 'double your traffic',
                    'triple your leads', '100% guarantee', 'instant results',
                    'overnight success', 'guaranteed ranking', 'promised results',
                    # NEW: More promise patterns
                    'dramatically improve', 'greatly improve', 'significantly increase'
                ]
            },

            # Offshore/Low-Quality Indicators - FIXED CASE SENSITIVITY
            'offshore_spam': {
                'weight': 3.2,
                'patterns': [
                    # FIXED: Case-insensitive matching will handle these
                    '(india)', '(pakistan)', '(philippines)', '(bangladesh)',
                    'offshore team', 'based in india', 'indian company',
                    'overseas team', 'international team',
                    # NEW: More offshore patterns
                    'business consultant (india)', 'consultant india',
                    'team in india', 'india based', 'from india'
                ]
            },

            # Generic Business Pitches
            'generic_pitch': {
                'weight': 2.8,
                'patterns': [
                    'comprehensive services', 'full-service agency', 'one-stop solution',
                    'complete package', 'all-in-one service', 'turnkey solution',
                    'end-to-end service', 'complete suite'
                ]
            },

            # Urgency/Pressure Tactics
            'pressure_tactics': {
                'weight': 2.5,
                'patterns': [
                    'limited time offer', 'act now', 'don\'t miss out',
                    'exclusive opportunity', 'special pricing', 'this month only',
                    'expires soon', 'hurry up', 'quick response needed'
                ]
            },
            
            # NEW: Website potential/improvement spam
            'website_improvement_spam': {
                'weight': 4.2,
                'patterns': [
                    'potential in your website', 'improve your website',
                    'see a lot of potential', 'potential in your business',
                    'help improve these search results', 'improve search results',
                    'move you up in the rankings', 'improve your rankings'
                ]
            },
            
            # NEW: Quote/pricing request patterns
            'quote_request_spam': {
                'weight': 3.0,
                'patterns': [
                    'may i send you a quote', 'send you prices',
                    'send you a quote and prices', 'if interested',
                    'would like to send you prices', 'showing you a few things'
                ]
            }
        }

        # Business legitimacy indicators (reduce spam score)
        self.LEGITIMACY_INDICATORS = {
            'established_business': {
                'weight': -2.0,
                'patterns': [
                    'years of experience', 'established since', 'founded in',
                    'trusted by', 'certified partner', 'accredited',
                    'licensed', 'insured', 'bonded'
                ]
            },

            'professional_language': {
                'weight': -1.5,
                'patterns': [
                    'best regards', 'sincerely', 'kind regards',
                    'thank you for your time', 'look forward to',
                    'please let me know', 'happy to discuss'
                ]
            },

            'specific_reference': {
                'weight': -2.5,
                'patterns': [
                    'saw your recent', 'read about your', 'noticed your announcement',
                    'your latest project', 'your recent success', 'your industry expertise'
                ]
            }
        }

    def extract_domain(self, email_address):
        """Extract domain from email address"""
        if not email_address or '@' not in email_address:
            return None
        return email_address.lower().split('@')[-1].strip()

    def is_trusted_domain(self, email_address):
        """Check if email is from a trusted business domain"""
        domain = self.extract_domain(email_address)
        return domain in self.TRUSTED_MARKETING_DOMAINS if domain else False

    def is_free_email(self, email_address):
        """Check if email is from a free email service"""
        domain = self.extract_domain(email_address)
        return domain in self.FREE_EMAIL_SERVICES if domain else False

    def analyze_marketing_patterns(self, subject, body):
        """
        ENHANCED: Analyze email content for marketing spam patterns
        FIXED: Case-insensitive matching and better pattern coverage
        """
        combined_text = f"{subject} {body}".lower()  # Convert to lowercase for matching
        spam_score = 0.0
        detected_patterns = []

        # Check spam indicators
        for category, config in self.SPAM_INDICATORS.items():
            matches = 0
            matched_patterns = []

            for pattern in config['patterns']:
                # FIXED: Case-insensitive matching
                if pattern.lower() in combined_text:
                    matches += 1
                    matched_patterns.append(pattern)

            if matches > 0:
                # Calculate score based on matches and weight
                category_score = min(matches * config['weight'] * 0.5, config['weight'] * 2)
                spam_score += category_score
                detected_patterns.append({
                    'category': category,
                    'score': category_score,
                    'matches': matched_patterns[:3]  # Limit to first 3 matches
                })

        # Check legitimacy indicators (reduce spam score)
        for category, config in self.LEGITIMACY_INDICATORS.items():
            matches = 0
            matched_patterns = []

            for pattern in config['patterns']:
                if pattern.lower() in combined_text:
                    matches += 1
                    matched_patterns.append(pattern)

            if matches > 0:
                # Reduce spam score based on legitimacy indicators
                legitimacy_reduction = min(matches * abs(config['weight']) * 0.3, abs(config['weight']) * 1.5)
                spam_score -= legitimacy_reduction
                detected_patterns.append({
                    'category': category,
                    'score': -legitimacy_reduction,
                    'matches': matched_patterns[:2]
                })

        return max(spam_score, 0.0), detected_patterns

    def check_reply_context(self, subject, headers):
        """Check if this is a reply to an existing conversation"""
        # Check for Reply indicators
        if subject.lower().startswith(('re:', 'fwd:', 'fw:')):
            return True

        # Check for conversation headers
        if isinstance(headers, dict):
            if headers.get('In-Reply-To') or headers.get('References'):
                return True

        return False

    def analyze_sender_reputation(self, sender_email, sender_name=''):
        """
        ENHANCED: Analyze sender reputation factors
        ADDED: SEO domain detection
        """
        reputation_score = 0.0
        reputation_factors = []

        # Check if trusted domain
        if self.is_trusted_domain(sender_email):
            reputation_score -= 5.0  # Strong negative (good)
            reputation_factors.append('trusted_domain')
            return reputation_score, reputation_factors

        # NEW: Check for SEO-related domain names
        domain = self.extract_domain(sender_email)
        if domain:
            seo_domain_indicators = [
                'seo', 'marketing', 'digital', 'webdesign', 'rankboost',
                'searchengine', 'optimization', 'webpromo', 'traffico'
            ]
            if any(indicator in domain.lower() for indicator in seo_domain_indicators):
                reputation_score += 3.0
                reputation_factors.append('seo_domain_name')

        # Check if free email service
        if self.is_free_email(sender_email):
            reputation_score += 2.0
            reputation_factors.append('free_email_service')

        # Check for business-sounding names with free email (red flag)
        if sender_name and self.is_free_email(sender_email):
            business_indicators = [
                'expert', 'specialist', 'consultant', 'agency', 'services',
                'solutions', 'company', 'corp', 'llc', 'inc', 'ltd'
            ]
            if any(indicator in sender_name.lower() for indicator in business_indicators):
                reputation_score += 1.5
                reputation_factors.append('business_name_free_email')

        # Check for suspicious sender patterns
        suspicious_patterns = [
            r'.*\d{3,}@',  # Numbers in email like marketing123@
            r'.*marketing.*@',  # marketing in email
            r'.*noreply.*@',  # noreply emails for marketing
            r'.*info.*@.*\.(?:tk|ml|ga|cf)',  # info@ with suspicious TLDs
        ]

        for pattern in suspicious_patterns:
            if re.match(pattern, sender_email.lower()):
                reputation_score += 1.0
                reputation_factors.append('suspicious_email_pattern')
                break

        return reputation_score, reputation_factors

    def filter_marketing_spam(self, email_data):
        """
        ENHANCED: Main filtering function for marketing spam
        FIXED: Better detection and logging
        """
        try:
            subject = email_data.get('subject', '')
            body = email_data.get('body', '')
            sender_email = email_data.get('from', '')
            sender_name = email_data.get('display_name', '')

            # Initialize results
            results = {
                'is_marketing_spam': False,
                'spam_score': 0.0,
                'confidence': 0.0,
                'action': 'allow',  # allow, flag, block
                'detected_patterns': [],
                'sender_analysis': {},
                'filter_details': {}
            }

            # ENHANCED: Debug logging for missed emails
            # Sanitize subject for logging to prevent truncation
            try:
                clean_subject = subject[:50].replace('\n', ' ').replace('\r', ' ').replace('\'', '')
                # Also sanitize sender email for logging
                clean_sender = str(sender_email)[:100].replace('\n', ' ').replace('\r', ' ')
                safe_log(f"Marketing filter analyzing: From={clean_sender}, Subject={clean_subject}...")
            except Exception as log_error:
                safe_log(f"Marketing filter: Error logging email details: {log_error}")

            # Skip filtering for trusted domains
            if self.is_trusted_domain(sender_email):
                results['action'] = 'allow'
                results['filter_details']['reason'] = 'trusted_domain'
                safe_log(f"Marketing filter: Allowing trusted domain {self.extract_domain(sender_email)}")
                return results

            # Check if this is a reply (reduce scrutiny)
            is_reply = self.check_reply_context(subject, email_data.get('headers', {}))

            # Analyze content patterns
            content_score, content_patterns = self.analyze_marketing_patterns(subject, body)

            # Analyze sender reputation
            sender_score, sender_factors = self.analyze_sender_reputation(sender_email, sender_name)

            # Calculate total spam score
            total_score = content_score + sender_score

            # ENHANCED: Log pattern matches for debugging
            if content_patterns:
                safe_log(f"Marketing filter detected patterns: {[p['category'] for p in content_patterns]}")

            # Reduce score for replies
            if is_reply:
                total_score *= 0.3  # Significant reduction for replies
                sender_factors.append('email_reply')

            # ENHANCED: More aggressive thresholds for SEO spam
            if total_score >= 6.0:  # Lowered from 8.0
                action = 'block'
                is_spam = True
                confidence = min(total_score / 10.0, 1.0)
            elif total_score >= 4.0:  # Lowered from 5.0  
                action = 'flag'
                is_spam = True
                confidence = min(total_score / 8.0, 1.0)
            else:
                action = 'allow'
                is_spam = False
                confidence = max(1.0 - (total_score / 6.0), 0.0)

            # Update results
            results.update({
                'is_marketing_spam': is_spam,
                'spam_score': round(total_score, 2),
                'confidence': round(confidence, 3),
                'action': action,
                'detected_patterns': content_patterns,
                'sender_analysis': {
                    'domain': self.extract_domain(sender_email),
                    'is_free_email': self.is_free_email(sender_email),
                    'is_trusted': self.is_trusted_domain(sender_email),
                    'reputation_factors': sender_factors,
                    'reputation_score': sender_score
                },
                'filter_details': {
                    'content_score': content_score,
                    'sender_score': sender_score,
                    'is_reply': is_reply,
                    'total_patterns': len(content_patterns)
                }
            })

            # ENHANCED: Log all significant results (not just block/flag)
            if total_score > 2.0:  # Log anything with some spam indicators
                safe_log(f"Marketing spam filter: {action.upper()} - "
                        f"Score: {total_score:.2f}, Confidence: {confidence:.3f}, "
                        f"From: {self.extract_domain(sender_email)}, "
                        f"Patterns: {len(content_patterns)}")

            return results

        except Exception as e:
            safe_log(f"Marketing spam filter error: {e}", "ERROR")
            return {
                'is_marketing_spam': False,
                'spam_score': 0.0,
                'confidence': 0.0,
                'action': 'allow',
                'detected_patterns': [],
                'sender_analysis': {},
                'filter_details': {'error': str(e)}
            }

# Global instance
marketing_spam_filter = MarketingSpamFilter()

def filter_marketing_spam(email_data):
    """Convenience function for the main email filter"""
    return marketing_spam_filter.filter_marketing_spam(email_data)

def get_spam_score_adjustment(filter_results):
    """
    ENHANCED: Convert filter results to spam score adjustment for SpamAssassin
    FIXED: More aggressive scoring for SEO spam
    """
    if not filter_results['is_marketing_spam']:
        return 0.0

    # Convert internal score to SpamAssassin score adjustment
    action = filter_results['action']
    confidence = filter_results['confidence']
    spam_score = filter_results['spam_score']

    if action == 'block':
        return min(8.0 + (confidence * 2.0), 12.0)  # Increased from 8.0 max
    elif action == 'flag':
        return min(4.0 + (confidence * 2.0), 8.0)   # Increased from 5.0 max
    else:
        # Even "allow" emails with some score should get minor penalty
        if spam_score > 2.0:
            return min(spam_score * 0.5, 2.0)
        return 0.0

# Test function to verify the fix works
def test_seo_spam_email():
    """Test function to verify the enhanced patterns catch the SEO spam"""
    test_email = {
        'from': 'amit@smartseostrategist.com',
        'display_name': 'Amit',
        'subject': 'Ist Page of Google',
        'body': '''Hi there

I was going through your website from your email account & I personally see a lot of potential in your website & business. With your permission I would like to send you prices showing you a few things to greatly improve these search results for you.

We can place your website on Google's 1st page (Yahoo, etc.).

These things are not difficult, and my report will be very specific. It will show you exactly what needs to be done to move you up in the rankings dramatically.

May I send you a quote and prices? If interested.

Thanks,
Amit,
Business Consultant (INDIA)''',
        'headers': {}
    }
    
    result = filter_marketing_spam(test_email)
    print(f"Test Result: {result['action']}, Score: {result['spam_score']}, Patterns: {len(result['detected_patterns'])}")
    for pattern in result['detected_patterns']:
        print(f"  - {pattern['category']}: {pattern['matches']}")
    
    return result

if __name__ == "__main__":
    # Test the enhanced filter
    print("Testing enhanced marketing spam filter...")
    test_result = test_seo_spam_email()
    if test_result['action'] in ['flag', 'block'] and test_result['spam_score'] > 5.0:
        print("✅ SUCCESS: Enhanced filter would catch the SEO spam!")
    else:
        print("❌ STILL FAILING: Filter needs more work")
