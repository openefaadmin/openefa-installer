#!/usr/bin/env python3
"""
Email Classification Module
Handles email categorization, known sender detection, and system notification identification
"""

from utils.logging import safe_log

class EmailClassifier:
    """Advanced email classification and sender analysis"""
    
    def __init__(self):
        # Known legitimate senders and their characteristics
        self.KNOWN_LEGITIMATE_SENDERS = {
            'dattobackup.com': {
                'type': 'backup_service',
                'spam_score_reduction': 3.0,
                'expected_urgency': True,
                'expected_keywords': ['backup', 'error', 'critical', 'warning', 'alert', 'failed', 'success']
            },
            'datto.com': {
                'type': 'backup_service',
                'spam_score_reduction': 3.0,
                'expected_urgency': True,
                'expected_keywords': ['backup', 'error', 'critical', 'warning', 'alert', 'failed', 'success']
            },
            'alerts.datto.com': {
                'type': 'backup_service',
                'spam_score_reduction': 3.0,
                'expected_urgency': True,
                'expected_keywords': ['backup', 'error', 'critical', 'warning', 'alert', 'failed', 'success']
            },
            'mailguard.net': {
                'type': 'email_security',
                'spam_score_reduction': 2.0,
                'expected_urgency': False,
                'expected_keywords': ['quarantine', 'blocked', 'security', 'threat']
            },
            'proxmoxve.com': {
                'type': 'infrastructure',
                'spam_score_reduction': 2.5,
                'expected_urgency': True,
                'expected_keywords': ['backup', 'task', 'node', 'vm', 'container']
            }
        }

        # Email addresses that receive system notifications
        # Add your monitored addresses here
        self.SYSTEM_NOTIFICATION_RECIPIENTS = {
            'alerts@example.com',
            'notifications@example.com',
        }

        # Specific sender email addresses that always send system notifications
        self.SYSTEM_NOTIFICATION_SENDERS = {
            'reporting@dattobackup.com',
            'noreply@datto.com',
            'alerts@datto.com',
            'notifications@proxmoxve.com',
            'noreply@proxmoxve.com',
        }

        # System notification patterns that shouldn't be penalized
        self.SYSTEM_NOTIFICATION_PATTERNS = [
            # Backup systems
            ('backup', ['error', 'failed', 'success', 'completed', 'warning']),
            ('sync', ['completed', 'failed', 'error', 'started']),
            ('replication', ['completed', 'failed', 'error', 'started']),
            
            # Monitoring systems
            ('alert', ['critical', 'warning', 'resolved', 'triggered']),
            ('monitor', ['down', 'up', 'critical', 'warning']),
            
            # Infrastructure
            ('server', ['down', 'up', 'reboot', 'maintenance']),
            ('service', ['stopped', 'started', 'failed', 'running']),
            ('disk', ['full', 'space', 'usage', 'critical']),
            ('cpu', ['high', 'usage', 'critical', 'warning']),
            ('memory', ['high', 'usage', 'critical', 'warning'])
        ]

    def check_known_sender(self, sender_address):
        """
        Check if the sender is from a known legitimate source
        Checks both domain and specific email addresses
        
        Returns:
            tuple: (is_known, sender_info_dict)
        """
        if not sender_address:
            return False, None
        
        sender_lower = sender_address.lower()
        
        # First check if it's a known system notification sender email
        if sender_lower in self.SYSTEM_NOTIFICATION_SENDERS:
            # Extract domain for sender info
            sender_domain = sender_lower.split('@')[-1]
            if sender_domain in self.KNOWN_LEGITIMATE_SENDERS:
                return True, self.KNOWN_LEGITIMATE_SENDERS[sender_domain]
            else:
                # Return generic system notification info
                return True, {
                    'type': 'system_notification',
                    'spam_score_reduction': 3.0,
                    'expected_urgency': True,
                    'expected_keywords': ['notification', 'alert', 'report', 'status']
                }
        
        # Then check domain as before
        sender_domain = sender_lower.split('@')[-1]
        
        # Check exact domain match
        if sender_domain in self.KNOWN_LEGITIMATE_SENDERS:
            return True, self.KNOWN_LEGITIMATE_SENDERS[sender_domain]
        
        # Check subdomain matches (e.g., alerts.datto.com matches datto.com)
        for known_domain, info in self.KNOWN_LEGITIMATE_SENDERS.items():
            if sender_domain.endswith('.' + known_domain) or sender_domain == known_domain:
                return True, info
                
        return False, None

    def is_system_notification_content(self, text, subject, recipients=None, sender=None):
        """
        Check if the content matches system notification patterns
        OR if it's sent to a system notification recipient
        OR if it's from a system notification sender
        """
        # Check if from a system notification sender
        if sender and sender.lower() in self.SYSTEM_NOTIFICATION_SENDERS:
            return True
            
        # Check if sent to a system notification recipient
        if recipients:
            for recipient in recipients:
                if recipient.lower() in self.SYSTEM_NOTIFICATION_RECIPIENTS:
                    return True
        
        # Then check content patterns as before
        combined_text = (subject + ' ' + text).lower()
        
        for primary_keyword, secondary_keywords in self.SYSTEM_NOTIFICATION_PATTERNS:
            if primary_keyword in combined_text:
                for secondary in secondary_keywords:
                    if secondary in combined_text:
                        return True
        return False

    def classify_email(self, text, subject, sender=None, recipients=None, has_attachments=False, has_links=False):
        """
        Advanced email classification using multiple signals:
        - Content analysis
        - Structure analysis
        - Sender patterns
        - Recipient patterns
        - Metadata (attachments, links)
        
        Returns primary category and confidence score
        """
        try:
            # Check if this is from a known sender
            is_known_sender, sender_info = self.check_known_sender(sender)
            
            # Check if content matches system notification patterns OR sent to notification recipients
            is_system_notification = self.is_system_notification_content(text, subject, recipients, sender)
            
            # Log if classified by recipient or sender
            if recipients and any(r.lower() in self.SYSTEM_NOTIFICATION_RECIPIENTS for r in recipients):
                safe_log(f"Email classified as system_notification due to recipient")
            elif sender and sender.lower() in self.SYSTEM_NOTIFICATION_SENDERS:
                safe_log(f"Email classified as system_notification due to sender: {sender}")
            
            # Combine subject and text with subject given more weight
            combined_text = subject + " " + subject + " " + text
            combined_text = combined_text.lower()
            
            # Define categories and their associated keywords/patterns
            categories = {
                'marketing': {
                    'keywords': ['offer', 'discount', 'sale', 'promotion', 'subscribe', 'newsletter', 'limited time', 
                              'exclusive', 'deal', 'coupon', 'campaign', 'marketing', 'advertise', 'buy now',
                              'special offer', 'just for you', 'new product', 'introducing', 'announcement'],
                    'subject_patterns': ['off', '%', 'sale', 'deal', 'new', 'promo', 'exclusive'],
                    'metadata_signals': {'has_unsubscribe': 3, 'many_links': 2, 'image_heavy': 2}
                },
                'transactional': {
                    'keywords': ['receipt', 'invoice', 'statement', 'account', 'transaction', 'purchase', 'order', 
                               'payment', 'paid', 'confirmation', 'shipped', 'tracking', 'delivered', 
                               'subscription', 'your account', 'password', 'login'],
                    'subject_patterns': ['receipt', 'invoice', 'order', 'confirm', 'payment', 'shipped'],
                    'metadata_signals': {'has_pdf': 3, 'sender_official': 4, 'few_links': 1}
                },
                'system_notification': {
                    'keywords': ['backup', 'error', 'failed', 'success', 'completed', 'alert', 'warning', 
                               'critical', 'monitor', 'server', 'service', 'task', 'job', 'process',
                               'disk', 'cpu', 'memory', 'usage', 'threshold', 'status', 'report'],
                    'subject_patterns': ['alert', 'error', 'warning', 'backup', 'monitor', 'report', 'status'],
                    'metadata_signals': {'known_sender': 5, 'automated': 3, 'consistent_format': 2}
                },
                'phishing': {
                    'keywords': ['verify', 'confirm', 'update', 'security', 'suspicious', 'unusual', 'login', 'account',
                              'password', 'expired', 'blocked', 'unauthorized', 'validate', 'click here', 'click link',
                              'banking', 'paypal', 'apple id', 'microsoft', 'google', 'amazon', 'ebay'],
                    'subject_patterns': ['urgent', 'alert', 'warning', 'security', 'verify', 'account'],
                    'metadata_signals': {'suspicious_links': 5, 'masked_links': 4, 'domain_mismatch': 5}
                },
                'notification': {
                    'keywords': ['notification', 'alert', 'reminder', 'notice', 'update', 'status', 
                                'completed', 'processed', 'confirmed', 'verification', 'activity', 'changed',
                                'scheduled', 'upcoming', 'calendar', 'event', 'meeting'],
                    'subject_patterns': ['notify', 'alert', 'remind', 'update'],
                    'metadata_signals': {'automated_sender': 3, 'consistent_format': 2}
                },
                'personal': {
                    'keywords': ['hello', 'hi', 'hey', 'thanks', 'thank you', 'appreciate', 'best regards', 
                               'sincerely', 'cheers', 'regards', 'best wishes', 'hope you', 'how are you',
                               'personal', 'private', 'confidential'],
                    'subject_patterns': ['re:', 'fwd:', 'hello', 'hi', 'fyi', 'personal'],
                    'metadata_signals': {'few_links': 2, 'conversational': 3, 'no_marketing': 2}
                },
                'business': {
                    'keywords': ['meeting', 'agenda', 'project', 'client', 'proposal', 'contract', 'business', 
                             'report', 'quarterly', 'fiscal', 'budget', 'conference', 'deadline', 'goals',
                             'objectives', 'strategy', 'team', 'department', 'company'],
                    'subject_patterns': ['meeting', 'report', 'update', 'project', 'proposal'],
                    'metadata_signals': {'has_attachment': 2, 'business_sender': 3, 'formal_tone': 2}
                },
                'spam': {
                    'keywords': ['viagra', 'pills', 'winner', 'lottery', 'prize', 'claim', 'millions', 'billionaire',
                              'rich', 'money', 'cash', 'investment', 'bank transfer', 'inheritance', 'prince',
                              'overseas', 'foreign', 'fund', 'confidential', 'opportunity'],
                    'subject_patterns': ['congrat', 'winner', 'prize', 'urgent', 'million', 'dollar', 'free'],
                    'metadata_signals': {'suspicious_origin': 4, 'poor_grammar': 3, 'excessive_punctuation': 2}
                }
            }
            
            # Add bonus score for system notifications if from known sender or to known recipient
            if 'system_notification' in categories:
                if is_known_sender:
                    categories['system_notification']['metadata_signals']['known_sender'] = 8
                if is_system_notification:
                    categories['system_notification']['metadata_signals']['automated'] = 5
                    # Add extra bonus if both sender and recipient indicate system notification
                    if sender and sender.lower() in self.SYSTEM_NOTIFICATION_SENDERS:
                        categories['system_notification']['metadata_signals']['known_sender'] = 10
                    if recipients and any(r.lower() in self.SYSTEM_NOTIFICATION_RECIPIENTS for r in recipients):
                        categories['system_notification']['metadata_signals']['automated'] = 7
            
            # Start scoring each category
            category_scores = {}
            for category, signals in categories.items():
                # Initialize score
                score = 0
                
                # Score based on keywords
                keyword_matches = sum(1 for keyword in signals['keywords'] if keyword in combined_text)
                keyword_score = keyword_matches / len(signals['keywords']) * 10 if keyword_matches > 0 else 0
                score += keyword_score
                
                # Score based on subject patterns
                subject_lower = subject.lower()
                subject_matches = sum(1 for pattern in signals['subject_patterns'] if pattern in subject_lower)
                subject_score = subject_matches / len(signals['subject_patterns']) * 15 if subject_matches > 0 else 0
                score += subject_score
                
                # Add metadata signal scores if available
                if 'has_attachment' in signals['metadata_signals'] and has_attachments:
                    score += signals['metadata_signals']['has_attachment']
                    
                if 'many_links' in signals['metadata_signals'] and has_links and has_links > 3:
                    score += signals['metadata_signals']['many_links']
                    
                if 'few_links' in signals['metadata_signals'] and (not has_links or has_links <= 1):
                    score += signals['metadata_signals']['few_links']
                
                if 'suspicious_links' in signals['metadata_signals'] and 'suspicious' in str(text).lower():
                    score += signals['metadata_signals']['suspicious_links']
                    
                # Additional signal: check for unsubscribe text (strong indicator of marketing)
                if 'has_unsubscribe' in signals['metadata_signals'] and 'unsubscribe' in combined_text:
                    score += signals['metadata_signals']['has_unsubscribe']
                    
                # Special case: if sender contains a commercial domain and category is transactional
                if sender and 'sender_official' in signals['metadata_signals']:
                    commercial_domains = ['.com', '.org', '.net', '.co', '.io']
                    if any(domain in sender.lower() for domain in commercial_domains):
                        score += signals['metadata_signals']['sender_official']
                        
                # Apply metadata signals for system notifications
                if category == 'system_notification':
                    if 'known_sender' in signals['metadata_signals'] and is_known_sender:
                        score += signals['metadata_signals']['known_sender']
                    if 'automated' in signals['metadata_signals'] and is_system_notification:
                        score += signals['metadata_signals']['automated']
                        
                # Penalize score for obvious category mismatches
                if category == 'personal' and 'unsubscribe' in combined_text:
                    score -= 5
                    
                if category == 'transactional' and 'discount' in combined_text and 'coupon' in combined_text:
                    score -= 3
                    
                category_scores[category] = max(0, score)  # Ensure no negative scores
                
            # Get the top categories based on score
            sorted_categories = sorted(category_scores.items(), key=lambda x: x[1], reverse=True)
            
            # If no significant scores, mark as 'general'
            if not sorted_categories or sorted_categories[0][1] < 3:
                primary_category = 'general'
                confidence = 1.0
            else:
                primary_category = sorted_categories[0][0]
                
                # Calculate confidence (0-10 scale)
                top_score = sorted_categories[0][1]
                
                # If we have a second place category, use the gap to determine confidence
                if len(sorted_categories) > 1 and sorted_categories[1][1] > 0:
                    second_score = sorted_categories[1][1]
                    score_gap = top_score - second_score
                    
                    # Higher gap = higher confidence
                    confidence = min(10, (score_gap / second_score * 7) + 3) if second_score > 0 else 10
                else:
                    confidence = min(10, top_score)
                    
            # Get top 3 categories with scores
            top_three = sorted_categories[:3] if len(sorted_categories) >= 3 else sorted_categories
            
            safe_log(f"Classification: {primary_category} (confidence: {confidence:.1f})")
            
            return {
                "primary_category": primary_category,
                "confidence": confidence,
                "top_categories": top_three,
                "all_scores": category_scores
            }
        except Exception as e:
            safe_log(f"Enhanced email classification error: {e}", "ERROR")
            return {
                "primary_category": 'general',
                "confidence": 1.0,
                "top_categories": [('general', 1.0)],
                "all_scores": {}
            }

    def analyze_entity_combinations(self, entities):
        """Identify suspicious combinations of entities"""
        entity_types = [ent.get("label") for ent in entities]
        combos = []
        
        # Check for specific combinations
        if "MONEY" in entity_types and "URL" in entity_types:
            combos.append("MONEY+URL")
        
        if "MONEY" in entity_types and "PERSON" in entity_types:
            combos.append("MONEY+PERSON")
            
        if "ORG" in entity_types and "MONEY" in entity_types:
            combos.append("ORG+MONEY")
            
        if "EMAIL" in entity_types and "CARDINAL" in entity_types:
            combos.append("EMAIL+CARDINAL")
            
        if entity_types.count("MONEY") >= 3:
            combos.append("MULTIPLE_MONEY")
            
        if entity_types.count("URL") >= 3:
            combos.append("MULTIPLE_URL")
            
        if "WORK_OF_ART" in entity_types and "PERSON" in entity_types:
            combos.append("CREATIVE_CONTENT")
            
        return combos

# Global instance
email_classifier = EmailClassifier()
