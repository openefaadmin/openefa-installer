#!/usr/bin/env python3
"""
Mail Log Analyzer for SpaCy Server
Parses and analyzes combined mail logs for patterns and issues
"""

import re
import sys
import json
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path

class MailLogAnalyzer:
    def __init__(self, log_file="/var/log/mail.log"):
        self.log_file = log_file
        self.stats = defaultdict(int)
        self.domains = Counter()
        self.issues = []
        self.spacy_results = []
        
    def parse_log_line(self, line):
        """Parse a single mail log line"""
        patterns = {
            'timestamp': r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
            'from_addr': r'from=<([^>]+)>',
            'to_addr': r'to=<([^>]+)>',
            'status': r'status=(\w+)',
            'message_id': r'message-id=<([^>]+)>',
            'spacy_filter': r'relay=spacyfilter.*\((.*?)\)',
            'rejected': r'rejected:(.+)',
            'blocked': r'blocked.*?(\w+)',
        }
        
        result = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, line)
            if match:
                result[key] = match.group(1)
                
        return result
    
    def analyze_spacy_results(self, line):
        """Extract SpaCy filter results"""
        if 'spacyfilter' in line:
            if 'REJECTED' in line:
                self.stats['spacy_rejected'] += 1
                reason = re.search(r'REJECTED[:\s]+(.+?)(?:\s+Score|$)', line)
                if reason:
                    self.issues.append(f"Rejected: {reason.group(1)}")
            elif 'sent' in line:
                self.stats['spacy_passed'] += 1
                
    def analyze_domains(self, parsed):
        """Track domain statistics"""
        if 'from_addr' in parsed:
            domain = parsed['from_addr'].split('@')[-1] if '@' in parsed['from_addr'] else 'unknown'
            self.domains[domain] += 1
            
    def process_logs(self, lines_to_read=1000):
        """Process recent log entries"""
        try:
            with open(self.log_file, 'r') as f:
                # Read last N lines
                lines = f.readlines()[-lines_to_read:]
                
                for line in lines:
                    parsed = self.parse_log_line(line)
                    
                    if parsed:
                        # Update general stats
                        if 'status' in parsed:
                            self.stats[f"status_{parsed['status']}"] += 1
                        
                        # Analyze SpaCy results
                        self.analyze_spacy_results(line)
                        
                        # Track domains
                        self.analyze_domains(parsed)
                        
        except Exception as e:
            print(f"Error processing logs: {e}")
            
    def generate_report(self):
        """Generate analysis report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'stats': dict(self.stats),
            'top_domains': dict(self.domains.most_common(10)),
            'recent_issues': self.issues[-10:] if self.issues else [],
            'summary': {
                'total_processed': sum(self.stats.values()),
                'spacy_rejection_rate': (
                    self.stats['spacy_rejected'] / 
                    (self.stats['spacy_rejected'] + self.stats['spacy_passed'])
                    if (self.stats['spacy_rejected'] + self.stats['spacy_passed']) > 0 
                    else 0
                ) * 100
            }
        }
        
        return report
    
    def print_summary(self):
        """Print human-readable summary"""
        print("\n=== Mail Log Analysis ===\n")
        print(f"Total emails processed: {sum(self.stats.values())}")
        print(f"SpaCy passed: {self.stats.get('spacy_passed', 0)}")
        print(f"SpaCy rejected: {self.stats.get('spacy_rejected', 0)}")
        
        if self.stats.get('spacy_rejected', 0) + self.stats.get('spacy_passed', 0) > 0:
            rejection_rate = (self.stats['spacy_rejected'] / 
                            (self.stats['spacy_rejected'] + self.stats['spacy_passed'])) * 100
            print(f"Rejection rate: {rejection_rate:.1f}%")
        
        print("\n=== Top Sending Domains ===")
        for domain, count in self.domains.most_common(5):
            print(f"  {domain}: {count}")
            
        if self.issues:
            print("\n=== Recent Issues ===")
            for issue in self.issues[-5:]:
                print(f"  - {issue}")

def main():
    analyzer = MailLogAnalyzer()
    
    # Check if custom log file provided
    if len(sys.argv) > 1:
        analyzer.log_file = sys.argv[1]
    
    print(f"Analyzing {analyzer.log_file}...")
    analyzer.process_logs()
    
    # Generate report
    report = analyzer.generate_report()
    
    # Save report to SpaCy logs directory
    report_file = Path("/opt/spacyserver/logs/mail_analysis.json")
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    analyzer.print_summary()
    print(f"\nDetailed report saved to: {report_file}")

if __name__ == "__main__":
    main()