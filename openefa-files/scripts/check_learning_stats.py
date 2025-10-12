#!/usr/bin/env python3
"""
Check conversation learning statistics
"""

import sys
import os
sys.path.insert(0, '/opt/spacyserver')

from modules.conversation_learner import ConversationLearner

def main():
    learner = ConversationLearner()
    stats = learner.get_statistics()
    
    print("="*60)
    print("CONVERSATION LEARNING STATISTICS")
    print("="*60)
    print(f"Vocabulary patterns learned: {stats.get('vocabulary_size', 0)}")
    print(f"Domain relationships tracked: {stats.get('relationships', 0)}")
    print(f"Professional phrases identified: {stats.get('phrases', 0)}")
    print(f"Client domains monitored: {stats.get('domains_tracked', 0)}")
    print(f"Average messages per domain: {stats.get('avg_messages_per_domain', 0):.1f}")
    
    if stats.get('top_relationships'):
        print("\nTop 5 Email Relationships:")
        for i, (sender, recipient, count) in enumerate(stats['top_relationships'], 1):
            print(f"  {i}. {sender} → {recipient}: {count} messages")
    
    print("\nLearning Status: ACTIVE ✅")
    print("Confidence will increase as more patterns are learned.")
    print("\nTo view email headers, look for:")
    print("  X-Conversation-Pattern-Adjustment: (spam score change)")
    print("  X-Conversation-Legitimacy: (0-1 legitimacy score)")
    print("  X-Learning-Confidence: (0-1 confidence level)")

if __name__ == "__main__":
    main()