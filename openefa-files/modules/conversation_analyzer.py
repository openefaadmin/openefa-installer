"""
Conversation Legitimacy Analyzer
Uses SpaCy + sentence-transformers to detect legitimate conversations vs fake replies

This analyzer uses content-based analysis instead of relying on database conversation history.
It can distinguish real email replies from "Re:" phishing attacks by analyzing:
1. Quoted text presence and quality
2. Entity overlap between quoted and current content
3. Semantic similarity (are they on topic?)
4. Conversational markers (reply indicators)
5. Pronoun usage patterns
"""

import re
import spacy
from typing import Dict, Tuple
from pathlib import Path

# Global state for lazy loading
_nlp = None
_semantic_model = None

def get_spacy_model():
    """Lazy load SpaCy model (reuse if already loaded)"""
    global _nlp
    if _nlp is None:
        _nlp = spacy.load("en_core_web_lg")
    return _nlp

def get_semantic_model():
    """Lazy load sentence-transformers model (reuse if already loaded)"""
    global _semantic_model
    if _semantic_model is None:
        from sentence_transformers import SentenceTransformer
        # MiniLM model: fast, lightweight (~80MB), excellent for semantic similarity
        _semantic_model = SentenceTransformer('all-MiniLM-L6-v2')
    return _semantic_model


def extract_quoted_text(email_body: str) -> str:
    """
    Extract quoted text from email body
    Looks for lines starting with >, |, or other quote indicators
    """
    quoted_lines = []
    lines = email_body.split('\n')

    for line in lines:
        stripped = line.strip()
        # Check for quote indicators
        if stripped.startswith(('>','|', '│')):
            # Remove quote prefix
            clean_line = re.sub(r'^[>\|│\s]+', '', stripped)
            if clean_line:  # Not empty after removing prefix
                quoted_lines.append(clean_line)

    return '\n'.join(quoted_lines)


def analyze_entity_overlap(quoted_text: str, current_text: str, nlp) -> Tuple[float, set, set]:
    """
    Analyze entity overlap between quoted and current content
    Returns: (overlap_ratio, quoted_entities, current_entities)
    """
    if not quoted_text or not current_text:
        return 0.0, set(), set()

    # Extract entities from both texts
    quoted_doc = nlp(quoted_text[:10000])  # Limit to 10K chars for performance
    current_doc = nlp(current_text[:10000])

    quoted_entities = {ent.text.lower() for ent in quoted_doc.ents}
    current_entities = {ent.text.lower() for ent in current_doc.ents}

    if not quoted_entities:
        return 0.0, quoted_entities, current_entities

    # Calculate overlap ratio
    overlap = len(quoted_entities & current_entities)
    overlap_ratio = overlap / len(quoted_entities)

    return overlap_ratio, quoted_entities, current_entities


def detect_conversational_markers(current_text: str) -> Tuple[int, list]:
    """
    Detect reply indicators and conversational patterns
    Returns: (marker_count, detected_patterns)
    """
    reply_patterns = [
        (r'\b(yes|no|correct|exactly|right|indeed|absolutely)\b', 'agreement'),
        (r'\b(that\'s|this is|it is|they are|these are)\b', 'pronoun_reference'),
        (r'\b(as (you|I) (mentioned|said|stated|noted))\b', 'explicit_reference'),
        (r'\b(regarding|about|concerning) (your|the)\b', 'topic_continuation'),
        (r'\b(thank you|thanks|appreciated|got it)\b', 'politeness'),
        (r'\b(I (agree|disagree|understand))\b', 'opinion'),
        (r'\b(you (asked|mentioned|said|wrote))\b', 'direct_reference'),
    ]

    detected = []
    marker_count = 0

    for pattern, pattern_type in reply_patterns:
        if re.search(pattern, current_text, re.IGNORECASE):
            marker_count += 1
            detected.append(pattern_type)

    return marker_count, detected


def analyze_pronoun_usage(current_text: str, has_quoted_text: bool, nlp) -> float:
    """
    Analyze pronoun density in current email
    High pronoun usage WITH quoted text = legitimate reply referencing previous content
    High pronoun usage WITHOUT quoted text = suspicious
    """
    doc = nlp(current_text[:5000])  # Limit for performance

    reference_pronouns = {'it', 'this', 'that', 'these', 'those', 'they', 'them'}
    pronoun_count = sum(1 for token in doc if token.text.lower() in reference_pronouns)

    # Short emails with pronouns
    word_count = len([token for token in doc if token.is_alpha])

    if word_count == 0:
        return 0.0

    pronoun_density = pronoun_count / word_count

    # Pronouns are GOOD if there's quoted text (referencing previous conversation)
    # Pronouns are SUSPICIOUS if there's no quoted text (fake reply)
    if has_quoted_text and pronoun_count > 2:
        return 15.0  # Bonus for legitimate pronoun usage
    elif not has_quoted_text and pronoun_density > 0.15:
        return -10.0  # Penalty for suspicious pronoun usage

    return 0.0


def calculate_semantic_similarity(quoted_text: str, current_text: str, semantic_model) -> float:
    """
    Calculate semantic similarity between quoted and current content
    Returns similarity score 0-1 (1 = very similar topics)
    """
    if not quoted_text or not current_text:
        return 0.0

    # Truncate to reasonable lengths (models have token limits)
    quoted_text = quoted_text[:1000]
    current_text = current_text[:1000]

    try:
        from sentence_transformers import util

        # Encode both texts
        quoted_embedding = semantic_model.encode(quoted_text, convert_to_tensor=True)
        current_embedding = semantic_model.encode(current_text, convert_to_tensor=True)

        # Calculate cosine similarity
        similarity = util.cos_sim(quoted_embedding, current_embedding).item()

        return max(0.0, min(1.0, similarity))  # Clamp to 0-1
    except Exception as e:
        print(f"Semantic similarity error: {e}")
        return 0.0


def analyze_conversation_legitimacy(current_email: str, subject: str = "") -> Dict:
    """
    Analyze whether this email is a legitimate conversation/reply

    Returns dict with:
        - legitimacy_score: 0-100 (higher = more legitimate)
        - is_legitimate_conversation: bool
        - details: breakdown of scoring
    """
    # Initialize models (lazy loaded)
    nlp = get_spacy_model()

    # Extract quoted text
    quoted_text = extract_quoted_text(current_email)
    has_quoted_text = len(quoted_text) > 50

    # Get text without quotes for current content analysis
    current_text = re.sub(r'^[>\|│\s]+.*$', '', current_email, flags=re.MULTILINE)
    current_text = current_text.strip()

    # Scoring components
    score = 0.0
    details = {}

    # 1. QUOTED TEXT PRESENCE (0-25 points)
    if has_quoted_text:
        quoted_score = min(25.0, len(quoted_text) / 200 * 25)  # Up to 25 points
        score += quoted_score
        details['quoted_text'] = {
            'present': True,
            'length': len(quoted_text),
            'score': quoted_score
        }
    else:
        details['quoted_text'] = {'present': False, 'score': 0}

    # 2. ENTITY OVERLAP (0-30 points)
    entity_overlap, quoted_entities, current_entities = analyze_entity_overlap(
        quoted_text, current_text, nlp
    )
    entity_score = entity_overlap * 30
    score += entity_score
    details['entity_overlap'] = {
        'ratio': entity_overlap,
        'quoted_entities': list(quoted_entities)[:10],  # Limit for brevity
        'current_entities': list(current_entities)[:10],
        'score': entity_score
    }

    # 3. CONVERSATIONAL MARKERS (0-20 points)
    marker_count, markers = detect_conversational_markers(current_text)
    marker_score = min(20.0, marker_count * 5)  # 5 points per marker, max 20
    score += marker_score
    details['conversational_markers'] = {
        'count': marker_count,
        'markers': markers,
        'score': marker_score
    }

    # 4. PRONOUN USAGE (0-15 points or -10 penalty)
    pronoun_score = analyze_pronoun_usage(current_text, has_quoted_text, nlp)
    score += pronoun_score
    details['pronoun_usage'] = {'score': pronoun_score}

    # 5. SEMANTIC SIMILARITY (0-25 points) - ONLY if we have quoted text
    if has_quoted_text and len(quoted_text) > 30 and len(current_text) > 10:
        try:
            semantic_model = get_semantic_model()
            similarity = calculate_semantic_similarity(quoted_text, current_text, semantic_model)
            semantic_score = similarity * 25
            score += semantic_score
            details['semantic_similarity'] = {
                'similarity': similarity,
                'score': semantic_score
            }
        except Exception as e:
            details['semantic_similarity'] = {'error': str(e), 'score': 0}
    else:
        details['semantic_similarity'] = {'skipped': True, 'score': 0}

    # 6. SHORT CONFIRMATION BONUS (0-35 points)
    # Brief replies like "that's correct", "yes", "no problem" are legitimate if they have quoted text
    doc = nlp(current_text[:1000])
    word_count = len([token for token in doc if token.is_alpha])

    if has_quoted_text and word_count <= 20 and marker_count > 0:
        # Short response WITH quoted text AND conversational markers = likely legitimate brief reply
        short_bonus = 35.0
        score += short_bonus
        details['short_confirmation_bonus'] = {
            'word_count': word_count,
            'applied': True,
            'score': short_bonus
        }
    else:
        details['short_confirmation_bonus'] = {'applied': False, 'score': 0}

    # Ensure score is in valid range
    score = max(0.0, min(100.0, score))

    # Determine if legitimate (threshold: 60)
    is_legitimate = score >= 60

    return {
        'legitimacy_score': score,
        'is_legitimate_conversation': is_legitimate,
        'has_quoted_text': has_quoted_text,
        'details': details,
        'recommendation': _get_recommendation(score)
    }


def _get_recommendation(score: float) -> str:
    """Get recommendation based on legitimacy score"""
    if score >= 80:
        return "High confidence legitimate conversation - reduce fake_reply penalty by 95%"
    elif score >= 60:
        return "Likely legitimate conversation - reduce fake_reply penalty by 90%"
    elif score >= 40:
        return "Uncertain - reduce fake_reply penalty by 50%"
    elif score >= 20:
        return "Likely fake reply - reduce fake_reply penalty by 25%"
    else:
        return "High confidence fake reply - apply full penalty"


# Quick test function
if __name__ == "__main__":
    # Test with example email conversation
    test_email = """that's correct.

On Sun, Nov 23, 2025 at 8:47 AM Jane Smith <jane.smith@example.com> wrote:

> Yes
>
> On Sat, Nov 22, 2025 at 7:52 PM John Doe <john.doe@example.com> wrote:
>
>> Jane:
>>
>> You mean that ABC Holdings LLC and Smith Family Trust are 50/50 on
>> title to the 123 Main Street property, right?
>>
>> John Doe
"""

    result = analyze_conversation_legitimacy(test_email)
    print(f"Legitimacy Score: {result['legitimacy_score']:.1f}/100")
    print(f"Is Legitimate: {result['is_legitimate_conversation']}")
    print(f"Recommendation: {result['recommendation']}")
    print(f"\nDetails:")
    for key, value in result['details'].items():
        print(f"  {key}: {value}")
