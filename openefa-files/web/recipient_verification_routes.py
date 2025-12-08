"""
Recipient Verification Routes for OpenEFA Web Interface
API endpoints for managing and testing recipient verification settings
"""

from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
import sys
import logging

# Add modules path
sys.path.insert(0, '/opt/spacyserver/modules')
sys.path.insert(0, '/opt/spacyserver')

from modules.recipient_verification import RecipientVerificationTester, RecipientVerificationManager

logger = logging.getLogger(__name__)

# Create blueprint
recipient_verification_bp = Blueprint('recipient_verification', __name__)


def get_db_connection():
    """Get database connection - import from main app"""
    import mysql.connector
    from config.database import DB_CONFIG
    return mysql.connector.connect(**DB_CONFIG)


def superadmin_required(f):
    """Decorator to require superadmin access"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'superadmin':
            return jsonify({'success': False, 'error': 'Superadmin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function


@recipient_verification_bp.route('/api/recipient-verification/test-domain/<int:domain_id>', methods=['POST'])
@login_required
@superadmin_required
def test_domain_verification(domain_id):
    """
    Test recipient verification for a specific domain

    Returns:
        JSON with test results including whether verification is supported
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get domain info
        cursor.execute("""
            SELECT domain, relay_host, relay_port
            FROM client_domains
            WHERE id = %s
        """, (domain_id,))

        domain_info = cursor.fetchone()

        if not domain_info:
            return jsonify({'success': False, 'error': 'Domain not found'}), 404

        if not domain_info['relay_host']:
            return jsonify({
                'success': False,
                'error': 'No relay host configured for this domain'
            }), 400

        # Test the relay host
        tester = RecipientVerificationTester()
        test_result = tester.test_relay_host(
            domain_info['relay_host'],
            domain_info['relay_port'] or 25,
            domain_info['domain']
        )

        # Update database with test results
        status = 'supported' if test_result['supported'] else 'not_supported'

        cursor.execute("""
            UPDATE client_domains
            SET recipient_verification_status = %s,
                recipient_verification_last_tested = NOW()
            WHERE id = %s
        """, (status, domain_id))

        conn.commit()

        # Log audit
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'RECIPIENT_VERIFICATION_TESTED', %s, %s)
        """, (
            current_user.id,
            f'Tested recipient verification for {domain_info["domain"]}: {status}',
            request.remote_addr
        ))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'supported': test_result['supported'],
            'status': status,
            'smtp_code': test_result['smtp_code'],
            'message': test_result['message'],
            'error': test_result['error'],
            'server_name': test_result['server_name'],
            'test_timestamp': test_result['test_timestamp']
        })

    except Exception as e:
        logger.error(f"Error testing domain verification: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@recipient_verification_bp.route('/api/recipient-verification/update-mode/<int:domain_id>', methods=['POST'])
@login_required
@superadmin_required
def update_verification_mode(domain_id):
    """
    Update recipient verification mode for a domain

    Request JSON:
        mode: 'auto', 'enabled', or 'disabled'

    Returns:
        JSON with success status
    """
    try:
        data = request.get_json()
        mode = data.get('mode', 'auto')

        if mode not in ['auto', 'enabled', 'disabled']:
            return jsonify({
                'success': False,
                'error': 'Invalid mode. Must be auto, enabled, or disabled'
            }), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get domain info
        cursor.execute("""
            SELECT domain FROM client_domains WHERE id = %s
        """, (domain_id,))

        domain_info = cursor.fetchone()

        if not domain_info:
            return jsonify({'success': False, 'error': 'Domain not found'}), 404

        # Update verification mode
        cursor.execute("""
            UPDATE client_domains
            SET recipient_verification_mode = %s,
                updated_at = NOW()
            WHERE id = %s
        """, (mode, domain_id))

        conn.commit()

        # Log audit
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'RECIPIENT_VERIFICATION_MODE_CHANGED', %s, %s)
        """, (
            current_user.id,
            f'Changed verification mode for {domain_info["domain"]} to: {mode}',
            request.remote_addr
        ))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': f'Verification mode updated to {mode}'
        })

    except Exception as e:
        logger.error(f"Error updating verification mode: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@recipient_verification_bp.route('/api/recipient-verification/stats/<int:domain_id>', methods=['GET'])
@login_required
def get_verification_stats(domain_id):
    """
    Get recipient verification statistics for a domain

    Query params:
        days: Number of days to look back (default: 7)

    Returns:
        JSON with verification statistics
    """
    try:
        days = int(request.args.get('days', 7))

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get domain info
        cursor.execute("""
            SELECT domain, recipient_verification_mode, recipient_verification_status,
                   recipient_verification_last_tested
            FROM client_domains
            WHERE id = %s
        """, (domain_id,))

        domain_info = cursor.fetchone()

        if not domain_info:
            return jsonify({'success': False, 'error': 'Domain not found'}), 404

        # Get verification stats
        cursor.execute("""
            SELECT
                verification_result,
                COUNT(*) as count
            FROM recipient_verification_stats
            WHERE domain = %s
              AND timestamp > DATE_SUB(NOW(), INTERVAL %s DAY)
            GROUP BY verification_result
        """, (domain_info['domain'], days))

        stats_results = cursor.fetchall()

        # Get rejection logs
        cursor.execute("""
            SELECT
                recipient,
                smtp_code,
                smtp_message,
                timestamp
            FROM recipient_rejections
            WHERE domain = %s
              AND timestamp > DATE_SUB(NOW(), INTERVAL %s DAY)
            ORDER BY timestamp DESC
            LIMIT 20
        """, (domain_info['domain'], days))

        rejection_logs = cursor.fetchall()

        cursor.close()
        conn.close()

        # Format stats
        stats = {result['verification_result']: result['count'] for result in stats_results}

        return jsonify({
            'success': True,
            'domain': domain_info['domain'],
            'mode': domain_info['recipient_verification_mode'],
            'status': domain_info['recipient_verification_status'],
            'last_tested': domain_info['recipient_verification_last_tested'].isoformat() if domain_info['recipient_verification_last_tested'] else None,
            'stats': {
                'accepted': stats.get('accepted', 0),
                'rejected': stats.get('rejected', 0),
                'error': stats.get('error', 0),
                'total': sum(stats.values())
            },
            'recent_rejections': [
                {
                    'recipient': r['recipient'],
                    'smtp_code': r['smtp_code'],
                    'message': r['smtp_message'],
                    'timestamp': r['timestamp'].isoformat() if r['timestamp'] else None
                }
                for r in rejection_logs
            ],
            'days': days
        })

    except Exception as e:
        logger.error(f"Error getting verification stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@recipient_verification_bp.route('/api/recipient-verification/verify-recipient', methods=['POST'])
@login_required
@superadmin_required
def verify_single_recipient():
    """
    Test verification for a single recipient email address

    Request JSON:
        recipient: Email address to verify
        domain_id: Domain ID to use for verification

    Returns:
        JSON with verification result
    """
    try:
        data = request.get_json()
        recipient = data.get('recipient', '').strip().lower()
        domain_id = data.get('domain_id')

        if not recipient or '@' not in recipient:
            return jsonify({
                'success': False,
                'error': 'Valid recipient email address required'
            }), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get domain info
        cursor.execute("""
            SELECT domain, relay_host, relay_port
            FROM client_domains
            WHERE id = %s
        """, (domain_id,))

        domain_info = cursor.fetchone()

        if not domain_info:
            return jsonify({'success': False, 'error': 'Domain not found'}), 404

        if not domain_info['relay_host']:
            return jsonify({
                'success': False,
                'error': 'No relay host configured for this domain'
            }), 400

        # Verify the recipient
        tester = RecipientVerificationTester()
        is_valid, smtp_code, message = tester.verify_recipient(
            domain_info['relay_host'],
            domain_info['relay_port'] or 25,
            recipient
        )

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'recipient': recipient,
            'is_valid': is_valid,
            'smtp_code': smtp_code,
            'message': message
        })

    except Exception as e:
        logger.error(f"Error verifying recipient: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
