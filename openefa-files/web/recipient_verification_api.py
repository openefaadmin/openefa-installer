"""
Recipient Verification API Endpoints for Dashboard and Reports
Provides data for UI components showing recipient verification status and rejections
"""

from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from sqlalchemy import create_engine, text
import os
import logging

logger = logging.getLogger(__name__)

# Create blueprint
recipient_verification_api_bp = Blueprint('recipient_verification_api', __name__)


def get_db_engine():
    """Get SQLAlchemy database engine"""
    try:
        # Use same connection method as main app
        MY_CNF_PATH = '/etc/spacy-server/.my.cnf'
        HOST = os.getenv('DB_HOST', 'localhost')
        DB_NAME = os.getenv('DB_NAME', 'spacy_email_db')

        db_url = f"mysql+pymysql://{HOST}/{DB_NAME}?read_default_file={MY_CNF_PATH}"
        engine = create_engine(
            db_url,
            pool_size=5,
            max_overflow=10,
            pool_recycle=3600,
            pool_pre_ping=True
        )
        return engine
    except Exception as e:
        logger.error(f"Failed to create database engine: {e}")
        return None


@recipient_verification_api_bp.route('/api/recipient-verification/dashboard-stats', methods=['GET'])
@login_required
def get_dashboard_stats():
    """
    Get recipient verification statistics for dashboard widget

    Returns:
        JSON with today's stats, rejection counts, trends
    """
    try:
        engine = get_db_engine()
        if not engine:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500

        with engine.connect() as conn:
            # Today's rejections
            result = conn.execute(text("""
                SELECT COUNT(*) as count
                FROM recipient_rejections
                WHERE DATE(timestamp) = CURDATE()
            """))
            today_rejections = result.fetchone()[0]

            # This week's rejections
            result = conn.execute(text("""
                SELECT COUNT(*) as count
                FROM recipient_rejections
                WHERE timestamp > DATE_SUB(NOW(), INTERVAL 7 DAY)
            """))
            week_rejections = result.fetchone()[0]

            # Top rejected domains today
            result = conn.execute(text("""
                SELECT domain, COUNT(*) as count
                FROM recipient_rejections
                WHERE DATE(timestamp) = CURDATE()
                GROUP BY domain
                ORDER BY count DESC
                LIMIT 3
            """))
            top_domains = [{'domain': row[0], 'count': row[1]} for row in result]

            # Recent rejections (last 10)
            result = conn.execute(text("""
                SELECT timestamp, sender, recipient, domain
                FROM recipient_rejections
                ORDER BY timestamp DESC
                LIMIT 10
            """))
            recent_rejections = [
                {
                    'timestamp': row[0].isoformat() if row[0] else None,
                    'sender': row[1],
                    'recipient': row[2],
                    'domain': row[3]
                }
                for row in result
            ]

            # Policy server status
            import subprocess
            try:
                status_result = subprocess.run(
                    ['systemctl', 'is-active', 'openefa-policy'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                policy_server_status = 'active' if status_result.stdout.strip() == 'active' else 'inactive'
            except:
                policy_server_status = 'unknown'

            # Domains with verification enabled
            result = conn.execute(text("""
                SELECT COUNT(*) as count
                FROM client_domains
                WHERE active = 1
                  AND recipient_verification_status = 'supported'
            """))
            domains_with_verification = result.fetchone()[0]

            return jsonify({
                'success': True,
                'today_rejections': today_rejections,
                'week_rejections': week_rejections,
                'top_domains': top_domains,
                'recent_rejections': recent_rejections,
                'policy_server_status': policy_server_status,
                'domains_with_verification': domains_with_verification
            })

    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@recipient_verification_api_bp.route('/api/recipient-verification/domain-stats/<domain>', methods=['GET'])
@login_required
def get_domain_stats(domain):
    """
    Get recipient verification statistics for a specific domain

    Args:
        domain: Domain name

    Query params:
        days: Number of days to look back (default: 30)

    Returns:
        JSON with domain-specific verification stats
    """
    try:
        days = int(request.args.get('days', 30))

        engine = get_db_engine()
        if not engine:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500

        with engine.connect() as conn:
            # Domain verification configuration
            result = conn.execute(text("""
                SELECT
                    recipient_verification_mode,
                    recipient_verification_status,
                    recipient_verification_last_tested,
                    relay_host,
                    relay_port
                FROM client_domains
                WHERE domain = :domain AND active = 1
            """), {'domain': domain})

            domain_config = result.fetchone()
            if not domain_config:
                return jsonify({'success': False, 'error': 'Domain not found'}), 404

            # Rejection statistics for this domain
            result = conn.execute(text("""
                SELECT COUNT(*) as count
                FROM recipient_rejections
                WHERE domain = :domain
                  AND timestamp > DATE_SUB(NOW(), INTERVAL :days DAY)
            """), {'domain': domain, 'days': days})
            total_rejections = result.fetchone()[0]

            # Rejections by day
            result = conn.execute(text("""
                SELECT
                    DATE(timestamp) as date,
                    COUNT(*) as count
                FROM recipient_rejections
                WHERE domain = :domain
                  AND timestamp > DATE_SUB(NOW(), INTERVAL :days DAY)
                GROUP BY DATE(timestamp)
                ORDER BY date DESC
            """), {'domain': domain, 'days': days})

            rejections_by_day = [
                {'date': row[0].isoformat() if row[0] else None, 'count': row[1]}
                for row in result
            ]

            # Top rejected recipients
            result = conn.execute(text("""
                SELECT
                    recipient,
                    COUNT(*) as count,
                    MAX(timestamp) as last_seen
                FROM recipient_rejections
                WHERE domain = :domain
                  AND timestamp > DATE_SUB(NOW(), INTERVAL :days DAY)
                GROUP BY recipient
                ORDER BY count DESC
                LIMIT 10
            """), {'domain': domain, 'days': days})

            top_rejected = [
                {
                    'recipient': row[0],
                    'count': row[1],
                    'last_seen': row[2].isoformat() if row[2] else None
                }
                for row in result
            ]

            # Recent rejections details
            result = conn.execute(text("""
                SELECT
                    timestamp,
                    sender,
                    recipient,
                    smtp_code,
                    smtp_message
                FROM recipient_rejections
                WHERE domain = :domain
                  AND timestamp > DATE_SUB(NOW(), INTERVAL :days DAY)
                ORDER BY timestamp DESC
                LIMIT 20
            """), {'domain': domain, 'days': days})

            recent_rejections = [
                {
                    'timestamp': row[0].isoformat() if row[0] else None,
                    'sender': row[1],
                    'recipient': row[2],
                    'smtp_code': row[3],
                    'smtp_message': row[4]
                }
                for row in result
            ]

            return jsonify({
                'success': True,
                'domain': domain,
                'verification_mode': domain_config[0],
                'verification_status': domain_config[1],
                'last_tested': domain_config[2].isoformat() if domain_config[2] else None,
                'relay_host': domain_config[3],
                'relay_port': domain_config[4],
                'total_rejections': total_rejections,
                'rejections_by_day': rejections_by_day,
                'top_rejected': top_rejected,
                'recent_rejections': recent_rejections,
                'days': days
            })

    except Exception as e:
        logger.error(f"Error getting domain stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@recipient_verification_api_bp.route('/api/recipient-verification/system-health', methods=['GET'])
@login_required
def get_system_health():
    """
    Get recipient verification system health status

    Returns:
        JSON with policy server status, performance metrics, error counts
    """
    try:
        import subprocess

        # Check policy server status
        try:
            status_result = subprocess.run(
                ['systemctl', 'is-active', 'openefa-policy'],
                capture_output=True,
                text=True,
                timeout=5
            )
            service_status = status_result.stdout.strip()

            # Get service details
            details_result = subprocess.run(
                ['systemctl', 'status', 'openefa-policy', '--no-pager', '-l'],
                capture_output=True,
                text=True,
                timeout=5
            )
            service_details = details_result.stdout

            # Extract memory usage
            memory_usage = None
            for line in service_details.split('\n'):
                if 'Memory:' in line:
                    memory_usage = line.split('Memory:')[1].strip().split()[0]
                    break

        except Exception as e:
            logger.error(f"Error checking service status: {e}")
            service_status = 'unknown'
            memory_usage = None

        # Check if port is listening
        try:
            port_check = subprocess.run(
                ['netstat', '-tlnp'],
                capture_output=True,
                text=True,
                timeout=5
            )
            port_listening = '10040' in port_check.stdout
        except:
            port_listening = False

        engine = get_db_engine()
        if not engine:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500

        with engine.connect() as conn:
            # Total queries processed (from rejections + verifications)
            result = conn.execute(text("""
                SELECT COUNT(*) as count
                FROM recipient_verification_stats
                WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """))
            queries_24h = result.fetchone()[0]

            # Error count
            result = conn.execute(text("""
                SELECT COUNT(*) as count
                FROM recipient_verification_stats
                WHERE verification_result = 'error'
                  AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """))
            errors_24h = result.fetchone()[0]

            # Rejection rate
            result = conn.execute(text("""
                SELECT
                    COUNT(CASE WHEN verification_result = 'rejected' THEN 1 END) as rejected,
                    COUNT(CASE WHEN verification_result = 'accepted' THEN 1 END) as accepted
                FROM recipient_verification_stats
                WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """))
            row = result.fetchone()
            rejected_count = row[0] or 0
            accepted_count = row[1] or 0
            total = rejected_count + accepted_count
            rejection_rate = (rejected_count / total * 100) if total > 0 else 0

            # Domains with verification
            result = conn.execute(text("""
                SELECT
                    domain,
                    recipient_verification_mode,
                    recipient_verification_status,
                    recipient_verification_last_tested
                FROM client_domains
                WHERE active = 1
                ORDER BY recipient_verification_status DESC, domain
            """))

            domains = [
                {
                    'domain': row[0],
                    'mode': row[1],
                    'status': row[2],
                    'last_tested': row[3].isoformat() if row[3] else None
                }
                for row in result
            ]

            return jsonify({
                'success': True,
                'policy_server': {
                    'status': service_status,
                    'port_listening': port_listening,
                    'memory_usage': memory_usage
                },
                'metrics_24h': {
                    'total_queries': queries_24h,
                    'errors': errors_24h,
                    'rejection_rate': round(rejection_rate, 2),
                    'rejected': rejected_count,
                    'accepted': accepted_count
                },
                'domains': domains
            })

    except Exception as e:
        logger.error(f"Error getting system health: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
