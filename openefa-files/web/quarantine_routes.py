"""
Quarantine Routes for SpacyWeb
To integrate: Add these routes to /opt/spacyserver/web/app.py
"""

from flask import render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from datetime import datetime, timedelta
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.message import EmailMessage
import mysql.connector
import re

# These functions should be added to app.py


@app.route('/quarantine')
@login_required
def quarantine_view():
    """Main quarantine view - list of quarantined emails"""
    try:
        # Get filter parameters
        domain_filter = request.args.get('domain', '')
        status_filter = request.args.get('status', 'held')
        search_query = request.args.get('search', '')
        page = int(request.args.get('page', 1))
        per_page = 50

        # Get user's authorized domains
        user_domains = get_user_authorized_domains(current_user)

        # Build query
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Base query
        query = """
            SELECT
                id, message_id, timestamp, sender, sender_domain,
                recipients, subject, spam_score, quarantine_status,
                quarantine_reason, quarantine_expires_at, has_attachments,
                attachment_count, virus_detected, phishing_detected,
                reviewed_by, reviewed_at,
                DATEDIFF(quarantine_expires_at, NOW()) as days_until_expiry
            FROM email_quarantine
            WHERE 1=1
        """
        params = []

        # Filter by status
        if status_filter and status_filter != 'all':
            query += " AND quarantine_status = %s"
            params.append(status_filter)

        # Filter by domain (user access control)
        if not current_user.is_admin():
            # Non-admin users only see emails for their authorized domains
            if user_domains:
                domain_placeholders = ','.join(['%s'] * len(user_domains))
                query += f" AND (sender_domain IN ({domain_placeholders})"
                params.extend(user_domains)

                # Also check recipient domains
                for domain in user_domains:
                    query += " OR recipients LIKE %s"
                    params.append(f'%{domain}%')
                query += ")"
        else:
            # Admin can filter by specific domain if requested
            if domain_filter:
                query += " AND (sender_domain = %s OR recipients LIKE %s)"
                params.extend([domain_filter, f'%{domain_filter}%'])

        # Search filter
        if search_query:
            query += """ AND (
                sender LIKE %s OR
                subject LIKE %s OR
                recipients LIKE %s
            )"""
            search_param = f'%{search_query}%'
            params.extend([search_param, search_param, search_param])

        # Only show non-expired
        query += " AND quarantine_expires_at > NOW()"

        # Order by timestamp (newest first)
        query += " ORDER BY timestamp DESC"

        # Count total for pagination
        count_query = f"SELECT COUNT(*) as total FROM ({query}) as filtered"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()['total']

        # Add pagination
        offset = (page - 1) * per_page
        query += f" LIMIT {per_page} OFFSET {offset}"

        # Execute main query
        cursor.execute(query, params)
        quarantined_emails = cursor.fetchall()

        # Calculate pagination
        total_pages = (total_count + per_page - 1) // per_page

        # Get statistics
        stats_query = """
            SELECT
                COUNT(*) as total_held,
                COUNT(CASE WHEN quarantine_expires_at < DATE_ADD(NOW(), INTERVAL 7 DAY) THEN 1 END) as expiring_soon,
                AVG(spam_score) as avg_spam_score,
                SUM(CASE WHEN virus_detected = 1 THEN 1 ELSE 0 END) as virus_count
            FROM email_quarantine
            WHERE quarantine_status = 'held'
            AND quarantine_expires_at > NOW()
        """

        if not current_user.is_admin() and user_domains:
            domain_placeholders = ','.join(['%s'] * len(user_domains))
            stats_query += f" AND sender_domain IN ({domain_placeholders})"
            cursor.execute(stats_query, user_domains)
        else:
            cursor.execute(stats_query)

        stats = cursor.fetchone()

        cursor.close()
        conn.close()

        return render_template('quarantine.html',
                             quarantined_emails=quarantined_emails,
                             stats=stats,
                             page=page,
                             total_pages=total_pages,
                             total_count=total_count,
                             status_filter=status_filter,
                             domain_filter=domain_filter,
                             search_query=search_query,
                             user_domains=user_domains,
                             selected_domain=domain_filter or (user_domains[0] if user_domains else ''))

    except Exception as e:
        logger.error(f"Error loading quarantine view: {e}")
        flash(f'Error loading quarantine: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))


@app.route('/quarantine/<int:email_id>')
@login_required
def quarantine_detail(email_id):
    """Detailed view of a single quarantined email"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get email details
        query = """
            SELECT
                id, message_id, timestamp, sender, sender_domain,
                recipients, recipient_domains, subject,
                raw_email, email_size, text_content, html_content,
                has_attachments, attachment_count, attachment_names,
                spam_score, spam_modules_detail, virus_detected, virus_names,
                phishing_detected, spf_result, dkim_result, dmarc_result,
                auth_score, quarantine_status, quarantine_reason,
                quarantine_expires_at, user_classification,
                reviewed_by, reviewed_at, released_by, released_at,
                admin_notes,
                DATEDIFF(quarantine_expires_at, NOW()) as days_until_expiry
            FROM email_quarantine
            WHERE id = %s
        """

        cursor.execute(query, (email_id,))
        email = cursor.fetchone()

        if not email:
            flash('Email not found', 'warning')
            return redirect(url_for('quarantine_view'))

        # Check access permissions
        if not current_user.is_admin():
            user_domains = get_user_authorized_domains(current_user)
            sender_domain = email['sender_domain']
            recipient_domains = json.loads(email['recipient_domains']) if email['recipient_domains'] else []

            # User must have access to sender domain or one of recipient domains
            has_access = (sender_domain in user_domains) or any(rd in user_domains for rd in recipient_domains)

            if not has_access:
                flash('Access denied', 'danger')
                return redirect(url_for('quarantine_view'))

        # Parse JSON fields
        if email['recipients']:
            email['recipients_list'] = json.loads(email['recipients'])
        else:
            email['recipients_list'] = []

        if email['attachment_names']:
            email['attachment_names_list'] = json.loads(email['attachment_names'])
        else:
            email['attachment_names_list'] = []

        if email['spam_modules_detail']:
            email['spam_modules'] = json.loads(email['spam_modules_detail'])
        else:
            email['spam_modules'] = {}

        # Get action history
        history_query = """
            SELECT
                action_type, action_timestamp, performed_by,
                user_role, action_details, reason
            FROM quarantine_actions_log
            WHERE quarantine_id = %s
            ORDER BY action_timestamp DESC
        """
        cursor.execute(history_query, (email_id,))
        email['action_history'] = cursor.fetchall()

        # Sanitize text content for preview (limit to 10KB)
        if email['text_content']:
            email['text_preview'] = email['text_content'][:10000]
        else:
            email['text_preview'] = ''

        cursor.close()
        conn.close()

        return render_template('quarantine_detail.html', email=email)

    except Exception as e:
        logger.error(f"Error loading email detail: {e}")
        flash(f'Error loading email: {str(e)}', 'danger')
        return redirect(url_for('quarantine_view'))


@app.route('/api/quarantine/<int:email_id>/release', methods=['POST'])
@login_required
def api_quarantine_release(email_id):
    """Release email from quarantine and relay to destination"""
    try:
        # Get release destination config
        with open('/opt/spacyserver/config/quarantine_config.json', 'r') as f:
            config = json.load(f)

        release_config = config.get('release_destination', {})
        mode = release_config.get('mode', 'mailguard')

        if mode == 'mailguard':
            dest = release_config.get('mailguard', {})
        else:
            dest = release_config.get('zimbra', {})

        relay_host = dest.get('host', os.getenv('SPACY_RELAY_HOST', 'YOUR_EFA_SERVER_IP'))
        relay_port = dest.get('port', 25)

        # Get email from database
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        query = "SELECT * FROM email_quarantine WHERE id = %s"
        cursor.execute(query, (email_id,))
        email = cursor.fetchone()

        if not email:
            return jsonify({'success': False, 'error': 'Email not found'}), 404

        if email['quarantine_status'] != 'held':
            return jsonify({'success': False, 'error': 'Email already released or deleted'}), 400

        # Check permissions
        if not current_user.is_admin():
            user_domains = get_user_authorized_domains(current_user)
            sender_domain = email['sender_domain']

            if sender_domain not in user_domains:
                return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Parse recipients
        recipients = json.loads(email['recipients']) if email['recipients'] else []

        # Relay email using SMTP
        try:
            # Parse raw email
            msg = EmailMessage()
            msg.set_content(email['raw_email'])

            # Connect and send
            with smtplib.SMTP(relay_host, relay_port, timeout=30) as smtp:
                smtp.sendmail(email['sender'], recipients, email['raw_email'])

            # Update database
            update_query = """
                UPDATE email_quarantine
                SET quarantine_status = 'released',
                    released_by = %s,
                    released_at = NOW(),
                    released_to = %s
                WHERE id = %s
            """
            cursor.execute(update_query, (current_user.email, mode, email_id))

            # Log action
            log_query = """
                INSERT INTO quarantine_actions_log
                (quarantine_id, action_type, performed_by, user_role, action_details)
                VALUES (%s, %s, %s, %s, %s)
            """
            log_data = json.dumps({
                'released_to': relay_host,
                'recipient_count': len(recipients),
                'mode': mode
            })
            cursor.execute(log_query, (email_id, 'released', current_user.email,
                                      'admin' if current_user.is_admin() else 'user', log_data))

            conn.commit()

            logger.info(f"Email {email_id} released by {current_user.email} to {relay_host}")

            return jsonify({
                'success': True,
                'message': f'Email released and sent to {mode}',
                'released_to': relay_host
            })

        except smtplib.SMTPException as e:
            logger.error(f"SMTP error releasing email {email_id}: {e}")
            return jsonify({'success': False, 'error': f'Failed to relay email: {str(e)}'}), 500

    except Exception as e:
        logger.error(f"Error releasing email {email_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route('/api/quarantine/<int:email_id>/delete', methods=['POST'])
@login_required
def api_quarantine_delete(email_id):
    """Delete email from quarantine (mark as spam)"""
    try:
        data = request.get_json() or {}
        reason = data.get('reason', 'User confirmed spam')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if email exists and get details
        cursor.execute("SELECT * FROM email_quarantine WHERE id = %s", (email_id,))
        email = cursor.fetchone()

        if not email:
            return jsonify({'success': False, 'error': 'Email not found'}), 404

        # Check permissions
        if not current_user.is_admin():
            user_domains = get_user_authorized_domains(current_user)
            if email['sender_domain'] not in user_domains:
                return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Update status
        update_query = """
            UPDATE email_quarantine
            SET quarantine_status = 'deleted',
                user_classification = 'spam',
                deleted_by = %s,
                deleted_at = NOW()
            WHERE id = %s
        """
        cursor.execute(update_query, (current_user.email, email_id))

        # Log action
        log_query = """
            INSERT INTO quarantine_actions_log
            (quarantine_id, action_type, performed_by, user_role, reason)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(log_query, (email_id, 'marked_spam', current_user.email,
                                  'admin' if current_user.is_admin() else 'user', reason))

        conn.commit()

        logger.info(f"Email {email_id} marked as spam by {current_user.email}")

        return jsonify({'success': True, 'message': 'Email marked as spam and deleted'})

    except Exception as e:
        logger.error(f"Error deleting email {email_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route('/api/quarantine/<int:email_id>/not-spam', methods=['POST'])
@login_required
def api_quarantine_mark_not_spam(email_id):
    """Mark email as not spam (for learning) and release"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get email
        cursor.execute("SELECT * FROM email_quarantine WHERE id = %s", (email_id,))
        email = cursor.fetchone()

        if not email:
            return jsonify({'success': False, 'error': 'Email not found'}), 404

        # Check permissions
        if not current_user.is_admin():
            user_domains = get_user_authorized_domains(current_user)
            if email['sender_domain'] not in user_domains:
                return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Update classification
        update_query = """
            UPDATE email_quarantine
            SET user_classification = 'not_spam',
                reviewed_by = %s,
                reviewed_at = NOW()
            WHERE id = %s
        """
        cursor.execute(update_query, (current_user.email, email_id))

        # Log action
        log_query = """
            INSERT INTO quarantine_actions_log
            (quarantine_id, action_type, performed_by, user_role)
            VALUES (%s, %s, %s, %s)
        """
        cursor.execute(log_query, (email_id, 'marked_not_spam', current_user.email,
                                  'admin' if current_user.is_admin() else 'user'))

        conn.commit()

        # TODO: Add sender to whitelist (implement in future)
        # TODO: Update spam filter learning (implement in future)

        logger.info(f"Email {email_id} marked as not spam by {current_user.email}")

        return jsonify({
            'success': True,
            'message': 'Email marked as not spam. Release separately if needed.'
        })

    except Exception as e:
        logger.error(f"Error marking email {email_id} as not spam: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route('/api/quarantine/bulk-release', methods=['POST'])
@login_required
def api_quarantine_bulk_release():
    """Bulk release multiple emails"""
    try:
        data = request.get_json()
        email_ids = data.get('email_ids', [])

        if not email_ids:
            return jsonify({'success': False, 'error': 'No emails selected'}), 400

        if len(email_ids) > 100:
            return jsonify({'success': False, 'error': 'Maximum 100 emails at once'}), 400

        success_count = 0
        error_count = 0
        errors = []

        for email_id in email_ids:
            # Call single release function for each email
            try:
                response = api_quarantine_release(email_id)
                if response[1] == 200:  # Success
                    success_count += 1
                else:
                    error_count += 1
                    errors.append(f"Email {email_id}: {response[0].get_json().get('error')}")
            except Exception as e:
                error_count += 1
                errors.append(f"Email {email_id}: {str(e)}")

        return jsonify({
            'success': True,
            'message': f'Released {success_count} emails, {error_count} errors',
            'success_count': success_count,
            'error_count': error_count,
            'errors': errors[:10]  # Limit error messages
        })

    except Exception as e:
        logger.error(f"Error in bulk release: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
