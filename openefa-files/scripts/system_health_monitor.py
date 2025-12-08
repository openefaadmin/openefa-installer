#!/opt/spacyserver/venv/bin/python3
"""
System Health Monitor for OpenEFA
Monitors critical system components and sends SMS alerts for issues:
- Postfix service status
- Mail queue size
- Email processing health
- Database connectivity
- Disk space
"""

import sys
import os
import subprocess
import re
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv('/etc/spacy-server/.env')

# Add parent directory to path
sys.path.insert(0, '/opt/spacyserver')

from notification_service import NotificationService

# Thresholds
MAIL_QUEUE_THRESHOLD = 50
DISK_SPACE_THRESHOLD = 90  # percent
ALERT_COOLDOWN_MINUTES = 30  # Don't re-alert for same issue within 30 min

# State file to track last alerts
STATE_FILE = '/tmp/health_monitor_state.txt'


def load_alert_state():
    """Load last alert timestamps to prevent spam"""
    state = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                for line in f:
                    if ':' in line:
                        alert_type, timestamp_str = line.strip().split(':', 1)
                        state[alert_type] = datetime.fromisoformat(timestamp_str)
        except Exception as e:
            print(f"Error loading state: {e}")
    return state


def save_alert_state(state):
    """Save alert timestamps"""
    try:
        with open(STATE_FILE, 'w') as f:
            for alert_type, timestamp in state.items():
                f.write(f"{alert_type}:{timestamp.isoformat()}\n")
    except Exception as e:
        print(f"Error saving state: {e}")


def should_alert(alert_type, state):
    """Check if enough time has passed since last alert"""
    if alert_type not in state:
        return True

    last_alert = state[alert_type]
    if datetime.now() - last_alert > timedelta(minutes=ALERT_COOLDOWN_MINUTES):
        return True

    return False


def check_postfix_status():
    """Check if Postfix is running"""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'postfix'],
            capture_output=True,
            text=True,
            timeout=5
        )

        status = result.stdout.strip()
        if status == 'active':
            return True, "Postfix is running"
        else:
            return False, f"Postfix is {status}"

    except subprocess.TimeoutExpired:
        return False, "Postfix status check timed out"
    except Exception as e:
        return False, f"Error checking Postfix: {e}"


def check_mail_queue():
    """Check mail queue size - filtering out spam backscatter"""
    try:
        result = subprocess.run(
            ['mailq'],
            capture_output=True,
            text=True,
            timeout=10
        )

        output = result.stdout

        # Parse mailq output
        # "Mail queue is empty" or "-- X Kbytes in Y Request(s)."
        if 'Mail queue is empty' in output or 'queue is empty' in output:
            return True, 0, "Mail queue is empty"

        # Get list of client domains to filter for legitimate mail
        try:
            db_name = os.getenv('DB_NAME', 'spacy_email_db')
            domain_result = subprocess.run(
                ['mysql', '--defaults-file=/opt/spacyserver/config/.my.cnf',
                 db_name, '-N', '-e',
                 'SELECT domain FROM client_domains WHERE active = 1;'],
                capture_output=True,
                text=True,
                timeout=5
            )
            client_domains = [d.strip() for d in domain_result.stdout.split('\n') if d.strip()]
        except Exception:
            client_domains = []

        # Count legitimate vs backscatter messages
        lines = output.split('\n')
        legitimate_count = 0
        backscatter_count = 0

        for line in lines:
            # Look for sender lines (lines with @ in them that aren't headers)
            if '@' in line and not line.startswith('-'):
                # Skip MAILER-DAEMON bounces to suspicious domains
                if 'MAILER-DAEMON' in line:
                    # Check if recipient is to a client domain
                    is_client_bounce = False
                    for domain in client_domains:
                        if f'@{domain}' in line.lower():
                            is_client_bounce = True
                            break

                    if is_client_bounce:
                        legitimate_count += 1
                    else:
                        backscatter_count += 1
                else:
                    # Non-bounce messages - check if to/from client domains
                    is_client_mail = False
                    for domain in client_domains:
                        if f'@{domain}' in line.lower():
                            is_client_mail = True
                            break

                    if is_client_mail:
                        legitimate_count += 1

        # Get total count from summary line
        total_count = 0
        match = re.search(r'(\d+)\s+Request', output, re.IGNORECASE)
        if match:
            total_count = int(match.group(1))

        # Alert only on legitimate client emails stuck in queue
        if legitimate_count > MAIL_QUEUE_THRESHOLD:
            return False, legitimate_count, f"{legitimate_count} CLIENT emails stuck in queue (ignoring {backscatter_count} spam bounces)"
        elif legitimate_count > 0:
            return True, legitimate_count, f"{legitimate_count} client emails in queue, {backscatter_count} spam bounces (normal)"
        elif total_count > 0:
            return True, 0, f"Queue has {total_count} spam bounces (no client mail stuck)"
        else:
            return True, 0, "Mail queue is empty"

    except subprocess.TimeoutExpired:
        return False, -1, "Mail queue check timed out"
    except Exception as e:
        return False, -1, f"Error checking mail queue: {e}"


def check_policy_server_status():
    """Check if OpenEFA recipient policy server is running"""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'openefa-policy'],
            capture_output=True,
            text=True,
            timeout=5
        )

        status = result.stdout.strip()
        if status == 'active':
            # Also check if it's listening on port 10040
            try:
                port_result = subprocess.run(
                    ['ss', '-tlnp'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if ':10040' in port_result.stdout:
                    return True, "Policy server is running and listening on port 10040"
                else:
                    return False, "Policy server is active but not listening on port 10040"
            except Exception:
                # If we can't check port, assume it's OK if service is active
                return True, "Policy server is running"
        else:
            return False, f"Policy server is {status}"

    except subprocess.TimeoutExpired:
        return False, "Policy server status check timed out"
    except Exception as e:
        return False, f"Error checking policy server: {e}"


def check_spacyweb_status():
    """Check if SpacyWeb (gunicorn) dashboard is running and responding"""
    try:
        # Check if service is active
        result = subprocess.run(
            ['systemctl', 'is-active', 'spacyweb'],
            capture_output=True,
            text=True,
            timeout=5
        )

        status = result.stdout.strip()
        if status != 'active':
            return False, f"SpacyWeb service is {status}"

        # Check if it's listening on port 5500
        port_result = subprocess.run(
            ['ss', '-tlnp'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if ':5500' not in port_result.stdout:
            return False, "SpacyWeb is active but not listening on port 5500"

        # Check if it's actually responding to HTTPS requests (login page)
        try:
            http_result = subprocess.run(
                ['curl', '-k', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                 '--max-time', '5', 'https://127.0.0.1:5500/auth/login'],
                capture_output=True,
                text=True,
                timeout=10
            )

            http_code = http_result.stdout.strip()
            if http_code == '200':
                return True, "SpacyWeb is running and responding (HTTPS 200)"
            elif http_code == '000':
                return False, "SpacyWeb is not responding to HTTPS requests (connection failed)"
            else:
                return False, f"SpacyWeb is responding with HTTPS {http_code} (expected 200)"
        except Exception as e:
            # If HTTPS check fails, but service is running, that's still concerning
            return False, f"SpacyWeb service active but HTTPS health check failed: {e}"

    except subprocess.TimeoutExpired:
        return False, "SpacyWeb status check timed out"
    except Exception as e:
        return False, f"Error checking SpacyWeb: {e}"


def check_spacy_filter_running():
    """Check if email filter has processed emails recently"""
    try:
        # Check if log file exists and has recent activity
        log_file = '/var/log/mail.log'
        if not os.path.exists(log_file):
            return True, "Log file not found (might be OK)"

        # Get last 50 lines of mail.log
        result = subprocess.run(
            ['tail', '-n', '50', log_file],
            capture_output=True,
            text=True,
            timeout=5
        )

        # Look for recent SpaCy filter activity
        lines = result.stdout.split('\n')
        spacy_lines = [l for l in lines if 'spacy' in l.lower() or 'email_filter' in l.lower()]

        # If we see any SpaCy activity in last 50 lines, assume it's working
        if len(spacy_lines) > 0:
            return True, f"Email filter active ({len(spacy_lines)} recent entries)"

        # No activity might be OK if no emails received
        return True, "No recent email filter activity (might be normal)"

    except Exception as e:
        return True, f"Could not check filter status: {e}"


def check_database_connection():
    """Check if database is accessible"""
    try:
        result = subprocess.run(
            ['mysql', '--defaults-file=/opt/spacyserver/config/.my.cnf', '-e', 'SELECT 1;'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            return True, "Database connection OK"
        else:
            return False, f"Database connection failed: {result.stderr}"

    except subprocess.TimeoutExpired:
        return False, "Database connection timed out"
    except Exception as e:
        return False, f"Database error: {e}"


def check_database_auth_errors():
    """
    Check for REAL database problems using precise health check.

    UPDATED: No longer monitors Aborted_clients (normal reconnects).
    Only alerts on actual failures:
    - MySQL service down
    - Cannot connect/ping
    - Cannot execute queries
    - Authentication failures (Aborted_connects)
    - Connection pool maxed out
    """
    try:
        # Run the precise health check script
        result = subprocess.run(
            ['/opt/spacyserver/scripts/check_mysql_health.sh'],
            capture_output=True,
            text=True,
            timeout=10
        )

        # Exit code 0 = healthy, 1 = problem
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            # Health check failed - extract error message
            error_msg = result.stdout.strip()
            return False, error_msg

    except subprocess.TimeoutExpired:
        return False, "Database health check timed out"
    except FileNotFoundError:
        # Fallback if health check script doesn't exist
        return True, "Health check script not found (using basic check)"
    except Exception as e:
        return False, f"Database health check error: {e}"


def check_disk_space():
    """Check disk space on critical partitions"""
    try:
        result = subprocess.run(
            ['df', '-h', '/'],
            capture_output=True,
            text=True,
            timeout=5
        )

        lines = result.stdout.split('\n')
        if len(lines) >= 2:
            # Parse df output
            parts = lines[1].split()
            if len(parts) >= 5:
                usage_str = parts[4].rstrip('%')
                usage = int(usage_str)

                if usage >= DISK_SPACE_THRESHOLD:
                    return False, usage, f"Disk space critical: {usage}% used"
                else:
                    return True, usage, f"Disk space OK: {usage}% used"

        return True, 0, "Disk space check unclear"

    except Exception as e:
        return True, 0, f"Error checking disk space: {e}"


def main():
    """Run all health checks and send alerts if needed"""
    print("=" * 60)
    print(f"System Health Monitor - {datetime.now()}")
    print("=" * 60)

    # Load alert state
    state = load_alert_state()
    alerts_to_send = []

    # Check Postfix
    print("\n1. Checking Postfix status...")
    postfix_ok, postfix_msg = check_postfix_status()
    print(f"   {postfix_msg}")
    if not postfix_ok and should_alert('postfix_down', state):
        alerts_to_send.append(('postfix_down', f"CRITICAL: Postfix mail server is DOWN - {postfix_msg}"))

    # Check mail queue
    print("\n2. Checking mail queue...")
    queue_ok, queue_count, queue_msg = check_mail_queue()
    print(f"   {queue_msg}")
    if not queue_ok and should_alert('mail_queue', state):
        alerts_to_send.append(('mail_queue', f"WARNING: {queue_count} emails stuck in mail queue (threshold: {MAIL_QUEUE_THRESHOLD})"))

    # Check SpacyWeb dashboard (gunicorn)
    print("\n3. Checking SpacyWeb dashboard...")
    spacyweb_ok, spacyweb_msg = check_spacyweb_status()
    print(f"   {spacyweb_msg}")
    if not spacyweb_ok and should_alert('spacyweb_down', state):
        alerts_to_send.append(('spacyweb_down', f"CRITICAL: SpacyWeb dashboard is DOWN - {spacyweb_msg}. Web interface is not accessible!"))

    # Check email filter
    print("\n4. Checking email filter...")
    filter_ok, filter_msg = check_spacy_filter_running()
    print(f"   {filter_msg}")
    # We'll skip alerting on this for now since it might be normal when no mail arrives

    # Check policy server (recipient verification)
    print("\n5. Checking recipient policy server...")
    policy_ok, policy_msg = check_policy_server_status()
    print(f"   {policy_msg}")
    if not policy_ok and should_alert('policy_server_down', state):
        alerts_to_send.append(('policy_server_down', f"CRITICAL: Recipient policy server is DOWN - {policy_msg}. Invalid recipients will NOT be rejected!"))

    # Check database
    print("\n6. Checking database...")
    db_ok, db_msg = check_database_connection()
    print(f"   {db_msg}")
    if not db_ok and should_alert('database_down', state):
        alerts_to_send.append(('database_down', f"CRITICAL: Database connection failed - {db_msg}"))

    # Check database authentication errors in logs
    print("\n7. Checking database authentication...")
    db_auth_ok, db_auth_msg = check_database_auth_errors()
    print(f"   {db_auth_msg}")
    if not db_auth_ok and should_alert('database_auth_errors', state):
        alerts_to_send.append(('database_auth_errors', f"WARNING: {db_auth_msg} - Check application credentials"))

    # Check disk space
    print("\n8. Checking disk space...")
    disk_ok, disk_usage, disk_msg = check_disk_space()
    print(f"   {disk_msg}")
    if not disk_ok and should_alert('disk_space', state):
        alerts_to_send.append(('disk_space', f"CRITICAL: Disk space at {disk_usage}% - Clean up needed"))

    # Send alerts
    if alerts_to_send:
        print(f"\n⚠️  {len(alerts_to_send)} alert(s) to send:")
        service = NotificationService()

        for alert_type, message in alerts_to_send:
            print(f"   - {message}")
            try:
                result = service.send_system_alert(alert_type.upper(), message)
                print(f"     Result: {result}")

                # Update state if sent successfully
                if any(r.get('status') == 'sent' for r in result.values() if isinstance(r, dict)):
                    state[alert_type] = datetime.now()
            except Exception as e:
                print(f"     Error sending alert: {e}")

        # Save updated state
        save_alert_state(state)
    else:
        print("\n✅ All systems healthy - no alerts needed")

    print("\n" + "=" * 60)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
