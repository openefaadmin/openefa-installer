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

# Add parent directory to path
sys.path.insert(0, '/opt/spacyserver')

from notification_service import NotificationService

# Thresholds
MAIL_QUEUE_THRESHOLD = 10
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
    """Check mail queue size"""
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

        # Look for queue count
        match = re.search(r'(\d+)\s+Request', output, re.IGNORECASE)
        if match:
            queue_count = int(match.group(1))
            if queue_count > MAIL_QUEUE_THRESHOLD:
                return False, queue_count, f"{queue_count} emails stuck in queue"
            else:
                return True, queue_count, f"{queue_count} emails in queue (normal)"

        # If we can't parse, assume OK
        return True, 0, "Mail queue status unclear but likely OK"

    except subprocess.TimeoutExpired:
        return False, -1, "Mail queue check timed out"
    except Exception as e:
        return False, -1, f"Error checking mail queue: {e}"


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
            ['mysql', '-u', 'spacy_user', '-pAdrastosIhadn63r', '-e', 'SELECT 1;'],
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

    # Check email filter
    print("\n3. Checking email filter...")
    filter_ok, filter_msg = check_spacy_filter_running()
    print(f"   {filter_msg}")
    # We'll skip alerting on this for now since it might be normal when no mail arrives

    # Check database
    print("\n4. Checking database...")
    db_ok, db_msg = check_database_connection()
    print(f"   {db_msg}")
    if not db_ok and should_alert('database_down', state):
        alerts_to_send.append(('database_down', f"CRITICAL: Database connection failed - {db_msg}"))

    # Check disk space
    print("\n5. Checking disk space...")
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
