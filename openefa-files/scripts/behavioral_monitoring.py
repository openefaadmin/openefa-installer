#!/usr/bin/env python3
"""
Behavioral Anomaly Monitoring Dashboard
Provides insights into sender behavior patterns and detected anomalies
"""

import pymysql
import json
from datetime import datetime, timedelta
from tabulate import tabulate


def get_db_connection():
    """Get database connection"""
    with open('/opt/spacyserver/config/.my.cnf', 'r') as f:
        lines = f.readlines()
        config = {}
        for line in lines:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                config[key] = value.strip('"')

    return pymysql.connect(
        host='localhost',
        user=config.get('user', 'spacy_user'),
        password=config.get('password', ''),
        database=os.getenv('DB_NAME', 'spacy_email_db')
    )


def get_anomaly_summary():
    """Get summary of recent anomalies"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Last 24 hours anomalies
    cursor.execute("""
        SELECT
            anomaly_type,
            anomaly_severity,
            COUNT(*) as count,
            AVG(anomaly_score) as avg_score
        FROM behavioral_anomalies
        WHERE anomaly_timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        GROUP BY anomaly_type, anomaly_severity
        ORDER BY count DESC
    """)

    print("\n📊 BEHAVIORAL ANOMALIES - LAST 24 HOURS")
    print("=" * 60)

    headers = ['Type', 'Severity', 'Count', 'Avg Score']
    rows = []
    for row in cursor.fetchall():
        rows.append([row[0], row[1], row[2], f"{row[3]:.1f}"])

    if rows:
        print(tabulate(rows, headers=headers, tablefmt='grid'))
    else:
        print("No anomalies detected in the last 24 hours")

    cursor.close()
    conn.close()


def get_compromised_accounts():
    """Get potentially compromised accounts"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            ci.sender_email,
            ci.total_indicators,
            ci.risk_score,
            ci.indicator_timestamp,
            ci.sudden_volume_spike,
            ci.unusual_send_time,
            ci.new_recipient_pattern,
            ci.suspicious_content_change
        FROM compromise_indicators ci
        WHERE ci.requires_review = 1
        ORDER BY ci.risk_score DESC, ci.indicator_timestamp DESC
        LIMIT 10
    """)

    print("\n⚠️  POTENTIAL ACCOUNT COMPROMISES")
    print("=" * 60)

    rows = cursor.fetchall()
    if rows:
        for row in rows:
            print(f"\n📧 {row[0]}")
            print(f"   Risk Score: {row[2]:.1f}")
            print(f"   Time: {row[3]}")
            print(f"   Indicators ({row[1]} total):")
            if row[4]: print("     • Sudden volume spike")
            if row[5]: print("     • Unusual send time")
            if row[6]: print("     • New recipient pattern")
            if row[7]: print("     • Suspicious content change")
    else:
        print("No accounts flagged for compromise review")

    cursor.close()
    conn.close()


def get_sender_baselines():
    """Get sender baseline statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            COUNT(*) as total_senders,
            AVG(learning_confidence) as avg_confidence,
            SUM(CASE WHEN learning_confidence >= 0.8 THEN 1 ELSE 0 END) as established,
            SUM(CASE WHEN learning_confidence >= 0.5 AND learning_confidence < 0.8 THEN 1 ELSE 0 END) as learning,
            SUM(CASE WHEN learning_confidence < 0.5 THEN 1 ELSE 0 END) as insufficient,
            AVG(total_emails_analyzed) as avg_emails,
            AVG(consistency_score) as avg_consistency
        FROM sender_behavior_baseline
    """)

    row = cursor.fetchone()

    print("\n📈 BEHAVIORAL BASELINE STATUS")
    print("=" * 60)

    if row and row[0] > 0:
        print(f"Total Senders Tracked: {row[0]}")
        print(f"Average Confidence: {row[1]*100:.1f}%")
        print(f"Average Emails Analyzed: {row[5]:.0f}")
        print(f"Average Consistency Score: {row[6]*100:.1f}%")
        print("\nBaseline Quality:")
        print(f"  🟢 Established: {row[2]} senders ({row[2]/row[0]*100:.1f}%)")
        print(f"  🟡 Learning: {row[3]} senders ({row[3]/row[0]*100:.1f}%)")
        print(f"  🔴 Insufficient Data: {row[4]} senders ({row[4]/row[0]*100:.1f}%)")
    else:
        print("No baseline data available yet")

    cursor.close()
    conn.close()


def get_top_anomalous_senders():
    """Get senders with most anomalies"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            sbb.sender_email,
            sbb.anomaly_count,
            sbb.last_anomaly_date,
            sbb.learning_confidence,
            COUNT(ba.id) as recent_anomalies
        FROM sender_behavior_baseline sbb
        LEFT JOIN behavioral_anomalies ba ON
            sbb.sender_email = ba.sender_email AND
            ba.anomaly_timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        WHERE sbb.anomaly_count > 0
        GROUP BY sbb.sender_email, sbb.anomaly_count, sbb.last_anomaly_date, sbb.learning_confidence
        ORDER BY recent_anomalies DESC, sbb.anomaly_count DESC
        LIMIT 10
    """)

    print("\n🚨 TOP ANOMALOUS SENDERS")
    print("=" * 60)

    headers = ['Sender', 'Total', '7-Day', 'Last Anomaly', 'Confidence']
    rows = []
    for row in cursor.fetchall():
        rows.append([
            row[0][:40] + '...' if len(row[0]) > 40 else row[0],
            row[1],
            row[4],
            row[2].strftime('%m/%d %H:%M') if row[2] else 'N/A',
            f"{row[3]*100:.0f}%"
        ])

    if rows:
        print(tabulate(rows, headers=headers, tablefmt='grid'))
    else:
        print("No anomalous senders detected")

    cursor.close()
    conn.close()


def get_hourly_patterns():
    """Show hourly sending patterns"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get today's hourly pattern
    cursor.execute("""
        SELECT
            SUM(hour_0) as h0, SUM(hour_1) as h1, SUM(hour_2) as h2, SUM(hour_3) as h3,
            SUM(hour_4) as h4, SUM(hour_5) as h5, SUM(hour_6) as h6, SUM(hour_7) as h7,
            SUM(hour_8) as h8, SUM(hour_9) as h9, SUM(hour_10) as h10, SUM(hour_11) as h11,
            SUM(hour_12) as h12, SUM(hour_13) as h13, SUM(hour_14) as h14, SUM(hour_15) as h15,
            SUM(hour_16) as h16, SUM(hour_17) as h17, SUM(hour_18) as h18, SUM(hour_19) as h19,
            SUM(hour_20) as h20, SUM(hour_21) as h21, SUM(hour_22) as h22, SUM(hour_23) as h23
        FROM sending_patterns
        WHERE pattern_date = CURDATE()
    """)

    row = cursor.fetchone()

    print("\n⏰ TODAY'S HOURLY SENDING PATTERN")
    print("=" * 60)

    if row and any(row):
        hours = []
        values = []
        max_val = max([v for v in row if v])

        for hour in range(24):
            val = row[hour] or 0
            hours.append(f"{hour:02d}")
            # Create bar chart
            bar_len = int(val / max_val * 20) if max_val > 0 else 0
            values.append(f"{'█' * bar_len} {val}")

        # Display in 4 rows of 6 hours each
        for start in [0, 6, 12, 18]:
            print(f"Hours {start:02d}-{start+5:02d}: ", end="")
            for i in range(start, start + 6):
                if i < 24:
                    val = row[i] or 0
                    print(f"{hours[i]}:{val:3.0f} ", end="")
            print()
    else:
        print("No sending data for today yet")

    cursor.close()
    conn.close()


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("    SPACY BEHAVIORAL ANOMALY MONITORING DASHBOARD")
    print("=" * 60)

    get_anomaly_summary()
    get_compromised_accounts()
    get_sender_baselines()
    get_top_anomalous_senders()
    get_hourly_patterns()

    print("\n" + "=" * 60)
    print("Dashboard generated at:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 60)