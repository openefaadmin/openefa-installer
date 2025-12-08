#!/usr/bin/env python3
"""
Daily Security Report Generator
Comprehensive email security statistics and analytics
Can be run manually or via cron for automatic daily emails
"""

import sys
import os
sys.path.insert(0, '/opt/spacyserver/web')
sys.path.insert(0, '/opt/spacyserver')

from datetime import datetime, timedelta
import mysql.connector
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import argparse
import json

# Import existing auth system
from auth import get_db_connection

class SecurityDailyReport:
    def __init__(self, days=1, email_to=None):
        """
        Initialize report generator

        Args:
            days: Number of days to include in report (default: 1 for daily)
            email_to: Email address to send report to (if None, print to stdout)
        """
        self.days = days
        self.email_to = email_to
        self.date_to = datetime.now()
        self.date_from = self.date_to - timedelta(days=days)

    def get_connection(self):
        """Get database connection"""
        return get_db_connection()

    def get_overall_stats(self, conn):
        """Get overall email statistics"""
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT
                COUNT(*) as total_emails,
                SUM(CASE WHEN disposition = 'quarantined' THEN 1 ELSE 0 END) as quarantined,
                SUM(CASE WHEN disposition = 'delivered' THEN 1 ELSE 0 END) as delivered,
                SUM(CASE WHEN disposition = 'deleted' THEN 1 ELSE 0 END) as deleted,
                ROUND(AVG(spam_score), 2) as avg_spam_score,
                ROUND(MAX(spam_score), 2) as max_spam_score,
                ROUND(MIN(spam_score), 2) as min_spam_score
            FROM email_analysis
            WHERE timestamp >= %s AND timestamp <= %s
        """
        cursor.execute(query, (self.date_from, self.date_to))
        return cursor.fetchone()

    def get_organization_breakdown(self, conn):
        """Get per-organization statistics"""
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT
                'All Domains' as organization,
                COUNT(*) as total_emails,
                SUM(CASE WHEN disposition = 'quarantined' THEN 1 ELSE 0 END) as quarantined,
                SUM(CASE WHEN disposition = 'delivered' THEN 1 ELSE 0 END) as delivered,
                ROUND(100.0 * SUM(CASE WHEN disposition = 'quarantined' THEN 1 ELSE 0 END) / COUNT(*), 2) as quarantine_rate,
                ROUND(AVG(spam_score), 2) as avg_spam_score
            FROM email_analysis
            WHERE timestamp >= %s AND timestamp <= %s
            GROUP BY organization
            ORDER BY total_emails DESC
        """
        cursor.execute(query, (self.date_from, self.date_to))
        return cursor.fetchall()

    def get_quarantine_breakdown(self, conn):
        """Get quarantine reasons breakdown"""
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT
                quarantine_reason,
                COUNT(*) as count,
                ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM email_quarantine
                                          WHERE timestamp >= %s AND timestamp <= %s), 2) as percentage
            FROM email_quarantine
            WHERE timestamp >= %s AND timestamp <= %s
            GROUP BY quarantine_reason
            ORDER BY count DESC
            LIMIT 10
        """
        cursor.execute(query, (self.date_from, self.date_to, self.date_from, self.date_to))
        return cursor.fetchall()

    def get_false_positive_rate(self, conn):
        """Get false positive analysis (quarantined then released)"""
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT
                COUNT(*) as total_quarantined,
                SUM(CASE WHEN quarantine_status = 'released' THEN 1 ELSE 0 END) as released,
                ROUND(100.0 * SUM(CASE WHEN quarantine_status = 'released' THEN 1 ELSE 0 END) / COUNT(*), 2) as release_rate
            FROM email_quarantine
            WHERE timestamp >= %s AND timestamp <= %s
        """
        cursor.execute(query, (self.date_from, self.date_to))
        return cursor.fetchone()

    def get_module_effectiveness(self, conn):
        """Get module contribution to spam detection"""
        cursor = conn.cursor(dictionary=True)

        # This is a simplified version - you could enhance this by parsing modules_run JSON
        query = """
            SELECT
                'Header Forgery' as module_name,
                COUNT(*) as emails_flagged,
                ROUND(AVG(spam_score), 2) as avg_contribution
            FROM email_analysis
            WHERE timestamp >= %s AND timestamp <= %s
                AND modules_run LIKE CONCAT('%%', 'header_forgery_detector', '%%')
                AND spam_score > 0

            UNION ALL

            SELECT
                'Attachment Inspector' as module_name,
                COUNT(*) as emails_flagged,
                ROUND(AVG(spam_score), 2) as avg_contribution
            FROM email_analysis
            WHERE timestamp >= %s AND timestamp <= %s
                AND modules_run LIKE CONCAT('%%', 'attachment_inspector', '%%')
                AND spam_score > 5

            UNION ALL

            SELECT
                'Authentication (SPF/DKIM/DMARC)' as module_name,
                COUNT(*) as emails_flagged,
                ROUND(AVG(spam_score), 2) as avg_contribution
            FROM email_analysis
            WHERE timestamp >= %s AND timestamp <= %s
                AND (original_spf != 'pass' OR original_dkim != 'pass' OR original_dmarc != 'pass')

            ORDER BY emails_flagged DESC
        """
        cursor.execute(query, (self.date_from, self.date_to,
                              self.date_from, self.date_to,
                              self.date_from, self.date_to))
        return cursor.fetchall()

    def get_top_threats(self, conn):
        """Get top spam/threat sources"""
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT
                sender,
                subject,
                spam_score,
                quarantine_reason,
                timestamp
            FROM email_analysis
            WHERE timestamp >= %s AND timestamp <= %s
                AND disposition = 'quarantined'
            ORDER BY spam_score DESC
            LIMIT 10
        """
        cursor.execute(query, (self.date_from, self.date_to))
        return cursor.fetchall()

    def get_header_forgery_stats(self, conn):
        """Get specific stats for header forgery detection"""
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT
                COUNT(*) as total_checked,
                SUM(CASE WHEN modules_run LIKE CONCAT('%%', 'header_forgery_detector', '%%')
                    AND spam_score > 0 THEN 1 ELSE 0 END) as forgery_detected,
                ROUND(100.0 * SUM(CASE WHEN modules_run LIKE CONCAT('%%', 'header_forgery_detector', '%%')
                    AND spam_score > 0 THEN 1 ELSE 0 END) / COUNT(*), 2) as detection_rate
            FROM email_analysis
            WHERE timestamp >= %s AND timestamp <= %s
                AND modules_run LIKE CONCAT('%%', 'header_forgery_detector', '%%')
        """
        cursor.execute(query, (self.date_from, self.date_to))
        return cursor.fetchone()

    def generate_text_report(self, stats):
        """Generate formatted text report"""
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("EMAIL SECURITY DAILY REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Report Period: {self.date_from.strftime('%Y-%m-%d %H:%M')} to {self.date_to.strftime('%Y-%m-%d %H:%M')}")
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("=" * 80)
        report_lines.append("")

        # Overall Statistics
        report_lines.append("OVERALL EMAIL STATISTICS")
        report_lines.append("-" * 80)
        overall = stats['overall']
        total_emails = int(overall['total_emails'] or 0)
        delivered = int(overall['delivered'] or 0)
        quarantined = int(overall['quarantined'] or 0)
        deleted = int(overall['deleted'] or 0)

        report_lines.append(f"Total Emails Processed:  {total_emails:,}")
        report_lines.append(f"  ✅ Delivered:           {delivered:,} ({100.0 * delivered / max(total_emails, 1):.1f}%)")
        report_lines.append(f"  ⚠️  Quarantined:         {quarantined:,} ({100.0 * quarantined / max(total_emails, 1):.1f}%)")
        report_lines.append(f"  🗑️  Deleted:             {deleted:,} ({100.0 * deleted / max(total_emails, 1):.1f}%)")
        report_lines.append(f"Average Spam Score:      {float(overall['avg_spam_score'] or 0):.2f}")
        report_lines.append(f"Spam Score Range:        {float(overall['min_spam_score'] or 0):.1f} to {float(overall['max_spam_score'] or 0):.1f}")
        report_lines.append("")

        # Organization Breakdown
        report_lines.append("PER-ORGANIZATION BREAKDOWN")
        report_lines.append("-" * 80)
        report_lines.append(f"{'Organization':<25} {'Emails':<10} {'Quarantined':<12} {'Rate':<8} {'Avg Score':<10}")
        report_lines.append("-" * 80)
        for org in stats['organizations']:
            report_lines.append(
                f"{org['organization']:<25} "
                f"{int(org['total_emails'] or 0):<10,} "
                f"{int(org['quarantined'] or 0):<12,} "
                f"{float(org['quarantine_rate'] or 0):<7.1f}% "
                f"{float(org['avg_spam_score'] or 0):<10.2f}"
            )
        report_lines.append("")

        # Quarantine Reasons
        report_lines.append("TOP QUARANTINE REASONS")
        report_lines.append("-" * 80)
        report_lines.append(f"{'Reason':<40} {'Count':<10} {'Percentage':<10}")
        report_lines.append("-" * 80)
        for reason in stats['quarantine_reasons']:
            report_lines.append(
                f"{reason['quarantine_reason']:<40} "
                f"{int(reason['count'] or 0):<10,} "
                f"{float(reason['percentage'] or 0):<9.1f}%"
            )
        report_lines.append("")

        # False Positive Rate
        report_lines.append("FALSE POSITIVE ANALYSIS")
        report_lines.append("-" * 80)
        fp = stats['false_positive']
        if fp and int(fp['total_quarantined'] or 0) > 0:
            total_q = int(fp['total_quarantined'] or 0)
            released = int(fp['released'] or 0)
            release_rate = float(fp['release_rate'] or 0)
            report_lines.append(f"Total Quarantined:       {total_q:,}")
            report_lines.append(f"Manually Released:       {released:,}")
            report_lines.append(f"False Positive Rate:     {release_rate:.2f}%")
            if release_rate > 10:
                report_lines.append("⚠️  WARNING: High false positive rate detected!")
        else:
            report_lines.append("No quarantine releases in this period")
        report_lines.append("")

        # Module Effectiveness
        report_lines.append("MODULE EFFECTIVENESS")
        report_lines.append("-" * 80)
        report_lines.append(f"{'Module':<40} {'Flagged':<10} {'Avg Score':<10}")
        report_lines.append("-" * 80)
        for module in stats['modules']:
            report_lines.append(
                f"{module['module_name']:<40} "
                f"{int(module['emails_flagged'] or 0):<10,} "
                f"{float(module['avg_contribution'] or 0):<10.2f}"
            )
        report_lines.append("")

        # Header Forgery Stats (if available)
        if stats.get('header_forgery'):
            hf = stats['header_forgery']
            if hf and int(hf['total_checked'] or 0) > 0:
                report_lines.append("HEADER FORGERY DETECTION (NEW MODULE)")
                report_lines.append("-" * 80)
                report_lines.append(f"Emails Checked:          {int(hf['total_checked'] or 0):,}")
                report_lines.append(f"Forgeries Detected:      {int(hf['forgery_detected'] or 0):,}")
                report_lines.append(f"Detection Rate:          {float(hf['detection_rate'] or 0):.2f}%")
                report_lines.append("")

        # Top Threats
        report_lines.append("TOP 10 THREATS (Highest Spam Scores)")
        report_lines.append("-" * 80)
        report_lines.append(f"{'Score':<8} {'Sender':<30} {'Reason':<25} {'Date':<20}")
        report_lines.append("-" * 80)
        for threat in stats['top_threats'][:10]:
            report_lines.append(
                f"{float(threat['spam_score'] or 0):<8.1f} "
                f"{threat['sender'][:28]:<30} "
                f"{threat['quarantine_reason'][:23]:<25} "
                f"{threat['timestamp'].strftime('%Y-%m-%d %H:%M'):<20}"
            )
        report_lines.append("")

        # Recommendations
        report_lines.append("RECOMMENDATIONS")
        report_lines.append("-" * 80)
        recommendations = []

        # Check for high false positive rate
        if fp and float(fp.get('release_rate', 0) or 0) > 10:
            release_rate = float(fp['release_rate'] or 0)
            recommendations.append(f"⚠️  High false positive rate ({release_rate:.1f}%) - Consider tuning spam thresholds")

        # Check for high quarantine rate per org
        for org in stats['organizations']:
            qrate = float(org.get('quarantine_rate', 0) or 0)
            if qrate > 50:
                recommendations.append(
                    f"⚠️  {org['organization']}: Very high quarantine rate ({qrate:.1f}%) - "
                    "Consider per-organization score adjustments"
                )

        # Check for header forgery effectiveness
        if stats.get('header_forgery') and int(stats['header_forgery'].get('forgery_detected', 0) or 0) > 0:
            forgery_count = int(stats['header_forgery']['forgery_detected'] or 0)
            recommendations.append(
                f"✅ Header Forgery Detector catching {forgery_count} attacks - "
                "Monitor for false positives over next 30 days"
            )

        if recommendations:
            for rec in recommendations:
                report_lines.append(rec)
        else:
            report_lines.append("✅ No critical issues detected. System performing normally.")

        report_lines.append("")
        report_lines.append("=" * 80)
        report_lines.append("End of Report")
        report_lines.append("=" * 80)

        return "\n".join(report_lines)

    def send_email_report(self, report_text):
        """Send report via email"""
        if not self.email_to:
            print(report_text)
            return

        try:
            msg = MIMEMultipart()
            msg['From'] = f"security-reports@{os.getenv('MAIL_DOMAIN', 'localhost')}"
            msg['To'] = self.email_to
            msg['Subject'] = f'Daily Email Security Report - {self.date_to.strftime("%Y-%m-%d")}'

            # Add body
            body = f"""Daily Email Security Report

This is your automated daily security report for the OpenEFA email security system.

Period: {self.date_from.strftime('%Y-%m-%d %H:%M')} to {self.date_to.strftime('%Y-%m-%d %H:%M')}

See attached detailed report.

---
This is an automated report from OpenEFA Spacy Email Filter
Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
            msg.attach(MIMEText(body, 'plain'))

            # Attach detailed report
            attachment = MIMEText(report_text, 'plain')
            attachment.add_header('Content-Disposition', 'attachment',
                                filename=f'security_report_{self.date_to.strftime("%Y%m%d")}.txt')
            msg.attach(attachment)

            # Send via local SMTP
            with smtplib.SMTP('localhost', 25) as server:
                server.send_message(msg)

            print(f"✅ Report emailed to {self.email_to}")

        except Exception as e:
            print(f"❌ Error sending email: {e}")
            print("\nReport content:")
            print(report_text)

    def generate_and_send(self):
        """Main method to generate and send report"""
        try:
            conn = self.get_connection()

            # Gather all statistics
            stats = {
                'overall': self.get_overall_stats(conn),
                'organizations': self.get_organization_breakdown(conn),
                'quarantine_reasons': self.get_quarantine_breakdown(conn),
                'false_positive': self.get_false_positive_rate(conn),
                'modules': self.get_module_effectiveness(conn),
                'header_forgery': self.get_header_forgery_stats(conn),
                'top_threats': self.get_top_threats(conn)
            }

            conn.close()

            # Generate report
            report_text = self.generate_text_report(stats)

            # Send or print
            self.send_email_report(report_text)

            return True

        except Exception as e:
            print(f"❌ Error generating report: {e}")
            import traceback
            traceback.print_exc()
            return False


def main():
    parser = argparse.ArgumentParser(description='Generate daily email security report')
    parser.add_argument('--days', type=int, default=1, help='Number of days to include (default: 1)')
    parser.add_argument('--email', type=str, help='Email address to send report to (if not specified, prints to stdout)')
    parser.add_argument('--weekly', action='store_true', help='Generate weekly report (7 days)')
    parser.add_argument('--monthly', action='store_true', help='Generate monthly report (30 days)')

    args = parser.parse_args()

    # Determine days
    if args.weekly:
        days = 7
    elif args.monthly:
        days = 30
    else:
        days = args.days

    # Generate report
    reporter = SecurityDailyReport(days=days, email_to=args.email)
    success = reporter.generate_and_send()

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
