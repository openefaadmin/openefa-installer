#!/usr/bin/env python3
"""
Server Activity Report Generator
Generates comprehensive reports on user activity and system operations
"""

from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from io import BytesIO
import tempfile
from reportlab.platypus import Image

class ActivityReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()

    def setup_custom_styles(self):
        """Setup custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        ))

        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            textColor=colors.darkblue
        ))

        self.styles.add(ParagraphStyle(
            name='Highlight',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.red,
            fontName='Helvetica-Bold'
        ))

    def get_db_connection(self):
        """Get MySQL connection - using system's auth module"""
        # Import from the parent directory's auth module
        import sys
        import os
        sys.path.insert(0, os.path.dirname(__file__))
        from auth import get_db_connection as get_system_db_connection
        return get_system_db_connection()

    def get_fail2ban_stats(self):
        """Get fail2ban statistics for all jails"""
        import subprocess
        import re

        stats = {
            'service_active': False,
            'jails': []
        }

        try:
            # Check if fail2ban is active
            result = subprocess.run(['systemctl', 'is-active', 'fail2ban'],
                                  capture_output=True, text=True, timeout=5)
            stats['service_active'] = (result.stdout.strip() == 'active')

            if not stats['service_active']:
                return stats

            # Get list of jails
            result = subprocess.run(['fail2ban-client', 'status'],
                                  capture_output=True, text=True, timeout=5)

            # Parse jail list from output like "Jail list:	spacyweb, sshd"
            jail_match = re.search(r'Jail list:\s+(.+)', result.stdout)
            if not jail_match:
                return stats

            jail_names = [j.strip() for j in jail_match.group(1).split(',')]

            # Get stats for each jail
            for jail_name in jail_names:
                try:
                    result = subprocess.run(['fail2ban-client', 'status', jail_name],
                                          capture_output=True, text=True, timeout=5)

                    jail_info = {
                        'name': jail_name,
                        'currently_failed': 0,
                        'total_failed': 0,
                        'currently_banned': 0,
                        'total_banned': 0,
                        'banned_ips': []
                    }

                    # Parse the status output
                    for line in result.stdout.split('\n'):
                        if 'Currently failed:' in line:
                            match = re.search(r'Currently failed:\s+(\d+)', line)
                            if match:
                                jail_info['currently_failed'] = int(match.group(1))
                        elif 'Total failed:' in line:
                            match = re.search(r'Total failed:\s+(\d+)', line)
                            if match:
                                jail_info['total_failed'] = int(match.group(1))
                        elif 'Currently banned:' in line:
                            match = re.search(r'Currently banned:\s+(\d+)', line)
                            if match:
                                jail_info['currently_banned'] = int(match.group(1))
                        elif 'Total banned:' in line:
                            match = re.search(r'Total banned:\s+(\d+)', line)
                            if match:
                                jail_info['total_banned'] = int(match.group(1))
                        elif 'Banned IP list:' in line:
                            # The banned IPs appear after this line
                            ip_line = line.split('Banned IP list:')[-1].strip()
                            if ip_line:
                                jail_info['banned_ips'] = [ip.strip() for ip in ip_line.split()]

                    stats['jails'].append(jail_info)

                except Exception as e:
                    # If we can't get stats for a specific jail, skip it
                    continue

            return stats

        except Exception as e:
            # If fail2ban is not available, return empty stats
            return stats

    def fetch_activity_data(self, date_from, date_to):
        """Fetch user activity data from audit log"""
        conn = self.get_db_connection()
        cursor = conn.cursor(dictionary=True)

        data = {}

        # Total activity count
        cursor.execute("""
            SELECT COUNT(*) as total
            FROM audit_log
            WHERE DATE(created_at) BETWEEN %s AND %s
        """, (date_from, date_to))
        data['total_activities'] = cursor.fetchone()['total']

        # Activity by action type
        cursor.execute("""
            SELECT action, COUNT(*) as count
            FROM audit_log
            WHERE DATE(created_at) BETWEEN %s AND %s
            GROUP BY action
            ORDER BY count DESC
        """, (date_from, date_to))
        data['activity_by_type'] = cursor.fetchall()

        # Activity by user
        cursor.execute("""
            SELECT u.email, u.role, COUNT(a.id) as activity_count,
                   MAX(a.created_at) as last_activity
            FROM audit_log a
            JOIN users u ON a.user_id = u.id
            WHERE DATE(a.created_at) BETWEEN %s AND %s
            GROUP BY u.id, u.email, u.role
            ORDER BY activity_count DESC
        """, (date_from, date_to))
        data['activity_by_user'] = cursor.fetchall()

        # Active users per day
        cursor.execute("""
            SELECT DATE(created_at) as activity_date,
                   COUNT(DISTINCT user_id) as active_users
            FROM audit_log
            WHERE DATE(created_at) BETWEEN %s AND %s
            GROUP BY DATE(created_at)
            ORDER BY activity_date
        """, (date_from, date_to))
        data['active_users_by_day'] = cursor.fetchall()

        # Failed logins
        cursor.execute("""
            SELECT u.email, a.details, a.ip_address, a.created_at
            FROM audit_log a
            LEFT JOIN users u ON a.user_id = u.id
            WHERE DATE(a.created_at) BETWEEN %s AND %s
            AND a.action = 'LOGIN_FAILED'
            ORDER BY a.created_at DESC
            LIMIT 50
        """, (date_from, date_to))
        data['failed_logins'] = cursor.fetchall()

        # Successful logins
        cursor.execute("""
            SELECT u.email, u.role, a.ip_address, a.created_at
            FROM audit_log a
            JOIN users u ON a.user_id = u.id
            WHERE DATE(a.created_at) BETWEEN %s AND %s
            AND a.action = 'LOGIN_SUCCESS'
            ORDER BY a.created_at DESC
            LIMIT 100
        """, (date_from, date_to))
        data['successful_logins'] = cursor.fetchall()

        # Admin actions
        cursor.execute("""
            SELECT u.email, a.action, a.details, a.created_at
            FROM audit_log a
            JOIN users u ON a.user_id = u.id
            WHERE DATE(a.created_at) BETWEEN %s AND %s
            AND a.action IN ('USER_CREATED_BY_ADMIN', 'USER_UPDATED_BY_ADMIN',
                             'USER_DEACTIVATED', 'USER_ACTIVATED',
                             'PASSWORD_RESET_BY_ADMIN')
            ORDER BY a.created_at DESC
            LIMIT 50
        """, (date_from, date_to))
        data['admin_actions'] = cursor.fetchall()

        # System operations
        cursor.execute("""
            SELECT u.email, a.action, a.details, a.created_at
            FROM audit_log a
            LEFT JOIN users u ON a.user_id = u.id
            WHERE DATE(a.created_at) BETWEEN %s AND %s
            AND a.action IN ('FULL_SYSTEM_BACKUP_CREATED', 'DATABASE_BACKUP_CREATED',
                             'CLEANUP_MANUAL_RUN', 'CLEANUP_AUTO_RUN',
                             'REPORT_GENERATED')
            ORDER BY a.created_at DESC
            LIMIT 50
        """, (date_from, date_to))
        data['system_operations'] = cursor.fetchall()

        # Login activity by hour
        cursor.execute("""
            SELECT HOUR(created_at) as hour, COUNT(*) as count
            FROM audit_log
            WHERE DATE(created_at) BETWEEN %s AND %s
            AND action = 'LOGIN_SUCCESS'
            GROUP BY HOUR(created_at)
            ORDER BY hour
        """, (date_from, date_to))
        data['logins_by_hour'] = cursor.fetchall()

        # Recipient Verification stats
        try:
            # Total rejections in date range
            cursor.execute("""
                SELECT COUNT(*) as total
                FROM recipient_rejections
                WHERE DATE(timestamp) BETWEEN %s AND %s
            """, (date_from, date_to))
            data['recipient_verification_total'] = cursor.fetchone()['total']

            # Rejections by domain
            cursor.execute("""
                SELECT domain, COUNT(*) as count
                FROM recipient_rejections
                WHERE DATE(timestamp) BETWEEN %s AND %s
                GROUP BY domain
                ORDER BY count DESC
            """, (date_from, date_to))
            data['recipient_verification_by_domain'] = cursor.fetchall()

            # Recent rejections
            cursor.execute("""
                SELECT timestamp, sender, recipient, domain, smtp_code, smtp_message
                FROM recipient_rejections
                WHERE DATE(timestamp) BETWEEN %s AND %s
                ORDER BY timestamp DESC
                LIMIT 50
            """, (date_from, date_to))
            data['recipient_verification_recent'] = cursor.fetchall()

            # Top rejected recipients
            cursor.execute("""
                SELECT recipient, domain, COUNT(*) as count
                FROM recipient_rejections
                WHERE DATE(timestamp) BETWEEN %s AND %s
                GROUP BY recipient, domain
                ORDER BY count DESC
                LIMIT 20
            """, (date_from, date_to))
            data['recipient_verification_top_recipients'] = cursor.fetchall()

            # Domains with verification enabled
            cursor.execute("""
                SELECT domain, recipient_verification_mode, recipient_verification_status,
                       relay_host, relay_port
                FROM client_domains
                WHERE active = 1 AND recipient_verification_status = 'supported'
                ORDER BY domain
            """)
            data['recipient_verification_domains'] = cursor.fetchall()

            # Policy server status
            import subprocess
            try:
                result = subprocess.run(['systemctl', 'is-active', 'openefa-policy'],
                                      capture_output=True, text=True, timeout=5)
                data['recipient_verification_policy_status'] = result.stdout.strip()
            except:
                data['recipient_verification_policy_status'] = 'unknown'

        except Exception as e:
            # If recipient verification tables don't exist, set empty data
            data['recipient_verification_total'] = 0
            data['recipient_verification_by_domain'] = []
            data['recipient_verification_recent'] = []
            data['recipient_verification_top_recipients'] = []
            data['recipient_verification_domains'] = []
            data['recipient_verification_policy_status'] = 'not configured'

        # Fail2ban statistics
        try:
            data['fail2ban_stats'] = self.get_fail2ban_stats()
        except Exception as e:
            data['fail2ban_stats'] = {
                'service_active': False,
                'jails': []
            }

        cursor.close()
        conn.close()

        return data

    def create_chart(self, data, chart_type='bar', title='', xlabel='', ylabel=''):
        """Create a matplotlib chart and return as Image object"""
        fig, ax = plt.subplots(figsize=(8, 4))

        if chart_type == 'bar':
            ax.bar(range(len(data['x'])), data['y'], color='steelblue')
            ax.set_xticks(range(len(data['x'])))
            ax.set_xticklabels(data['x'], rotation=45, ha='right')
        elif chart_type == 'line':
            ax.plot(data['x'], data['y'], marker='o', color='steelblue', linewidth=2)
            plt.xticks(rotation=45, ha='right')

        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
        ax.grid(axis='y', alpha=0.3)

        plt.tight_layout()

        # Save to BytesIO
        img_buffer = BytesIO()
        plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight')
        img_buffer.seek(0)
        plt.close()

        # Create ReportLab Image
        img = Image(img_buffer, width=6*inch, height=3*inch)
        return img

    def generate_activity_report(self, date_from, date_to, output_path, user_info):
        """Generate the activity report PDF"""
        try:
            # Fetch all data
            data = self.fetch_activity_data(date_from, date_to)

            # Create PDF
            doc = SimpleDocTemplate(output_path, pagesize=letter,
                                   topMargin=0.75*inch, bottomMargin=0.75*inch)
            story = []

            # OpenEFA Branding Header
            branding_style = ParagraphStyle(
                name='Branding',
                parent=self.styles['Normal'],
                fontSize=28,
                textColor=colors.HexColor('#1e3a8a'),  # Dark blue
                fontName='Helvetica-Bold',
                alignment=TA_CENTER,
                spaceAfter=30  # Increased spacing to prevent overlap
            )
            tagline_style = ParagraphStyle(
                name='Tagline',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#64748b'),  # Slate gray
                alignment=TA_CENTER,
                spaceAfter=20
            )

            story.append(Paragraph("OpenEFA", branding_style))
            story.append(Paragraph("Open Email Filtering Appliance", tagline_style))

            # Separator line
            from reportlab.platypus import HRFlowable
            story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#1e3a8a'),
                                   spaceAfter=20, spaceBefore=10))

            # Title
            title = Paragraph(f"Server Activity Report", self.styles['CustomTitle'])
            story.append(title)
            story.append(Spacer(1, 0.2*inch))

            # Report metadata
            date_range = f"{date_from} to {date_to}"
            metadata = f"<b>Report Period:</b> {date_range}<br/>"
            metadata += f"<b>Generated By:</b> {user_info['name']} ({user_info['email']})<br/>"
            metadata += f"<b>Generated On:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>"
            story.append(Paragraph(metadata, self.styles['Normal']))
            story.append(Spacer(1, 0.3*inch))

            # Executive Summary
            story.append(Paragraph("Executive Summary", self.styles['CustomHeading']))
            summary = f"Total Activities: <b>{data['total_activities']:,}</b><br/>"
            summary += f"Active Users: <b>{len(data['activity_by_user'])}</b><br/>"
            summary += f"Successful Logins: <b>{len(data['successful_logins'])}</b><br/>"
            summary += f"Failed Login Attempts: <b>{len(data['failed_logins'])}</b><br/>"
            summary += f"Administrative Actions: <b>{len(data['admin_actions'])}</b><br/>"
            summary += f"Recipient Rejections: <b>{data['recipient_verification_total']:,}</b><br/>"

            # Fail2ban summary
            if data['fail2ban_stats']['service_active']:
                total_banned_ips = sum(jail['currently_banned'] for jail in data['fail2ban_stats']['jails'])
                total_bans_all_time = sum(jail['total_banned'] for jail in data['fail2ban_stats']['jails'])
                summary += f"Fail2ban: <b>{len(data['fail2ban_stats']['jails'])} jails active</b>, "
                summary += f"<b>{total_banned_ips} currently banned</b>, "
                summary += f"<b>{total_bans_all_time} total bans</b><br/>"
            else:
                summary += f"Fail2ban: <b>Not Active</b><br/>"

            story.append(Paragraph(summary, self.styles['Normal']))
            story.append(Spacer(1, 0.2*inch))

            # Recipient Verification Section
            if data['recipient_verification_total'] > 0 or data['recipient_verification_domains']:
                story.append(Paragraph("Recipient Verification", self.styles['CustomHeading']))

                # Policy server status
                policy_status_color = 'green' if data['recipient_verification_policy_status'] == 'active' else 'red'
                policy_status_text = data['recipient_verification_policy_status'].upper()

                rv_summary = f"<b>Policy Server Status:</b> <font color='{policy_status_color}'>{policy_status_text}</font><br/>"
                rv_summary += f"<b>Total Rejections:</b> {data['recipient_verification_total']:,}<br/>"
                rv_summary += f"<b>Domains Protected:</b> {len(data['recipient_verification_domains'])}<br/>"
                rv_summary += f"<b>Domains Affected:</b> {len(data['recipient_verification_by_domain'])}<br/>"
                story.append(Paragraph(rv_summary, self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))

                # Protected domains table
                if data['recipient_verification_domains']:
                    story.append(Paragraph("<b>Protected Domains:</b>", self.styles['Normal']))
                    domains_table_data = [['Domain', 'Mode', 'Relay Host', 'Status']]
                    for row in data['recipient_verification_domains']:
                        domains_table_data.append([
                            row['domain'],
                            row['recipient_verification_mode'],
                            f"{row['relay_host']}:{row['relay_port']}",
                            row['recipient_verification_status']
                        ])

                    domains_table = Table(domains_table_data, colWidths=[2.0*inch, 1.0*inch, 1.8*inch, 1.2*inch])
                    domains_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#fbbf24')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('FONTSIZE', (0, 1), (-1, -1), 8),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    story.append(domains_table)
                    story.append(Spacer(1, 0.2*inch))

                # Rejections by domain
                if data['recipient_verification_by_domain']:
                    story.append(Paragraph("<b>Rejections by Domain:</b>", self.styles['Normal']))
                    domain_stats_table_data = [['Domain', 'Rejections']]
                    for row in data['recipient_verification_by_domain'][:10]:
                        domain_stats_table_data.append([
                            row['domain'],
                            str(row['count'])
                        ])

                    domain_stats_table = Table(domain_stats_table_data, colWidths=[4.5*inch, 1.5*inch])
                    domain_stats_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#fbbf24')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('FONTSIZE', (0, 1), (-1, -1), 8),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    story.append(domain_stats_table)
                    story.append(Spacer(1, 0.2*inch))

                # Top rejected recipients
                if data['recipient_verification_top_recipients']:
                    story.append(Paragraph("<b>Most Rejected Recipients:</b>", self.styles['Normal']))
                    top_recipients_table_data = [['Recipient', 'Domain', 'Count']]
                    for row in data['recipient_verification_top_recipients'][:15]:
                        top_recipients_table_data.append([
                            row['recipient'][:40],
                            row['domain'],
                            str(row['count'])
                        ])

                    top_recipients_table = Table(top_recipients_table_data, colWidths=[3.0*inch, 2.0*inch, 1.0*inch])
                    top_recipients_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#fbbf24')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('FONTSIZE', (0, 1), (-1, -1), 8),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    story.append(top_recipients_table)
                    story.append(Spacer(1, 0.2*inch))

                # Recent rejections
                if data['recipient_verification_recent']:
                    story.append(Paragraph("<b>Recent Rejections (Sample):</b>", self.styles['Normal']))
                    recent_table_data = [['Timestamp', 'Sender', 'Recipient', 'Code']]
                    for row in data['recipient_verification_recent'][:20]:
                        recent_table_data.append([
                            row['timestamp'].strftime('%m/%d %H:%M'),
                            row['sender'][:25],
                            row['recipient'][:25],
                            str(row['smtp_code']) if row['smtp_code'] else 'N/A'
                        ])

                    recent_table = Table(recent_table_data, colWidths=[0.9*inch, 2.2*inch, 2.2*inch, 0.7*inch])
                    recent_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#fbbf24')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('FONTSIZE', (0, 1), (-1, -1), 7),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('WORDWRAP', (0, 0), (-1, -1), True)
                    ]))
                    story.append(recent_table)
                    story.append(Spacer(1, 0.2*inch))

            story.append(Spacer(1, 0.1*inch))

            # Fail2ban Section
            if data['fail2ban_stats']['service_active'] and data['fail2ban_stats']['jails']:
                story.append(Paragraph("Fail2ban Intrusion Prevention", self.styles['CustomHeading']))

                # Service status
                service_status_text = "ACTIVE" if data['fail2ban_stats']['service_active'] else "INACTIVE"
                service_status_color = 'green' if data['fail2ban_stats']['service_active'] else 'red'

                total_banned_ips = sum(jail['currently_banned'] for jail in data['fail2ban_stats']['jails'])
                total_bans_all_time = sum(jail['total_banned'] for jail in data['fail2ban_stats']['jails'])
                total_failed_attempts = sum(jail['total_failed'] for jail in data['fail2ban_stats']['jails'])

                f2b_summary = f"<b>Service Status:</b> <font color='{service_status_color}'>{service_status_text}</font><br/>"
                f2b_summary += f"<b>Active Jails:</b> {len(data['fail2ban_stats']['jails'])}<br/>"
                f2b_summary += f"<b>Currently Banned IPs:</b> {total_banned_ips}<br/>"
                f2b_summary += f"<b>Total Bans (All Time):</b> {total_bans_all_time}<br/>"
                f2b_summary += f"<b>Total Failed Attempts (All Time):</b> {total_failed_attempts}<br/>"
                story.append(Paragraph(f2b_summary, self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))

                # Jail statistics table
                story.append(Paragraph("<b>Jail Statistics:</b>", self.styles['Normal']))
                jail_table_data = [['Jail', 'Currently Failed', 'Total Failed', 'Currently Banned', 'Total Banned']]

                for jail in data['fail2ban_stats']['jails']:
                    jail_table_data.append([
                        jail['name'],
                        str(jail['currently_failed']),
                        str(jail['total_failed']),
                        str(jail['currently_banned']),
                        str(jail['total_banned'])
                    ])

                jail_table = Table(jail_table_data, colWidths=[1.8*inch, 1.1*inch, 1.0*inch, 1.2*inch, 1.0*inch])
                jail_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc2626')),  # Red header
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('ALIGN', (1, 0), (-1, -1), 'CENTER'),  # Center numeric columns
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                story.append(jail_table)
                story.append(Spacer(1, 0.2*inch))

                # Currently banned IPs
                all_banned_ips = []
                for jail in data['fail2ban_stats']['jails']:
                    for ip in jail['banned_ips']:
                        all_banned_ips.append({'ip': ip, 'jail': jail['name']})

                if all_banned_ips:
                    story.append(Paragraph("<b>Currently Banned IP Addresses:</b>", self.styles['Highlight']))
                    banned_ip_table_data = [['IP Address', 'Jail', 'Status']]

                    for ban in all_banned_ips[:50]:  # Limit to 50 IPs
                        banned_ip_table_data.append([
                            ban['ip'],
                            ban['jail'],
                            'BANNED'
                        ])

                    banned_ip_table = Table(banned_ip_table_data, colWidths=[2.5*inch, 2.0*inch, 1.5*inch])
                    banned_ip_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc2626')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('FONTSIZE', (0, 1), (-1, -1), 8),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fee2e2')]),  # Light red
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    story.append(banned_ip_table)
                    story.append(Spacer(1, 0.2*inch))
                else:
                    story.append(Paragraph("<i>No IPs currently banned</i>", self.styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))

            story.append(Spacer(1, 0.1*inch))

            # Activity by Type Chart
            if data['activity_by_type']:
                story.append(Paragraph("Activity by Type", self.styles['CustomHeading']))
                chart_data = {
                    'x': [row['action'][:20] for row in data['activity_by_type'][:10]],
                    'y': [row['count'] for row in data['activity_by_type'][:10]]
                }
                chart = self.create_chart(chart_data, 'bar',
                                         'Top 10 Activity Types',
                                         'Action Type', 'Count')
                story.append(chart)
                story.append(Spacer(1, 0.3*inch))

            # Activity by User Table
            if data['activity_by_user']:
                story.append(Paragraph("User Activity", self.styles['CustomHeading']))
                user_table_data = [['User', 'Role', 'Actions', 'Last Activity']]
                for row in data['activity_by_user'][:15]:
                    last_activity = row['last_activity'].strftime('%Y-%m-%d %H:%M') if row['last_activity'] else 'N/A'
                    user_table_data.append([
                        row['email'][:30],
                        row['role'],
                        str(row['activity_count']),
                        last_activity
                    ])

                user_table = Table(user_table_data, colWidths=[2.8*inch, 0.9*inch, 0.7*inch, 1.6*inch])
                user_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('WORDWRAP', (0, 0), (-1, -1), True)
                ]))
                story.append(user_table)
                story.append(Spacer(1, 0.3*inch))

            # New page for detailed logs
            story.append(PageBreak())

            # Successful Logins
            if data['successful_logins']:
                story.append(Paragraph("Successful Logins", self.styles['CustomHeading']))
                story.append(Paragraph(f"Total: {len(data['successful_logins'])}", self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))

                success_table_data = [['User', 'Role', 'IP Address', 'Timestamp']]
                for row in data['successful_logins'][:30]:  # Show top 30
                    success_table_data.append([
                        row['email'][:30],
                        row['role'],
                        row['ip_address'] or 'N/A',
                        row['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                    ])

                success_table = Table(success_table_data, colWidths=[2.5*inch, 0.9*inch, 1.3*inch, 1.5*inch])
                success_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.green),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgreen]),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('WORDWRAP', (0, 0), (-1, -1), True)
                ]))
                story.append(success_table)
                story.append(Spacer(1, 0.3*inch))

            # Failed Logins
            if data['failed_logins']:
                story.append(Paragraph("Failed Login Attempts", self.styles['CustomHeading']))
                story.append(Paragraph(f"Total: {len(data['failed_logins'])}", self.styles['Highlight']))
                story.append(Spacer(1, 0.1*inch))

                failed_table_data = [['Email', 'IP Address', 'Timestamp']]
                for row in data['failed_logins'][:20]:
                    email = row['email'] if row['email'] else 'Unknown'
                    failed_table_data.append([
                        email[:30],
                        row['ip_address'] or 'N/A',
                        row['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                    ])

                failed_table = Table(failed_table_data, colWidths=[2.5*inch, 1.5*inch, 1.8*inch])
                failed_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('WORDWRAP', (0, 0), (-1, -1), True)
                ]))
                story.append(failed_table)
                story.append(Spacer(1, 0.3*inch))

            # Administrative Actions
            if data['admin_actions']:
                story.append(Paragraph("Administrative Actions", self.styles['CustomHeading']))
                admin_table_data = [['Admin', 'Action', 'Details', 'Timestamp']]
                for row in data['admin_actions'][:20]:
                    admin_table_data.append([
                        row['email'][:20],
                        row['action'].replace('_', ' ')[:25],
                        row['details'][:40] if row['details'] else '',
                        row['created_at'].strftime('%m/%d %H:%M')
                    ])

                admin_table = Table(admin_table_data, colWidths=[1.6*inch, 1.4*inch, 2.0*inch, 0.9*inch])
                admin_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('FONTSIZE', (0, 1), (-1, -1), 7),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('WORDWRAP', (0, 0), (-1, -1), True)
                ]))
                story.append(admin_table)
                story.append(Spacer(1, 0.3*inch))

            # System Operations
            if data['system_operations']:
                story.append(Paragraph("System Operations", self.styles['CustomHeading']))
                sys_table_data = [['User', 'Operation', 'Details', 'Timestamp']]
                for row in data['system_operations'][:20]:
                    user = row['email'][:20] if row['email'] else 'System'
                    sys_table_data.append([
                        user,
                        row['action'].replace('_', ' ')[:25],
                        row['details'][:40] if row['details'] else '',
                        row['created_at'].strftime('%m/%d %H:%M')
                    ])

                sys_table = Table(sys_table_data, colWidths=[1.6*inch, 1.4*inch, 2.0*inch, 0.9*inch])
                sys_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.green),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('FONTSIZE', (0, 1), (-1, -1), 7),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('WORDWRAP', (0, 0), (-1, -1), True)
                ]))
                story.append(sys_table)
                story.append(Spacer(1, 0.3*inch))

            # Build PDF
            doc.build(story)
            return True

        except Exception as e:
            print(f"Error generating activity report: {e}")
            import traceback
            traceback.print_exc()
            return False
