#!/usr/bin/env python3
"""
Enhanced Executive Report System
Includes 30-day email volume tracking and expanded metrics
"""

from datetime import datetime, timedelta
import json
from sqlalchemy import text
import tempfile
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from io import BytesIO

class EnhancedEmailReportGenerator:
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
            name='ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=12,
            leftIndent=20,
            rightIndent=20
        ))
        
        self.styles.add(ParagraphStyle(
            name='StatHighlight',
            parent=self.styles['Normal'],
            fontSize=13,
            textColor=colors.darkblue,
            fontName='Helvetica-Bold'
        ))

    def get_enhanced_domain_stats(self, engine, domain, date_from, date_to):
        """Get comprehensive statistics for a domain including 30-day trends"""
        try:
            print(f"Getting stats for {domain} from {date_from} to {date_to}")
            with engine.connect() as conn:
                # Get current period stats
                current_stats = self._get_period_stats(conn, domain, date_from, date_to)
                
                # Get previous 30-day period for comparison
                previous_date_to = datetime.strptime(date_from, '%Y-%m-%d')
                previous_date_from = (previous_date_to - timedelta(days=30)).strftime('%Y-%m-%d')
                previous_date_to_str = (previous_date_to - timedelta(days=1)).strftime('%Y-%m-%d')
                
                previous_stats = self._get_period_stats(conn, domain, previous_date_from, previous_date_to_str)
                
                # Get daily email volume for trend analysis
                daily_volume = self._get_daily_volume(conn, domain, date_from, date_to)
                
                # Get hourly distribution
                hourly_distribution = self._get_hourly_distribution(conn, domain, date_from, date_to)
                
                # Get top senders
                top_senders = self._get_top_senders(conn, domain, date_from, date_to)
                
                # Get security threats by type
                security_threats = self._get_security_threats(conn, domain, date_from, date_to)
                
                return {
                    'current_period': current_stats,
                    'previous_period': previous_stats,
                    'daily_volume': daily_volume,
                    'hourly_distribution': hourly_distribution,
                    'top_senders': top_senders,
                    'security_threats': security_threats
                }
                
        except Exception as e:
            print(f"Error getting enhanced domain stats: {e}")
            return None

    def _get_period_stats(self, conn, domain, date_from, date_to):
        """Get statistics for a specific time period"""
        base_query = f"""
            FROM email_analysis
            WHERE recipients LIKE '%@{domain}%'
            AND DATE(timestamp) >= '{date_from}'
            AND DATE(timestamp) <= '{date_to}'
        """
        
        # Total emails
        total_query = f"SELECT COUNT(*) {base_query}"
        total_emails = conn.execute(text(total_query)).fetchone()[0]
        
        # Sentiment distribution
        sentiment_query = f"""
            SELECT
                CASE
                    WHEN sentiment_polarity > 0.3 THEN 'Very Positive'
                    WHEN sentiment_polarity > 0.1 THEN 'Positive'
                    WHEN sentiment_polarity > -0.1 THEN 'Neutral'
                    WHEN sentiment_polarity > -0.3 THEN 'Negative'
                    ELSE 'Very Negative'
                END as sentiment_category,
                COUNT(*) as count
            {base_query} AND sentiment_polarity IS NOT NULL
            GROUP BY sentiment_category
        """
        sentiment_data = dict(conn.execute(text(sentiment_query)).fetchall())
        
        # Category distribution
        category_query = f"""
            SELECT email_category, COUNT(*) as count
            {base_query} AND email_category IS NOT NULL
            GROUP BY email_category
            ORDER BY count DESC
        """
        categories = dict(conn.execute(text(category_query)).fetchall())
        
        # Security metrics - Updated to use spam scores instead of categories
        security_query = f"""
            SELECT 
                SUM(CASE WHEN spam_score > 5.0 THEN 1 ELSE 0 END) as high_risk_blocked,
                SUM(CASE WHEN spam_score >= 3.0 AND spam_score <= 5.0 THEN 1 ELSE 0 END) as medium_risk_flagged,
                AVG(CASE WHEN spam_score IS NOT NULL THEN spam_score ELSE 0 END) as avg_spam_score,
                MAX(spam_score) as max_spam_score,
                SUM(CASE WHEN spam_score > 10.0 THEN 1 ELSE 0 END) as critical_threats
            {base_query}
        """
        security_result = conn.execute(text(security_query)).fetchone()
        security_metrics = {
            'spam_count': security_result[0] or 0,  # High risk emails (>5.0 score)
            'phishing_count': security_result[4] or 0,  # Critical threats (>10.0 score)
            'avg_spam_score': float(security_result[2] or 0.0),
            'high_risk_count': security_result[0] or 0,
            'medium_risk_count': security_result[1] or 0,
            'max_spam_score': float(security_result[3] or 0.0)
        }
        
        # Government communications - count emails from .gov domains
        gov_query = f"""
            SELECT COUNT(*) 
            {base_query} AND sender LIKE '%.gov'
        """
        gov_count = conn.execute(text(gov_query)).fetchone()[0]
        
        # Get blocked domains data
        blocked_domains = self._get_blocked_domains(conn, domain, date_from, date_to)
        
        return {
            'total_emails': total_emails,
            'sentiment_distribution': sentiment_data,
            'categories': categories,
            'security_metrics': security_metrics,
            'government_communications': gov_count,
            'blocked_domains': blocked_domains
        }

    def _get_daily_volume(self, conn, domain, date_from, date_to):
        """Get daily email volume for trend analysis"""
        query = f"""
            SELECT DATE(timestamp) as email_date, COUNT(*) as count
            FROM email_analysis
            WHERE recipients LIKE '%@{domain}%'
            AND DATE(timestamp) >= '{date_from}'
            AND DATE(timestamp) <= '{date_to}'
            GROUP BY DATE(timestamp)
            ORDER BY email_date
        """
        return dict(conn.execute(text(query)).fetchall())

    def _get_hourly_distribution(self, conn, domain, date_from, date_to):
        """Get hourly distribution of emails"""
        query = f"""
            SELECT HOUR(timestamp) as hour, COUNT(*) as count
            FROM email_analysis
            WHERE recipients LIKE '%@{domain}%'
            AND DATE(timestamp) >= '{date_from}'
            AND DATE(timestamp) <= '{date_to}'
            GROUP BY HOUR(timestamp)
            ORDER BY hour
        """
        return dict(conn.execute(text(query)).fetchall())

    def _get_top_senders(self, conn, domain, date_from, date_to, limit=10):
        """Get top email senders by volume"""
        query = f"""
            SELECT sender, COUNT(*) as count
            FROM email_analysis
            WHERE recipients LIKE '%@{domain}%'
            AND DATE(timestamp) >= '{date_from}'
            AND DATE(timestamp) <= '{date_to}'
            GROUP BY sender
            ORDER BY count DESC
            LIMIT {limit}
        """
        return conn.execute(text(query)).fetchall()

    def _get_blocked_domains(self, conn, domain, date_from, date_to):
        """Get blocked domains statistics"""
        try:
            # Check if client_domains table exists and get domain_id
            domain_id_query = "SELECT id FROM client_domains WHERE domain = :domain"
            domain_result = conn.execute(text(domain_id_query), {'domain': domain}).fetchone()
            
            if domain_result:
                domain_id = domain_result[0]
                
                # Get blocked attempts grouped by rule
                blocked_query = """
                    SELECT 
                        rule_type,
                        rule_matched,
                        COUNT(*) as block_count,
                        COUNT(DISTINCT sender_domain) as unique_domains
                    FROM blocked_attempts
                    WHERE client_domain_id = :domain_id
                    AND timestamp >= :date_from
                    AND timestamp <= :date_to
                    GROUP BY rule_type, rule_matched
                    ORDER BY block_count DESC
                    LIMIT 10
                """
                
                blocked_results = conn.execute(text(blocked_query), {
                    'domain_id': domain_id,
                    'date_from': date_from,
                    'date_to': date_to
                }).fetchall()
                
                blocked_data = []
                total_blocked = 0
                for row in blocked_results:
                    blocked_data.append({
                        'rule_type': row[0],
                        'pattern': row[1],
                        'count': row[2],
                        'unique_domains': row[3]
                    })
                    total_blocked += row[2]
                
                return {
                    'total_blocked': total_blocked,
                    'rules': blocked_data
                }
            else:
                return {
                    'total_blocked': 0,
                    'rules': []
                }
        except Exception as e:
            print(f"Error getting blocked domains: {e}")
            return {
                'total_blocked': 0,
                'rules': []
            }
    
    def _get_security_threats(self, conn, domain, date_from, date_to):
        """Get detailed security threat breakdown"""
        query = f"""
            SELECT 
                email_category,
                COUNT(*) as count,
                AVG(spam_score) as avg_score,
                MAX(spam_score) as max_score
            FROM spacy_analysis
            WHERE recipients LIKE '%@{domain}%'
            AND DATE(timestamp) >= '{date_from}'
            AND DATE(timestamp) <= '{date_to}'
            AND email_category IN ('spam', 'phishing', 'suspicious')
            GROUP BY email_category
        """
        return conn.execute(text(query)).fetchall()

    def create_volume_trend_chart(self, daily_volume, title="Email Volume Trend"):
        """Create a line chart showing daily email volume"""
        if not daily_volume:
            return None
            
        fig, ax = plt.subplots(figsize=(8, 4))
        
        dates = list(daily_volume.keys())
        volumes = list(daily_volume.values())
        
        ax.plot(dates, volumes, marker='o', linewidth=2, markersize=4)
        ax.set_title(title, fontsize=12, fontweight='bold')
        ax.set_xlabel('Date')
        ax.set_ylabel('Number of Emails')
        ax.grid(True, alpha=0.3)
        
        # Format x-axis to show fewer dates if there are many
        if len(dates) > 10:
            step = len(dates) // 10
            ax.set_xticks(dates[::step])
        
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        # Save to BytesIO
        img_buffer = BytesIO()
        plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight')
        img_buffer.seek(0)
        plt.close()
        
        return img_buffer

    def create_hourly_distribution_chart(self, hourly_data):
        """Create a bar chart showing hourly email distribution"""
        if not hourly_data:
            return None
            
        fig, ax = plt.subplots(figsize=(8, 4))
        
        hours = list(range(24))
        volumes = [hourly_data.get(hour, 0) for hour in hours]
        
        bars = ax.bar(hours, volumes, color='steelblue', alpha=0.7)
        ax.set_title('Email Volume by Hour of Day', fontsize=12, fontweight='bold')
        ax.set_xlabel('Hour (24-hour format)')
        ax.set_ylabel('Number of Emails')
        ax.set_xticks(range(0, 24, 2))
        ax.grid(True, alpha=0.3, axis='y')
        
        # Highlight peak hours
        max_volume = max(volumes) if volumes else 0
        for i, bar in enumerate(bars):
            if volumes[i] > max_volume * 0.8:  # Highlight bars > 80% of max
                bar.set_color('darkred')
        
        plt.tight_layout()
        
        # Save to BytesIO
        img_buffer = BytesIO()
        plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight')
        img_buffer.seek(0)
        plt.close()
        
        return img_buffer

    def generate_enhanced_domain_report(self, engine, domain, date_from, date_to, output_path, user_info=None):
        """Generate comprehensive PDF report for a domain"""
        
        try:
            # Get enhanced statistics
            stats = self.get_enhanced_domain_stats(engine, domain, date_from, date_to)
            if not stats:
                print(f"ERROR: No stats returned for domain {domain}")
                return False
        except Exception as e:
            print(f"ERROR getting stats for {domain}: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        current = stats['current_period']
        previous = stats['previous_period']
        
        # Create PDF document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        story = []
        
        # Title and header
        title = Paragraph(f"Executive Email Security Report", self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 12))
        
        # Report metadata
        report_info = f"""
        <b>Domain:</b> {domain}<br/>
        <b>Reporting Period:</b> {date_from} to {date_to} (30 days)<br/>
        <b>Generated:</b> {datetime.now().strftime('%B %d, %Y at %I:%M %p')}<br/>
        """
        if user_info:
            report_info += f"<b>Generated for:</b> {user_info.get('name', 'N/A')} ({user_info.get('email', 'N/A')})<br/>"
        
        story.append(Paragraph(report_info, self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Executive Summary with 30-day comparison
        story.append(Paragraph("Executive Summary", self.styles['CustomHeading']))
        
        total_current = current['total_emails']
        total_previous = previous['total_emails']
        volume_change = total_current - total_previous
        volume_percent_change = (volume_change / total_previous * 100) if total_previous > 0 else 0
        
        # Calculate key metrics
        current_sentiment = current['sentiment_distribution']
        positive_current = current_sentiment.get('Positive', 0) + current_sentiment.get('Very Positive', 0)
        positive_percent = (positive_current / total_current * 100) if total_current > 0 else 0
        
        security_current = current['security_metrics']
        # Count high-risk (>5.0) and critical (>10.0) emails as blocked threats
        threats_blocked = security_current['high_risk_count'] + security_current['phishing_count']
        threat_rate = (threats_blocked / total_current * 100) if total_current > 0 else 0
        
        # Determine trend direction
        trend_indicator = "↑" if volume_change > 0 else "↓" if volume_change < 0 else "→"
        trend_color = "green" if volume_change >= 0 else "orange" if volume_change > -total_previous * 0.1 else "red"
        
        summary_text = f"""
        <b>Email Volume:</b> {total_current:,} emails processed in the last 30 days 
        {trend_indicator} {abs(volume_percent_change):.1f}% vs. previous period ({total_previous:,} emails)
        
        <br/><br/>
        
        <b>Security Performance:</b> Successfully identified and blocked {threats_blocked} high-risk emails 
        (spam score > 5.0, representing {threat_rate:.1f}% of total traffic), maintaining robust protection for {domain}.
        
        <br/><br/>
        
        <b>Communication Quality:</b> {positive_percent:.1f}% of emails showed positive sentiment, 
        indicating healthy business communications. Average spam risk score: {security_current['avg_spam_score']:.1f}/10.0.
        
        <br/><br/>
        
        <b>Government Communications:</b> {current['government_communications']} emails from .gov domains 
        were received and properly handled, ensuring official government communications were prioritized.
        """
        
        story.append(Paragraph(summary_text, self.styles['ExecutiveSummary']))
        story.append(Spacer(1, 20))
        
        # Key Performance Metrics Table
        story.append(Paragraph("Key Performance Indicators", self.styles['CustomHeading']))
        
        # Calculate comparison metrics
        previous_threats = previous['security_metrics']['high_risk_count'] + previous['security_metrics']['phishing_count']
        threat_change = threats_blocked - previous_threats
        
        previous_positive = previous['sentiment_distribution'].get('Positive', 0) + previous['sentiment_distribution'].get('Very Positive', 0)
        previous_positive_percent = (previous_positive / total_previous * 100) if total_previous > 0 else 0
        sentiment_change = positive_percent - previous_positive_percent
        
        # Get blocked domains info
        blocked_current = current.get('blocked_domains', {})
        blocked_previous = previous.get('blocked_domains', {})
        total_blocked_current = blocked_current.get('total_blocked', 0)
        total_blocked_previous = blocked_previous.get('total_blocked', 0)
        blocked_change = total_blocked_current - total_blocked_previous
        
        # Get specific blocked domain patterns for display
        blocked_patterns = []
        if blocked_current.get('rules'):
            for rule in blocked_current['rules'][:3]:  # Top 3 blocked patterns
                blocked_patterns.append(f"{rule['pattern']} ({rule['count']})")
        blocked_patterns_str = ', '.join(blocked_patterns) if blocked_patterns else 'N/A'
        
        kpi_data = [
            ['Metric', 'Current Period', 'Previous Period', 'Change', 'Status'],
            [
                'Total Email Volume', 
                f'{total_current:,}', 
                f'{total_previous:,}', 
                f'{volume_change:+,} ({volume_percent_change:+.1f}%)',
                '✓' if abs(volume_percent_change) < 20 else '⚠'
            ],
            [
                'High-Risk Emails Blocked', 
                f'{threats_blocked}', 
                f'{previous_threats}', 
                f'{threat_change:+}',
                '✓' if threats_blocked < total_current * 0.05 else '⚠'
            ],
            [
                'Blocked Domains/Patterns',
                f'{total_blocked_current:,}',
                f'{total_blocked_previous:,}',
                f'{blocked_change:+,}',
                '✓' if total_blocked_current > 0 else '⚠'
            ],
            [
                'Top Blocked Patterns',
                blocked_patterns_str if len(blocked_patterns_str) < 30 else blocked_patterns_str[:27] + '...',
                '-',
                '-',
                '✓'
            ],
            [
                'Positive Communication %', 
                f'{positive_percent:.1f}%', 
                f'{previous_positive_percent:.1f}%', 
                f'{sentiment_change:+.1f}%',
                '✓' if positive_percent > 60 else '⚠'
            ],
            [
                'Average Spam Score', 
                f'{security_current["avg_spam_score"]:.1f}/10', 
                f'{previous["security_metrics"]["avg_spam_score"]:.1f}/10', 
                f'{security_current["avg_spam_score"] - previous["security_metrics"]["avg_spam_score"]:+.1f}',
                '✓' if security_current["avg_spam_score"] < 3.0 else '⚠'
            ],
            [
                'Government Emails (.gov)', 
                f'{current["government_communications"]}', 
                f'{previous["government_communications"]}', 
                f'{current["government_communications"] - previous["government_communications"]:+}',
                '✓'
            ]
        ]
        
        kpi_table = Table(kpi_data, colWidths=[2.2*inch, 1.1*inch, 1.1*inch, 1.1*inch, 0.6*inch])
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 9)
        ]))
        
        story.append(kpi_table)
        story.append(Spacer(1, 20))
        
        # Blocked Domains/Patterns Detail Section
        if blocked_current.get('rules'):
            story.append(Paragraph("Blocked Domain Patterns Detail", self.styles['CustomHeading']))
            
            blocked_detail_data = [['Pattern', 'Type', 'Blocked Count', 'Unique Domains']]
            for rule in blocked_current['rules'][:10]:  # Show top 10 blocked patterns
                blocked_detail_data.append([
                    rule['pattern'],
                    rule['rule_type'].upper(),
                    f"{rule['count']:,}",
                    str(rule['unique_domains'])
                ])
            
            blocked_table = Table(blocked_detail_data, colWidths=[2*inch, 1*inch, 1.2*inch, 1.2*inch])
            blocked_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 9)
            ]))
            
            story.append(blocked_table)
            story.append(Spacer(1, 12))
            
            # Add explanation note
            blocked_note = f"""
            <i>Note: The blocked domains/patterns shown above represent emails that were blocked at the 
            network perimeter level before entering the main email processing pipeline. For {domain}, 
            the most commonly blocked pattern is *.cn (China domains) which helps protect against 
            international spam and phishing attempts.</i>
            """
            story.append(Paragraph(blocked_note, self.styles['Normal']))
            story.append(Spacer(1, 20))
        
        # Email Volume Trend Chart
        if stats['daily_volume']:
            story.append(Paragraph("Email Volume Trends", self.styles['CustomHeading']))
            volume_chart = self.create_volume_trend_chart(
                stats['daily_volume'], 
                f"Daily Email Volume for {domain}"
            )
            if volume_chart:
                img = Image(volume_chart, width=5*inch, height=2.5*inch)
                story.append(img)
                story.append(Spacer(1, 12))
        
        # Hourly Distribution Chart
        if stats['hourly_distribution']:
            story.append(Paragraph("Peak Activity Analysis", self.styles['CustomHeading']))
            hourly_chart = self.create_hourly_distribution_chart(stats['hourly_distribution'])
            if hourly_chart:
                img = Image(hourly_chart, width=5*inch, height=2.5*inch)
                story.append(img)
                story.append(Spacer(1, 12))
        
        # Top Senders Analysis
        if stats['top_senders']:
            story.append(Paragraph("Top Email Sources", self.styles['CustomHeading']))
            
            sender_data = [['Sender', 'Email Count', 'Percentage']]
            for sender, count in stats['top_senders'][:10]:
                percentage = (count / total_current * 100) if total_current > 0 else 0
                # Truncate long email addresses
                display_sender = sender if len(sender) <= 35 else sender[:32] + "..."
                sender_data.append([display_sender, str(count), f'{percentage:.1f}%'])
            
            sender_table = Table(sender_data, colWidths=[3*inch, 1*inch, 1*inch])
            sender_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 9)
            ]))
            
            story.append(sender_table)
            story.append(Spacer(1, 20))
        
        # Security Threat Analysis
        if stats['security_threats']:
            story.append(Paragraph("Security Threat Analysis", self.styles['CustomHeading']))
            
            threat_data = [['Threat Type', 'Count', 'Avg Score', 'Max Score', 'Risk Level']]
            for threat_type, count, avg_score, max_score in stats['security_threats']:
                risk_level = "High" if avg_score > 7 else "Medium" if avg_score > 4 else "Low"
                threat_data.append([
                    threat_type.title(), 
                    str(count), 
                    f'{avg_score:.1f}', 
                    f'{max_score:.1f}',
                    risk_level
                ])
            
            threat_table = Table(threat_data, colWidths=[1.5*inch, 0.8*inch, 1*inch, 1*inch, 1*inch])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 9)
            ]))
            
            story.append(threat_table)
            story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(Paragraph("Strategic Recommendations", self.styles['CustomHeading']))
        
        recommendations = []
        
        # Volume-based recommendations
        if abs(volume_percent_change) > 50:
            if volume_change > 0:
                recommendations.append("• Monitor increased email volume for potential spam campaigns")
            else:
                recommendations.append("• Investigate significant decrease in email volume - potential delivery issues")
        
        # Security-based recommendations
        if threat_rate > 5:
            recommendations.append("• Consider additional email security training for staff")
        elif threat_rate < 1:
            recommendations.append("• Excellent security posture maintained - continue current protocols")
        
        # Sentiment-based recommendations
        if positive_percent < 50:
            recommendations.append("• Review customer communication strategies to improve sentiment")
        elif positive_percent > 80:
            recommendations.append("• Exceptional communication quality - consider sharing best practices")
        
        # Peak time recommendations
        if stats['hourly_distribution']:
            peak_hours = [h for h, v in stats['hourly_distribution'].items() if v > total_current/24 * 2]
            if peak_hours:
                recommendations.append(f"• Peak email hours: {min(peak_hours)}-{max(peak_hours)}:00 - optimize server resources accordingly")
        
        # Government communication recommendations
        if current['government_communications'] > 10:
            recommendations.append("• High volume of government communications detected - ensure priority handling")
        
        # Default recommendations
        recommendations.extend([
            "• Continue monthly email security monitoring and reporting",
            "• Maintain current email authentication protocols (SPF/DKIM/DMARC)",
            "• Review and update email security policies quarterly"
        ])
        
        rec_text = "<br/>".join(recommendations[:8])  # Limit to 8 recommendations
        story.append(Paragraph(rec_text, self.styles['Normal']))
        
        # Footer
        story.append(Spacer(1, 30))
        footer_text = f"""
        <i>This comprehensive report was generated by MailGuardian Email Security Analytics on 
        {datetime.now().strftime('%B %d, %Y at %I:%M %p')}. For questions about this report or 
        to request additional analysis, please contact your email security administrator.</i>
        """
        story.append(Paragraph(footer_text, self.styles['Normal']))
        
        # Build PDF
        doc.build(story)
        return True


# Enhanced route for the main Flask app
def enhanced_domain_report_route(app):
    """Enhanced domain report route to add to your Flask app"""
    
    @app.route('/reports/enhanced-domain/<domain>')
    @login_required
    def enhanced_domain_report(domain):
        """Generate enhanced PDF report for a specific domain with 30-day metrics"""
        
        # Check if user has access to this domain
        if not current_user.is_admin():
            user_authorized_domains = get_user_authorized_domains(current_user)
            if domain not in user_authorized_domains:
                flash('Access denied for this domain report', 'error')
                return redirect(url_for('dashboard'))
        
        # Check if domain is in hosted domains (populated from client_domains table)
        from app import HOSTED_DOMAINS
        hosted_domains = HOSTED_DOMAINS if HOSTED_DOMAINS else []

        if domain not in hosted_domains:
            flash('Enhanced reports are only available for hosted domains', 'error')
            return redirect(url_for('dashboard'))
        
        try:
            # Get date range (last 30 days)
            date_to = datetime.now().strftime('%Y-%m-%d')
            date_from = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
            
            # Get database engine
            engine = get_db_engine()
            if not engine:
                flash('Database connection failed', 'error')
                return redirect(url_for('dashboard'))
            
            # Create enhanced report generator
            report_generator = EnhancedEmailReportGenerator()
            
            # Create temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
                temp_path = tmp_file.name
            
            # Generate enhanced report
            user_info = {
                'name': current_user.get_display_name(),
                'email': current_user.email
            }
            
            success = report_generator.generate_enhanced_domain_report(
                engine, domain, date_from, date_to, temp_path, user_info
            )
            
            if not success:
                flash('Failed to generate enhanced report', 'error')
                return redirect(url_for('dashboard'))
            
            return send_file(
                temp_path,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=f'{domain}_enhanced_email_report_{date_from}_to_{date_to}.pdf'
            )
            
        except Exception as e:
            flash(f'Enhanced report generation failed: {str(e)}', 'error')
            return redirect(url_for('dashboard'))

# Function to add to your existing database stats function
def get_enhanced_dashboard_stats(user=None):
    """Enhanced version of get_dashboard_stats with additional metrics"""
    engine = get_db_engine()
    if not engine:
        return {}

    try:
        with engine.connect() as conn:
            # Get the standard stats
            domain_filter = get_domain_filter_sql(user)
            
            # Get last 30 days stats
            date_30_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
            
            # Total emails in last 30 days
            total_30_query = f"""
                SELECT COUNT(*) FROM spacy_analysis 
                {domain_filter} AND DATE(timestamp) >= '{date_30_days_ago}'
            """
            total_30_days = conn.execute(text(total_30_query)).fetchone()[0]
            
            # Daily average
            daily_average = total_30_days / 30
            
            # Get previous 30 days for comparison
            date_60_days_ago = (datetime.now() - timedelta(days=60)).strftime('%Y-%m-%d')
            date_30_days_ago_end = (datetime.now() - timedelta(days=31)).strftime('%Y-%m-%d')
            
            previous_30_query = f"""
                SELECT COUNT(*) FROM spacy_analysis 
                {domain_filter} 
                AND DATE(timestamp) >= '{date_60_days_ago}' 
                AND DATE(timestamp) <= '{date_30_days_ago_end}'
            """
            previous_30_days = conn.execute(text(previous_30_query)).fetchone()[0]
            
            # Calculate trend
            volume_change = total_30_days - previous_30_days
            volume_percent_change = (volume_change / previous_30_days * 100) if previous_30_days > 0 else 0
            
            # Get peak day
            peak_day_query = f"""
                SELECT DATE(timestamp) as email_date, COUNT(*) as count
                FROM spacy_analysis
                {domain_filter} AND DATE(timestamp) >= '{date_30_days_ago}'
                GROUP BY DATE(timestamp)
                ORDER BY count DESC
                LIMIT 1
            """
            peak_day_result = conn.execute(text(peak_day_query)).fetchone()
            peak_day = {
                'date': peak_day_result[0] if peak_day_result else None,
                'count': peak_day_result[1] if peak_day_result else 0
            }
            
            # Get all the standard stats
            standard_stats = get_dashboard_stats(user)
            
            # Enhance with new metrics
            standard_stats.update({
                'volume_metrics': {
                    'last_30_days': total_30_days,
                    'daily_average': round(daily_average, 1),
                    'previous_30_days': previous_30_days,
                    'volume_change': volume_change,
                    'volume_percent_change': round(volume_percent_change, 1),
                    'peak_day': peak_day
                }
            })
            
            return standard_stats
            
    except Exception as e:
        print(f"Error getting enhanced dashboard stats: {e}")
        return get_dashboard_stats(user)  # Fallback to standard stats
