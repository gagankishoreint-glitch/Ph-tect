"""
PDF Report Generator Module
Generates professional PDF reports for phishing analysis
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from io import BytesIO
import datetime
import os


class PhishingReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()
    
    def _create_custom_styles(self):
        """Create custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#1e293b')
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.HexColor('#3b82f6')
        ))
        
        self.styles.add(ParagraphStyle(
            name='SubHeader',
            parent=self.styles['Heading3'],
            fontSize=12,
            spaceBefore=15,
            spaceAfter=8,
            textColor=colors.HexColor('#475569')
        ))
        
        self.styles.add(ParagraphStyle(
            name='ReportBody',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=8,
            alignment=TA_JUSTIFY,
            textColor=colors.HexColor('#334155')
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskHigh',
            parent=self.styles['Normal'],
            fontSize=16,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#dc2626'),
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskMedium',
            parent=self.styles['Normal'],
            fontSize=16,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#f59e0b'),
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskLow',
            parent=self.styles['Normal'],
            fontSize=16,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#10b981'),
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='ReportFooter',
            parent=self.styles['Normal'],
            fontSize=8,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#94a3b8')
        ))
    
    def _get_risk_style(self, risk_level):
        """Get appropriate style based on risk level"""
        risk_level = risk_level.upper()
        if 'CRITICAL' in risk_level or 'HIGH' in risk_level:
            return self.styles['RiskHigh']
        elif 'MEDIUM' in risk_level:
            return self.styles['RiskMedium']
        else:
            return self.styles['RiskLow']
    
    def _get_risk_color(self, risk_level):
        """Get color based on risk level"""
        risk_level = risk_level.upper()
        if 'CRITICAL' in risk_level:
            return colors.HexColor('#991b1b')
        elif 'HIGH' in risk_level:
            return colors.HexColor('#dc2626')
        elif 'MEDIUM' in risk_level:
            return colors.HexColor('#f59e0b')
        else:
            return colors.HexColor('#10b981')
    
    def generate_email_report(self, analysis_data):
        """Generate PDF report for email analysis"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=50
        )
        
        story = []
        
        # Title
        story.append(Paragraph("🛡️ Phishing Email Analysis Report", self.styles['ReportTitle']))
        story.append(Spacer(1, 10))
        
        # Report metadata
        report_info = [
            ['Report Generated:', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Analysis Type:', 'Email Threat Analysis'],
            ['Platform:', 'Phishing Intelligence Platform v4.0']
        ]
        
        info_table = Table(report_info, colWidths=[1.5*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#64748b')),
            ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#334155')),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 20))
        
        # Horizontal line
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
        story.append(Spacer(1, 20))
        
        # Risk Assessment Summary
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        risk_level = analysis_data.get('risk_level', 'Unknown')
        risk_color = self._get_risk_color(risk_level)
        
        # Risk score box
        risk_data = [
            [Paragraph(f"Threat Level: {risk_level}", self._get_risk_style(risk_level))],
            [Paragraph(f"Risk Score: {analysis_data.get('danger_score', 0)}/100", self.styles['ReportBody'])]
        ]
        
        risk_table = Table(risk_data, colWidths=[5*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 2, risk_color),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 15))
        
        # Advice
        advice = analysis_data.get('advice', 'No specific advice available.')
        story.append(Paragraph(f"<b>Assessment:</b> {advice}", self.styles['ReportBody']))
        story.append(Spacer(1, 20))
        
        # Email Details
        story.append(Paragraph("Email Details", self.styles['SectionHeader']))
        
        email_details = [
            ['Sender:', analysis_data.get('sender', 'N/A')],
            ['Subject:', analysis_data.get('subject', 'N/A')],
        ]
        
        details_table = Table(email_details, colWidths=[1.2*inch, 4.5*inch])
        details_table.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#64748b')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(details_table)
        story.append(Spacer(1, 20))
        
        # Threat Indicators
        story.append(Paragraph("Threat Indicators Detected", self.styles['SectionHeader']))
        
        reasons = analysis_data.get('reasons', [])
        if reasons:
            for i, reason in enumerate(reasons, 1):
                story.append(Paragraph(f"⚠️ {reason}", self.styles['ReportBody']))
        else:
            story.append(Paragraph("✅ No threat indicators detected.", self.styles['ReportBody']))
        
        story.append(Spacer(1, 20))
        
        # ML Analysis
        story.append(Paragraph("Machine Learning Analysis", self.styles['SectionHeader']))
        ml_prob = analysis_data.get('ml_probability', 0)
        ml_conf = analysis_data.get('ml_confidence', 'N/A')
        story.append(Paragraph(f"Phishing Probability: {ml_prob}%", self.styles['ReportBody']))
        story.append(Paragraph(f"Confidence: {ml_conf}", self.styles['ReportBody']))
        
        story.append(Spacer(1, 20))
        
        # URLs Found
        urls = analysis_data.get('extracted_urls', [])
        if urls:
            story.append(Paragraph("URLs Extracted from Email", self.styles['SectionHeader']))
            for url in urls:
                story.append(Paragraph(f"🔗 {url}", self.styles['ReportBody']))
            story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(Paragraph("Recommendations", self.styles['SectionHeader']))
        
        recommendations = self._get_recommendations(analysis_data)
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['ReportBody']))
        
        story.append(Spacer(1, 30))
        
        # Footer
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            "Generated by Phishing Intelligence Platform | For educational purposes only",
            self.styles['ReportFooter']
        ))
        story.append(Paragraph(
            "Always verify suspicious communications through official channels",
            self.styles['ReportFooter']
        ))
        
        doc.build(story)
        buffer.seek(0)
        return buffer
    
    def generate_url_report(self, analysis_data):
        """Generate PDF report for URL analysis"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=50
        )
        
        story = []
        
        # Title
        story.append(Paragraph("🔗 URL Threat Intelligence Report", self.styles['ReportTitle']))
        story.append(Spacer(1, 10))
        
        # Report metadata
        report_info = [
            ['Report Generated:', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Analysis Type:', 'URL Threat Intelligence'],
            ['Platform:', 'Phishing Intelligence Platform v4.0']
        ]
        
        info_table = Table(report_info, colWidths=[1.5*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#64748b')),
            ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#334155')),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 20))
        
        # URL Being Analyzed
        story.append(Paragraph("Target URL", self.styles['SectionHeader']))
        url = analysis_data.get('url', 'N/A')
        story.append(Paragraph(f"<font color='#3b82f6'>{url}</font>", self.styles['ReportBody']))
        story.append(Spacer(1, 10))
        
        # Horizontal line
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
        story.append(Spacer(1, 20))
        
        # Risk Assessment
        story.append(Paragraph("Risk Assessment", self.styles['SectionHeader']))
        
        risk_level = analysis_data.get('risk_level', 'Unknown')
        risk_color = self._get_risk_color(risk_level)
        
        risk_data = [
            [Paragraph(f"Threat Level: {risk_level}", self._get_risk_style(risk_level))],
            [Paragraph(f"Risk Score: {analysis_data.get('danger_score', 0)}/100", self.styles['ReportBody'])]
        ]
        
        risk_table = Table(risk_data, colWidths=[5*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 2, risk_color),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 15))
        
        summary = analysis_data.get('summary', 'No summary available.')
        story.append(Paragraph(f"<b>Summary:</b> {summary}", self.styles['ReportBody']))
        story.append(Spacer(1, 20))
        
        # Domain Intelligence
        domain_info = analysis_data.get('domain_info', {})
        if domain_info.get('success'):
            story.append(Paragraph("Domain Intelligence", self.styles['SectionHeader']))
            
            domain_data = [
                ['Domain:', domain_info.get('domain', 'N/A')],
                ['Registrar:', domain_info.get('registrar', 'N/A')],
                ['Created:', domain_info.get('creation_date', 'N/A')],
                ['Domain Age:', f"{domain_info.get('domain_age_days', 'N/A')} days"],
                ['Expires:', domain_info.get('expiration_date', 'N/A')],
                ['Country:', domain_info.get('registrant_country', 'N/A')],
            ]
            
            domain_table = Table(domain_data, colWidths=[1.5*inch, 4*inch])
            domain_table.setStyle(TableStyle([
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ]))
            story.append(domain_table)
            story.append(Spacer(1, 15))
        
        # SSL Certificate
        ssl_info = analysis_data.get('ssl_info', {})
        story.append(Paragraph("SSL Certificate", self.styles['SectionHeader']))
        
        if ssl_info.get('has_ssl'):
            ssl_data = [
                ['Status:', '✅ Valid SSL Certificate'],
                ['Issuer:', ssl_info.get('issuer', 'N/A')],
                ['Organization:', ssl_info.get('issuer_org', 'N/A')],
                ['Valid From:', ssl_info.get('valid_from', 'N/A')],
                ['Valid Until:', ssl_info.get('valid_until', 'N/A')],
                ['Days Until Expiry:', str(ssl_info.get('days_until_expiry', 'N/A'))],
            ]
        else:
            ssl_data = [
                ['Status:', '❌ No Valid SSL Certificate'],
            ]
        
        ssl_table = Table(ssl_data, colWidths=[1.5*inch, 4*inch])
        ssl_table.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(ssl_table)
        story.append(Spacer(1, 15))
        
        # Redirect Analysis
        redirect_info = analysis_data.get('redirect_info', {})
        if redirect_info.get('success'):
            story.append(Paragraph("Redirect Analysis", self.styles['SectionHeader']))
            
            redirect_data = [
                ['Redirect Count:', str(redirect_info.get('redirect_count', 0))],
                ['Uses URL Shortener:', '⚠️ Yes' if redirect_info.get('uses_shortener') else 'No'],
                ['Crosses Domains:', '⚠️ Yes' if redirect_info.get('crosses_domains') else 'No'],
                ['Final URL:', redirect_info.get('final_url', 'N/A')],
            ]
            
            redirect_table = Table(redirect_data, colWidths=[1.5*inch, 4*inch])
            redirect_table.setStyle(TableStyle([
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ]))
            story.append(redirect_table)
            story.append(Spacer(1, 15))
        
        # Content Analysis
        content_info = analysis_data.get('content_info', {})
        if content_info.get('success'):
            story.append(Paragraph("Content Analysis", self.styles['SectionHeader']))
            
            content_data = [
                ['Page Title:', content_info.get('page_title', 'N/A')[:50]],
                ['Login Form Detected:', '⚠️ Yes' if content_info.get('has_login_form') else 'No'],
                ['Password Field:', '⚠️ Yes' if content_info.get('has_password_field') else 'No'],
                ['Requests Sensitive Info:', '🚨 Yes' if content_info.get('requests_sensitive_info') else 'No'],
                ['External Form Action:', '🚨 Yes' if content_info.get('external_form_action') else 'No'],
            ]
            
            content_table = Table(content_data, colWidths=[1.5*inch, 4*inch])
            content_table.setStyle(TableStyle([
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ]))
            story.append(content_table)
            story.append(Spacer(1, 15))
        
        # All Risk Factors
        story.append(Paragraph("All Risk Factors", self.styles['SectionHeader']))
        
        reasons = analysis_data.get('reasons', [])
        if reasons:
            for reason in reasons:
                story.append(Paragraph(f"⚠️ {reason}", self.styles['ReportBody']))
        else:
            story.append(Paragraph("✅ No risk factors identified.", self.styles['ReportBody']))
        
        story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(Paragraph("Recommendations", self.styles['SectionHeader']))
        recommendations = self._get_url_recommendations(analysis_data)
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['ReportBody']))
        
        story.append(Spacer(1, 30))
        
        # Footer
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            "Generated by Phishing Intelligence Platform | For educational purposes only",
            self.styles['ReportFooter']
        ))
        story.append(Paragraph(
            "Always verify suspicious URLs through official channels before clicking",
            self.styles['ReportFooter']
        ))
        
        doc.build(story)
        buffer.seek(0)
        return buffer
    
    def _get_recommendations(self, analysis_data):
        """Generate recommendations based on email analysis"""
        recommendations = []
        score = analysis_data.get('danger_score', 0)
        
        if score >= 60:
            recommendations.append("Do NOT click any links in this email")
            recommendations.append("Do NOT download any attachments")
            recommendations.append("Do NOT reply to this email or provide any information")
            recommendations.append("Report this email to your IT security team")
            recommendations.append("Mark this email as spam/phishing in your email client")
        elif score >= 40:
            recommendations.append("Exercise caution before taking any action")
            recommendations.append("Verify the sender through an alternative communication channel")
            recommendations.append("Do not click links - instead, navigate directly to the official website")
            recommendations.append("Contact the supposed sender via their official phone number")
        else:
            recommendations.append("This email appears relatively safe, but always stay vigilant")
            recommendations.append("When in doubt, verify through official channels")
            recommendations.append("Keep your security software updated")
        
        return recommendations
    
    def _get_url_recommendations(self, analysis_data):
        """Generate recommendations based on URL analysis"""
        recommendations = []
        score = analysis_data.get('danger_score', 0)
        
        if score >= 60:
            recommendations.append("Do NOT visit this URL under any circumstances")
            recommendations.append("Do NOT enter any personal information if you already visited")
            recommendations.append("If you entered credentials, change your passwords immediately")
            recommendations.append("Report this URL to Google Safe Browsing and PhishTank")
            recommendations.append("Run a security scan on your device if you visited the site")
        elif score >= 40:
            recommendations.append("Exercise extreme caution if you must visit this URL")
            recommendations.append("Verify the legitimacy through official channels first")
            recommendations.append("Use a sandboxed browser or virtual machine if investigating")
            recommendations.append("Do not enter any credentials or personal information")
        else:
            recommendations.append("This URL appears relatively safe based on our analysis")
            recommendations.append("Always verify HTTPS and check for the padlock icon")
            recommendations.append("Be cautious of any requests for sensitive information")
            recommendations.append("Keep your browser and security software updated")
        
        return recommendations
