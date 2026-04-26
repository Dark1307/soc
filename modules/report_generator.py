import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# ─── Reports folder ───
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports_output')
os.makedirs(REPORTS_DIR, exist_ok=True)

def get_report_path(filename):
    """Get full path of a report file."""
    return os.path.join(REPORTS_DIR, filename)

def list_reports():
    """List all generated reports."""
    reports = []
    try:
        for f in os.listdir(REPORTS_DIR):
            if f.endswith('.pdf'):
                path = os.path.join(REPORTS_DIR, f)
                reports.append({
                    'filename': f,
                    'size': os.path.getsize(path),
                    'created': datetime.fromtimestamp(
                        os.path.getctime(path)
                    ).strftime('%Y-%m-%d %H:%M:%S'),
                })
        reports.sort(key=lambda x: x['created'], reverse=True)
    except Exception as e:
        return {'error': str(e)}
    return {'reports': reports}

def generate(data):
    """Generate a PDF report from scan/analysis data."""
    report_type = data.get('type', 'General')
    findings    = data.get('findings', [])
    summary     = data.get('summary', '')
    severity    = data.get('severity', 'LOW')
    target      = data.get('target', 'N/A')

    # ─── Filename ───
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename  = f'SOC_Report_{report_type}_{timestamp}.pdf'
    filepath  = os.path.join(REPORTS_DIR, filename)

    # ─── Colors ───
    DARK    = colors.HexColor('#0a0e17')
    CYAN    = colors.HexColor('#00b8d4')
    RED     = colors.HexColor('#ff1744')
    YELLOW  = colors.HexColor('#ffd600')
    GREEN   = colors.HexColor('#00e676')
    WHITE   = colors.white
    GRAY    = colors.HexColor('#607b9f')
    PANEL   = colors.HexColor('#111827')

    SEV_COLOR = {
        'CRITICAL': RED,
        'HIGH':     RED,
        'MEDIUM':   YELLOW,
        'LOW':      GREEN,
    }

    # ─── Document ───
    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        rightMargin=40, leftMargin=40,
        topMargin=40,   bottomMargin=40
    )

    styles = getSampleStyleSheet()
    story  = []

    # ─── Custom Styles ───
    title_style = ParagraphStyle(
        'Title', fontSize=22, textColor=CYAN,
        fontName='Helvetica-Bold', spaceAfter=4,
        alignment=TA_CENTER
    )
    subtitle_style = ParagraphStyle(
        'Subtitle', fontSize=11, textColor=GRAY,
        fontName='Helvetica', spaceAfter=2,
        alignment=TA_CENTER
    )
    heading_style = ParagraphStyle(
        'Heading', fontSize=13, textColor=CYAN,
        fontName='Helvetica-Bold', spaceBefore=14, spaceAfter=6
    )
    normal_style = ParagraphStyle(
        'Normal2', fontSize=10, textColor=colors.black,
        fontName='Helvetica', spaceAfter=4, leading=16
    )
    label_style = ParagraphStyle(
        'Label', fontSize=9, textColor=GRAY,
        fontName='Helvetica'
    )

    # ─── Header ───
    story.append(Paragraph('INTEGRATED SOC INTELLIGENCE SUITE', title_style))
    story.append(Paragraph('Security Operations Center — Automated Report', subtitle_style))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width='100%', thickness=1, color=CYAN))
    story.append(Spacer(1, 10))

    # ─── Meta Info Table ───
    meta_data = [
        ['Report Type',  report_type,
         'Generated',    datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ['Target',       target,
         'Severity',     severity],
    ]
    meta_table = Table(meta_data, colWidths=[100, 180, 80, 150])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND',  (0,0), (-1,-1), colors.HexColor('#f8f9fa')),
        ('TEXTCOLOR',   (0,0), (0,-1), GRAY),
        ('TEXTCOLOR',   (2,0), (2,-1), GRAY),
        ('FONTNAME',    (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE',    (0,0), (-1,-1), 9),
        ('FONTNAME',    (1,0), (1,-1), 'Helvetica-Bold'),
        ('FONTNAME',    (3,0), (3,-1), 'Helvetica-Bold'),
        ('TEXTCOLOR',   (3,1), (3,1), SEV_COLOR.get(severity, GREEN)),
        ('ROWBACKGROUNDS', (0,0), (-1,-1),
         [colors.HexColor('#f1f3f5'), colors.HexColor('#e9ecef')]),
        ('GRID',        (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
        ('PADDING',     (0,0), (-1,-1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # ─── Executive Summary ───
    story.append(Paragraph('Executive Summary', heading_style))
    story.append(HRFlowable(width='100%', thickness=0.5, color=GRAY))
    story.append(Spacer(1, 6))
    if summary:
        story.append(Paragraph(summary, normal_style))
    else:
        story.append(Paragraph(
            f'This report was automatically generated by the SOC Intelligence Suite. '
            f'The {report_type} analysis identified {len(findings)} finding(s) '
            f'with an overall severity of {severity}.',
            normal_style
        ))
    story.append(Spacer(1, 10))

    # ─── Findings ───
    if findings:
        story.append(Paragraph('Detailed Findings', heading_style))
        story.append(HRFlowable(width='100%', thickness=0.5, color=GRAY))
        story.append(Spacer(1, 6))

        table_data = [['#', 'Type', 'Severity', 'Details']]
        for i, f in enumerate(findings[:50], 1):
            sev = f.get('severity', 'LOW')
            table_data.append([
                str(i),
                f.get('type', 'N/A'),
                sev,
                f.get('details', f.get('line', 'N/A'))[:80],
            ])

        findings_table = Table(
            table_data,
            colWidths=[25, 110, 70, 300]
        )
        findings_table.setStyle(TableStyle([
            ('BACKGROUND',  (0,0), (-1,0), PANEL),
            ('TEXTCOLOR',   (0,0), (-1,0), WHITE),
            ('FONTNAME',    (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',    (0,0), (-1,-1), 8),
            ('FONTNAME',    (0,1), (-1,-1), 'Helvetica'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1),
             [colors.white, colors.HexColor('#f8f9fa')]),
            ('GRID',        (0,0), (-1,-1), 0.3, colors.HexColor('#dee2e6')),
            ('PADDING',     (0,0), (-1,-1), 6),
            ('ALIGN',       (0,0), (0,-1), 'CENTER'),
            ('ALIGN',       (2,0), (2,-1), 'CENTER'),
        ]))

        # Color severity cells
        for i, f in enumerate(findings[:50], 1):
            sev = f.get('severity', 'LOW')
            col = SEV_COLOR.get(sev, GREEN)
            findings_table.setStyle(TableStyle([
                ('TEXTCOLOR', (2,i), (2,i), col),
                ('FONTNAME',  (2,i), (2,i), 'Helvetica-Bold'),
            ]))

        story.append(findings_table)
        story.append(Spacer(1, 14))

    # ─── Recommendations ───
    story.append(Paragraph('Recommendations', heading_style))
    story.append(HRFlowable(width='100%', thickness=0.5, color=GRAY))
    story.append(Spacer(1, 6))

    recommendations = {
        'Port Scan': [
            '• Close all unnecessary open ports immediately.',
            '• Place a firewall in front of all exposed services.',
            '• Disable Telnet (port 23) and use SSH instead.',
            '• Restrict RDP (port 3389) access to VPN only.',
            '• Monitor all database ports (3306, 5432, 27017).',
        ],
        'Log Analysis': [
            '• Block all IPs showing attack patterns at firewall.',
            '• Enable WAF (Web Application Firewall) rules.',
            '• Implement rate limiting on login endpoints.',
            '• Use parameterized queries to prevent SQL injection.',
            '• Sanitize all user inputs to prevent XSS.',
        ],
        'Network Monitor': [
            '• Immediately block suspicious source IPs.',
            '• Review firewall rules for C2 communication.',
            '• Enable IDS/IPS on network perimeter.',
            '• Monitor outbound traffic for data exfiltration.',
        ],
        'General': [
            '• Apply all pending security patches.',
            '• Enable multi-factor authentication (MFA).',
            '• Conduct regular penetration testing.',
            '• Train staff on security awareness.',
            '• Implement a proper incident response plan.',
        ],
    }

    recs = recommendations.get(report_type, recommendations['General'])
    for rec in recs:
        story.append(Paragraph(rec, normal_style))
    story.append(Spacer(1, 14))

    # ─── Footer ───
    story.append(HRFlowable(width='100%', thickness=1, color=CYAN))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f'Generated by SOC Intelligence Suite v1.0 | '
        f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | '
        f'CONFIDENTIAL — For authorized personnel only',
        label_style
    ))

    # ─── Build PDF ───
    doc.build(story)

    return {
        'status': 'success',
        'filename': filename,
        'filepath': filepath,
        'message': f'Report generated: {filename}'
    }