"""
PDF Report Generator for MemSafe vulnerability analysis reports.
"""

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
from typing import Dict, List, Any
from io import BytesIO


def generate_pdf_report(parsed_data: Dict[str, Any], code_input: str, output_path: str = None) -> BytesIO:
    """
    Generate a PDF report from analysis results.
    
    Args:
        parsed_data: Parsed JSON data from AI analysis
        code_input: Original C code that was analyzed
        output_path: Optional file path to save PDF. If None, returns BytesIO buffer.
        
    Returns:
        BytesIO buffer containing PDF data, or None if output_path is provided
    """
    buffer = BytesIO() if output_path is None else None
    
    # Create PDF document
    doc = SimpleDocTemplate(
        output_path if output_path else buffer,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=18
    )
    
    # Container for the 'Flowable' objects
    elements = []
    
    # Define styles
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1f77b4'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=12,
        spaceBefore=12
    )
    
    subheading_style = ParagraphStyle(
        'CustomSubHeading',
        parent=styles['Heading3'],
        fontSize=12,
        textColor=colors.HexColor('#34495e'),
        spaceAfter=8,
        spaceBefore=8
    )
    
    # Title
    elements.append(Paragraph("MemSafe Security Analysis Report", title_style))
    elements.append(Spacer(1, 0.2*inch))
    
    # Date
    date_str = datetime.now().strftime("%B %d, %Y at %I:%M %p")
    elements.append(Paragraph(f"<i>Generated on {date_str}</i>", styles['Normal']))
    elements.append(Spacer(1, 0.3*inch))
    
    # Summary Section
    elements.append(Paragraph("Executive Summary", heading_style))
    summary = parsed_data.get('summary', 'No summary provided.')
    elements.append(Paragraph(summary, styles['Normal']))
    elements.append(Spacer(1, 0.2*inch))
    
    # Safety Score
    elements.append(Paragraph("Safety Score", heading_style))
    safety_score = parsed_data.get('safety_score', 0)
    score_color = colors.green if safety_score >= 80 else colors.orange if safety_score >= 60 else colors.red
    
    score_data = [
        ['Safety Score', f'{safety_score} / 100'],
    ]
    score_table = Table(score_data, colWidths=[2*inch, 2*inch])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), colors.HexColor('#ecf0f1')),
        ('BACKGROUND', (1, 0), (1, 0), score_color),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 14),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(score_table)
    elements.append(Spacer(1, 0.3*inch))
    
    # Vulnerabilities Section
    vulnerabilities = parsed_data.get('vulnerabilities', [])
    if vulnerabilities:
        elements.append(Paragraph("Detected Vulnerabilities", heading_style))
        elements.append(Spacer(1, 0.1*inch))
        
        for idx, vuln in enumerate(vulnerabilities, 1):
            vuln_type = vuln.get('type', 'Unknown Vulnerability')
            severity = vuln.get('severity', 'Unknown')
            cwe = vuln.get('cwe', 'N/A')
            explanation = vuln.get('explanation', 'No explanation provided.')
            
            # Vulnerability header
            elements.append(Paragraph(
                f"<b>{idx}. {vuln_type}</b> — Severity: {severity} (CWE-{cwe})",
                subheading_style
            ))
            
            # Explanation
            elements.append(Paragraph(explanation, styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
            
            # Code snippet if available
            start_line = vuln.get("insecure_snippet_start_line")
            end_line = vuln.get("insecure_snippet_end_line")
            if start_line is not None and end_line is not None:
                lines = code_input.split("\n")
                if start_line <= len(lines) and end_line <= len(lines):
                    snippet_lines = lines[start_line-1:end_line]
                    snippet_text = "\n".join(snippet_lines)
                    elements.append(Paragraph("<b>Vulnerable Code:</b>", styles['Normal']))
                    elements.append(Paragraph(
                        f"<font face='Courier' size='9'>{snippet_text}</font>",
                        styles['Normal']
                    ))
                    elements.append(Spacer(1, 0.1*inch))
            
            elements.append(Spacer(1, 0.15*inch))
    else:
        elements.append(Paragraph("Detected Vulnerabilities", heading_style))
        elements.append(Paragraph("✅ No vulnerabilities detected!", styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
    
    # Rust Suggestions Section
    suggested_rust = parsed_data.get('suggested_rust', [])
    if suggested_rust:
        elements.append(PageBreak())
        elements.append(Paragraph("Suggested Rust Fixes", heading_style))
        elements.append(Spacer(1, 0.1*inch))
        
        for idx, rust_fix in enumerate(suggested_rust, 1):
            rust_snippet = rust_fix.get('rust_snippet', '')
            why_safe = rust_fix.get('why_safe', '')
            
            elements.append(Paragraph(f"<b>Fix #{idx}</b>", subheading_style))
            
            if rust_snippet:
                elements.append(Paragraph("<b>Rust Code:</b>", styles['Normal']))
                elements.append(Paragraph(
                    f"<font face='Courier' size='9'>{rust_snippet}</font>",
                    styles['Normal']
                ))
                elements.append(Spacer(1, 0.1*inch))
            
            if why_safe:
                elements.append(Paragraph("<b>Why it's safer:</b>", styles['Normal']))
                elements.append(Paragraph(why_safe, styles['Normal']))
            
            elements.append(Spacer(1, 0.2*inch))
    
    # Original Code Section
    elements.append(PageBreak())
    elements.append(Paragraph("Original C Code", heading_style))
    elements.append(Spacer(1, 0.1*inch))
    elements.append(Paragraph(
        f"<font face='Courier' size='8'>{code_input}</font>",
        styles['Normal']
    ))
    
    # Footer
    elements.append(Spacer(1, 0.3*inch))
    elements.append(Paragraph(
        "<i>Generated by MemSafe — Memory Safety Analysis Tool</i>",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, alignment=TA_CENTER, textColor=colors.grey)
    ))
    
    # Build PDF
    doc.build(elements)
    
    if buffer:
        buffer.seek(0)
        return buffer
    
    return None

