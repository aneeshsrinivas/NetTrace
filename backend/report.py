import io
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from xml.sax.saxutils import escape

def build_pdf(data):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=(595, 842), leftMargin=48, rightMargin=48, topMargin=56, bottomMargin=56)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="TitleN", fontName="Helvetica-Bold", fontSize=23, leading=28, textColor=colors.HexColor("#111111"), spaceAfter=8))
    styles.add(ParagraphStyle(name="BodyN", fontName="Helvetica", fontSize=9, leading=14, spaceAfter=7))
    styles.add(ParagraphStyle(name="SmallN", fontName="Helvetica", fontSize=7.5, leading=11, textColor=colors.HexColor("#444444")))
    styles.add(ParagraphStyle(name="HeadingN", fontName="Helvetica-Bold", fontSize=13, leading=17, spaceBefore=18, spaceAfter=9))
    P = lambda value, style="BodyN": Paragraph(escape(str(value)), styles[style])
    story = [P("NETTRACE / INVESTIGATION REPORT", "SmallN"), Spacer(1, 14), P("Capture investigation", "TitleN"), P(data["filename"]),
             P(f"Analysed {data['analyzed_at']}  |  SHA-256: {data['sha256']}", "SmallN"), Spacer(1, 16)]
    s = data["summary"]
    rows = [["PACKETS", "IP PACKETS", "HOSTS", "FINDINGS"], [str(s["packets_processed"]), str(s["ip_packets"]), str(s["hosts"]), str(s["findings"])]]
    table = Table(rows, colWidths=[124] * 4, rowHeights=[22, 32])
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#F1F3ED")), ("TEXTCOLOR", (0,0), (-1,0), colors.HexColor("#555555")), ("FONTNAME", (0,0), (-1,-1), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,0), 8), ("FONTSIZE", (0,1), (-1,1), 17), ("BOTTOMPADDING", (0,0), (-1,-1), 9), ("LEFTPADDING", (0,0), (-1,-1), 12)]))
    story += [table, P("Traffic summary", "HeadingN"), P(f"Protocols: {', '.join(f'{k} {v}' for k,v in s['protocols'].items()) or 'none'}  |  Distinct destination ports: {s['distinct_ports']}  |  Duration: {s['duration_seconds'] if s['duration_seconds'] is not None else 'unavailable'} s")]
    story += [P("Detection settings", "HeadingN"), P("Port scanning: 8 distinct destination ports from one source. SYN-heavy: 10 unique initial SYN attempts and at most 20% matching response flows. Repeated connections: 6 unique attempts to the same service spanning at least 10 seconds. A unique attempt uses source/destination addresses, ports, and TCP sequence number; retransmissions with the same tuple and sequence number count once. Enabled: " + ", ".join(k.replace('_', ' ') for k,v in data['rules'].items() if v) + ".")]
    story.append(P("Investigation findings", "HeadingN"))
    if not data["findings"]:
        story.append(P("No configured rule threshold was met in the observed capture. This does not establish that the traffic is safe."))
    for finding in data["findings"]:
        story.append(KeepTogether([P(f"{finding['id']}  /  {finding['title']}", "HeadingN"), P(f"Rule: {finding['rule']}  |  {finding['source']} → {finding['destination']}"), P(finding['details']), P(finding['rationale']), P("Evidence packet indices: " + (", ".join(map(str, finding['evidence'])) or "none") + f" ({finding['evidence_total']} total relevant attempts)"), P("Caution: " + finding["limitation"], "SmallN")]))
    story += [P("Methodology and limits", "HeadingN"), P("NetTrace reads the selected capture locally and stores extracted packet metadata, findings, and a SHA-256 digest; packet payloads and original capture bytes are not retained in investigation history. Packet indices refer to capture order. Detection rules are heuristics and findings are indicators for review, not proof of an attack. Capture loss, truncation, encryption, and missing reverse traffic affect interpretation. IPv4 and IPv6 addresses are extracted when present; unsupported link-layer frames may not yield IP metadata. A SHA-256 digest identifies byte changes but does not independently prove authenticity or completeness.")]
    def footer(canvas, document):
        canvas.setStrokeColor(colors.HexColor("#CCCCCC")); canvas.line(48, 45, 547, 45)
        canvas.setFont("Helvetica", 8); canvas.setFillColor(colors.HexColor("#555555"))
        canvas.drawString(48, 31, "NETTRACE  /  Offline packet investigation")
        canvas.drawRightString(547, 31, f"Page {document.page}")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
