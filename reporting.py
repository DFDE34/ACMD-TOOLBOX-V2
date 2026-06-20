import io
import json
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.enums import TA_CENTER

# Caractères de boîte ASCII → remplacements lisibles en Latin-1
_BOX_MAP = str.maketrans({
    '╔': '+', '╗': '+', '╚': '+', '╝': '+', '╠': '+', '╣': '+',
    '╦': '+', '╩': '+', '╬': '+', '║': '|', '═': '-',
    '┌': '+', '┐': '+', '└': '+', '┘': '+', '├': '+', '┤': '+',
    '┬': '+', '┴': '+', '┼': '+', '│': '|', '─': '-',
    '✓': '[OK]', '✗': '[KO]', '✕': '[X]', '●': '*', '○': 'o',
    '▶': '>', '◀': '<', '»': '>>', '«': '<<',
})


def _clean(text, limit=None):
    """
    Nettoie le texte pour ReportLab (polices Latin-1 uniquement) :
    - Remplace les caractères de boîte ASCII par des équivalents ASCII
    - Supprime les caractères non encodables en Latin-1
    - Tronque si limit est précisé
    """
    text = str(text or '').translate(_BOX_MAP)
    result = []
    for ch in text:
        try:
            ch.encode('latin-1')
            result.append(ch)
        except (UnicodeEncodeError, UnicodeDecodeError):
            result.append('?')
    text = ''.join(result)
    if limit and len(text) > limit:
        text = text[:limit] + ' [...]'
    return text


def _safe(text):
    """Échappe pour XML/Paragraph ReportLab (après _clean)."""
    text = _clean(text)
    return (text.replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;'))


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name='ACMDTitle', parent=styles['Title'],
        fontSize=24, textColor=colors.HexColor('#0d1117'),
        spaceAfter=6, alignment=TA_CENTER
    ))
    styles.add(ParagraphStyle(
        name='ACMDSubtitle', parent=styles['Normal'],
        fontSize=11, textColor=colors.HexColor('#57606a'),
        alignment=TA_CENTER, spaceAfter=20
    ))
    styles.add(ParagraphStyle(
        name='ACMDH1', parent=styles['Heading1'],
        fontSize=15, textColor=colors.white,
        backColor=colors.HexColor('#1f6feb'),
        spaceBefore=14, spaceAfter=10,
        leftIndent=6, leading=22
    ))
    styles.add(ParagraphStyle(
        name='ACMDH2', parent=styles['Heading2'],
        fontSize=12, textColor=colors.HexColor('#0d1117'),
        spaceBefore=10, spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        name='ACMDMono', parent=styles['Normal'],
        fontName='Courier', fontSize=8, leading=11,
        textColor=colors.HexColor('#1a1a1a'),
        backColor=colors.HexColor('#f6f8fa'),
        wordWrap='LTR',
    ))
    styles.add(ParagraphStyle(
        name='ACMDMeta', parent=styles['Normal'],
        fontSize=9, textColor=colors.HexColor('#57606a')
    ))
    styles.add(ParagraphStyle(
        name='TCell', parent=styles['Normal'],
        fontSize=7.5, leading=10, wordWrap='LTR',
        spaceAfter=0, spaceBefore=0,
    ))
    styles.add(ParagraphStyle(
        name='TCellMono', parent=styles['Normal'],
        fontName='Courier', fontSize=7, leading=9,
        wordWrap='LTR', spaceAfter=0, spaceBefore=0,
        textColor=colors.HexColor('#1a1a1a'),
    ))
    return styles


STATUS_COLORS = {
    'completed': colors.HexColor('#1a7f37'),
    'failed':    colors.HexColor('#cf222e'),
    'running':   colors.HexColor('#9a6700'),
    'pending':   colors.HexColor('#57606a'),
}


def _status_color(status):
    return STATUS_COLORS.get(status, colors.grey).hexval()


def generate_pdf_report(username, scans, workflow_runs, history, notes,
                        scope='all', target_filter=None):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm,
        leftMargin=2 * cm, rightMargin=2 * cm,
        title=f'Rapport ACMD Toolbox - {username}'
    )
    styles = _build_styles()
    story = []

    # Filtrage par cible
    if target_filter:
        scans = [s for s in scans
                 if target_filter.lower() in (s.get('target') or '').lower()]
        workflow_runs = [w for w in workflow_runs
                         if target_filter.lower() in (w.get('target') or '').lower()]
        history = [h for h in history
                   if target_filter.lower() in (h.get('input') or '').lower()]

    # ── Page de garde ────────────────────────────────────────────────────
    story.append(Spacer(1, 4 * cm))
    story.append(Paragraph('ACMD TOOLBOX V2', styles['ACMDTitle']))
    story.append(Paragraph('Rapport de tests de securite / pentest', styles['ACMDSubtitle']))
    story.append(Spacer(1, 1 * cm))
    story.append(HRFlowable(width='100%', color=colors.HexColor('#1f6feb'), thickness=1.5))
    story.append(Spacer(1, 0.6 * cm))

    meta_rows = [
        ['Genere par', _clean(username)],
        ['Date de generation', datetime.now().strftime('%d/%m/%Y %H:%M')],
        ['Cible filtree', _clean(target_filter) if target_filter else 'Toutes les cibles'],
        ['Scans inclus', str(len(scans))],
        ['Workflows inclus', str(len(workflow_runs))],
        ["Entrees d'historique", str(len(history))],
    ]
    meta_table = Table(meta_rows, colWidths=[6 * cm, 9 * cm])
    meta_table.setStyle(TableStyle([
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#57606a')),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#d0d7de')),
    ]))
    story.append(meta_table)
    story.append(PageBreak())

    # ── 1. Synthese ──────────────────────────────────────────────────────
    story.append(Paragraph('1. Synthese', styles['ACMDH1']))

    completed  = len([s for s in scans if s.get('status') == 'completed'])
    failed     = len([s for s in scans if s.get('status') == 'failed'])
    targets    = sorted({s.get('target') for s in scans if s.get('target')})
    tools_used = sorted({s.get('tool_name') for s in scans if s.get('tool_name')})

    summary_rows = [
        ['Indicateur', 'Valeur'],
        ['Scans executes', str(len(scans))],
        ['Scans reussis', str(completed)],
        ['Scans en echec', str(failed)],
        ['Cibles distinctes analysees', str(len(targets))],
        ['Outils utilises', ', '.join(_clean(t) for t in tools_used) if tools_used else '-'],
        ['Workflows executes', str(len(workflow_runs))],
    ]
    summary_table = Table(summary_rows, colWidths=[7 * cm, 8 * cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f6feb')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9.5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#d0d7de')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f6f8fa')]),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(summary_table)
    if targets:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            'Cibles concernees : ' + ', '.join(_safe(t) for t in targets),
            styles['ACMDMeta']
        ))

    # ── 2. Detail des scans ──────────────────────────────────────────────
    if scope in ('all', 'scans') and scans:
        story.append(PageBreak())
        story.append(Paragraph('2. Detail des scans', styles['ACMDH1']))

        for s in scans:
            block = []
            header = (f"<b>{_safe(s.get('tool_name'))}</b> -&gt; "
                      f"cible : <b>{_safe(s.get('target'))}</b>")
            block.append(Paragraph(header, styles['ACMDH2']))

            status = s.get('status', 'pending')
            sc = _status_color(status)
            meta = (f"Statut : <font color='{sc}'><b>{status.upper()}</b></font>"
                    f" | Options : {_safe(s.get('options') or '-')}"
                    f" | Lance le : {_safe(s.get('started_at') or s.get('created_at') or '-')}")
            block.append(Paragraph(meta, styles['ACMDMeta']))
            block.append(Spacer(1, 0.15 * cm))

            raw_out = s.get('output') or s.get('error') or '(aucune sortie enregistree)'
            cleaned = _clean(raw_out, limit=2000)
            block.append(Paragraph(
                _safe(cleaned).replace('\n', '<br/>'),
                styles['ACMDMono']
            ))
            block.append(Spacer(1, 0.4 * cm))
            block.append(HRFlowable(width='100%', color=colors.HexColor('#d0d7de'), thickness=0.5))
            block.append(Spacer(1, 0.3 * cm))

            story.append(KeepTogether(block[:3]))
            story.extend(block[3:])

    # ── 3. Workflows executes ────────────────────────────────────────────
    if scope in ('all', 'workflows') and workflow_runs:
        story.append(PageBreak())
        story.append(Paragraph('3. Workflows executes', styles['ACMDH1']))

        # Styles pour les cellules du tableau workflow
        cell  = styles['TCell']
        cmono = styles['TCellMono']

        for w in workflow_runs:
            status = w.get('status', 'pending')
            sc = _status_color(status)
            header = (f"<b>{_safe(w.get('wf_name', 'Workflow'))}</b>"
                      f" sur cible <b>{_safe(w.get('target'))}</b>")
            story.append(Paragraph(header, styles['ACMDH2']))
            meta = (f"Statut global : <font color='{sc}'><b>{status.upper()}</b></font>"
                    f" | Etapes : {w.get('total_steps', 0)}"
                    f" | Termine le : {_safe(w.get('finished_at') or '-')}")
            story.append(Paragraph(meta, styles['ACMDMeta']))
            story.append(Spacer(1, 0.2 * cm))

            try:
                results = json.loads(w.get('results') or '[]')
            except Exception:
                results = []

            if results:
                # En-têtes
                header_row = [
                    Paragraph('<b>#</b>', cell),
                    Paragraph('<b>Outil</b>', cell),
                    Paragraph('<b>Statut</b>', cell),
                    Paragraph('<b>Resultat (extrait)</b>', cell),
                ]
                rows = [header_row]
                for r in results:
                    excerpt = _clean(r.get('output') or r.get('error') or '', limit=200)
                    # Supprime les lignes de séparation de boîte redondantes
                    excerpt = ' '.join(
                        ln.strip() for ln in excerpt.splitlines()
                        if ln.strip() and not set(ln.strip()) <= set('+-|=')
                    )
                    rst = r.get('status', '')
                    rst_color = _status_color(rst)
                    rows.append([
                        Paragraph(_safe(str(r.get('step', ''))), cell),
                        Paragraph(_safe(r.get('tool', r.get('label', ''))), cell),
                        Paragraph(
                            f"<font color='{rst_color}'><b>{rst.upper()}</b></font>",
                            cell
                        ),
                        Paragraph(_safe(excerpt), cmono),
                    ])

                # Largeurs : #, Outil, Statut, Résultat
                t = Table(rows, colWidths=[0.8 * cm, 3.5 * cm, 2.2 * cm, 9 * cm])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#24292f')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTSIZE', (0, 0), (-1, -1), 7.5),
                    ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#d0d7de')),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                     [colors.white, colors.HexColor('#f6f8fa')]),
                ]))
                story.append(t)
            story.append(Spacer(1, 0.6 * cm))

    # ── 4. Historique des operations ─────────────────────────────────────
    if scope in ('all', 'history') and history:
        story.append(PageBreak())
        story.append(Paragraph("4. Historique des operations", styles['ACMDH1']))

        cell  = styles['TCell']
        cmono = styles['TCellMono']

        header_row = [
            Paragraph('<b>Date</b>', cell),
            Paragraph('<b>Outil</b>', cell),
            Paragraph('<b>Entree</b>', cell),
            Paragraph('<b>Resultat (extrait)</b>', cell),
        ]
        rows = [header_row]
        for h in history[:200]:
            rows.append([
                Paragraph(_safe((h.get('created_at') or '')[:16]), cell),
                Paragraph(_safe(h.get('tool') or ''), cell),
                Paragraph(_safe(_clean(h.get('input') or '', limit=50)), cell),
                Paragraph(_safe(_clean(h.get('output') or '', limit=100)), cmono),
            ])
        t = Table(rows,
                  colWidths=[3 * cm, 3 * cm, 4 * cm, 5.5 * cm],
                  repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#24292f')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#d0d7de')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.white, colors.HexColor('#f6f8fa')]),
        ]))
        story.append(t)

    # ── 5. Notes de l'analyste ───────────────────────────────────────────
    if scope == 'all' and notes:
        story.append(PageBreak())
        story.append(Paragraph("5. Notes de l'analyste", styles['ACMDH1']))
        for n in notes:
            story.append(Paragraph(
                f"<b>{_safe(n.get('title') or 'Sans titre')}</b>",
                styles['ACMDH2']
            ))
            story.append(Paragraph(
                _safe(_clean(n.get('content') or '')).replace('\n', '<br/>'),
                styles['Normal']
            ))
            story.append(Spacer(1, 0.4 * cm))

    # ── Pied de page ─────────────────────────────────────────────────────
    def _footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont('Helvetica', 7.5)
        canvas.setFillColor(colors.HexColor('#8c959f'))
        canvas.drawString(
            2 * cm, 1.2 * cm,
            'ACMD Toolbox V2 - Rapport genere automatiquement, a usage interne / pedagogique.'
        )
        canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f'Page {doc_.page}')
        canvas.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    buf.seek(0)
    return buf
