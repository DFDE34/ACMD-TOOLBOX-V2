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
        fontName='Courier', fontSize=8, leading=10,
        textColor=colors.HexColor('#1a1a1a'),
        backColor=colors.HexColor('#f6f8fa'),
    ))
    styles.add(ParagraphStyle(
        name='ACMDMeta', parent=styles['Normal'],
        fontSize=9, textColor=colors.HexColor('#57606a')
    ))
    return styles


STATUS_COLORS = {
    'completed': colors.HexColor('#1a7f37'),
    'failed':    colors.HexColor('#cf222e'),
    'running':   colors.HexColor('#9a6700'),
    'pending':   colors.HexColor('#57606a'),
}


def _status_color(status):
    c = STATUS_COLORS.get(status, colors.grey)
    return c.hexval()


def _truncate(text, limit=1500):
    text = str(text or '')
    if len(text) > limit:
        return text[:limit] + '\n[... tronqué — voir le résultat complet dans l\'application ...]'
    return text


def _safe(text):
    text = '' if text is None else str(text)
    return (text.replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;'))


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
        scans = [s for s in scans if target_filter.lower() in (s.get('target') or '').lower()]
        workflow_runs = [w for w in workflow_runs if target_filter.lower() in (w.get('target') or '').lower()]
        history = [h for h in history if target_filter.lower() in (h.get('input') or '').lower()]

    # ── Page de garde ────────────────────────────────────────────────────
    story.append(Spacer(1, 4 * cm))
    story.append(Paragraph('ACMD TOOLBOX V2', styles['ACMDTitle']))
    story.append(Paragraph('Rapport de tests de sécurité / pentest', styles['ACMDSubtitle']))
    story.append(Spacer(1, 1 * cm))
    story.append(HRFlowable(width='100%', color=colors.HexColor('#1f6feb'), thickness=1.5))
    story.append(Spacer(1, 0.6 * cm))

    meta_rows = [
        ['Généré par', username],
        ['Date de génération', datetime.now().strftime('%d/%m/%Y %H:%M')],
        ['Cible filtrée', target_filter or 'Toutes les cibles'],
        ['Scans inclus', str(len(scans))],
        ['Workflows inclus', str(len(workflow_runs))],
        ['Entrées d\'historique', str(len(history))],
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

    # ── 1. Synthèse ──────────────────────────────────────────────────────
    story.append(Paragraph('1. Synthèse', styles['ACMDH1']))

    completed = len([s for s in scans if s.get('status') == 'completed'])
    failed = len([s for s in scans if s.get('status') == 'failed'])
    targets = sorted({s.get('target') for s in scans if s.get('target')})
    tools_used = sorted({s.get('tool_name') for s in scans if s.get('tool_name')})

    summary_rows = [
        ['Indicateur', 'Valeur'],
        ['Scans exécutés', str(len(scans))],
        ['Scans réussis', str(completed)],
        ['Scans en échec', str(failed)],
        ['Cibles distinctes analysées', str(len(targets))],
        ['Outils utilisés', ', '.join(tools_used) if tools_used else '—'],
        ['Workflows exécutés', str(len(workflow_runs))],
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
        story.append(Paragraph('Cibles concernées : ' + ', '.join(_safe(t) for t in targets), styles['ACMDMeta']))

    # ── 2. Détail des scans ──────────────────────────────────────────────
    if scope in ('all', 'scans') and scans:
        story.append(PageBreak())
        story.append(Paragraph('2. Détail des scans', styles['ACMDH1']))

        for s in scans:
            block = []
            header = (f"<b>{_safe(s.get('tool_name'))}</b> &rarr; "
                      f"cible : <b>{_safe(s.get('target'))}</b>")
            block.append(Paragraph(header, styles['ACMDH2']))

            status = s.get('status', 'pending')
            status_color = _status_color(status)
            meta = (f"Statut : <font color='{status_color}'><b>{status.upper()}</b></font> &nbsp;|&nbsp; "
                    f"Options : {_safe(s.get('options') or '—')} &nbsp;|&nbsp; "
                    f"Lancé le : {_safe(s.get('started_at') or s.get('created_at') or '—')}")
            block.append(Paragraph(meta, styles['ACMDMeta']))
            block.append(Spacer(1, 0.15 * cm))

            output = s.get('output') or s.get('error') or '(aucune sortie enregistrée)'
            block.append(Paragraph(_safe(_truncate(output)).replace('\n', '<br/>'), styles['ACMDMono']))
            block.append(Spacer(1, 0.4 * cm))
            block.append(HRFlowable(width='100%', color=colors.HexColor('#d0d7de'), thickness=0.5))
            block.append(Spacer(1, 0.3 * cm))

            story.append(KeepTogether(block[:3]))
            story.extend(block[3:])

    # ── 3. Workflows exécutés ────────────────────────────────────────────
    if scope in ('all', 'workflows') and workflow_runs:
        story.append(PageBreak())
        story.append(Paragraph('3. Workflows exécutés', styles['ACMDH1']))

        for w in workflow_runs:
            status = w.get('status', 'pending')
            status_color = _status_color(status)
            header = (f"<b>{_safe(w.get('wf_name', 'Workflow'))}</b>"
                      f" sur cible <b>{_safe(w.get('target'))}</b>")
            story.append(Paragraph(header, styles['ACMDH2']))
            meta = (f"Statut global : <font color='{status_color}'><b>{status.upper()}</b></font>"
                    f" &nbsp;|&nbsp; Étapes : {w.get('total_steps', 0)}"
                    f" &nbsp;|&nbsp; Terminé le : {_safe(w.get('finished_at') or '—')}")
            story.append(Paragraph(meta, styles['ACMDMeta']))
            story.append(Spacer(1, 0.2 * cm))

            try:
                results = json.loads(w.get('results') or '[]')
            except Exception:
                results = []

            if results:
                rows = [['#', 'Outil', 'Statut', 'Résultat (extrait)']]
                for r in results:
                    excerpt = (r.get('output') or r.get('error') or '')[:150].replace('\n', ' ')
                    rows.append([
                        str(r.get('step', '')),
                        _safe(r.get('tool', r.get('label', ''))),
                        r.get('status', ''),
                        _safe(excerpt),
                    ])
                t = Table(rows, colWidths=[1 * cm, 3.5 * cm, 2.5 * cm, 8 * cm])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#24292f')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 7.5),
                    ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#d0d7de')),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f6f8fa')]),
                ]))
                story.append(t)
            story.append(Spacer(1, 0.6 * cm))

    # ── 4. Historique des opérations ─────────────────────────────────────
    if scope in ('all', 'history') and history:
        story.append(PageBreak())
        story.append(Paragraph('4. Historique des opérations', styles['ACMDH1']))

        rows = [['Date', 'Outil', 'Entrée', 'Résultat (extrait)']]
        for h in history[:200]:
            rows.append([
                _safe((h.get('created_at') or '')[:16]),
                _safe(h.get('tool') or ''),
                _safe((h.get('input') or '')[:40]),
                _safe((h.get('output') or '')[:80]),
            ])
        t = Table(rows, colWidths=[3 * cm, 3 * cm, 4 * cm, 5 * cm], repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#24292f')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#d0d7de')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f6f8fa')]),
        ]))
        story.append(t)

    # ── 5. Notes de l'analyste ───────────────────────────────────────────
    if scope == 'all' and notes:
        story.append(PageBreak())
        story.append(Paragraph('5. Notes de l\'analyste', styles['ACMDH1']))
        for n in notes:
            story.append(Paragraph(f"<b>{_safe(n.get('title') or 'Sans titre')}</b>", styles['ACMDH2']))
            story.append(Paragraph(_safe(n.get('content') or '').replace('\n', '<br/>'), styles['Normal']))
            story.append(Spacer(1, 0.4 * cm))

    # ── Pied de page ─────────────────────────────────────────────────────
    def _footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont('Helvetica', 7.5)
        canvas.setFillColor(colors.HexColor('#8c959f'))
        canvas.drawString(2 * cm, 1.2 * cm,
                          'ACMD Toolbox V2 — Rapport généré automatiquement, à usage interne / pédagogique.')
        canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f'Page {doc_.page}')
        canvas.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    buf.seek(0)
    return buf
