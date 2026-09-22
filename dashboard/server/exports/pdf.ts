// PDF deliverable export (Task 58, spec §6.6).
//
// Two templates render from the SAME normalized view model:
//   * Executive  — cover page with an arc risk gauge, KPI table, severity
//                  breakdown, top 10 findings, plain-language summary, and
//                  references.
//   * Technical  — cover, KPI table, per-host and per-check sections with
//                  evidence ±3 context windows (offending line highlighted),
//                  fallback attempt logs, read-only repro commands, impact,
//                  remediation, and references.
//
// Both templates carry a running page header (report title + campaign), a
// footer with page numbers and the confidentiality line, consistent
// typography, and severity badges. All free text already passed through the
// shared redactor in the view model, so no un-redacted evidence/secret can
// reach a rendered document.

import PDFDocument from "pdfkit";
import {
  campaignLabel,
  describeScopeText,
  scoreHex,
  severityHex,
  severityTextHex,
  SEVERITY_ORDER,
  type ExportEvidenceBlock,
  type ExportFinding,
  type ExportTemplate,
  type ExportViewModel,
} from "./viewmodel";

const MARGIN = 50;
const HEADER_HEIGHT = 18;
const BROKEN_STATUSES = new Set(["NonCompliant", "DegradedPartial", "Error"]);
const INK = "#111827";
const MUTED = "#4B5563";
const RULE = "#D1D5DB";
const MONO = "Courier";

function contentWidth(doc: PDFKit.PDFDocument): number {
  return doc.page.width - MARGIN * 2;
}

function ensureSpace(doc: PDFKit.PDFDocument, needed: number): void {
  if (doc.y + needed > doc.page.height - MARGIN) doc.addPage();
}

// ---------------------------------------------------------------------------
// Running header / footer
// ---------------------------------------------------------------------------

function drawHeader(doc: PDFKit.PDFDocument, viewModel: ExportViewModel): void {
  const y = 28;
  const width = contentWidth(doc);
  doc.font("Helvetica-Bold").fontSize(8).fillColor(MUTED);
  doc.text(viewModel.title, MARGIN, y, { width: width * 0.62, lineBreak: false });
  doc.font("Helvetica").fontSize(8).fillColor(MUTED);
  doc.text(campaignLabel(viewModel.scope), MARGIN, y, { width, align: "right", lineBreak: false });
  const ruleY = y + 12;
  doc.moveTo(MARGIN, ruleY).lineTo(MARGIN + width, ruleY).strokeColor(RULE).lineWidth(0.5).stroke();
  doc.x = MARGIN;
  doc.y = MARGIN + HEADER_HEIGHT - 6;
  doc.fillColor(INK);
}

function drawFooter(
  doc: PDFKit.PDFDocument,
  viewModel: ExportViewModel,
  pageNumber: number,
  pageCount: number,
): void {
  const y = doc.page.height - 40;
  const width = contentWidth(doc);
  doc.moveTo(MARGIN, y - 6).lineTo(MARGIN + width, y - 6).strokeColor(RULE).lineWidth(0.5).stroke();
  doc.font("Helvetica").fontSize(7.5).fillColor(MUTED);
  doc.text(viewModel.confidentiality, MARGIN, y, { width: width * 0.72, lineBreak: false });
  doc.text(`Page ${pageNumber} of ${pageCount}`, MARGIN, y, { width, align: "right", lineBreak: false });
  doc.fillColor(INK);
}

// ---------------------------------------------------------------------------
// Shared drawing primitives
// ---------------------------------------------------------------------------

function sectionHeading(doc: PDFKit.PDFDocument, text: string, size = 14): void {
  ensureSpace(doc, size + 20);
  doc.moveDown(0.5);
  doc.font("Helvetica-Bold").fontSize(size).fillColor(INK);
  doc.text(text, { width: contentWidth(doc) });
  const y = doc.y + 2;
  doc.moveTo(MARGIN, y).lineTo(MARGIN + contentWidth(doc), y).strokeColor(RULE).lineWidth(0.7).stroke();
  doc.moveDown(0.5);
}

function paragraph(
  doc: PDFKit.PDFDocument,
  text: string,
  options: { size?: number; color?: string; bold?: boolean; font?: string } = {},
): void {
  if (!text) return;
  ensureSpace(doc, 18);
  doc
    .font(options.font ?? (options.bold ? "Helvetica-Bold" : "Helvetica"))
    .fontSize(options.size ?? 10)
    .fillColor(options.color ?? INK)
    .text(text, { width: contentWidth(doc) });
}

function bullet(doc: PDFKit.PDFDocument, text: string): void {
  ensureSpace(doc, 16);
  doc.font("Helvetica").fontSize(10).fillColor(INK).text(`•  ${text}`, {
    width: contentWidth(doc),
    indent: 8,
  });
}

/** Label/value rows with a hairline rule, used for the KPI table. */
function drawKeyValueTable(
  doc: PDFKit.PDFDocument,
  rows: readonly (readonly [string, string | number])[],
): void {
  const width = contentWidth(doc);
  const labelWidth = width * 0.58;
  for (const [label, value] of rows) {
    ensureSpace(doc, 20);
    const y = doc.y;
    doc.font("Helvetica").fontSize(9).fillColor(MUTED);
    doc.text(label, MARGIN, y, { width: labelWidth, lineBreak: false });
    doc.font("Helvetica-Bold").fontSize(10).fillColor(INK);
    doc.text(String(value), MARGIN + labelWidth, y, { width: width - labelWidth, align: "right", lineBreak: false });
    const ruleY = y + 14;
    doc.moveTo(MARGIN, ruleY).lineTo(MARGIN + width, ruleY).strokeColor("#EEF2F7").lineWidth(0.5).stroke();
    doc.y = ruleY + 4;
  }
  doc.moveDown(0.4);
}

function drawBadge(doc: PDFKit.PDFDocument, label: string, severity: string): number {
  const paddingX = 7;
  const height = 15;
  doc.font("Helvetica-Bold").fontSize(8);
  const width = Math.max(doc.widthOfString(label.toUpperCase()) + paddingX * 2, 52);
  const x = MARGIN;
  const y = doc.y;
  doc.save();
  doc.roundedRect(x, y, width, height, 3).fill(severityHex(severity));
  doc.fillColor(severityTextHex(severity)).text(label.toUpperCase(), x, y + 4, { width, align: "center", lineBreak: false });
  doc.restore();
  doc.fillColor(INK);
  doc.x = MARGIN;
  // `text` advanced the cursor; reset it so callers can place the title
  // beside the badge rather than underneath it.
  doc.y = y;
  return width;
}

function brokenFindings(viewModel: ExportViewModel): ExportFinding[] {
  return viewModel.findings.filter((finding) => BROKEN_STATUSES.has(finding.status));
}

// ---------------------------------------------------------------------------
// Risk gauge (arc)
// ---------------------------------------------------------------------------

function arcPath(cx: number, cy: number, radius: number, startDeg: number, endDeg: number): string {
  const steps = 72;
  let path = "";
  for (let index = 0; index <= steps; index += 1) {
    const angle = ((startDeg + ((endDeg - startDeg) * index) / steps) * Math.PI) / 180;
    const x = cx + radius * Math.cos(angle);
    const y = cy + radius * Math.sin(angle);
    path += `${index === 0 ? "M" : "L"}${x.toFixed(2)} ${y.toFixed(2)} `;
  }
  return path.trim();
}

function drawRiskGauge(doc: PDFKit.PDFDocument, score: number): void {
  ensureSpace(doc, 130);
  const width = contentWidth(doc);
  const cx = MARGIN + width / 2;
  const radius = Math.min(78, width / 3);
  const cy = doc.y + radius + 14;
  const fraction = Math.max(0, Math.min(100, score)) / 100;
  const color = scoreHex(score);

  doc.path(arcPath(cx, cy, radius, 180, 360)).lineWidth(16).strokeColor("#E5E7EB").stroke();
  if (fraction > 0) {
    doc.path(arcPath(cx, cy, radius, 180, 180 + 180 * fraction)).lineWidth(16).strokeColor(color).stroke();
  }

  // Pointer from the hub to the score angle.
  const angle = ((180 + 180 * fraction) * Math.PI) / 180;
  doc
    .moveTo(cx, cy)
    .lineTo(cx + (radius - 22) * Math.cos(angle), cy + (radius - 22) * Math.sin(angle))
    .strokeColor(color)
    .lineWidth(2)
    .stroke();
  doc.circle(cx, cy, 4).fill(color);

  doc.font("Helvetica-Bold").fontSize(24).fillColor(color);
  doc.text(`${score.toFixed(1)}`, cx - radius, cy - 34, { width: radius * 2, align: "center", lineBreak: false });
  doc.font("Helvetica").fontSize(8).fillColor(MUTED);
  doc.text("weighted risk score (0–100, higher is safer)", cx - radius, cy - 8, {
    width: radius * 2,
    align: "center",
    lineBreak: false,
  });
  doc.font("Helvetica").fontSize(7).fillColor(MUTED);
  doc.text("0", cx - radius - 4, cy + 6, { lineBreak: false });
  doc.text("100", cx + radius - 12, cy + 6, { lineBreak: false });
  doc.y = cy + 22;
  doc.x = MARGIN;
  doc.fillColor(INK);
}

// ---------------------------------------------------------------------------
// Cover page
// ---------------------------------------------------------------------------

function drawCover(doc: PDFKit.PDFDocument, viewModel: ExportViewModel, template: ExportTemplate): void {
  const width = contentWidth(doc);
  const top = 110;
  doc.rect(MARGIN, top, width, 6).fill(template === "executive" ? "#E11D48" : "#0EA5E9");

  doc.font("Helvetica-Bold").fontSize(26).fillColor(INK);
  doc.text(viewModel.title, MARGIN, top + 34, { width });
  doc.font("Helvetica").fontSize(15).fillColor(MUTED);
  doc.text(
    template === "executive" ? "Executive Summary" : "Technical Audit Report",
    MARGIN,
    doc.y + 6,
    { width },
  );

  doc.moveDown(1.4);
  drawKeyValueTable(doc, [
    ["Client", viewModel.client ?? "—"],
    ["Campaign", campaignLabel(viewModel.scope)],
    ["Scope", describeScopeText(viewModel.scope)],
    ["Generated", viewModel.generatedAt],
    ["Prepared by", viewModel.generator],
  ]);

  doc.moveDown(0.6);
  if (template === "executive") {
    drawRiskGauge(doc, viewModel.kpis.riskScore);
  } else {
    drawKeyValueTable(doc, [
      ["Weighted Risk Score", `${viewModel.kpis.riskScore.toFixed(1)} / 100`],
      ["Evidence Coverage", `${viewModel.kpis.coverage.toFixed(1)}%`],
      ["Findings in scope", viewModel.kpis.totalFindings],
      ["Hosts in scope", viewModel.kpis.hostCount],
    ]);
  }

  doc.moveDown(0.8);
  const noticeY = doc.y;
  doc.save();
  doc.roundedRect(MARGIN, noticeY, width, 34, 4).fill("#FFF7ED");
  doc.restore();
  doc.font("Helvetica-Oblique").fontSize(9).fillColor("#9A3412");
  doc.text(viewModel.confidentiality, MARGIN + 8, noticeY + 9, { width: width - 16 });
  doc.y = noticeY + 46;
  doc.x = MARGIN;
  doc.fillColor(INK);
}

// ---------------------------------------------------------------------------
// Executive template
// ---------------------------------------------------------------------------

function renderExecutive(doc: PDFKit.PDFDocument, viewModel: ExportViewModel): void {
  drawCover(doc, viewModel, "executive");
  doc.addPage();

  sectionHeading(doc, "Key Performance Indicators", 14);
  drawKeyValueTable(doc, [
    ["Weighted risk score (0–100)", viewModel.kpis.riskScore],
    ["Evidence coverage (%)", viewModel.kpis.coverage],
    ["Total findings", viewModel.kpis.totalFindings],
    ["Failing / degraded findings", viewModel.kpis.failingFindings],
    ["Open findings", viewModel.kpis.openFindings],
    ["Open Critical findings", viewModel.kpis.openCriticals],
    ["Hosts", viewModel.kpis.hostCount],
    ["Scan reports", viewModel.kpis.totalReports],
    ["Standard references", viewModel.kpis.referenceCount],
  ]);

  sectionHeading(doc, "Severity Breakdown", 14);
  const maxSeverity = Math.max(1, ...SEVERITY_ORDER.map((severity) => viewModel.kpis.severity[severity] ?? 0));
  for (const severity of SEVERITY_ORDER) {
    const total = viewModel.kpis.severity[severity] ?? 0;
    const failing = viewModel.kpis.failingSeverity[severity] ?? 0;
    if (total === 0 && failing === 0) continue;
    ensureSpace(doc, 22);
    const y = doc.y;
    const badgeWidth = drawBadge(doc, severity, severity);
    doc.font("Helvetica").fontSize(9).fillColor(INK);
    doc.text(`${total} total · ${failing} failing/degraded`, MARGIN + badgeWidth + 8, y + 3, {
      width: contentWidth(doc) - badgeWidth - 8,
      lineBreak: false,
    });
    doc.x = MARGIN;
    doc.y = y + 20;
    const barWidth = contentWidth(doc);
    doc.rect(MARGIN, doc.y, barWidth, 6).fill("#EEF2F7");
    if (total > 0) doc.rect(MARGIN, doc.y, barWidth * (total / maxSeverity), 6).fill(severityHex(severity));
    doc.y += 14;
  }

  const top = brokenFindings(viewModel).slice(0, 10);
  if (top.length > 0) {
    sectionHeading(doc, "Top 10 Findings", 14);
    top.forEach((finding, index) => {
      ensureSpace(doc, 44);
      const badgeWidth = drawBadge(doc, finding.severity, finding.severity);
      const startY = doc.y;
      doc
        .font("Helvetica-Bold")
        .fontSize(10)
        .fillColor(INK)
        .text(`${index + 1}. ${finding.checkId} — ${finding.title}`, MARGIN + badgeWidth + 8, startY + 2, {
          width: contentWidth(doc) - badgeWidth - 8,
        });
      doc.y = Math.max(doc.y, startY + 16);
      doc.x = MARGIN;
      paragraph(doc, `${finding.hostname} · ${finding.status} · ${finding.category}`, { size: 8, color: MUTED });
      if (finding.recommendation) paragraph(doc, finding.recommendation, { size: 8 });
      doc.moveDown(0.3);
    });
  }

  sectionHeading(doc, "Plain-Language Summary", 14);
  for (const sentence of viewModel.summary) bullet(doc, sentence);

  sectionHeading(doc, "References", 14);
  if (viewModel.references.length === 0) {
    paragraph(doc, "No standard references were mapped in this scope.", { size: 9, color: MUTED });
  } else {
    for (const reference of viewModel.references.slice(0, 100)) {
      paragraph(
        doc,
        `${reference.reference} (${reference.standard}) — ${reference.count} finding(s), ${reference.nonCompliant} non-compliant`,
        { size: 8, color: MUTED },
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Technical template
// ---------------------------------------------------------------------------

function drawEvidenceBlock(doc: PDFKit.PDFDocument, block: ExportEvidenceBlock): void {
  ensureSpace(doc, 30);
  const header = `${block.path}${block.line !== null ? `:${block.line}${block.col !== null ? `:${block.col}` : ""}` : ""}`;
  paragraph(doc, header, { size: 9, bold: true });
  if (block.fileMode !== null) {
    paragraph(
      doc,
      `mode ${block.fileMode}${block.fileUid !== null ? ` uid ${block.fileUid}` : ""}${block.fileGid !== null ? ` gid ${block.fileGid}` : ""}`,
      { size: 8, color: MUTED },
    );
  }
  for (const line of block.lines) {
    ensureSpace(doc, 12);
    const gutter = line.lineNumber !== null ? `${String(line.lineNumber).padStart(6)} | ` : "       | ";
    if (line.offending) {
      doc.save();
      doc.rect(MARGIN, doc.y - 1, contentWidth(doc), 11).fill("#FEE2E2");
      doc.restore();
      doc.font("Helvetica-Bold").fontSize(8).fillColor("#B91C1C");
    } else {
      doc.font(MONO).fontSize(8).fillColor("#374151");
    }
    doc.text(`${gutter}${line.text}`, { width: contentWidth(doc) });
  }
  doc.fillColor(INK);
  doc.moveDown(0.3);
}

function drawFindingDetail(doc: PDFKit.PDFDocument, finding: ExportFinding): void {
  ensureSpace(doc, 90);
  const badgeWidth = drawBadge(doc, finding.severity, finding.severity);
  const startY = doc.y;
  doc
    .font("Helvetica-Bold")
    .fontSize(11)
    .fillColor(INK)
    .text(`${finding.checkId} — ${finding.title}`, MARGIN + badgeWidth + 8, startY + 3, {
      width: contentWidth(doc) - badgeWidth - 8,
    });
  doc.y = Math.max(doc.y, startY + 18);
  doc.x = MARGIN;

  paragraph(
    doc,
    `Host ${finding.hostname} (${finding.displayId}) · Status ${finding.status} · Category ${finding.category} · Treatment ${finding.treatment} · Evidence depth ${finding.evidenceDepth ?? "unknown"}`,
    { size: 9, color: MUTED },
  );
  if (finding.location) paragraph(doc, `Location: ${finding.location}`, { size: 9 });
  if (finding.description) paragraph(doc, finding.description, { size: 9 });
  if (finding.impact) paragraph(doc, `Impact: ${finding.impact}`, { size: 9 });
  if (finding.degradedReason) paragraph(doc, `Degraded reason: ${finding.degradedReason}`, { size: 9, color: "#B45309" });
  if (finding.evidence) paragraph(doc, `Evidence: ${finding.evidence}`, { size: 9 });

  for (const block of finding.evidenceBlocks) drawEvidenceBlock(doc, block);

  if (finding.fallbackLog.length > 0) {
    ensureSpace(doc, 24);
    paragraph(doc, "Fallback attempt log:", { size: 9, bold: true });
    for (const entry of finding.fallbackLog) {
      paragraph(doc, `- ${entry.source} => ${entry.outcome}`, { size: 8, color: MUTED });
    }
  }

  if (finding.repro) {
    ensureSpace(doc, 30);
    paragraph(doc, "Reproduce (read-only):", { size: 9, bold: true });
    doc.font(MONO).fontSize(8).fillColor("#1F2937").text(finding.repro, { width: contentWidth(doc) });
  }

  if (finding.recommendation) paragraph(doc, `Remediation: ${finding.recommendation}`, { size: 9 });
  if (finding.references.length > 0) {
    paragraph(doc, `References: ${finding.references.join(", ")}`, { size: 8, color: MUTED });
  }
  if (finding.treatmentDueDate || finding.treatmentAssignee) {
    paragraph(
      doc,
      `Treatment owner: ${finding.treatmentAssignee ?? "unassigned"}${finding.treatmentDueDate ? ` · due ${finding.treatmentDueDate}` : ""}`,
      { size: 8, color: MUTED },
    );
  }
  doc.moveDown(0.6);
  doc.moveTo(MARGIN, doc.y).lineTo(MARGIN + contentWidth(doc), doc.y).strokeColor(RULE).lineWidth(0.4).stroke();
  doc.moveDown(0.4);
}

function renderTechnical(doc: PDFKit.PDFDocument, viewModel: ExportViewModel): void {
  drawCover(doc, viewModel, "technical");
  doc.addPage();

  sectionHeading(doc, "Key Performance Indicators", 14);
  drawKeyValueTable(doc, [
    ["Weighted risk score (0–100)", viewModel.kpis.riskScore],
    ["Evidence coverage (%)", viewModel.kpis.coverage],
    ["Total findings", viewModel.kpis.totalFindings],
    ["Failing / degraded findings", viewModel.kpis.failingFindings],
    ["Open findings", viewModel.kpis.openFindings],
    ["Open Critical findings", viewModel.kpis.openCriticals],
    ["Hosts", viewModel.kpis.hostCount],
    ["Scan reports", viewModel.kpis.totalReports],
  ]);

  sectionHeading(doc, "Findings by Host", 14);
  if (viewModel.hosts.length === 0) paragraph(doc, "No hosts matched this scope.", { size: 10, color: MUTED });
  for (const host of viewModel.hosts) {
    doc.addPage();
    sectionHeading(doc, `${host.hostname} (${host.displayId})`, 15);
    paragraph(
      doc,
      [
        host.machineId ? `Machine ID ${host.machineId}` : null,
        host.platform ? `Platform ${host.platform}` : null,
        host.os ? `OS ${host.os}` : null,
        host.arch ? `Arch ${host.arch}` : null,
        host.latestReceivedAt ? `Latest scan ${host.latestReceivedAt}` : null,
        host.riskScore !== null ? `Risk ${host.riskScore.toFixed(1)}/100` : null,
        host.coverage !== null ? `Coverage ${host.coverage.toFixed(1)}%` : null,
      ]
        .filter((part): part is string => part !== null)
        .join(" · "),
      { size: 9, color: MUTED },
    );
    for (const finding of host.findings) drawFindingDetail(doc, finding);
  }

  doc.addPage();
  sectionHeading(doc, "Findings by Check", 15);
  for (const check of viewModel.checks) {
    ensureSpace(doc, 40);
    paragraph(doc, `${check.checkId} — ${check.title}`, { size: 10, bold: true, color: severityHex(check.severity) });
    paragraph(
      doc,
      `Severity ${check.severity} · ${check.findingCount} finding(s) on ${check.hostCount} host(s)${check.references.length > 0 ? ` · ${check.references.join(", ")}` : ""}`,
      { size: 8, color: MUTED },
    );
  }

  if (viewModel.references.length > 0) {
    sectionHeading(doc, "Standard References", 15);
    for (const reference of viewModel.references) {
      paragraph(
        doc,
        `${reference.reference} (${reference.standard}) — ${reference.count} finding(s), ${reference.nonCompliant} non-compliant, ${reference.hosts} host(s)`,
        { size: 8, color: MUTED },
      );
    }
  }

  sectionHeading(doc, "Executive Summary", 15);
  for (const sentence of viewModel.summary) bullet(doc, sentence);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/** Render a PDF for the given template. Pure: returns the document bytes. */
export function renderPdf(
  viewModel: ExportViewModel,
  template: ExportTemplate = "technical",
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: "A4",
        margins: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN },
        bufferPages: true,
        compress: false,
        info: {
          Title: `${viewModel.title} — ${template === "executive" ? "Executive Summary" : "Technical Audit"}`,
          Author: viewModel.generator,
          Subject: template === "executive" ? "Executive Summary" : "Technical Audit",
          Keywords: [
            `HBS-EXPORT-MARKER-${template}`,
            "HBS-COVER-PAGE",
            "HBS-PAGE-FOOTER",
            `risk=${viewModel.kpis.riskScore}`,
            `coverage=${viewModel.kpis.coverage}`,
            `findings=${viewModel.kpis.totalFindings}`,
          ].join("; "),
          CreationDate: new Date(viewModel.generatedAt),
        },
      });
      const chunks: Buffer[] = [];
      doc.on("data", (chunk: Buffer) => chunks.push(chunk));
      doc.on("end", () => resolve(Buffer.concat(chunks)));
      doc.on("error", reject);

      doc.on("pageAdded", () => drawHeader(doc, viewModel));

      if (template === "executive") renderExecutive(doc, viewModel);
      else renderTechnical(doc, viewModel);

      // Stamp the footer (page numbers + confidentiality) on every buffered
      // page now that the final page count is known.
      const range = doc.bufferedPageRange();
      for (let index = range.start; index < range.start + range.count; index += 1) {
        doc.switchToPage(index);
        drawFooter(doc, viewModel, index - range.start + 1, range.count);
      }

      doc.end();
    } catch (error) {
      reject(error);
    }
  });
}
