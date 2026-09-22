// PDF deliverable export (Task 58, spec §6.6).
//
// Two templates render from the SAME normalized view model:
//   * Executive  — cover, score gauge, severity breakdown, top findings, and
//                  plain-language summary sentences.
//   * Technical  — per-host and per-check sections with evidence ±3 context
//                  windows, fallback logs, repro commands, references, impact,
//                  remediation, and severity badges.
//
// All free text already passed through the shared redactor in the view model,
// so no un-redacted evidence/secret can reach a rendered document.

import PDFDocument from "pdfkit";
import {
  SEVERITY_ARGB,
  type ExportEvidenceBlock,
  type ExportFinding,
  type ExportTemplate,
  type ExportViewModel,
} from "./viewmodel";

const MARGIN = 50;
const BROKEN_STATUSES = new Set(["NonCompliant", "DegradedPartial", "Error"]);
const INK = "#111827";
const MUTED = "#4B5563";
const RULE = "#D1D5DB";

function contentWidth(doc: PDFKit.PDFDocument): number {
  return doc.page.width - MARGIN * 2;
}

function severityHex(severity: string): string {
  return `#${(SEVERITY_ARGB[severity] ?? "FF7F7F7F").slice(2)}`;
}

function scoreColor(score: number): string {
  if (score >= 80) return "#2E7D32";
  if (score >= 60) return "#F9A825";
  if (score >= 40) return "#E8590C";
  return "#C00000";
}

function ensureSpace(doc: PDFKit.PDFDocument, needed: number): void {
  if (doc.y + needed > doc.page.height - MARGIN) doc.addPage();
}

function sectionHeading(doc: PDFKit.PDFDocument, text: string, size = 14): void {
  ensureSpace(doc, size + 20);
  doc.moveDown(0.6);
  doc.font("Helvetica-Bold").fontSize(size).fillColor(INK);
  doc.text(text, { width: contentWidth(doc) });
  const y = doc.y + 2;
  doc.moveTo(MARGIN, y).lineTo(MARGIN + contentWidth(doc), y).strokeColor(RULE).lineWidth(0.7).stroke();
  doc.moveDown(0.5);
}

function paragraph(doc: PDFKit.PDFDocument, text: string, options: { size?: number; color?: string; bold?: boolean } = {}): void {
  if (!text) return;
  ensureSpace(doc, 18);
  doc
    .font(options.bold ? "Helvetica-Bold" : "Helvetica")
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

function drawBadge(doc: PDFKit.PDFDocument, label: string, severity: string): number {
  const paddingX = 7;
  const height = 15;
  doc.font("Helvetica-Bold").fontSize(8);
  const width = Math.max(doc.widthOfString(label.toUpperCase()) + paddingX * 2, 52);
  const x = MARGIN;
  const y = doc.y;
  doc.save();
  doc.roundedRect(x, y, width, height, 3).fill(severityHex(severity));
  doc.fillColor("#FFFFFF").text(label.toUpperCase(), x, y + 4, { width, align: "center", lineBreak: false });
  doc.restore();
  doc.fillColor(INK);
  doc.x = MARGIN;
  // `text` advanced the cursor; reset it so callers can place the title
  // beside the badge rather than underneath it.
  doc.y = y;
  return width;
}

function drawScoreGauge(doc: PDFKit.PDFDocument, score: number): void {
  ensureSpace(doc, 64);
  const width = contentWidth(doc);
  const height = 16;
  const x = MARGIN;
  const y = doc.y + 22;
  doc.font("Helvetica-Bold").fontSize(22).fillColor(scoreColor(score));
  doc.text(`${score.toFixed(1)} / 100`, x, y - 26, { width, align: "right" });
  doc.roundedRect(x, y, width, height, 8).fill("#E5E7EB");
  const fraction = Math.max(0, Math.min(100, score)) / 100;
  if (fraction > 0) {
    doc.roundedRect(x, y, Math.max(width * fraction, 6), height, 8).fill(scoreColor(score));
  }
  doc.y = y + height + 12;
}

function brokenFindings(viewModel: ExportViewModel): ExportFinding[] {
  return viewModel.findings.filter((finding) => BROKEN_STATUSES.has(finding.status));
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
    paragraph(doc, "Fallback log:", { size: 9, bold: true });
    for (const entry of finding.fallbackLog) {
      paragraph(doc, `- ${entry.source} => ${entry.outcome}`, { size: 8, color: MUTED });
    }
  }

  if (finding.repro) {
    ensureSpace(doc, 30);
    paragraph(doc, "Reproduce (read-only):", { size: 9, bold: true });
    doc.font("Courier").fontSize(8).fillColor("#1F2937").text(finding.repro, { width: contentWidth(doc) });
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
    ensureSpace(doc, 11);
    const gutter = line.lineNumber !== null ? `${String(line.lineNumber).padStart(6)} | ` : "       | ";
    doc
      .font("Courier")
      .fontSize(8)
      .fillColor(line.offending ? "#B91C1C" : "#374151")
      .text(`${gutter}${line.text}`, { width: contentWidth(doc) });
  }
  doc.fillColor(INK);
  doc.moveDown(0.3);
}

function renderExecutive(doc: PDFKit.PDFDocument, viewModel: ExportViewModel): void {
  sectionHeading(doc, viewModel.title, 20);
  paragraph(doc, "Executive Summary", { size: 13, bold: true, color: MUTED });
  paragraph(doc, `Generated ${viewModel.generatedAt}`, { size: 9, color: MUTED });
  paragraph(
    doc,
    `Scope: ${viewModel.scope.kind}${viewModel.scope.campaignName ? ` · ${viewModel.scope.campaignName}` : ""}`,
    { size: 9, color: MUTED },
  );
  paragraph(doc, "Confidential — prepared for the commissioning client. Contains redacted security findings.", {
    size: 9,
    color: MUTED,
  });

  sectionHeading(doc, "Weighted Risk Score");
  drawScoreGauge(doc, viewModel.kpis.riskScore);
  paragraph(
    doc,
    `Evidence coverage ${viewModel.kpis.coverage.toFixed(1)}% · ${viewModel.kpis.totalFindings} findings across ${viewModel.kpis.hostCount} host(s).`,
  );

  sectionHeading(doc, "Severity Breakdown");
  for (const severity of Object.keys(viewModel.kpis.severity)) {
    const total = viewModel.kpis.severity[severity] ?? 0;
    const failing = viewModel.kpis.failingSeverity[severity] ?? 0;
    if (total === 0 && failing === 0) continue;
    paragraph(doc, `${severity}: ${total} total (${failing} failing/degraded)`, {
      size: 10,
      color: severityHex(severity),
      bold: true,
    });
  }

  sectionHeading(doc, "Key Metrics");
  bullet(doc, `Open findings: ${viewModel.kpis.openFindings} (${viewModel.kpis.openCriticals} Critical)`);
  bullet(doc, `Scan reports in scope: ${viewModel.kpis.totalReports}`);
  bullet(doc, `Distinct standard references: ${viewModel.kpis.referenceCount}`);
  for (const [state, count] of Object.entries(viewModel.kpis.treatment)) {
    bullet(doc, `Treatment ${state}: ${count}`);
  }

  const top = brokenFindings(viewModel).slice(0, 10);
  if (top.length > 0) {
    sectionHeading(doc, "Top Findings");
    for (const finding of top) {
      ensureSpace(doc, 42);
      const badgeWidth = drawBadge(doc, finding.severity, finding.severity);
      const startY = doc.y;
      doc
        .font("Helvetica-Bold")
        .fontSize(10)
        .fillColor(INK)
        .text(`${finding.checkId} — ${finding.title}`, MARGIN + badgeWidth + 8, startY + 2, {
          width: contentWidth(doc) - badgeWidth - 8,
        });
      doc.y = Math.max(doc.y, startY + 16);
      doc.x = MARGIN;
      paragraph(doc, `${finding.hostname} · ${finding.status}`, { size: 8, color: MUTED });
      if (finding.recommendation) paragraph(doc, finding.recommendation, { size: 8 });
      doc.moveDown(0.3);
    }
  }

  sectionHeading(doc, "Plain-Language Summary");
  for (const sentence of viewModel.summary) bullet(doc, sentence);

  sectionHeading(doc, "References");
  if (viewModel.references.length === 0) {
    paragraph(doc, "No standard references were mapped in this scope.", { size: 9, color: MUTED });
  } else {
    for (const reference of viewModel.references.slice(0, 100)) {
      paragraph(doc, `${reference.reference} (${reference.standard}) — ${reference.count} finding(s), ${reference.nonCompliant} non-compliant`, {
        size: 8,
        color: MUTED,
      });
    }
  }
}

function renderTechnical(doc: PDFKit.PDFDocument, viewModel: ExportViewModel): void {
  sectionHeading(doc, viewModel.title, 18);
  paragraph(doc, "Technical Audit Report", { size: 13, bold: true, color: MUTED });
  paragraph(doc, `Generated ${viewModel.generatedAt}`, { size: 9, color: MUTED });
  paragraph(
    doc,
    `Scope: ${viewModel.scope.kind}${viewModel.scope.campaignName ? ` · ${viewModel.scope.campaignName}` : ""} · Risk score ${viewModel.kpis.riskScore.toFixed(1)}/100 · Coverage ${viewModel.kpis.coverage.toFixed(1)}%`,
    { size: 9, color: MUTED },
  );

  sectionHeading(doc, "Findings by Host");
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
      paragraph(doc, `${reference.reference} (${reference.standard}) — ${reference.count} finding(s), ${reference.nonCompliant} non-compliant, ${reference.hosts} host(s)`, {
        size: 8,
        color: MUTED,
      });
    }
  }

  sectionHeading(doc, "Executive Summary", 15);
  for (const sentence of viewModel.summary) bullet(doc, sentence);
}

/** Render a PDF for the given template. Pure: returns the document bytes. */
export function renderPdf(viewModel: ExportViewModel, template: ExportTemplate = "technical"): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: "A4",
        margins: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN },
        compress: true,
        info: {
          Title: `${viewModel.title} — ${template === "executive" ? "Executive Summary" : "Technical Audit"}`,
          Author: "HBS Security Review Platform",
          Subject: template === "executive" ? "Executive Summary" : "Technical Audit",
          Keywords: `HBS-EXPORT-MARKER-${template}`,
          CreationDate: new Date(viewModel.generatedAt),
        },
      });
      const chunks: Buffer[] = [];
      doc.on("data", (chunk: Buffer) => chunks.push(chunk));
      doc.on("end", () => resolve(Buffer.concat(chunks)));
      doc.on("error", reject);

      if (template === "executive") renderExecutive(doc, viewModel);
      else renderTechnical(doc, viewModel);

      doc.end();
    } catch (error) {
      reject(error);
    }
  });
}
