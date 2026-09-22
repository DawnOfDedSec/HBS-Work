// Editable Word deliverable export (Task 58, spec §6.6).
//
// Mirrors the technical PDF from the same normalized view model: cover page,
// table of contents, headings, KPI table, findings by host/check, evidence ±3
// context windows, fallback logs, read-only repro commands, references, and
// remediation instructions. Rendered as a real .docx so the auditor can edit
// it before delivery.

import {
  AlignmentType,
  BorderStyle,
  Document,
  Footer,
  Header,
  HeadingLevel,
  Packer,
  PageBreak,
  PageNumber,
  Paragraph,
  ShadingType,
  Table,
  TableCell,
  TableRow,
  TableOfContents,
  TextRun,
  WidthType,
} from "docx";
import {
  campaignLabel,
  describeScopeText,
  severityHex,
  severityTextHex,
  SEVERITY_ARGB,
  SEVERITY_TEXT_ARGB,
  type ExportEvidenceBlock,
  type ExportFinding,
  type ExportViewModel,
} from "./viewmodel";

const BROKEN_STATUSES = new Set(["NonCompliant", "DegradedPartial", "Error"]);

function argb6(argb: string): string {
  return argb.slice(2);
}

function severityShading(severity: string): { type: (typeof ShadingType)[keyof typeof ShadingType]; fill: string } {
  return { type: ShadingType.CLEAR, fill: argb6(SEVERITY_ARGB[severity] ?? "FF64748B") };
}

function severityColor(severity: string): string {
  return argb6(SEVERITY_TEXT_ARGB[severity] ?? "FFFFFFFF");
}

function text(
  value: string,
  options: { bold?: boolean; italics?: boolean; size?: number; color?: string; font?: string; break?: number } = {},
): TextRun {
  return new TextRun({
    text: value,
    bold: options.bold,
    italics: options.italics,
    size: options.size ?? 20,
    color: options.color,
    font: options.font,
    break: options.break,
  });
}

function body(
  value: string,
  options: { bold?: boolean; italics?: boolean; size?: number; color?: string; spacingAfter?: number } = {},
): Paragraph {
  return new Paragraph({
    children: [text(value, options)],
    spacing: { after: options.spacingAfter ?? 80 },
  });
}

function bullet(value: string): Paragraph {
  return new Paragraph({
    children: [text(value)],
    bullet: { level: 0 },
    spacing: { after: 60 },
  });
}

function pageBreak(): Paragraph {
  return new Paragraph({ children: [new PageBreak()] });
}

function keyValueTable(rows: readonly [string, string | number][]): Table {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: rows.map(
      ([label, value]) =>
        new TableRow({
          children: [
            new TableCell({
              width: { size: 38, type: WidthType.PERCENTAGE },
              children: [new Paragraph({ children: [text(label, { bold: true })] })],
            }),
            new TableCell({
              width: { size: 62, type: WidthType.PERCENTAGE },
              children: [new Paragraph({ children: [text(String(value))] })],
            }),
          ],
        }),
    ),
  });
}

function evidenceParagraph(block: ExportEvidenceBlock): Paragraph {
  const runs: TextRun[] = [];
  const header = `${block.path}${block.line !== null ? `:${block.line}${block.col !== null ? `:${block.col}` : ""}` : ""}`;
  runs.push(text(header, { bold: true, size: 18, font: "Consolas", break: 0 }));
  if (block.fileMode !== null) {
    runs.push(
      text(
        `mode ${block.fileMode}${block.fileUid !== null ? ` uid ${block.fileUid}` : ""}${block.fileGid !== null ? ` gid ${block.fileGid}` : ""}`,
        { size: 16, color: "6B7280", font: "Consolas", break: 1 },
      ),
    );
  }
  for (const line of block.lines) {
    const gutter = line.lineNumber !== null ? `${String(line.lineNumber).padStart(6)} | ` : "       | ";
    runs.push(
      text(`${gutter}${line.text}`, {
        size: 16,
        font: "Consolas",
        color: line.offending ? "B91C1C" : "374151",
        bold: line.offending,
        break: 1,
      }),
    );
  }
  return new Paragraph({ children: runs, spacing: { after: 120 } });
}

function findingParagraphs(finding: ExportFinding): Paragraph[] {
  const paragraphs: Paragraph[] = [];
  paragraphs.push(
    new Paragraph({
      heading: HeadingLevel.HEADING_3,
      children: [
        text(`${finding.severity.toUpperCase()} `, {
          bold: true,
          size: 18,
          color: severityColor(finding.severity),
          font: "Consolas",
        }),
        text(`${finding.checkId} — ${finding.title}`, { bold: true, size: 22 }),
      ],
      spacing: { before: 160, after: 80 },
    }),
  );
  paragraphs.push(
    body(
      `Host ${finding.hostname} (${finding.displayId}) · Status ${finding.status} · Category ${finding.category} · Treatment ${finding.treatment} · Evidence depth ${finding.evidenceDepth ?? "unknown"}`,
      { size: 18, color: "4B5563" },
    ),
  );
  if (finding.location) paragraphs.push(body(`Location: ${finding.location}`, { size: 18 }));
  if (finding.description) paragraphs.push(body(finding.description, { size: 18 }));
  if (finding.impact) paragraphs.push(body(`Impact: ${finding.impact}`, { size: 18 }));
  if (finding.degradedReason) paragraphs.push(body(`Degraded reason: ${finding.degradedReason}`, { size: 18, color: "B45309" }));
  if (finding.evidence) paragraphs.push(body(`Evidence: ${finding.evidence}`, { size: 18 }));

  for (const block of finding.evidenceBlocks) paragraphs.push(evidenceParagraph(block));

  if (finding.fallbackLog.length > 0) {
    paragraphs.push(body("Fallback attempt log:", { bold: true, size: 18 }));
    for (const entry of finding.fallbackLog) {
      paragraphs.push(body(`- ${entry.source} => ${entry.outcome}`, { size: 16, color: "6B7280" }));
    }
  }
  if (finding.repro) {
    paragraphs.push(body("Reproduce (read-only):", { bold: true, size: 18 }));
    paragraphs.push(new Paragraph({ children: [text(finding.repro, { font: "Consolas", size: 16 })], spacing: { after: 80 } }));
  }
  if (finding.recommendation) paragraphs.push(body(`Remediation: ${finding.recommendation}`, { size: 18 }));
  if (finding.references.length > 0) paragraphs.push(body(`References: ${finding.references.join(", ")}`, { size: 16, color: "6B7280" }));
  if (finding.treatmentAssignee || finding.treatmentDueDate) {
    paragraphs.push(
      body(
        `Treatment owner: ${finding.treatmentAssignee ?? "unassigned"}${finding.treatmentDueDate ? ` · due ${finding.treatmentDueDate}` : ""}`,
        { size: 16, color: "6B7280" },
      ),
    );
  }
  paragraphs.push(
    new Paragraph({
      border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: "D1D5DB" } },
      spacing: { after: 120 },
    }),
  );
  return paragraphs;
}

function coverPage(viewModel: ExportViewModel): (Paragraph | Table)[] {
  return [
    new Paragraph({
      alignment: AlignmentType.LEFT,
      children: [text(viewModel.title, { bold: true, size: 52, color: "0F172A" })],
      spacing: { before: 2400, after: 120 },
    }),
    body("Technical Audit Report", { size: 30, color: "475569" }),
    body(`${viewModel.generator}`, { size: 18, color: "94A3B8", spacingAfter: 240 }),
    keyValueTable([
      ["Client", viewModel.client ?? "—"],
      ["Campaign", campaignLabel(viewModel.scope)],
      ["Scope", describeScopeText(viewModel.scope)],
      ["Generated", viewModel.generatedAt],
    ]),
    new Paragraph({
      spacing: { before: 240, after: 120 },
      children: [text(viewModel.confidentiality, { size: 18, color: "9A3412", italics: true })],
    }),
    pageBreak(),
  ];
}

/** Render the editable technical deliverable. Pure: returns the document bytes. */
export async function renderDocx(viewModel: ExportViewModel): Promise<Buffer> {
  const children: (Paragraph | Table)[] = [];

  // --- Cover page ---------------------------------------------------------
  children.push(...coverPage(viewModel));

  // --- Table of contents --------------------------------------------------
  children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: [text("Table of Contents")] }));
  children.push(new TableOfContents(undefined, { hyperlink: true, headingStyleRange: "1-3" }));
  children.push(pageBreak());

  // --- KPI table ----------------------------------------------------------
  children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: [text("Key Performance Indicators")] }));
  children.push(
    keyValueTable([
      ["Weighted Risk Score (0-100)", viewModel.kpis.riskScore],
      ["Evidence Coverage (%)", viewModel.kpis.coverage],
      ["Total Findings", viewModel.kpis.totalFindings],
      ["Failing / Degraded Findings", viewModel.kpis.failingFindings],
      ["Open Findings", viewModel.kpis.openFindings],
      ["Open Critical Findings", viewModel.kpis.openCriticals],
      ["Hosts", viewModel.kpis.hostCount],
      ["Scan Reports", viewModel.kpis.totalReports],
      ["Standard References", viewModel.kpis.referenceCount],
    ]),
  );

  children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: [text("Executive Summary")] }));
  for (const sentence of viewModel.summary) children.push(bullet(sentence));

  // --- Findings by host ---------------------------------------------------
  children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: [text("Findings by Host")] }));
  if (viewModel.hosts.length === 0) children.push(body("No hosts matched this scope.", { color: "6B7280" }));
  for (const host of viewModel.hosts) {
    children.push(new Paragraph({ heading: HeadingLevel.HEADING_2, children: [text(`${host.hostname} (${host.displayId})`)] }));
    children.push(
      body(
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
        { size: 18, color: "6B7280" },
      ),
    );
    for (const finding of host.findings) children.push(...findingParagraphs(finding));
  }

  // --- Findings by check --------------------------------------------------
  children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: [text("Findings by Check")] }));
  for (const check of viewModel.checks) {
    children.push(
      body(
        `${check.checkId} — ${check.title} · ${check.severity} · ${check.findingCount} finding(s) on ${check.hostCount} host(s)${check.references.length > 0 ? ` · ${check.references.join(", ")}` : ""}`,
        { size: 18 },
      ),
    );
  }

  // --- References ---------------------------------------------------------
  if (viewModel.references.length > 0) {
    children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: [text("Standard References")] }));
    for (const reference of viewModel.references) {
      children.push(
        body(
          `${reference.reference} (${reference.standard}) — ${reference.count} finding(s), ${reference.nonCompliant} non-compliant, ${reference.hosts} host(s)`,
          { size: 16, color: "6B7280" },
        ),
      );
    }
  }

  const document = new Document({
    creator: viewModel.generator,
    title: viewModel.title,
    description: "HBS technical audit deliverable",
    keywords: "HBS-EXPORT-MARKER-docx",
    features: { updateFields: true },
    sections: [
      {
        headers: {
          default: new Header({
            children: [
              new Paragraph({
                children: [
                  text(`${viewModel.title} · ${campaignLabel(viewModel.scope)}`, { size: 14, color: "6B7280" }),
                ],
              }),
            ],
          }),
        },
        footers: {
          default: new Footer({
            children: [
              new Paragraph({
                alignment: AlignmentType.CENTER,
                children: [text(viewModel.confidentiality, { size: 14, color: "6B7280" })],
              }),
              new Paragraph({
                alignment: AlignmentType.CENTER,
                children: [
                  new TextRun({
                    children: ["Page ", PageNumber.CURRENT, " of ", PageNumber.TOTAL_PAGES],
                    size: 14,
                    color: "6B7280",
                  }),
                ],
              }),
            ],
          }),
        },
        children,
      },
    ],
  });

  return Packer.toBuffer(document);
}

export { BROKEN_STATUSES as DOCX_BROKEN_STATUSES };
