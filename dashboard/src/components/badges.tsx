import {
  Apple,
  CircleCheck,
  CircleDot,
  CircleMinus,
  CircleSlash,
  CircleX,
  Cpu,
  Flame,
  Info,
  MonitorSmartphone,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Terminal,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import { Badge, type BadgeTone } from "./ui";
import type { EvidenceDepth, Severity, Status, TreatmentState } from "../types";

type BadgeProps = { className?: string; showLabel?: boolean };

type Descriptor = { tone: BadgeTone; icon: LucideIcon; label: string };

const SEVERITY_META: Record<string, Descriptor> = {
  Critical: { tone: "critical", icon: ShieldAlert, label: "Critical" },
  High: { tone: "high", icon: TriangleAlert, label: "High" },
  Medium: { tone: "medium", icon: Flame, label: "Medium" },
  Low: { tone: "low", icon: CircleDot, label: "Low" },
  Informational: { tone: "info", icon: Info, label: "Informational" },
};

const STATUS_META: Record<string, Descriptor> = {
  Compliant: { tone: "compliant", icon: CircleCheck, label: "Compliant" },
  NonCompliant: { tone: "noncompliant", icon: CircleX, label: "Non-compliant" },
  DegradedPartial: { tone: "degraded", icon: TriangleAlert, label: "Degraded (partial)" },
  Error: { tone: "error", icon: ShieldAlert, label: "Error" },
  NotApplicable: { tone: "na", icon: CircleMinus, label: "Not applicable" },
};

const TREATMENT_META: Record<string, Descriptor> = {
  open: { tone: "open", icon: CircleDot, label: "Open" },
  accepted_risk: { tone: "accepted", icon: ShieldAlert, label: "Accepted risk" },
  false_positive: { tone: "false-positive", icon: CircleSlash, label: "False positive" },
  remediated: { tone: "remediated", icon: CircleCheck, label: "Remediated" },
};

const EVIDENCE_META: Record<string, Descriptor> = {
  AuthoritativePrimary: { tone: "evidence-primary", icon: ShieldCheck, label: "Primary evidence" },
  AuthoritativeFallback: { tone: "evidence-fallback", icon: ShieldQuestion, label: "Fallback evidence" },
  DegradedPartial: { tone: "evidence-degraded", icon: TriangleAlert, label: "Degraded evidence" },
};

function fallbackDescriptor(value: string, tone: BadgeTone = "neutral"): Descriptor {
  return { tone, icon: Info, label: value };
}

function render(descriptor: Descriptor, { className, showLabel = true }: BadgeProps) {
  return (
    <Badge tone={descriptor.tone} icon={descriptor.icon} className={className}>
      {showLabel ? descriptor.label : <span className="sr-only">{descriptor.label}</span>}
    </Badge>
  );
}

export type SeverityBadgeProps = BadgeProps & { severity: Severity | string };
export function SeverityBadge({ severity, ...rest }: SeverityBadgeProps) {
  return render(SEVERITY_META[severity] ?? fallbackDescriptor(severity), rest);
}

export type StatusBadgeProps = BadgeProps & { status: Status | string };
export function StatusBadge({ status, ...rest }: StatusBadgeProps) {
  return render(STATUS_META[status] ?? fallbackDescriptor(status), rest);
}

export type TreatmentBadgeProps = BadgeProps & { state: TreatmentState | string };
export function TreatmentBadge({ state, ...rest }: TreatmentBadgeProps) {
  return render(TREATMENT_META[state] ?? fallbackDescriptor(state), rest);
}

export type EvidenceDepthBadgeProps = BadgeProps & { depth: EvidenceDepth | string };
export function EvidenceDepthBadge({ depth, ...rest }: EvidenceDepthBadgeProps) {
  return render(EVIDENCE_META[depth] ?? fallbackDescriptor(depth), rest);
}

const PLATFORM_ICON: Array<{ match: RegExp; icon: LucideIcon }> = [
  { match: /win/i, icon: MonitorSmartphone },
  { match: /darwin|mac|osx/i, icon: Apple },
  { match: /linux|deb|rpm|ubuntu|rhel|centos/i, icon: Terminal },
];

export type PlatformBadgeProps = BadgeProps & { platform: string | null | undefined };

/** Host platform, rendered as an icon + monospace label. */
export function PlatformBadge({ platform, className, showLabel = true }: PlatformBadgeProps) {
  if (!platform) {
    return (
      <Badge tone="na" icon={Cpu} className={className}>
        {showLabel ? "Unknown platform" : <span className="sr-only">Unknown platform</span>}
      </Badge>
    );
  }
  const icon = PLATFORM_ICON.find((candidate) => candidate.match.test(platform))?.icon ?? Cpu;
  const descriptor: Descriptor = { tone: "info", icon, label: platform };
  return render(descriptor, { className, showLabel });
}
