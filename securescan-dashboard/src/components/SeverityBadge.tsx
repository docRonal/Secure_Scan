import type { Severity } from "../types";
import { useLanguage } from "../i18n";

const LABEL_KEY: Record<Severity, "severityInfo" | "severityLow" | "severityMedium" | "severityHigh" | "severityCritical"> = {
  info: "severityInfo",
  low: "severityLow",
  medium: "severityMedium",
  high: "severityHigh",
  critical: "severityCritical",
};

const DOT: Record<Severity, string> = {
  info: "bg-sev-info",
  low: "bg-sev-low",
  medium: "bg-sev-medium",
  high: "bg-sev-high",
  critical: "bg-sev-critical",
};

export default function SeverityBadge({ severity }: { severity: Severity }) {
  const { t: tr } = useLanguage();
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface2 px-2.5 py-1 text-xs font-medium text-ink">
      <span className={`h-1.5 w-1.5 rounded-full ${DOT[severity]}`} />
      {tr(LABEL_KEY[severity])}
    </span>
  );
}
