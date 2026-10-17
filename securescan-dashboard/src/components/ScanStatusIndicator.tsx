import type { ScanStatus } from "../types";
import { useLanguage } from "../i18n";

const LABEL_KEY: Record<ScanStatus, "scanQueued" | "scanRunning" | "scanCompleted" | "scanError" | "scanUnverified" | "scanCancelled"> = {
  queued: "scanQueued",
  running: "scanRunning",
  completed: "scanCompleted",
  failed: "scanError",
  blocked_unverified: "scanUnverified",
  cancelled: "scanCancelled",
};

const COLOR: Record<ScanStatus, string> = {
  queued: "text-muted",
  running: "text-accent",
  completed: "text-accent",
  failed: "text-sev-critical",
  blocked_unverified: "text-sev-medium",
  cancelled: "text-muted",
};

export default function ScanStatusIndicator({ status }: { status: ScanStatus }) {
  const { t: tr } = useLanguage();
  const isRunning = status === "running" || status === "queued";

  return (
    <span className={`inline-flex items-center gap-2 text-sm font-medium ${COLOR[status]}`}>
      <span className="relative flex h-2 w-2">
        {isRunning && (
          <span className="absolute inline-flex h-full w-full animate-pulse-ring rounded-full bg-accent" />
        )}
        <span
          className={`relative inline-flex h-2 w-2 rounded-full ${
            status === "failed"
              ? "bg-sev-critical"
              : status === "blocked_unverified"
              ? "bg-sev-medium"
              : status === "cancelled"
              ? "bg-muted"
              : "bg-accent"
          }`}
        />
      </span>
      {tr(LABEL_KEY[status])}
    </span>
  );
}
