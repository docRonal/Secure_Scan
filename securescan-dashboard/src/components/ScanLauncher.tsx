import { Play, Lock, Square } from "lucide-react";
import type { Asset, Scan, ScanType } from "../types";
import ScanStatusIndicator from "./ScanStatusIndicator";
import { useLanguage } from "../i18n";

interface Props {
  asset: Asset;
  scans: Scan[];
  launching: ScanType | null;
  onLaunch: (scanType: ScanType) => void;
  selectedScanId: number | null;
  onSelectScan: (id: number) => void;
  onCancelScan: (id: number) => void;
}

function formatTime(iso: string | null, language: string): string {
  if (!iso) return "—";
  const locale = language === "ru" ? "ru-RU" : "en-GB";
  return new Date(iso).toLocaleString(locale, { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
}

const CANCELLABLE_STATUSES = new Set(["queued", "running"]);
const RUNNING_STATUSES = new Set(["queued", "running"]);

function formatStep(step: string, language: string, translate: (key: "stepSpider" | "stepAjaxSpider" | "stepActiveScan" | "stepComplete" | "stepCheck") => string) {
  if (language === "ru") return step;
  if (step === "Spider (краулинг)") return translate("stepSpider");
  if (step === "AJAX Spider (JavaScript-маршруты)") return translate("stepAjaxSpider");
  if (step === "Active scan (тестирование)") return translate("stepActiveScan");
  if (step === "Завершено") return translate("stepComplete");
  if (step.startsWith("Проверка: ")) return `${translate("stepCheck")}: ${step.slice("Проверка: ".length)}`;
  return step;
}

export default function ScanLauncher({
  asset, scans, launching, onLaunch, selectedScanId, onSelectScan, onCancelScan,
}: Props) {
  const { t: tr, language } = useLanguage();
  return (
    <div className="rounded-xl border border-line bg-surface p-5 shadow-panel">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-display text-sm font-semibold text-ink">{tr("scanning")}</h3>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => onLaunch("passive")}
            disabled={launching !== null}
            className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface2 px-3 py-1.5 text-xs font-medium text-ink transition-colors hover:border-accent/50 disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5" />
            {launching === "passive" ? tr("launch") : tr("passiveScan")}
          </button>
          <button
            onClick={() => onLaunch("active")}
            disabled={launching !== null || !asset.is_verified}
            title={!asset.is_verified ? tr("ownershipRequired") : undefined}
            className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface2 px-3 py-1.5 text-xs font-medium text-ink transition-colors hover:border-accent/50 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {asset.is_verified ? <Play className="h-3.5 w-3.5" /> : <Lock className="h-3.5 w-3.5" />}
            {launching === "active" ? tr("launch") : tr("activeScan")}
          </button>
        </div>
      </div>

      <div className="mt-4 divide-y divide-line">
        {scans.length === 0 && (
          <p className="py-6 text-center text-sm text-muted">{tr("noScans")}</p>
        )}
        {scans.map((scan) => {
          const cancellable = CANCELLABLE_STATUSES.has(scan.status) && !scan.cancel_requested;
          const isRunning = RUNNING_STATUSES.has(scan.status);
          return (
            <div
              key={scan.id}
              role="button"
              tabIndex={0}
              onClick={() => onSelectScan(scan.id)}
              onKeyDown={(e) => e.key === "Enter" && onSelectScan(scan.id)}
              className={`flex w-full cursor-pointer flex-col gap-1.5 py-3 text-left transition-colors ${
                selectedScanId === scan.id ? "bg-surface2/60" : "hover:bg-surface2/30"
              } -mx-2 rounded-lg px-2`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-3">
                  <span className="w-14 font-mono text-xs text-muted">#{scan.id}</span>
                  <span className="text-xs text-muted">{scan.scan_type === "passive" ? tr("passive") : tr("active")}</span>
                  <span className="hidden font-mono text-xs text-muted sm:inline">{formatTime(scan.created_at, language)}</span>
                </div>
                <div className="flex items-center gap-2">
                  {scan.cancel_requested && isRunning && (
                    <span className="text-[11px] text-muted">{tr("stopping")}</span>
                  )}
                  {cancellable && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onCancelScan(scan.id);
                      }}
                      title={tr("stopScan")}
                      className="rounded-md p-1 text-muted transition-colors hover:bg-surface2 hover:text-sev-critical"
                    >
                      <Square className="h-3 w-3" />
                    </button>
                  )}
                  <ScanStatusIndicator status={scan.status} />
                </div>
              </div>

              {isRunning && (
                <div className="flex items-center gap-2 pl-[76px]">
                  <div className="h-1 flex-1 overflow-hidden rounded-full bg-surface2">
                    <div
                      className="h-full rounded-full bg-accent transition-all duration-500"
                      style={{ width: `${Math.max(scan.progress_percent, 3)}%` }}
                    />
                  </div>
                  <span className="w-9 shrink-0 text-right font-mono text-[11px] text-muted">
                    {scan.progress_percent}%
                  </span>
                  {scan.current_step && (
                    <span className="shrink-0 truncate text-[11px] text-muted">
                      {formatStep(scan.current_step, language, tr)}
                    </span>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
