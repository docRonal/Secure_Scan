import { useState } from "react";
import { Radar, Trash2, Pause, Play as PlayIcon } from "lucide-react";
import type { Asset, MonitorSchedule, ScanType } from "../types";
import { api, ApiError } from "../api";
import { useLanguage, type TranslationKey } from "../i18n";

const FREQUENCY_OPTIONS = [
  { hours: 24, label: "daily" as const },
  { hours: 168, label: "weekly" as const },
  { hours: 720, label: "monthly" as const },
];

interface Props {
  asset: Asset;
  schedules: MonitorSchedule[];
  onChange: () => void;
}

function formatTime(iso: string | null, language: string, notRunText: string): string {
  if (!iso) return notRunText;
  const locale = language === "ru" ? "ru-RU" : "en-GB";
  return new Date(iso).toLocaleString(locale, { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export default function MonitoringPanel({ asset, schedules, onChange }: Props) {
  const { t: tr, language } = useLanguage();
  const [scanType, setScanType] = useState<ScanType>("passive");
  const [frequency, setFrequency] = useState(24);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleCreate() {
    setCreating(true);
    setError(null);
    try {
      await api.createSchedule(asset.id, scanType, frequency);
      onChange();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : tr("scheduleFailed"));
    } finally {
      setCreating(false);
    }
  }

  async function toggle(schedule: MonitorSchedule) {
    await api.updateSchedule(schedule.id, { is_active: !schedule.is_active });
    onChange();
  }

  async function remove(schedule: MonitorSchedule) {
    await api.deleteSchedule(schedule.id);
    onChange();
  }

  return (
    <div className="rounded-xl border border-line bg-surface p-5 shadow-panel">
      <div className="flex items-center gap-2">
        <Radar className="h-4 w-4 text-accent" />
        <h3 className="font-display text-sm font-semibold text-ink">{tr("monitoringTitle")}</h3>
      </div>
      <p className="mt-1 text-xs text-muted">
        {tr("monitoringDescription")}
      </p>
      {asset.is_demo && (
        <p className="mt-2 rounded-lg border border-accent/30 bg-accent/10 px-3 py-2 text-[11px] leading-relaxed text-accent">
          {tr("demoScheduleNotice")}
        </p>
      )}

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <select
          value={scanType}
          onChange={(e) => setScanType(e.target.value as ScanType)}
          className="rounded-md border border-line bg-surface2 px-2.5 py-1.5 text-xs text-ink focus:border-accent"
        >
          <option value="passive">{tr("passiveScan")}</option>
          <option value="active" disabled={!asset.is_verified}>
            {tr("activeScan")}{!asset.is_verified ? ` ${tr("activeNeedsVerification")}` : ""}
          </option>
        </select>
        <select
          value={frequency}
          onChange={(e) => setFrequency(Number(e.target.value))}
          className="rounded-md border border-line bg-surface2 px-2.5 py-1.5 text-xs text-ink focus:border-accent"
        >
          {FREQUENCY_OPTIONS.map((f) => (
            <option key={f.hours} value={f.hours}>
              {tr(f.label as TranslationKey)}
            </option>
          ))}
        </select>
        <button
          onClick={handleCreate}
          disabled={creating}
          className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-base transition-opacity hover:opacity-90 disabled:opacity-50"
        >
          {creating ? tr("enabling") : tr("enable")}
        </button>
      </div>
      {error && <p className="mt-2 text-xs text-sev-critical">{error}</p>}

      <div className="mt-4 divide-y divide-line">
        {schedules.length === 0 && (
          <p className="py-4 text-center text-xs text-muted">{tr("noSchedules")}</p>
        )}
        {schedules.map((s) => (
          <div key={s.id} className="flex items-center justify-between gap-3 py-2.5">
            <div className="text-xs">
              <span className="font-mono text-ink">
                {s.scan_type === "passive" ? tr("passive") : tr("active")} · {tr("everyHours", { hours: s.frequency_hours })}
              </span>
              <p className="mt-0.5 text-muted">
                {tr("lastRun", { time: formatTime(s.last_run_at, language, tr("neverRun")) })} · {tr("nextRun", { time: formatTime(s.next_run_at, language, tr("neverRun")) })}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-1.5">
              <span
                className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${
                  s.is_active ? "bg-accent/15 text-accent" : "bg-surface2 text-muted"
                }`}
              >
                {s.is_active ? tr("enabled") : tr("paused")}
              </span>
              <button
                onClick={() => toggle(s)}
                aria-label={s.is_active ? tr("pauseSchedule") : tr("resumeSchedule")}
                className="rounded-md p-1.5 text-muted hover:bg-surface2 hover:text-ink"
              >
                {s.is_active ? <Pause className="h-3.5 w-3.5" /> : <PlayIcon className="h-3.5 w-3.5" />}
              </button>
              <button
                onClick={() => remove(s)}
                aria-label={tr("deleteSchedule")}
                className="rounded-md p-1.5 text-muted hover:bg-surface2 hover:text-sev-critical"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
