import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Cell } from "recharts";
import { ExternalLink, AlertTriangle, FileText, Table2, Square } from "lucide-react";
import type { Report, Severity } from "../types";
import SeverityBadge from "./SeverityBadge";
import { api } from "../api";
import { useLanguage } from "../i18n";

const SEVERITY_COLOR: Record<Severity, string> = {
  info: "#5B7083",
  low: "#3E8FB0",
  medium: "#D8A23A",
  high: "#D9662B",
  critical: "#C23B3B",
};

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export default function ReportPanel({ report }: { report: Report }) {
  const { t: tr, language } = useLanguage();
  const localizedError = language === "ru"
    ? report.error_message
    : report.status === "cancelled"
    ? tr("cancelledDetails")
    : report.status === "blocked_unverified"
    ? tr("blockedDetails")
    : tr("failedDetails");
  const chartData = ORDER.map((sev) => ({
    severity: sev,
    label: tr(`severity${sev[0].toUpperCase()}${sev.slice(1)}` as "severityInfo"),
    count: report.severity_counts[sev] ?? 0,
  }));

  return (
    <div className="rounded-xl border border-line bg-surface p-5 shadow-panel">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="font-display text-sm font-semibold text-ink">
            {tr("reportForScan", { id: report.scan_id })}
          </h3>
          <p className="mt-0.5 font-mono text-xs text-muted">{report.domain}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2 sm:gap-4">
          <div className="text-right">
            <div className="font-display text-2xl font-semibold text-ink">{report.risk_score}</div>
            <div className="text-[11px] text-muted">{tr("riskScore")}</div>
          </div>
          <a
            href={api.getReportHtmlUrl(report.scan_id)}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 rounded-lg border border-line px-2.5 py-1.5 text-xs text-muted hover:border-accent/50 hover:text-ink"
          >
            HTML <ExternalLink className="h-3 w-3" />
          </a>
          <a
            href={api.getReportPdfUrl(report.scan_id)}
            className="inline-flex items-center gap-1 rounded-lg border border-line px-2.5 py-1.5 text-xs text-muted hover:border-accent/50 hover:text-ink"
          >
            PDF <FileText className="h-3 w-3" />
          </a>
          <a
            href={api.getReportCsvUrl(report.scan_id)}
            className="inline-flex items-center gap-1 rounded-lg border border-line px-2.5 py-1.5 text-xs text-muted hover:border-accent/50 hover:text-ink"
          >
            CSV <Table2 className="h-3 w-3" />
          </a>
        </div>
      </div>

      {report.error_message && (
        <div
          className={`mt-4 flex items-start gap-2.5 rounded-lg border px-3.5 py-3 text-xs ${
            report.status === "cancelled"
              ? "border-line bg-surface2/60 text-muted"
              : "border-sev-critical/30 bg-sev-critical/10 text-sev-critical"
          }`}
        >
          {report.status === "cancelled" ? (
            <Square className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
          ) : (
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
          )}
          <div>
            <p className="font-medium">
              {report.status === "cancelled"
                ? tr("scanStopped")
                : report.status === "blocked_unverified"
                ? tr("scanBlocked")
                : tr("scanFailed")}
            </p>
            <p className={`mt-0.5 leading-relaxed ${report.status === "cancelled" ? "text-muted" : "text-sev-critical/90"}`}>
              {localizedError}
            </p>
          </div>
        </div>
      )}

      <div className="mt-4 h-28">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} layout="vertical" margin={{ left: 0, right: 16, top: 0, bottom: 0 }}>
            <XAxis type="number" hide />
            <YAxis
              type="category"
              dataKey="label"
              width={64}
              tick={{ fill: "#8B99AE", fontSize: 11, fontFamily: "IBM Plex Mono" }}
              axisLine={false}
              tickLine={false}
            />
            <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={14}>
              {chartData.map((d) => (
                <Cell key={d.severity} fill={SEVERITY_COLOR[d.severity]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="mt-2 divide-y divide-line">
        {report.findings.length === 0 && (
          <p className="py-6 text-center text-sm text-muted">{tr("noFindings")}</p>
        )}
        {report.findings.map((f, i) => (
          <div key={i} className="py-3">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-sm text-ink">{f.title}</p>
                <p className="mt-1 text-xs leading-relaxed text-muted">{f.description}</p>
                {f.recommendation && (
                  <p className="mt-1.5 text-xs leading-relaxed text-accent">→ {f.recommendation}</p>
                )}
                <p className="mt-1.5 font-mono text-[11px] text-muted">
                  {f.checker}
                  {f.owasp_category ? ` · OWASP ${f.owasp_category}` : ""}
                  {f.cwe_id ? ` · ${f.cwe_id}` : ""}
                </p>
              </div>
              <SeverityBadge severity={f.severity} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
