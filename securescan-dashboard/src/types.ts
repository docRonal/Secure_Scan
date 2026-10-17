export type VerificationMethod = "dns_txt" | "meta_tag" | "file_token";
export type ScanType = "passive" | "active";
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "blocked_unverified" | "cancelled";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface User {
  id: number;
  email: string;
  created_at: string;
  is_guest: boolean;
}

export interface Asset {
  id: number;
  domain: string;
  is_verified: boolean;
  is_demo: boolean;
  verification_token: string;
  verification_method: VerificationMethod | null;
}

export interface Finding {
  checker: string;
  title: string;
  severity: Severity;
  description: string;
  recommendation: string | null;
  owasp_category: string | null;
  cwe_id: string | null;
  evidence: string | null;
}

export interface Scan {
  id: number;
  asset_id: number;
  scan_type: ScanType;
  status: ScanStatus;
  cancel_requested: boolean;
  progress_percent: number;
  current_step: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  findings: Finding[];
}

export interface Report {
  scan_id: number;
  domain: string;
  scan_type: ScanType;
  status: ScanStatus;
  error_message: string | null;
  generated_at: string | null;
  risk_score: number;
  severity_counts: Record<Severity, number>;
  findings: Finding[];
}

export interface MonitorSchedule {
  id: number;
  asset_id: number;
  scan_type: ScanType;
  frequency_hours: number;
  is_active: boolean;
  last_run_at: string | null;
  next_run_at: string;
}
