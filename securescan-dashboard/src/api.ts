import type { Asset, Scan, Report, MonitorSchedule, ScanType, VerificationMethod, User } from "./types";
import { auth } from "./auth";

const DEFAULT_PORTS = [8000, 8001, 8002, 3000, 5173];
const FALLBACK_API_URL = "http://127.0.0.1:8000";

let resolvedApiUrl: string | null = null;

async function resolveApiUrl(): Promise<string> {
  if (resolvedApiUrl) {
    return resolvedApiUrl;
  }

  const configuredUrl = import.meta.env.VITE_API_URL?.trim();
  if (configuredUrl) {
    const normalizedUrl = configuredUrl;
    resolvedApiUrl = normalizedUrl;
    return normalizedUrl;
  }

  const checks = Array.from(new Set(["http://127.0.0.1", "http://localhost"]))
    .flatMap((base) => DEFAULT_PORTS.map((port) => `${base}:${port}`));

  for (const url of checks) {
    try {
      const response = await fetch(`${url}/docs`, { method: "GET" });
      if (response.ok) {
        resolvedApiUrl = url;
        return resolvedApiUrl;
      }
    } catch {
      // Continue probing the remaining local API ports.
    }
  }

  resolvedApiUrl = FALLBACK_API_URL;
  return resolvedApiUrl;
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = auth.getToken();
  const apiUrl = await resolveApiUrl();
  const resp = await fetch(`${apiUrl}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  });
  if (!resp.ok) {
    if (resp.status === 401) auth.clearToken();
    const body = await resp.json().catch(() => ({}));
    const storedLanguage = localStorage.getItem("securescan-language");
    const language = storedLanguage === "ru" || storedLanguage === "en"
      ? storedLanguage
      : navigator.language.toLowerCase().startsWith("ru") ? "ru" : "en";
    const message = language === "ru"
      ? body.detail ?? `Ошибка запроса: ${resp.status}`
      : `Request failed (HTTP ${resp.status}).`;
    throw new ApiError(resp.status, message);
  }
  if (resp.status === 204) return undefined as T;
  return resp.json();
}

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

// Downloads use direct links, so the access token is passed as a query parameter.
// The backend explicitly supports this for report downloads.
function downloadUrl(path: string): string {
  const token = auth.getToken();
  const sep = path.includes("?") ? "&" : "?";
  const baseUrl = resolvedApiUrl ?? FALLBACK_API_URL;
  return `${baseUrl}${path}${token ? `${sep}token=${encodeURIComponent(token)}` : ""}`;
}

export const api = {
  register: (email: string, password: string) =>
    request<{ access_token: string }>("/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  login: (email: string, password: string) =>
    request<{ access_token: string }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  me: () => request<User>("/auth/me"),

  listAssets: () => request<Asset[]>("/assets"),
  createAsset: (domain: string) =>
    request<Asset>("/assets", { method: "POST", body: JSON.stringify({ domain }) }),
  getAsset: (id: number) => request<Asset>(`/assets/${id}`),
  verifyAsset: (id: number, method: VerificationMethod) =>
    request<Asset>(`/assets/${id}/verify?method=${method}`, { method: "POST" }),

  createScan: (assetId: number, scanType: ScanType) =>
    request<Scan>("/scans", {
      method: "POST",
      body: JSON.stringify({ asset_id: assetId, scan_type: scanType }),
    }),
  getScan: (id: number) => request<Scan>(`/scans/${id}`),
  listScans: (assetId: number) => request<Scan[]>(`/scans?asset_id=${assetId}`),
  cancelScan: (id: number) => request<Scan>(`/scans/${id}/cancel`, { method: "POST" }),

  getReport: (scanId: number) => request<Report>(`/reports/${scanId}`),
  getReportHtmlUrl: (scanId: number) => downloadUrl(`/reports/${scanId}?format=html`),
  getReportPdfUrl: (scanId: number) => downloadUrl(`/reports/${scanId}?format=pdf`),
  getReportCsvUrl: (scanId: number) => downloadUrl(`/reports/${scanId}?format=csv`),

  listSchedules: (assetId: number) =>
    request<MonitorSchedule[]>(`/monitoring?asset_id=${assetId}`),
  createSchedule: (assetId: number, scanType: ScanType, frequencyHours: number) =>
    request<MonitorSchedule>("/monitoring", {
      method: "POST",
      body: JSON.stringify({ asset_id: assetId, scan_type: scanType, frequency_hours: frequencyHours }),
    }),
  updateSchedule: (id: number, payload: { is_active?: boolean; frequency_hours?: number }) =>
    request<MonitorSchedule>(`/monitoring/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
  deleteSchedule: (id: number) => request<void>(`/monitoring/${id}`, { method: "DELETE" }),
};

export { ApiError };
