import { useEffect, useState, useCallback } from "react";
import { ScanSearch, Menu } from "lucide-react";
import type { Asset, Scan, Report, MonitorSchedule, ScanType, User } from "./types";
import { api } from "./api";
import { auth } from "./auth";
import Sidebar from "./components/Sidebar";
import VerificationPanel from "./components/VerificationPanel";
import ScanLauncher from "./components/ScanLauncher";
import ReportPanel from "./components/ReportPanel";
import MonitoringPanel from "./components/MonitoringPanel";
import LoginScreen from "./components/LoginScreen";
import { useLanguage } from "./i18n";

type Tab = "overview" | "monitoring";

const RUNNING_STATUSES = new Set(["queued", "running"]);
const AUTH_REQUIRED = import.meta.env.VITE_AUTH_REQUIRED !== "false";

export default function App() {
  const { t: tr } = useLanguage();
  const [authChecked, setAuthChecked] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [selectedAssetId, setSelectedAssetId] = useState<number | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [schedules, setSchedules] = useState<MonitorSchedule[]>([]);
  const [tab, setTab] = useState<Tab>("overview");
  const [launching, setLaunching] = useState<ScanType | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const selectedAsset = assets.find((a) => a.id === selectedAssetId) ?? null;

  const refreshAssets = useCallback(async () => {
    try {
      const list = await api.listAssets();
      setAssets(list);
      if (list.length > 0 && selectedAssetId === null) {
        setSelectedAssetId(list[0].id);
      }
      setLoadError(null);
    } catch {
      setLoadError(`${tr("backendUnavailable")} uvicorn app.main:app --reload`);
    }
  }, [selectedAssetId, tr]);

  const refreshScans = useCallback(async (assetId: number) => {
    const list = await api.listScans(assetId);
    setScans(list);
    return list;
  }, []);

  const refreshSchedules = useCallback(async (assetId: number) => {
    const list = await api.listSchedules(assetId);
    setSchedules(list);
  }, []);

  useEffect(() => {
    if (!auth.getToken() && AUTH_REQUIRED) {
      setAuthChecked(true);
      return;
    }
    api
      .me()
      .then(setUser)
      .catch(() => setUser(null))
      .finally(() => setAuthChecked(true));
  }, []);

  function handleLogout() {
    if (user?.is_guest) return;
    auth.clearToken();
    setUser(null);
    setAssets([]);
    setSelectedAssetId(null);
    setScans([]);
    setSelectedScanId(null);
    setReport(null);
    setSchedules([]);
  }

  useEffect(() => {
    if (!user) return;
    refreshAssets();
  }, [user]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (selectedAssetId === null) return;
    refreshScans(selectedAssetId).then((list) => {
      setSelectedScanId(list[0]?.id ?? null);
    });
    refreshSchedules(selectedAssetId);
  }, [selectedAssetId, refreshScans, refreshSchedules]);

  useEffect(() => {
    if (selectedScanId === null) {
      setReport(null);
      return;
    }
    api.getReport(selectedScanId).then(setReport).catch(() => setReport(null));
  }, [selectedScanId]);

  useEffect(() => {
    if (selectedScanId === null || selectedAssetId === null) return;
    const current = scans.find((s) => s.id === selectedScanId);
    if (!current || !RUNNING_STATUSES.has(current.status)) return;

    const interval = setInterval(async () => {
      const list = await refreshScans(selectedAssetId);
      const updated = list.find((s) => s.id === selectedScanId);
      if (updated && !RUNNING_STATUSES.has(updated.status)) {
        api.getReport(selectedScanId).then(setReport).catch(() => {});
      }
    }, 2500);
    return () => clearInterval(interval);
  }, [selectedScanId, selectedAssetId, scans, refreshScans]);

  async function handleCreateAsset(domain: string) {
    const asset = await api.createAsset(domain);
    await refreshAssets();
    setSelectedAssetId(asset.id);
  }

  function handleVerified(updated: Asset) {
    setAssets((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
  }

  async function handleLaunch(scanType: ScanType) {
    if (selectedAssetId === null) return;
    setLaunching(scanType);
    try {
      const scan = await api.createScan(selectedAssetId, scanType);
      await refreshScans(selectedAssetId);
      setSelectedScanId(scan.id);
    } catch (err: any) {
      setLoadError(err.message ?? tr("scanStartFailed"));
    } finally {
      setLaunching(null);
    }
  }

  async function handleCancelScan(scanId: number) {
    if (selectedAssetId === null) return;
    try {
      await api.cancelScan(scanId);
      await refreshScans(selectedAssetId);
    } catch (err: any) {
      setLoadError(err.message ?? tr("scanCancelFailed"));
    }
  }

  if (!authChecked) {
    return <div className="flex h-screen items-center justify-center bg-base text-muted text-sm">{tr("loading")}</div>;
  }

  if (!user) {
    return (
      <LoginScreen
        onAuthenticated={() => {
          api.me().then(setUser).catch(() => setUser(null));
        }}
      />
    );
  }

  return (
    <div className="flex h-screen bg-base">
      <Sidebar
        assets={assets}
        selectedId={selectedAssetId}
        onSelect={setSelectedAssetId}
        onCreate={handleCreateAsset}
        user={user}
        onLogout={handleLogout}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
      />

      <main className="flex-1 overflow-y-auto">
        {/* The sidebar is already visible on desktop, so this menu button is mobile-only. */}
        <div className="flex items-center gap-3 border-b border-line px-4 py-3 md:hidden">
          <button
            onClick={() => setMobileMenuOpen(true)}
            aria-label={tr("openMenu")}
            className="rounded-md p-1.5 text-muted hover:bg-surface2 hover:text-ink"
          >
            <Menu className="h-5 w-5" />
          </button>
          <span className="font-display text-sm font-semibold text-ink">SecureScan AI</span>
        </div>

        {loadError && (
          <div className="border-b border-sev-critical/30 bg-sev-critical/10 px-6 py-2.5 text-xs text-sev-critical">
            {loadError}
          </div>
        )}

        {!selectedAsset ? (
          <div className="flex h-full flex-col items-center justify-center gap-3 text-muted">
            <ScanSearch className="h-8 w-8" strokeWidth={1.5} />
            <p className="text-sm">{tr("addAssetPrompt")}</p>
          </div>
        ) : (
          <div className="mx-auto max-w-3xl px-4 py-6 md:px-6 md:py-8">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="font-display text-xl font-semibold text-ink">{selectedAsset.domain}</h1>
                  {selectedAsset.is_demo && (
                    <span className="rounded-full border border-accent/30 bg-accent/10 px-2 py-0.5 text-[11px] font-medium text-accent">
                      {tr("demoData")}
                    </span>
                  )}
                </div>
                <p className="mt-0.5 text-xs text-muted">
                  {tr("assetNumber", { id: selectedAsset.id })} ·{" "}
                  {selectedAsset.is_verified ? tr("ownershipConfirmed") : tr("verificationRequired")}
                </p>
              </div>
              <div className="flex rounded-lg border border-line bg-surface p-1">
                {(["overview", "monitoring"] as Tab[]).map((t) => (
                  <button
                    key={t}
                    onClick={() => setTab(t)}
                    className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                      tab === t ? "bg-surface2 text-ink" : "text-muted hover:text-ink"
                    }`}
                  >
                    {t === "overview" ? tr("overview") : tr("monitoring")}
                  </button>
                ))}
              </div>
            </div>

            {tab === "overview" ? (
              <div className="mt-6 space-y-5">
                <VerificationPanel asset={selectedAsset} onVerified={handleVerified} />
                <ScanLauncher
                  asset={selectedAsset}
                  scans={scans}
                  launching={launching}
                  onLaunch={handleLaunch}
                  selectedScanId={selectedScanId}
                  onSelectScan={setSelectedScanId}
                  onCancelScan={handleCancelScan}
                />
                {report && <ReportPanel report={report} />}
              </div>
            ) : (
              <div className="mt-6">
                <MonitoringPanel
                  asset={selectedAsset}
                  schedules={schedules}
                  onChange={() => refreshSchedules(selectedAsset.id)}
                />
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
