import { useState, type FormEvent } from "react";
import { ShieldCheck, ShieldAlert, Plus, ScanSearch, LogOut, X } from "lucide-react";
import type { Asset, User } from "../types";
import { LanguageSwitcher, useLanguage } from "../i18n";

interface Props {
  assets: Asset[];
  selectedId: number | null;
  onSelect: (id: number) => void;
  onCreate: (domain: string) => Promise<void>;
  user: User;
  onLogout: () => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

export default function Sidebar({
  assets, selectedId, onSelect, onCreate, user, onLogout, mobileOpen, onCloseMobile,
}: Props) {
  const { t: tr } = useLanguage();
  const [domain, setDomain] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!domain.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      await onCreate(domain.trim());
      setDomain("");
    } catch (err: any) {
      setError(err.message ?? tr("addAssetFailed"));
    } finally {
      setSubmitting(false);
    }
  }

  function handleSelect(id: number) {
    onSelect(id);
    onCloseMobile();
  }

  return (
    <>
      {/* Backdrop for the open mobile navigation drawer. */}
      {mobileOpen && (
        <div
          onClick={onCloseMobile}
          className="fixed inset-0 z-40 bg-black/50 md:hidden"
          aria-hidden="true"
        />
      )}

      <aside
        className={`fixed inset-y-0 left-0 z-50 flex h-full w-72 flex-col border-r border-line bg-surface transition-transform duration-200 ease-out md:static md:z-auto md:translate-x-0 ${
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="scanline-texture border-b border-line px-5 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ScanSearch className="h-5 w-5 text-accent" strokeWidth={2} />
              <span className="font-display text-[15px] font-semibold tracking-tight">
                SecureScan AI
              </span>
            </div>
            <button
              onClick={onCloseMobile}
              aria-label={tr("closeMenu")}
              className="rounded-md p-1 text-muted hover:bg-surface2 hover:text-ink md:hidden"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          <p className="mt-1 text-xs text-muted">{tr("watchedAssets")}</p>
        </div>

        <div className="flex-1 overflow-y-auto px-3 py-3">
          {assets.length === 0 && (
            <p className="px-2 py-6 text-center text-sm text-muted">
              {tr("emptyAssets")}
            </p>
          )}
          <ul className="space-y-1">
            {assets.map((asset) => (
              <li key={asset.id}>
                <button
                  onClick={() => handleSelect(asset.id)}
                  className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2.5 text-left text-sm transition-colors ${
                    selectedId === asset.id
                      ? "bg-surface2 text-ink"
                      : "text-muted hover:bg-surface2/60 hover:text-ink"
                  }`}
                >
                  {asset.is_verified ? (
                    <ShieldCheck className="h-4 w-4 shrink-0 text-accent" />
                  ) : (
                    <ShieldAlert className="h-4 w-4 shrink-0 text-sev-medium" />
                  )}
                  <span className="truncate font-mono text-[13px]">{asset.domain}</span>
                  {asset.is_demo && (
                    <span className="ml-auto shrink-0 rounded-full border border-accent/30 bg-accent/10 px-1.5 py-0.5 text-[10px] font-medium text-accent">
                      Demo
                    </span>
                  )}
                </button>
              </li>
            ))}
          </ul>
        </div>

        <form onSubmit={handleSubmit} className="border-t border-line p-3">
          <div className="flex items-center gap-2 rounded-lg border border-line bg-surface2 px-3 py-2 focus-within:border-accent">
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              className="w-full bg-transparent font-mono text-[13px] text-ink placeholder:text-muted focus:outline-none"
            />
            <button
              type="submit"
              disabled={submitting}
              aria-label={tr("addAsset")}
              className="shrink-0 rounded-md bg-accent/15 p-1 text-accent transition-colors hover:bg-accent/25 disabled:opacity-50"
            >
              <Plus className="h-4 w-4" />
            </button>
          </div>
          {error && <p className="mt-2 text-xs text-sev-critical">{error}</p>}
        </form>

        <a
          href="https://github.com/docRonal/Secure_Scan"
          target="_blank"
          rel="noreferrer"
          className="border-t border-line px-3 py-2 text-center text-xs text-muted hover:text-ink"
        >
          {tr("sourceCode")}
        </a>

        <div className="flex items-center justify-between gap-2 border-t border-line px-3 py-2.5">
          <span className="truncate text-xs text-muted" title={user.email}>
            {user.email}
          </span>
          <LanguageSwitcher />
          {!user.is_guest && (
            <button
              onClick={onLogout}
              aria-label={tr("logout")}
              title={tr("logout")}
              className="shrink-0 rounded-md p-1.5 text-muted transition-colors hover:bg-surface2 hover:text-sev-critical"
            >
              <LogOut className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </aside>
    </>
  );
}
