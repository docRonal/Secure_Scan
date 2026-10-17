import { useState } from "react";
import { ShieldCheck, Copy, Check } from "lucide-react";
import type { Asset, VerificationMethod } from "../types";
import { api, ApiError } from "../api";
import { useLanguage } from "../i18n";

const METHODS: { key: VerificationMethod; hint: (token: string, domain: string) => string }[] = [
  {
    key: "dns_txt",
    hint: (token, domain) => `_securescan.${domain}  TXT  "${token}"`,
  },
  {
    key: "meta_tag",
    hint: (token) => `<meta name="securescan-verification" content="${token}">`,
  },
  {
    key: "file_token",
    hint: (token, domain) => `https://${domain}/securescan-verify.txt  →  ${token}`,
  },
];

interface Props {
  asset: Asset;
  onVerified: (asset: Asset) => void;
}

export default function VerificationPanel({ asset, onVerified }: Props) {
  const { t: tr } = useLanguage();
  const [method, setMethod] = useState<VerificationMethod>("dns_txt");
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function handleCheck() {
    setChecking(true);
    setError(null);
    try {
      const updated = await api.verifyAsset(asset.id, method);
      onVerified(updated);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : tr("verifyFailed"));
    } finally {
      setChecking(false);
    }
  }

  function handleCopy() {
    navigator.clipboard.writeText(asset.verification_token);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  if (asset.is_verified) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-accent/30 bg-accent/10 px-4 py-3 text-sm text-accent">
        <ShieldCheck className="h-4 w-4" />
        {asset.verification_method
          ? tr("verifiedActiveAvailable", {
              method: asset.verification_method === "dns_txt"
                ? tr("dnsTxt")
                : asset.verification_method === "meta_tag"
                ? tr("metaTag")
                : tr("fileToken"),
            })
          : tr("verifiedActiveAvailableNoMethod")}
      </div>
    );
  }

  if (asset.is_demo) {
    return (
      <div className="rounded-xl border border-line bg-surface p-5 shadow-panel">
        <h3 className="font-display text-sm font-semibold text-ink">{tr("verificationTitle")}</h3>
        <p className="mt-2 text-xs leading-relaxed text-muted">
          {tr("demoDomainNotice", { domain: asset.domain })}
        </p>
        <p className="mt-2 text-xs leading-relaxed text-muted">
          {tr("addOwnedDomain")}
        </p>
      </div>
    );
  }

  const active = METHODS.find((m) => m.key === method)!;

  return (
    <div className="rounded-xl border border-line bg-surface p-5 shadow-panel">
      <h3 className="font-display text-sm font-semibold text-ink">{tr("verificationTitle")}</h3>
      <p className="mt-1 text-xs text-muted">
        {tr("verificationMethodsRequired")}
      </p>

      <div className="mt-4 flex gap-1.5">
        {METHODS.map((m) => (
          <button
            key={m.key}
            onClick={() => setMethod(m.key)}
            className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
              method === m.key ? "bg-accent/15 text-accent" : "text-muted hover:bg-surface2"
            }`}
          >
            {m.key === "dns_txt" ? tr("dnsTxt") : m.key === "meta_tag" ? tr("metaTag") : tr("fileToken")}
          </button>
        ))}
      </div>

      <div className="mt-3 flex items-center justify-between gap-2 rounded-lg border border-line bg-base px-3 py-2.5">
        <code className="truncate font-mono text-xs text-ink">
          {active.hint(asset.verification_token, asset.domain)}
        </code>
        <button
          onClick={handleCopy}
          aria-label={tr("copyToken")}
          className="shrink-0 text-muted hover:text-ink"
        >
          {copied ? <Check className="h-3.5 w-3.5 text-accent" /> : <Copy className="h-3.5 w-3.5" />}
        </button>
      </div>

      <button
        onClick={handleCheck}
        disabled={checking}
        className="mt-4 rounded-lg bg-accent px-4 py-2 text-sm font-medium text-base transition-opacity hover:opacity-90 disabled:opacity-50"
      >
        {checking ? tr("checking") : tr("verifyToken")}
      </button>
      {error && <p className="mt-2 text-xs text-sev-critical">{error}</p>}
    </div>
  );
}
