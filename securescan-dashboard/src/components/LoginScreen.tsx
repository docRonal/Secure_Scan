import { useState, type FormEvent } from "react";
import { ShieldCheck, Loader2 } from "lucide-react";
import { api, ApiError } from "../api";
import { auth } from "../auth";
import { LanguageSwitcher, useLanguage } from "../i18n";

interface Props {
  onAuthenticated: () => void;
}

export default function LoginScreen({ onAuthenticated }: Props) {
  const { t: tr } = useLanguage();
  const registrationEnabled = import.meta.env.VITE_PUBLIC_REGISTRATION_ENABLED === "true";
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const { access_token } = mode === "login"
        ? await api.login(email, password)
        : await api.register(email, password);
      auth.setToken(access_token);
      onAuthenticated();
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : tr("backendUnavailable");
      setError(message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex h-screen items-center justify-center bg-base">
      <div className="w-full max-w-sm rounded-xl border border-line bg-surface p-6 shadow-panel">
        <div className="mb-6 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-accent" strokeWidth={2} />
            <span className="font-display text-[15px] font-semibold tracking-tight text-ink">
              SecureScan AI
            </span>
          </div>
          <LanguageSwitcher />
        </div>

        <p className="mb-4 text-xs text-muted">{tr("accountProvisioning")}</p>

        {registrationEnabled && (
          <div className="mb-5 flex rounded-lg border border-line bg-surface2 p-1">
            {(["login", "register"] as const).map((option) => (
              <button
                key={option}
                type="button"
                onClick={() => {
                  setMode(option);
                  setError(null);
                  setEmail("");
                  setPassword("");
                }}
                className={`flex-1 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                  mode === option ? "bg-surface text-ink" : "text-muted hover:text-ink"
                }`}
              >
                {option === "login" ? tr("login") : tr("register")}
              </button>
            ))}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="mb-1 block text-xs text-muted">Email</label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              className="w-full rounded-lg border border-line bg-surface2 px-3 py-2 text-sm text-ink placeholder:text-muted focus:border-accent focus:outline-none"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-muted">{tr("password")}</label>
            <input
              type="password"
              required
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={tr("passwordPlaceholder")}
              className="w-full rounded-lg border border-line bg-surface2 px-3 py-2 text-sm text-ink placeholder:text-muted focus:border-accent focus:outline-none"
            />
          </div>

          {error && <p className="text-xs text-sev-critical">{error}</p>}

          <button
            type="submit"
            disabled={submitting}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-accent px-3 py-2.5 text-sm font-medium text-white transition-colors hover:bg-accent/90 disabled:opacity-50"
          >
            {submitting && <Loader2 className="h-4 w-4 animate-spin" />}
            {mode === "login" ? tr("signIn") : tr("createAccount")}
          </button>
        </form>
        <a
          href="https://github.com/docRonal/Secure_Scan"
          target="_blank"
          rel="noreferrer"
          className="mt-4 block text-center text-xs text-muted hover:text-ink"
        >
          {tr("sourceCode")}
        </a>
      </div>
    </div>
  );
}
