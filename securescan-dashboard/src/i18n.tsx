import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";

const translations = {
  ru: {
    loading: "Загрузка…",
    backendUnavailable: "Не удалось подключиться к backend. Убедитесь, что он запущен.",
    scanStartFailed: "Не удалось запустить скан",
    scanCancelFailed: "Не удалось остановить скан",
    addAssetFailed: "Не удалось добавить актив",
    verifyFailed: "Не удалось проверить владение активом",
    scheduleFailed: "Не удалось создать расписание",
    openMenu: "Открыть меню",
    closeMenu: "Закрыть меню",
    addAssetPrompt: "Добавьте актив слева, чтобы начать проверку.",
    demoData: "Демо: синтетические данные",
    assetNumber: "Актив #{id}",
    ownershipConfirmed: "владение подтверждено",
    verificationRequired: "требуется верификация",
    overview: "Обзор",
    monitoring: "Мониторинг",
    login: "Вход",
    accountProvisioning: "Учётную запись создаёт оператор сервиса. Запросите у него данные для входа.",
    register: "Регистрация",
    password: "Пароль",
    passwordPlaceholder: "не менее 8 символов",
    signIn: "Войти",
    createAccount: "Создать аккаунт",
    watchedAssets: "Активы под наблюдением",
    emptyAssets: "Активов пока нет — добавьте первый домен.",
    addAsset: "Добавить актив",
    logout: "Выйти",
    scanning: "Сканирование",
    passiveScan: "Пассивный скан",
    activeScan: "Активный скан",
    launch: "Запуск…",
    ownershipRequired: "Требуется подтверждение владения активом",
    noScans: "Сканов ещё не было — запустите первый.",
    passive: "Пассивный",
    active: "Активный",
    stopping: "Останавливается…",
    stopScan: "Остановить скан",
    reportForScan: "Отчёт по скану #{id}",
    riskScore: "Оценка риска",
    scanStopped: "Скан остановлен",
    scanBlocked: "Скан заблокирован",
    scanFailed: "Скан завершился с ошибкой",
    noFindings: "Находок нет.",
    verificationTitle: "Подтверждение владения активом",
    verificationMethodsRequired: "Подтверждение обязательно перед активным сканированием. Пассивные проверки доступны без него.",
    verifiedActiveAvailable: "Владение подтверждено ({method}) — активное сканирование доступно.",
    verifiedActiveAvailableNoMethod: "Владение подтверждено — активное сканирование доступно.",
    demoDomainNotice: "{domain} — демонстрационный домен из зарезервированной зоны .example (RFC 2606). Он не существует в интернете, поэтому его нельзя подтвердить.",
    addOwnedDomain: "Чтобы проверить владение и запустить активное сканирование, добавьте домен, которым вы владеете.",
    dnsTxt: "Запись DNS TXT",
    metaTag: "Мета-тег",
    fileToken: "Файл-токен",
    copyToken: "Скопировать токен",
    checking: "Проверяю…",
    verifyToken: "Проверить размещение токена",
    monitoringTitle: "Непрерывный мониторинг",
    monitoringDescription: "Плановые повторные сканы. При появлении новых находок отправляется уведомление.",
    demoScheduleNotice: "Демо: расписание показано для примера. Запуски невозможны, так как домен demo-shop.example зарезервирован.",
    activeNeedsVerification: "(нужна верификация)",
    daily: "Раз в сутки",
    weekly: "Раз в неделю",
    monthly: "Раз в месяц",
    enabling: "Создаю…",
    enable: "Включить",
    noSchedules: "Расписаний пока нет.",
    everyHours: "каждые {hours} ч",
    lastRun: "Последний запуск: {time}",
    nextRun: "Следующий: {time}",
    neverRun: "ещё не запускался",
    enabled: "активно",
    paused: "на паузе",
    pauseSchedule: "Приостановить",
    resumeSchedule: "Возобновить",
    deleteSchedule: "Удалить расписание",
    scanQueued: "В очереди",
    scanRunning: "Сканирование",
    scanCompleted: "Завершён",
    scanError: "Ошибка",
    scanUnverified: "Заблокирован",
    scanCancelled: "Остановлен",
    cancelledDetails: "Сканирование отменено пользователем.",
    blockedDetails: "Активное сканирование требует подтверждённого владения активом.",
    failedDetails: "Сканирование не удалось. Подробности доступны в логах backend.",
    stepSpider: "Spider (обход страниц)",
    stepAjaxSpider: "AJAX Spider (JavaScript-маршруты)",
    stepActiveScan: "Активный скан (проверка)",
    stepComplete: "Завершено",
    stepCheck: "Проверка",
    severityInfo: "Инфо",
    severityLow: "Низкий",
    severityMedium: "Средний",
    severityHigh: "Высокий",
    severityCritical: "Критический",
    language: "Язык интерфейса",
  },
  en: {
    loading: "Loading…",
    backendUnavailable: "Could not connect to the backend. Make sure it is running.",
    scanStartFailed: "Could not start the scan",
    scanCancelFailed: "Could not stop the scan",
    addAssetFailed: "Could not add the asset",
    verifyFailed: "Could not verify asset ownership",
    scheduleFailed: "Could not create the schedule",
    openMenu: "Open menu",
    closeMenu: "Close menu",
    addAssetPrompt: "Add an asset on the left to start a scan.",
    demoData: "Demo: synthetic data",
    assetNumber: "Asset #{id}",
    ownershipConfirmed: "ownership verified",
    verificationRequired: "verification required",
    overview: "Overview",
    monitoring: "Monitoring",
    login: "Sign in",
    accountProvisioning: "Sign-in accounts are provisioned by the service operator. Ask them for your credentials.",
    register: "Create account",
    password: "Password",
    passwordPlaceholder: "At least 8 characters",
    signIn: "Sign in",
    createAccount: "Create account",
    watchedAssets: "Monitored assets",
    emptyAssets: "No assets yet. Add your first domain below.",
    addAsset: "Add asset",
    logout: "Sign out",
    scanning: "Scanning",
    passiveScan: "Passive scan",
    activeScan: "Active scan",
    launch: "Starting…",
    ownershipRequired: "Asset ownership verification is required",
    noScans: "No scans yet. Start the first one.",
    passive: "Passive",
    active: "Active",
    stopping: "Stopping…",
    stopScan: "Stop scan",
    reportForScan: "Scan report #{id}",
    riskScore: "Risk score",
    scanStopped: "Scan stopped",
    scanBlocked: "Scan blocked",
    scanFailed: "Scan failed",
    noFindings: "No findings.",
    verificationTitle: "Asset ownership verification",
    verificationMethodsRequired: "Verification is required before active scans. Passive checks are available without it.",
    verifiedActiveAvailable: "Ownership verified ({method}) — active scanning is available.",
    verifiedActiveAvailableNoMethod: "Ownership verified — active scanning is available.",
    demoDomainNotice: "{domain} is a demo domain in the reserved .example zone (RFC 2606). It does not exist on the public internet and cannot be verified.",
    addOwnedDomain: "To verify ownership and run an active scan, add a domain you own.",
    dnsTxt: "DNS TXT record",
    metaTag: "Meta tag",
    fileToken: "Verification file",
    copyToken: "Copy token",
    checking: "Checking…",
    verifyToken: "Verify token placement",
    monitoringTitle: "Continuous monitoring",
    monitoringDescription: "Scheduled recurring scans. Notifications are sent when new findings appear.",
    demoScheduleNotice: "Demo: this schedule is illustrative. Scans cannot run because demo-shop.example is reserved.",
    activeNeedsVerification: "(verification required)",
    daily: "Daily",
    weekly: "Weekly",
    monthly: "Monthly",
    enabling: "Creating…",
    enable: "Enable",
    noSchedules: "No schedules yet.",
    everyHours: "every {hours} h",
    lastRun: "Last run: {time}",
    nextRun: "Next: {time}",
    neverRun: "not run yet",
    enabled: "active",
    paused: "paused",
    pauseSchedule: "Pause schedule",
    resumeSchedule: "Resume schedule",
    deleteSchedule: "Delete schedule",
    scanQueued: "Queued",
    scanRunning: "Scanning",
    scanCompleted: "Completed",
    scanError: "Failed",
    scanUnverified: "Blocked",
    scanCancelled: "Cancelled",
    cancelledDetails: "The scan was cancelled by the user.",
    blockedDetails: "Active scanning requires verified asset ownership.",
    failedDetails: "The scan failed. See backend logs for details.",
    stepSpider: "Spider crawl",
    stepAjaxSpider: "AJAX Spider (JavaScript routes)",
    stepActiveScan: "Active scan",
    stepComplete: "Completed",
    stepCheck: "Check",
    severityInfo: "Info",
    severityLow: "Low",
    severityMedium: "Medium",
    severityHigh: "High",
    severityCritical: "Critical",
    language: "Interface language",
  },
} as const;

export type Language = keyof typeof translations;
export type TranslationKey = keyof typeof translations.en;

interface LanguageContextValue {
  language: Language;
  setLanguage: (language: Language) => void;
  t: (key: TranslationKey, params?: Record<string, string | number>) => string;
}

const LanguageContext = createContext<LanguageContextValue | null>(null);
const STORAGE_KEY = "securescan-language";

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [language, setLanguage] = useState<Language>(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "ru" || stored === "en") return stored;
    return navigator.language.toLowerCase().startsWith("ru") ? "ru" : "en";
  });

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, language);
    document.documentElement.lang = language;
  }, [language]);

  const t = useCallback(
    (key: TranslationKey, params: Record<string, string | number> = {}) =>
      Object.entries(params).reduce(
        (text, [name, value]) => text.split(`{${name}}`).join(String(value)),
        translations[language][key] as string,
      ),
    [language],
  );

  return (
    <LanguageContext.Provider value={{ language, setLanguage, t }}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useLanguage() {
  const context = useContext(LanguageContext);
  if (!context) throw new Error("useLanguage must be used within LanguageProvider");
  return context;
}

export function LanguageSwitcher() {
  const { language, setLanguage, t } = useLanguage();

  return (
    <div
      aria-label={t("language")}
      className="inline-flex rounded-md border border-line bg-surface2 p-0.5"
      role="group"
    >
      {(["ru", "en"] as const).map((option) => (
        <button
          key={option}
          type="button"
          aria-pressed={language === option}
          onClick={() => setLanguage(option)}
          className={`min-w-9 rounded px-2 py-1 text-[11px] font-semibold uppercase transition-colors ${
            language === option ? "bg-surface text-ink" : "text-muted hover:text-ink"
          }`}
        >
          {option}
        </button>
      ))}
    </div>
  );
}