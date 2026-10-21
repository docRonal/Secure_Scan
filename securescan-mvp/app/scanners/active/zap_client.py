"""HTTP client for the public OWASP ZAP API."""
import time

import requests


class ZAPError(RuntimeError):
    """ZAP API or connection error."""


class ZAPScanCancelled(RuntimeError):
    """The user cancelled the scan."""


class ZAPTimeout(RuntimeError):
    """The scan exceeded its configured time limit."""

    def __init__(self, message: str, last_progress: int):
        super().__init__(message)
        self.last_progress = last_progress


class ZAPClient:
    def __init__(self, base_url: str, api_key: str | None, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _get(
        self, path: str, params: dict | None = None, timeout: float | None = None
    ) -> dict:
        params = dict(params or {})
        if self.api_key:
            params["apikey"] = self.api_key
        try:
            resp = requests.get(
                f"{self.base_url}{path}",
                params=params,
                timeout=self.timeout if timeout is None else timeout,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise ZAPError(f"Не удалось обратиться к ZAP API ({path}): {exc}") from exc
        return resp.json()

    def is_available(self) -> bool:
        try:
            self._get("/JSON/core/view/version/")
            return True
        except ZAPError:
            return False

    # ---------------------------------------------------------------- spider

    def start_spider(self, target_url: str) -> str:
        """Start the standard spider to discover in-scope pages."""
        data = self._get("/JSON/spider/action/scan/", {"url": target_url, "recurse": "true"})
        return data["scan"]

    def spider_status(self, scan_id: str) -> int:
        """Return spider progress as a percentage."""
        data = self._get("/JSON/spider/view/status/", {"scanId": scan_id})
        return int(data["status"])

    def start_ajax_spider(self, target_url: str) -> None:
        """Start AJAX Spider to discover JavaScript-generated routes."""
        self._get(
            "/JSON/ajaxSpider/action/scan/",
            {"url": target_url, "inScope": "true"},
        )

    def ajax_spider_status(self, _scan_id: str | None = None) -> int:
        """Convert AJAX Spider status to the shared poller's progress value."""
        data = self._get("/JSON/ajaxSpider/view/status/")
        return 100 if str(data.get("status", "")).lower() == "stopped" else 0

    def stop_ajax_spider(self) -> None:
        """Stop AJAX Spider in ZAP."""
        self._get("/JSON/ajaxSpider/action/stop/")

    # ------------------------------------------------------------ active scan

    def start_active_scan(self, target_url: str, scan_policy: str | None = None) -> str:
        """Start ZAP active scanning, which sends test payloads to the target."""
        params = {"url": target_url, "recurse": "true"}
        if scan_policy:
            params["scanPolicyName"] = scan_policy
        data = self._get("/JSON/ascan/action/scan/", params)
        return data["scan"]

    @staticmethod
    def _normalize_attack_strength(attack_strength: str) -> str:
        """Normalize attack strength to values supported by ZAP."""
        supported = {"Low", "Medium", "High"}
        value = (attack_strength or "High").strip()
        if value in supported:
            return value
        return "High"

    def configure_scan_policy(
        self,
        scan_policy: str | None,
        *,
        attack_strength: str = "High",
        alert_threshold: str = "Medium",
        enable_all_scanners: bool = True,
    ) -> None:
        """Configure active scanners through the ZAP API."""
        if scan_policy == "Default Policy":
            scan_policy = None

        normalized_attack_strength = self._normalize_attack_strength(attack_strength)

        scanners = self._get("/JSON/ascan/view/scanners/").get("scanners", [])
        for scanner in scanners:
            scanner_id = scanner.get("id")
            if not scanner_id:
                continue
            self._get(
                "/JSON/ascan/action/setScannerAttackStrength/",
                {"id": scanner_id, "attackStrength": normalized_attack_strength},
            )
            self._get(
                "/JSON/ascan/action/setScannerAlertThreshold/",
                {"id": scanner_id, "alertThreshold": alert_threshold},
            )

        if enable_all_scanners:
            self._get("/JSON/ascan/action/enableAllScanners/")

    def ascan_status(self, scan_id: str) -> int:
        data = self._get("/JSON/ascan/view/status/", {"scanId": scan_id})
        return int(data["status"])

    def stop_active_scan(self, scan_id: str) -> None:
        """Stop an active scan in ZAP."""
        self._get("/JSON/ascan/action/stop/", {"scanId": scan_id})

    def stop_spider(self, scan_id: str) -> None:
        """Stop the standard spider in ZAP."""
        self._get("/JSON/spider/action/stop/", {"scanId": scan_id})

    # ---------------------------------------------------------------- alerts

    def get_alerts(
        self,
        base_url: str,
        timeout: float | None = None,
        start: int = 0,
        count: int = 100,
    ) -> list[dict]:
        """Fetch ZAP alerts for the requested base URL."""
        data = self._get(
            "/JSON/core/view/alerts/",
            {"baseurl": base_url, "start": start, "count": count},
            timeout=timeout,
        )
        return data.get("alerts", [])

    # --------------------------------------------------------------- helpers

    def wait_until_complete(
        self, status_fn, scan_id: str, poll_interval: float, max_wait: int,
        should_cancel=None, on_progress=None,
    ) -> None:
        """Poll scan progress until completion, cancellation, or timeout."""
        waited = 0.0
        last_progress = 0
        while True:
            if should_cancel is not None and should_cancel():
                raise ZAPScanCancelled("Скан отменён пользователем")

            progress = status_fn(scan_id)
            last_progress = progress
            if on_progress is not None:
                on_progress(progress)

            if progress >= 100:
                return
            if waited >= max_wait:
                raise ZAPTimeout(
                    f"Скан не завершился за {max_wait} сек. (прогресс {progress}%). "
                    "Увеличьте zap_max_wait_seconds или проверьте состояние ZAP вручную.",
                    last_progress=last_progress,
                )
            time.sleep(poll_interval)
            waited += poll_interval
