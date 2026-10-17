"""Notification interfaces and the default structured-log implementation."""
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

logger = logging.getLogger("securescan.notifications")


@dataclass
class NotificationEvent:
    asset_domain: str
    scan_id: int
    new_findings_count: int
    highest_new_severity: str
    summary: str


class Notifier(ABC):
    @abstractmethod
    def send(self, event: NotificationEvent) -> None:
        raise NotImplementedError


class LoggingNotifier(Notifier):
    """Default implementation that writes notification events to the app log."""

    def send(self, event: NotificationEvent) -> None:
        logger.warning(
            "[ALERT] %s — скан #%s: %s новых находок, макс. severity=%s. %s",
            event.asset_domain,
            event.scan_id,
            event.new_findings_count,
            event.highest_new_severity,
            event.summary,
        )


active_notifier: Notifier = LoggingNotifier()
