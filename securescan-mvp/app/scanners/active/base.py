"""Base interface for active-scanning engine plugins."""
from abc import ABC, abstractmethod
from typing import Callable

from app.scanners.base import ScanFinding


class ActiveScannerPlugin(ABC):
    """Active scanner plugin interface."""

    name: str = "active_scan_plugin"

    @abstractmethod
    def run(
        self,
        domain: str,
        verification_proof: str,
        should_cancel: Callable[[], bool],
        on_progress: Callable[[int, str], None] | None = None,
    ) -> list[ScanFinding]:
        """Run an active scan and report findings and progress."""
        raise NotImplementedError
