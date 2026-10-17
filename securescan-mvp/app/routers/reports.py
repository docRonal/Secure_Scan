from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session
from typing import Literal

from app.db import get_db
from app.models import ScanJob, Asset, User
from app.reporting.report_generator import (
    build_report, render_html_report, render_csv_report, render_pdf_report,
)
from app.security import get_current_user_flexible as get_current_user

router = APIRouter(prefix="/reports", tags=["reports"])


def _assert_owns_scan(scan_id: int, db: Session, current_user: User) -> None:
    """Return 404 for missing or unowned scans to prevent enumeration."""
    owned = (
        db.query(ScanJob)
        .join(Asset, ScanJob.asset_id == Asset.id)
        .filter(ScanJob.id == scan_id, Asset.owner_id == current_user.id)
        .first()
    )
    if not owned:
        raise HTTPException(404, "Скан не найден")


@router.get("/{scan_id}")
def get_report(
    scan_id: int,
    format: Literal["json", "html", "csv", "pdf"] = Query(default="json"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _assert_owns_scan(scan_id, db, current_user)

    try:
        report = build_report(db, scan_id)
    except ValueError:
        raise HTTPException(404, "Скан не найден")

    if format == "html":
        return HTMLResponse(content=render_html_report(report))

    if format == "csv":
        csv_body = render_csv_report(report)
        return Response(
            content=csv_body,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-report.csv"'},
        )

    if format == "pdf":
        pdf_bytes = render_pdf_report(report)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-report.pdf"'},
        )

    return report
