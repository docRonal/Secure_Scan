"""Tests for safe report exports."""
import csv
import io

from app.reporting.report_generator import render_csv_report


def test_csv_export_neutralizes_spreadsheet_formulas():
    report = {
        "findings": [
            {
                "severity": "low",
                "title": "\t=HYPERLINK(\"https://example.invalid\")",
                "checker": "headers",
                "owasp_category": None,
                "cwe_id": None,
                "description": "+1+1",
                "recommendation": None,
                "evidence": "@SUM(A1:A2)",
            }
        ]
    }

    rows = list(csv.reader(io.StringIO(render_csv_report(report))))

    assert rows[1][1].startswith("'\t=")
    assert rows[1][5] == "'+1+1"
    assert rows[1][7] == "'@SUM(A1:A2)"