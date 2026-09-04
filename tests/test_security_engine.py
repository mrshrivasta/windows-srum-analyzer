"""Tests for the Security Engine and Detection Rules — rule-level unit tests
against synthetic context dicts, PLUS genuine engine-level tests that write
REAL spec-conformant SRUM export CSVs to real temp files and run the actual
ScanEngine (no mocking of csv parsing)."""
import csv
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import ScanEngine, parse_srum_timestamp
from app.detection_rules import (
    rule_large_outbound_transfer_outlier,
    rule_suspicious_execution_directory,
    rule_unexpected_networked_application,
    rule_disproportionate_background_activity,
    rule_unparseable_timestamp,
    rule_unrecognized_export_format,
)

NETWORK_FIELDS = ["TimeStamp", "AppId", "UserId", "InterfaceLuid", "L2ProfileId", "BytesSent", "BytesRecvd"]
APP_RESOURCE_FIELDS = [
    "TimeStamp", "AppId", "UserId", "ForegroundCycleTime", "BackgroundCycleTime",
    "FaceTime", "ForegroundContextSwitches", "BackgroundContextSwitches",
    "ForegroundBytesRead", "ForegroundBytesWritten", "BackgroundBytesRead",
    "BackgroundBytesWritten",
]


# ----------------------------------------------------------------------
# Rule-level unit tests (synthetic context dicts)
# ----------------------------------------------------------------------

def test_rule_large_outbound_transfer_outlier_fires():
    ctx = {"table": "network", "bytes_sent": 200 * 1024 * 1024, "bytes_sent_mean": 1000, "app_id": "C:\\evil.exe"}
    result = rule_large_outbound_transfer_outlier(ctx)
    assert result is not None
    assert result["rule_id"] == "WSR-001"
    assert result["severity"] == "high"


def test_rule_large_outbound_transfer_outlier_respects_floor():
    # Even a huge multiple of a tiny mean should not fire below the 50MB floor.
    ctx = {"table": "network", "bytes_sent": 1000, "bytes_sent_mean": 1, "app_id": "x.exe"}
    assert rule_large_outbound_transfer_outlier(ctx) is None


def test_rule_large_outbound_transfer_outlier_ignores_non_network():
    ctx = {"table": "app_resource", "bytes_sent": 999999999, "bytes_sent_mean": 1}
    assert rule_large_outbound_transfer_outlier(ctx) is None


def test_rule_suspicious_execution_directory_fires():
    ctx = {"app_id": "C:\\Users\\bob\\AppData\\Local\\Temp\\payload.exe"}
    result = rule_suspicious_execution_directory(ctx)
    assert result is not None
    assert result["rule_id"] == "WSR-002"


def test_rule_suspicious_execution_directory_clean_path():
    ctx = {"app_id": "C:\\Program Files\\Vendor\\app.exe"}
    assert rule_suspicious_execution_directory(ctx) is None


def test_rule_unexpected_networked_application_fires():
    ctx = {"table": "network", "app_id": "C:\\Users\\bob\\weird_tool.exe"}
    result = rule_unexpected_networked_application(ctx)
    assert result is not None
    assert result["rule_id"] == "WSR-003"


def test_rule_unexpected_networked_application_allowlisted():
    ctx = {"table": "network", "app_id": "C:\\Program Files\\Google\\Chrome\\chrome.exe"}
    assert rule_unexpected_networked_application(ctx) is None


def test_rule_disproportionate_background_activity_fires():
    ctx = {
        "table": "app_resource",
        "foreground_cycle_time": 1000,
        "background_cycle_time": 50_000_000,
        "app_id": "C:\\ProgramData\\svc\\worker.exe",
    }
    result = rule_disproportionate_background_activity(ctx)
    assert result is not None
    assert result["rule_id"] == "WSR-004"


def test_rule_disproportionate_background_activity_requires_suspicious_dir():
    ctx = {
        "table": "app_resource",
        "foreground_cycle_time": 1000,
        "background_cycle_time": 50_000_000,
        "app_id": "C:\\Program Files\\Vendor\\worker.exe",
    }
    assert rule_disproportionate_background_activity(ctx) is None


def test_rule_unparseable_timestamp_fires():
    ctx = {"timestamp_unparsed": True, "timestamp_raw": "not-a-date", "app_id": "x.exe"}
    result = rule_unparseable_timestamp(ctx)
    assert result is not None
    assert result["rule_id"] == "WSR-005"


def test_rule_unrecognized_export_format_fires():
    ctx = {"unrecognized_format": True, "csv_path": "/tmp/weird.csv"}
    result = rule_unrecognized_export_format(ctx)
    assert result is not None
    assert result["rule_id"] == "WSR-006"


def test_parse_srum_timestamp_iso8601():
    dt = parse_srum_timestamp("2024-03-15T10:30:00")
    assert dt is not None and dt.year == 2024 and dt.month == 3


def test_parse_srum_timestamp_us_format():
    dt = parse_srum_timestamp("03/15/2024 10:30:00")
    assert dt is not None and dt.year == 2024


def test_parse_srum_timestamp_invalid():
    assert parse_srum_timestamp("banana") is None
    assert parse_srum_timestamp("") is None


# ----------------------------------------------------------------------
# Engine-level tests: REAL spec-conformant CSVs written via csv.DictWriter,
# parsed by the real ScanEngine.
# ----------------------------------------------------------------------

def _write_network_csv(path, rows):
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=NETWORK_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _write_app_resource_csv(path, rows):
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=APP_RESOURCE_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def test_engine_detects_outbound_outlier_and_suspicious_dir():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "NetworkUsage.csv")
        # 20 real "normal" low-volume rows, so the outlier row (below) is a
        # true statistical outlier relative to the real computed mean rather
        # than dominating/skewing it on its own.
        rows = [
            {
                "TimeStamp": "2024-03-15T09:00:00", "AppId": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
                "UserId": "S-1-5-21-1111", "InterfaceLuid": "1", "L2ProfileId": "0",
                "BytesSent": 9000 + i, "BytesRecvd": 20000,
            }
            for i in range(20)
        ]
        rows.append({
            "TimeStamp": "2024-03-15T09:05:00", "AppId": "C:\\Program Files\\Vendor\\svchost.exe",
            "UserId": "S-1-5-21-1111", "InterfaceLuid": "1", "L2ProfileId": "0",
            "BytesSent": 8000, "BytesRecvd": 15000,
        })
        rows.append({
            # Real statistical outlier: huge BytesSent from a Temp-dir AppId
            "TimeStamp": "2024-03-15T09:10:00",
            "AppId": "C:\\Users\\bob\\AppData\\Local\\Temp\\suspicious_uploader.exe",
            "UserId": "S-1-5-21-1111", "InterfaceLuid": "1", "L2ProfileId": "0",
            "BytesSent": 300 * 1024 * 1024, "BytesRecvd": 100,
        })
        _write_network_csv(csv_path, rows)

        engine = ScanEngine(csv_path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WSR-001" in rule_ids  # outbound transfer outlier
        assert "WSR-002" in rule_ids  # suspicious execution directory
        assert "WSR-003" in rule_ids  # unexpected networked app (the temp exe)
        assert result["files_scanned"] == 1
        assert result["errors_count"] == 0

        outlier_finding = next(f for f in result["findings"] if f["rule_id"] == "WSR-001")
        assert "suspicious_uploader.exe" in outlier_finding["description"]
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_disproportionate_background_activity():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "AppResourceUseMonitor.csv")
        rows = [
            {
                "TimeStamp": "2024-03-15T09:00:00", "AppId": "C:\\Program Files\\Vendor\\app.exe",
                "UserId": "S-1-5-21-1111", "ForegroundCycleTime": 5_000_000, "BackgroundCycleTime": 2_000_000,
                "FaceTime": 100, "ForegroundContextSwitches": 10, "BackgroundContextSwitches": 5,
                "ForegroundBytesRead": 1000, "ForegroundBytesWritten": 500,
                "BackgroundBytesRead": 200, "BackgroundBytesWritten": 100,
            },
            {
                # Disproportionate background activity from a ProgramData path
                "TimeStamp": "2024-03-15T09:10:00", "AppId": "C:\\ProgramData\\hidden\\worker.exe",
                "UserId": "S-1-5-21-1111", "ForegroundCycleTime": 1000, "BackgroundCycleTime": 80_000_000,
                "FaceTime": 0, "ForegroundContextSwitches": 1, "BackgroundContextSwitches": 900,
                "ForegroundBytesRead": 0, "ForegroundBytesWritten": 0,
                "BackgroundBytesRead": 5000, "BackgroundBytesWritten": 5000,
            },
        ]
        _write_app_resource_csv(csv_path, rows)

        engine = ScanEngine(csv_path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WSR-004" in rule_ids
        finding = next(f for f in result["findings"] if f["rule_id"] == "WSR-004")
        assert "worker.exe" in finding["description"]
    finally:
        shutil.rmtree(tmpdir)


def test_engine_flags_unparseable_timestamp():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "NetworkUsage.csv")
        rows = [
            {
                "TimeStamp": "not-a-real-date", "AppId": "C:\\Program Files\\Vendor\\app.exe",
                "UserId": "S-1-5-21-1111", "InterfaceLuid": "1", "L2ProfileId": "0",
                "BytesSent": 100, "BytesRecvd": 100,
            },
        ]
        _write_network_csv(csv_path, rows)

        engine = ScanEngine(csv_path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WSR-005" in rule_ids
        assert result["errors_count"] >= 1
    finally:
        shutil.rmtree(tmpdir)


def test_engine_flags_unrecognized_export_format():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "weird_table.csv")
        with open(csv_path, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["SomeColumn", "OtherColumn"])
            writer.writerow(["a", "b"])

        engine = ScanEngine(csv_path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WSR-006" in rule_ids
        assert result["files_scanned"] == 1
    finally:
        shutil.rmtree(tmpdir)


def test_engine_walks_directory_of_csvs():
    tmpdir = tempfile.mkdtemp()
    try:
        _write_network_csv(os.path.join(tmpdir, "net.csv"), [
            {
                "TimeStamp": "2024-03-15T09:00:00", "AppId": "chrome.exe",
                "UserId": "S-1-5-21-1111", "InterfaceLuid": "1", "L2ProfileId": "0",
                "BytesSent": 5000, "BytesRecvd": 5000,
            },
        ])
        _write_app_resource_csv(os.path.join(tmpdir, "app.csv"), [
            {
                "TimeStamp": "2024-03-15T09:00:00", "AppId": "app.exe",
                "UserId": "S-1-5-21-1111", "ForegroundCycleTime": 1000, "BackgroundCycleTime": 500,
                "FaceTime": 0, "ForegroundContextSwitches": 1, "BackgroundContextSwitches": 1,
                "ForegroundBytesRead": 0, "ForegroundBytesWritten": 0,
                "BackgroundBytesRead": 0, "BackgroundBytesWritten": 0,
            },
        ])
        # non-CSV file should be ignored
        with open(os.path.join(tmpdir, "notes.txt"), "w") as f:
            f.write("hello")

        engine = ScanEngine(tmpdir)
        result = engine.run()

        assert result["files_scanned"] == 2
        assert result["dirs_scanned"] == 1
    finally:
        shutil.rmtree(tmpdir)


def test_clean_export_produces_no_findings():
    tmpdir = tempfile.mkdtemp()
    try:
        csv_path = os.path.join(tmpdir, "NetworkUsage.csv")
        _write_network_csv(csv_path, [
            {
                "TimeStamp": "2024-03-15T09:00:00", "AppId": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
                "UserId": "S-1-5-21-1111", "InterfaceLuid": "1", "L2ProfileId": "0",
                "BytesSent": 5000, "BytesRecvd": 5000,
            },
        ])
        engine = ScanEngine(csv_path)
        result = engine.run()
        assert result["findings"] == []
        assert result["errors_count"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_missing_target_path_increments_errors_not_crash():
    engine = ScanEngine("/definitely/does/not/exist/anywhere.csv")
    result = engine.run()
    assert result["errors_count"] >= 1
    assert result["findings"] == []
