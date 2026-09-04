import csv
import os
import shutil
import tempfile


NETWORK_FIELDS = ["TimeStamp", "AppId", "UserId", "InterfaceLuid", "L2ProfileId", "BytesSent", "BytesRecvd"]


def _make_srum_export_dir_with_finding():
    """Writes a real spec-conformant SRUM Network Usage CSV export, with a
    real statistical BytesSent outlier row from a Temp-dir AppId, to a real
    temp directory. Returns the directory path."""
    tmpdir = tempfile.mkdtemp()
    csv_path = os.path.join(tmpdir, "NetworkUsage.csv")
    rows = [
        {
            "TimeStamp": "2024-03-15T09:00:00", "AppId": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
            "UserId": "S-1-5-21-1111", "InterfaceLuid": "1", "L2ProfileId": "0",
            "BytesSent": 9000 + i, "BytesRecvd": 20000,
        }
        for i in range(20)
    ]
    rows.append({
        "TimeStamp": "2024-03-15T09:05:00",
        "AppId": "C:\\Users\\bob\\AppData\\Local\\Temp\\suspicious_uploader.exe",
        "UserId": "S-1-5-21-1111", "InterfaceLuid": "1", "L2ProfileId": "0",
        "BytesSent": 300 * 1024 * 1024, "BytesRecvd": 100,
    })
    with open(csv_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=NETWORK_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return tmpdir


def test_full_scan_alert_incident_workflow(registered_client):
    tmpdir = _make_srum_export_dir_with_finding()
    try:
        # Run a real scan against a real SRUM CSV export directory
        resp = registered_client.post("/scan/run", data={"target_path": tmpdir}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data

        # Logs page should show at least one scan
        resp = registered_client.get("/logs")
        assert tmpdir.encode() in resp.data

        # Alerts page should load — WSR-001 (high severity) should have alerted
        resp = registered_client.get("/alerts")
        assert resp.status_code == 200

        # Analytics JSON endpoint returns real aggregated data
        resp = registered_client.get("/analytics/data")
        assert resp.status_code == 200
        assert resp.is_json

        # Reports CSV export works
        resp = registered_client.get("/reports/export.csv")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/csv")
        assert b"WSR-001" in resp.data or b"WSR-002" in resp.data
    finally:
        shutil.rmtree(tmpdir)


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp",
        "scan_depth_limit": "3",
        "exclude_paths": "/proc,/sys",
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
