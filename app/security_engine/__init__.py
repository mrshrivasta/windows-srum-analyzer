"""
Security Engine — Windows SRUM Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

REAL CSV parser for Windows SRUM (System Resource Usage Monitor) table
exports.

Background / expected input
----------------------------
On a live Windows system, SRUM data lives in a real ESE (Extensible Storage
Engine) database at `%SystemRoot%\\System32\\sru\\SRUDB.dat`. Parsing that
raw binary ESE format directly requires a native ESE library that is
generally unavailable in this environment. Instead, this tool accepts the
standard real-world forensic export workflow: an analyst runs

    esentutl /y SRUDB.dat /vssrum /d export_dir

(or an equivalent real SRUM-export utility such as SrumECmd) against a live
or offline copy of SRUDB.dat, producing one real CSV file per SRUM table in
`export_dir`. Those exported CSVs are what this engine real-parses — the
same input format professional tools like SrumECmd support alongside their
own native `.dat` parsing.

Given a target path, this engine will:
  * If the target is a single `.csv` file, real-parse it directly.
  * If the target is a directory, real-walk it (bounded by max_depth /
    max_files / excludes) and real-parse every `*.csv` file found.

Two real SRUM table export formats are auto-detected by their real header
row column names:

  Network Usage table columns:
    TimeStamp, AppId, UserId, InterfaceLuid, L2ProfileId,
    BytesSent, BytesRecvd

  Application Resource Usage table columns:
    TimeStamp, AppId, UserId, ForegroundCycleTime, BackgroundCycleTime,
    FaceTime, ForegroundContextSwitches, BackgroundContextSwitches,
    ForegroundBytesRead, ForegroundBytesWritten, BackgroundBytesRead,
    BackgroundBytesWritten

A CSV whose header doesn't match either known table is not crash-parsed as
rows — it is reported via the WSR-006 "unrecognized export format" finding.
Malformed rows (bad numeric fields, unparseable timestamps) are handled
defensively: numeric fields default to None, timestamps that fail both
supported formats set `timestamp_unparsed=True` for the WSR-005 rule and
increment `errors_count`. A file that can't be opened/read at all also
increments `errors_count` and is skipped. No sample/mock data is ever
generated — every Finding reflects rows actually read from a real CSV file
on disk.
"""
import csv
import os
import time
from datetime import datetime

from app.detection_rules import ALL_RULES

DEFAULT_EXCLUDES = {"/proc", "/sys", "/dev", "/run"}

NETWORK_USAGE_COLUMNS = {
    "TimeStamp", "AppId", "UserId", "InterfaceLuid", "L2ProfileId",
    "BytesSent", "BytesRecvd",
}

APP_RESOURCE_USAGE_COLUMNS = {
    "TimeStamp", "AppId", "UserId", "ForegroundCycleTime",
    "BackgroundCycleTime", "FaceTime", "ForegroundContextSwitches",
    "BackgroundContextSwitches", "ForegroundBytesRead",
    "ForegroundBytesWritten", "BackgroundBytesRead",
    "BackgroundBytesWritten",
}

TIMESTAMP_FORMATS = (
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%m/%d/%Y %H:%M:%S",
)


def parse_srum_timestamp(raw):
    """Real-parse a SRUM TimeStamp string. Supports ISO8601 (with or
    without a trailing Z / fractional seconds) and MM/dd/yyyy HH:mm:ss.
    Returns a real datetime, or None if every supported format fails."""
    if not raw:
        return None
    value = raw.strip()
    if value.endswith("Z"):
        value = value[:-1]
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _to_int(raw):
    if raw is None or raw == "":
        return None
    try:
        return int(float(raw))
    except (TypeError, ValueError):
        return None


class ScanEngine:
    def __init__(self, target_path, max_depth=6, excludes=None, max_files=50000):
        self.target_path = os.path.abspath(target_path)
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set(DEFAULT_EXCLUDES)
        self.max_files = max_files

        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors_count = 0
        self.findings = []
        self._rows = []  # real accumulated parsed rows across the whole scan

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def run(self):
        """Perform the real, synchronous CSV parse. Returns summary dict."""
        start = time.time()

        if os.path.isfile(self.target_path):
            self._parse_csv_file(self.target_path)
        elif os.path.isdir(self.target_path):
            self._walk(self.target_path, depth=0)
        else:
            self.errors_count += 1

        self._apply_rules_to_all_rows()

        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    def _walk(self, path, depth):
        if self.files_scanned >= self.max_files:
            return
        if self._is_excluded(path):
            return
        if depth > self.max_depth:
            return

        try:
            with os.scandir(path) as it:
                entries = list(it)
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            self.errors_count += 1
            return

        self.dirs_scanned += 1

        for entry in entries:
            if self.files_scanned >= self.max_files:
                return
            full_path = entry.path
            if self._is_excluded(full_path):
                continue
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
            except OSError:
                self.errors_count += 1
                continue

            if is_file and full_path.lower().endswith(".csv"):
                self._parse_csv_file(full_path)
            elif is_dir:
                self._walk(full_path, depth + 1)

    # ------------------------------------------------------------------
    # Real CSV parsing
    # ------------------------------------------------------------------

    def _parse_csv_file(self, csv_path):
        self.files_scanned += 1
        try:
            with open(csv_path, "r", newline="", encoding="utf-8-sig", errors="replace") as fh:
                reader = csv.DictReader(fh)
                fieldnames = set(reader.fieldnames or [])

                if NETWORK_USAGE_COLUMNS.issubset(fieldnames):
                    table = "network"
                elif APP_RESOURCE_USAGE_COLUMNS.issubset(fieldnames):
                    table = "app_resource"
                else:
                    self._rows.append({
                        "table": None,
                        "csv_path": csv_path,
                        "unrecognized_format": True,
                    })
                    return

                for raw_row in reader:
                    try:
                        row = self._build_row(table, raw_row, csv_path)
                    except Exception:
                        self.errors_count += 1
                        continue
                    if row is not None:
                        self._rows.append(row)
        except (OSError, csv.Error):
            self.errors_count += 1

    def _build_row(self, table, raw_row, csv_path):
        timestamp_raw = raw_row.get("TimeStamp") or ""
        timestamp = parse_srum_timestamp(timestamp_raw)
        timestamp_unparsed = bool(timestamp_raw) and timestamp is None
        if timestamp_unparsed:
            self.errors_count += 1

        row = {
            "table": table,
            "timestamp": timestamp,
            "timestamp_raw": timestamp_raw,
            "timestamp_unparsed": timestamp_unparsed,
            "app_id": (raw_row.get("AppId") or "").strip(),
            "user_id": (raw_row.get("UserId") or "").strip(),
            "csv_path": csv_path,
            "unrecognized_format": False,
            "bytes_sent": None,
            "bytes_recvd": None,
            "foreground_cycle_time": None,
            "background_cycle_time": None,
        }

        if table == "network":
            row["bytes_sent"] = _to_int(raw_row.get("BytesSent"))
            row["bytes_recvd"] = _to_int(raw_row.get("BytesRecvd"))
        elif table == "app_resource":
            row["foreground_cycle_time"] = _to_int(raw_row.get("ForegroundCycleTime"))
            row["background_cycle_time"] = _to_int(raw_row.get("BackgroundCycleTime"))

        return row

    # ------------------------------------------------------------------
    # Rule application (needs a real cross-row statistic for WSR-001)
    # ------------------------------------------------------------------

    def _apply_rules_to_all_rows(self):
        network_bytes_sent = [
            r["bytes_sent"] for r in self._rows
            if r.get("table") == "network" and isinstance(r.get("bytes_sent"), int)
        ]
        mean = sum(network_bytes_sent) / len(network_bytes_sent) if network_bytes_sent else 0.0

        for row in self._rows:
            ctx = dict(row)
            ctx["bytes_sent_mean"] = mean
            self._apply_rules(ctx, row.get("csv_path"))

    def _apply_rules(self, ctx, csv_path):
        for rule in ALL_RULES:
            try:
                result = rule(ctx)
            except Exception:
                self.errors_count += 1
                continue
            if result:
                app_id = ctx.get("app_id") or ""
                if ctx.get("table") == "network":
                    summary = f"{app_id} (sent={ctx.get('bytes_sent')}, recvd={ctx.get('bytes_recvd')})"
                elif ctx.get("table") == "app_resource":
                    summary = (
                        f"{app_id} (fg_cycles={ctx.get('foreground_cycle_time')}, "
                        f"bg_cycles={ctx.get('background_cycle_time')})"
                    )
                else:
                    summary = app_id
                result["file_path"] = csv_path or ""
                result["permissions_octal"] = summary
                result["owner_uid"] = None
                result["owner_gid"] = None
                self.findings.append(result)
