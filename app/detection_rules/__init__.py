"""
Detection Rules — Windows SRUM Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects a REAL, already-parsed SRUM (System Resource Usage Monitor)
row (a "context" dict produced by app.security_engine.ScanEngine while
real-parsing an esentutl-exported SRUM table CSV) and returns a Finding dict
if a forensically-relevant condition is met. Rules are pure functions of a
context dict so they can be unit tested with synthetic data as well as
exercised end-to-end against real parsed CSV rows.

Context dict shape (built by the engine for every parsed row):
    {
        "table": "network" | "app_resource" | None,
        "timestamp": datetime | None,        # real parsed TimeStamp (or None)
        "timestamp_raw": str,                # raw TimeStamp string from the CSV
        "timestamp_unparsed": bool,          # True if TimeStamp couldn't be parsed
        "app_id": str,                       # real AppId (exe path / package name)
        "user_id": str,                      # real UserId (SID string)
        "bytes_sent": int | None,            # Network Usage: real BytesSent
        "bytes_recvd": int | None,           # Network Usage: real BytesRecvd
        "bytes_sent_mean": float,            # real mean BytesSent across this whole scan
        "foreground_cycle_time": int | None, # App Resource Usage: real ForegroundCycleTime
        "background_cycle_time": int | None, # App Resource Usage: real BackgroundCycleTime
        "csv_path": str,                     # source CSV file path
        "unrecognized_format": bool,         # True only for the WSR-006 file-level pseudo-row
    }
"""

# Severity scale used consistently across the whole project
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

# Outlier detection floor for WSR-001: even if a row is >5x the mean, it is
# only flagged once it also crosses this absolute minimum (50MB), so a scan
# full of tiny transfers doesn't produce noisy "outlier" findings.
OUTLIER_MULTIPLIER = 5
OUTLIER_MIN_BYTES = 50 * 1024 * 1024  # 50MB

SUSPICIOUS_LOCATIONS = (
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
)

# Small bundled allowlist of common, legitimate networked applications. Any
# AppId with real observed network activity that is NOT in this list trips
# the broad, intentionally low-severity WSR-003 heuristic.
NETWORK_APP_ALLOWLIST = {
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "svchost.exe",
    "microsoftedgeupdate.exe",
    "onedrive.exe",
    "teams.exe",
    "outlook.exe",
}

# WSR-004 background-persistence heuristic: background cycle time must be at
# least this many times the foreground cycle time, AND BackgroundCycleTime
# must clear a minimum absolute floor so near-zero values don't produce
# meaningless ratios.
BACKGROUND_RATIO_THRESHOLD = 20
BACKGROUND_MIN_CYCLES = 1_000_000


def _basename(app_id):
    return (app_id or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _finding(rule_id, rule_name, severity, description):
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "description": description,
    }


def rule_large_outbound_transfer_outlier(ctx):
    """WSR-001: A real Network Usage row's BytesSent is a statistical
    outlier — more than 5x the real mean BytesSent observed across every
    Network Usage row in this scan, with an absolute floor of 50MB so small
    scans of low-volume traffic don't trigger on noise. A single application
    sending an outsized volume of outbound traffic relative to everything
    else on the host is a classic signal for data exfiltration or a C2
    beaconing/upload channel."""
    if ctx.get("table") != "network":
        return None
    bytes_sent = ctx.get("bytes_sent")
    mean = ctx.get("bytes_sent_mean") or 0
    if bytes_sent is None:
        return None
    if bytes_sent > OUTLIER_MIN_BYTES and mean > 0 and bytes_sent > OUTLIER_MULTIPLIER * mean:
        app_id = ctx.get("app_id") or "(unknown)"
        return _finding(
            "WSR-001", "Large Outbound Transfer Outlier", SEVERITY_HIGH,
            f"SRUM Network Usage row for '{app_id}' sent {bytes_sent:,} bytes, "
            f"which is more than {OUTLIER_MULTIPLIER}x the mean BytesSent "
            f"({mean:,.0f}) observed across every row in this scan — a "
            f"statistical outbound-transfer outlier consistent with data "
            f"exfiltration or a large C2 upload.",
        )
    return None


def rule_suspicious_execution_directory(ctx):
    """WSR-002: A real row's AppId path is located in a directory classic
    malware frequently executes from (Temp, Public, ProgramData). SRUM
    records network/resource activity for the exact binary path that ran,
    so this is a strong real-world execution-location signature."""
    if ctx.get("unrecognized_format"):
        return None
    app_id = ctx.get("app_id") or ""
    lowered = app_id.lower()
    for loc in SUSPICIOUS_LOCATIONS:
        if loc in lowered:
            return _finding(
                "WSR-002", "Suspicious Execution Directory", SEVERITY_MEDIUM,
                f"SRUM row for '{app_id}' shows activity from a classic "
                f"malware staging location ({loc.strip(chr(92))}).",
            )
    return None


def rule_unexpected_networked_application(ctx):
    """WSR-003: A real row shows network activity (BytesSent/BytesRecvd) for
    an AppId that is NOT in the small bundled allowlist of common legitimate
    networked applications. This is an intentionally broad, low-severity
    heuristic — SRUM records network activity for many normal apps, so this
    rule is meant as a triage starting point, not a definitive verdict."""
    if ctx.get("table") != "network":
        return None
    app_id = ctx.get("app_id") or ""
    if not app_id:
        return None
    base = _basename(app_id)
    if base and base not in NETWORK_APP_ALLOWLIST:
        return _finding(
            "WSR-003", "Unexpected Networked Application", SEVERITY_LOW,
            f"SRUM Network Usage row shows '{app_id}' communicating over the "
            f"network but it is not in the bundled allowlist of common "
            f"legitimate networked applications. Broad heuristic — review, "
            f"do not treat as definitive.",
        )
    return None


def rule_disproportionate_background_activity(ctx):
    """WSR-004: A real Application Resource Usage row's BackgroundCycleTime
    is disproportionately large versus its ForegroundCycleTime (ratio > 20x,
    with a minimum-cycle floor to avoid noise on tiny values), combined with
    execution from a suspicious directory. An app that consumes far more CPU
    in the background than the foreground while running from a Temp/Public/
    ProgramData path is a real background-persistence heuristic — consistent
    with a headless/hidden process doing work the user never sees."""
    if ctx.get("table") != "app_resource":
        return None
    fg = ctx.get("foreground_cycle_time")
    bg = ctx.get("background_cycle_time")
    if fg is None or bg is None:
        return None
    if bg < BACKGROUND_MIN_CYCLES:
        return None
    app_id = ctx.get("app_id") or ""
    lowered = app_id.lower()
    in_suspicious_dir = any(loc in lowered for loc in SUSPICIOUS_LOCATIONS)
    if not in_suspicious_dir:
        return None
    ratio = bg / fg if fg > 0 else float("inf")
    if ratio > BACKGROUND_RATIO_THRESHOLD:
        ratio_str = "inf" if ratio == float("inf") else f"{ratio:.1f}x"
        return _finding(
            "WSR-004", "Disproportionate Background Activity", SEVERITY_MEDIUM,
            f"SRUM Application Resource Usage row for '{app_id}' shows "
            f"BackgroundCycleTime ({bg:,}) is {ratio_str} its "
            f"ForegroundCycleTime ({fg:,}) while running from a suspicious "
            f"directory — consistent with a hidden/background-persistence "
            f"process.",
        )
    return None


def rule_unparseable_timestamp(ctx):
    """WSR-005: A real row's TimeStamp value could not be parsed in either
    supported format (ISO8601 or MM/dd/yyyy HH:mm:ss). Informational — flags
    export/tooling anomalies or a non-standard SRUM export worth reviewing,
    without dropping the row."""
    if ctx.get("unrecognized_format"):
        return None
    if ctx.get("timestamp_unparsed"):
        raw = ctx.get("timestamp_raw") or ""
        app_id = ctx.get("app_id") or "(unknown)"
        return _finding(
            "WSR-005", "Unparseable Timestamp", SEVERITY_LOW,
            f"SRUM row for '{app_id}' has a TimeStamp value ('{raw}') that "
            f"could not be parsed as ISO8601 or MM/dd/yyyy HH:mm:ss.",
        )
    return None


def rule_unrecognized_export_format(ctx):
    """WSR-006: A CSV file's header row didn't match the known columns for
    either the Network Usage or Application Resource Usage SRUM tables. Not
    a crash — reported as a parse-note so analysts know the file is either a
    different SRUM table export (unsupported by this tool) or not a SRUM
    export at all."""
    if ctx.get("unrecognized_format"):
        csv_path = ctx.get("csv_path") or ""
        return _finding(
            "WSR-006", "Unrecognized SRUM Export Format", SEVERITY_LOW,
            f"'{csv_path}' does not match the expected header columns for "
            f"either the Network Usage or Application Resource Usage SRUM "
            f"table export. This tool only parses those two table exports; "
            f"the file may be a different SRUM table or not a SRUM export "
            f"at all.",
        )
    return None


ALL_RULES = [
    rule_large_outbound_transfer_outlier,
    rule_suspicious_execution_directory,
    rule_unexpected_networked_application,
    rule_disproportionate_background_activity,
    rule_unparseable_timestamp,
    rule_unrecognized_export_format,
]
