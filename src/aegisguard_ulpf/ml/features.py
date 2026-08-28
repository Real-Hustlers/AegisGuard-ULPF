"""Deterministic ML-ready feature extraction; no model inference is performed."""
import csv
from pathlib import Path
def _get(event, path, default=None):
    value = event.model_dump(mode="json") if hasattr(event, "model_dump") else event
    for key in path.split("."):
        if not isinstance(value, dict): return default
        value = value.get(key)
    return default if value is None else value
def extract_features(events):
    events = list(events); users = {_get(e, "actor.user") for e in events if _get(e, "actor.user")}; ips = {_get(e, "src_endpoint.ip") for e in events if _get(e, "src_endpoint.ip")}
    failures = sum(_get(e, "classification.outcome") == "FAILURE" for e in events)
    return [{"event_type": _get(e, "classification.type", "UNKNOWN"), "severity": _get(e, "classification.severity", "unknown"), "event_frequency": len(events), "failed_login_count": failures, "unique_users": len(users), "unique_source_ips": len(ips)} for e in events]
def write_features_csv(events, output_path):
    rows = extract_features(events); path = Path(output_path); path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["event_type", "severity", "event_frequency", "failed_login_count", "unique_users", "unique_source_ips"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields); writer.writeheader(); writer.writerows(rows)
    return path
