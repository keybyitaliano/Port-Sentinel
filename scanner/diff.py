import json
from datetime import datetime, timezone
from pathlib import Path


def _report_path(reports_dir: Path, target: str) -> Path:
    safe_name = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in target)
    return reports_dir / f"{safe_name}.json"


def load_previous_scan(reports_dir: Path, target: str) -> dict | None:
    path = _report_path(reports_dir, target)
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_scan(reports_dir: Path, target: str, results: list[dict]) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = _report_path(reports_dir, target)
    payload = {
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "open_ports": results,
    }
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return path


def compute_diff(previous: dict | None, current_results: list[dict]) -> dict:
    if previous is None:
        return {
            "has_baseline": False,
            "new_ports": [],
            "closed_ports": [],
            "changed_banners": [],
        }

    prev_map = {item["port"]: item for item in previous.get("open_ports", [])}
    curr_map = {item["port"]: item for item in current_results}

    new_ports = sorted(set(curr_map.keys()) - set(prev_map.keys()))
    closed_ports = sorted(set(prev_map.keys()) - set(curr_map.keys()))

    changed_banners = []
    for port in sorted(set(prev_map.keys()) & set(curr_map.keys())):
        old_b = prev_map[port].get("banner")
        new_b = curr_map[port].get("banner")
        if old_b != new_b:
            changed_banners.append({"port": port, "old": old_b, "new": new_b})

    return {
        "has_baseline": True,
        "previous_scan_at": previous.get("scanned_at"),
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "changed_banners": changed_banners,
    }