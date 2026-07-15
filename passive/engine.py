"""
engine.py
Runs all passive scan rules against a single captured traffic record and
stores any findings. This is called once per request/response, right
after the proxy addon writes the traffic row to storage.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "proxy"))
import storage  # noqa: E402
from rules import ALL_RULES  # noqa: E402


def scan(traffic_id, traffic_record):
    for rule in ALL_RULES:
        try:
            findings = rule(traffic_record)
        except Exception as e:
            # A single bad rule/response shouldn't take down capture -
            # log and move on rather than crash the proxy addon.
            print(f"[passive] rule {rule.__name__} failed: {e}")
            continue
        for f in findings:
            storage.record_finding(
                traffic_id=traffic_id,
                host=traffic_record["host"],
                url=traffic_record["url"],
                risk=f["risk"],
                name=f["name"],
                description=f.get("description", ""),
                evidence=f.get("evidence", ""),
                source="passive",
            )
