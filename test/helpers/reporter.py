# test/helpers/reporter.py

from __future__ import annotations
import json
import time
from pathlib import Path

class Reporter:
    def __init__(self, *, test_name: str, artifacts_dir: Path, emit_yaml: bool):
        self.test_name = test_name
        self.artifacts_dir = artifacts_dir
        self.emit_yaml = emit_yaml
        self.record = {
            "test_name": test_name,
            "start_ts": time.time(),
            "exchanges": [],
            "events": [],
            "failures": [],
        }

    def add_exchange(self, exchange: dict):
        self.record["exchanges"].append(exchange)

    def add_event(self, name: str, detail: dict | None = None):
        self.record["events"].append({"name": name, "detail": detail})

    def fail(self, category: str, message: str, detail: dict | None = None):
        self.record["failures"].append({
            "category": category,
            "message": message,
            "detail": detail,
        })

    def finalize(self, outcome: str):
        self.record["outcome"] = outcome
        self.record["end_ts"] = time.time()
        self._write()

    def _write(self):
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

        jsonl_path = self.artifacts_dir / f"{self.test_name}.jsonl"
        with jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(self.record) + "\n")

        if self.emit_yaml:
            import yaml
            yaml_path = self.artifacts_dir / f"{self.test_name}.yaml"
            with yaml_path.open("w", encoding="utf-8") as f:
                yaml.safe_dump(self.record, f, sort_keys=False)

#
#      EXAMPLE USAGE
#
#    reporter.add_exchange(
#        make_exchange(
#            phase="authenticate",
#            request={"route": "control.authenticate"},
#            response={"error_code": 0},
#            crypto={
#                "key_used": "session",
#                "pad_len": pad_len,
#                "magic_ok": True,
#            },
#        )
#    )
