# test/helpers/reporter.py
from __future__ import annotations

import json
import os
import pathlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def _safe_json_default(obj: Any) -> Any:
    # Ensure JSON serialization never crashes reporting.
    if isinstance(obj, (bytes, bytearray)):
        return {"__bytes__": True, "len": len(obj), "sha256": None}
    try:
        return str(obj)
    except Exception:
        return repr(obj)


def _now_iso() -> str:
    # ISO-ish timestamp without timezone dependency.
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _load_redactor():
    # Prefer project redaction helper if present; otherwise do minimal redaction.
    try:
        from test.helpers.redaction import redact_record  # type: ignore
        return redact_record
    except Exception:
        return None


_REDACT = _load_redactor()


def _minimal_redact(record: Dict[str, Any]) -> Dict[str, Any]:
    # Last-resort redaction: remove common secret-ish keys.
    if not isinstance(record, dict):
        return record
    secret_keys = {
        "pin",
        "pass",
        "access_code",
        "pass_phrase",
        "link_enc",
        "link_hmac",
        "sk",
        "shm",
        "session_key",
        "session_hmac",
        "key",
        "secret",
        "password",
    }

    def scrub(v: Any) -> Any:
        if isinstance(v, dict):
            out = {}
            for k, vv in v.items():
                if str(k).lower() in secret_keys:
                    out[k] = "<redacted>"
                else:
                    out[k] = scrub(vv)
            return out
        if isinstance(v, list):
            return [scrub(x) for x in v]
        return v

    return scrub(record)


@dataclass
class Reporter:
    run_id: str
    test_id: str
    artifacts_dir: pathlib.Path
    emit_jsonl: bool = True
    emit_yaml: bool = False
    enable: bool = True

    _t0: float = field(default_factory=time.monotonic, init=False)
    _records: List[Dict[str, Any]] = field(default_factory=list, init=False)
    _jsonl_path: Optional[pathlib.Path] = field(default=None, init=False)
    _yaml_path: Optional[pathlib.Path] = field(default=None, init=False)

    def _t_ms(self) -> int:
        return int((time.monotonic() - self._t0) * 1000)

    def _ensure_paths(self) -> None:
        if not self.enable:
            return
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        base = self.run_id.replace(os.sep, "_")
        self._jsonl_path = self.artifacts_dir / f"{base}.jsonl"
        self._yaml_path = self.artifacts_dir / f"{base}.summary.yaml"

    def _apply_redaction(self, record: Dict[str, Any]) -> Dict[str, Any]:
        if _REDACT is not None:
            try:
                return _REDACT(record)
            except Exception:
                # If project redactor fails, fall back.
                return _minimal_redact(record)
        return _minimal_redact(record)

    def emit(self, record_type: str, **fields: Any) -> Dict[str, Any]:
        """
        Emit a typed record. Always adds:
          - run_id
          - test_id
          - record_type
          - t_ms
          - ts_utc
        Writes JSONL immediately (append-only) when enabled.
        """
        if not self.enable:
            return {}

        self._ensure_paths()

        record: Dict[str, Any] = {
            "run_id": self.run_id,
            "test_id": self.test_id,
            "record_type": record_type,
            "t_ms": self._t_ms(),
            "ts_utc": _now_iso(),
        }
        record.update(fields)

        record = self._apply_redaction(record)

        self._records.append(record)

        if self.emit_jsonl and self._jsonl_path is not None:
            with self._jsonl_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=_safe_json_default, sort_keys=False))
                f.write("\n")

        return record

    def test_start(self) -> None:
        self.emit(
            "test_start",
            meta={
                "pid": os.getpid(),
            },
        )

    def test_end(self, outcome: str, when: Optional[str], longrepr: Any) -> None:
        err: Optional[Dict[str, Any]] = None
        if longrepr is not None:
            # pytest longrepr can be various types; store as string safely.
            err = {"when": when, "longrepr": str(longrepr)}

        self.emit(
            "test_end",
            outcome=outcome,
            error=err,
        )

    def finalize(self) -> None:
        """
        Finalize reporting. JSONL is already written incrementally.
        YAML summary is derived from the collected in-memory records.
        """
        if not self.enable:
            return

        self._ensure_paths()

        if self.emit_yaml and self._yaml_path is not None:
            summary = {
                "run_id": self.run_id,
                "test_id": self.test_id,
                "record_count": len(self._records),
                "records": self._records,
            }
            # YAML is optional; try PyYAML, otherwise write a JSON-formatted fallback.
            try:
                import yaml  # type: ignore

                with self._yaml_path.open("w", encoding="utf-8") as f:
                    yaml.safe_dump(summary, f, sort_keys=False, default_flow_style=False)
            except Exception:
                # Fallback: write JSON with .yaml extension (still readable, avoids hard dependency)
                with self._yaml_path.open("w", encoding="utf-8") as f:
                    f.write(json.dumps(summary, indent=2, default=_safe_json_default, sort_keys=False))
                    f.write("\n")
