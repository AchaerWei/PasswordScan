"""JSON streaming pipeline — real-time JSON-lines output for SIEM/SOAR integration.

Each finding is emitted as a single JSON line (JSONL format) for easy ingestion
by log aggregators, SIEM platforms, and automated response systems.
"""
from __future__ import annotations
import json, sys
from datetime import datetime
from pathlib import Path


class Pipeline:
    """Streams scan findings as JSONL for real-time integration."""

    def __init__(self, output_path: str | Path | None = None):
        self._file = None
        self._count = 0
        if output_path:
            self._file = open(output_path, 'w', encoding='utf-8')

    def emit(self, finding: dict):
        """Emit a single finding as a JSON line."""
        record = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "weak_password_found",
            "source": "netspider-max",
            "ip": finding.get('ip', ''),
            "port": finding.get('port', 0),
            "service": finding.get('service', ''),
            "username": finding.get('username', ''),
            "password": finding.get('password', ''),
            "finding_type": finding.get('finding_type', ''),
            "severity": _severity(finding.get('finding_type', '')),
        }
        line = json.dumps(record, ensure_ascii=False) + '\n'
        if self._file:
            self._file.write(line)
            self._file.flush()
        sys.stdout.write(line)
        self._count += 1

    def close(self):
        if self._file:
            self._file.close()
            self._file = None

    @property
    def count(self) -> int:
        return self._count


def _severity(finding_type: str) -> str:
    if finding_type in ('weak_password', 'default_password'):
        return "critical"
    if finding_type == 'no_auth':
        return "high"
    if finding_type == 'open_service':
        return "info"
    return "medium"
