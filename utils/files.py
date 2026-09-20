"""Filesystem helpers used by the interactive PCAP2Flows tool."""

from __future__ import annotations

from pathlib import Path

PCAP_SUFFIXES = {".pcap", ".pcapng"}


def find_pcaps(directory: str | Path) -> list[Path]:
    """Return PCAP/PCAPNG files recursively under *directory*."""
    root = Path(directory).expanduser().resolve()
    if not root.is_dir():
        return []
    return sorted(
        path for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in PCAP_SUFFIXES
    )
