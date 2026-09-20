"""Zeek-flowmeter engine for converting PCAP files into flow CSV files."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pandas as pd


def parse_flowmeter_log(log_path: Path, output_csv: Path) -> None:
    """Parse flowmeter.log, drop metadata and uid, and save a CSV."""
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()

    header_line = next((line for line in lines if line.startswith("#fields")), None)
    if header_line is None:
        raise ValueError(f"No #fields line found in {log_path}")

    columns = header_line.replace("#fields\t", "", 1).split("\t")
##    uid_index = columns.index("uid") if "uid" in columns else None
##    if uid_index is not None:
##        columns.pop(uid_index)

    rows: list[list[str]] = []
    for line in lines:
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
##        if uid_index is not None and len(fields) > uid_index:
##            fields.pop(uid_index)
        #padding empty fields with ""
        fields = (fields + [""] * len(columns))[: len(columns)]
        rows.append(fields)

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows, columns=columns).to_csv(output_csv, index=False)


def _find_zeek(executable: str | None = None) -> str:
    if executable:
        return executable
    default = Path("/opt/zeek/bin/zeek")
    return str(default) if default.exists() else "zeek"


def run(
    input_dir: str | Path,
    output_dir: str | Path,
    *,
    zeek_executable: str | None = None,
) -> list[Path]:
    """Process every PCAP under *input_dir* with Zeek-flowmeter."""
    input_dir = Path(input_dir).expanduser().resolve()
    output_dir = Path(output_dir).expanduser().resolve()
    zeek = _find_zeek(zeek_executable)

    pcaps = sorted(p for p in input_dir.rglob("*.pcap") if p.is_file())
    if not pcaps:
        raise FileNotFoundError(f"No .pcap files found under: {input_dir}")

    generated: list[Path] = []
    for pcap in pcaps:
        relative_parent = pcap.parent.relative_to(input_dir)
        work_dir = output_dir / "work" / relative_parent / pcap.stem
        csv_path = output_dir / "csv" / relative_parent / f"{pcap.stem}.csv"
        work_dir.mkdir(parents=True, exist_ok=True)

        print(f"[Zeek] {pcap.name} -> {csv_path.name}")
        subprocess.run(
            [zeek, "-C", "flowmeter", "-r", str(pcap)],
            cwd=work_dir,
            check=True,
        )

        flow_log = work_dir / "flowmeter.log"
        if not flow_log.exists():
            raise FileNotFoundError(f"Zeek did not produce {flow_log}")

        parse_flowmeter_log(flow_log, csv_path)
        generated.append(csv_path)

        for log_file in work_dir.glob("*.log"):
            log_file.unlink(missing_ok=True)

    return generated
