"""Statistics for generated CSV flow files."""

from __future__ import annotations

from pathlib import Path

import pandas as pd


def collect_csv_statistics(input_dir: str | Path) -> pd.DataFrame:
    input_dir = Path(input_dir).expanduser().resolve()
    rows = []
    for path in sorted(p for p in input_dir.rglob("*.csv") if p.is_file()
                        and "summary.csv" not in p.name):
        try:
            row_count = len(pd.read_csv(path))
        except Exception:
            row_count = None
        rows.append(
            {
                "file": str(path.relative_to(input_dir)),
                "rows": row_count,
                "size_bytes": path.stat().st_size,
            }
        )
    return pd.DataFrame(rows, columns=["file", "rows", "size_bytes"])
