"""Utilities for removing columns that are constant across CSV datasets."""

from __future__ import annotations
from pathlib import Path
import pandas as pd


PROTECTED_COLUMNS = {"label"}

def remove_constant_columns(
    input_dir: str | Path,
    output_dir: str | Path
) -> dict[str, list[str]]:

    input_dir = Path(input_dir).expanduser().resolve()
    output_dir = Path(output_dir).expanduser().resolve()

    summary= []
    
    files = sorted(
        p for p in input_dir.rglob("*.csv")
        if p.is_file()
    )

    if not files:
        raise FileNotFoundError(f"No CSV files found under: {input_dir}")

    removed_per_file: dict[str, list[str]] = {}

    for path in files:
        if "filter_summary" in path.name:
            continue
        df = pd.read_csv(path)

        constant_columns = []

        for column in df.columns:
            if column in PROTECTED_COLUMNS:
                continue

            if df[column].nunique(dropna=False) <= 1:
                constant_columns.append(column)

        df.drop(columns=constant_columns, inplace=True)
##        print('dropped columns: ')
##        print(constant_columns)

        rel = path.relative_to(input_dir)
        dest = output_dir / rel

        dest.parent.mkdir(parents=True, exist_ok=True)

        df.to_csv(dest, index=False)
        
        removed_per_file[str(rel)] = constant_columns
      #  print(removed_per_file)
        summary.append({
            "file": str(rel),
            "removed_count": len(constant_columns),
            "removed_columns": ", ".join(constant_columns),
        })

        summary_path = output_dir / "constant_columns_summary.csv"

        pd.DataFrame(
        summary,columns=["file", "removed_count", "removed_columns"]
                        ).to_csv(summary_path, index=False)
    

    return removed_per_file
