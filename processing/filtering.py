"""Generic port-based filtering for all supported flow formats."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

PORT_COLUMN_CANDIDATES = {
    "argus": [("Sport", "Dport"), ("sport", "dport")],
    "zeek": [("id_orig_p", "id_resp_p")],
    "ntlflowlyzer": [("src_port", "dst_port")],
}


def _resolve_port_columns(df: pd.DataFrame, tool: str) -> tuple[str, str]:
    tool = tool.lower()
    if tool not in PORT_COLUMN_CANDIDATES:
        raise ValueError(f"Unsupported tool: {tool}")

    for src_col, dst_col in PORT_COLUMN_CANDIDATES[tool]:
        if src_col in df.columns and dst_col in df.columns:
            return src_col, dst_col

    expected = ", ".join(f"{a}/{b}" for a, b in PORT_COLUMN_CANDIDATES[tool])
    raise KeyError(f"Could not find port columns for {tool}. Expected: {expected}")


def filter_dataframe_by_port(df: pd.DataFrame, tool: str, port: int) -> pd.DataFrame:
    """Return rows whose source or destination port matches *port*."""
    src_col, dst_col = _resolve_port_columns(df, tool)
    target = str(port)
    src = df[src_col].astype(str).str.strip().str.replace(r"\.0$", "", regex=True)
    dst = df[dst_col].astype(str).str.strip().str.replace(r"\.0$", "", regex=True)
    return df[(src == target) | (dst == target)].copy()


def filter_directory_by_port(
    input_dir: str | Path,
    output_dir: str | Path,
    *,
    tool: str,
    port: int,
) -> Path:
    """Filter every CSV recursively and write a row-count summary."""
    input_dir = Path(input_dir).expanduser().resolve()
    output_dir = Path(output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    summary: list[dict[str, object]] = []
    csv_files = sorted(p for p in input_dir.rglob("*.csv") if p.is_file()
                       and "summary.csv" not in p.name)
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found under: {input_dir}")

    for src_file in csv_files:
        rel_path = src_file.relative_to(input_dir)
        dest_file = output_dir / rel_path
        dest_file.parent.mkdir(parents=True, exist_ok=True)

        try:
            df = pd.read_csv(src_file)
            filtered = filter_dataframe_by_port(df, tool, port)
            filtered.to_csv(dest_file, index=False)
            print(f"[Filter:{port}] {rel_path}: {len(df)} -> {len(filtered)} rows")
            summary.append(
                {
                    "file": str(rel_path),
                    "input_rows": len(df),
                    "output_rows": len(filtered),
                }
            )
        except (KeyError, ValueError) as exc:
            print(f"[Skipped] {rel_path}: {exc}")

    summary_path = output_dir / "row_filter_summary.csv"
    pd.DataFrame(summary, columns=["file", "input_rows", "output_rows"]).to_csv(
        summary_path, index=False
    )
    return summary_path
