from pathlib import Path

import pandas as pd


def label_from_filename(path: Path) -> str:
    stem = path.stem

    if "flows_" in stem:
        return stem.split("flows_", 1)[1]

    return stem

def add_labels(
    input_dir: str | Path,
    output_dir: str | Path,
) -> dict[str, str]:

    input_dir = Path(input_dir).expanduser().resolve()
    output_dir = Path(output_dir).expanduser().resolve()

    files = sorted(
        p for p in input_dir.rglob("*.csv")
        if p.is_file() and "summary" not in p.name
    )

    if not files:
        raise FileNotFoundError(f"No CSV files found under: {input_dir}")

    added_labels: dict[str, str] = {}

    for path in files:
        df = pd.read_csv(path)

        label = label_from_filename(path)

        df["label"] = label

        rel = path.relative_to(input_dir)
        dest = output_dir / rel

        dest.parent.mkdir(parents=True, exist_ok=True)

        df.to_csv(dest, index=False)

        added_labels[str(rel)] = label

    return added_labels
