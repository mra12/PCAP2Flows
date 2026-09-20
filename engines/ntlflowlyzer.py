#!/usr/bin/env python3

"""NTLFlowLyzer adapter for PCAP2Flows."""

from __future__ import annotations

import csv
import io
import json
import os
import subprocess
from pathlib import Path
import pandas as pd

# Default NTLFlowLyzer configuration.
# pcap_file_address, output_file_address, and number_of_threads
# are added dynamically for each run.

##NTL_DEFAULT_CONFIG = {
##    "feature_extractor_min_flows": 2500,
##    "writer_min_rows": 1000,
##    "read_packets_count_value_log_info": 1000000,
##    "check_flows_ending_min_flows": 20000,
##    "capturer_updating_flows_min_value": 5000,
##    "max_flow_duration": 120000,
##    "activity_timeout": 300,
##    "floating_point_unit": ".4f",
##    "max_rows_number": 800000,
##    "features_ignore_list": [],
##}

ROOT = Path(__file__).resolve().parent.parent
NTL_CONFIG_FILE = (
    ROOT
    / "config"
    / "ntlflowlyzer.json"
)

def load_default_config(config_path: Path) -> dict:
    """Load user-editable NTLFlowLyzer settings."""

    if not config_path.is_file():
        raise FileNotFoundError(
            f"NTLFlowLyzer config file not found: {config_path}"
        )

    with config_path.open("r", encoding="utf-8") as f:
        return json.load(f)

def prompt_number_of_threads() -> int:
    """Ask the user how many threads NTLFlowLyzer should use."""

    cpu_count = os.cpu_count() or 1

    recommended_min = max(3, int(cpu_count * 0.5))
    recommended_max = max(3, int(cpu_count * 2))

    print("\nNTLFlowLyzer thread configuration")
    print("--------------------------------")
    print(f"Detected CPU cores: {cpu_count}")
    print("Minimum allowed: 3")
    print("Default: 4")
    print(
        "Recommended range: "
        f"0.5 * CPU count < value < 2 * CPU count "
        f"(approximately {recommended_min} to {recommended_max})"
    )

    while True:
        value = input("Number of threads [4]: ").strip()

        # Pressing Enter uses the documented default.
        if not value:
            return 4

        try:
            threads = int(value)
        except ValueError:
            print("[!] Please enter a whole number.")
            continue

        if threads < 3:
            print("[!] NTLFlowLyzer requires at least 3 threads.")
            continue

        return threads


def find_pcaps(input_dir: Path) -> list[Path]:
    """Recursively find PCAP files."""

    return sorted(
        path
        for path in input_dir.rglob("*")
        if path.is_file() and path.suffix.lower() == ".pcap"
    )


def remove_label_column(csv_path: Path) -> None:
    df = pd.read_csv(csv_path)

    if "label" in df.columns:
        df.drop(columns=["label"], inplace=True)
        df.to_csv(csv_path, index=False)

        print(f"[NTLFlowLyzer] Removed 'label' column from: {csv_path}")



def run(
    input_dir: str | Path,
    output_dir: str | Path,
) -> list[Path]:
    """Generate NTLFlowLyzer CSV files from PCAP files."""

    input_dir = Path(input_dir).expanduser().resolve()
    output_dir = Path(output_dir).expanduser().resolve()

    default_config = load_default_config(NTL_CONFIG_FILE)

    if not input_dir.is_dir():
        raise FileNotFoundError(
            f"Input directory does not exist: {input_dir}"
        )

    pcaps = find_pcaps(input_dir)

    if not pcaps:
        raise FileNotFoundError(
            f"No .pcap files found under: {input_dir}"
        )
    
    csv_dir = output_dir / "csv"
    config_dir = output_dir / "config"

    csv_dir.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)

    number_of_threads = prompt_number_of_threads()

    generated: list[Path] = []

    print(f"\n[NTLFlowLyzer] Found {len(pcaps)} PCAP file(s).")
    print(
        f"[NTLFlowLyzer] Using {number_of_threads} threads."
    )

    for pcap_path in pcaps:
        relative = pcap_path.relative_to(input_dir)

        # Preserve the PCAP's directory structure.
        relative_parent = relative.parent

        output_parent = csv_dir / relative_parent
        config_parent = config_dir / relative_parent

        output_parent.mkdir(parents=True, exist_ok=True)
        config_parent.mkdir(parents=True, exist_ok=True)

        csv_path = (
            output_parent
            / f"flows_{pcap_path.stem}.csv"
        )

        config_path = (
            config_parent
            / f"config_{pcap_path.stem}.json"
        )

        config = {
            **default_config,
            "pcap_file_address": str(pcap_path),
            "output_file_address": str(csv_path),
            "number_of_threads": number_of_threads,
        }
##        print('config is :')
##        for i in config:
##            print(i)
##        print('************************\n****************\n')

        with config_path.open(
            "w",
            encoding="utf-8",
        ) as config_file:
            json.dump(
                config,
                config_file,
                indent=4,
            )

        print()
        print(f"[NTLFlowLyzer] PCAP:   {pcap_path}")
        print(f"[NTLFlowLyzer] Config: {config_path}")
        print(f"[NTLFlowLyzer] CSV:    {csv_path}")

        command = [
            "ntlflowlyzer",
            "-c",
            str(config_path),
        ]

        print(
            "[NTLFlowLyzer] Running:",
            " ".join(command),
        )

        subprocess.run(
            command,
            check=True,
        )

        if not csv_path.exists():
            raise FileNotFoundError(
                "NTLFlowLyzer completed but the expected "
                f"CSV was not created: {csv_path}"
            )
        # NTLFlowLyzer always adds a label column.
        # Remove it only after successful flow generation.
        remove_label_column(csv_path)
        generated.append(csv_path)

    return generated
