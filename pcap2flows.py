# PCAP2Flows: Multi-Engine PCAP-to-Flow Conversion Framework
# Copyright (C) 2026 Mohammed Rashed, Carlos García-Rubio, Celeste Campo
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

#!/usr/bin/env python3
"""Interactive PCAP2Flows tool."""

from __future__ import annotations

from pathlib import Path
import subprocess

from engines import argus, ntlflowlyzer, zeek
from processing.constant_columns import remove_constant_columns
from processing.filtering import filter_directory_by_port
from processing.statistics import collect_csv_statistics
from processing.label_adder import add_labels
from utils.files import find_pcaps

ROOT = Path(__file__).resolve().parent
DEFAULT_INPUT = ROOT / "input_pcaps"
DEFAULT_OUTPUT = ROOT / "output"

ENGINE_LABELS = {
    "argus": "Argus",
    "ntlflowlyzer": "NTLFlowLyzer",
    "zeek": "Zeek-flowmeter",
}


def print_header() -> None:
    print("\n" + "=" * 58)
    print("                     PCAP2Flows")
    print("=" * 58)
    print("Convert PCAP traffic captures into network-flow CSV files.")


def prompt_choice(prompt: str, choices: set[str]) -> str:
    """Prompt until the user enters one of the allowed choices."""
    while True:
        value = input(prompt).strip()
        if value in choices:
            return value
        print(f"Invalid choice. Please select one of: {', '.join(sorted(choices))}")


def prompt_yes_no(prompt: str, *, default: bool = False) -> bool:
    """Ask an interactive yes/no question."""
    suffix = " [Y/n]: " if default else " [y/N]: "
    while True:
        value = input(prompt + suffix).strip().lower()
        if not value:
            return default
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print("Please enter Y or N.")


def prompt_directory(prompt: str, default: Path) -> Path:
    """Ask for a directory, using *default* when the answer is blank."""
    value = input(f"{prompt} [{default}]: " ).strip()
    selected = Path(value).expanduser() if value else default
    return selected.resolve()


def prompt_pcap_directory(default: Path) -> Path | None:
    """Prompt until a directory containing capture files is selected."""
    while True:
        selected = prompt_directory("PCAP input directory", default)
        print(f"Selected input directory: {selected}")

        if not selected.is_dir():
            print(f"[!] Directory does not exist: {selected}")
        else:
            pcaps = find_pcaps(selected)
            if pcaps:
                print(f"[+] Found {len(pcaps)} capture file(s).")
                for pcap in pcaps[:5]:
                    print(f"    - {pcap.relative_to(selected)}")
                if len(pcaps) > 5:
                    print(f"    ... and {len(pcaps) - 5} more")
                return selected
            print(f"[!] No .pcap or .pcapng files found in: {selected}")

        print("Place capture files in that folder, or enter a different directory.")
        if not prompt_yes_no("Choose another input directory?", default=True):
            return None


def prompt_port() -> int:
    while True:
        value = input("Enter the protocol port number (e.g. 1883): ").strip()
        try:
            port = int(value)
        except ValueError:
            print("Port must be an integer.")
            continue
        if 1 <= port <= 65535:
            return port
        print("Port must be between 1 and 65535.")


def choose_engine(*, allow_all: bool = True, allow_back: bool = True) -> str | None:
    print("\nSelect a flow-generation tool:")
    print("  1. Argus")
    print("  2. NTLFlowLyzer")
    print("  3. Zeek-flowmeter")
    if allow_all:
        print("  4. All tools")
    if allow_back:
        print("  0. Back")

    options = {"1", "2", "3"}
    if allow_all:
        options.add("4")
    if allow_back:
        options.add("0")

    choice = prompt_choice("Choice: ", options)
    mapping = {"1": "argus", "2": "ntlflowlyzer", "3": "zeek", "4": "all"}
    return None if choice == "0" else mapping[choice]


def engine_csv_dir(output_root: Path, engine: str) -> Path:
    return output_root / engine / "csv"


def run_one_engine(engine: str, input_dir: Path, output_root: Path) -> list[Path]:
    target = output_root / engine
    if engine == "argus":
        return argus.run(input_dir, target)
    if engine == "zeek":
        return zeek.run(input_dir, target)
    if engine == "ntlflowlyzer":
        return ntlflowlyzer.run(input_dir, target)
    raise ValueError(f"Unsupported engine: {engine}")


def generate_flows() -> None:
    print("\n--- Generate flows ---")
    engine = choose_engine()
    if engine is None:
        return

    input_dir = prompt_pcap_directory(DEFAULT_INPUT)
    if input_dir is None:
        return

    output_root = prompt_directory("Output directory", DEFAULT_OUTPUT)
    print(f"Selected output directory: {output_root}")

    engines = ["argus", "ntlflowlyzer", "zeek"] if engine == "all" else [engine]
    completed: list[str] = []

    print("\nStarting flow generation...")
    for selected in engines:
        print(f"\n[{ENGINE_LABELS[selected]}]")
        try:
            generated = run_one_engine(selected, input_dir, output_root)
            completed.append(selected)
            print(f"[+] Generated {len(generated)} CSV file(s).")
        except NotImplementedError as exc:
            print(f"[!] {exc}")
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            print(f"[!] {ENGINE_LABELS[selected]} failed: {exc}")
        except Exception as exc:
            print(f"[!] {ENGINE_LABELS[selected]} failed: {exc}")

    if not completed:
        print("\nNo engines completed successfully.")
        return
    if prompt_yes_no("\nPost-process the generated flows now? (Default: NO)"):
        postprocess_generated(completed, output_root)


def postprocess_generated(engines: list[str], output_root: Path) -> None:
    """Interactively post-process output produced in the current run."""
    do_filter = prompt_yes_no("Filter flows by protocol port?")
    port = prompt_port() if do_filter else None
    do_constants = prompt_yes_no("Remove columns with one common value across all CSV files?")
    do_labels = prompt_yes_no("Add label column from filename?")

    for engine in engines:
        source = engine_csv_dir(output_root, engine)
        if not source.is_dir():
            print(f"[!] No CSV directory found for {ENGINE_LABELS[engine]}: {source}")
            continue

        current = source
        if port is not None:
            filtered_dir = output_root / engine / f"filtered_port_{port}"
            try:
                summary = filter_directory_by_port(
                    current, filtered_dir, tool=engine, port=port
                )
                print(f"[+] {ENGINE_LABELS[engine]} filter summary: {summary}")
                current = filtered_dir
            except Exception as exc:
                print(f"[!] Filtering failed for {ENGINE_LABELS[engine]}: {exc}")

        if do_constants:
            processed_dir = output_root / engine / "processed"
            try:
                removed = remove_constant_columns(current, processed_dir)
                print(f"[+] {ENGINE_LABELS[engine]}:")

                for filename, columns in removed.items():
                    print(f"- {filename}: {len(columns)} constant column(s) removed")
                    print(70*'-')
                    print(columns)
                    print(5*'\n')
                    
##                print(
##                    f"[+] {ENGINE_LABELS[engine]}: removed "
##                    f"{len(removed)} constant column(s)."
##                )
                current = processed_dir
            except Exception as exc:
                print(f"[!] Constant-column processing failed: {exc}")

        # Add labels
        if do_labels:
            labeled_dir = output_root / engine / "labeled"

            try:
                labels = add_labels(
                    current,
                    labeled_dir,
                )

                print(f"[+] {ENGINE_LABELS[engine]} labels added:")

                for filename, label in labels.items():
                    print(f"- {filename}: {label}")

                current = labeled_dir

            except Exception as exc:
                print(
                    f"[!] Labeling failed for "
                    f"{ENGINE_LABELS[engine]}: {exc}"
                )

def filter_existing_flows() -> None:
    print("\n--- Filter existing flows by port ---")
    engine = choose_engine(allow_all=False)
    if engine is None:
        return

    default_input = engine_csv_dir(DEFAULT_OUTPUT, engine)
    input_dir = prompt_directory("CSV input directory", default_input)
    port = prompt_port()
    default_output = DEFAULT_OUTPUT / engine / f"filtered_port_{port}"
    output_dir = prompt_directory("Filtered output directory", default_output)

    try:
        summary = filter_directory_by_port(
            input_dir, output_dir, tool=engine, port=port
        )
        print(f"\n[+] Filtering complete. Summary: {summary}")
    except Exception as exc:
        print(f"\n[!] Filtering failed: {exc}")


def remove_constants_interactive() -> None:
    print("\n--- Remove common-value columns ---")
    input_dir = prompt_directory("CSV input directory", DEFAULT_OUTPUT)
    output_dir = prompt_directory(
        "Processed output directory", DEFAULT_OUTPUT / "processed"
    )
    try:
        removed = remove_constant_columns(input_dir, output_dir)
        print(f"\n[+] Removed {len(removed)} constant column(s).")
        if removed:
            for column in removed:
                print(f"    - {column}")
    except Exception as exc:
        print(f"\n[!] Post-processing failed: {exc}")


def add_labels_interactive() -> None:
    print("\n--- Add labels ---")

    input_dir = prompt_directory(
        "CSV input directory",
        DEFAULT_OUTPUT,
    )

    output_dir = prompt_directory(
        "Labeled output directory",
        DEFAULT_OUTPUT / "labeled",
    )

    try:
        labels = add_labels(
            input_dir,
            output_dir,
        )

        print("\n[+] Labels added:")

        for filename, label in labels.items():
            print(f"- {filename}: {label}")

    except Exception as exc:
        print(f"\n[!] Labeling failed: {exc}")
        
def show_statistics() -> None:
    print("\n--- Flow-file statistics ---")
    input_dir = prompt_directory("CSV directory", DEFAULT_OUTPUT)
    table = collect_csv_statistics(input_dir)
    if table.empty:
        print("No CSV files found.")
        return

    print()
    print(table.to_string(index=False))

    if prompt_yes_no("Save these statistics to CSV?"):
        default_file = input_dir / "flow_statistics.csv"
        value = input(f"Statistics file [{default_file}]: ").strip()
        save_path = Path(value).expanduser().resolve() if value else default_file
        save_path.parent.mkdir(parents=True, exist_ok=True)
        table.to_csv(save_path, index=False)
        print(f"[+] Saved: {save_path}")


def main() -> None:
    DEFAULT_INPUT.mkdir(parents=True, exist_ok=True)
    DEFAULT_OUTPUT.mkdir(parents=True, exist_ok=True)

    while True:
        print_header()
        print("\nMain menu")
        print("  1. Generate flows")
        print("  2. Filter existing flows by port")
        print("  3. Remove common-value columns")
        print("  4. Add labels")
        print("  5. Show flow-file statistics")
        print("  6. Exit")

        choice = prompt_choice(
            "\nChoice: ",
            {"1", "2", "3", "4", "5", "6"}
        )

        if choice == "1":
            generate_flows()

        elif choice == "2":
            filter_existing_flows()

        elif choice == "3":
            remove_constants_interactive()

        elif choice == "4":
            add_labels_interactive()

        elif choice == "5":
            show_statistics()

        else:
            print("\nGoodbye.")
            break

        input("\nPress Enter to return to the main menu...")



if __name__ == "__main__":
    main()
