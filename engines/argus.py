"""Argus engine for converting PCAP files into flow CSV files."""

from __future__ import annotations

import subprocess
from pathlib import Path

from utils.files import find_pcaps

ARGUS_FIELDS = [
    "srcid", "rank", "stime", "ltime", "trans", "flgs", "seq", "dur",
    "runtime", "idle", "mean", "stddev", "sum", "min", "max", "saddr",
    "daddr", "proto", "sport", "dport", "stos", "dtos", "sdsb", "ddsb",
    "sttl", "dttl", "pkts", "spkts", "dpkts", "bytes", "sbytes", "dbytes",
    "appbytes", "sappbytes", "dappbytes", "pcr", "load", "sload", "dload",
    "loss", "sloss", "dloss", "ploss", "psloss", "pdloss", "retrans",
    "sretrans", "dretrans", "pretrans", "psretrans", "pdretrans", "sgap",
    "dgap", "rate", "srate", "drate", "dir", "sintpkt", "sintdist",
    "sintpktact", "sintdistact", "sintpktidl", "sintdistidl", "dintpkt",
    "dintdist", "dintpktact", "dintdistact", "dintpktidl", "dintdistidl",
    "state", "suser", "duser", "swin", "dwin", "tcprtt", "synack", "ackdat",
    "tcpopt", "inode", "offset", "smeansz", "dmeansz", "spktsz", "smaxsz",
    "dpktsz", "dmaxsz", "sminsz", "dminsz",
]


def pcap_to_argus(pcap_path: Path, argus_path: Path) -> None:
    """Convert one PCAP file to Argus binary format."""
    argus_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["argus", "-r", str(pcap_path), "-w", str(argus_path)],
        check=True,
    )


def argus_to_csv(argus_path: Path, csv_path: Path) -> None:
    """Extract configured Argus fields into a CSV file."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    filename_parts = argus_path.stem.split("_")
    filename_part3 = filename_parts[-1] if len(filename_parts) >= 3 else "Unknown"

    command = ["ra", "-r", str(argus_path), "-M", "noman", "-c", ",", "-s", *ARGUS_FIELDS]
    result = subprocess.run(command, check=True, capture_output=True, text=True)

    with csv_path.open("w", encoding="utf-8", newline="") as out:
    # Write CSV header
       # out.write(",".join(ARGUS_FIELDS)+"\n")
        for line in result.stdout.splitlines():
            if line.strip():
                #out.write(f"{line},{filename_part3}\n")
                out.write(f"{line}\n")


def run(input_dir: str | Path, output_dir: str | Path) -> list[Path]:
    """Process every PCAP under *input_dir* and return generated CSV paths."""
    input_dir = Path(input_dir).expanduser().resolve()
    output_dir = Path(output_dir).expanduser().resolve()

    pcaps = find_pcaps(input_dir)
    if not pcaps:
        raise FileNotFoundError(f"No .pcap or .pcapng files found under: {input_dir}")

    argus_dir = output_dir / "argus_binary"
    csv_dir = output_dir / "csv"
    generated: list[Path] = []

    for pcap in pcaps:
        relative = pcap.relative_to(input_dir)
        argus_path = (argus_dir / relative).with_suffix(".argus")
        csv_path = (csv_dir / relative).with_name(f"argusflows_{relative.stem}.csv")

        print(f"[Argus] {pcap.name} -> {csv_path.name}")
        pcap_to_argus(pcap, argus_path)
        argus_to_csv(argus_path, csv_path)
        generated.append(csv_path)

    return generated
