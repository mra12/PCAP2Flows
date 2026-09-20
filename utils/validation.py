"""Input validation helpers."""

from pathlib import Path


def existing_directory(value: str) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.is_dir():
        raise NotADirectoryError(path)
    return path
