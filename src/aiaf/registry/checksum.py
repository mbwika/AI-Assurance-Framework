"""Checksum utilities for model integrity verification."""
import hashlib
from typing import Optional


def calculate_sha256(filepath: str, chunk_size: int = 4096) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_model(file_path: str, stored_hash: Optional[str]) -> bool:
    if stored_hash is None:
        return False
    current_hash = calculate_sha256(file_path)
    return current_hash == stored_hash
