"""Summarise a directory for the collector example."""

import hashlib
import os


def summarise(root: str) -> dict:
    """Return the file count, total size and a digest of names and sizes.

    Raises OSError when the root is missing or unreadable, so the caller can
    report a failed collection instead of an empty snapshot.
    """
    entries = []
    with os.scandir(root) as listing:
        for entry in listing:
            if entry.is_file(follow_symlinks=False):
                entries.append((entry.name, entry.stat(follow_symlinks=False).st_size))
    entries.sort()

    digest = hashlib.sha256()
    for name, size in entries:
        digest.update(f"{name}\0{size}\n".encode())

    return {
        "files": len(entries),
        "bytes": sum(size for _, size in entries),
        "listing_sha256": digest.hexdigest(),
    }
