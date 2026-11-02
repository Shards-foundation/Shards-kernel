"""Single-host local revision checkpoint for signed mTLS ingress policy v2.

This is an operational rollback *detection* layer, not an external
tamper-evident anchor. Moving/rolling back the database and its backups
together can defeat it; independent trust anchoring remains a P0 gate.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path


def _identity(path: Path) -> tuple[int, int]:
    """Require a private, existing local regular SQLite file, never a symlink."""
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("Ingress checkpoint must be an existing absolute regular file")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or (info.st_mode & 0o077):
        raise ValueError("Ingress checkpoint must be a private 0600 database")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ValueError("Ingress checkpoint must belong to the serving user")
    return info.st_dev, info.st_ino


def _check_inputs(
    path: Path, ingress_id: str, revision: int, digest: str
) -> tuple[int, int]:
    if (
        not isinstance(ingress_id, str)
        or not 1 <= len(ingress_id) <= 128
        or not ingress_id.isascii()
        or not all(ch.isalnum() or ch in "_-" for ch in ingress_id)
        or type(revision) is not int
        or revision < 1
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(c not in "0123456789abcdef" for c in digest)
    ):
        raise ValueError("Invalid signed ingress revision identity")
    return _identity(path)


def checkpoint_ingress_revision(
    path: Path, *, ingress_id: str, revision: int, digest: str
) -> tuple[int, int]:
    """Commit new signed revision atomically before accepting any requests.

    Database must be created/protected by the trusted host operator before
    running the ingress. Never reset it to roll back an enrolled policy.
    """
    identity = _check_inputs(path, ingress_id, revision, digest)
    try:
        with sqlite3.connect(path, timeout=2.0) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """CREATE TABLE IF NOT EXISTS ingress_policy_checkpoint (
                    ingress_id TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL,
                    digest TEXT NOT NULL
                )"""
            )
            row = db.execute(
                "SELECT revision, digest FROM ingress_policy_checkpoint WHERE ingress_id=?",
                (ingress_id,),
            ).fetchone()
            if row is not None and (
                type(row[0]) is not int
                or row[0] < 1
                or not isinstance(row[1], str)
                or revision < row[0]
                or (revision == row[0] and digest != row[1])
            ):
                raise ValueError("Ingress policy revision rollback or digest substitution")
            if row is None:
                db.execute(
                    "INSERT INTO ingress_policy_checkpoint VALUES (?, ?, ?)",
                    (ingress_id, revision, digest),
                )
            elif revision > row[0]:
                db.execute(
                    "UPDATE ingress_policy_checkpoint SET revision=?, digest=? WHERE ingress_id=?",
                    (revision, digest, ingress_id),
                )
            if _identity(path) != identity:
                raise ValueError("Ingress checkpoint database changed during update")
    except sqlite3.Error as exc:
        raise ValueError("Ingress checkpoint database unavailable") from exc
    return identity


def verify_ingress_checkpoint(
    path: Path, *, ingress_id: str, revision: int, digest: str,
    identity: tuple[int, int],
) -> None:
    """Fail closed on replacement, deletion or newer/different signed version."""
    if _check_inputs(path, ingress_id, revision, digest) != identity:
        raise ValueError("Ingress checkpoint database was replaced")
    try:
        with sqlite3.connect(path, timeout=2.0) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT revision, digest FROM ingress_policy_checkpoint WHERE ingress_id=?",
                (ingress_id,),
            ).fetchone()
            if row is None or row != (revision, digest):
                raise ValueError("Ingress policy checkpoint no longer matches running policy")
            if _identity(path) != identity:
                raise ValueError("Ingress checkpoint database was replaced")
    except sqlite3.Error as exc:
        raise ValueError("Ingress checkpoint database unavailable") from exc
