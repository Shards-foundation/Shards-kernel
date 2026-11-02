"""Single-host local revision checkpoint for signed mTLS ingress policy v2.

This is an operational rollback *detection* layer, not an external
tamper-evident anchor. Moving/rolling back the database and its backups
together can defeat it; independent trust anchoring remains a P0 gate.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Iterator


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


@contextmanager
def _connect_existing(path: Path) -> Iterator[sqlite3.Connection]:
    """Own the entire SQLite connection lifetime, including exceptional exits.

    SQLite's connection context manager *only* commits/rolls back; it does
    not close the descriptor. Wrap it with closing() to prevent TLS ingress
    requests from exhausting file descriptors under bounded RLIMIT_NOFILE.
    mode=rw ensures missing trust databases are never silently created.
    """
    with closing(
        sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=2.0)
    ) as connection:
        with connection:
            yield connection


def bootstrap_ingress_checkpoint(
    path: Path, *, ingress_id: str, revision: int, digest: str
) -> tuple[int, int]:
    """Explicit single-use trusted-operator enrolment of a *virgin* DB.

    Invoke out-of-band only after verifying the signed v2 ingress policy.
    Startup deliberately never calls this method. An empty/replaced DB
    at runtime is not treated as an opportunity to enrol new authority.
    """
    identity = _check_inputs(path, ingress_id, revision, digest)
    try:
        with _connect_existing(path) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            # A deleted row or table in a previously enrolled database
            # must not be silently re-created by this bootstrap path.
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE type IN "
                "('table', 'index', 'view', 'trigger') LIMIT 1"
            ).fetchone() is not None:
                raise ValueError("Ingress checkpoint already initialised or altered")
            db.execute(
                """CREATE TABLE ingress_policy_checkpoint (
                    ingress_id TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL,
                    digest TEXT NOT NULL
                )"""
            )
            db.execute(
                "INSERT INTO ingress_policy_checkpoint VALUES (?, ?, ?)",
                (ingress_id, revision, digest),
            )
            if _identity(path) != identity:
                raise ValueError("Ingress checkpoint database changed during bootstrap")
    except sqlite3.Error as exc:
        raise ValueError("Ingress checkpoint database unavailable") from exc
    return identity


def checkpoint_ingress_revision(
    path: Path, *, ingress_id: str, revision: int, digest: str,
    activate: bool = True,
) -> tuple[int, int]:
    """Validate a signed revision; optionally activate it transactionally.

    Preflight callers MUST use activate=False: merely constructing an ingress
    instance cannot change persistent policy authority before its TLS files
    validate and its listener successfully binds. The start() path uses the
    default activate=True *after* the listener socket has bound but *before*
    any request handling begins. Existing rows/identity are always required;
    missing or replaced state fails closed, with no implicit enrolment.
    """
    if type(activate) is not bool:
        raise ValueError("Ingress activation must be a boolean")
    identity = _check_inputs(path, ingress_id, revision, digest)
    try:
        with _connect_existing(path) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT revision, digest FROM ingress_policy_checkpoint WHERE ingress_id=?",
                (ingress_id,),
            ).fetchone()
            if row is None:
                raise ValueError("Missing enrolled ingress checkpoint")
            if (
                type(row[0]) is not int
                or row[0] < 1
                or not isinstance(row[1], str)
                or revision < row[0]
                or (revision == row[0] and digest != row[1])
            ):
                raise ValueError("Ingress policy revision rollback or digest substitution")
            if activate and revision > row[0]:
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
        with _connect_existing(path) as db:
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
