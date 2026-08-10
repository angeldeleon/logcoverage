"""Bounded, symlink-refusing traversal of a rule directory.

A rule directory is the least trustworthy input this tool has. It is usually a
clone of a public repository, often with a fork's worth of local additions, and
it is a *tree* — so unlike a single export file it can be arbitrarily deep,
arbitrarily wide, and can contain links pointing anywhere the running account can
read.

Four things are enforced here, and each one exists because the alternative is a
concrete failure rather than a theoretical one:

* **No symlinks, at all.** Not "no symlinks that escape the root" — no symlinks.
  Escape detection by path comparison is a race: the check and the open are two
  lookups of the same name. Every file is opened with ``O_NOFOLLOW`` and every
  directory entry is tested with ``is_symlink(follow_symlinks=False)`` before it
  is descended into, so a link is skipped and recorded rather than resolved. The
  consequence for an operator who genuinely symlinks a shared rule directory is
  one log line telling them exactly which path was skipped.
* **Depth, count and byte caps.** A tree with a directory cycle made of bind
  mounts, or four hundred thousand files, must fail as a bounded read rather
  than as an out-of-memory kill on a cron job.
* **``O_NONBLOCK`` on every open.** A FIFO in a rule directory blocks inside
  ``os.open`` before any regular-file check can refuse it, and would hang the
  scheduled run forever with nothing in the log.
* **Deterministic ordering.** ``os.scandir`` returns entries in filesystem order,
  which differs between machines. Everything is sorted, because the observations
  this produces are persisted and diffed, and an ordering that varies would
  manufacture drift on every run.

Nothing here parses anything. It hands bytes to the format modules.
"""

from __future__ import annotations

import logging
import os
import stat
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

_READ_CHUNK = 1024 * 1024
RULE_SUFFIXES: tuple[str, ...] = (".yml", ".yaml")


class RuleLoadError(Exception):
    """The rule input could not be read at all."""


@dataclass(frozen=True, slots=True)
class LoadedFile:
    """One rule file, read whole."""

    path: str
    """Path relative to the root, with forward slashes. Stable across machines,
    which matters because it is the fallback identity for a rule with no id."""

    data: bytes


@dataclass(slots=True)
class LoadResult:
    files: list[LoadedFile]
    skipped: list[str]
    """Human-readable reasons, one per skipped path. Surfaced in the report:
    a rule file that was silently skipped is a detection this tool would
    otherwise claim to have assessed."""

    truncated: bool = False
    """True when a cap stopped the walk. The caller turns this into an
    indeterminate facet — a partial rule set cannot support a claim that some
    source is read by nothing."""


def read_file(path: Path, *, max_bytes: int) -> bytes:
    """Read one file through a descriptor, refusing anything that is not a regular file.

    ``O_NOFOLLOW`` and ``O_NONBLOCK`` for the reasons in the module docstring.
    The size is checked from ``fstat`` before reading and again while reading,
    because the first tells the truth about a regular file and the second is what
    catches a file that grows underneath us.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError as exc:
        raise RuleLoadError(f"file not found: {path}") from exc
    except OSError as exc:
        # ELOOP lands here: the path is a symlink and we refused to follow it.
        raise RuleLoadError(f"cannot open {path}: {exc}") from exc

    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuleLoadError(f"{path} is not a regular file; refusing to read it")
        if info.st_size > max_bytes:
            raise RuleLoadError(f"{path} is {info.st_size} bytes, above the {max_bytes} byte limit")
        os.set_blocking(fd, True)

        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, _READ_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise RuleLoadError(f"{path} exceeds the {max_bytes} byte limit while reading")
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as exc:
        raise RuleLoadError(f"cannot read {path}: {exc}") from exc
    finally:
        os.close(fd)


def walk_rule_tree(
    root: str | Path,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
    max_depth: int,
    suffixes: tuple[str, ...] = RULE_SUFFIXES,
) -> LoadResult:
    """Read every rule file under *root*, bounded and without following links.

    Raises :class:`RuleLoadError` only when the root itself is unusable. An
    individual unreadable file is recorded in ``skipped`` and the walk continues:
    one malformed file in a repository of three thousand must not cost the other
    two thousand nine hundred and ninety-nine their analysis.
    """
    base = Path(root).expanduser()
    result = LoadResult(files=[], skipped=[])

    try:
        if base.is_symlink():
            raise RuleLoadError(f"rule path {base} is a symlink; refusing to follow it")
        if base.is_file():
            result.files.append(LoadedFile(path=base.name, data=read_file(base, max_bytes=max_file_bytes)))
            return result
        if not base.is_dir():
            raise RuleLoadError(f"rule path not found: {base}")
    except OSError as exc:
        raise RuleLoadError(f"cannot stat rule path {base}: {exc}") from exc

    total_bytes = 0
    # Explicit stack rather than os.walk: os.walk offers no depth bound and its
    # symlink handling is a keyword argument somebody will eventually flip.
    stack: list[tuple[Path, int]] = [(base, 0)]

    while stack:
        directory, depth = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            result.skipped.append(f"{_rel(base, directory)}: cannot list directory ({exc})")
            continue

        for entry in entries:
            entry_path = Path(entry.path)
            relative = _rel(base, entry_path)
            try:
                if entry.is_symlink():
                    # Recorded, not silently dropped. An operator who symlinks a
                    # shared rule set needs to know why their rules vanished.
                    result.skipped.append(f"{relative}: symlink, not followed")
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth + 1 > max_depth:
                        result.skipped.append(f"{relative}: deeper than max_depth ({max_depth})")
                        result.truncated = True
                        continue
                    stack.append((entry_path, depth + 1))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    # A device node, socket or FIFO. Named rather than ignored,
                    # because one appearing in a rule directory is worth knowing
                    # about.
                    result.skipped.append(f"{relative}: not a regular file")
                    continue
            except OSError as exc:
                result.skipped.append(f"{relative}: cannot stat ({exc})")
                continue

            if entry_path.suffix.lower() not in suffixes:
                continue

            if len(result.files) >= max_files:
                result.skipped.append(f"{relative}: beyond max_files ({max_files})")
                result.truncated = True
                continue

            try:
                data = read_file(entry_path, max_bytes=max_file_bytes)
            except RuleLoadError as exc:
                result.skipped.append(str(exc))
                continue

            total_bytes += len(data)
            if total_bytes > max_total_bytes:
                result.skipped.append(f"{relative}: beyond max_total_bytes ({max_total_bytes})")
                result.truncated = True
                continue

            result.files.append(LoadedFile(path=relative, data=data))

    # Sorted for the reason in the module docstring: these paths become rule keys
    # and the keys are persisted and compared between runs.
    result.files.sort(key=lambda loaded: loaded.path)
    result.skipped.sort()
    if result.skipped:
        log.info("skipped %d path(s) while walking %s", len(result.skipped), base)
    return result


def _rel(base: Path, path: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError:  # pragma: no cover - the walk never leaves base
        return path.name
