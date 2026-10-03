#!/usr/bin/env python3
"""
DWARF source-location → address index, with a lightweight on-disk cache.

Decoding a large binary's DWARF line program with pyelftools is slow (tens of
seconds), and `patcher.py` is invoked repeatedly against the *same* binary by
the outer harness. To avoid re-parsing the binary every run, the resolved
`(file, line, column) -> [addr, ...]` mapping is cached to a small JSON sidecar
next to the binary. Subsequent runs load the sidecar (a few milliseconds)
instead of touching the DWARF at all.

The cache is:
  * keyed to the binary's (size, mtime) so it is auto-invalidated if the binary
    is rebuilt;
  * scoped to the set of source files that have been indexed so far ("covered"),
    and grown incrementally — the first run that touches a new file pays the
    parse cost once, every later run that touches it is a cache hit;
  * usable standalone: run this module as a script to pre-warm the cache for a
    binary and a known set of files.

Only the line-program *headers* of CUs that do not reference a target file are
inspected; the expensive state-machine decode runs only for CUs that do. See
DwarfLineIndex for details.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional, Set, Tuple

from elftools.elf.elffile import ELFFile


# ---------------------------------------------------------------------------
# Path normalization / file matching  (based on Test/utils/elf.py style)
# ---------------------------------------------------------------------------

def _normpath(p: str) -> str:
    return os.path.normpath(p)


def _safe_decode(x) -> str:
    if isinstance(x, (bytes, bytearray)):
        return x.decode("utf-8", errors="replace")
    return str(x)


def _file_match(query: str, dwarf_path: str, mode: str = "suffix") -> bool:
    q = _normpath(query)
    d = _normpath(dwarf_path)
    if mode == "exact":
        return q == d
    if mode == "basename":
        return os.path.basename(q) == os.path.basename(d)
    if mode == "suffix":
        return d.endswith(q) or d.endswith(os.path.basename(q))
    if mode == "regex":
        return re.search(query, dwarf_path) is not None
    raise ValueError(f"Unknown match mode: {mode!r}")


# ---------------------------------------------------------------------------
# DWARF line program helpers
# ---------------------------------------------------------------------------

def _resolve_lineprog_file(lineprog, file_index: int) -> Optional[str]:
    """Resolve file_entry[file_index] in a DWARF line program to an absolute or relative path string."""
    if not file_index:
        return None
    files = lineprog["file_entry"]
    if file_index < 1 or file_index > len(files):
        return None
    fe = files[file_index - 1]          # pyelftools uses 1-based file indices
    name = _safe_decode(fe.name)
    dir_index = getattr(fe, "dir_index", 0)
    inc_dirs = lineprog["include_directory"]
    if dir_index and 1 <= dir_index <= len(inc_dirs):
        d = _safe_decode(inc_dirs[dir_index - 1])
        return _normpath(f"{d}/{name}")
    return _normpath(name)


# Index value type alias: { (normalized_file_path, line, column_or_None) -> [addr, ...] }
IndexDict = Dict[Tuple[str, int, Optional[int]], List[int]]


# ---------------------------------------------------------------------------
# Core logic: line program → address index
# ---------------------------------------------------------------------------

class DwarfLineIndex:
    """
    Builds a source location → address mapping by traversing the DWARF line
    program once. Can be reused for multiple queries against the same binary.

    When `target_files` is given, only compilation units whose line-program
    file table references one of those source files are decoded. Running the
    line-program state machine (`get_entries()`) is by far the most expensive
    step — for a large binary it dominates total runtime — while parsing each
    CU's line-program *header* (which contains the file table) is cheap. Since
    a patcher run only touches the few files named in its `--patch` specs,
    skipping the state-machine decode for irrelevant CUs cuts the build from
    tens of seconds to well under a second with no loss of coverage: any CU
    that contains code for a target file (including inlined code) lists that
    file in its table and is therefore still decoded.

    Pass `target_files=None` to index every CU (the original behavior).

    Use `DwarfLineIndex.from_index(index)` to wrap a pre-built mapping (e.g.
    loaded from the on-disk cache) without touching the binary at all.
    """

    def __init__(self, dwarfinfo, target_files=None) -> None:
        self._index: IndexDict = {}
        # Match on basename: a superset of the suffix matcher used by queries,
        # so the filter can never exclude a CU that a query would later match.
        self._target_basenames: Optional[set] = (
            {os.path.basename(_normpath(f)) for f in target_files}
            if target_files is not None else None
        )
        self._build(dwarfinfo)

    @classmethod
    def from_index(cls, index: IndexDict) -> "DwarfLineIndex":
        """Wrap an already-built index mapping (skips all DWARF parsing)."""
        self = cls.__new__(cls)
        self._index = index
        self._target_basenames = None
        return self

    def _cu_references_target(self, lineprog) -> bool:
        """True if this CU's line-program file table names a target file.

        Cheap: reads the already-parsed header file table, no state-machine
        decode. Returns True unconditionally when no target filter is set.
        """
        if self._target_basenames is None:
            return True
        for fe in lineprog["file_entry"]:
            if os.path.basename(_safe_decode(fe.name)) in self._target_basenames:
                return True
        return False

    def _build(self, dwarfinfo) -> None:
        for cu in dwarfinfo.iter_CUs():
            lineprog = dwarfinfo.line_program_for_CU(cu)
            if lineprog is None:
                continue
            if not self._cu_references_target(lineprog):
                continue
            for entry in lineprog.get_entries():
                st = entry.state
                if st is None or st.end_sequence or st.address is None:
                    continue
                fpath = _resolve_lineprog_file(lineprog, st.file)
                if not fpath:
                    continue
                col = getattr(st, "column", None)
                key = (fpath, st.line, col)
                self._index.setdefault(key, []).append(int(st.address))

    def query(
        self,
        src_file: str,
        line_no: int,
        column: Optional[int] = None,
        match_mode: str = "suffix",
    ) -> List[int]:
        """
        Return the list of addresses corresponding to src_file:line_no(:column).

        If column is specified, addresses matching that column are returned first;
        if none match, all addresses for the line are returned instead.
        If column is None, all addresses for the line are returned.
        """
        all_addrs: List[int] = []
        col_addrs: List[int] = []

        for (fpath, ln, col), addrs in self._index.items():
            if ln != line_no:
                continue
            if not _file_match(src_file, fpath, mode=match_mode):
                continue
            all_addrs.extend(addrs)
            if column is not None and col == column:
                col_addrs.extend(addrs)

        result = col_addrs if (column is not None and col_addrs) else all_addrs
        return sorted(set(result))


# ---------------------------------------------------------------------------
# On-disk cache
# ---------------------------------------------------------------------------

CACHE_VERSION = 1


def cache_path_for(binary_path: str) -> str:
    """Sidecar cache path next to the binary."""
    return binary_path + ".metapro-dwarf-idx.json"


def _binary_stamp(binary_path: str) -> Dict[str, int]:
    """Identity fingerprint used to invalidate the cache when the binary changes."""
    st = os.stat(binary_path)
    return {"size": st.st_size, "mtime_ns": st.st_mtime_ns}


def _build_index_dict(binary_path: str, target_files: Optional[Set[str]]) -> IndexDict:
    """Parse the binary's DWARF and return the (filtered) index mapping."""
    with open(binary_path, "rb") as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            raise ValueError(f"No DWARF info found in: {binary_path}")
        return DwarfLineIndex(elf.get_dwarf_info(), target_files=target_files)._index


def save_index(binary_path: str, index: IndexDict, covered: Set[str]) -> bool:
    """Write the index + covered-file set to the sidecar cache.

    Returns False (with a warning) instead of raising if the cache cannot be
    written (e.g. read-only directory) — caching is an optimization, never a
    correctness requirement.
    """
    cpath = cache_path_for(binary_path)
    payload = {
        "version": CACHE_VERSION,
        "stamp": _binary_stamp(binary_path),
        "covered": sorted(covered),
        # col may be None -> stored as JSON null and restored as None.
        "entries": [[k[0], k[1], k[2], v] for k, v in index.items()],
    }
    try:
        tmp = cpath + ".tmp"
        with open(tmp, "w") as f:
            json.dump(payload, f, separators=(",", ":"), indent=4)
        os.replace(tmp, cpath)
        return True
    except OSError as e:
        sys.stderr.write(f"dwarf_index: could not write cache {cpath}: {e}\n")
        return False


def load_index(binary_path: str) -> Optional[Tuple[IndexDict, Set[str]]]:
    """Load (index, covered) from the sidecar, or None if absent/stale/corrupt."""
    cpath = cache_path_for(binary_path)
    if not os.path.exists(cpath):
        return None
    try:
        with open(cpath) as f:
            c = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if c.get("version") != CACHE_VERSION:
        return None
    try:
        if c.get("stamp") != _binary_stamp(binary_path):
            return None
    except OSError:
        return None
    index: IndexDict = {
        (e[0], e[1], e[2]): e[3] for e in c.get("entries", [])
    }
    covered: Set[str] = set(c.get("covered", []))
    return index, covered


def load_or_build_index(binary_path: str, target_files) -> DwarfLineIndex:
    """Return a DwarfLineIndex covering `target_files`, using the cache when
    possible and extending+persisting it on a miss.

    * Full hit (cache covers every target file): load only, no DWARF parse.
    * Partial/empty: parse DWARF for the not-yet-covered files, merge into the
      cached entries, and re-save so the cache grows monotonically.
    """
    if not os.path.isfile(binary_path):
        raise FileNotFoundError(f"File not found: {binary_path}")

    target_files = set(target_files)
    cached = load_index(binary_path)

    if cached is not None:
        index, covered = cached
        # "*" marks a full-binary index (every file already covered).
        missing = set() if "*" in covered else (target_files - covered)
        if not missing:
            return DwarfLineIndex.from_index(index)
        # Parse only the missing files and merge into the cached mapping.
        new_index = _build_index_dict(binary_path, missing)
        for k, v in new_index.items():
            index.setdefault(k, v)
        covered |= missing
        save_index(binary_path, index, covered)
        return DwarfLineIndex.from_index(index)

    # No usable cache: build for the requested files and persist.
    index = _build_index_dict(binary_path, target_files)
    save_index(binary_path, index, target_files)
    return DwarfLineIndex.from_index(index)


# ---------------------------------------------------------------------------
# Public query API (kept here so callers can resolve a location standalone)
# ---------------------------------------------------------------------------

def find_addresses_for_location(
    binary_path: str,
    file: str,
    line: int,
    column: int = -1,
) -> List[int]:
    """Return the list of binary addresses for a source location, via the cache."""
    idx = load_or_build_index(binary_path, {file})
    return idx.query(file, line, column)


# ---------------------------------------------------------------------------
# CLI: pre-warm the cache for a binary
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Pre-build and cache the DWARF line index for a binary so "
                    "that repeated patcher runs avoid re-parsing it."
    )
    ap.add_argument("binary", help="ELF binary with DWARF info")
    ap.add_argument("files", nargs="*",
                    help="source files to index (default: all files in the binary)")
    a = ap.parse_args()

    target = set(a.files) if a.files else None
    index = _build_index_dict(a.binary, target)
    # A full-binary index is marked with the "*" sentinel so any later request
    # is treated as covered (see load_or_build_index).
    covered = set(a.files) if a.files else {"*"}
    ok = save_index(a.binary, index, covered)
    print(f"Indexed {len(index)} location(s) "
          f"({'all files' if target is None else f'{len(target)} file(s)'}); "
          f"cache {'written to ' + cache_path_for(a.binary) if ok else 'NOT written'}.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
