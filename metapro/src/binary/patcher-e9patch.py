#!/usr/bin/env python3
"""
Address resolver for the e9patch-based binary patcher.

Unlike the surgical patcher (patcher.py), this file does NOT touch the binary at
all. The actual rewriting — reading the ELF, building trampolines, and writing
the patched binary — is delegated to e9patch / e9tool via the C wrapper in
patch_e9patch.c. This script's only job is the part e9patch can't do on its own:

  resolve each patch spec (file:line:col range) to the concrete virtual
  addresses involved, using DWARF line info (cached by dwarf_index.py),
  and hand back a plain data structure of integer addresses.

For an INSERT_NOT_NULL_CHECKER site we need two addresses:

  * patch_addr  — the VA of the first instruction of the guarded statement;
                  e9patch patches this to call patch_insert_if_wrapper().
  * skip_target — the VA just past the statement, where control must land
                  when the null check returns false (the statement is skipped).

Both are produced as Python ints; render them as hex with f"0x{addr:x}" when
feeding e9tool. Everything about trampoline layout, register saving, and the
return path now lives inside e9patch's instrumentation, so none of that is here.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import sys
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
import subprocess as sp


from dwarf_index import (  # noqa: E402
    DwarfLineIndex,
    _file_match,
    load_or_build_index,
)


# ── Types ────────────────────────────────────────────────────────────────────
class Template(Enum):
    INSERT_EXPR = "INSERT_EXPR"
    INSERT_NOT_NULL_CHECKER = "INSERT_NOT_NULL_CHECKER"

    @property
    def e9_wrapper(self) -> str:
        """Name of the e9patch C wrapper (see patch_e9patch.c) that e9tool
        calls at the patch site for this template."""
        return {
            Template.INSERT_EXPR: "patch_insert_expr",
            Template.INSERT_NOT_NULL_CHECKER: "patch_insert_if_wrapper",
        }[self]


@dataclass(frozen=True)
class SrcLocation:
    file: str
    line: int
    col: int


@dataclass
class PatchSpec:
    """User-provided patch specification (pre-resolution)."""
    id: int
    function: str
    start: SrcLocation
    end: SrcLocation
    # Config template. When given it decides wrap-vs-insert (INSERT_NOT_NULL_CHECKER
    # wraps + skips; INSERT_EXPR only inserts). Optional for backward compatibility: when
    # None the span decides (start != end -> wrap), which mis-classifies an INSERT_EXPR
    # whose anchor has a non-zero span as a wrap.
    template: Optional[Template] = None


@dataclass
class PatchPoint:
    """A resolved patch site, ready to be handed to e9patch.

    All addresses are virtual addresses as plain ints. Use to_hex() (or
    f"0x{addr:x}") when emitting them for e9tool.

    For an INSERT_NOT_NULL_CHECKER site (start != end), e9patch patches
    `patch_addr` to call patch_insert_if_wrapper(id, function); when that
    returns false the statement is skipped by redirecting control to
    `skip_target`. For an insert-only site (start == end) there is no null
    check and `skip_target` is None.
    """
    id: int                          # passed to the runtime as the first arg
    function: str                    # enclosing function (second runtime arg)
    jmp_id: int                      # per-site jmp id (third arg of exec_expr)
    patch_addr: int                  # VA to patch (first insn of the statement)
    end_addr: int                    # VA of the last insn of the statement
    skip_target: Optional[int]       # VA to jump to on a failed null check
    has_null_check: bool             # True for a wrap (INSERT_NOT_NULL_CHECKER): emit skip
    insert_before: bool = True       # insert the expr before (vs after) the patch site;
                                     # a zero-width span (insert-after site) sets this False
    skip_replay: Tuple[int, ...] = ()  # instruction bytes to re-run before jumping to
                                     # skip_target (see plan_skip_replay); empty for most sites

    @property
    def template(self) -> Template:
        return (Template.INSERT_NOT_NULL_CHECKER if self.has_null_check
                else Template.INSERT_EXPR)

    def to_hex(self) -> Dict[str, object]:
        """Serializable view with addresses rendered as hex strings."""
        d = asdict(self)
        for key in ("patch_addr", "end_addr", "skip_target"):
            d[key] = None if d[key] is None else f"0x{d[key]:x}"
        d["template"] = self.template.value
        d["skip_replay"] = " ".join(f"{b:02x}" for b in self.skip_replay)
        return d


# ── CLI patch-spec parser ────────────────────────────────────────────────────
def parse_patch_spec(s: str) -> PatchSpec:
    """Parse 'id:function:file:start_line:start_col:end_line:end_col[:template]'.

    Same file is reused for the end location (statements don't span files). The
    trailing template field is optional (INSERT_EXPR / INSERT_NOT_NULL_CHECKER); when
    absent the span decides wrap-vs-insert (legacy behaviour).
    """
    parts = s.split(":")
    if len(parts) not in (7, 8):
        raise argparse.ArgumentTypeError(
            f"Invalid --patch spec: {s!r}; expected "
            f"id:function:file:start_line:start_col:end_line:end_col[:template]"
        )
    pid, func, file, sl, sc, el, ec = parts[:7]
    template = None
    if len(parts) == 8 and parts[7]:
        try:
            template = Template(parts[7])
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"Invalid --patch spec: {s!r}: unknown template {parts[7]!r}")
    try:
        return PatchSpec(
            id=int(pid),
            function=func,
            start=SrcLocation(file=file, line=int(sl), col=int(sc)),
            end=SrcLocation(file=file, line=int(el), col=int(ec)),
            template=template,
        )
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid --patch spec: {s!r}: {e}")


def parse_jmp_ids(file_path: str) -> Dict[str, Dict[int, int]]:
    result: Dict[str, Dict[int, int]] = {}
    with open(file_path, 'r') as f:
        jmp_ids = json.load(f)
    for file in jmp_ids:
        result[file] = {int(line): int(id_) for line, id_ in jmp_ids[file].items()}
    return result


# ── Symbol table ─────────────────────────────────────────────────────────────
def load_function_ranges(
    binary_path: str,
) -> Dict[str, List[Tuple[int, int]]]:
    """Build a `name -> list of (lo, hi)` VA-range map from the binary's symbol
    table, read straight from `.symtab` (falling back to `.dynsym`).

    This is the only piece of binary metadata the e9patch path needs: the ranges
    bound the DWARF address search in `function_va_range`. e9patch reads and
    rewrites the binary itself downstream, so no preprocessing/cave step is
    required here. Parsing the raw symbol-table bytes with `struct` (rather than
    pyelftools' per-symbol objects) keeps this at ~0.04 s even on large binaries.

    A name maps to several ranges when static functions in different source files
    share it; `function_va_range` disambiguates those by source file.
    """
    from elftools.elf.elffile import ELFFile

    functions: Dict[str, List[Tuple[int, int]]] = {}
    with open(binary_path, "rb") as f:
        elf = ELFFile(f)
        sec = (elf.get_section_by_name(".symtab")
               or elf.get_section_by_name(".dynsym"))
        if sec is None:
            return functions
        strdata = elf.get_section(sec["sh_link"]).data()
        data = sec.data()
        entsize = sec["sh_entsize"]
        endian = "<" if elf.little_endian else ">"
        if elf.elfclass == 64:
            # Elf64_Sym: name(I) info(B) other(B) shndx(H) value(Q) size(Q)
            unpack = struct.Struct(endian + "IBBHQQ").unpack_from
            def fields(off):
                name_off, _i, _o, _s, value, size = unpack(data, off)
                return name_off, value, size
        else:
            # Elf32_Sym: name(I) value(I) size(I) info(B) other(B) shndx(H)
            unpack = struct.Struct(endian + "IIIBBH").unpack_from
            def fields(off):
                name_off, value, size, _i, _o, _s = unpack(data, off)
                return name_off, value, size

        for off in range(0, len(data) - entsize + 1, entsize):
            name_off, value, size = fields(off)
            if size <= 0 or value <= 0 or not name_off:
                continue
            end = strdata.find(b"\x00", name_off)
            name = strdata[name_off:end if end != -1 else None].decode(
                "utf-8", "replace")
            rng = (value, value + size)
            ranges = functions.setdefault(name, [])
            # Keep every distinct range so same-named functions in different
            # source files can be told apart later by VA.
            if rng not in ranges:
                ranges.append(rng)
    return functions


# The e9compile'd instrumentation binary that defines the patch wrappers
# (patch_insert_expr / patch_insert_if_wrapper). Same path used by call_e9patch.
WRAPPER_BINARY = "/usr/local/bin/metapro-e9patch"


def load_wrapper_addrs(
    wrapper_binary: str = WRAPPER_BINARY,
) -> Dict[str, int]:
    """Resolve the VAs of the e9patch C wrappers from the instrumentation
    binary's own symbol table (reusing load_function_ranges).

    Returns a `name -> VA` map for patch_insert_expr / patch_insert_if_wrapper.
    These are the addresses in `wrapper_binary`'s address space; the trampoline
    feeds them to e9patch via the $exprFn / $ifFn metadata so the patched code
    can call into the loaded instrumentation.
    """
    ranges = load_function_ranges(wrapper_binary)
    addrs: Dict[str, int] = {}
    for name in ("patch_insert_expr", "patch_insert_if_wrapper"):
        rs = ranges.get(name)
        if not rs:
            raise ValueError(
                f"wrapper function {name!r} not found in {wrapper_binary!r} "
                f"(stripped, or wrong binary?)"
            )
        # A wrapper is a single global function, so there is exactly one range;
        # its lo VA is the entry address.
        addrs[name] = rs[0][0]
    return addrs


# ── DWARF address resolution ─────────────────────────────────────────────────
def function_va_range(
    functions: Dict[str, List[Tuple[int, int]]],
    idx: DwarfLineIndex, name: str, src_file: str,
) -> Optional[Tuple[int, int]]:
    """Return the [lo, hi) VA range of function `name` from the cached symbol
    table, or None if it is absent.

    A symbol name is not unique across a program: static functions in different
    source files can share the same name, so the cache may hold several ranges
    for one name. When that happens, disambiguate with `src_file` by picking the
    range whose VA window contains DWARF line addresses attributed to that
    source file. Returns None if the name is unknown, or if it is ambiguous and
    no range matches `src_file`."""
    ranges = functions.get(name)
    if not ranges:
        return None
    if len(ranges) == 1:
        return ranges[0]
    # Multiple functions share this name; the right one is the range that holds
    # the DWARF line addresses belonging to `src_file`.
    file_addrs = [
        a
        for (fpath, _ln, _col), addrs in idx._index.items()
        if _file_match(src_file, fpath)
        for a in addrs
    ]
    best: Optional[Tuple[int, int]] = None
    best_hits = 0
    for lo, hi in ranges:
        hits = sum(1 for a in file_addrs if lo <= a < hi)
        if hits > best_hits:
            best, best_hits = (lo, hi), hits
    return best


def _located_addrs(
    idx: DwarfLineIndex, src_file: str, func_range: Tuple[int, int],
    is_cold=None,
) -> List[Tuple[int, int, Optional[int], bool]]:
    """Every in-function instruction address the line table records for `src_file`, as
    (address, line, column, generated) sorted by address, with the line-0 rows resolved.

    A row whose line is 0 has no source location of its own: the compiler emits it for code it
    generated, and in an ASAN build such a row precedes *every* checked access -- the shadow
    address computation, which the access that follows depends on. That code belongs to the
    statement of the next row that does carry a line, so this attributes it there and flags it
    `generated`.

    Resolving those rows is what lets a fall-through land on the real first instruction of the
    next statement. Left unresolved they are invisible (line 0 sorts before every real line, so
    such a row is neither in range nor past it), and the fall-through lands on the *second*
    instruction of the next statement's check sequence, past the load it needs: skipping a
    `GF_LOG(...)` in gpac-42518828 that way left `%rax` holding the return value of `gf_log`,
    and the shadow check on it then read a wild address.

    Trailing generated code has no following statement to belong to and stays at line 0.

    `is_cold` (see asan_report_stub_filter) drops rows that belong to ASAN's out-of-line failure
    blocks rather than to the statement they name -- they are unreachable except from a failed
    check, so they are code no patch site may resolve to, in range or past it.
    """
    func_lo, func_hi = func_range
    rows: List[Tuple[int, int, Optional[int]]] = []
    for (fpath, ln, col), addrs in idx._index.items():
        if not _file_match(src_file, fpath):
            continue
        rows.extend((a, ln, col) for a in addrs
                    if func_lo <= a < func_hi and not (is_cold is not None and is_cold(a)))
    rows.sort()

    located: List[Tuple[int, int, Optional[int], bool]] = []
    generated: List[int] = []            # line-0 rows waiting for the statement they belong to
    for a, ln, col in rows:
        if ln == 0:
            generated.append(a)
            continue
        located.extend((g, ln, col, True) for g in generated)
        generated = []
        located.append((a, ln, col, False))
    located.extend((g, 0, None, True) for g in generated)
    return located


def resolve_range_addrs(
    idx: DwarfLineIndex, spec: PatchSpec, func_range: Tuple[int, int], is_cold=None,
) -> Optional[Tuple[Tuple[int, ...], Optional[int]]]:
    """Resolve a patch spec by scanning DWARF line entries with the same
    range-matching rule the LLVM pass uses when picking instrumentation
    insertion points (see instrument_pass.cpp).

    Candidate addresses are restricted to `func_range = [lo, hi)` — the VA
    range of the target function. Without this filter, a source line past
    `spec.end` can map to an address in another function that the linker
    placed at a lower VA.

    Returns (in_range_addrs, skip_target):
    - in_range_addrs: tuple of in-function addresses whose source loc
      (file, line, col) lies in the inclusive range [spec.start, spec.end].
      May be empty if no DWARF entry matches the range directly (e.g. an
      insert-only site between DWARF line entries).
    - skip_target: lowest in-function address strictly past spec.end (line >
      end.line, or same line with col > end.col). None if no post-range
      address exists (insert-only sites, or sites at function end).

    Caller derives patch_addr / end_addr from min/max of in_range_addrs.
    Returns None only if BOTH are empty — at least one must be present.
    """
    s, e = spec.start, spec.end
    point = s == e                      # zero-width point spec (insert site)
    in_range: List[int] = []
    after: List[int] = []
    before = 0
    for a, ln, col, generated in _located_addrs(idx, s.file, func_range, is_cold):
        # Strictly past the end of the range.
        if ln > e.line or (ln == e.line and col is not None and col > e.col):
            after.append(a)
            continue
        if generated:
            # Compiler-generated code belonging to a statement inside the range. It is only
            # ever needed as a fall-through candidate (handled above): letting it into
            # in_range would move patch_addr onto ASAN's scope bookkeeping, which the skip
            # must run rather than jump over (see advance_past_asan_lifetime).
            continue
        if ln < s.line:
            continue
        # Strictly before the end of the range.
        if ln < e.line or (ln == e.line and col is not None and col <= e.col):
            # For a point spec, `before` is the last instruction *strictly*
            # before the location; those addresses fall outside in_range, so
            # track them here (the at-point instructions belong to what follows).
            if point:
                before = max(before, a)
        if ln == s.line and col is not None and col < s.col:
            continue
        # Unknown column on a boundary line is treated as in-range.
        in_range.append(a)
        # For a span, `before` is the last in-function instruction at or before
        # the ending location (counterpart to skip_target's first-past-end addr).
        if not point:
            before = max(before, a)

    if not in_range and not after:
        return None
    if s == e:
        return (before,), None
    # skip_target is the fall-through *past the whole statement*, so it must lie after the
    # statement's own instructions (> end_addr). Code reordering / inlining -- amplified by
    # ASAN's inserted shadow-check and outlined-report code -- can place an instruction from
    # a past-end source line at a VA *below* the statement, so a plain min(after) can point
    # backwards and make the null-check skip jump into an infinite loop. Restrict to
    # addresses strictly past end_addr (= max(in_range)) so the skip only ever goes forward.
    end = max(in_range) if in_range else None
    forward = [a for a in after if end is None or a > end]
    skip_target = min(forward) if forward else None
    return tuple(in_range), skip_target


# ── ASAN lifetime instrumentation at patch sites ─────────────────────────────
# Shadow byte values ASAN writes when a stack object enters or leaves scope:
# 0x00-0x07 = fully/partially addressable, 0xf1-0xf8 = the redzone and
# "use after scope" markers. See asan_internal.h / ASanStackVariableDescription.
_ASAN_SHADOW_BYTES = frozenset(range(0x00, 0x08)) | frozenset(range(0xF1, 0xF9))

# Out-of-line forms of the same bookkeeping, for ranges too big to store inline.
_ASAN_SHADOW_FN_PREFIXES = ("__asan_set_shadow", "__asan_unpoison_stack_memory")


def asan_shadow_fn_addrs(
    functions: Dict[str, List[Tuple[int, int]]],
) -> Dict[int, str]:
    """Entry VA -> name for the ASAN shadow-setting helpers, so a `call` to one
    can be recognised in `advance_past_asan_lifetime`."""
    return {
        lo: name
        for name, ranges in functions.items()
        if name.startswith(_ASAN_SHADOW_FN_PREFIXES)
        for lo, _hi in ranges
    }


# The reporters a failed shadow check branches to. They do not return, and the blocks that call
# them are only reachable from such a branch (see asan_report_stub_filter).
_ASAN_REPORT_FN_PREFIX = "__asan_report"
_ASAN_STUB_MAX_INSNS = 3        # `lea rdi,[rsp+X]` / `mov rdi,reg` and the call itself


def asan_report_fn_addrs(
    functions: Dict[str, List[Tuple[int, int]]],
) -> Dict[int, str]:
    """Entry VA -> name for ASAN's failure reporters (`__asan_report_load8`, ...)."""
    return {
        lo: name
        for name, ranges in functions.items()
        if name.startswith(_ASAN_REPORT_FN_PREFIX)
        for lo, _hi in ranges
    }


def asan_report_stub_filter(
    binary_path: str, segments: List[dict], elfclass: int,
    report_fns: Dict[int, str],
):
    """A predicate `addr -> bool` telling whether `addr` starts one of ASAN's out-of-line failure
    blocks: a couple of instructions setting up the faulting address, then a call to an
    `__asan_report_*`.

    Those blocks sit past the end of the function's real code and carry line-table rows of their
    own -- clang attributes each to the line of the access it reports -- so the same source line
    appears twice, once as code and once as a reporter. Taking them for code is what broke
    ndpi-42514015: the rows of a cold block pushed `end_addr` 629 bytes past the statement, which
    in turn ruled out the real next-statement row (it now sat *before* that end) and left the skip
    pointing at `lea 0x40(%rsp),%rdi; call __asan_report_load8`. Disabling the statement then
    called the reporter for a check nobody had performed, and ASAN, finding the address perfectly
    addressable, printed `unknown-crash` on it.

    Dropping these rows cannot lose reachable code: a reporter never returns, so its block is only
    ever entered by the branch of a failed check.

    Results are cached, since the same handful of addresses is tested for every patch spec."""
    cache: Dict[int, bool] = {}
    if not report_fns:
        return lambda _addr: False
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
        from capstone.x86 import X86_OP_IMM
    except ImportError:
        return lambda _addr: False
    md = Cs(CS_ARCH_X86, CS_MODE_64 if elfclass == 64 else CS_MODE_32)
    md.detail = True

    def is_stub(addr: int) -> bool:
        hit = cache.get(addr)
        if hit is not None:
            return hit
        cache[addr] = False
        off = _va_to_file_offset(segments, addr)
        if off is None:
            return False
        with open(binary_path, "rb") as f:
            f.seek(off)
            code = f.read(16 * _ASAN_STUB_MAX_INSNS)
        for i, insn in enumerate(md.disasm(code, addr)):
            if i >= _ASAN_STUB_MAX_INSNS:
                break
            if insn.mnemonic.startswith("call"):
                ops = insn.operands
                cache[addr] = bool(ops and ops[0].type == X86_OP_IMM
                                   and ops[0].imm in report_fns)
                break
            if _leaves_the_path(insn.mnemonic):
                break                      # a branch before any call: ordinary code
        return cache[addr]

    return is_stub


def _is_asan_lifetime_insn(insn, shadow_fns: Dict[int, str]) -> bool:
    """True if `insn` is ASAN scope bookkeeping rather than program code.

    Two forms are recognised:

      * an immediate-to-memory store of shadow bytes, e.g.
        `movb $0x4, 0x1ec(%rcx)` — every byte of the immediate must be a legal
        shadow value, and the destination must not be addressed off rsp/rbp.
        The frame's shadow base always lives in a scratch register (reloaded
        from a spill slot), whereas a plain local is addressed off the frame
        pointer, so that one test separates shadow writes from stores to
        ordinary stack variables.
      * a direct `call` to `__asan_set_shadow_*` / `__asan_unpoison_stack_memory`.
    """
    from capstone.x86 import (X86_OP_IMM, X86_OP_MEM, X86_REG_RSP, X86_REG_RBP,
                              X86_REG_ESP, X86_REG_EBP)

    if insn.mnemonic == "call":
        ops = insn.operands
        return (len(ops) == 1 and ops[0].type == X86_OP_IMM
                and ops[0].imm in shadow_fns)

    if not insn.mnemonic.startswith("mov"):
        return False
    ops = insn.operands
    if len(ops) != 2 or ops[0].type != X86_OP_MEM or ops[1].type != X86_OP_IMM:
        return False
    mem = ops[0].mem
    if mem.index != 0 or mem.base in (X86_REG_RSP, X86_REG_RBP,
                                      X86_REG_ESP, X86_REG_EBP):
        return False
    size = ops[0].size
    if size not in (1, 2, 4, 8):
        return False
    imm = ops[1].imm & ((1 << (8 * size)) - 1)
    return all((imm >> (8 * i)) & 0xFF in _ASAN_SHADOW_BYTES
               for i in range(size))


def advance_past_asan_lifetime(
    binary_path: str, segments: List[dict], elfclass: int,
    patch_addr: int, limit_addr: int, shadow_fns: Dict[int, str],
    max_insns: int = 8,
) -> int:
    """Return the first address at/after `patch_addr` that is real program code,
    stepping over any leading ASAN scope bookkeeping.

    A null-check patch turns into "jump from `patch_addr` to `skip_target`", so
    every instruction in between is bypassed when the check fails. When the
    guarded statement is a declaration, its *first* instruction is the ASAN
    store that brings the new variable into scope (shadow f8 -> 00/04). Skipping
    that leaves the variable poisoned, and the next read of it aborts with a
    bogus `stack-use-after-scope` — bogus because the variable is merely
    uninitialised, which is exactly what the source-level equivalent
    (`int h; if (cond) h = ...;`) would produce.

    Starting the jump *after* the bookkeeping keeps ASAN's shadow consistent
    while still skipping the statement, and costs no detection ability (unlike
    building the target with -fno-sanitize-address-use-after-scope).

    Never advances to or past `limit_addr` (the skip target): a site whose whole
    range is bookkeeping is left alone.
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

    md = Cs(CS_ARCH_X86, CS_MODE_64 if elfclass == 64 else CS_MODE_32)
    md.detail = True

    off = _va_to_file_offset(segments, patch_addr)
    if off is None or limit_addr <= patch_addr:
        return patch_addr
    span = min(limit_addr - patch_addr, 16 * max_insns)
    with open(binary_path, "rb") as f:
        f.seek(off)
        code = f.read(span)

    cur = patch_addr
    for insn in md.disasm(code, patch_addr):
        if cur + insn.size >= limit_addr or not _is_asan_lifetime_insn(
                insn, shadow_fns):
            break
        cur += insn.size
        if cur - patch_addr > 16 * max_insns:
            break
    return cur


def _next_row_addr(idx: DwarfLineIndex, src_file: str, func_range: Tuple[int, int],
                   addr: int, is_cold=None) -> Optional[int]:
    """The lowest address the line table records after `addr`, within the function.

    That is where the code of the next statement begins, so it bounds the instructions belonging
    to the statement that starts at `addr`."""
    later = [a for a, _ln, _col, _generated in _located_addrs(idx, src_file, func_range, is_cold)
             if a > addr]
    return min(later) if later else None


def last_insn_of_statement(
    binary_path: str, segments: List[dict], elfclass: int,
    patch_addr: int, limit_addr: int, max_insns: int = 64,
) -> Tuple[Optional[int], Optional[str]]:
    """Address of the last instruction in [patch_addr, limit_addr), and its mnemonic.

    An insert-after site has to run its expression once the statement is done, and e9patch runs it
    right after the one instruction it displaces -- so that instruction has to be the statement's
    last, not its first. The line table only marks where a statement *starts* (and on an ASAN build
    the marked instruction is often just the shadow check, with the access itself following it), so
    the end has to be found by decoding forward to where the next statement begins.

    Returns (None, None) when the range cannot be decoded, leaving the caller with the
    line-table address it already had.
    """
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    except ImportError:
        return None, None

    if limit_addr <= patch_addr:
        return None, None
    off = _va_to_file_offset(segments, patch_addr)
    if off is None:
        return None, None
    span = limit_addr - patch_addr
    if span > 16 * max_insns:
        # A statement this long is not one the line table bounded for us; leave it alone.
        return None, None
    with open(binary_path, "rb") as f:
        f.seek(off)
        code = f.read(span)

    md = Cs(CS_ARCH_X86, CS_MODE_64 if elfclass == 64 else CS_MODE_32)
    last_addr: Optional[int] = None
    last_mnemonic: Optional[str] = None
    for insn in md.disasm(code, patch_addr):
        if insn.address + insn.size > limit_addr:
            break
        last_addr, last_mnemonic = insn.address, insn.mnemonic
    return last_addr, last_mnemonic


# Instructions after which the next instruction may not run: an unconditional transfer never comes
# back, and a conditional one skips what follows whenever it is taken. A `call` is not one of them --
# it returns, so displacing it runs the callee and then the expression.
_NEVER_FALLS_THROUGH = ("ud2", "hlt")
# Prefixes covering a whole family, so the width suffixes capstone appends (`retq`, `jmpq`, `iretd`)
# are matched too. No fall-through mnemonic starts with any of these.
_TRANSFER_PREFIXES = ("j", "ret", "iret", "loop")


def _leaves_the_path(mnemonic: Optional[str]) -> bool:
    """Whether the instruction after this one is not reliably reached.

    An insert-after site displaces one instruction and runs the expression behind it, so a statement
    ending in a transfer cannot carry one: the expression would never run (an unconditional jump or a
    return) or only run when a branch is not taken (a conditional jump, `loop`).
    """
    if mnemonic is None:
        return False
    name = mnemonic.lower()
    return (name in _NEVER_FALLS_THROUGH
            or name.startswith(_TRANSFER_PREFIXES))


# ── Register state at the skip target ────────────────────────────────────────
# A wrap disables its statement by jumping from patch_addr to skip_target, and $insert_if
# restores every register first, so the code at skip_target runs with the register state of
# patch_addr. That is only equivalent to "the statement did not run" while the skipped range
# holds nothing but the statement's own instructions. It often does not: the compiler hoists
# the *next* statement's operand loads into the range, and they come out of the line table as
# line-0 rows, so they are neither in range (they are excluded as generated code) nor past it.
#
# gpac-42537014 disabled `solved_template[last_num+1] = 0;` and landed on
#     mov rcx,[rsp+0x7f8]   <- line 0, inside the skipped range, feeds the next statement
#     mov rdx,[rsp+0x138]   <- line 0, feeds this statement's store
#     movb $0x0,(rdx)       <- the statement, end_addr
#     mov rcx,(rcx)         <- skip_target
# with %rcx still holding what it held at patch_addr (10), and the load faulted on address 10.
#
# Re-running the skipped load right before the jump fixes that: without the skip the range
# would have written the register anyway, so replaying its last definition can only bring the
# state closer to the un-skipped one, never further from it.

# Bases a replayed memory operand may use: rsp is restored by $RSTOR_RSP before the jump and
# rbp is callee-saved, so both hold their patch_addr values there.
_REPLAY_BASES = ("rsp", "rbp")
# Cap on replayed bytes. The `jrcxz .Lskip` in $insert_if reaches over the skip path with a
# rel8, which today spans 21 bytes; 64 more stays well inside the 127-byte reach.
_REPLAY_MAX_BYTES = 64
_LIVE_SCAN_INSNS = 64          # how far past skip_target to look for uses
_ANALYSIS_MAX_BYTES = 4096     # ranges bigger than this are left alone (unanalysable)
# Registers a call may read without the read being visible in the instruction: the SysV
# argument registers (al carries the vararg count, so rax is in).
_SYSV_ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax")


def _build_reg_family() -> Dict[str, str]:
    """Sub-register name -> its 64-bit register, so `eax` and `al` count as writes to `rax`."""
    fams = {
        "rax": ("eax", "ax", "al", "ah"), "rbx": ("ebx", "bx", "bl", "bh"),
        "rcx": ("ecx", "cx", "cl", "ch"), "rdx": ("edx", "dx", "dl", "dh"),
        "rsi": ("esi", "si", "sil"), "rdi": ("edi", "di", "dil"),
        "rbp": ("ebp", "bp", "bpl"), "rsp": ("esp", "sp", "spl"),
    }
    for n in range(8, 16):
        fams[f"r{n}"] = (f"r{n}d", f"r{n}w", f"r{n}b")
    out: Dict[str, str] = {}
    for canon, subs in fams.items():
        out[canon] = canon
        for sub in subs:
            out[sub] = canon
    return out


_REG_FAMILY = _build_reg_family()


def _canon_reg(name: str) -> str:
    return _REG_FAMILY.get(name, name)


# Zeroing idioms: `op reg,reg` where both operands are the same register produces 0 whatever the
# register held, so it defines that register without reading it. The encoding says otherwise --
# XOR/SUB are read-modify-write, and capstone reports the operand roles it is given -- but every
# compiler emits these to materialize a zero (they are shorter than `mov $0,reg` and the hardware
# recognizes them as dependency breakers), at every optimization level including -O0. Counting the
# apparent read as real made a register look live at a skip target when it was not: ffmpeg-42506577
# lost the one hunk that fixed the bug to `xor %r8d,%r8d` sitting at the landing address.
_ZEROING_MNEMONICS = ("xor", "sub")


def _is_zeroing_idiom(insn) -> bool:
    """Whether this is `op reg,reg` on one and the same register, i.e. a pure definition of it."""
    if insn.mnemonic not in _ZEROING_MNEMONICS:
        return False
    try:
        operands = insn.operands
    except Exception:                      # detail unavailable for this instruction
        return False
    if len(operands) != 2:
        return False
    # capstone: 1 == X86_OP_REG, compared numerically so this needs no capstone import here
    if any(op.type != 1 for op in operands):
        return False
    return operands[0].reg == operands[1].reg


def _reg_access(md, insn) -> Tuple[Set[str], Set[str]]:
    """(read, written) canonical register names for one instruction."""
    try:
        rd, wr = insn.regs_access()
    except Exception:                      # detail unavailable for this instruction
        return set(), set()
    reads = {_canon_reg(md.reg_name(r)) for r in rd}
    writes = {_canon_reg(md.reg_name(r)) for r in wr}
    if _is_zeroing_idiom(insn):
        # The operand is written, never read: drop it from the reads, keeping any other read
        # (the flags) as it is
        reads -= {_canon_reg(md.reg_name(insn.operands[0].reg))}
    return reads, writes


def _decode_range(binary_path: str, segments: List[dict], elfclass: int,
                  lo: int, span: int):
    """Decode `span` bytes from VA `lo` with operand detail. [] if unmappable."""
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    except ImportError:
        return []
    off = _va_to_file_offset(segments, lo)
    if off is None or span <= 0:
        return []
    with open(binary_path, "rb") as f:
        f.seek(off)
        code = f.read(span)
    md = Cs(CS_ARCH_X86, CS_MODE_64 if elfclass == 64 else CS_MODE_32)
    md.detail = True
    return md, list(md.disasm(code, lo))


def _branch_target(insn) -> Optional[int]:
    """Target of a branch, or None when it is indirect (unknown)."""
    from capstone.x86 import X86_OP_IMM
    ops = insn.operands
    if len(ops) == 1 and ops[0].type == X86_OP_IMM:
        return ops[0].imm
    return None


def _is_replayable(insn, sp_stable: bool, bp_stable: bool) -> bool:
    """Whether re-running this instruction outside its original position is equivalent.

    Only a full-width load or constant is: `mov reg,[rsp/rbp+disp]`, `mov reg,imm`,
    `lea reg,[rsp/rbp+disp]`. Those read nothing but a stable base, write no flags, and define
    the whole 64-bit register (a 32-bit destination zero-extends), so replaying one cannot
    depend on -- or disturb -- anything else. A narrower or read-modify-write destination would
    mix in the register's current contents, and a rip-relative operand would read the
    trampoline instead of the code.
    """
    from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM

    if insn.mnemonic not in ("mov", "movabs", "lea"):
        return False
    ops = insn.operands
    if len(ops) != 2 or ops[0].type != X86_OP_REG or ops[0].size not in (4, 8):
        return False
    if insn.size > 12:
        return False
    src = ops[1]
    if src.type == X86_OP_IMM:
        return insn.mnemonic != "lea"
    if src.type != X86_OP_MEM:
        return False
    mem = src.mem
    if mem.index != 0 or mem.segment != 0 or mem.base == 0:
        return False
    base = _canon_reg(insn.reg_name(mem.base))
    if base not in _REPLAY_BASES:
        return False
    return sp_stable if base == "rsp" else bp_stable


def plan_skip_replay(
    binary_path: str, segments: List[dict], elfclass: int,
    patch_addr: int, skip_target: int,
) -> Tuple[Tuple[int, ...], Tuple[str, ...]]:
    """Plan the register repair for a wrap's skip.

    Returns (replay_bytes, unrepairable), where `replay_bytes` are instruction bytes to run
    just before jumping to `skip_target` and `unrepairable` names the registers the code at
    `skip_target` reads, the skipped range defines, and no replay can restore. A site with a
    non-empty `unrepairable` cannot be disabled correctly and is dropped by the caller --
    patching it anyway lands on code reading a register that holds an unrelated value.

    ((), ()) means the plain jump is already correct, which is the common case: nothing is
    emitted and the skip path keeps its current cost.
    """
    if skip_target <= patch_addr or skip_target - patch_addr > _ANALYSIS_MAX_BYTES:
        return (), ()
    decoded = _decode_range(binary_path, segments, elfclass,
                            patch_addr, skip_target - patch_addr)
    if not decoded:
        return (), ()
    md, insns = decoded
    insns = [i for i in insns if i.address + i.size <= skip_target]
    if not insns:
        return (), ()

    # rsp/rbp have to be unchanged across the range for a base+disp replay to address the same
    # slot. A call/ret pair leaves both as they were, anything else (push, pop, sub rsp, ...)
    # does not.
    sp_stable = bp_stable = True
    written_in_range: Set[str] = set()
    for insn in insns:
        _, wr = _reg_access(md, insn)
        written_in_range |= wr
        if insn.mnemonic.startswith(("call", "ret")):
            continue
        if "rsp" in wr:
            sp_stable = False
        if "rbp" in wr:
            bp_stable = False

    # Branches inside the range: one that jumps over an instruction means that instruction is
    # not guaranteed to run, so its definition must not be replayed as if it had.
    branches: List[Tuple[int, float]] = []
    for insn in insns:
        if not _leaves_the_path(insn.mnemonic):
            continue
        target = _branch_target(insn)
        branches.append((insn.address,
                         float("inf") if target is None else float(target)))

    def guaranteed(addr: int) -> bool:
        return not any(b < addr < t for b, t in branches)

    # Last guaranteed, replayable definition of each register in the range.
    defs: Dict[str, object] = {}
    for insn in insns:
        _, wr = _reg_access(md, insn)
        wr -= {"rsp", "rip", "eflags"}
        if not wr or not guaranteed(insn.address):
            continue
        if not _is_replayable(insn, sp_stable, bp_stable):
            for reg in wr:                 # a definition we cannot reproduce
                defs.pop(reg, None)
            continue
        for reg in wr:
            defs[reg] = insn

    # Registers the code at skip_target reads before writing. Scanning the fall-through of a
    # conditional branch only sees one path, but every read it does see is a real one.
    decoded_after = _decode_range(binary_path, segments, elfclass, skip_target,
                                  16 * _LIVE_SCAN_INSNS)
    md2, after = decoded_after if decoded_after else (md, [])
    live: List[str] = []                   # explicit reads: a wrong value here is a real bug
    assumed: List[str] = []                # call arguments: read without the read being visible
    written_after: Set[str] = set()
    for insn in after[:_LIVE_SCAN_INSNS]:
        rd, wr = _reg_access(md2, insn)
        is_call = insn.mnemonic.startswith("call")
        for reg in sorted(rd):
            if (reg in written_in_range and reg not in written_after
                    and reg not in ("rsp", "rip", "eflags") and reg not in live):
                live.append(reg)
        if is_call:
            for reg in _SYSV_ARG_REGS:
                if (reg in written_in_range and reg not in written_after
                        and reg not in live and reg not in assumed):
                    assumed.append(reg)
        written_after |= wr
        if is_call or _leaves_the_path(insn.mnemonic):
            break

    unrepairable = tuple(reg for reg in live if reg not in defs)
    chosen = {defs[reg].address: defs[reg] for reg in live if reg in defs}
    size = sum(i.size for i in chosen.values())
    for reg in assumed:                    # only while there is room; never forces a drop
        insn = defs.get(reg)
        if insn is None or insn.address in chosen or size + insn.size > _REPLAY_MAX_BYTES:
            continue
        chosen[insn.address] = insn
        size += insn.size
    if size > _REPLAY_MAX_BYTES:
        # More state to restore than the skip path has room for; the jump cannot be made
        # correct, so report every live register as unrepairable rather than emit half of it.
        return (), tuple(live)

    replay: List[int] = []
    for addr in sorted(chosen):            # program order; each is independent anyway
        replay.extend(chosen[addr].bytes)
    return tuple(replay), unrepairable


def resolve_patch_points(
    specs: List[PatchSpec],
    functions: Dict[str, List[Tuple[int, int]]],
    line_idx: DwarfLineIndex,
    jmp_ids: Dict[str, Dict[int, int]],
    binary_path: str,
) -> List[PatchPoint]:
    """Resolve every patch spec to a PatchPoint of integer addresses.

    Specs whose function is unknown or whose range can't be resolved are
    warned about and dropped.
    """
    # Placeholder jmp_id for sites missing from jmp_ids.json: max known + 1 so
    # it can't collide with a real id (jmp_id is uint64_t on the runtime side).
    _all_jmp_ids = [v for fmap in jmp_ids.values() for v in fmap.values()]
    placeholder_jmp_id = 123456789 # Placeholder for non-exist jmp id

    # For nudging a null-check site past ASAN's scope bookkeeping (see
    # advance_past_asan_lifetime). On an uninstrumented binary shadow_fns is
    # empty and no site starts with a shadow store, so this is a no-op.
    segments, elfclass = _pt_load_segments(binary_path)
    shadow_fns = asan_shadow_fn_addrs(functions)
    # ASAN's out-of-line failure blocks carry line-table rows of the statements they report on,
    # so they have to be kept out of the resolution entirely (see asan_report_stub_filter). On an
    # uninstrumented binary there are no reporters and this is a no-op.
    is_cold = asan_report_stub_filter(binary_path, segments, elfclass,
                                      asan_report_fn_addrs(functions))

    points: List[PatchPoint] = []
    for spec in specs:
        func_range = function_va_range(
            functions, line_idx, spec.function, spec.start.file
        )
        if func_range is None:
            print(f"warning: function {spec.function!r} (in {spec.start.file}) "
                  f"not found in symbol table; skipping patch {spec.id}.",
                  file=sys.stderr)
            continue
        addrs = resolve_range_addrs(line_idx, spec, func_range, is_cold)
        if addrs is None:
            print(f"warning: cannot resolve range {spec.start}..{spec.end} "
                  f"within {spec.function}; skipping patch {spec.id}.",
                  file=sys.stderr)
            continue
        in_range_addrs, skip_target = addrs
        # Wrap-vs-insert is decided by the config template, not the span. An INSERT_EXPR
        # (pure insertion) must never emit the [patch_addr, skip_target) skip -- on an
        # ASAN binary a statement's instructions scatter across the function, so the span
        # bloats and skipping it swallows unrelated code (an infinite loop). The span still
        # tells us whether to insert *before* (non-zero span) or *after* (zero-width).
        is_wrap = (spec.template == Template.INSERT_NOT_NULL_CHECKER
                   if spec.template is not None else spec.start != spec.end)
        insert_before = spec.start != spec.end
        if is_wrap and skip_target is None:
            # A wrap with no forward fall-through past the statement cannot be disabled
            # safely (nowhere to jump on a failed check). Skip it rather than emit a patch
            # with a `None` skip target (a broken command, or a backward jump into a loop).
            print(f"warning: patch {spec.id}: no forward skip target past {spec.end}; "
                  f"cannot disable the statement, skipping.", file=sys.stderr)
            continue
        if in_range_addrs:
            patch_addr = min(in_range_addrs)
            end_addr = max(in_range_addrs)
        else:
            # No DWARF entry matched the range directly; use the next address
            # as the patch site (insert-only sites between DWARF line entries).
            patch_addr = end_addr = skip_target

        # An insert-after site (zero-width span) has its expression run right after the one
        # instruction e9patch displaces, so that instruction has to be the *last* of the
        # statement. The line table gives its first one, so decode forward to where the next
        # statement starts and take the instruction before that.
        if not insert_before:
            limit = _next_row_addr(line_idx, spec.start.file, func_range, patch_addr,
                                   is_cold)
            if limit is None:
                print(f"warning: patch {spec.id}: nothing follows {spec.start} in the line "
                      f"table; inserting after its first instruction only.", file=sys.stderr)
            else:
                last_addr, mnemonic = last_insn_of_statement(
                    binary_path, segments, elfclass, patch_addr, limit)
                if last_addr is None:
                    print(f"warning: patch {spec.id}: could not bound the statement at "
                          f"0x{patch_addr:x}..0x{limit:x} (undecodable, or too long to be one "
                          f"statement); inserting after its first instruction only.",
                          file=sys.stderr)
                elif _leaves_the_path(mnemonic):
                    # Displacing it would run the transfer first, and the expression never
                    # after it. Better to say so than to emit a patch that cannot fire.
                    print(f"warning: patch {spec.id}: the statement at {spec.start} ends in "
                          f"`{mnemonic}` at 0x{last_addr:x}, which does not fall through; "
                          f"cannot insert after it, skipping.", file=sys.stderr)
                    continue
                elif last_addr != patch_addr:
                    print(f"note: patch {spec.id}: insert-after site "
                          f"0x{patch_addr:x} -> 0x{last_addr:x}, the last instruction "
                          f"(`{mnemonic}`) of the statement.")
                    patch_addr = end_addr = last_addr

        # A wrap skips [patch_addr, skip_target) when the check fails. If the statement
        # opens with ASAN scope bookkeeping, let that run first so the skip cannot leave a
        # live variable poisoned.
        skip_replay: Tuple[int, ...] = ()
        if is_wrap and skip_target is not None:
            moved = advance_past_asan_lifetime(
                binary_path, segments, elfclass, patch_addr, skip_target,
                shadow_fns,
            )
            if moved != patch_addr:
                print(f"note: patch {spec.id}: moving patch site "
                      f"0x{patch_addr:x} -> 0x{moved:x} to keep ASAN scope "
                      f"bookkeeping out of the skipped range.")
                patch_addr = moved
                end_addr = max(end_addr, patch_addr)

            # The skipped range can hold loads the code at skip_target needs (see
            # plan_skip_replay); re-run them before the jump, or drop the site when they
            # cannot be re-run.
            skip_replay, unrepairable = plan_skip_replay(
                binary_path, segments, elfclass, patch_addr, skip_target)
            if unrepairable:
                print(f"warning: patch {spec.id}: the code at 0x{skip_target:x} reads "
                      f"{', '.join(unrepairable)}, which 0x{patch_addr:x}..0x{skip_target:x} "
                      f"defines in a way the skip cannot reproduce; disabling the statement "
                      f"would land on a stale register, skipping.", file=sys.stderr)
                continue
            if skip_replay:
                print(f"note: patch {spec.id}: replaying {len(skip_replay)} byte(s) of loads "
                      f"from the skipped range before jumping to 0x{skip_target:x}.")

        file_ids = jmp_ids.get(spec.start.file, {})
        jmp_id = file_ids.get(spec.start.line)
        if jmp_id is None:
            print(f"warning: no jmp_id for {spec.start.file}:{spec.start.line}; "
                  f"using placeholder {placeholder_jmp_id} for patch {spec.id}.",
                  file=sys.stderr)
            jmp_id = placeholder_jmp_id

        points.append(PatchPoint(
            id=spec.id,
            function=spec.function,
            jmp_id=jmp_id,
            patch_addr=patch_addr,
            end_addr=end_addr,
            skip_target=skip_target if is_wrap else None,
            has_null_check=is_wrap,
            insert_before=insert_before,
            skip_replay=skip_replay,
        ))
    return points


def call_e9patch(points: List[PatchPoint], work_dir:str, binary_path:str, output_dir: str, verbose = False) -> None:
    print("Calling e9patch with resolved patch points...")
    binary = os.path.basename(binary_path)
    
    # --option forwards a flag to the e9patch backend; these keep the loader and
    # trampolines out of a sanitizer's shadow map (see the layout notes below).
    cmd = ('e9tool -O0 '
           f'--option --mem-ub=0x{E9_MEM_UB:x} '
           f'--option --loader-base=0x{E9_LOADER_BASE:x} ')
    for i,p in enumerate(points):
        # Matcher
        matcher = f'addr == 0x{p.patch_addr:x}'
        cmd += f"-M '{matcher}' "

        # Patch
        if p.has_null_check:
            # Wrap: insert the expr before the statement, then skip it on a failed check.
            patch = f'before patch_insert_expr({p.id}, "{p.function}", {p.jmp_id})@/usr/local/bin/metapro-e9patch'
            cmd += f"-P '{patch}' "
            patch = f'before if patch_insert_if_wrapper({p.id}, "{p.function}", {p.skip_target})@/usr/local/bin/metapro-e9patch goto'
            cmd += f"-P '{patch}' "
        elif p.insert_before:
            # Pure insertion before the statement (no skip).
            patch = f'before patch_insert_expr({p.id}, "{p.function}", {p.jmp_id})@/usr/local/bin/metapro-e9patch'
            cmd += f"-P '{patch}' "
        else:
            # Pure insertion after the statement.
            patch = f'after patch_insert_expr({p.id}, "{p.function}", {p.jmp_id})@/usr/local/bin/metapro-e9patch'
            cmd += f"-P '{patch}' "
        
    output_binary = os.path.join(output_dir, f'{binary}.inst')
    cmd += f"-o {output_binary} "
    if verbose:
        cmd += "--debug "
    cmd += binary_path

    print(f"Running command: {cmd}")
    result = sp.run(cmd, capture_output=True, text=True, shell=True)

    if result.returncode != 0:
        print(f"Error running e9tool for patch id {p.id}: {result.stderr}", file=sys.stderr)
        return False

    print(f"Patched binary written to {output_binary}")
    return True


# ── Address-space layout (sanitizer-compatible) ──────────────────────────────
# Everything e9patch adds to the target has to fit in the address space that a
# sanitizer runtime leaves alone. On x86_64 Linux, ASAN reserves one contiguous
# span for its shadow map at process startup:
#
#   low shadow  0x00007fff7000 - 0x00008fff6fff
#   shadow gap  0x00008fff7000 - 0x02008fff6fff   (mprotect'd, but still claimed)
#   high shadow 0x02008fff7000 - 0x10007fff7fff
#
# ASAN's InitializeShadowMemory() requires that whole span to be free, gap
# included: any pre-existing mapping inside it aborts the process with
# "Shadow memory range interleaves with an existing memory mapping". That check
# runs from an init_array constructor, i.e. before the e9patch loader at the ELF
# entry point ever executes, so it sees the PT_LOAD segments e9patch adds.
#
# e9patch's default --loader-base (0x20e9e9000) lands in the shadow gap, which
# is why an unpatched-for-sanitizers .inst binary dies at startup. Everything we
# add must therefore stay in "low mem", below ASAN_SHADOW_BEG. (Above the shadow
# is not an option: --loader-base only accepts 0x0..0x800000000.)
ASAN_SHADOW_BEG = 0x7FFF7000

# e9patch parks the loaded wrapper binary at this base VA. It is
# target-independent (the region is conventionally free: above the target's
# segments and brk heap, below ASAN's shadow), so the reserve records derived
# from it depend only on the wrapper binary — the same for every target.
E9_RESERVE_BASE = 0x70000000

# Upper bound for trampoline placement (--mem-ub), keeping trampolines clear of
# the shadow. Trampolines are normally allocated in the pages around the target's
# own segments, so this is just a hard ceiling and costs no patch coverage.
# Do NOT also set --mem-lb: the allocator relies on the free space *below* the
# target (a non-PIE binary starts at 0x400000), and fencing it off drops the
# patch success rate substantially (~82% vs 100% on our test targets).
E9_MEM_UB = 0x77000000

# Base VA for the e9patch loader (--loader-base), which becomes the patched
# binary's entry point. e9patch requires it above every reserve region and above
# --mem-ub, so it goes between E9_MEM_UB and ASAN_SHADOW_BEG. The loader is a
# single ~4KB page, so the remaining headroom is ample.
E9_LOADER_BASE = 0x78000000

assert E9_RESERVE_BASE < E9_MEM_UB < E9_LOADER_BASE < ASAN_SHADOW_BEG


# ── e9patch low-level JSON-RPC builder (no e9tool) ───────────────────────────

# e9tool registers every instruction within +/- this many bytes of a patch site
# (INT8_MAX + 2 + 15) so e9patch knows which bytes it may displace/pun when
# inserting the jump, and can resolve $instr / $BREAK in the trampoline.
INSTR_WINDOW = 127 + 2 + 15


def _pt_load_segments(binary_path: str) -> Tuple[List[dict], int]:
    """Return (`PT_LOAD` segments, ELF class) for `binary_path`.

    Each segment dict carries vaddr/filesz/memsz/offset/flags plus the raw file
    `data`. Used both to load the wrapper (reserve) and to map VAs to file
    offsets in the target (e9patch's offsets are file offsets, not VAs)."""
    from elftools.elf.elffile import ELFFile

    segs: List[dict] = []
    with open(binary_path, "rb") as f:
        elf = ELFFile(f)
        elfclass = elf.elfclass
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            segs.append({
                "vaddr": seg["p_vaddr"],
                "filesz": seg["p_filesz"],
                "memsz": seg["p_memsz"],
                "offset": seg["p_offset"],
                "flags": seg["p_flags"],
                "data": seg.data(),
            })
    return segs, elfclass


def _va_to_file_offset(segments: List[dict], va: int) -> Optional[int]:
    """Map a virtual address to its file offset using the `PT_LOAD` segments.
    e9patch's patch/instruction `offset` fields are file offsets."""
    for s in segments:
        lo = s["vaddr"]
        if lo <= va < lo + s["filesz"]:
            return s["offset"] + (va - lo)
    return None


def _seg_protection(flags: int) -> str:
    """ELF p_flags (R=4 W=2 X=1) -> e9patch 'rwx' protection string."""
    return (("r" if flags & 0x4 else "-")
            + ("w" if flags & 0x2 else "-")
            + ("x" if flags & 0x1 else "-"))


def build_reserve_records(base: int, init_va: int) -> List[dict]:
    """Build the `reserve` params that map the wrapper binary's PT_LOAD segments
    into the target's address space at `base`.

    This is what e9tool's `@wrapper` syntax does implicitly. The result depends
    only on the wrapper (not the target), so it is identical for every binary we
    patch; we still rebuild it from the wrapper ELF each run so a wrapper rebuild
    cannot silently desync the bytes from the call addresses (which are
    `base + symbol_va`). The executable segment additionally carries `init`
    (= base + init_va), the routine the e9patch loader calls once to run the
    wrapper's constructors (dlopen the runtime, dlsym exec/check funcs)."""
    segs, _ = _pt_load_segments(WRAPPER_BINARY)
    params_list: List[dict] = []
    for s in segs:
        data = bytearray(s["data"])                       # file bytes (filesz)
        data.extend(b"\x00" * (s["memsz"] - len(data)))   # zero-pad bss to memsz
        params: dict = {
            "address": base + s["vaddr"],
            "protection": _seg_protection(s["flags"]),
            "bytes": list(data),
        }
        if s["flags"] & 0x1:                              # executable segment
            params["init"] = base + init_va
        params_list.append(params)
    return params_list


def build_instruction_records(
    binary_path: str, segments: List[dict], elfclass: int,
    func_range: Optional[Tuple[int, int]], patch_addr: int,
) -> List[dict]:
    """Build `instruction` params for every instruction within +/- INSTR_WINDOW
    bytes of `patch_addr`, matching what e9tool emits.

    Boundaries are obtained by disassembling forward from a known instruction
    boundary — the enclosing function's low VA, falling back to `patch_addr`
    itself — so we never start mid-instruction (x86 has no reliable backward
    disassembly). Returns a list of {address, length, offset} params."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

    md = Cs(CS_ARCH_X86, CS_MODE_64 if elfclass == 64 else CS_MODE_32)

    win_lo = patch_addr - INSTR_WINDOW
    win_hi = patch_addr + INSTR_WINDOW
    # Anchor at a guaranteed boundary at/below the patch (function entry); if
    # unknown, fall back to the patch itself (loses the [win_lo, patch) window).
    start_va = (func_range[0]
                if func_range and func_range[0] <= patch_addr
                else patch_addr)

    start_off = _va_to_file_offset(segments, start_va)
    if start_off is None:
        return []
    with open(binary_path, "rb") as f:
        f.seek(start_off)
        code = f.read((win_hi + 16) - start_va)  # +16: slack for the last insn

    records: List[dict] = []
    for insn in md.disasm(code, start_va):
        if insn.address > win_hi:
            break
        if insn.address < win_lo:
            continue
        off = _va_to_file_offset(segments, insn.address)
        if off is None:
            continue
        records.append({
            "address": f"0x{insn.address:x}",
            "length": insn.size,
            "offset": off,
        })
    return records


def call_e9patch_without_e9tool(points: List[PatchPoint], work_dir:str, binary_path:str, output_dir: str, verbose = False) -> None:
    print("Calling e9patch without e9tool with resolved patch points...")
    binary = os.path.basename(binary_path)
    output_binary = os.path.join(output_dir, f'{binary}.inst')

    # Wrapper layout: the call targets and the init routine, rebased to where the
    # reserve records below load the wrapper (E9_RESERVE_BASE). load_function_ranges
    # gives the file VAs; the wrapper is position-independent, so the reserve
    # records and these addresses must share the same base.
    wrapper_ranges = load_function_ranges(WRAPPER_BINARY)
    def _wrapper_va(name: str) -> int:
        rs = wrapper_ranges.get(name)
        if not rs:
            raise ValueError(
                f"wrapper symbol {name!r} not found in {WRAPPER_BINARY!r} "
                f"(stripped, or wrong binary?)"
            )
        return rs[0][0]
    expr_fn = E9_RESERVE_BASE + _wrapper_va("patch_insert_expr")
    if_fn = E9_RESERVE_BASE + _wrapper_va("patch_insert_if_wrapper")
    init_va = _wrapper_va("init")

    # Target segments: VA -> file-offset mapping (for patch/instruction offsets)
    # and the byte source for the instruction-window disassembly. Function ranges
    # anchor that disassembly at an instruction boundary.
    segments, elfclass = _pt_load_segments(binary_path)
    func_ranges = load_function_ranges(binary_path)

    # JSON-RPC records, one per line. Ids are just RPC correlation tags.
    json_rpc_inputs: List[str] = []
    next_id = 0
    def emit(method: str, params: dict) -> None:
        nonlocal next_id
        json_rpc_inputs.append(json.dumps(
            {"jsonrpc": "2.0", "method": method, "params": params, "id": next_id}))
        next_id += 1

    # 1. Open the target binary.
    emit("binary", {"version": "1.0.0", "filename": binary_path, "mode": "elf.exe"})

    # 2. Options: disable the e9patch optimizations that reorder/merge code so the
    #    fixed trampoline layout is emitted verbatim (mirrors e9tool's output), and
    #    pin the loader/trampolines to low mem so they cannot collide with a
    #    sanitizer's shadow map (see the layout notes above).
    #
    #    This record must come *after* the "binary" record above: e9patch rejects
    #    any message that precedes "binary".
    emit("options", {"argv": [
        "-Oprologue=0", "-Oprologue-size=0", "-Oepilogue=0", "-Oepilogue-size=0",
        "-Opeephole=false", "-Oorder=false", "-Oscratch-stack=false",
        "--mem-granularity=128",
        f"--mem-ub=0x{E9_MEM_UB:x}",
        f"--loader-base=0x{E9_LOADER_BASE:x}",
    ]})

    # 3. Reserve: load the wrapper binary's segments into the target's address
    #    space at E9_RESERVE_BASE (target-independent; built from the wrapper ELF).
    for params in build_reserve_records(E9_RESERVE_BASE, init_va):
        emit("reserve", params)

    # 4. Trampolines (e9tool-style decomposition, with descriptive names):
    #    $insert_expr / $insert_if are the per-call sequences; $tmp_before and
    #    $tmp_after are the parent trampolines placed at the site. All save/
    #    restore the caller-saved regs + flags so the displaced original
    #    instruction ($instr) runs as if untouched. rsp is first stepped past the
    #    SysV red zone (lea rsp,[rsp-0x4000]) and restored ($RSTOR_RSP) per call.
    emit("trampoline", {"name": "$insert_expr", "template": [
        72, 141, 164, 36, {"int32": -0x4000},  # lea rsp,[rsp-0x4000]
        81, 80, 15, 144, 192, 159, 80,         # push rcx; push rax; seto al; lahf; push rax(flags)
        65, 83, 65, 82, 65, 81, 65, 80, 82, 86, 87,  # push r11,r10,r9,r8,rdx,rsi,rdi
        "$ARGS@insert_expr",                   # mov rdi,id; lea rsi,func; mov edx,jmpId
        232, "$FUNC@insert_expr",              # call patch_insert_expr (e8 rel32)
        "$RSTOR@insert_expr",                  # (empty)
        95, 94, 90, 65, 88, 65, 89, 65, 90, 65, 91,  # pop rdi,rsi,rdx,r8,r9,r10,r11
        88, 4, 127, 158, 88, 89,               # pop rax(flags); add al,0x7f; sahf; pop rax; pop rcx
        "$RSTOR_RSP@insert_expr",              # lea rsp,[rsp+0x4000]
    ]})
    emit("trampoline", {"name": "$insert_if", "template": [
        72, 141, 164, 36, {"int32": -0x4000},  # lea rsp,[rsp-0x4000]
        81, 80, 15, 144, 192, 159, 80,         # push rcx; push rax; seto al; lahf; push rax(flags)
        65, 83, 65, 82, 65, 81, 65, 80, 82, 86, 87,  # push r11,r10,r9,r8,rdx,rsi,rdi
        "$ARGS@insert_if",                     # mov rdi,id; lea rsi,func; movabs rdx,dest
        232, "$FUNC@insert_if",                # call patch_insert_if_wrapper (e8 rel32)
        "$RSTOR@insert_if",                    # (empty)
        72, 137, 193,                          # mov rcx, rax  (rax = goto target, 0 == continue)
        95, 94, 90, 65, 88, 65, 89, 65, 90, 65, 91,  # pop rdi,rsi,rdx,r8,r9,r10,r11
        88, 4, 127, 158, 88,                   # pop rax(flags); add al,0x7f; sahf; pop rax
        227, {"rel8": ".Lskip@insert_if"},     # jrcxz .Lskip  (continue if 0)
        100, 72, 137, 12, 37, {"int32": 64},   # mov fs:[0x40], rcx  (stash goto target)
        89,                                    # pop rcx  (restore original rcx)
        "$RSTOR_RSP@insert_if",                # lea rsp,[rsp+0x4000]
        # Loads the skipped range would have done for the code at the skip target (usually
        # empty; see plan_skip_replay). Placed last, with rsp and every register already back
        # to their original values, so the copied [rsp+disp] operands address the same slots.
        "$REPLAY@insert_if",
        100, 255, 36, 37, {"int32": 64},       # jmp fs:[0x40]  (goto skip target)
        ".Lskip@insert_if",
        89,                                    # pop rcx  (restore original rcx)
        "$RSTOR_RSP@insert_if",                # lea rsp,[rsp+0x4000]
    ]})
    # Parent for INSERT_NOT_NULL_CHECKER: expr + if-check before the statement.
    emit("trampoline", {"name": "$tmp_before", "template": [
        ".Ltrampoline",
        "$insert_expr", "$insert_if",
        "$instr", "$BREAK",                    # displaced original insn, then return
        "$DATA@insert_expr", "$DATA@insert_if",  # the func-name strings (lea targets)
    ]})
    # Parent for insert-only sites: expr called after the original statement.
    emit("trampoline", {"name": "$tmp_after", "template": [
        ".Ltrampoline",
        "$instr",
        "$insert_expr",
        "$BREAK",
        "$DATA@insert_expr",
    ]})
    # Parent for an INSERT_EXPR whose anchor spans a range (insert-before): expr called
    # before the original statement, with NO if-check / skip. Unlike $tmp_before this must
    # never skip the statement -- a pure insertion only adds code.
    emit("trampoline", {"name": "$tmp_before_noskip", "template": [
        ".Ltrampoline",
        "$insert_expr",
        "$instr", "$BREAK",
        "$DATA@insert_expr",
    ]})

    # Per-call metadata builders (bound per patch site). lea rsi reaches the
    # func-name string defined in $DATA via the rip-relative label.
    RSTOR_RSP = [72, 141, 164, 36, {"int32": 0x4000}]   # lea rsp,[rsp+0x4000]
    def args_expr(p: PatchPoint) -> List[object]:
        return [
            72, 199, 199, {"int32": p.id},                  # mov rdi, id
            72, 141, 53, {"rel32": ".Lstr@insert_expr"},    # lea rsi, [rip+func]
            186, {"int32": p.jmp_id},                       # mov edx, jmp_id
        ]
    def args_if(p: PatchPoint) -> List[object]:
        return [
            72, 199, 199, {"int32": p.id},                  # mov rdi, id
            72, 141, 53, {"rel32": ".Lstr@insert_if"},      # lea rsi, [rip+func]
            72, 186, {"int64": p.skip_target},              # movabs rdx, skip_target
        ]

    # e9patch requires patch sites in descending address order (largest first)
    # so patching high-VA sites keeps the offsets of lower, not-yet-emitted sites
    # valid.
    sorted_points = sorted(points, key=lambda p: p.patch_addr, reverse=True)

    # 5. Instruction windows, registered before the patches that reference them.
    #    Dedupe by file offset since adjacent sites' windows can overlap.
    instr_by_off: Dict[int, dict] = {}
    for p in sorted_points:
        ranges = func_ranges.get(p.function, [])
        func_range = next(
            ((lo, hi) for lo, hi in ranges if lo <= p.patch_addr < hi), None)
        for params in build_instruction_records(
                binary_path, segments, elfclass, func_range, p.patch_addr):
            instr_by_off[params["offset"]] = params
    for off in sorted(instr_by_off, reverse=True):
        emit("instruction", instr_by_off[off])

    # 6. Patches: bind a parent trampoline + per-site metadata at the site's file
    #    offset (NOT the VA — e9patch offsets are file offsets).
    for p in sorted_points:
        patch_off = _va_to_file_offset(segments, p.patch_addr)
        if patch_off is None:
            print(f"warning: cannot map patch addr 0x{p.patch_addr:x} to a file "
                  f"offset; skipping patch {p.id}.", file=sys.stderr)
            continue
        if p.has_null_check and p.skip_target is not None:
            metadata = {
                "$ARGS@insert_expr": args_expr(p),
                "$FUNC@insert_expr": [{"rel32": expr_fn}],   # &patch_insert_expr
                "$RSTOR@insert_expr": [],
                "$RSTOR_RSP@insert_expr": RSTOR_RSP,
                "$DATA@insert_expr": [".Lstr@insert_expr", {"string": p.function}],
                "$ARGS@insert_if": args_if(p),
                "$FUNC@insert_if": [{"rel32": if_fn}],       # &patch_insert_if_wrapper
                "$RSTOR@insert_if": [],
                "$RSTOR_RSP@insert_if": RSTOR_RSP,
                "$REPLAY@insert_if": list(p.skip_replay),
                "$DATA@insert_if": [".Lstr@insert_if", {"string": p.function}],
            }
            trampoline = "$tmp_before"
        else:
            # Pure insertion (INSERT_EXPR): expr only, no skip. A spanned anchor inserts
            # before ($tmp_before_noskip); a zero-width (insert-after) site inserts after.
            metadata = {
                "$ARGS@insert_expr": args_expr(p),
                "$FUNC@insert_expr": [{"rel32": expr_fn}],
                "$RSTOR@insert_expr": [],
                "$RSTOR_RSP@insert_expr": RSTOR_RSP,
                "$DATA@insert_expr": [".Lstr@insert_expr", {"string": p.function}],
            }
            trampoline = "$tmp_before_noskip" if p.insert_before else "$tmp_after"
        emit("patch", {"trampoline": trampoline, "metadata": metadata,
                       "offset": patch_off})

    # 7. Emit the patched binary (the emit `filename` is the output; e9patch's
    #    --output below only redirects its stdout/log).
    emit("emit", {"filename": output_binary, "format": "binary"})

    # Write JSON-RPC input to a file
    with open(os.path.join(work_dir, "e9patch_input.json"), "w") as f:
        for line in json_rpc_inputs:
            f.write(line + "\n")

    cmd = ['e9patch', '--input', os.path.join(work_dir, "e9patch_input.json"),
           '--output', os.path.join(output_dir, 'e9patch_output.log')]
    if verbose:
        cmd.append('--debug')
    res = sp.run(cmd, capture_output=True)
    if res.returncode != 0:
        print(f"Error running e9patch: {res.stderr.decode()}", file=sys.stderr)
        return False
    else:
        print(f"e9patch output written to {os.path.join(output_dir, 'e9patch_output.log')}")
        return True


# ── Main ─────────────────────────────────────────────────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser(
        description="resolve DWARF source locations to the integer addresses "
                    "an e9patch driver needs (patch address + skip destination). "
                    "Does not read or write the binary itself."
    )
    ap.add_argument('work_dir', help='working directory')
    ap.add_argument("binary_file", help="ELF binary to resolve against (-O0 -g)")
    ap.add_argument("output_dir", help="directory for the resolved patch points")
    ap.add_argument(
        "--patch", "-p", dest="patches",
        action="append", required=True, type=parse_patch_spec,
        metavar="ID:FUNC:FILE:START_LINE:START_COL:END_LINE:END_COL",
        help="patch site (repeatable)",
    )
    ap.add_argument('-v', '--verbose', action='store_true', help='verbose e9patch output')
    args = ap.parse_args()

    specs: List[PatchSpec] = args.patches
    if not specs:
        print("error: no --patch specs given.", file=sys.stderr)
        return 1

    # Per-site jmp ids (third arg of exec_expr on the runtime side).
    jmp_id_file = os.path.join(args.work_dir, 'metapro-out', "jmp-ids.json")
    jmp_ids = parse_jmp_ids(jmp_id_file)

    # Function VA ranges bound the DWARF address search below. They come
    # straight from the binary's symbol table (~0.04 s); no preprocessing step
    # is needed because e9patch reads and rewrites the binary itself downstream.
    functions = load_function_ranges(args.binary_file)
    if not functions:
        print(f"error: no function symbols found in {args.binary_file} "
              f"(stripped binary?); cannot resolve patch sites.",
              file=sys.stderr)
        return 1

    target_files = {s.start.file for s in specs} | {s.end.file for s in specs}
    try:
        line_idx = load_or_build_index(args.binary_file, target_files)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    points = resolve_patch_points(specs, functions, line_idx, jmp_ids,
                                  args.binary_file)
    if not points:
        print("error: no patch sites resolved.", file=sys.stderr)
        return 1
    print(f"Resolved {len(points)} of {len(specs)} patch site(s).")
    for p in points:
        skip = "n/a" if p.skip_target is None else f"0x{p.skip_target:x}"
        print(f"id={p.id} template={p.template.value} jmp_id={p.jmp_id} "
              f"patch=0x{p.patch_addr:x} end=0x{p.end_addr:x} skip={skip}")
        
    # patch_res = call_e9patch(points, args.work_dir, args.binary_file, args.output_dir, args.verbose)
    patch_res = call_e9patch_without_e9tool(points, args.work_dir, args.binary_file, args.output_dir, args.verbose)
    if not patch_res:
        print("error: e9patch failed to apply patches.", file=sys.stderr)
        return 1
    else:
        print("e9patch applied patches successfully.")

    # The resolved data structure is the only output: integer addresses for the
    # e9patch driver to consume.
    os.makedirs(args.output_dir, exist_ok=True)
    out_path = os.path.join(args.output_dir, "patch_points.json")
    with open(out_path, "w") as f:
        json.dump([p.to_hex() for p in points], f, indent=2)
    print(f"Resolved patch points written to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
