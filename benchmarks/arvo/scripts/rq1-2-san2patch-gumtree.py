from argparse import ArgumentParser
import bisect
import difflib
import importlib.util
import json
from multiprocessing.pool import AsyncResult
import multiprocessing as mp
import os
import re
import shutil
import sys
import subprocess as sp
import time
import traceback
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, TextIO, Tuple

import pandas as pd

import docker
import minibenchmark
import checkout


def _load_run_metapro():
    """Import run-metapro.py, whose hyphenated name blocks a normal import (same pattern as
    run-contrafix.py's _load_metapro_binary()). Its run() is what actually *executes* the
    metapro tool to produce metapro-source/ -- checkout.setup_metapro() only builds/installs
    the tool itself, it never runs it. Without this, every diff's _diff_to_config() call below
    hits 'missing source for <file>' and silently returns no patch, regardless of the diff."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'run-metapro.py')
    spec = importlib.util.spec_from_file_location('run_metapro', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules['run_metapro'] = module
    spec.loader.exec_module(module)
    return module

# gpac-383825169, gpac-42532224, gpac-42531310, ffmpeg-42527871, libxml2-424613315, libxml2-424229869
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','..','..'))
CONTAINER_ROOT_DIR = '/root/project/metac'

# Tag of this experiment in the files it writes into a bug's work directory. The rq1-2 scripts
# (and san2patch itself) run over the same work directories, so a file of one would otherwise
# be overwritten by, or read back as, the file of another.
RESULT_TAG = 'gumtree'


def _patch_out_dir(work_dir: str) -> str:
    """Directory of this experiment's patched binaries (<binary>.inst) and patcher output."""
    return os.path.join(work_dir, 'san2patch-deepseek', RESULT_TAG)


def _patch_location_key(patch: dict) -> str:
    """Identify a patch by its source location (function/file/span), ignoring its ID.

    Used to tell whether a patch targets the same place as one applied by a previous
    patch. Mirrors the location fields used to build the patcher command in patch().
    """
    return ':'.join(str(patch.get(k, '')) for k in
                    ('function', 'file', 'line', 'col', 'end_line', 'end_col'))


def _next_free_id(patches: List[dict], reserved=()) -> int:
    """Return the smallest positive integer ID not used by any patch in `patches`
    nor in `reserved`. Used to relocate a patch whose ID collides with another."""
    used = {p['id'] for p in patches} | set(reserved)
    nid = 1
    while nid in used:
        nid += 1
    return nid


# ---------------------------------------------------------------------------
# Deterministic patch-config generation via GumTree + srcML AST diff.
#
# Rather than asking an LLM, we diff the original source (source/) against the
# *preprocessed* source (metapro-source/, with the diff applied) at the AST level
# (GumTree with its srcML C front-end), which ignores whitespace / reindentation,
# then map the structural edits onto metapro's patch templates. Locations are read
# directly from metapro-source, so they are already in the preprocessed
# coordinates the binary patcher expects (no line/column offsetting needed).
#
# Requirements (provided on PATH by the environment):
#   * gumtree (3.0.0) with the c-srcml generator
#   * srcml   (1.0.0 -- GumTree 3.0.0 cannot read the XML emitted by 1.1.0)
# ---------------------------------------------------------------------------

GUMTREE_BIN = 'gumtree'
SRCML_BIN = 'srcml'
GUMTREE_C_GEN = 'c-srcml'
# metapro-source is the instrumented original; it differs from source/ only by a
# single prepended line, so a statement at source line L is at metapro-source line
# L + PREPROC_LINE_OFFSET (verified: columns differ, but lines map by +1).
PREPROC_LINE_OFFSET = 1

_SRC_NS = 'http://www.srcML.org/srcML/src'
_POS_NS = 'http://www.srcML.org/srcML/position'
_POS_START = f'{{{_POS_NS}}}start'
_POS_END = f'{{{_POS_NS}}}end'

# srcML element names that represent a full statement (an INSERT_EXPR unit / a
# valid anchor for "insert before this statement"). These are srcML localnames -- and the
# c-srcml GumTree generator reuses them verbatim as node types -- so a loop is `for`/`while`/
# `do` (not `for_stmt`/...) and a jump is `break`/`continue` (not `break_stmt`/...).
_STMT_TAGS = {'expr_stmt', 'decl_stmt', 'if_stmt', 'while', 'for',
              'do', 'switch', 'return', 'break', 'continue', 'goto'}

# srcML statements that carry a controlling <condition> (the target of a
# REPLACE_CONDITION patch). srcML localnames: only `if` is wrapped in an `if_stmt`.
_CONDITION_TAGS = {'if_stmt', 'while', 'for', 'do'}

# srcML localnames of control statements that pair a controlling header (<control>/
# <condition>) with a body <block>. When a replace touches only the body (header text
# unchanged), it is narrowed to the body so the loop/switch header is left in place.
_CONTROL_BODY_TAGS = {'for', 'while', 'do', 'switch'}

# metapro wraps every such condition in this call:
#   __metapro_replace_cond_c(<id>, "<orig cond>", (unsigned int)(<orig cond>), "<func>")
# Its first argument is the patch id and its source span is the patch location.
_COND_WRAPPER = '__metapro_replace_cond_c'


def _read_text(path: str) -> str:
    with open(path, 'r', errors='replace') as f:
        return f.read()


def _line_starts(text: str) -> List[int]:
    """Char offset of the first character of each line (line N -> starts[N-1])."""
    starts = [0]
    for i, ch in enumerate(text):
        if ch == '\n':
            starts.append(i + 1)
    return starts


def _off_to_linecol(starts: List[int], off: int) -> Tuple[int, int]:
    """Char offset -> (line [1-based], col [0-based])."""
    line = bisect.bisect_right(starts, off)
    return line, off - starts[line - 1]


def _local_tag(elem) -> str:
    return elem.tag.rsplit('}', 1)[-1]


def _elem_span(elem, starts: List[int]):
    """srcML element -> (start_off, end_off_exclusive, sline, scol0, eline, ecol_excl)
    using the file's line-start table. srcML positions are 1-based line and col;
    pos:end points at the last character (inclusive), so we make the offset
    exclusive. Returns None if the element carries no position."""
    s = elem.get(_POS_START)
    e = elem.get(_POS_END)
    if not s or not e:
        return None
    sl, sc = (int(x) for x in s.split(':'))
    el, ec = (int(x) for x in e.split(':'))
    start_off = starts[sl - 1] + (sc - 1)
    end_off = starts[el - 1] + ec  # last char is col ec (1-based) -> +1 exclusive == ec
    return start_off, end_off, sl, sc - 1, el, ec


def _srcml_root(path: str):
    """Parse a C file to a srcML XML tree (with --position) and return the root."""
    res = sp.run([SRCML_BIN, '--position', '-l', 'C', '--tabs', '1', os.path.abspath(path)],
                 capture_output=True, text=True)
    if res.returncode != 0 or not res.stdout.strip():
        raise RuntimeError(f'srcml failed on {path}: {res.stderr[:300]}')
    return ET.fromstring(res.stdout)


def _enclosing_function(root, starts: List[int], off: int):
    """Name of the innermost <function> whose source span contains `off`."""
    best, best_off = None, -1
    for fn in root.iter(f'{{{_SRC_NS}}}function'):
        span = _elem_span(fn, starts)
        if span and span[0] <= off < span[1] and span[0] > best_off:
            best, best_off = fn, span[0]
    if best is None:
        return None
    name = best.find(f'{{{_SRC_NS}}}name')
    return ''.join(name.itertext()).strip() if name is not None else None


def _best_stmt_span_at_line(root, text: str, starts: List[int], line: int, ref_text: str):
    """Among statement elements that *start* on `line` (1-based) in metapro-source,
    return the _elem_span whose covered text is closest to `ref_text` -- the original
    statement from source, whitespace-normalized.

    metapro-source is instrumented, so one line can carry several statements (e.g. a
    wrapped condition `__metapro_replace_cond_c(...)` next to the real one). Choosing
    the candidate with the lowest text distance from the original locates the right
    statement -- and thus the correct start/end column -- where a smallest-span
    heuristic could not. Returns None if no statement starts on `line`."""
    best, best_ratio = None, -1.0
    for el in root.iter():
        if _local_tag(el) not in _STMT_TAGS:
            continue
        span = _elem_span(el, starts)
        if not span or span[2] != line:
            continue
        cand = _norm(text[span[0]:span[1]])
        ratio = difflib.SequenceMatcher(None, cand, ref_text).ratio()
        if ratio > best_ratio:
            best, best_ratio = span, ratio
    return best


def _ref_end_linecol(text: str, starts: List[int], start_off: int, ref_norm: str):
    """Walk `text` from `start_off` until the whitespace-normalized content equals
    `ref_norm`, and return (end_line, end_col) for that point in the same convention as
    _elem_span (1-based line of the last char, col == that char's 1-based col + 1).

    Used to trim a srcML statement span that overshoots the real statement -- e.g. srcML
    extends a block to swallow a trailing `#endif`, so the if_stmt's own pos:end lands
    lines past the closing `}`. Matching against the deleted statement's exact text
    recovers the true end. Returns None if ref_norm is not reached."""
    target = len(ref_norm)
    cnt, prev_space, i, n = 0, True, start_off, len(text)
    while i < n and cnt < target:
        if text[i].isspace():
            if not prev_space:
                cnt += 1
                prev_space = True
        else:
            cnt += 1
            prev_space = False
            if cnt == target:  # ref_norm ends on a non-space char
                end_line = _off_to_linecol(starts, i)[0]
                return end_line, i - starts[end_line - 1] + 2
        i += 1
    return None


def _parent_map(root):
    """child -> parent map for an ElementTree (ET has no parent pointers)."""
    return {child: parent for parent in root.iter() for child in parent}


def _find_elem_by_span(root, start_off: int, tag: str, starts: List[int]):
    """The element matching a GumTree-inserted node by tag and start offset."""
    for el in root.iter():
        if _local_tag(el) != tag:
            continue
        span = _elem_span(el, starts)
        if span and span[0] == start_off:
            return el
    return None


def _adjacent_stmt(pmap, elem, forward: bool, starts=None, skip_offsets=frozenset()):
    """Nearest sibling of `elem` that is a statement, scanning forward/backward.

    Because srcML represents blank lines as nothing and comments as <comment>
    elements (not in _STMT_TAGS), this naturally skips empty/comment-only lines and
    lands on the first real statement -- the one the insertion anchors to.

    Siblings whose start offset is in `skip_offsets` are skipped too. Passing the newly
    inserted statements' offsets there makes a run of consecutive inserts all anchor on the
    same *pre-existing* statement past the run -- one that maps back to source -- instead of
    each anchoring on the next inserted (unmatched) statement, whose metapro span, and so the
    patch, cannot be resolved (only the last insert of the run would survive)."""
    parent = pmap.get(elem)
    if parent is None:
        return None
    children = list(parent)
    idx = children.index(elem)
    seq = children[idx + 1:] if forward else list(reversed(children[:idx]))
    for sib in seq:
        if _local_tag(sib) not in _STMT_TAGS:
            continue
        if skip_offsets:
            span = _elem_span(sib, starts)
            if span and span[0] in skip_offsets:
                continue
        return sib
    return None


def _replaced_stmts(a_root, after_text: str, a_starts: List[int],
                    dest_to_src: Dict[int, int], added: str, in_hunk,
                    inserted_stmt_offsets, before_stmt_texts):
    """After-tree statements that were *replaced in place* by the diff.

    A replace deletes the original statement and inserts a new one at the same spot.
    GumTree matches the enclosing statement node (it pre-existed) and reports the
    rewrite at *expression* granularity (update/insert/delete on the inner exprs), so
    there is no whole-statement insert-tree to key on. We therefore walk the AST at
    statement granularity -- the "minimum statement", not an expression -- and accept
    a statement element when all of the following hold:

      * it overlaps the changed region (its start is in a hunk);
      * its start offset is matched to the original (an unmatched statement is a
        wholly new insert, handled by the INSERT_EXPR path, not a replace);
      * its whitespace-normalized text appears among the diff's added lines (so its
        body was actually rewritten -- an unchanged statement stays a context line and
        never appears in `added`; e.g. the enclosing `if`/`else` is dropped here);
      * it is not itself a newly inserted statement (`inserted_stmt_offsets`, the
        starts of GumTree insert-tree/insert-node statement actions) -- that is a pure
        insertion, again the INSERT_EXPR path; and
      * its token stream is not that of some original statement (`before_stmt_texts`, keyed
        by _norm_tokens). A statement merely *moved* into a new wrapper (e.g. the body of an
        INSERT_NOT_NULL_CHECKER), or just respaced (`i,k` -> `i, k`), still appears among the
        added lines but its tokens are unchanged -- this excludes it. The token comparison
        (not _norm) is what makes a cosmetic respacing not read as a rewrite.

    When qualifying statements nest, only the innermost is returned so the patch
    anchors on the minimum statement, not its container. Returns a list of
    (statement element, _elem_span) pairs in document order.
    """
    cands = []
    for el in a_root.iter():
        if _local_tag(el) not in _STMT_TAGS:
            continue
        span = _elem_span(el, a_starts)
        if not span or not in_hunk(span[0]):
            continue
        if span[0] not in dest_to_src:
            continue  # unmatched -> a wholly new statement (INSERT_EXPR), not a replace
        if span[0] in inserted_stmt_offsets:
            continue  # a freshly inserted statement (INSERT_EXPR), not a replace
        text = _norm(after_text[span[0]:span[1]])
        if text not in added:
            continue  # statement body unchanged by the diff
        if _norm_tokens(after_text[span[0]:span[1]]) in before_stmt_texts:
            continue  # unchanged statement merely relocated/reindented, not rewritten
        cands.append((el, span))
    # Keep only minimum statements: drop any candidate that strictly contains another.
    result = []
    for el, span in cands:
        if any(c_el is not el and span[0] <= o[0] and o[1] <= span[1]
               and (span[1] - span[0]) > (o[1] - o[0]) for c_el, o in cands):
            continue
        result.append((el, span))
    return result


def _after_node_src_line(elem, a_starts: List[int], before_starts: List[int],
                         dest_to_src: Dict[int, int]):
    """Original-source line of an unchanged after-tree node, via GumTree matches.

    Tries the node itself, then its descendants (a matched child sits on the same
    line as the statement), so it is robust to which granularity GumTree matched.
    Returns a 1-based source line, or None."""
    for node in elem.iter():
        span = _elem_span(node, a_starts)
        if span and span[0] in dest_to_src:
            return _off_to_linecol(before_starts, dest_to_src[span[0]])[0]
    return None


def _strip_c_comments(s: str) -> str:
    """Remove C `/* ... */` and `// ...` comments from `s`, leaving string/char literals
    untouched. Source slices are taken verbatim from the patched file, so a comment in the
    added code would otherwise leak into the emitted patch text -- and, once whitespace is
    collapsed, a `//` line comment would swallow the rest of the statement (e.g. the closing
    `}` of an inserted block). A block comment becomes a single space so it cannot glue two
    tokens together. `//` ends at its newline, so this must run before whitespace collapse."""
    out, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if c in '"\'':
            q = c
            out.append(c)
            i += 1
            while i < n:
                out.append(s[i])
                if s[i] == '\\' and i + 1 < n:
                    out.append(s[i + 1])
                    i += 2
                    continue
                if s[i] == q:
                    i += 1
                    break
                i += 1
            continue
        if c == '/' and i + 1 < n and s[i + 1] == '/':
            while i < n and s[i] != '\n':
                i += 1
            continue
        if c == '/' and i + 1 < n and s[i + 1] == '*':
            i += 2
            while i + 1 < n and not (s[i] == '*' and s[i + 1] == '/'):
                i += 1
            i += 2
            out.append(' ')
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def _norm(s: str) -> str:
    """Collapse all runs of whitespace to single spaces for tolerant text matching, first
    stripping C comments (see _strip_c_comments) so a comment in a verbatim source slice
    neither leaks into the patch text nor eats the rest of the line once collapsed."""
    return ' '.join(_strip_c_comments(s).split())


_TOKEN_RE = re.compile(r'[A-Za-z0-9_]+|[^\sA-Za-z0-9_]')


def _norm_tokens(s: str) -> str:
    """Canonical token stream of `s`: C tokens (identifier/number runs, or a single other
    non-space character) joined by single spaces, comments stripped. Unlike _norm this
    ignores spacing *around* punctuation -- `i,k` and `i, k` compare equal -- while still
    keeping two adjacent identifiers apart (`size_t i` stays two tokens). Used only to decide
    whether a statement is textually unchanged (see _replaced_stmts / before_stmt_texts), so
    a purely cosmetic respacing is not mistaken for a rewrite; never emitted into a patch."""
    return ' '.join(_TOKEN_RE.findall(_strip_c_comments(s)))


def _clip_trailing_cpp(s: str) -> str:
    """Trim a source slice at the first preprocessor-directive line (first non-space
    char is '#'). srcML over-extends a block to swallow a trailing `#endif`, so a
    deleted statement's slice can carry cpp directives that are not part of it."""
    out = []
    for line in s.splitlines(keepends=True):
        if line.lstrip().startswith('#'):
            break
        out.append(line)
    return ''.join(out)


def _parse_tree_str(s: str):
    """GumTree node label 'expr_stmt [10,20]' / 'operator: != [10,12]' ->
    (type, label, start, end). Offsets are char offsets in the source/dest file."""
    m = re.search(r'\[(\d+),(\d+)\]\s*$', s)
    start, end = int(m.group(1)), int(m.group(2))
    head = s[:m.start()].rstrip()
    if ': ' in head:
        typ, label = head.split(': ', 1)
    else:
        typ, label = head, None
    return typ, label, start, end


def _run_gumtree(before_path: str, after_path: str):
    """GumTree diff between two C files (absolute paths). Returns
    (actions, dest_to_src):

    * actions     -- list of {action, type, label, start, end, parent, at}.
    * dest_to_src -- {after/dest start offset: before/src start offset} for every
                     matched node, used to map an unchanged after-tree node back to
                     its original-source position.
    """
    res = sp.run([GUMTREE_BIN, 'textdiff', '-g', GUMTREE_C_GEN, '-f', 'json', '-m', 'gumtree-hybrid',
                  os.path.abspath(before_path), os.path.abspath(after_path)],
                 capture_output=True, text=True)
    if res.returncode != 0 or not res.stdout.strip():
        raise RuntimeError(f'gumtree failed: {res.stderr[:500]}')
    data = json.loads(res.stdout)
    actions = []
    for a in data.get('actions', []):
        if a['tree'].startswith("comment:"):
            # Skip comment change
            continue
        typ, label, start, end = _parse_tree_str(a['tree'])
        actions.append({'action': a['action'], 'type': typ, 'label': label,
                        'start': start, 'end': end,
                        'parent': a.get('parent'), 'at': a.get('at')})
    dest_to_src = {}
    for mt in data.get('matches', []):
        _, _, src_start, _ = _parse_tree_str(mt['src'])
        _, _, dst_start, _ = _parse_tree_str(mt['dest'])
        dest_to_src[dst_start] = src_start
    return actions, dest_to_src


def _parse_unified_diff(diff_path: str) -> Dict[str, dict]:
    """Parse a unified diff into {relative_path: {'hunks', 'added', 'removed'}}:

    * 'hunks'  -- (b_start, b_end, a_start, a_end) 1-based inclusive line ranges in
                  the before(source)/after(san2patch-source) files; used to ignore
                  GumTree actions outside the changed region.
    * 'added'  -- normalized text of all added lines; an inserted statement reported
                  by GumTree is accepted only if its text appears here, which drops
                  GumTree's spurious re-matches.
    * 'removed'-- normalized text of all removed lines; the mirror of 'added', used to
                  confirm a GumTree-deleted statement was actually removed by the diff.
    """
    files: Dict[str, dict] = {}
    cur = None
    hunk_re = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')
    for raw in _read_text(diff_path).splitlines():
        if raw.startswith('+++ '):
            p = raw[4:].split('\t')[0].strip()
            if p.startswith('b/'):
                p = p[2:]
            cur = None if p == '/dev/null' else p
            if cur:
                files.setdefault(cur, {'hunks': [], 'added': [], 'removed': []})
        elif raw.startswith('--- ') or raw.startswith('diff '):
            continue
        elif raw.startswith('@@') and cur:
            m = hunk_re.match(raw)
            if not m:
                continue
            bs = int(m.group(1)); bc = int(m.group(2) or 1)
            as_ = int(m.group(3)); ac = int(m.group(4) or 1)
            files[cur]['hunks'].append((bs, bs + max(bc, 1) - 1, as_, as_ + max(ac, 1) - 1,
                                        ac - bc))  # net: the clamped ranges lose a pure insertion's count
        elif cur and files[cur]['hunks'] and raw.startswith('+'):
            files[cur]['added'].append(raw[1:])
        elif cur and files[cur]['hunks'] and raw.startswith('-'):
            files[cur]['removed'].append(raw[1:])
    return {f: {'hunks': info['hunks'], 'added': _norm('\n'.join(info['added'])),
                'removed': _norm('\n'.join(info['removed']))}
            for f, info in files.items() if info['hunks']}


def _escape_expr(s: str, macros: dict = None, local_vars: frozenset = frozenset()) -> str:
    """Prepare an expression for the JSON config:
      1. expand preprocessor macros to their definition (so the binary patcher, which has no
         preprocessor, sees the real expression -- e.g. AVERROR_INVALIDDATA -> its integer
         form; see _expand_macros). `local_vars` (see _registered_var_names) is excluded from
         this step: a real parameter/local always wins over a same-named but out-of-scope
         macro.
      2. canonicalize scalar casts to their stdint.h spelling (see _canonicalize_casts).
      3. escape for the C string literal it is re-embedded into (it is passed via environment
         variable, see test_poc): backslashes first, then quotes.
    `macros` is optional; a missing table skips its step."""
    if macros:
        s = _expand_macros(s, macros, disabled=local_vars)
    s = _canonicalize_casts(s)
    return s.replace('\\', '\\\\').replace('"', '\\"')


# Every parameter and local variable metapro's instrumentation touches is registered this way,
# once per function, at its point of declaration.
_VAR_REGISTRATION_RE = re.compile(r'__metapro_table_insert_var_c\("[^"]*",\s*"([^"]*)"')


def _registered_var_names(m_text: str) -> frozenset:
    """Names metapro registered as real parameters/locals (via __metapro_table_insert_var_c,
    see above) in one function's instrumented text.

    macros.json is built project-wide with no notion of scope, so it can hold a macro whose
    name collides with an unrelated local variable the real compile never actually expanded at
    this call site -- confirmed on ffmpeg-42528431's cbs_h2645_read_more_rbsp_data:
    libavcodec/bitstream.h unconditionally `#define`s bits_left to bits_left_be, yet
    metapro-source (built from the real preprocessor) still shows the plain local `bits_left`
    both as its own name and in the wrapped condition's text, proving that #define was never
    active here. Excluding registered names from macro expansion (see _escape_expr) stops a
    same-named but out-of-scope macro from silently renaming a real local/parameter in the
    emitted patch expression -- which would then reference a variable the interpreter never
    registered and abort the PoC ("terrible error in meta-program or interpreter")."""
    return frozenset(_VAR_REGISTRATION_RE.findall(m_text))


# ============================================================================
# Emit-side helpers ported from gen-san2patch-config.py (text-level analysis).
# The GumTree AST analysis above produces the same typed changes; these turn a
# derived statement into final patch text: macro expansion, cast canonicalization,
# blacklisted log/print stripping, multi-statement wrapping. Comment stripping is
# intentionally omitted -- srcML/GumTree already drop comments when parsing to the AST.
# ============================================================================


def _skip_literal(text, i):
    """`i` at a quote; return the index just past the matching string/char literal."""
    q, n, L = text[i], i + 1, len(text)
    while n < L:
        if text[n] == '\\':
            n += 2
            continue
        if text[n] == q:
            return n + 1
        n += 1
    return n


def _skip_ws(text, i):
    L = len(text)
    while i < L and text[i].isspace():
        i += 1
    return i


def _skip_balanced(text, i, opench, closech):
    """`i` at `opench`; return the index just past its matching `closech`, skipping over
    string/char literals so brackets inside them are not counted."""
    depth, L = 0, len(text)
    while i < L:
        c = text[i]
        if c in '"\'':
            i = _skip_literal(text, i)
            continue
        if c == opench:
            depth += 1
        elif c == closech:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return i


def _net_braces(s: str) -> int:
    """Net `{` minus `}` in `s` (literals skipped). >0 means `s` opens more blocks than it
    closes -- e.g. a control header `if (cond) {` whose body/close live on later lines."""
    depth, i, L = 0, 0, len(s)
    while i < L:
        c = s[i]
        if c in '"\'':
            i = _skip_literal(s, i)
            continue
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
        i += 1
    return depth


_CAST_TYPE_WIDTH = {
    # signed integers
    'int8_t': ['int8_t', '__int8', 'char', 'signed char'],
    'int16_t': ['int16_t', '__int16', 'short', 'short int', 'signed short',
                'signed short int'],
    'int32_t': ['int32_t', '__int32', 'int', 'signed', 'signed int', 'wchar_t'],
    'int64_t': ['int64_t', '__int64', 'long', 'long int', 'signed long',
                'signed long int', 'long long', 'long long int', 'signed long long',
                'signed long long int', 'ssize_t', 'ptrdiff_t', 'intptr_t', 'intmax_t',
                'off_t', 'off64_t'],
    # unsigned integers
    'uint8_t': ['uint8_t', 'u_int8_t', 'unsigned char'],
    'uint16_t': ['uint16_t', 'u_int16_t', 'unsigned short', 'unsigned short int'],
    'uint32_t': ['uint32_t', 'u_int32_t', 'unsigned', 'unsigned int', 'u_int'],
    'uint64_t': ['uint64_t', 'u_int64_t', 'size_t', 'uintptr_t', 'uintmax_t',
                 'unsigned long', 'unsigned long int', 'unsigned long long',
                 'unsigned long long int'],
    # floating point
    'float': ['float'],
    'double': ['double', 'long double'],
}
_CAST_CANON = {spelling: canon
               for canon, spellings in _CAST_TYPE_WIDTH.items()
               for spelling in spellings}
# Match a scalar (non-pointer) cast `(TYPE)`; longest spellings first so "unsigned long"
# wins over "long". Each spelling's internal spaces become `\s+` to survive whitespace
# collapse. No '*' is allowed, so pointer casts are left to _PTR_CAST_RE.
_CAST_TYPE_RE = re.compile(
    r'\(\s*(' + '|'.join(
        r'\s+'.join(re.escape(tok) for tok in s.split())
        for s in sorted(_CAST_CANON, key=len, reverse=True)) + r')\s*\)')


def _canonicalize_casts(s: str) -> str:
    """Rewrite scalar casts in emitted patch text to their stdint.h spelling under the LP64
    model the arvo x86-64 builds use -- `(unsigned)`/`(unsigned int)` -> `(uint32_t)`,
    `(int)` -> `(int32_t)`, `(long)` -> `(int64_t)`, `(size_t)` -> `(uint64_t)`, etc. (see
    _CAST_TYPE_WIDTH). Only exact scalar-type casts are rewritten; pointer casts and every
    other token are left verbatim. Unlike _normalize_code (comparison keys only, which also
    folds pointer casts to (void*) and expands macros), this touches nothing but the scalar
    cast spelling, so it is safe to apply to code that is actually re-inserted."""
    return _CAST_TYPE_RE.sub(
        lambda m: '(' + _CAST_CANON[_norm(m.group(1))] + ')', s)


# Authoritative values for macros the source-tree grep cannot see: system-header macros
# (e.g. EINVAL) and command-line `-D` defines, applied via _apply_custom_macros so they
# take precedence over the metapro table. Extend as needed.
CUSTOM_MACROS = {
    'EINVAL': '22',
    'ENOMEM': '12',
    'INT_MAX': '2147483647',
    'UINT_MAX': '4294967295',
    'UINT16_MAX': '65535',
    'UINT32_MAX': '4294967295',
    'INT64_MAX': '9223372036854775807',
    'SIZE_MAX': '18446744073709551615',
}


# A single C identifier token; shared by macro parsing/substitution.
_IDENT_RE = re.compile(r'[A-Za-z_]\w*')


_MACRO_EXPAND_MAX_DEPTH = 32


def _load_macro_table(macros_json_path: str) -> Dict[str, dict]:
    """Load metapro-out/macros.json into {name: entry}. Returns {} if it is missing or
    unreadable, so macro expansion is simply skipped.

    enum_constant entries are normalized into object-like macro entries whose expanded_body
    is the enum member's integer `value`, so _expand_macros can consume them uniformly with
    #define macros."""
    try:
        with open(macros_json_path) as f:
            table = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(table, dict):
        return {}
    for name, entry in table.items():
        if isinstance(entry, dict) and entry.get('kind') == 'enum_constant':
            entry['expanded_body'] = _norm(str(entry.get('value', '')))
            entry['function_like'] = False
            entry['params'] = []
            entry['variadic'] = False
    return table


def _apply_custom_macros(table: Dict[str, dict]) -> None:
    """Overlay CUSTOM_MACROS -- system-header / command-line `-D` defines the preprocessor
    dump (macros.json) and the source-tree grep both miss (e.g. EINVAL) -- onto the rich
    macro table as object-like entries. They take precedence, so a use like `-EINVAL`
    resolves even when the table has no entry for the macro. Mutates `table` in place."""
    for name, val in CUSTOM_MACROS.items():
        table[name] = {'expanded_body': _norm(val), 'function_like': False,
                       'params': [], 'variadic': False, 'undefined': False}


def _split_macro_args(s: str) -> List[str]:
    """Split a macro call's argument string on top-level commas (depth 0, skipping string/
    char literals). Returns [] for an empty arg string; nested parens/brackets/braces keep
    their commas together (so a comma inside a nested call is not a separator)."""
    s = s.strip()
    if not s:
        return []
    args, depth, start, i, n = [], 0, 0, 0, len(s)
    while i < n:
        c = s[i]
        if c in '"\'':
            i = _skip_literal(s, i)
            continue
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        elif c == ',' and depth == 0:
            args.append(s[start:i])
            start = i + 1
        i += 1
    args.append(s[start:])
    return [a.strip() for a in args]


def _substitute_params(body: str, mapping: Dict[str, str]) -> str:
    """Replace whole-identifier occurrences of a macro parameter (keys of `mapping`,
    including __VA_ARGS__) in `body` with its argument text, skipping string/char literals.
    Non-parameter identifiers are left untouched."""
    out, i, n = [], 0, len(body)
    while i < n:
        c = body[i]
        if c in '"\'':
            j = _skip_literal(body, i)
            out.append(body[i:j])
            i = j
            continue
        if c.isalpha() or c == '_':
            m = _IDENT_RE.match(body, i)
            out.append(mapping.get(m.group(0), m.group(0)))
            i = m.end()
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def _expand_macros(code: str, table: Dict[str, dict], disabled=frozenset(),
                   depth: int = 0) -> str:
    """Expand C preprocessor macros in `code` using the metapro macro table (see
    _load_macro_table). Object-like macros are replaced by their expanded_body; function-like
    macros parse their `( ... )` argument list, macro-expand each argument, then substitute
    the parameters -- and __VA_ARGS__ for variadic macros -- into expanded_body. The result
    is re-scanned so anything left resolves too, with the expanding macro disabled to stop
    self-reference (and _MACRO_EXPAND_MAX_DEPTH as a backstop). String/char literals are
    copied verbatim, so an identifier inside a literal is never mistaken for a macro.

    TODO: the `#` (stringize) and `##` (token-paste) operators are not implemented. A macro
    whose expanded_body uses either is left un-expanded at its call site rather than
    mis-expanded (detected by a `#` anywhere in the body)."""
    if depth > _MACRO_EXPAND_MAX_DEPTH:
        return code
    out, i, n = [], 0, len(code)
    while i < n:
        c = code[i]
        if c in '"\'':
            j = _skip_literal(code, i)
            out.append(code[i:j])
            i = j
            continue
        if not (c.isalpha() or c == '_'):
            out.append(c)
            i += 1
            continue
        m = _IDENT_RE.match(code, i)
        name = m.group(0)
        end = m.end()
        entry = table.get(name)
        if entry is None or entry.get('undefined') or name in disabled:
            out.append(name)
            i = end
            continue
        body = entry.get('expanded_body', '')
        if '#' in body:  # TODO: stringize / token-paste not supported yet
            out.append(name)
            i = end
            continue
        if entry.get('function_like'):
            k = _skip_ws(code, end)
            if k >= n or code[k] != '(':
                out.append(name)  # bare name, not an invocation
                i = end
                continue
            argend = _skip_balanced(code, k, '(', ')')
            args = [_expand_macros(a, table, disabled, depth + 1)
                    for a in _split_macro_args(code[k + 1:argend - 1])]
            params = entry.get('params', [])
            variadic = entry.get('variadic')
            named = params[:-1] if variadic else params
            mapping = {p: (args[idx] if idx < len(args) else '')
                       for idx, p in enumerate(named)}
            if variadic:
                mapping['__VA_ARGS__'] = ', '.join(args[len(named):])
            expansion = _substitute_params(body, mapping)
            out.append(_expand_macros(expansion, table, disabled | {name}, depth + 1))
            i = argend
            continue
        # object-like: expanded_body has no params to fill
        out.append(_expand_macros(body, table, disabled | {name}, depth + 1))
        i = end
    return ''.join(out)


def _count_top_level_stmts(text: str) -> int:
    """Number of statements at brace/paren/bracket depth 0 in `text`: each `;` at depth 0,
    plus each `}` that closes a top-level block (e.g. an inserted `if (...) { ... }`).
    String/char literals are skipped so terminators inside them are not counted. Used to
    decide whether an inserted run is a compound (multiple statements) needing `{ }`."""
    depth, count, pending, i, n = 0, 0, False, 0, len(text)
    while i < n:
        c = text[i]
        if c in '"\'':
            i = _skip_literal(text, i)
            pending = True
            continue
        if c in '([{':
            depth += 1
            i += 1
            continue
        if c in ')]}':
            depth -= 1
            i += 1
            if c == '}' and depth == 0:
                count += 1
                pending = False
            continue
        if c == ';' and depth == 0:
            count += 1
            pending = False
            i += 1
            continue
        if not c.isspace():
            pending = True
        i += 1
    if pending:
        count += 1
    return count


# ---------------------------------------------------------------------------
# Blacklisted (log/print) call removal.
#
# san2patch- / LLM-generated diffs often add pure logging or printing next to the real
# fix (e.g. `fprintf(stderr, "...")`). Such a statement has no bearing on whether the
# bug is repaired, and the called symbol may not even resolve when the statement is
# re-inserted by the binary patcher. So any inserted / replacement statement that is
# *nothing but* a call to one of these names is dropped from the derived config. Names
# are matched on the call's leading identifier, so a name here is removed whether it is a
# real function or a function-like macro. Extend the set to silence other pure-logging
# helpers.
# ---------------------------------------------------------------------------
_BLACKLISTED_CALLS = {
    # C stdio printing / logging
    'printf', 'fprintf', 'vprintf', 'vfprintf', 'dprintf', 'vdprintf',
    'puts', 'fputs', 'perror',
    # POSIX syslog
    'syslog', 'vsyslog',
    # project-specific loggers used across the arvo benchmark projects
    'av_log',            # ffmpeg
    'GF_LOG',            # gpac
    'xmlGenericError', 'xmlFatalErr', 'xmlErrMemory', 'xmlFatalErrMsg',  # libxml2
    'php_printf',        # php-src
    'NDPI_LOG_DBG', 'NDPI_LOG_ERR', 'NDPI_LOG_INFO',  # ndpi
}


def _split_stmts(s: str):
    """Split `s` into statements at `;` that sit at brace/paren/bracket depth 0, skipping
    string/char literals so a terminator inside a literal never splits. A trailing block
    statement with no closing `;` (e.g. `if (c) { ... }`) comes back whole; each
    `;`-terminated statement keeps its `;`."""
    out, depth, start, i, n = [], 0, 0, 0, len(s)
    while i < n:
        c = s[i]
        if c in '"\'':
            i = _skip_literal(s, i)
            continue
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        elif c == ';' and depth == 0:
            out.append(s[start:i + 1])
            start = i + 1
        i += 1
    if s[start:].strip():
        out.append(s[start:])
    return out


def _bare_call_name(stmt: str):
    """If `stmt` is exactly a bare call statement -- an identifier then a parenthesized
    argument list spanning the rest of the statement (bar a trailing `;`) -- return that
    identifier, else None. An assignment, cast, `return`, member access or a trailing
    operator all fail the match, so only side-effect-only calls (the shape a log/print
    line takes) are recognised; a call used as a subexpression is left alone."""
    s = stmt.strip()
    if s.endswith(';'):
        s = s[:-1].strip()
    m = re.match(r'^([A-Za-z_]\w*)\s*\(', s)
    if not m:
        return None
    end = _skip_balanced(s, s.index('('), '(', ')')
    if s[end:].strip():
        return None  # something follows the call -> not a bare call statement
    return m.group(1)


def _clean_stmt(stmt: str) -> str:
    """Strip blacklisted (log/print) calls from a single statement, recursing into any
    brace block it carries so a call nested inside an inserted `if (cond) { ... }` is
    removed while the control flow (the real fix, e.g. the guarding `if` and its `return`)
    is preserved. An `else`/`while` tail after the block is cleaned too. Returns '' when
    the statement is itself a bare blacklisted call."""
    stmt = stmt.strip()
    if not stmt:
        return ''
    if _bare_call_name(stmt) in _BLACKLISTED_CALLS:
        return ''
    b = stmt.find('{')
    if b == -1:
        return stmt
    end = _skip_balanced(stmt, b, '{', '}')        # index past the matching '}'
    head = stmt[:b].strip()                         # e.g. "if (cond)" / "else" / ""
    # `_skip_balanced` returns the index past the matching `}` when the block is closed; on
    # an unbalanced fragment -- git diff can slice a block's `}` onto a line outside the run,
    # so an insert may open a `{` that never closes -- it runs off the end and there is no
    # `}` to drop. Take the body through `end` (not `end - 1`) in that case, or we would
    # slice off the body's own last character (e.g. the `;` after `break`).
    closed = _net_braces(stmt[b:end]) == 0
    inner = _strip_blacklisted_calls(stmt[b + 1:end - 1] if closed else stmt[b + 1:end])
    tail = _clean_stmt(stmt[end:]) if closed else ''  # an `else`/`while` tail, or ''
    out = (head + ' ' if head else '') + '{ ' + inner + ' }'
    return out + ' ' + tail if tail else out


def _strip_blacklisted_calls(text: str) -> str:
    """Drop statements that are nothing but a blacklisted (log/print) call from the
    inserted/replacement statement run `text` (normalized; possibly several
    `;`-separated statements). Calls nested one or more blocks deep -- e.g. the `av_log`
    inside an inserted `if (cond) { av_log(...); return; }` -- are stripped too, while the
    surrounding control flow is kept (see _clean_stmt). Returns the surviving statements
    re-joined, or '' when nothing survives."""
    kept = []
    for stmt in _split_stmts(text.strip()):
        cleaned = _clean_stmt(stmt)
        if cleaned:
            kept.append(cleaned)
    return ' '.join(kept)


def _insert_expr_text(text: str) -> str:
    """Build the INSERT_EXPR `exprs` value from inserted source `text` (normalized): make
    sure it ends with a terminator, then wrap it in `{ ... }` when it is more than one
    statement so the patcher treats the run as a single compound statement."""
    expr = text if text.endswith((';', '}')) else text + ';'
    if _count_top_level_stmts(expr) > 1:
        expr = '{ ' + expr + ' }'
    return expr


def _merge_insert_exprs(exprs0: List[str]) -> str:
    """Fold several statements inserted at one point into a single compound statement, in the
    order given, so the one METAPRO_EXPR_<id> slot (see test_poc) carries them all."""
    return '{ ' + ' '.join(exprs0) + ' }'


def _merge_checker_conds(exprs0: List[str]) -> str:
    """Fold several not-null checkers wrapping one location into a single condition. Nested
    `if (c) { ... }` wrappers compose as a conjunction, so AND the distinct conditions; a
    never-true `0` (a disabling REPLACE/REMOVE checker) dominates and collapses to `0`."""
    seen: List[str] = []
    for c in exprs0:
        if c not in seen:
            seen.append(c)
    if '0' in seen:
        return '0'
    if len(seen) == 1:
        return seen[0]
    return ' && '.join('(' + c + ')' for c in seen)


def _coalesce_same_location(patches: List[dict], template: str, combine) -> List[dict]:
    """Collapse every `template` patch sharing a location into one, keeping output order
    (first occurrence). The binary patcher keys a template's expression by patch id alone
    (METAPRO_EXPR_<id> / METAPRO_PATCH_NOT_NULL_CHECKER_EXPR_<id>, see test_poc) and
    same-location patches share an id, so N separate same-location patches would clobber one
    another in that single env slot -- only the last would apply. `combine(exprs0_list)` folds
    their `exprs[0]` values into the one that survives. Other templates pass through untouched."""
    out: List[dict] = []
    idx_by_key: Dict[str, int] = {}
    acc_by_key: Dict[str, List[str]] = {}
    for p in patches:
        if p['template'] != template:
            out.append(p)
            continue
        key = _patch_location_key(p)
        if key in idx_by_key:
            acc_by_key[key].append(p['exprs'][0])
        else:
            idx_by_key[key] = len(out)
            acc_by_key[key] = [p['exprs'][0]]
            out.append(dict(p))
    for key, exprs0 in acc_by_key.items():
        if len(exprs0) > 1:
            out[idx_by_key[key]]['exprs'] = [combine(exprs0)]
    return out


def _control_parts(stmt_el, starts: List[int]):
    """For a control statement (for/while/do/switch), return (header_span, body_block_elem):
    the source span of its controlling header (<control> for `for`, else <condition>) and its
    body <block> element. Either component is None when the statement lacks it."""
    header = stmt_el.find(f'{{{_SRC_NS}}}control')
    if header is None:
        header = stmt_el.find(f'{{{_SRC_NS}}}condition')
    hspan = _elem_span(header, starts) if header is not None else None
    block = stmt_el.find(f'{{{_SRC_NS}}}block')
    return hspan, block


def _if_inner(if_stmt_el):
    """The <if> child of an <if_stmt> (holds its <condition> and then-<block>)."""
    return if_stmt_el.find(f'{{{_SRC_NS}}}if')


def _if_condition_text(if_stmt_el, after_text: str, a_starts: List[int]):
    """Whitespace-normalized condition expression of an <if_stmt> (the <expr> inside
    <condition>, i.e. without the outer parens), or None."""
    inner = _if_inner(if_stmt_el)
    cond = inner.find(f'{{{_SRC_NS}}}condition') if inner is not None else None
    if cond is None:
        return None
    expr = cond.find(f'{{{_SRC_NS}}}expr')
    span = _elem_span(expr if expr is not None else cond, a_starts)
    return _norm(after_text[span[0]:span[1]]) if span else None


def _if_body_stmts(if_stmt_el):
    """Direct statement children of an <if_stmt>'s then-block (the wrapped ones)."""
    inner = _if_inner(if_stmt_el)
    block = inner.find(f'{{{_SRC_NS}}}block') if inner is not None else None
    bc = block.find(f'{{{_SRC_NS}}}block_content') if block is not None else None
    return [c for c in bc if _local_tag(c) in _STMT_TAGS] if bc is not None else []


def _condition_expr_text(stmt_el, text: str, starts: List[int]):
    """Whitespace-normalized controlling condition of an if/while/for/do statement --
    the <expr> inside its first <condition> (without the outer parens), or None.
    Unlike _if_condition_text this works for any _CONDITION_TAGS statement."""
    cond = next(stmt_el.iter(f'{{{_SRC_NS}}}condition'), None)
    if cond is None:
        return None
    expr = cond.find(f'{{{_SRC_NS}}}expr')
    span = _elem_span(expr if expr is not None else cond, starts)
    return _norm(text[span[0]:span[1]]) if span else None


def _unescape_str_literal(s: str) -> str:
    """Inverse of metapro embedding a condition as a C string literal: drop the
    surrounding double quotes and unescape the C escapes (\\", \\\\, and -- since a
    multi-line condition keeps its newlines/tabs as \\n/\\t -- the whitespace ones, so
    _norm can then collapse them to match the after-source condition)."""
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    simple = {'n': '\n', 't': '\t', 'r': '\r', '"': '"', '\\': '\\'}
    out, i = [], 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            out.append(simple.get(s[i + 1], s[i + 1]))
            i += 2
        else:
            out.append(s[i])
            i += 1
    return ''.join(out)


def _cond_wrappers(m_root, m_starts: List[int], lines):
    """metapro __metapro_replace_cond_c(id, "orig", (unsigned int)(orig), "func") calls
    that *start on one of* `lines` (the patched metapro lines). Returns a list of
    {id, orig, func, span}: the patch id (1st arg), the original condition text
    (2nd arg, whitespace-normalized), the function name (4th arg) and the call's
    source span -- exactly the coordinates a REPLACE_CONDITION patch is reported at.

    metapro instruments *every* condition in the file, so the tree holds thousands of
    these (plus far more unrelated instrumentation calls). Filtering by start line --
    cheap, from the position attribute -- before the costlier name/argument extraction
    keeps this to the handful of conditions the diff actually touched."""
    out = []
    for call in m_root.iter(f'{{{_SRC_NS}}}call'):
        start = call.get(_POS_START)
        if not start or int(start.split(':', 1)[0]) not in lines:
            continue
        name = call.find(f'{{{_SRC_NS}}}name')
        if name is None or ''.join(name.itertext()).strip() != _COND_WRAPPER:
            continue
        alist = call.find(f'{{{_SRC_NS}}}argument_list')
        args = alist.findall(f'{{{_SRC_NS}}}argument') if alist is not None else []
        if len(args) < 4:
            continue
        id_txt = ''.join(args[0].itertext()).strip()
        span = _elem_span(call, m_starts)
        if not id_txt.isdigit() or span is None:
            continue
        out.append({
            'id': int(id_txt),
            'orig': _norm(_unescape_str_literal(''.join(args[1].itertext()).strip())),
            'func': _unescape_str_literal(''.join(args[3].itertext()).strip()),
            'span': span,
        })
    return out


def _replace_cond_exprs(new_cond: str, orig: str):
    """Classify how a condition was rewritten relative to its original `orig` and
    return the REPLACE_CONDITION `exprs`, or None when it is unchanged.

    * Pattern #2 -- a new sub-condition inserted before or after the original with
      `&&`/`||`, which keeps `orig` intact and is expressed with two exprs:
        - appended  (`orig <op> sub`) -> ['<op>', sub]  (operator first, then new cond)
        - prepended (`sub <op> orig`) -> [sub, '<op>']  (new cond first, then operator)
    * Pattern #1 -- any other rewrite is treated as a full replacement of the whole
      condition: ['<new cond>'] (a single expr the wrapper evaluates in place of orig)."""
    if new_cond == orig:
        return None
    # The rewrite may wrap the original (and/or the added sub-condition) in parentheses --
    # e.g. `(sub) || (orig)` -- so match the original both bare and parenthesized. Without
    # this, a sub-condition added before/after a parenthesized original is misread as a full
    # replacement (pattern #1) instead of pattern #2.
    for op in ('&&', '||'):
        sep = f' {op} '
        for o in (orig, f'({orig})'):
            if new_cond.startswith(o + sep):
                return [op, new_cond[len(o) + len(sep):]]
            if new_cond.endswith(sep + o):
                return [new_cond[:-(len(sep) + len(o))], op]
    return [new_cond]  # pattern #1: replace the whole condition


def _metapro_span_for(after_stmt, after_text, a_starts, before_starts, dest_to_src,
                      m_root, m_text, m_starts):
    """Map an after-tree statement back to source (via GumTree matches), then to the
    matching metapro-source statement span (the candidate on `source_line + 1` whose
    text is closest to the original). Returns the _elem_span tuple, or None."""
    a_span = _elem_span(after_stmt, a_starts)
    if a_span is None:
        return None
    ref_text = _norm(after_text[a_span[0]:a_span[1]])
    src_line = _after_node_src_line(after_stmt, a_starts, before_starts, dest_to_src)
    if src_line is None:
        return None
    return _best_stmt_span_at_line(m_root, m_text, m_starts,
                                   src_line + PREPROC_LINE_OFFSET, ref_text)

def parse_function_range(before_path: str, before_text: str, before_starts: List[int], func: str):
    """Locate `func`'s definition in the original source with srcML.

    Computed directly from `before_path` rather than read from metapro's
    patch-info.json: parse the file, find the <function> whose <name> is `func`,
    and take its source span -- from the start of its signature (column 0 for a
    top-level definition) through its closing `}` (the last character on the end
    line). srcML positions are 1-based line/col.

    Returns a triple:
      * (start_line, start_col, end_line, end_col) -- 1-based lines, 0-based start
        column and exclusive end column, in the same convention as _elem_span.
        The other coordinate systems follow from these without re-parsing: the
        after-patch line is recoverable from the diff hunks, and metapro-source
        sits a fixed PREPROC_LINE_OFFSET below the before line.
      * before_sliced_function -- `before_text` with every line outside the
        function blanked out (positions preserved, see _slice_function).
      * before_ast -- the srcML <function> Element itself, so callers can walk the
        function's subtree without writing the slice out and re-parsing it.
    Returns (None, None, None, None), None, None if the function is not found.
    """
    root = _srcml_root(before_path)
    for fn in root.iter(f'{{{_SRC_NS}}}function'):
        name = fn.find(f'{{{_SRC_NS}}}name')
        if name is None or ''.join(name.itertext()).strip() != func:
            continue
        span = _elem_span(fn, before_starts)
        if span:
            start_off, end_off, sline, scol, eline, ecol = span
            before_sliced_function = _slice_function(before_text, start_off, end_off)
            return (sline, scol, eline, ecol), before_sliced_function, fn

    print(f"Warning: function range not found for {func} in {before_path}")
    return (None, None, None, None), None, None


# A line that *opens* a C function definition: a return type then `name(` with no
# trailing `;` (so it is not a call/statement) and starting at column 0 (top-level).
# Best-effort -- per the step-by-step plan the result need not be exact.
_CTRL_KW = {'if', 'for', 'while', 'switch', 'return', 'sizeof', 'do', 'else'}
_FUNC_DEF_RE = re.compile(r'^[A-Za-z_][A-Za-z_0-9\s\*]*?\b([A-Za-z_]\w*)\s*\([^;]*$')
# A function-definition opening whose name sits on its own line, the return type
# having been written on the preceding line(s): `name(` flush at column 0 with no
# trailing `;` (so it is a definition, not a call/prototype statement). Complements
# _FUNC_DEF_RE, which requires the return type and name to share one line.
_FUNC_NAME_LINE_RE = re.compile(r'^([A-Za-z_]\w*)\s*\([^;]*$')


def _patched_function_names(diff_path: str, rel_path: str) -> List[str]:
    """Best-effort names of *every* function the diff patches in `rel_path`, in first-seen
    order (deduplicated).

    A file's diff can touch several functions -- e.g. a cosmetic reindent in one plus the
    real fix in another -- and each must be sliced and diffed on its own, so decide a name
    per hunk rather than only from the first. Per hunk: the git hunk-header context
    (`@@ ... @@ <tail>`) names the nearest *preceding* function, but a brand-new function
    definition in the hunk's leading context lines (at column 0) takes precedence, since the
    change is really inside it. Both signature shapes are recognised: the return type and
    name on one line (_FUNC_DEF_RE) and the name on its own line below the return type
    (_FUNC_NAME_LINE_RE). Not guaranteed exact."""
    names: List[str] = []
    in_file = False
    header_name = None
    body_def_name = None
    decided = True  # current hunk's name already recorded? (True until a hunk starts)
    for raw in _read_text(diff_path).splitlines():
        if raw.startswith('+++ '):
            p = raw[4:].split('\t')[0].strip()
            if p.startswith('b/'):
                p = p[2:]
            in_file = (p == rel_path)
            continue
        if not in_file or raw.startswith('--- ') or raw.startswith('diff '):
            continue
        if raw.startswith('@@'):
            tail = raw.split('@@')[-1].strip()
            m = re.search(r'([A-Za-z_]\w*)\s*\(', tail)
            header_name = m.group(1) if m else header_name
            body_def_name = None
            decided = False
            continue
        if decided:
            continue
        if raw[:1] in ('+', '-'):
            # First changed line of this hunk: its function name is settled now.
            name = body_def_name or header_name
            if name and name not in names:
                names.append(name)
            decided = True
            continue
        src_line = raw[1:] if raw[:1] == ' ' else raw  # drop the diff context marker
        m = _FUNC_DEF_RE.match(src_line) or _FUNC_NAME_LINE_RE.match(src_line)
        if m and m.group(1) not in _CTRL_KW:
            body_def_name = m.group(1)
    return names


def _patched_function_name(diff_path: str, rel_path: str):
    """The first function the diff patches in `rel_path` (see _patched_function_names)."""
    names = _patched_function_names(diff_path, rel_path)
    return names[0] if names else None


def _slice_function(text: str, start_off: int, end_off: int) -> str:
    """Blank out everything outside the function's [start_off, end_off) line range,
    replacing those lines with empty lines so the function keeps its original position
    (a function starting on line 100 stays on line 100, with lines 1-99 emptied). This
    lets srcML/GumTree parse only the function while every line and column still matches
    the full file -- so downstream offsets and reported positions need no translation."""
    starts = _line_starts(text)
    s_line = _off_to_linecol(starts, start_off)[0]
    e_line = _off_to_linecol(starts, max(start_off, end_off - 1))[0]
    s = starts[s_line - 1]
    e = starts[e_line] if e_line < len(starts) else len(text)
    # Keep one '\n' per removed line so line numbers (and total line count) are preserved.
    prefix = '\n' * text[:s].count('\n')
    suffix = '\n' * text[e:].count('\n')
    return prefix + text[s:e] + suffix


def slice_after_function(after_text: str, a_starts: List[int], hunks, out_path: str,
                         before_start_line: int, before_start_col: int,
                         before_end_line: int, before_end_col: int):
    """After-patch counterpart of parse_function_range, derived from the diff
    instead of a second full-file srcML parse.

    The signature and closing-brace lines move down by however many lines the
    diff adds (added minus removed) *above* them, so we map each before-patch
    boundary through the hunks. `hunks` are the (b_start, b_end, a_start, a_end)
    1-based inclusive ranges from _parse_unified_diff.

    We must NOT require a hunk to be *contained* in the function span: a unified
    diff carries context lines (typically 3), so a hunk patching the body has its
    before-range starting a few lines above the function signature and ending at
    or below the closing `}`. Treating that as "outside the function" leaves the
    end line unshifted and slices the function off mid-body (dropping the closing
    `}` and any statement the insertion pushed down). Instead, classify each hunk
    against the function span:

      * entirely above the function (b_end < start)  -> shifts both boundaries
        down (the whole function moved);
      * entirely below the function (b_start > end)  -> shifts neither;
      * overlapping the function                     -> its changes sit below the
        signature (leading context) and above the closing `}` (trailing context),
        so it shifts the end line but leaves the start line put.

    The sliced function is written to `out_path` and parsed with srcML, so the
    returned AST holds only the patched function (positions preserved, matching
    the full after-source coordinates) -- callers walk it instead of the whole
    after tree.

    Returns (start_line, start_col, end_line, end_col), after_sliced_function,
    after_ast -- the same shape as parse_function_range. Start/end columns are
    inherited from the before-patch span: the signature and closing-brace lines
    are not touched by the diff."""
    start_net = 0
    end_net = 0
    for hunk in hunks:
        b_start, b_end, a_start, a_end = hunk[:4]
        hunk_net = hunk[4] if len(hunk) > 4 else (a_end - a_start) - (b_end - b_start)
        if b_end < before_start_line:
            start_net += hunk_net
            end_net += hunk_net
        elif b_start > before_end_line:
            continue
        else:
            end_net += hunk_net
    start_line = before_start_line + start_net
    end_line = before_end_line + end_net
    start_off = a_starts[start_line - 1]
    end_off = a_starts[end_line] if end_line < len(a_starts) else len(after_text)
    after_sliced_function = _slice_function(after_text, start_off, end_off)
    with open(out_path, 'w') as f:
        f.write(after_sliced_function)
    after_ast = _srcml_root(out_path)
    return (start_line, before_start_col, end_line, before_end_col), after_sliced_function, after_ast


def slice_metapro_function(m_text: str, m_starts: List[int], out_path: str,
                           before_start_line: int, before_start_col: int,
                           before_end_line: int, before_end_col: int):
    """metapro-source counterpart of parse_function_range.

    metapro-source is the instrumented original and differs from source/ only by a
    single prepended line (PREPROC_LINE_OFFSET); instrumentation is inline and adds
    no lines, so the patched function occupies the same line range shifted down by
    that offset, and the structural start/end columns (signature / closing `}`)
    carry over unchanged.

    The sliced function is written to `out_path` and parsed with srcML, so the
    returned AST holds only the patched function (positions preserved, matching the
    full metapro-source coordinates the binary patcher expects) -- callers walk it
    instead of the whole, possibly huge, instrumented file.

    Returns (start_line, start_col, end_line, end_col), m_sliced_function, m_ast --
    the same shape as parse_function_range."""
    start_line = before_start_line + PREPROC_LINE_OFFSET
    end_line = before_end_line + PREPROC_LINE_OFFSET
    start_off = m_starts[start_line - 1]
    end_off = m_starts[end_line] if end_line < len(m_starts) else len(m_text)
    m_sliced_function = _slice_function(m_text, start_off, end_off)
    with open(out_path, 'w') as f:
        f.write(m_sliced_function)
    m_ast = _srcml_root(out_path)
    return (start_line, before_start_col, end_line, before_end_col), m_sliced_function, m_ast


def _derive_patches(workdir:str, diff_file_path: str, before_path: str, after_path: str, metapro_path: str,
                    rel_path: str, info: dict, loc_ids: Dict[str, int], macros=None, func_name=None):
    """Derive INSERT_EXPR and INSERT_NOT_NULL_CHECKER patches for one patched function.

    `func_name` selects the function to slice and diff (a file's diff may patch several --
    see _patched_function_names); it defaults to the first one the diff touches.

    * INSERT_EXPR -- a wholly new statement (GumTree `insert-tree` of a statement
      node). Located just before the original statement it anchors to (its nearest
      statement sibling in the after-tree, which skips blank/comment-only lines),
      mapped back to source via GumTree matches -- robust to whole-hunk reindentation.
    * INSERT_NOT_NULL_CHECKER -- a new `if (cond)` that *wraps* existing statements
      (GumTree `insert-node` of an if_stmt whose body statements are moved in, i.e.
      already present in source). `exprs` is the wrapping condition; the location
      spans the first wrapped statement's start to the last one's end.
    * REPLACE statement -- the original statement is deleted and a new statement is
      put in its place. GumTree matches the enclosing statement and reports the edit
      at expression granularity, so it is detected by walking up to the minimum
      enclosing statement (see _replaced_stmts). It is emitted as two patches sharing
      the original statement's location (and id): an INSERT_EXPR carrying the new
      statement, and an INSERT_NOT_NULL_CHECKER with a never-true `0` condition that
      wraps -- and thereby disables -- the original statement.

    Positions are read from metapro-source (closest-text statement on `source +1`).
    GumTree noise is dropped by requiring inserted text to appear among the diff's
    added lines. Patches at the same location share an id via `loc_ids`, so a replace
    expressed as INSERT_EXPR + INSERT_NOT_NULL_CHECKER at one spot gets one id.
    Returns (patches, num_skipped).
    """
    if func_name is None:
        func_name = _patched_function_name(diff_file_path, rel_path)
    before_text = _read_text(before_path)
    before_starts = _line_starts(before_text)
    start_time = time.time()
    ((before_func_start_line, before_func_start_col,
      before_func_end_line, before_func_end_col),
      before_sliced_function, before_ast) = parse_function_range(
        before_path,
        before_text,
        before_starts,
        func_name
    )
    if before_sliced_function is None:
        return [], 0  # function not located in source -> nothing to derive for it
    print(f'Parse srcML before-tree for {rel_path} in {time.time() - start_time:.1f}s')
    before_sliced_path = os.path.join(workdir, 'san2patch', f'before-{RESULT_TAG}.c')
    with open(before_sliced_path, 'w') as f:
        f.write(before_sliced_function)
    # _slice_function preserves srcML line/col but collapses each pre-function line to a
    # bare '\n', so char offsets shift. Rebuild the line-start table from the sliced text
    # so _elem_span / _off_to_linecol yield offsets into before_sliced_function -- the same
    # coordinates GumTree reports (it runs on before_sliced_path).
    before_starts = _line_starts(before_sliced_function)

    after_text = _read_text(after_path)
    a_starts = _line_starts(after_text)
    after_sliced_path = os.path.join(workdir, 'san2patch', f'after-{RESULT_TAG}.c')
    start_time = time.time()
    ((after_func_start_line, after_func_start_col,
      after_func_end_line, after_func_end_col),
     after_sliced_function, a_root) = slice_after_function(
        after_text, a_starts, info['hunks'], after_sliced_path,
        before_func_start_line, before_func_start_col,
        before_func_end_line, before_func_end_col)
    print(f'Parse srcML after-tree for {rel_path} in {time.time() - start_time:.1f}s')
    # Rebuild from the sliced text (see before_starts) -- matches the offsets GumTree
    # reports for the after tree (it runs on after_sliced_path).
    a_starts = _line_starts(after_sliced_function)

    pmap = _parent_map(a_root)
    m_text = _read_text(metapro_path)
    m_starts = _line_starts(m_text)
    metapro_sliced_path = os.path.join(workdir, 'san2patch', f'metapro-{RESULT_TAG}.c')
    start_time = time.time()
    ((metapro_func_start_line, metapro_func_start_col,
      metapro_func_end_line, metapro_func_end_col),
     m_sliced_function, m_root) = slice_metapro_function(
        m_text, m_starts, metapro_sliced_path,
        before_func_start_line, before_func_start_col,
        before_func_end_line, before_func_end_col)
    print(f'Parse srcML metapro-tree for {rel_path} in {time.time() - start_time:.1f}s')
    # Rebuild from the sliced text (see before_starts) so _elem_span / _best_stmt_span_at_line
    # index m_sliced_function consistently.
    m_starts = _line_starts(m_sliced_function)
    local_vars = _registered_var_names(m_sliced_function)

    start_time = time.time()
    actions, dest_to_src = _run_gumtree(before_sliced_path, after_sliced_path)
    print(f'GumTree diff for {rel_path} in {time.time() - start_time:.1f}s')
    a_ranges = [(h[2], h[3]) for h in info['hunks']]
    added = info['added']
    removed = info['removed']

    # Starts of statements GumTree reports as newly inserted, and the verbatim text of
    # every original statement -- used to tell a true replace from a pure insertion or
    # a statement merely relocated into a new wrapper (see _replaced_stmts).
    inserted_stmt_offsets = {a['start'] for a in actions
                             if a['action'] in ('insert-tree', 'insert-node')
                             and a['type'] in _STMT_TAGS}
    before_stmt_texts = set()
    for el in before_ast.iter():
        if _local_tag(el) in _STMT_TAGS:
            bspan = _elem_span(el, before_starts)
            if bspan:
                before_stmt_texts.add(_norm_tokens(before_sliced_function[bspan[0]:bspan[1]]))

    def in_hunk(off):
        return any(s <= _off_to_linecol(a_starts, off)[0] <= e for s, e in a_ranges)

    # After-tree offsets GumTree actually edited, taken from the edit script rather than
    # the diff hunk header -- robust to the applied patch landing a few lines off from its
    # header. Only insert/update actions carry a reliable after-tree position (inserts are
    # already in the after tree; an update is a matched node, mapped back through the
    # matches). delete/move actions reference before-tree offsets with no meaningful after
    # position and are skipped -- otherwise a body deletion's before offset can fall inside
    # an unrelated after-tree condition span.
    src_to_dest = {v: k for k, v in dest_to_src.items()}
    changed_after_offs = set()
    for a in actions:
        if a['action'].startswith('insert'):
            changed_after_offs.add(a['start'])
        elif a['action'].startswith('update'):
            d = src_to_dest.get(a['start'])
            if d is not None:
                changed_after_offs.add(d)

    def metapro_span(stmt):
        return _metapro_span_for(stmt, after_sliced_function, a_starts, before_starts,
                                 dest_to_src, m_root, m_sliced_function, m_starts)

    # m_root holds only the patched function (sliced), so the enclosing function is the
    # same for every INSERT/REMOVE patch -- resolve its name once instead of re-walking
    # the tree per action. (REPLACE_CONDITION reads its function from the cond wrapper.)
    func = _enclosing_function(m_root, m_starts,
                               m_starts[metapro_func_start_line - 1] + metapro_func_start_col)

    patches = []
    skipped = 0
    # After-tree offsets of body statements already emitted as a wrap-with-edit replace (the
    # whole enclosing `if` was inserted over them); the replace pass must not re-emit them.
    wrap_replaced_offsets = set()
    start_time = time.time()
    for act in actions:
        # --- INSERT_NOT_NULL_CHECKER: a new `if` that wraps existing statements -----
        # A wrap moves *pre-existing* statements into a new `if (cond)`, so its body maps back
        # to source. A new `if` with a *new* body -- e.g. a guard `if (...) { res = ...; goto
        # done; }` -- does not; GumTree still reports it as an insert-node if_stmt (some child,
        # like a moved sub-expression in the condition, keeps it from being an insert-tree),
        # but it is a wholly new statement. So only take the wrap path when the body is
        # mappable; otherwise fall through to the INSERT_EXPR path below.
        if act['action'] == 'insert-node' and act['type'] == 'if_stmt' and in_hunk(act['start']):
            if_el = _find_elem_by_span(a_root, act['start'], 'if_stmt', a_starts)
            cond = _if_condition_text(if_el, after_sliced_function, a_starts) if if_el is not None else None
            body = _if_body_stmts(if_el) if if_el is not None else []
            # How each wrapped statement relates to the original source picks the shape. A body
            # statement is `wrapped` if it closely matches some original (>= _WRAP_MATCH_RATIO)
            # and `unchanged` if its tokens match one exactly. metapro_span fuzzy-matches even a
            # wholly new body statement to the nearest source line, so first_span/last_span
            # alone cannot tell a wrap from a new guard `if`; the ratios do. (The `added` set is
            # no discriminator either: wrapping re-indents the moved statement, so its
            # normalized line also appears among the added lines.) The location spans the first
            # body statement's start to the last body statement's end.
            #   * every body stmt unchanged  -> genuine wrap: guard them in place with an
            #     INSERT_NOT_NULL_CHECKER(cond) (the body text is untouched).
            #   * every body stmt wrapped but >=1 edited (e.g. a cast dropped) -> the wrap also
            #     rewrites the body, so a bare guard would lose the edit; model it as a replace
            #     -- insert the whole new `if` over, and disable, the original statement(s).
            #   * some body stmt matches no original -> a new guard `if` with a new body (e.g.
            #     `if (n > 0) { p[n] = 0; } else { p[0] = 0; }`): fall through to INSERT_EXPR.
            body_spans = [_elem_span(b, a_starts) for b in body]
            body_all_exact = bool(body) and all(
                _norm_tokens(''.join(b.itertext())) in before_stmt_texts for b in body)
            # A body statement is a *matched* pre-existing node when GumTree mapped its start
            # back to the original (`dest_to_src`) -- exactly what _replaced_stmts keys on. A
            # relocated-and-edited statement is matched; wholly new body code is an unmatched
            # insert. (A raw text ratio is unreliable: a new `obj->p[n] = 0;` guard body can
            # coincidentally resemble an unrelated existing assignment.)
            body_matched = bool(body) and all(
                sp is not None and sp[0] in dest_to_src for sp in body_spans)
            first_span = metapro_span(body[0]) if body else None
            last_span = metapro_span(body[-1]) if body else None
            if (cond and cond in added and body and func is not None
                    and first_span is not None and last_span is not None
                    and (body_all_exact or body_matched)):
                loc = {'function': func, 'file': rel_path,
                       'line': first_span[2], 'col': first_span[3],
                       'end_line': last_span[4], 'end_col': last_span[5] + 1}
                if body_all_exact:
                    # genuine wrap: the body is untouched, so guard it in place.
                    patches.append({'template': 'INSERT_NOT_NULL_CHECKER', **loc,
                                    'exprs': [_escape_expr(cond, macros, local_vars)]})
                else:
                    # wrap-with-edit: the body was relocated *and* rewritten (e.g. a cast
                    # dropped), so a bare guard would lose the edit -- the whole new `if`
                    # replaces the original body statement(s).
                    whole = _strip_blacklisted_calls(_norm(
                        after_sliced_function[act['start']:act['end']]))
                    if whole:
                        patches.append({'template': 'INSERT_EXPR', **loc,
                                        'exprs': [_escape_expr(_insert_expr_text(whole), macros, local_vars)]})
                    patches.append({'template': 'INSERT_NOT_NULL_CHECKER', **loc, 'exprs': ['0']})
                    # The body statements are the replaced originals; do not let the replace
                    # pass re-emit them as separate (inner) replacements.
                    for sp in body_spans:
                        if sp is not None:
                            wrap_replaced_offsets.add(sp[0])
                continue
            # not a wrap of existing statements -> fall through to INSERT_EXPR (a new if).

        # --- INSERT_EXPR: a wholly new statement ------------------------------------
        # `insert-tree` is a statement added whole; `insert-node` is a statement node added
        # with some child moved into it -- e.g. a new `int x = <expr>;` declaration that
        # re-homes an existing sub-expression (GumTree reports the decl_stmt as insert-node,
        # not insert-tree), or a new guard `if` whose condition reuses a moved sub-expression.
        # Its full text still sits verbatim in the after source, so it is emitted the same way.
        # (An `insert-node if_stmt` that *wraps existing statements* is the NOT_NULL_CHECKER
        # case handled above, which `continue`s before reaching here.)
        if act['action'] in ('insert-tree', 'insert-node') and act['type'] in _STMT_TAGS:
            if not in_hunk(act['start']):
                continue  # GumTree noise outside the changed region
            raw = after_sliced_function[act['start']:act['end']]
            text = _norm(raw)
            # Keep only code the diff actually added. `text in added` is the exact test, but
            # git diff can mark an interior line of a genuinely new block as *context* when it
            # matches a nearby line (e.g. the guard's `break;` aligned with an existing one),
            # so the statement is not one contiguous run of `+` lines even though GumTree
            # reports the whole subtree as inserted. Fall back to requiring every one of its
            # lines to appear among the added lines individually -- interior context-marked
            # lines are then tolerated, while a line the diff never added still rejects it.
            stmt_lines = [ln for ln in (_norm(l) for l in raw.split('\n')) if ln]
            if not text or (text not in added
                            and not all(ln in added for ln in stmt_lines)):
                skipped += 1  # not part of the code the diff actually added
                continue
            elem = _find_elem_by_span(a_root, act['start'], act['type'], a_starts)
            anchor = (_adjacent_stmt(pmap, elem, forward=True, starts=a_starts,
                                     skip_offsets=inserted_stmt_offsets)
                      if elem is not None else None)
            insert_after = False
            if anchor is None and elem is not None:
                anchor = _adjacent_stmt(pmap, elem, forward=False, starts=a_starts,
                                        skip_offsets=inserted_stmt_offsets)
                insert_after = True
            if anchor is None:
                skipped += 1
                continue
            span = metapro_span(anchor)
            if span is None:
                skipped += 1
                continue
            if func is None:
                skipped += 1
                continue
            if insert_after:
                # Insert *after* the original statement: anchor at its end, not its
                # start, so the new statement lands behind it. Zero-width (start ==
                # end) marks an after-insertion rather than a span to replace.
                line, col = span[4], span[5] + 1
                end_line, end_col = line, col
            else:
                line, col = span[2], span[3]
                end_line, end_col = span[4], span[5] + 1
            clean = _strip_blacklisted_calls(text)
            if not clean:
                # nothing but a blacklisted (log/print) call -- drop the patch entirely
                continue
            expr = _insert_expr_text(clean)
            patches.append({
                'template': 'INSERT_EXPR',
                'function': func,
                'file': rel_path,
                'line': line,
                'col': col,
                'exprs': [_escape_expr(expr, macros, local_vars)],
                'end_line': end_line,
                'end_col': end_col,
            })
            continue

        skipped += 1

    # --- REPLACE statement: original statement deleted, new statement put in its place.
    # Modelled at the *statement* level (GumTree diffs the rewrite at expression level,
    # so we anchor on the minimum enclosing statement). Each replace yields an
    # INSERT_EXPR (the new statement) plus an INSERT_NOT_NULL_CHECKER with a never-true
    # `0` condition (wraps and disables the original); both share the original
    # statement's location, so they also share an id.
    for stmt, span in _replaced_stmts(a_root, after_sliced_function, a_starts, dest_to_src,
                                      added, in_hunk,
                                      inserted_stmt_offsets | wrap_replaced_offsets,
                                      before_stmt_texts):
        # If the replace hits a control statement (for/while/do/switch) whose header is
        # textually unchanged and only its body was rewritten, patch the body -- not the whole
        # statement -- so the loop/switch header stays in place. Disable the original body
        # statement(s) and insert the new body block at their location. The header is unchanged
        # when no GumTree edit falls inside its <control>/<condition> span.
        if _local_tag(stmt) in _CONTROL_BODY_TAGS and func is not None:
            hspan, block = _control_parts(stmt, a_starts)
            bspan = _elem_span(block, a_starts) if block is not None else None
            if (hspan is not None and bspan is not None
                    and not any(hspan[0] <= o < hspan[1] for o in changed_after_offs)):
                # Original body statements are the pre-existing (matched) ones still inside the
                # rewritten body; their metapro span is where the body lived.
                orig = []
                for s in block.iter():
                    if _local_tag(s) not in _STMT_TAGS:
                        continue
                    ssp = _elem_span(s, a_starts)
                    if ssp and ssp[0] in dest_to_src:
                        orig.append(s)
                first = metapro_span(orig[0]) if orig else None
                last = metapro_span(orig[-1]) if orig else None
                if first is not None and last is not None:
                    loc_fields = {'function': func, 'file': rel_path,
                                  'line': first[2], 'col': first[3],
                                  'end_line': last[4], 'end_col': last[5] + 1}
                    clean = _strip_blacklisted_calls(
                        _norm(after_sliced_function[bspan[0]:bspan[1]]))
                    if clean:
                        patches.append({'template': 'INSERT_EXPR', **loc_fields,
                                        'exprs': [_escape_expr(_insert_expr_text(clean), macros, local_vars)]})
                    patches.append({'template': 'INSERT_NOT_NULL_CHECKER', **loc_fields,
                                    'exprs': ['0']})
                    continue
        m_span = metapro_span(stmt)
        if m_span is None:
            skipped += 1
            continue
        if func is None:
            skipped += 1
            continue
        text = _norm(after_sliced_function[span[0]:span[1]])
        line, col, end_line, end_col = m_span[2], m_span[3], m_span[4], m_span[5] + 1
        loc_fields = {'function': func, 'file': rel_path, 'line': line, 'col': col,
                      'end_line': end_line, 'end_col': end_col}
        # Insert the replacement statement -- unless it was nothing but a blacklisted
        # (log/print) call, in which case the replace degrades to a plain removal (the
        # disabling INSERT_NOT_NULL_CHECKER "0" below still fires).
        clean = _strip_blacklisted_calls(text)
        if clean:
            patches.append({'template': 'INSERT_EXPR', **loc_fields,
                            'exprs': [_escape_expr(_insert_expr_text(clean), macros, local_vars)]})
        patches.append({'template': 'INSERT_NOT_NULL_CHECKER', **loc_fields, 'exprs': ['0']})

    print(f'Derived INSERT patches for {rel_path} in {time.time() - start_time:.1f}s')

    # --- REMOVE statement: a statement deleted outright from its block (no replacement).
    # GumTree reports it as a `delete-tree` (subtree gone whole) or a `delete-node` (the node
    # deleted with some child moved out -- mirroring the insert-tree/insert-node pair) of a
    # statement node in the *before* tree. We disable it in place with a single
    # INSERT_NOT_NULL_CHECKER whose condition is the never-true `0` (wrapping the original in
    # `if (0) { ... }`). The location is read from metapro-source by mapping the deleted
    # statement's source line (+1) and picking the closest-text statement there. Only
    # outermost deletes are kept (a delete already covers its descendants), and the whole
    # statement text must appear among the diff's removed lines -- the mirror of the
    # INSERT_EXPR `added` gate. That gate also excludes an *unwrap* (e.g. an `if` removed but
    # its body kept in place): the body lines are not removed, so the statement's full text is
    # not entirely in `removed` and it is not disabled here.
    start_time = time.time()
    _DELETE_ACTIONS = ('delete-tree', 'delete-node')
    deleted = []
    for act in actions:
        if act['action'] not in _DELETE_ACTIONS or act['type'] not in _STMT_TAGS:
            continue
        if any(o is not act and o['start'] <= act['start'] and act['end'] <= o['end'] and
               (o['end'] - o['start']) > (act['end'] - act['start'])
               for o in actions
               if o['action'] in _DELETE_ACTIONS and o['type'] in _STMT_TAGS):
            continue  # contained in a larger deleted statement -> keep only the outermost
        deleted.append(act)
    for act in deleted:
        ref_text = _norm(_clip_trailing_cpp(before_sliced_function[act['start']:act['end']]))
        if not ref_text or ref_text not in removed:
            skipped += 1  # not part of the code the diff actually removed
            continue
        src_line = _off_to_linecol(before_starts, act['start'])[0]
        m_span = _best_stmt_span_at_line(m_root, m_sliced_function, m_starts,
                                         src_line + PREPROC_LINE_OFFSET, ref_text)
        if m_span is None:
            skipped += 1
            continue
        if func is None:
            skipped += 1
            continue
        # srcML can overshoot a block statement's end by swallowing a trailing cpp
        # directive (e.g. #endif); trim it back to where the deleted statement text ends.
        end = _ref_end_linecol(m_sliced_function, m_starts, m_span[0], ref_text)
        end_line, end_col = end if end is not None else (m_span[4], m_span[5] + 1)
        patches.append({
            'template': 'INSERT_NOT_NULL_CHECKER',
            'function': func,
            'file': rel_path,
            'line': m_span[2],
            'col': m_span[3],
            'exprs': ['0'],
            'end_line': end_line,
            'end_col': end_col,
        })

    print(f'Derived REMOVE patches for {rel_path} in {time.time() - start_time:.1f}s')

    # --- REPLACE_CONDITION: an if/while/for condition was rewritten -- either a new
    # sub-condition inserted before/after the original with `&&`/`||` (pattern #2) or the
    # whole condition replaced (pattern #1). metapro has already wrapped each condition in
    # __metapro_replace_cond_c(id, "orig", ...), so that call supplies the patch id,
    # function and source location; the new condition (and any operator) is recovered by
    # comparing the rewritten after-source condition against the wrapper's original. The
    # id is the metapro one (not a location-derived id), so it is set here and left
    # untouched below.
    #
    # A condition is a candidate only when a GumTree edit falls inside the <condition>
    # expression itself -- not merely somewhere in the if/while/for block, whose span
    # also covers the body (a body edit must not be read as a condition rewrite). We must
    # NOT key on the diff hunk range either: the change can sit on the enclosing `if` line
    # just outside the header's reported span. A newly inserted `if` (INSERT_NOT_NULL_-
    # CHECKER / INSERT_EXPR territory) has no original to replace, so it is excluded. The
    # wrapper-text comparison below is the final precise test. Collect first, then read
    # wrappers only on the mapped metapro lines (so when no condition changed we never
    # walk the metapro tree for wrappers).
    start_time = time.time()
    cond_changes = []  # (new_cond, metapro_line)
    for el in a_root.iter():
        if _local_tag(el) not in _CONDITION_TAGS:
            continue
        a_span = _elem_span(el, a_starts)
        if not a_span or a_span[0] in inserted_stmt_offsets:
            continue
        # An if/else-if chain is one <if_stmt> with a <condition> per branch (each on its own
        # source line, so each has its own metapro wrapper); a while/for/do has a single
        # condition. Examine each branch on its own -- keying only on the first would miss a
        # rewrite in an else-if. The owner element (the <if> branch, or the statement itself)
        # supplies both the branch condition and the source line to map.
        if _local_tag(el) == 'if_stmt':
            owners = [b for b in el if _local_tag(b) in ('if', 'elseif')]
        else:
            owners = [el]
        for owner in owners:
            cond_el = next(owner.iter(f'{{{_SRC_NS}}}condition'), None)
            cspan = _elem_span(cond_el, a_starts) if cond_el is not None else None
            if not cspan or not any(cspan[0] <= o < cspan[1] for o in changed_after_offs):
                continue
            new_cond = _condition_expr_text(owner, after_sliced_function, a_starts)
            if not new_cond:
                continue
            src_line = _after_node_src_line(owner, a_starts, before_starts, dest_to_src)
            if src_line is None:
                continue
            cond_changes.append((new_cond, src_line + PREPROC_LINE_OFFSET))

    if cond_changes:
        cond_wrappers = _cond_wrappers(m_root, m_starts,
                                       {m_line for _, m_line in cond_changes})
        used_wrapper_ids = set()
        for new_cond, m_line in cond_changes:
            for w in cond_wrappers:
                if w['span'][2] != m_line or w['id'] in used_wrapper_ids:
                    continue
                exprs = _replace_cond_exprs(new_cond, w['orig'])
                if exprs is None:
                    continue
                sp_ = w['span']
                patches.append({
                    'id': w['id'],
                    'template': 'REPLACE_CONDITION',
                    'function': w['func'],
                    'file': rel_path,
                    'line': sp_[2],
                    'col': sp_[3],
                    'exprs': [_escape_expr(e, macros, local_vars) for e in exprs],
                    'end_line': sp_[4],
                    'end_col': sp_[5] + 1,
                })
                used_wrapper_ids.add(w['id'])
                break

    print(f'Derived REPLACE_CONDITION patches for {rel_path} in {time.time() - start_time:.1f}s')

    # Several statements inserted at one point (e.g. a guard, a new declaration and a clamp
    # added together) are emitted as one INSERT_EXPR per statement, all at the same location.
    # But the patcher carries a template's expression in a single per-id env slot and shares
    # the id across a location (see below / test_poc), so those would clobber one another --
    # only the last statement would survive. Collapse each group into one patch: the inserted
    # statements become a single braced compound, and multiple not-null checkers become one
    # combined condition.
    patches = _coalesce_same_location(patches, 'INSERT_EXPR', _merge_insert_exprs)
    patches = _coalesce_same_location(patches, 'INSERT_NOT_NULL_CHECKER', _merge_checker_conds)

    # Assign ids: same location (function/file/span) -> same id, so an INSERT_EXPR
    # and an INSERT_NOT_NULL_CHECKER targeting one spot share it. REPLACE_CONDITION
    # keeps the metapro wrapper id it was already given.
    for p in patches:
        if p['template'] == 'REPLACE_CONDITION':
            continue
        p['id'] = loc_ids.setdefault(_patch_location_key(p), len(loc_ids) + 1)
    return patches, skipped


def _diff_to_config(output_log:TextIO, diff_file_path: str, orig_dir: str, patched_dir: str,
                    metapro_dir: str, project: str, bug_id: int) -> List[dict]:
    """Apply the diff onto `patched_dir` (san2patch-source), AST-diff each changed
    file against `orig_dir` (source), derive INSERT_EXPR patches with positions read
    from `metapro_dir` (metapro-source), then always revert `patched_dir`."""
    files = _parse_unified_diff(diff_file_path)
    if not files:
        print(f'[{project}-{bug_id}] no hunks in {os.path.basename(diff_file_path)}',
              file=output_log, flush=True)
        return []

    abs_diff = os.path.abspath(diff_file_path)
    config: List[dict] = []
    # The diff was produced against the pristine source/, so restore every file it touches in
    # san2patch-source from source/ before applying. san2patch-source can be left dirty by an
    # earlier build/patch, which would make `git apply` fail; every touched file is reverted the
    # same way in `finally`, so each patch is derived from a clean base.
    touched = [(os.path.join(orig_dir, rel), os.path.join(patched_dir, rel)) for rel in files]
    for src, dst in touched:
        if os.path.exists(src):
            shutil.copy(src, dst)
    try:
        # san2patch emits zero-context diffs (`@@ -166 +166,2 @@` with no surrounding lines),
        # which `git apply` rejects unless told to expect them with --unidiff-zero. The base was
        # just restored from source/, so the hunks' line numbers land exactly.
        res = sp.run(['git', '-C', patched_dir, 'apply', '--unidiff-zero', '--ignore-whitespace',
                      abs_diff], capture_output=True, text=True)
        if res.returncode != 0:
            print(f'[{project}-{bug_id}] git apply onto san2patch-source failed: {res.stderr[:300]}',
                  file=output_log, flush=True)
            return []

        loc_ids: Dict[str, int] = {}  # location key -> id, shared so same spot shares id
        # Preprocessor macro table (metapro-out/macros.json) -- resolves macros / enum
        # constants in emitted patch text so the binary patcher (no preprocessor) sees the
        # real expression. Absent table -> {} -> expansion is skipped. CUSTOM_MACROS overlaid.
        macros = _load_macro_table(os.path.join(
            ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id),
            'metapro-out', 'macros.json'))
        _apply_custom_macros(macros)
        for rel, info in files.items():
            before = os.path.join(orig_dir, rel)
            after = os.path.join(patched_dir, rel)
            metapro = os.path.join(metapro_dir, rel)
            if not all(os.path.exists(p) for p in (before, after, metapro)):
                print(f'[{project}-{bug_id}] missing source for {rel}, skipping',
                      file=output_log, flush=True)
                continue
            # A file's diff can patch several functions (e.g. a cosmetic reindent in one and
            # the real fix in another); slice and diff each on its own so none is missed.
            func_names = _patched_function_names(diff_file_path, rel) or [None]
            patches, skipped = [], 0
            try:
                for fname in func_names:
                    fp, fs = _derive_patches(
                        os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id)),
                        diff_file_path,
                        before, after, metapro, rel, info, loc_ids, macros, fname)
                    patches.extend(fp)
                    skipped += fs
            except Exception as e:  # parser/tool failure on one file shouldn't kill the rest
                print(f'[{project}-{bug_id}] {rel}: AST diff failed: {e}', file=output_log, flush=True)
                continue
            if skipped:
                print(f'[{project}-{bug_id}] {rel}: skipped {skipped} unhandled action(s)',
                      file=output_log, flush=True)
            config.extend(patches)
    finally:
        for src, dst in touched:
            if os.path.exists(src):
                shutil.copy(src, dst)
    return config


# Patch-template usage reporting
_INSERTION_TEMPLATES = ('INSERT_EXPR', 'INSERT_NOT_NULL_CHECKER')

# Bucket names of the tally dict patch_template_usage_tally() increments -- also the result
# JSON / CSV field names.
PATCH_TEMPLATE_USAGE_COUNTERS = ('condition replace', 'insert', 'both')


def patch_template_usage(patch_config: Optional[List[dict]]) -> str:
    """Classify one derived config by the patch templates it uses, in san2patch's own
    'both'/'replace'/'insert'/'-' convention (see the module comment above): 'both' when it
    uses REPLACE_CONDITION and an insertion template, 'replace' or 'insert' when only one, '-'
    when the config is empty / was not derived."""
    templates = {p.get('template') for p in (patch_config or [])}
    has_replace = 'REPLACE_CONDITION' in templates
    has_insert = any(t in templates for t in _INSERTION_TEMPLATES)
    if has_replace and has_insert:
        return 'both'
    if has_replace:
        return 'replace'
    if has_insert:
        return 'insert'
    return '-'


def patch_template_usage_tally(counts: Dict[str, int], usage: str) -> None:
    """Increment the bucket of `counts` (keys PATCH_TEMPLATE_USAGE_COUNTERS) matching one
    config's `usage` label (see patch_template_usage). `counts` should be seeded with each
    counter at 0."""
    if usage == 'replace':
        counts['condition replace'] += 1
    elif usage == 'insert':
        counts['insert'] += 1
    elif usage == 'both':
        counts['both'] += 1


def gen_patch_config(output_log:TextIO, project:str, bug_id:int, diff_file_path:str,
                     source_path:str, binary:str, config_output_path:str,
                     run_test_poc:bool = True, expect_test_fail = False,
                     prev_location:List[dict] = None,
                     run_func_test: bool = False):
    """Deterministically turn one diff into a patch config (no LLM, no feedback loop).

    The config is derived by AST-diffing the original source (``source/``) against
    the patched source (``san2patch-source/`` with the diff applied) via GumTree +
    srcML to identify the fix, then mapping each location into the instrumented
    ``metapro-source/`` (source line + 1) to read the preprocessed coordinates the
    binary patcher expects. The config is then applied with the binary patcher and,
    when expected to pass, checked against the PoC -- each exactly once.
    """
    project_workdir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    orig_dir = os.path.join(project_workdir, 'source')
    patched_dir = os.path.join(project_workdir, 'san2patch-source')
    metapro_dir = source_path  # metapro-source (instrumented); positions are read from here
    os.makedirs(_patch_out_dir(project_workdir), exist_ok=True)

    print(f'[{project}-{bug_id}] generating patch config from {os.path.basename(diff_file_path)}',
          file=sys.stderr, flush=True)
    print(f'[{project}-{bug_id}] generating patch config from {os.path.basename(diff_file_path)}',
          file=output_log, flush=True)

    patch_time = 0.
    test_time = 0.

    # Stage 1: derive the patch config from the AST diff.
    start_time = time.time()
    try:
        patch_config = _diff_to_config(output_log, diff_file_path, orig_dir, patched_dir, metapro_dir, project, bug_id)
    except Exception:
        traceback.print_exc()
        return False, time.time() - start_time, patch_time, test_time, 'N/A', '-', '-', None, dict()
    parse_time = time.time() - start_time

    if not patch_config:
        print(f'[{project}-{bug_id}] no patch derived from {os.path.basename(diff_file_path)}',
              file=output_log, flush=True)
        print(f'[{project}-{bug_id}] no patch derived from {os.path.basename(diff_file_path)}',
              file=sys.stderr, flush=True)
        return False, parse_time, patch_time, test_time, 'N/A', '-', '-', None, dict()

    # Reconcile against locations patched by previous patches. For each patch whose
    # location matches one already patched, reuse the previous patch ID (so the
    # config stays consistent). If *every* location was already patched, there is
    # nothing new to apply -- skip the patch/test stages.
    skip_patch = False
    if prev_location is not None:
        prev_id_by_loc = {_patch_location_key(p): p['id'] for p in prev_location}
        reserved_ids = set(prev_id_by_loc.values())
        skip_patch = len(patch_config) > 0
        for patch_entry in patch_config:
            patch_loc = _patch_location_key(patch_entry)
            prev_id = prev_id_by_loc.get(patch_loc)
            if prev_id is None:
                # New location -- this config has something to patch.
                skip_patch = False
            elif patch_entry['id'] != prev_id:
                # Same location, different ID: align with the previous patch. The ID
                # we are taking over may already belong to a *different* location in
                # this config -- move that patch to a fresh, unused ID so distinct
                # locations never share an ID.
                for other in patch_config:
                    if (other is not patch_entry and other['id'] == prev_id and
                            _patch_location_key(other) != patch_loc):
                        other['id'] = _next_free_id(patch_config, reserved_ids)
                patch_entry['id'] = prev_id

    with open(config_output_path, 'w') as f:
        json.dump(patch_config, f, indent=4)

    # Stage 2: apply the patch with the binary patcher.
    if not skip_patch:
        patch_ok, patch_time = patch(project, bug_id, binary, config_output_path)
        if not patch_ok:
            print(f'[{project}-{bug_id}] failed to patch', file=output_log, flush=True)
            print(f'[{project}-{bug_id}] failed to patch', file=sys.stderr, flush=True)
            return False, parse_time, patch_time, test_time, 'N/A', '-', '-', None, dict()
    else:
        # Copy the original binary to the patched location, so the test stage runs on the
        # shutil.copy(os.path.join(project_workdir, 'metapro-out', 'bin', binary),
        shutil.copy(os.path.join(project_workdir, 'metapro-out', 'asan-bin', binary),
                    os.path.join(_patch_out_dir(project_workdir), f'{binary}.inst'))
        patch_time = 0.000000001 # Small time to avoid '-'

    # Stage 3: run the PoC test against the patched binary -- but only when the patch
    # is expected to pass it. For patches san2patch did not deem plausible
    # (run_test_poc=False), the parseable + patchable config is the final result.
    if run_test_poc:
        test_ok, test_time, _ = test_poc(output_log, project, bug_id, binary, config_output_path, expect_fail=expect_test_fail)
        # Run with count_interpreter=True to gather interpreter usage statistics
        _, _, interpreter_usage = test_poc(output_log, project, bug_id, binary, config_output_path, expect_fail=expect_test_fail, count_interpreter=True)
        if test_time == 300.:
            # Timeout, reset
            test_time = 0.
        if not test_ok:
            print(f'[{project}-{bug_id}] failed PoC test', file=sys.stderr, flush=True)
            print(f'[{project}-{bug_id}] failed PoC test', file=output_log, flush=True)
            return False, parse_time, patch_time, test_time, 'N/A', '-', '-', None, dict()

    # State 4: run the functional test
    if run_func_test:
        test_ok, func_patch_time, func_test_time = test_functional(output_log, project, bug_id, config_output_path)
        if not test_ok:
            print(f'[{project}-{bug_id}] failed functional test', file=sys.stderr, flush=True)
            print(f'[{project}-{bug_id}] failed functional test', file=output_log, flush=True)
            return True, parse_time, patch_time, test_time, False, func_patch_time, func_test_time, patch_config, interpreter_usage
        else:
            print(f'[{project}-{bug_id}] functional test succeeded', file=sys.stderr, flush=True)
            print(f'[{project}-{bug_id}] functional test succeeded', file=output_log, flush=True)
            return True, parse_time, patch_time, test_time, True, func_patch_time, func_test_time, patch_config, interpreter_usage
    else:
        print(f'[{project}-{bug_id}] patch config succeeded', file=sys.stderr, flush=True)
        print(f'[{project}-{bug_id}] patch config succeeded', file=output_log, flush=True)
        return True, parse_time, patch_time, test_time, 'N/A', '-', '-', patch_config, interpreter_usage


def preprocess_patcher(project:str, bug_id:int, binary:str):
    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))

    # Reset san2patch-source
    if os.path.exists(os.path.join(container_work_dir, 'san2patch-source')):
        shutil.rmtree(os.path.join(container_work_dir, 'san2patch-source'))
    shutil.copytree(os.path.join(container_work_dir, 'source'),
                    os.path.join(container_work_dir, 'san2patch-source'))

    docker.exec_docker_cmd(['cp', '/root/project/metac/metapro/src/binary/patcher-e9patch.py',
                            '/usr/local/bin/patcher-e9patch.py'], bug_id, cwd=container_work_dir)
    docker.exec_docker_cmd(['chmod', '+x', '/usr/local/bin/patcher-e9patch.py'], bug_id, cwd=container_work_dir)
    
    # With E9Patch, we do not need to preprocess
    # cmd = ['binary_prep.py', os.path.join(container_work_dir, 'metapro-out', 'bin', binary)]
    # res = docker.exec_docker_cmd(cmd, bug_id, cwd=container_work_dir,
    #                              get_output=os.path.join(container_work_dir, 'binary_prep.log'))
    return True

# ---------------------------------------------------------------------------
# php-src's OSS-Fuzz ASan fuzzer binaries crash at load time -- before running any
# code, patched or not -- with `symbol lookup error: undefined symbol: X` for a small,
# fixed set of X's (__isoc99_printf and its v*/f*/s*printf siblings; xdr_destroy;
# __cxa_rethrow_primary_exception). Confirmed by testing (a) that this reproduces
# identically on the completely unpatched `metapro-out/asan-bin` binary -- a pre-existing
# defect in that build artifact, not something metapro/e9patch introduces -- and (b) that
# san2patch's own validator instead rebuilds from source on every attempt via build.py,
# *without* going through metapro-tcc/metapro-tcxx, hence its original run for a bug like
# this succeeds. The actual root cause (confirmed via the real instrumented link command
# in metapro-out/build-san.log, and by reproducing the plain duplicate-symbol pattern
# harmlessly in an isolated test binary): php-src's own build links the ASan runtime
# archive redundantly (`-fsanitize=address`/`-fsanitize=fuzzer-no-link` appear twice in
# its own generated link line), which leaves duplicate entries for every ASan-intercepted
# libc/libstdc++ symbol in the binary's dynamic symbol table (confirmed via
# `readelf --dyn-syms`: e.g. `__isoc99_printf` and its interceptor alias each appear at
# two separate symbol-table indices, same address) -- but that alone is harmless (a
# from-scratch reproduction with the identical duplicate flags still runs fine). What
# actually breaks resolution is `-rdynamic`, which metapro-tcc/metapro-tcxx add to every
# link (so the runtime can dlsym() a patched function's callee instead of needing its
# address at compile time, see below): promoting the duplicated symbols into the *dynamic*
# symbol table is what makes the dynamic linker's `_dl_lookup_symbol_x` choke on them at
# load/first-call time, where san2patch's plain (non-metapro, non-`-rdynamic`) rebuild
# never exposes them dynamically at all.
#
# Two of the three (`__isoc99_printf`-family, `xdr_destroy`) are safe to reimplement
# directly (thin wrappers over the real vprintf/vfprintf/vsprintf/vsnprintf, or the
# standard portable xdr_destroy body via <rpc/xdr.h>). `__cxa_rethrow_primary_exception`
# touches libstdc++'s internal exception-object bookkeeping, too risky to reimplement by
# hand; instead it forwards (via dlsym(RTLD_DEFAULT, ...)) to the binary's own
# `__interceptor___cxa_rethrow_primary_exception`, which -- despite the bare name failing
# to resolve -- does resolve under dlsym, and is compiler-rt's own correct implementation
# anyway. All three verified end to end: with this shim preloaded, php-src's real
# instrumented `metapro-out/asan-bin/php-fuzz-parser` runs libFuzzer normally, and running
# a real PoC through it reproduces the actual ASan crash report instead of failing at load.
#
# Preloading a tiny shim that actually defines/forwards the missing symbols gives the
# dynamic linker an unambiguous provider to bind to instead of the broken duplicated ones,
# sidestepping the defect without touching the frozen binary itself or metapro-tcc's own
# (functionally necessary) `-rdynamic`.
# ---------------------------------------------------------------------------
_PHP_SRC_COMPAT_SHIM_SRC = '''#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <rpc/xdr.h>

int __isoc99_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vprintf(format, args);
    va_end(args);
    return ret;
}

int __isoc99_fprintf(FILE *stream, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vfprintf(stream, format, args);
    va_end(args);
    return ret;
}

int __isoc99_sprintf(char *str, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vsprintf(str, format, args);
    va_end(args);
    return ret;
}

int __isoc99_snprintf(char *str, size_t size, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(str, size, format, args);
    va_end(args);
    return ret;
}

int __isoc99_vprintf(const char *format, va_list args) {
    return vprintf(format, args);
}

int __isoc99_vfprintf(FILE *stream, const char *format, va_list args) {
    return vfprintf(stream, format, args);
}

int __isoc99_vsprintf(char *str, const char *format, va_list args) {
    return vsprintf(str, format, args);
}

int __isoc99_vsnprintf(char *str, size_t size, const char *format, va_list args) {
    return vsnprintf(str, size, format, args);
}

/* xdr_destroy is a macro in modern <rpc/xdr.h> (`#undef` it to define the real function
 * php-src's binary expects instead); this is that macro's own standard body. */
#undef xdr_destroy
void xdr_destroy(XDR *xdrs) {
    if (xdrs->x_ops->x_destroy) {
        (*xdrs->x_ops->x_destroy)(xdrs);
    }
}

/* Forward to the binary's own (correct) compiler-rt interceptor rather than
 * reimplementing libstdc++'s exception-object internals -- see the module comment. */
void __cxa_rethrow_primary_exception(void* exc) {
    static void (*real)(void*) = 0;
    if (!real) {
        real = (void (*)(void*))dlsym(RTLD_DEFAULT, "__interceptor___cxa_rethrow_primary_exception");
    }
    if (real) {
        real(exc);
    }
}
'''
_PHP_SRC_COMPAT_SHIM_PATH = '/usr/local/lib/libphp-src-compat-shim.so'


def _ensure_php_src_compat_shim(bug_id: int, container_work_dir: str) -> bool:
    """Compile the php-src compat shim (see the module comment above) inside the
    container, unless it is already there from an earlier call for this bug (checked first
    so patch()+test_poc()'s several calls per bug don't each recompile it). Installs
    libtirpc-dev first for <rpc/xdr.h> (the real XDR struct layout, needed to get
    xdr_destroy's body right -- glibc dropped Sun RPC support and never shipped it).
    Returns whether the shim exists (already did, or was compiled successfully) --
    callers must not set LD_PRELOAD to a path that doesn't actually exist, or *every*
    subsequent exec in the container would fail to start instead of just php-src's
    affected binaries."""
    if docker.check_file_exist(_PHP_SRC_COMPAT_SHIM_PATH, bug_id):
        return True
    if not docker.check_file_exist('/usr/include/rpc/xdr.h', bug_id):
        docker.exec_docker_cmd(['apt-get', 'install', '-y', 'libtirpc-dev'], bug_id, cwd=container_work_dir)
    src_path = os.path.join(container_work_dir, 'php_src_compat_shim.c')
    with open(src_path, 'w') as f:  # container_work_dir is bind-mounted, so this reaches it
        f.write(_PHP_SRC_COMPAT_SHIM_SRC)
    res = docker.exec_docker_cmd(['cc', '-shared', '-fPIC', '-o', _PHP_SRC_COMPAT_SHIM_PATH, src_path, '-ldl'],
                                 bug_id, cwd=container_work_dir)
    return res.returncode == 0 and docker.check_file_exist(_PHP_SRC_COMPAT_SHIM_PATH, bug_id)


def _patcher_env(project: str = None, bug_id: int = None, container_work_dir: str = None):
    """Environment the binary patcher runs under (shared by every patcher call)."""
    new_env = os.environ.copy()
    if 'CXXFLAGS' in new_env:
        # Remove libc++ flags
        if '-stdlib=libc++' in new_env['CXXFLAGS']:
            new_env['CXXFLAGS'] = new_env['CXXFLAGS'].replace('-stdlib=libc++', '')
    new_env['CC'] = 'clang'
    new_env['CXX'] = 'clang++'
    new_env['LDFLAGS'] = '-pthread'
    new_env['UBSAN_OPTIONS'] = 'print_stacktrace=1:abort_on_error=1'
    new_env['ASAN_OPTIONS'] = 'detect_leaks=0'
    if project == 'php-src' and _ensure_php_src_compat_shim(bug_id, container_work_dir):
        new_env['LD_PRELOAD'] = _PHP_SRC_COMPAT_SHIM_PATH
    return new_env


def _patch_specs(patch_config_path:str) -> Set[str]:
    """Turn a patch config into the `-p ID:FUNC:FILE:...:TEMPLATE` specs the patcher takes.

    A REPLACE emits an INSERT_EXPR (new statement) and an INSERT_NOT_NULL_CHECKER ('0'
    disabler) at the *same* id/location -- one e9patch site (the runtime does both, keyed
    by id). Collapse them into a single spec (keyed by location, without the template) and
    keep the wrap template, which both inserts and skips; a lone INSERT_EXPR stays an
    insert. Emitting both as separate specs makes e9patch reject the second ("instruction
    already queued for patching").
    """
    loc_template = {}
    with open(patch_config_path, 'r') as f:
        dev_patch = json.load(f)
        for patch_entry in dev_patch:
            if patch_entry['template'] not in ('INSERT_EXPR', 'INSERT_NOT_NULL_CHECKER'):
                continue
            key = (f'{patch_entry["id"]}:{patch_entry["function"]}:{patch_entry["file"]}:'
                   f'{patch_entry["line"]}:{patch_entry["col"]}:'
                   f'{patch_entry["end_line"]}:{patch_entry["end_col"]}')
            if key not in loc_template or patch_entry['template'] == 'INSERT_NOT_NULL_CHECKER':
                loc_template[key] = patch_entry['template']
    return {f'{key}:{template}' for key, template in loc_template.items()}


def patch(project:str, bug_id:int, binary:str, patch_config_path:str):
    work_dir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))

    new_env = _patcher_env(project, bug_id, container_work_dir)

    metapro_out_dir = os.path.join(container_work_dir, 'metapro-out')
    dev_patches = _patch_specs(patch_config_path)

    if len(dev_patches) == 0:
        # No insert patch, skip
        # shutil.copy(os.path.join(metapro_out_dir, 'bin', binary),
        shutil.copy(os.path.join(metapro_out_dir, 'asan-bin', binary),
                    os.path.join(_patch_out_dir(container_work_dir), f'{binary}.inst'))
        return True, 0.

    # Run Binary patcher to apply the dev patch in binary level (w/o ASAN)
    san2patch_out_dir = _patch_out_dir(container_work_dir)
    BINARY_PATCHER = 'patcher-e9patch.py'
    # cmd = [BINARY_PATCHER, container_work_dir, os.path.join(metapro_out_dir, 'bin', binary),
    cmd = [BINARY_PATCHER, container_work_dir, os.path.join(metapro_out_dir, 'asan-bin', binary),
           san2patch_out_dir]
    for patch in dev_patches:
        cmd += ['-p', patch]
    # cmd.append('-v')
    # print(f'Running command: {" ".join(cmd)}')
    start_time = time.time()
    res = docker.exec_docker_cmd(cmd, bug_id, cwd=container_work_dir, env=new_env,
                                get_output=os.path.join(san2patch_out_dir, 'binary-patcher-san2patch.log'))
    patch_time = time.time() - start_time
    if res.returncode != 0:
        return False, patch_time

    return True, patch_time

def metapro_runtime_env(container_work_dir:str, patch_config_path:str, project: str = None,
                        bug_id: int = None, count_interpreter:bool=False) -> Dict[str,str]:
    """The METAPRO_* environment that makes a patched binary apply `patch_config_path`.

    e9patch only installs the *call sites*; which patch runs there, and what
    expression it evaluates, is decided at run time by these variables. So the
    same patched binary serves every candidate patch -- only this env changes.
    """
    new_env = dict()
    target_funcs = set()
    patch_ids = set()
    with open(patch_config_path, 'r') as f:
        patch_info = json.load(f)
        for patch_entry in patch_info:
            func = patch_entry['function']
            target_funcs.add(func)
            patch_id:int = patch_entry['id']
            patch_template:str = patch_entry['template']
            patch_ids.add(patch_id)
            exprs = patch_entry['exprs']
            if patch_template == 'INSERT_EXPR':
                new_env[f'METAPRO_EXPR_{patch_id}'] = exprs[0]
            elif patch_template == 'INSERT_NOT_NULL_CHECKER':
                new_env[f'METAPRO_PATCH_NOT_NULL_CHECKER_EXPR_{patch_id}'] = exprs[0]
            elif patch_template == 'REPLACE_CONDITION':
                new_env[f'METAPRO_PATCH_COND_{patch_id}'] = exprs[0]
                if len(exprs) > 1:
                    new_env[f'METAPRO_PATCH_COND_{patch_id}_2'] = exprs[1]

    patch_id_str = ''
    for p_id in patch_ids:
        patch_id_str += str(p_id) + ','
    patch_id_str = patch_id_str.rstrip(',')
    new_env['METAPRO_PATCH_ID'] = patch_id_str

    new_env['METAPRO_TARGET_FUNCTIONS'] = ''
    for func in target_funcs:
        new_env['METAPRO_TARGET_FUNCTIONS'] += func + ','
    new_env['METAPRO_TARGET_FUNCTIONS'] = new_env['METAPRO_TARGET_FUNCTIONS'].rstrip(',')
    new_env['METAPRO_OUTPUT_DIR'] = os.path.join(container_work_dir, 'metapro-out')
    # new_env['METAPRO_DEBUG_OUTPUT_FILE'] = os.path.join(container_work_dir, 'metapro-debug.log')
    new_env['ASAN_OPTIONS'] = 'detect_leaks=0'
    new_env['UBSAN_OPTIONS'] = 'abort_on_error=1:print_stacktrace=1'
    new_env['LIBRARY_PATH'] = '/usr/local/lib:' + new_env.get('LIBRARY_PATH', '')
    new_env['LD_LIBRARY_PATH'] = '/usr/local/lib:' + new_env.get('LD_LIBRARY_PATH', '')
    # new_env['METAPRO_DEBUG_PRINT_VAR_TABLE'] = '1'
    # new_env['METAPRO_DEBUG_PRINT_VAR_INSERT'] = '1'

    # Get interpreter node counter
    if count_interpreter:
        new_env['TS_NODE_COUNT_STMT_EXPR'] = os.path.join(container_work_dir, f'stmt-expr-count-{RESULT_TAG}.json')

    # See the module comment above _patcher_env: php-src's frozen ASan binaries crash at
    # load time on an undefined __isoc99_printf unrelated to any patch.
    if project == 'php-src' and _ensure_php_src_compat_shim(bug_id, container_work_dir):
        new_env['LD_PRELOAD'] = _PHP_SRC_COMPAT_SHIM_PATH
    return new_env


def test_poc(output_log:TextIO,project:str, bug_id:int, binary:str, patch_config_path:str, expect_fail = False, count_interpreter = False):
    work_dir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))

    # Setup env var
    new_env = metapro_runtime_env(container_work_dir, patch_config_path, project=project,
                                  bug_id=bug_id, count_interpreter=count_interpreter)
    if os.path.exists(os.path.join(work_dir, 'metapro-debug.log')):
        os.remove(os.path.join(work_dir, 'metapro-debug.log'))
    for k, v in new_env.items():
        print(f"export {k}='{v}'", file=output_log, flush=True)

    # Setup test command
    san2patch_out_dir = _patch_out_dir(container_work_dir)
    binary_path = os.path.join(san2patch_out_dir, f'{binary}.inst')

    # Run test
    with open(os.path.join(san2patch_out_dir, 'patch-test.log'), 'wb') as test_output_log:
        try:
            start_time = time.time()
            res = docker.exec_docker_cmd([binary_path, '/tmp/poc'], bug_id, env=new_env, get_output=True, timeout=300.)
            # res = docker.exec_docker_cmd(['time', '-v', binary_path, '/tmp/poc'], bug_id, env=new_env, get_output=True, timeout=300.)
            exec_time = time.time() - start_time
            test_output_log.write(res.stdout)
            if count_interpreter and os.path.exists(os.path.join(container_work_dir, f'stmt-expr-count-{RESULT_TAG}.json')):
                with open(os.path.join(container_work_dir, f'stmt-expr-count-{RESULT_TAG}.json'), 'r') as f:
                    interpreter_count = json.load(f)
            else:
                interpreter_count = {}
        except sp.TimeoutExpired as e:
            exec_time = 300.
            test_output_log.write(f'Execution timed out after 300 seconds.'.encode('utf-8'))
            print(f'Failed to run PoC due to timeout for {project}-{bug_id}', file=output_log, flush=True)
            return False, exec_time, dict()
    if b'with RTLD_DEEPBIND flag' in res.stdout:
        print(f'Failed to run PoC: sanitizer aborted before the PoC ran for {project}-{bug_id}', file=output_log, flush=True)
        return False, exec_time, interpreter_count
    if b'AddressSanitizer' in res.stdout or res.returncode == 139:
        if expect_fail:
            print(f'Expected to fail for {project}-{bug_id}', file=output_log, flush=True)
            return True, exec_time, interpreter_count
        else:
            print(f'Failed to run PoC due to ASAN error for {project}-{bug_id}', file=output_log, flush=True)
            return False, exec_time, interpreter_count
    elif project != 'php-src' and (b'UndefinedBehaviorSanitizer' in res.stdout or
                                   b'runtime error' in res.stdout):
        if expect_fail:
            print(f'Expected to fail for {project}-{bug_id}', file=output_log, flush=True)
            return True, exec_time, interpreter_count
        else:
            print(f'Failed to run PoC due to UBSAN error for {project}-{bug_id}', file=output_log, flush=True)
            return False, exec_time, interpreter_count
    elif res.returncode == 134:
        print(f'Failed to run PoC due to terrible error in meta-program or interpreter for {project}-{bug_id}', file=output_log, flush=True)
        return False, exec_time, interpreter_count
    
    if expect_fail:
        print(f'Expected to fail but passed when testing for {project}-{bug_id}', file=output_log, flush=True)
        return False, exec_time, interpreter_count
    else:
        print(f'{project}-{bug_id} metapro patch test success with return code {res.returncode} in {exec_time:.2f} seconds', file=output_log, flush=True)
        return True, exec_time, interpreter_count # return code != 0 also success


# ---------------------------------------------------------------------------
# Functional test against a fully binary-patched build
# ---------------------------------------------------------------------------
#
# The PoC runs one binary (the fuzz target), but a functional suite runs many:
# FFmpeg's FATE drives ./ffmpeg, ./ffprobe, tools/* and the per-library unit
# tests. Each is a separate ELF with its own addresses, so a patch has to be
# resolved and applied to each one individually -- there is no way to patch
# "the" binary once and have the suite see it.
#
# Applying is done in place (original saved next to it as <binary>.bak) rather
# than through a launcher, so the suite runs unmodified. That is safe as long as
# the patched file ends up *newer* than everything it is built from: FFmpeg's
# `ffmpeg: ffmpeg_g` rule (`strip -o $@ $<`) would otherwise re-derive ./ffmpeg
# from the untouched ffmpeg_g and quietly drop the patch. shutil.copy (not
# copy2) gives the installed binary a current mtime; restore uses copy2 to put
# the original timestamp back, so no rebuild is triggered either way.

FUNC_TEST_JOBS = 10
FUNC_TEST_TIMEOUT = 3600.
# Per-project override. A full FATE run is ~90 s once the samples are shared, so
# ffmpeg has plenty of slack at the default. libxml2's drivers are far slower
# under ASan -- a full `make check -j10 -k` did not finish inside 3600 s -- so it
# gets its own budget.
# Measured on the metapro build: a full `make check -j10 -k` is ~210 s with no
# METAPRO_* env and ~240 s with it. (Both are ~19x the 11 s the non-instrumented
# tree takes -- that gap is the instrumentation itself and no env setting reaches
# it.) 1800 s leaves ~7x slack for the patched run.
FUNC_TEST_TIMEOUT_BY_PROJECT = {'libxml2': 1800.}
# Fetching the FATE samples is a separate job from running the tests, and needs
# its own budget: the full set is ~1.3 GB, so the first fetch in a fresh
# container takes far longer than any test run. Sharing one timeout meant that
# first run spent the whole budget in rsync and was killed before it could
# write a result -- and, since it is killed with SIGKILL, without even flushing
# the log that would have said so. Later runs are incremental (~5 s).
FUNC_TEST_SAMPLE_TIMEOUT = 7200.
# Must match SAMPLES_DIR in gen-fate-supported.py. Deliberately not the
# per-container /src/fate-suite the build configured with: this path is on the
# bind mount all arvo containers share, so the ~1.3 GB sample set is fetched
# once for the whole benchmark instead of once per bug.
FATE_SAMPLES_DIR = '/root/project/fate-suite'

# libxml2's check drivers report a failing input as
#   Result for ./test/foo failed
#   File ./test/bar generated an error
# Keying regressions on these lines matches what san2patch's ArvoValidator does.
_LIBXML2_FAIL = re.compile(r'^(?:Result for|File)\s+(\./test/\S+)', re.M)
# Building the check programs is a separate job from running them, with its own
# budget, for the same reason the FATE sample fetch is (see below).
FUNC_TEST_BUILD_TIMEOUT = 1800.

# mrbtest (and bintest, which shares test/assert.rb) reports a broken test as a
# line starting "Fail: ", then the summary counts. The summary lines are indented,
# so anchoring at column 0 keeps "     KO: 3" out of the failure set.
_MRUBY_FAIL = re.compile(r'^Fail: (.+)$', re.M)
# A test killed by an exception is only counted, not named -- it shows up in the
# Crash tally instead. Fold a non-zero tally into the failure set so a patch that
# starts crashing tests is still caught. KO is deliberately ignored: it just
# counts the "Fail: " lines already captured above.
_MRUBY_CRASH = re.compile(r'^\s*Crash:\s*(\d+)\s*$', re.M)
# The metapro-instrumented sources reference the runtime library, but mruby's
# mrbtest link does not pull it in, so `rake test:build` dies with undefined
# references to __metapro_cond_c / __metapro_cond_res. Adding it here is what
# makes the functional test buildable at all.
MRUBY_LDFLAGS = '-fsanitize=address,undefined -L/usr/local/lib -lmetapro-runtime-c'

# tests/do.sh reports each pcap as "<name><pad>\tOK" / "\tERROR" / "\tSKIPPED",
# with a second ERROR shape carrying the reader's exit code. Both start with the
# pcap name, so one pattern covers them.
_NDPI_FAIL = re.compile(r'^(\S+)\s+ERROR', re.M)
# tests/unit/unit checks with assert(), so a broken test aborts rather than
# printing anything a parser could name. All that survives is the exit status,
# which do-unit.sh forwards -- hence a single synthetic entry.
_NDPI_UNIT_FAILED = '<unit-tests-failed>'

_ELF_MAGIC = b'\x7fELF'

# Build intermediates, our own backups and patcher output -- never test binaries.
_NOT_A_BINARY = ('.o', '.a', '.so', '.lo', '.la', '.bak', '.inst', '.d', '.c', '.h',
                 '.json', '.log', '.txt', '.mak', '.pc', '.ver', '.sh', '.py', '.dict',
                 '.options', '.asm', '.S')


# Shared libraries are ELF too, but they are not test binaries, and the patcher
# opens its target as an executable. A plain ".so" suffix check misses the
# versioned sonames (libndpi.so.4.7.0), so match the whole family.
_SHARED_LIB = re.compile(r'\.so(\.\d+)*$')


def _install_binary(src:str, dst:str, preserve_times:bool = False) -> None:
    """Replace `dst` with `src` even while `dst` is being executed.

    Writing straight over a running executable fails with ETXTBSY, and a
    container-side test process can easily outlive the `docker exec` that started
    it (docker does not forward signals, so a host-side timeout leaves it
    running). Copying to a temporary file and renaming sidesteps that entirely:
    rename swaps the directory entry, and any process already running the old
    image keeps its inode.

    preserve_times keeps src's mtime (restoring an original); without it the new
    file gets a current mtime, which is what an installed patch needs so the
    build system does not consider it stale and rebuild over it.
    """
    tmp = f'{dst}.metapro-tmp'
    try:
        if preserve_times:
            shutil.copy2(src, tmp)
        else:
            shutil.copy(src, tmp)
        os.replace(tmp, dst)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def _is_elf(path:str) -> bool:
    try:
        with open(path, 'rb') as f:
            return f.read(4) == _ELF_MAGIC
    except OSError:
        return False


def _defined_functions(binary_path:str) -> Optional[Set[str]]:
    """Names of functions `binary_path` defines, or None if they can't be read.

    Used to skip binaries that cannot contain the patch site: running the patcher
    against them would spend minutes building a DWARF index only to resolve
    nothing. None (no symbol table / no readelf) means "don't filter".
    """
    try:
        res = sp.run(['readelf', '-sW', binary_path], stdout=sp.PIPE, stderr=sp.DEVNULL)
    except OSError:
        return None
    if res.returncode != 0:
        return None
    names: Set[str] = set()
    for line in res.stdout.decode('utf-8', 'replace').splitlines():
        cols = line.split()
        # Num: Value Size Type Bind Vis Ndx Name
        if len(cols) >= 8 and cols[3] == 'FUNC' and cols[6] != 'UND':
            names.add(cols[7].split('@', 1)[0])
    return names or None


def collect_binaries(project:str, bug_id:int) -> List[Tuple[str, str]]:
    """Step 1: every binary the functional suite runs, as (run_path, patch_source).

    `run_path` is the file the suite executes and where the patched binary must be
    installed. `patch_source` is what the patcher resolves against: for a stripped
    program it is the unstripped twin (FFmpeg builds ffmpeg_g then strips it into
    ffmpeg -- same link, same addresses, but only the twin has the DWARF line info
    the patcher needs). For everything else the two are the same file.
    """
    project_workdir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    source_dir = os.path.join(project_workdir, 'metapro-source')

    found: List[str] = []
    for dirpath, dirnames, filenames in os.walk(source_dir):
        dirnames[:] = [d for d in dirnames if d not in ('.git', 'doc', 'presets')]
        for name in filenames:
            if name.endswith(_NOT_A_BINARY) or _SHARED_LIB.search(name):
                continue
            path = os.path.join(dirpath, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            if not os.access(path, os.X_OK) or not _is_elf(path):
                continue
            found.append(path)

    binaries: List[Tuple[str, str]] = []
    found_set = set(found)
    for path in sorted(found):
        # ffmpeg_g/ffprobe_g are the debug twins of binaries already in the list;
        # they are a patch *source*, not something the suite runs on its own.
        if path.endswith('_g') and path[:-2] in found_set:
            continue
        twin = f'{path}_g'
        binaries.append((path, twin if twin in found_set else path))
    return binaries


def patch_all_binaries(output_log:TextIO, project:str, bug_id:int, patch_config_path:str):
    """Step 2: apply `patch_config_path` to every functional-test binary.

    Each original is copied to <binary>.bak before it is replaced -- but only when
    no .bak exists yet, so re-running never backs a *patched* binary up over the
    pristine one. Binaries that do not define any patched function, or that the
    patcher cannot resolve a site in, are left untouched.

    Returns (ok, patched_paths, elapsed).
    """
    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    start_time = time.time()

    specs = _patch_specs(patch_config_path)
    if not specs:
        print(f'[{project}-{bug_id}] no insert patch in config; functional test runs unpatched binaries',
              file=output_log, flush=True)
        return True, [], time.time() - start_time

    with open(patch_config_path, 'r') as f:
        target_funcs = {p['function'] for p in json.load(f)}

    out_dir = os.path.join(_patch_out_dir(container_work_dir), 'func-bin')
    os.makedirs(out_dir, exist_ok=True)
    log_path = os.path.join(_patch_out_dir(container_work_dir), 'binary-patcher-func.log')
    new_env = _patcher_env(project, bug_id, container_work_dir)

    binaries = collect_binaries(project, bug_id)
    print(f'[{project}-{bug_id}] {len(binaries)} functional-test binaries found', file=output_log, flush=True)

    patched: List[str] = []
    with open(log_path, 'w') as patch_log:
        for run_path, patch_src in binaries:
            defined = _defined_functions(patch_src)
            if defined is not None and not (target_funcs & defined):
                # None of the patched functions is linked into this binary.
                continue

            cmd = ['patcher-e9patch.py', container_work_dir, patch_src, out_dir]
            for spec in specs:
                cmd += ['-p', spec]
            print(f'--- {run_path}', file=patch_log, flush=True)
            res = docker.exec_docker_cmd(cmd, bug_id, cwd=container_work_dir, env=new_env,
                                         get_output=patch_log)
            if res.returncode != 0:
                # Site not resolvable here (inlined away, different unit, ...).
                # Leave the original in place rather than failing the whole run.
                print(f'[{project}-{bug_id}] patcher failed for {run_path}, keeping original',
                      file=output_log, flush=True)
                continue

            inst = os.path.join(out_dir, f'{os.path.basename(patch_src)}.inst')
            if not os.path.exists(inst):
                print(f'[{project}-{bug_id}] no patched binary produced for {run_path}',
                      file=output_log, flush=True)
                continue

            backup = f'{run_path}.bak'
            if not os.path.exists(backup):
                shutil.copy2(run_path, backup)
            # Current mtime (not the patched file's): it must be newer than its
            # prerequisites so the build system does not re-derive it and drop
            # the patch.
            _install_binary(inst, run_path)
            patched.append(run_path)

    print(f'[{project}-{bug_id}] patched {len(patched)} binaries for the functional test',
          file=output_log, flush=True)
    return True, patched, time.time() - start_time


def restore_binaries(project:str, bug_id:int) -> int:
    """Put every <binary>.bak back and drop the backup. Returns how many restored."""
    project_workdir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    source_dir = os.path.join(project_workdir, 'metapro-source')
    restored = 0
    for dirpath, dirnames, filenames in os.walk(source_dir):
        dirnames[:] = [d for d in dirnames if d != '.git']
        for name in filenames:
            if not name.endswith('.bak'):
                continue
            backup = os.path.join(dirpath, name)
            original = backup[:-len('.bak')]
            # Original mtime, so nothing downstream thinks the file changed.
            _install_binary(backup, original, preserve_times=True)
            os.remove(backup)
            restored += 1
    return restored


def _prefetch_fate_samples(output_log:TextIO, project:str, bug_id:int) -> bool:
    """Fetch the FATE samples ahead of the timed test run (ffmpeg only).

    gen-fate-supported.py rsyncs the samples itself, but from inside the run it
    is timed against, so a cold fetch eats the whole test budget. Doing it here
    first, under its own timeout, leaves the test run facing only an incremental
    rsync. Best-effort: rsync failing is not fatal (sample-based tests then fail,
    which the baseline records), so a failure is reported and the run continues.
    """
    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    source_dir = os.path.join(container_work_dir, 'metapro-source')
    log_path = os.path.join(container_work_dir, 'fate-rsync.log')

    cmd = ['timeout', '-s', 'KILL', str(int(FUNC_TEST_SAMPLE_TIMEOUT)),
           'make', 'fate-rsync', f'SAMPLES={FATE_SAMPLES_DIR}']
    start_time = time.time()
    try:
        res = docker.exec_docker_cmd(cmd, bug_id, cwd=source_dir, get_output=log_path,
                                     timeout=FUNC_TEST_SAMPLE_TIMEOUT + 60.)
    except sp.TimeoutExpired:
        print(f'[{project}-{bug_id}] FATE sample fetch timed out; sample-based tests will fail',
              file=output_log, flush=True)
        return False
    if res.returncode != 0:
        print(f'[{project}-{bug_id}] FATE sample fetch failed (rc={res.returncode}), see {log_path}; '
              f'sample-based tests will fail', file=output_log, flush=True)
        return False
    print(f'[{project}-{bug_id}] FATE samples ready in {time.time() - start_time:.1f}s',
          file=output_log, flush=True)
    return True


def _build_libxml2_checks(output_log:TextIO, project:str, bug_id:int) -> bool:
    """Build libxml2's check programs before patch_all_binaries runs (libxml2 only).

    `make check` builds check_PROGRAMS itself, so any driver that did not exist
    when the binaries were patched would be linked fresh -- unpatched -- and the
    functional test would silently exercise original code. Building them up front
    means patch_all_binaries finds all eight, and the later `make check` sees them
    newer than their objects and leaves the patched files alone.

    CHECKER=true is the trick that separates the two halves: check-local invokes
    each driver as `$(CHECKER) ./runtest`, so CHECKER=true turns every one into a
    no-op `true ./runtest`. check-am then builds everything and runs nothing. It
    also avoids hardcoding the check_PROGRAMS list, which differs across versions.
    """
    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    source_dir = os.path.join(container_work_dir, 'metapro-source')
    log_path = os.path.join(container_work_dir, 'func-test-build.log')

    cmd = ['timeout', '-s', 'KILL', str(int(FUNC_TEST_BUILD_TIMEOUT)),
           'make', f'-j{FUNC_TEST_JOBS}', '-k', 'check-am', 'CHECKER=true']
    start_time = time.time()
    try:
        res = docker.exec_docker_cmd(cmd, bug_id, cwd=source_dir, get_output=log_path,
                                     timeout=FUNC_TEST_BUILD_TIMEOUT + 60.)
    except sp.TimeoutExpired:
        print(f'[{project}-{bug_id}] check-program build timed out', file=output_log, flush=True)
        return False
    if res.returncode != 0:
        print(f'[{project}-{bug_id}] check-program build failed (rc={res.returncode}), see {log_path}',
              file=output_log, flush=True)
        return False
    print(f'[{project}-{bug_id}] check programs built in {time.time() - start_time:.1f}s',
          file=output_log, flush=True)
    return True


def _build_mruby_tests(output_log:TextIO, project:str, bug_id:int) -> bool:
    """Build mrbtest before patch_all_binaries runs (mruby only).

    `rake test` is build-then-run in one task, so patching between the two halves
    means splitting it: this does `rake test:build`, and _run_mruby_test does
    `rake test:run`, which does not rebuild. Without the split, rake would link
    mrbtest after the patching step and the test would exercise original code.
    """
    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    source_dir = os.path.join(container_work_dir, 'metapro-source')
    log_path = os.path.join(container_work_dir, 'func-test-build.log')

    env = {'LDFLAGS': MRUBY_LDFLAGS,
           'LIBRARY_PATH': '/usr/local/lib:',
           'LD_LIBRARY_PATH': '/usr/local/lib:'}
    cmd = ['timeout', '-s', 'KILL', str(int(FUNC_TEST_BUILD_TIMEOUT)),
           'rake', 'test:build']
    start_time = time.time()
    try:
        res = docker.exec_docker_cmd(cmd, bug_id, cwd=source_dir, env=env, get_output=log_path,
                                     timeout=FUNC_TEST_BUILD_TIMEOUT + 60.)
    except sp.TimeoutExpired:
        print(f'[{project}-{bug_id}] mrbtest build timed out', file=output_log, flush=True)
        return False
    if res.returncode != 0:
        print(f'[{project}-{bug_id}] mrbtest build failed (rc={res.returncode}), see {log_path}',
              file=output_log, flush=True)
        return False
    print(f'[{project}-{bug_id}] mrbtest built in {time.time() - start_time:.1f}s',
          file=output_log, flush=True)
    return True


def _run_mruby_test(output_log:TextIO, project:str, bug_id:int,
                    new_env:Dict[str,str], log_path:str,
                    timeout:float) -> Optional[Set[str]]:
    """`rake test:run` for mruby; returns the set of failing tests.

    test:run only runs -- the build half already happened in prepare_functional_test
    -- so the binaries patched in between are the ones exercised. It covers both
    mrbtest (the library tests) and bintest, which drives bin/mruby and bin/mrbc.
    """
    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    source_dir = os.path.join(container_work_dir, 'metapro-source')

    run_env = dict(new_env)
    run_env['LDFLAGS'] = MRUBY_LDFLAGS
    cmd = ['timeout', '-s', 'KILL', str(int(timeout)), 'rake', 'test:run']
    try:
        docker.exec_docker_cmd(cmd, bug_id, cwd=source_dir, env=run_env,
                               get_output=log_path, timeout=timeout + 60.)
    except sp.TimeoutExpired:
        print(f'[{project}-{bug_id}] functional test timed out', file=output_log, flush=True)
        return None

    try:
        with open(log_path, 'r', errors='ignore') as f:
            out = f.read()
    except OSError:
        print(f'[{project}-{bug_id}] functional test produced no log', file=output_log, flush=True)
        return None

    failed = set(_MRUBY_FAIL.findall(out))
    # One entry per report block (mrbtest, bintest) that killed any test, so a
    # change in the tally shows up as a set difference like a named failure would.
    for i, n in enumerate(_MRUBY_CRASH.findall(out)):
        if int(n) > 0:
            failed.add(f'<crash#{i}={n}>')
    return failed


def _build_ndpi_tests(output_log:TextIO, project:str, bug_id:int) -> bool:
    """Build ndpiReader and the unit binary before patching (ndpi only).

    tests/do.sh and do-unit.sh only *run* binaries -- neither invokes make -- so
    unlike libxml2 there is no risk of the suite relinking over a patched file.
    The build is here so a tree that has not been built yet does not simply fail
    with "Missing ../example/ndpiReader"; when everything is current it is a no-op.
    """
    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    source_dir = os.path.join(container_work_dir, 'metapro-source')
    log_path = os.path.join(container_work_dir, 'func-test-build.log')

    cmd = ['timeout', '-s', 'KILL', str(int(FUNC_TEST_BUILD_TIMEOUT)),
           'make', f'-j{FUNC_TEST_JOBS}']
    start_time = time.time()
    try:
        res = docker.exec_docker_cmd(cmd, bug_id, cwd=source_dir, get_output=log_path,
                                     timeout=FUNC_TEST_BUILD_TIMEOUT + 60.)
    except sp.TimeoutExpired:
        print(f'[{project}-{bug_id}] ndpi build timed out', file=output_log, flush=True)
        return False
    if res.returncode != 0:
        print(f'[{project}-{bug_id}] ndpi build failed (rc={res.returncode}), see {log_path}',
              file=output_log, flush=True)
        return False
    print(f'[{project}-{bug_id}] ndpi binaries built in {time.time() - start_time:.1f}s',
          file=output_log, flush=True)
    return True


def _run_ndpi_tests(output_log:TextIO, project:str, bug_id:int,
                    new_env:Dict[str,str], log_path:str,
                    timeout:float) -> Optional[Set[str]]:
    """tests/do.sh + tests/do-unit.sh for ndpi; returns the set of failures.

    do.sh replays ~400 pcaps per config through ndpiReader and diffs each against
    a recorded result, naming every mismatch, so those become the failure set
    directly. do-unit.sh cannot name anything (its tests assert()), so it
    contributes one synthetic entry when it exits non-zero.

    NDPI_DISABLE_FUZZY matches what san2patch's validator sets. CXXFLAGS is
    cleared deliberately: do-unit.sh skips itself entirely when CXXFLAGS mentions
    a sanitizer, and inheriting one would silently drop the unit tests.
    """
    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    source_dir = os.path.join(container_work_dir, 'metapro-source')

    run_env = dict(new_env)
    run_env['NDPI_DISABLE_FUZZY'] = '1'
    run_env['CXXFLAGS'] = ''

    failed: Set[str] = set()

    # do.sh: named per-pcap failures.
    cmd = ['timeout', '-s', 'KILL', str(int(timeout)), './tests/do.sh']
    try:
        docker.exec_docker_cmd(cmd, bug_id, cwd=source_dir, env=run_env,
                               get_output=log_path, timeout=timeout + 60.)
    except sp.TimeoutExpired:
        print(f'[{project}-{bug_id}] functional test (do.sh) timed out', file=output_log, flush=True)
        return None
    try:
        with open(log_path, 'r', errors='ignore') as f:
            failed |= set(_NDPI_FAIL.findall(f.read()))
    except OSError:
        print(f'[{project}-{bug_id}] functional test produced no log', file=output_log, flush=True)
        return None

    # do-unit.sh: pass/fail only, appended to the same log for diagnosis.
    unit_log = f'{log_path}.unit'
    cmd = ['timeout', '-s', 'KILL', str(int(timeout)), './tests/do-unit.sh']
    try:
        res = docker.exec_docker_cmd(cmd, bug_id, cwd=source_dir, env=run_env,
                                     get_output=unit_log, timeout=timeout + 60.)
    except sp.TimeoutExpired:
        print(f'[{project}-{bug_id}] functional test (do-unit.sh) timed out', file=output_log, flush=True)
        return None
    if res.returncode != 0:
        failed.add(_NDPI_UNIT_FAILED)
    return failed


def prepare_functional_test(output_log:TextIO, project:str, bug_id:int) -> bool:
    """Whatever the suite needs in place *before* the timed run and before patching.

    Kept off the test clock deliberately: these steps are one-off and far slower
    than a test run, so sharing one timeout with the tests means the first run of
    a bug spends its whole budget here and dies without a result.
    """
    if project == 'ffmpeg':
        return _prefetch_fate_samples(output_log, project, bug_id)
    if project == 'libxml2':
        return _build_libxml2_checks(output_log, project, bug_id)
    if project == 'mruby':
        return _build_mruby_tests(output_log, project, bug_id)
    if project == 'ndpi':
        return _build_ndpi_tests(output_log, project, bug_id)
    return True


def _run_libxml2_check(output_log:TextIO, project:str, bug_id:int,
                       new_env:Dict[str,str], log_path:str,
                       timeout:float) -> Optional[Set[str]]:
    """`make check` for libxml2; returns the set of failing test inputs.

    Unlike FATE there is no result file to read -- the drivers report failures on
    stdout/stderr -- so the failures are parsed straight out of the run log. -k
    keeps going past a failing driver so one break does not hide the rest.
    """
    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    source_dir = os.path.join(container_work_dir, 'metapro-source')

    cmd = ['timeout', '-s', 'KILL', str(int(timeout)),
           'make', 'check', f'-j{FUNC_TEST_JOBS}', '-k']
    try:
        docker.exec_docker_cmd(cmd, bug_id, cwd=source_dir, env=new_env,
                               get_output=log_path, timeout=timeout + 60.)
    except sp.TimeoutExpired:
        print(f'[{project}-{bug_id}] functional test timed out', file=output_log, flush=True)
        return None

    # A non-zero rc is expected whenever any test fails, so it is not consulted;
    # what matters is which inputs failed, which the log records either way.
    try:
        with open(log_path, 'r', errors='ignore') as f:
            out = f.read()
    except OSError:
        print(f'[{project}-{bug_id}] functional test produced no log', file=output_log, flush=True)
        return None
    return set(_LIBXML2_FAIL.findall(out))


def _run_functional_suite(output_log:TextIO, project:str, bug_id:int,
                          patch_config_path:Optional[str], log_name:str,
                          timeout:Optional[float] = None) -> Optional[Set[str]]:
    """Run the project's functional suite once; return the set of failed test names.

    `patch_config_path` supplies the METAPRO_* run-time environment that selects the
    patch; pass None for a baseline run over the original binaries. Returns None if
    the suite could not be run at all.
    """
    if project not in ('ffmpeg', 'libxml2', 'mruby', 'ndpi'):
        print(f'[{project}-{bug_id}] functional test not implemented for {project}',
              file=output_log, flush=True)
        return None
    if timeout is None:
        timeout = FUNC_TEST_TIMEOUT_BY_PROJECT.get(project, FUNC_TEST_TIMEOUT)

    project_workdir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    source_dir = os.path.join(container_work_dir, 'metapro-source')
    runner = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'scripts', 'gen-fate-supported.py')

    if patch_config_path is None:
        new_env = {
            'ASAN_OPTIONS': 'detect_leaks=0',
            'UBSAN_OPTIONS': 'abort_on_error=1:print_stacktrace=1',
            'LIBRARY_PATH': '/usr/local/lib:',
            'LD_LIBRARY_PATH': '/usr/local/lib:',
        }
    else:
        new_env = metapro_runtime_env(container_work_dir, patch_config_path)

    # Prerequisites first, on their own clock (see prepare_functional_test), so
    # the timed run below only ever faces incremental work.
    prepare_functional_test(output_log, project, bug_id)

    if project == 'libxml2':
        # libxml2
        return _run_libxml2_check(output_log, project, bug_id, new_env,
                                  os.path.join(project_workdir, log_name), timeout)

    if project == 'mruby':
        # mruby
        return _run_mruby_test(output_log, project, bug_id, new_env,
                               os.path.join(project_workdir, log_name), timeout)

    if project == 'ndpi':
        # ndpi
        return _run_ndpi_tests(output_log, project, bug_id, new_env,
                               os.path.join(project_workdir, log_name), timeout)

    # ffmpeg
    cmd = ['timeout', '-s', 'KILL', str(int(timeout)),
           'python3', '-u', runner, str(bug_id), source_dir, '-j', str(FUNC_TEST_JOBS),
           '--failed-name', f'fate-failed-{RESULT_TAG}.txt']
    failed_path = os.path.join(project_workdir, f'fate-failed-{RESULT_TAG}.txt')
    if os.path.exists(failed_path):
        os.remove(failed_path)
    try:
        docker.exec_docker_cmd(cmd, bug_id, cwd=source_dir, env=new_env,
                               get_output=os.path.join(project_workdir, log_name),
                               timeout=timeout + 60.)
    except sp.TimeoutExpired:
        print(f'[{project}-{bug_id}] functional test timed out', file=output_log, flush=True)
        return None

    if not os.path.exists(failed_path):
        print(f'[{project}-{bug_id}] functional test produced no result file', file=output_log, flush=True)
        return None
    with open(failed_path, 'r') as f:
        return set(f.read().split())


def functional_baseline(output_log:TextIO, project:str, bug_id:int,
                        force:bool = False,
                        patch_config_path:Optional[str] = None) -> Optional[Set[str]]:
    """Tests that already fail on the *unpatched* build, cached across runs.

    The suite has a large standing failure set (missing samples, disabled muxers,
    ...), and re-measuring it for every candidate patch would double the cost of
    each one. It only depends on the build, so it is measured once, written to
    fate-failed-baseline-<RESULT_TAG>.txt, and parsed from there afterwards. The tag keeps
    it per experiment: each one measures it under its own runtime environment.
    """
    project_workdir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    baseline_path = os.path.join(project_workdir, f'fate-failed-baseline-{RESULT_TAG}.txt')

    if os.path.exists(baseline_path) and not force:
        with open(baseline_path, 'r') as f:
            baseline = set(f.read().split())
        print(f'[{project}-{bug_id}] using cached functional baseline ({len(baseline)} failures)',
              file=output_log, flush=True)
        return baseline

    # Measure on pristine binaries: undo any patch left over from an earlier run.
    restore_binaries(project, bug_id)
    print(f'[{project}-{bug_id}] measuring functional baseline on original binaries',
          file=output_log, flush=True)
    # The config is passed for its METAPRO_* env, not to apply anything: these are the
    # *unpatched* binaries, which carry no e9patch call sites, so no patch can run.
    # The reason to pass it is comparability -- baseline and patched runs then differ
    # only in the binaries, which is the point of a baseline. Cost is no longer an
    # argument either way: the runtime now skips instrumented code outright when
    # METAPRO_TARGET_FUNCTIONS is unset, which makes an env-less run marginally
    # cheaper (libxml2 make check: ~210 s without, ~240 s with).
    baseline = _run_functional_suite(output_log, project, bug_id, patch_config_path,
                                     'func-test-baseline.log')
    if baseline is None:
        return None
    with open(baseline_path, 'w') as f:
        f.write('\n'.join(sorted(baseline)) + ('\n' if baseline else ''))
    print(f'[{project}-{bug_id}] functional baseline: {len(baseline)} failures -> {baseline_path}',
          file=output_log, flush=True)
    return baseline


def test_functional(output_log:TextIO, project:str, bug_id:int, patch_config_path:str):
    """Collect the binaries, patch them all, and run the functional suite.

    A patch passes when it introduces no failure that the unpatched build did not
    already have. The binaries are always restored afterwards, so the tree is left
    as it was found whatever the outcome.

    Returns (ok, patch_time, test_time).
    """
    baseline = functional_baseline(output_log, project, bug_id,
                                   patch_config_path=patch_config_path, force=False)
    if baseline is None:
        print(f'[{project}-{bug_id}] no functional baseline; skipping functional test',
              file=output_log, flush=True)
        return False, '-', '-'

    test_time = '-'
    try:
        patch_ok, patched, patch_time = patch_all_binaries(output_log, project, bug_id, patch_config_path)

        if not patch_ok:
            print(f'[{project}-{bug_id}] no binary could be patched for the functional test',
                  file=output_log, flush=True)
            return False, patch_time, '-'

        start_time = time.time()
        failed = _run_functional_suite(output_log, project, bug_id, patch_config_path,
                                       'func-test.log')
        test_time = time.time() - start_time
    finally:
        restore_binaries(project, bug_id)

    if failed is None:
        return False, patch_time, test_time

    regressions = sorted(failed - baseline)
    if regressions:
        print(f'[{project}-{bug_id}] functional test failed: {len(regressions)} new failures, '
              f'e.g. {regressions[:5]}', file=output_log, flush=True)
        return False, patch_time, test_time
    print(f'[{project}-{bug_id}] functional test passed ({len(patched)} binaries patched, '
          f'{len(failed)} failures, all pre-existing)', file=output_log, flush=True)
    return True, patch_time, test_time


def _load_stage_result(san2patch_dir: str, i: int) -> dict:
    """Read <san2patch_dir>/result_stage_0_<i>.json -> {attempt_id: result_str}.

    san2patch records each generated patch's outcome under
    <strategy>/attempts/<attempt_id>/result (e.g. 'success', 'func_test_failed',
    'build_failed'). The diff files are named cur-patch_<attempt_id>.diff, so the
    attempt_id is what we look up. The result file lives directly under san2patch/
    (a sibling of gen_diff/). Returns {} if it is missing or unreadable.
    """
    result_path = os.path.join(san2patch_dir, f'result_stage_0_{i}.json')
    if not os.path.exists(result_path):
        return {}
    try:
        with open(result_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}
    flat = {}
    for strat in data.values():
        if not isinstance(strat, dict):
            continue
        for attempt_id, info in strat.get('attempts', {}).items():
            if isinstance(info, dict) and 'result' in info:
                flat[attempt_id] = info['result']
    return flat


def clean_generated_source(work_dir:str, *names:str):
    """Remove the source tree copies a run leaves behind in the bug's work directory.

    Each run copies `source` into a working tree of its own and never takes it back out,
    so a bug ends up holding several full checkouts. `source` and `metapro-source` are the
    trees the rest of the pipeline reads, so only the per-run copies go.
    """
    for name in names:
        path = os.path.join(work_dir, name)
        if not os.path.isdir(path):
            continue
        print(f'Removing generated source directory {path}', file=sys.stderr, flush=True)
        shutil.rmtree(path, ignore_errors=True)


def gen_plausible_patch_config_for_bug(project: str, bug_id: int, fuzz_target: str,
                                       run_func_test: bool = False, run_idx: int = 0):
    """Run one bug and drop the build tree it created.

    The config generator copies `source` into `san2patch-source` to apply the diff onto,
    and it is of no use once the run has read its coordinates back out. It is removed
    however the run ends -- a failure or a raised exception leaves one behind just as a
    success does.
    """
    work_dir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    try:
        return _gen_plausible_patch_config_for_bug(project, bug_id, fuzz_target,
                                                   run_func_test, run_idx)
    finally:
        clean_generated_source(work_dir, 'san2patch-source')


def _gen_plausible_patch_config_for_bug(project: str, bug_id: int, fuzz_target: str,
                                        run_func_test: bool = False, run_idx: int = 0):
    """Generate a patch config for plausible patch by San2Patch of one bug.

    `run_idx` (0-based) names this call's log/JSON outputs distinctly from every other
    repetition of the same bug (see RUN_COUNT in __main__), so running the whole
    experiment RUN_COUNT times never overwrites a previous run's result -- each is kept
    for the boxplot aggregation done once all runs finish.
    """
    project_workdir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    source_path = os.path.join(project_workdir, 'metapro-source')
    parse_time, patch_time, test_time = 0., 0., 0.
    output_log_path = os.path.join(project_workdir, 'san2patch-deepseek', f'san2patch-gen-config_run{run_idx}.log')
    output_log = open(output_log_path, 'wt')

    config_path = os.path.join(ROOT_DIR, 'config.json')
    if not os.path.exists(config_path):
        raise FileNotFoundError(f'Configuration file not found at {config_path}, please create based on config.template.json!')
    with open(config_path, 'r') as f:
        config = json.load(f)
    host_mount_path = config['host_mount_path']

    # A container already running with metapro/gumtree/srcml installed (e.g. left over from an
    # interrupted previous run of this same bug) is reused as-is instead of being torn down and
    # rebuilt from a clean image -- docker.checkout() on an already-named container stops+rm -f's
    # it first, which would throw away several minutes of apt/metapro/gumtree setup for nothing.
    already_set_up = (
        sp.run(['docker', 'inspect', '-f', '{{.State.Running}}', f'arvo-{bug_id}'],
               capture_output=True, text=True).stdout.strip() == 'true'
        and docker.exec_docker_cmd(['which', 'metapro', 'gumtree', 'srcml'],
                                   bug_id, get_output=True).returncode == 0
    )
    if already_set_up:
        print(f'Reusing already-running container for {project}-{bug_id} '
              f'(metapro/gumtree/srcml already installed)')
    else:
        res = docker.checkout(project, bug_id, host_mount_path, install_dependency=True)
        if not res:
            print(f'Failed to checkout {project}-{bug_id}')
            return False
        if not checkout.copy_source(project, bug_id):
            print(f'Failed to copy source for {project}-{bug_id}')
            return False
        res = checkout.setup_metapro(project, bug_id)
        if not res:
            print(f'Failed to setup metapro for {project}-{bug_id}')
            return False
        res = checkout.setup_gumtree(project, bug_id)
        if not res:
            print(f'Failed to setup gumtree/srcml for {project}-{bug_id}')
            return False

    # checkout.setup_metapro() above only builds/installs the metapro tool -- it does not run
    # it. run-metapro.py's run() is the actual execution that produces metapro-source/ (and
    # metapro-out/), which every _diff_to_config() call below reads positions from. Without
    # this, "missing source for <file>, skipping" fires for every diff regardless of content.
    overview_df = pd.read_csv(os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'overview.csv'))
    row = overview_df[(overview_df['project'] == project) & (overview_df['localId'] == bug_id)]
    is_ubsan = bool(len(row)) and row.iloc[0]['sanitizer'] == 'ubsan'
    run_metapro = _load_run_metapro()
    res, _, _, _ = run_metapro.run(project, bug_id, skip_checkout=True, is_ubsan=is_ubsan)
    if not res:
        print(f'Failed to run metapro for {project}-{bug_id}')
        return False

    # Find first plausible patch
    diff_file_path = ''
    for i in range(5):
        stage_dir = os.path.join(project_workdir, 'san2patch-deepseek', 'gen_diff', f'stage_0_{i}')
        if not os.path.exists(stage_dir):
            continue
        stage_results = _load_stage_result(os.path.join(project_workdir, 'san2patch-deepseek'), i)
        for file in os.listdir(stage_dir):
            if file.endswith('.diff') and file != 'cur-patch.diff':
                attempt_id = file.split('.')[0].rsplit('cur-patch_', 1)[-1]
                result = stage_results.get(attempt_id)
                if result in ('success', 'verify_failed'):
                    # Found a plausible patch
                    diff_file_path = os.path.join(stage_dir, file)
                    break
        else:
            continue
        break

    if not diff_file_path:
        print(f'[{project}-{bug_id}] no plausible patch found by san2patch, skip generating patch config for plausible patch', file=sys.stderr, flush=True)
        print(f'[{project}-{bug_id}] no plausible patch found by san2patch, skip generating patch config for plausible patch', file=output_log, flush=True)
        with open(os.path.join(project_workdir, f'san2patch-gumtree-result_run{run_idx}.json'), 'w') as f:
            json.dump({
                'result': 'N/A',
                'parse_time': '-',
                'patch_time': '-',
                'test_time': '-',
                'func_result': 'N/A',
                'func_patch_time': '-',
                'func_test_time': '-',
                'condition replace': '-',
                'insert': '-',
                'both': '-',
            }, f, indent=2)
        output_log.close()
        docker.stop_container(bug_id)
        return
    
    config_path = os.path.join(stage_dir, f'{diff_file_path.split("/")[-1].split(".")[0]}_{RESULT_TAG}_run{run_idx}.json')
    # Pre-process patcher first
    if not preprocess_patcher(project, bug_id, fuzz_target):
        print(f'[{project}-{bug_id}] failed to preprocess patcher, skip generating patch config for this bug', file=sys.stderr, flush=True)
        print(f'[{project}-{bug_id}] failed to preprocess patcher, skip generating patch config for this bug', file=output_log, flush=True)
        output_log.close()
        docker.stop_container(bug_id)
        return
    
    # Map the diff (cur-patch_<attempt_id>.diff) to san2patch's recorded result.
    patch_result, _parse_time, _patch_time, _test_time, func_result, func_patch_time, func_test_time, _patch_config, interpreter_usage = gen_patch_config(
        output_log,
        project, bug_id, diff_file_path, source_path,
        fuzz_target, config_path, run_func_test=run_func_test)
    parse_time += _parse_time
    patch_time += _patch_time
    test_time += _test_time

    print(f'[{project}-{bug_id}] plausible patch config generated with parse_time={parse_time:.2f}s, '
          f'patch_time={patch_time:.2f}s, test_time={test_time:.2f}s',
          file=sys.stderr, flush=True)
    print(f'[{project}-{bug_id}] plausible patch config generated with parse_time={parse_time:.2f}s, '
          f'patch_time={patch_time:.2f}s, test_time={test_time:.2f}s',
          file=output_log, flush=True)
    if func_result != 'N/A' and func_patch_time != '-' and func_test_time != '-':
        print(f'[{project}-{bug_id}] functional test patch_time={func_patch_time:.2f}s, test_time={func_test_time:.2f}s',
              file=sys.stderr, flush=True)
        print(f'[{project}-{bug_id}] functional test patch_time={func_patch_time:.2f}s, test_time={func_test_time:.2f}s',
              file=output_log, flush=True)
    
    # Which patch templates the plausible config used, tallied into the same 3 counters
    # (san2patch's own 'both'/'replace'/'insert'/'-' convention, see patch_template_usage) as
    # 0/1 for this one config; summing the columns over the corpus counts how many bugs'
    # plausible patch is replace-condition, insert or both. The `usage` label itself is not
    # kept in the result -- only the 3 counter columns -- so the CSV stays plain numbers,
    # easy to paste into a spreadsheet.
    usage_counts = {name: 0 for name in PATCH_TEMPLATE_USAGE_COUNTERS}
    patch_template_usage_tally(usage_counts, patch_template_usage(_patch_config))
    with open(os.path.join(project_workdir, f'san2patch-gumtree-result_run{run_idx}.json'), 'w') as f:
        json.dump({
            'result': 'Y' if patch_result else 'N',
            'parse_time': parse_time if parse_time != 0. else '-',
            'patch_time': patch_time if patch_time != 0. else '-',
            'test_time': test_time if test_time != 0. else '-',
            'func_result': 'Y' if func_result == True else 'N' if func_result == False else 'N/A',
            'func_patch_time': func_patch_time,
            'func_test_time': func_test_time,
            'condition replace': usage_counts['condition replace'],
            'insert': usage_counts['insert'],
            'both': usage_counts['both'],
        }, f)
    output_log.close()
    docker.stop_container(bug_id)


def _on_worker_error(exc: BaseException):
    """pool.apply_async swallows worker exceptions; print the full traceback to
    stderr exactly like Python's default handler. multiprocessing attaches the
    worker-side stack as the exception's __cause__ (a RemoteTraceback), so this
    surfaces the original crash site, not just the main-process re-raise.
    """
    traceback.print_exception(type(exc), exc, exc.__traceback__)


# Metric keys read out of a run's san2patch-parse-result_run<i>.json / interpreter-usage_run<i>.json
# and collected into the boxplot-ready dict below (see __main__). Kept as module-level constants so
# both the aggregation loop and (if ever needed) an external plotting script agree on the field list.
_RESULT_METRICS = ('result', 'parse_time', 'patch_time', 'test_time',
                   'func_result', 'func_patch_time', 'func_test_time',
                   'condition replace', 'insert', 'both')
_ABLATION_METRICS = ('unary', 'binary_arith', 'binary_cond', 'binary_relational', 'binary_bit',
                     'ternary', 'function_call', 'var_expr', 'field_expr', 'sizeof', 'literal',
                     'cast', 'subscript', 'assign', 'if', 'for', 'while', 'var_decl',
                     'flow_control', 'return')

# How many times to repeat the whole experiment per bug, so the boxplot has a real
# run-to-run distribution (binary-patch/test timing -- and occasionally result itself --
# can vary between runs) rather than one point per bug.
RUN_COUNT = 10


if __name__ == "__main__":
    parser = ArgumentParser(prog='run-san2patch', description='Run binary patcher to apply dev patch')
    parser.add_argument('-p', '--project', type=str, nargs='*', default=[],
                        help='Projects to checkout. Multiple projects available. Default: None')
    parser.add_argument('-b', '--bug-id', type=int, nargs='*', default=[],
                        help='Bug IDs to checkout. Multiple bug IDs available. Default: None')
    parser.add_argument('-j', '--jobs', type=int, default=1,
                        help='Number of parallel jobs to run. Default: 1')
    parser.add_argument('--use-msan', action='store_true',
                        help='Use bugs which use MSAN. Default: False')
    parser.add_argument('-m', '--mini', action='store_true',
                        help='Run mini benchmark on a small set of 5 bugs per project. Default: False')
    parser.add_argument('--run-func-test', action='store_true',
                        help='Run functional test after generating patch config. Default: False')
    parser.add_argument('-n', '--runs', type=int, default=RUN_COUNT,
                        help=f'Number of times to repeat the experiment per bug. Default: {RUN_COUNT}')
    args = parser.parse_args()

    projects:List[str] = args.project
    bug_ids:List[int] = args.bug_id

    # TODO: Temporary do not run whole benchmark
    if len(projects) == 0 and len(bug_ids) == 0:
        print('Either -p or -b option required', file=sys.stderr)
        exit(1)

    # Filter dataframe based on arguments
    df = pd.read_csv(os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'overview.csv'))
    projects_dir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects')

    # Boxplot-ready results, kept separate per project (one plot per project) and per bug
    # within a project (one boxplot-input list of RUN_COUNT values per bug, per metric):
    #   final_result[project][bug_id][metric] -> [value_run0, value_run1, ...]
    # ablation_result has the same shape for the interpreter node-usage counters.
    final_result: Dict[str, Dict[int, Dict[str, list]]] = {}
    ablation_result: Dict[str, Dict[int, Dict[str, list]]] = {}

    runned_bugs: Set[Tuple[str, int]] = set()
    for run_idx in range(args.runs):
        print(f'=== Run {run_idx + 1}/{args.runs} ===', file=sys.stderr, flush=True)
        pool = mp.Pool(processes=args.jobs)
        run_bugs: Set[Tuple[str, int]] = set()
        for index, row in df.iterrows():
            project = row['project']
            bug_id = row['localId']
            if (row['submodule_bug'] != 'N' or row['language'] != 'c' or row['patch url available?'] != 'Y' or
                row['ubuntu version'] != 20):
                # Excluded bugs
                continue
            if not args.use_msan and row['sanitizer'] == 'msan':
                # Exclude MSan
                continue
            if len(bug_ids) > 0 and bug_id not in bug_ids:
                # Test specified bugs only
                continue
            if len(projects) > 0 and project not in projects:
                # Test specified projects only
                continue
            if args.mini and str(bug_id) not in minibenchmark.ARVO_MINI[project]:
                # If mini benchmark, only run on a small set of bugs
                continue

            pool.apply_async(gen_plausible_patch_config_for_bug,
                             args=(project, bug_id, row['fuzz_target'],
                                   args.run_func_test, run_idx),
                             error_callback=_on_worker_error)
            run_bugs.add((project, bug_id))

        pool.close()
        pool.join()
        runned_bugs |= run_bugs

        # Read this run's per-bug result/interpreter-usage JSON (see
        # gen_plausible_patch_config_for_bug) and append each metric's value onto that
        # bug's list -- sorted so every run appends bugs in the same order, though the
        # dict key (not list position) is what actually keeps values matched to their bug.
        for project, bug_id in sorted(run_bugs):
            result_path = os.path.join(projects_dir, project, str(bug_id),
                                       f'san2patch-gumtree-result_run{run_idx}.json')
            try:
                with open(result_path) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                data = {}
            bug_result = final_result.setdefault(project, {}).setdefault(
                bug_id, {m: [] for m in _RESULT_METRICS})
            for metric in _RESULT_METRICS:
                bug_result[metric].append(data.get(metric))

    # One JSON file per project (not a combined CSV), so each is a self-contained input to
    # that project's own boxplot: {"<bug_id>": {"<metric>": [RUN_COUNT values], ...}, ...}
    for project, per_bug in final_result.items():
        out_path = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', f'rq1-san2patch-gumtree-result-{project}.json')
        with open(out_path, 'w') as f:
            json.dump({str(bug_id): metrics for bug_id, metrics in per_bug.items()}, f, indent=2)
        print(f'Wrote {out_path}', file=sys.stderr, flush=True)