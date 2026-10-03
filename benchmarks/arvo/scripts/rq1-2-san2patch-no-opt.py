from argparse import ArgumentParser
import bisect
import difflib
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
from typing import Dict, List, Optional, Set, TextIO, Tuple

# Add the san2patch subdirectory to sys.path to make the san2patch package importable
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'san2patch', 'san2patch'))

import pandas as pd

import docker
import minibenchmark
import checkout

# gpac-383825169, gpac-42532224, gpac-42531310, ffmpeg-42527871, libxml2-424613315, libxml2-424229869
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','..','..'))
CONTAINER_ROOT_DIR = '/root/project/metac'

# Tag of this experiment in the files it writes into a bug's work directory. The rq1-2 scripts
# (and san2patch itself) run over the same work directories, so a file of one would otherwise
# be overwritten by, or read back as, the file of another.
RESULT_TAG = 'no-opt'


def _patch_out_dir(work_dir: str) -> str:
    """Directory of this experiment's patched binaries (<binary>.inst) and patcher output."""
    return os.path.join(work_dir, 'san2patch-deepseek', RESULT_TAG)

# The AST comparisor is part of this repository rather than an installed package.
sys.path.insert(0, os.path.join(ROOT_DIR, 'ast-comparisor', 'src'))
from san2patch.patching.ast_comparisor import compare as ast_compare
from san2patch.patching.ast_comparisor.parser import parse_code


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
# Deterministic patch-config generation via this repository's AST comparisor.
#
# Rather than asking an LLM, we diff the original source (source/) against the
# *patched* source (san2patch-source/, with the diff applied) at the AST level
# (tree-sitter, via ast-comparisor), which ignores whitespace / reindentation and
# comments, and map the typed changes it reports onto metapro's patch templates:
# statements inserted, replaced or removed, and conditions rewritten.
#
# The comparisor reports every change at the location of the ORIGINAL code in source/,
# so each is mapped onto metapro-source -- the instrumented original, whose coordinates
# the binary patcher expects -- by _metapro_span: metapro-source sits a fixed
# PREPROC_LINE_OFFSET below source/, and among the statements starting on that line the
# one whose text is closest to the original supplies the columns. metapro's
# instrumentation is inline and can leave several statements on one line, which is why
# the closest-text choice (and not a line/column offset) is what makes this precise.
#
# No external tool is required: the AST diff used to be GumTree 3.0.0 with its c-srcml
# generator over srcml 1.0.0 output, both invoked as binaries on PATH.
# ---------------------------------------------------------------------------

# metapro-source is the instrumented original; it differs from source/ only by a
# single prepended line, so a statement at source line L is at metapro-source line
# L + PREPROC_LINE_OFFSET (verified: columns differ, but lines map by +1).
PREPROC_LINE_OFFSET = 1

# tree-sitter node types that represent a full statement: the candidates when locating a
# statement in metapro-source, mirroring the statements the comparisor aligns.
_STMT_TYPES = {'expression_statement', 'declaration', 'if_statement', 'while_statement',
               'for_statement', 'do_statement', 'switch_statement', 'return_statement',
               'break_statement', 'continue_statement', 'goto_statement'}

# metapro wraps every condition it can patch in this call:
#   __metapro_replace_cond_c(<id>, "<orig cond>", (unsigned int)(<orig cond>), "<func>")
# Its first argument is the patch id and its source span is the patch location. Note the original
# condition is evaluated as an argument, so a REPLACE_CONDITION patch cannot repair a fault that
# lies in the condition it replaces (see __metapro_replace_cond_c in metapro/include/_runtime_c.h).
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


# FFmpeg's libavutil/attributes.h defines these as bare macros (no parens) that expand to
# __attribute__((...)) / inline / nothing depending on the compiler. tree-sitter-c's grammar
# doesn't recognize an unknown bare identifier preceding a return type as an attribute, so
# e.g. "av_cold int foo(...)" desyncs the parser badly enough to corrupt the whole file's tree
# (confirmed on ffmpeg-42506578/libavcodec/mjpegdec.c: swallows everything into one root ERROR
# node, so ff_mjpeg_decode_sof's function_definition is never found). Blanked out (same length,
# so every downstream offset stays valid) rather than expanded, since the attribute itself
# carries no information this AST diff needs.
_ATTRIBUTE_MACRO_RE = re.compile(
    r'\b(av_always_inline|av_extern_inline|av_warn_unused_result|av_noinline|av_pure|'
    r'av_const|av_cold|av_flatten|attribute_deprecated|av_unused|av_used|av_alias|'
    r'av_noreturn)\b')

# A conditional-compilation directive appearing *inside* an expression/initializer (e.g. an
# array initializer picking elements in/out with #if/#endif, as in the same mjpegdec.c) is not
# a position tree-sitter-c's grammar accepts a preprocessor directive in (only declaration/
# statement level is), which can desync the parser as badly as the attribute macros above.
# Blanking every directive line (never the code between them) keeps all branches' bodies in
# the parsed text -- a "union of every #if branch" approximation that is wrong for compilation
# but fine for this AST diff, which only needs to locate statements/functions, not compile.
_PREPROC_DIRECTIVE_RE = re.compile(r'^([ \t]*)#\s*(if|ifdef|ifndef|elif|else|endif)\b.*$', re.M)


def _sanitize_for_ts(text: str) -> str:
    """Blank constructs tree-sitter-c's grammar cannot parse. Every replacement is same-length
    whitespace, so line/column positions computed from the *original* text stay valid against
    the parsed tree -- callers never need to know this happened."""
    text = _ATTRIBUTE_MACRO_RE.sub(lambda m: ' ' * len(m.group(0)), text)
    text = _PREPROC_DIRECTIVE_RE.sub(lambda m: ' ' * len(m.group(0)), text)
    return text


def _ts_parse(text: str):
    """Parse C source with tree-sitter and return the root node.

    tree-sitter indexes bytes, so the tree is built from `text` encoded as UTF-8 and node
    positions are translated back to character coordinates by _node_span -- the coordinates
    the rest of this module (and every emitted patch) uses."""
    return parse_code(_sanitize_for_ts(text).encode('utf-8', errors='replace'))


def _walk(node):
    """Every node of a subtree, parents before children (so the outermost match wins)."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _node_text(node, text: str, starts: List[int]) -> str:
    """The source text a node covers. Read from `text` rather than from `Node.text`, which a
    tree parsed without recording values does not carry (see parser.parse_code)."""
    span = _node_span(node, text, starts)
    return text[span[0]:span[1]]


def _byte_col_to_char(text: str, starts: List[int], line: int, byte_col: int) -> int:
    """A tree-sitter byte column on `line` (1-based) as a character column."""
    line_text = text[starts[line - 1]:starts[line] if line < len(starts) else len(text)]
    if byte_col == 0 or line_text.isascii():
        return byte_col
    return len(line_text.encode('utf-8', errors='replace')[:byte_col]
               .decode('utf-8', errors='replace'))


def _node_span(node, text: str, starts: List[int]):
    """tree-sitter node -> (start_off, end_off_exclusive, sline, scol0, eline, ecol_excl)
    using the file's line-start table: 1-based lines, 0-based start column and exclusive
    end column -- the span shape the whole module works with."""
    sline, eline = node.start_point[0] + 1, node.end_point[0] + 1
    scol = _byte_col_to_char(text, starts, sline, node.start_point[1])
    ecol = _byte_col_to_char(text, starts, eline, node.end_point[1])
    return starts[sline - 1] + scol, starts[eline - 1] + ecol, sline, scol, eline, ecol


def _function_name(node, text: str, starts: List[int]) -> str:
    """The name a function_definition declares: the first identifier of its declarator, which
    is the function's own name whatever pointer / parenthesized declarators wrap it."""
    declarator = node.child_by_field_name('declarator')
    if declarator is None:
        return None
    for child in _walk(declarator):
        if child.type == 'identifier':
            return _node_text(child, text, starts)
    return None


def _function_node(root, func: str, text: str, starts: List[int]):
    """The function_definition of `func` in a tree, or None if it holds no such function."""
    for node in _walk(root):
        if node.type == 'function_definition' and _function_name(node, text, starts) == func:
            return node
    return None


def _function_text_span(text: str, starts: List[int], func: str):
    """(start_off, end_off) of `func`'s definition, located textually.

    Used when tree-sitter cannot parse a file cleanly enough to see the definition at all:
    macro-heavy C leaves ERROR regions, and a function inside one is no function_definition
    (srcML parses some of those). The definition opens on the line that has `func(` with no
    trailing `;` -- at column 0, or after a return type on the same line -- takes the return
    type written on the line above it with it, and ends where its body's braces balance again.
    Returns None when the text holds no such definition."""
    opener = re.compile(rf'^(?:[A-Za-z_][A-Za-z_0-9\s\*]*?\b)?{re.escape(func)}\s*\([^;]*$')
    for line_no in range(1, len(starts) + 1):
        line_end = starts[line_no] if line_no < len(starts) else len(text)
        line = text[starts[line_no - 1]:line_end].rstrip('\n')
        if not opener.match(line):
            continue
        start_line = line_no
        if line.startswith(func) and start_line > 1:
            # `int\nfunc(...)`: the return type sits on the line above the name.
            previous = text[starts[start_line - 2]:starts[start_line - 1]].strip()
            if (previous and not previous.endswith((';', '}', '{', ',', '*/'))
                    and not previous.startswith(('#', '/', '*'))):
                start_line -= 1
        brace = text.find('{', starts[line_no - 1])
        if brace == -1:
            return None
        return starts[start_line - 1], _skip_balanced(text, brace, '{', '}')
    return None


def _sliced_function_node(root):
    """The function_definition of a sliced tree, which holds exactly one function (see
    _slice_function), or None when the slice does not parse as a function."""
    for node in _walk(root):
        if node.type == 'function_definition':
            return node
    return None


def _enclosing_function(root, off: int, text: str, starts: List[int]):
    """Name of the innermost function whose source span contains `off`."""
    best, best_off = None, -1
    for node in _walk(root):
        if node.type != 'function_definition':
            continue
        span = _node_span(node, text, starts)
        if span[0] <= off < span[1] and span[0] > best_off:
            best, best_off = node, span[0]
    return _function_name(best, text, starts) if best is not None else None


# Instrumentation calls that stand in for one of their own arguments, and which argument:
# the condition wrapper carries the original condition as its 2nd argument (a string literal),
# and the for-init registration evaluates to its last (see __metapro_init_var_c). Folding these
# back is what _uninstrumented does. Other instrumentation -- variable registration, the return
# and switch-arming preambles -- sits in statements of its own, so it never inflates the text of
# the statement it accompanies.
_INSTR_STANDINS = {_COND_WRAPPER: 1, '__metapro_init_var_c': -1}

# How close two candidates' scores have to be for _best_stmt_span_at_line to look past the plain
# text ratio. Only near-ties are re-judged, so a decision with a clear winner keeps whatever the
# ratio alone picked; the tie this exists for was decided by 0.001 (see below).
_TIE_EPSILON = 0.05


def _uninstrumented(node, text: str, starts: List[int]) -> str:
    """`node`'s text with metapro's instrumentation folded back to what it stands for, e.g.

        if (__metapro_replace_cond_c(4970, "i & 7", (unsigned int)(i & 7), "unpack_bstr")) { ... }
     -> if (i & 7) { ... }

    Read off the tree rather than by pattern-matching the text, so a nested call, a parenthesis
    inside a string literal or an escaped quote cannot throw the substitution off. The outermost
    match wins: once a call is folded, the calls inside it are already covered (_walk yields
    parents first)."""
    pieces: List[str] = []
    span = _node_span(node, text, starts)
    cur = span[0]
    for call in _walk(node):
        if call.type != 'call_expression':
            continue
        call_span = _node_span(call, text, starts)
        if call_span[0] < cur:
            continue                                  # inside a call already folded
        function = call.child_by_field_name('function')
        if function is None:
            continue
        index = _INSTR_STANDINS.get(_node_text(function, text, starts).strip())
        if index is None:
            continue
        arguments = call.child_by_field_name('arguments')
        args = ([a for a in arguments.named_children if a.type != 'comment']
                if arguments is not None else [])
        if len(args) < 4:
            continue
        stand_in = args[index]
        value = _node_text(stand_in, text, starts).strip()
        if stand_in.type == 'string_literal':
            value = _unescape_str_literal(value)
        pieces.append(text[cur:call_span[0]])
        pieces.append(value)
        cur = call_span[1]
    pieces.append(text[cur:span[1]])
    return ''.join(pieces)


def _best_stmt_span_at_line(root, text: str, starts: List[int], line: int, ref_text: str,
                            ref_type: Optional[str] = None):
    """Among statements that *start* on `line` (1-based) in metapro-source, return the
    _node_span whose covered text is closest to `ref_text` -- the original statement from
    source, whitespace-normalized.

    metapro-source is instrumented, so one line can carry several statements (e.g. a
    wrapped condition `__metapro_replace_cond_c(...)` next to the real one). Choosing
    the candidate with the lowest text distance from the original locates the right
    statement -- and thus the correct start/end column -- where a smallest-span
    heuristic could not. Returns None if no statement starts on `line`.

    `ref_type` is the original statement's node type, and candidates of that type are
    preferred outright: instrumenting a statement never changes what kind of statement it is
    (a wrapped condition leaves an `if` an `if`, a registration leaves a declaration a
    declaration), so a candidate of another type is not the statement being looked for, however
    close its text. Text alone gets this wrong when the wrappers outweigh the statement itself:
    in memsearch_swar of mruby-42532953 the `if (memcmp(p+1, xs+1, m-1) == 0) return ...;` being
    inserted in front of scored 0.366 against the `return (mrb_int)(p - ys);` nested in its own
    then-branch at 0.602, so the guard was placed after the read it was meant to prevent and the
    patched build reproduced the original crash. When no candidate has that type, all of them are
    considered, as before.

    Candidates within _TIE_EPSILON of the best are then re-judged on their *un-instrumented*
    text. The wrappers inflate a candidate that carries them, which costs an instrumented
    statement roughly as much ratio as being the wrong statement entirely: in unpack_bstr of
    mruby-42528658 the `if (i & 7) ... else ...` that was replaced scored 0.318 while the bare
    `bits <<= 1;` nested inside it scored 0.319, so the anchor landed on the shift, the else
    branch holding the out-of-bounds read was never disabled, and the patched build reproduced
    the original crash. Folding the wrappers away makes that comparison 0.739 vs 0.319. Only
    near-ties are re-judged, so decisions the ratio already makes confidently are untouched.

    Returns (span, node) -- the node too, so a caller trimming a removed if/while/for/do
    (see _derive_patches) can read its own consequence/body field instead of re-finding it."""
    scored = []
    for node in _walk(root):
        if node.type not in _STMT_TYPES or node.start_point[0] + 1 != line:
            continue
        span = _node_span(node, text, starts)
        cand = _norm(text[span[0]:span[1]])
        scored.append((difflib.SequenceMatcher(None, cand, ref_text).ratio(), node, span))
    if not scored:
        return None
    typed = [entry for entry in scored if entry[1].type == ref_type]
    if typed:
        scored = typed
    best_ratio = max(ratio for ratio, _node, _span in scored)
    tied = [entry for entry in scored if best_ratio - entry[0] <= _TIE_EPSILON]
    if len(tied) == 1:
        return tied[0][2], tied[0][1]
    # max() keeps the first of equal keys and `tied` is in _walk order, so a tie that the plain
    # ratio cannot break either resolves to the same candidate as before.
    best = max(tied, key=lambda entry: (difflib.SequenceMatcher(
        None, _norm(_uninstrumented(entry[1], text, starts)), ref_text).ratio(), entry[0]))
    return best[2], best[1]


def _node_at(root, line: int, col: int, at_end: bool = False):
    """The outermost named node that starts -- or with `at_end`, ends -- exactly at
    `line`:`col` (1-based line, 0-based column).

    This is how a location the comparisor reports is turned back into the original
    statement it belongs to: a change is reported at the start of the statement it applies
    to, and an insertion at the end of the block\'s last statement when it goes behind it.
    Returns None when no statement boundary sits there (e.g. an insertion into an empty
    block, whose location is the opening brace)."""
    point = (line - 1, col)
    for node in _walk(root):
        if not node.is_named:
            continue
        if (node.end_point if at_end else node.start_point) == point:
            return node
    return None


def _statement_of(node, at_end: bool = False):
    """The statement a patch location belongs to.

    A location can sit on a node that metapro-source cannot be searched for (see
    _best_stmt_span_at_line): a preprocessor conditional, whose own line holds a directive and
    not code, a `case` label, or a bare block. The statement it holds stands in for it -- the
    one starting first, or with `at_end` the one ending last -- which is also what gets
    disabled or replaced, leaving the directive, label or brace line itself in place."""
    if node is None or node.type in _STMT_TYPES:
        return node
    inner = [n for n in _walk(node) if n.type in _STMT_TYPES]
    if not inner:
        return None
    return max(inner, key=lambda n: n.end_byte) if at_end else min(inner, key=lambda n: n.start_byte)


def _ref_end_linecol(text: str, starts: List[int], start_off: int, ref_norm: str):
    """Walk `text` from `start_off` until the whitespace-normalized content equals
    `ref_norm`, and return (end_line, end_col) for that point in the same convention as
    _node_span (1-based line of the last char, col == that char's 0-based col + 1).

    Used to trim a metapro-source statement span that reaches past the original statement:
    metapro appends a filler `else if (...) { ; } else { ; }` to an instrumented `if`, so the
    instrumented statement ends lines below the original closing `}`. Matching against the
    original statement's exact text recovers the true end. Returns None if ref_norm is not
    reached."""
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



def _parse_unified_diff(diff_path: str) -> Dict[str, dict]:
    """Parse a unified diff into {relative_path: {'hunks', 'added', 'removed'}}:

    * 'hunks'  -- (b_start, b_end, a_start, a_end, net) 1-based inclusive line ranges in
                  the before(source)/after(san2patch-source) files, plus how many lines the
                  hunk adds (added minus removed). The ranges are clamped to at least one
                  line so they stay usable as intervals, which loses the count of a pure
                  insertion (`@@ -216,0 +218 @@` is a zero-line before-range): `net` carries
                  the real delta, so a caller shifting line numbers does not have to infer it
                  from the ranges. See slice_after_function.
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
                                        ac - bc))
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


def _cond_wrappers(m_root, m_text: str, m_starts: List[int], lines):
    """metapro __metapro_replace_cond_c(id, "orig", (unsigned int)(orig), "func") calls
    that *start on one of* `lines` (the patched metapro lines). Returns a list of
    {id, orig, func, span}: the patch id (1st arg), the original condition text
    (2nd arg, whitespace-normalized), the function name (4th arg) and the call's
    source span -- exactly the coordinates a REPLACE_CONDITION patch is reported at.

    metapro instruments *every* condition in the file, so the tree holds thousands of
    these (plus far more unrelated instrumentation calls). Filtering by start line --
    cheap, straight from the node position -- before the costlier name/argument extraction
    keeps this to the handful of conditions the diff actually touched."""
    out = []
    for call in _walk(m_root):
        if call.type != 'call_expression' or call.start_point[0] + 1 not in lines:
            continue
        name = call.child_by_field_name('function')
        if name is None or _node_text(name, m_text, m_starts).strip() != _COND_WRAPPER:
            continue
        alist = call.child_by_field_name('arguments')
        args = [a for a in alist.named_children if a.type != 'comment'] if alist is not None else []
        if len(args) < 4:
            continue
        id_txt = _node_text(args[0], m_text, m_starts).strip()
        if not id_txt.isdigit():
            continue
        out.append({
            'id': int(id_txt),
            'orig': _norm(_unescape_str_literal(_node_text(args[1], m_text, m_starts).strip())),
            'func': _unescape_str_literal(_node_text(args[3], m_text, m_starts).strip()),
            'span': _node_span(call, m_text, m_starts),
        })
    return out


def parse_function_range(before_path: str, before_text: str, before_starts: List[int], func: str):
    """Locate `func`'s definition in the original source.

    Computed directly from `before_text` rather than read from metapro's
    patch-info.json: parse the file, find the function_definition that declares
    `func`, and take its source span -- from the start of its signature (column 0
    for a top-level definition) through its closing `}`.

    Returns a triple:
      * (start_line, start_col, end_line, end_col) -- 1-based lines, 0-based start
        column and exclusive end column, in the same convention as _node_span.
        The other coordinate systems follow from these without re-parsing: the
        after-patch line is recoverable from the diff hunks, and metapro-source
        sits a fixed PREPROC_LINE_OFFSET below the before line.
      * before_sliced_function -- `before_text` with every line outside the
        function blanked out (positions preserved, see _slice_function).
      * before_ast -- the root of the sliced function's own tree, so callers walk
        only the patched function.

    The span is read from the sliced function's own tree rather than from the
    whole-file one, so it agrees with the tree callers get (the two can disagree:
    an ERROR region in the file can swallow a definition the slice parses fine).
    Returns (None, None, None, None), None, None if the function is not found.
    """
    fn = _function_node(_ts_parse(before_text), func, before_text, before_starts)
    if fn is not None:
        span = _node_span(fn, before_text, before_starts)[:2]
    else:
        span = _function_text_span(before_text, before_starts, func)
    if span is not None:
        before_sliced_function = _slice_function(before_text, *span)
        sliced_starts = _line_starts(before_sliced_function)
        before_ast = _ts_parse(before_sliced_function)
        fn = _function_node(before_ast, func, before_sliced_function, sliced_starts)
        if fn is not None:
            _s, _e, sline, scol, eline, ecol = _node_span(fn, before_sliced_function, sliced_starts)
            return (sline, scol, eline, ecol), before_sliced_function, before_ast

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


def slice_after_function(after_text: str, a_starts: List[int], hunks,
                         before_start_line: int, before_start_col: int,
                         before_end_line: int, before_end_col: int):
    """After-patch counterpart of parse_function_range, derived from the diff
    instead of a second lookup by name (which a diff that renames the function
    would defeat).

    The signature and closing-brace lines move down by however many lines the
    diff adds (added minus removed) *above* them, so we map each before-patch
    boundary through the hunks. `hunks` are the (b_start, b_end, a_start, a_end, net)
    entries from _parse_unified_diff, whose `net` is how many lines the hunk adds. Deriving
    that from the ranges instead reads 0 for every pure insertion, because a zero-line
    before-range is stored clamped to one line: on ffmpeg-42525124, a zero-context diff of
    nine single-line insertions came out as +4, and the function was sliced four lines short
    of its closing braces, so it no longer parsed as a function at all. On ffmpeg-42527871 the
    same undercount cut three lines, which left the last statement (`return 0;`) out of the
    after-body and made the comparisor report it as removed.

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

    The sliced function is parsed on its own, so the returned tree holds only the
    patched function (positions preserved, matching the full after-source
    coordinates) -- callers walk it instead of the whole after tree.

    Returns (start_line, start_col, end_line, end_col), after_sliced_function,
    after_ast -- the same shape as parse_function_range. Start/end columns are
    inherited from the before-patch span: the signature and closing-brace lines
    are not touched by the diff."""
    start_net = 0
    end_net = 0
    for hunk in hunks:
        b_start, b_end, a_start, a_end = hunk[:4]
        # Older callers pass the 4-tuple without a recorded delta; fall back to the ranges
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
    return ((start_line, before_start_col, end_line, before_end_col), after_sliced_function,
            _ts_parse(after_sliced_function))


def slice_metapro_function(m_text: str, m_starts: List[int],
                           before_start_line: int, before_start_col: int,
                           before_end_line: int, before_end_col: int):
    """metapro-source counterpart of parse_function_range.

    metapro-source is the instrumented original and differs from source/ only by a
    single prepended line (PREPROC_LINE_OFFSET); instrumentation is inline and adds
    no lines, so the patched function occupies the same line range shifted down by
    that offset, and the structural start/end columns (signature / closing `}`)
    carry over unchanged.

    The sliced function is parsed on its own, so the returned tree holds only the
    patched function (positions preserved, matching the full metapro-source
    coordinates the binary patcher expects) -- callers walk it instead of the whole,
    possibly huge, instrumented file.

    Returns (start_line, start_col, end_line, end_col), m_sliced_function, m_ast --
    the same shape as parse_function_range."""
    start_line = before_start_line + PREPROC_LINE_OFFSET
    end_line = before_end_line + PREPROC_LINE_OFFSET
    start_off = m_starts[start_line - 1]
    end_off = m_starts[end_line] if end_line < len(m_starts) else len(m_text)
    m_sliced_function = _slice_function(m_text, start_off, end_off)
    return ((start_line, before_start_col, end_line, before_end_col), m_sliced_function,
            _ts_parse(m_sliced_function))


def _metapro_span(stmt, before_text: str, before_starts: List[int],
                  m_root, m_text: str, m_starts: List[int]):
    """Map a statement of source/ onto the matching statement of metapro-source.

    Returns (span, node, ref_text): the metapro-source _node_span of the statement, that
    statement's own metapro-source node, and the original statement's whitespace-normalized
    text that located it. metapro-source sits PREPROC_LINE_OFFSET below source/, and among the
    statements starting on that line the one of the same kind, closest in text, is the
    statement (see _best_stmt_span_at_line). Returns (None, None, ref_text) when metapro-source
    has no statement on that line."""
    span = _node_span(stmt, before_text, before_starts)
    ref_text = _norm(before_text[span[0]:span[1]])
    found = _best_stmt_span_at_line(m_root, m_text, m_starts,
                                    span[2] + PREPROC_LINE_OFFSET, ref_text,
                                    ref_type=stmt.type)
    if found is None:
        return None, None, ref_text
    m_span, m_node = found
    return m_span, m_node, ref_text


def _stmt_metapro_range(location, before_root, before_text: str, before_starts: List[int],
                        m_root, m_text: str, m_starts: List[int], at_end: bool = False):
    """The metapro-source span of the original statement at a location the comparisor
    reported, plus that statement's own metapro-source node and its normalized text.
    (None, None, None) when the location is not a statement boundary or the statement cannot
    be found in metapro-source."""
    stmt = _statement_of(_node_at(before_root, location.line, location.col, at_end=at_end),
                         at_end=at_end)
    if stmt is None:
        return None, None, None
    return _metapro_span(stmt, before_text, before_starts, m_root, m_text, m_starts)


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


def _derive_patches(diff_file_path: str, before_path: str, after_path: str, metapro_path: str,
                    rel_path: str, info: dict, loc_ids: Dict[str, int], macros=None, func_name=None):
    """Derive the patches for one patched function from the changes the AST comparisor finds.

    `func_name` selects the function to slice and compare (a file's diff may patch several --
    see _patched_function_names); it defaults to the first one the diff touches.

    The comparisor aligns the original function body against the patched one and reports
    every difference as one of:

    * INSERT_EXPR -- statement(s) that only exist in the patched body. Located at the
      original statement they were added in front of; when they were added at the end of a
      block, at its last statement's end as a zero-width span (an after-insertion).
    * INSERT_EXPR + INSERT_NOT_NULL_CHECKER `0` -- statement(s) that were rewritten: the new
      text is inserted at, and the original disabled over, the original statement(s). Both
      are reported at that one location, so they also share an id.
    * INSERT_NOT_NULL_CHECKER `0` -- statement(s) removed outright, disabled in place. The
      span is trimmed to the original statement's text, since metapro's instrumentation
      reaches past it (a filler `else if (...) { ; } else { ; }` on an instrumented `if`).
    * REPLACE_CONDITION -- an if/while/for/do condition that was rewritten, either with a new
      sub-condition added before or after it (`&&`/`||`, two exprs) or replaced as a whole
      (one expr). Its id, function and span come from metapro's wrapper for that condition
      (see _cond_wrappers), which is the id the patcher expects -- not from `loc_ids`.

    Every other location is mapped from source/ onto metapro-source by _metapro_span.
    Reformatting is not a difference to the comparisor (whitespace and comments are ignored),
    so no diff-text gate is needed; what it could not express as a patch is counted in its
    SKIPPED list. Patches at the same location share an id via `loc_ids`.
    Returns (patches, num_skipped).
    """
    if func_name is None:
        func_name = _patched_function_name(diff_file_path, rel_path)
    before_text = _read_text(before_path)
    before_starts = _line_starts(before_text)
    start_time = time.time()
    ((before_func_start_line, before_func_start_col,
      before_func_end_line, before_func_end_col),
      before_sliced_function, before_root) = parse_function_range(
        before_path,
        before_text,
        before_starts,
        func_name
    )
    if before_sliced_function is None:
        return [], 0  # function not located in source -> nothing to derive for it
    print(f'Parse before-tree for {rel_path} in {time.time() - start_time:.1f}s')
    # _slice_function preserves line/col but collapses each pre-function line to a bare '\n',
    # so char offsets shift. Rebuild the line-start table from the sliced text so _node_span
    # yields offsets into before_sliced_function -- the text the comparison runs on.
    before_text = before_sliced_function
    before_starts = _line_starts(before_sliced_function)

    after_text = _read_text(after_path)
    a_starts = _line_starts(after_text)
    start_time = time.time()
    (_after_func_span, after_sliced_function, after_root) = slice_after_function(
        after_text, a_starts, info['hunks'],
        before_func_start_line, before_func_start_col,
        before_func_end_line, before_func_end_col)
    print(f'Parse after-tree for {rel_path} in {time.time() - start_time:.1f}s')
    after_text = after_sliced_function

    m_text = _read_text(metapro_path)
    m_starts = _line_starts(m_text)
    start_time = time.time()
    ((metapro_func_start_line, metapro_func_start_col,
      _metapro_func_end_line, _metapro_func_end_col),
     m_sliced_function, m_root) = slice_metapro_function(
        m_text, m_starts,
        before_func_start_line, before_func_start_col,
        before_func_end_line, before_func_end_col)
    print(f'Parse metapro-tree for {rel_path} in {time.time() - start_time:.1f}s')
    # Rebuild from the sliced text (see before_starts) so _node_span / _best_stmt_span_at_line
    # index m_sliced_function consistently.
    m_text = m_sliced_function
    m_starts = _line_starts(m_sliced_function)
    local_vars = _registered_var_names(m_text)

    # m_root holds only the patched function (sliced), so the enclosing function is the
    # same for every INSERT/REMOVE patch -- resolve its name once instead of re-walking
    # the tree per change. (REPLACE_CONDITION reads its function from the cond wrapper.)
    # It is the function that was sliced, so fall back to that name when the instrumented
    # slice does not parse cleanly enough to name it.
    func = _enclosing_function(m_root, m_starts[metapro_func_start_line - 1] + metapro_func_start_col,
                               m_text, m_starts) or func_name

    before_body = _sliced_function_node(before_root)
    after_body = _sliced_function_node(after_root)
    before_body = before_body.child_by_field_name('body') if before_body is not None else None
    after_body = after_body.child_by_field_name('body') if after_body is not None else None
    if before_body is None or after_body is None:
        print(f'Warning: function body not parsed for {func_name} in {rel_path}')
        return [], 0

    # --- compare the original body against the patched one ----------------------------
    start_time = time.time()
    ast_compare.COMPARE_RESULT.clear()
    ast_compare.PATCH_IDS.clear()
    ast_compare.SKIPPED.clear()
    ast_compare.compare_compound_stmt(before_body, after_body,
                                      before_text.encode('utf-8', errors='replace'),
                                      after_text.encode('utf-8', errors='replace'))
    changes = list(ast_compare.COMPARE_RESULT)
    skipped = len(ast_compare.SKIPPED)
    print(f'AST comparison for {rel_path} in {time.time() - start_time:.1f}s '
          f'({len(changes)} change(s), {skipped} skipped)')

    patches = []
    index = 0
    while index < len(changes):
        change = changes[index]
        index += 1

        # --- REPLACE_CONDITION: a condition was rewritten -----------------------------
        # metapro has already wrapped each condition in __metapro_replace_cond_c(id, "orig",
        # ...), so that call supplies the patch id, the function and the source location; the
        # rewritten condition (and any operator) is what the comparisor reports. Of the
        # wrappers on the mapped line -- an instrumented `if` also carries filler ones for
        # its `else if` -- the one recording this condition as its original is ours.
        if change.patch_type == 'REPLACE_CONDITION':
            cond_line = change.start_location.line + PREPROC_LINE_OFFSET
            cond_text = _norm(before_text[
                before_starts[change.start_location.line - 1] + change.start_location.col:
                before_starts[change.end_location.line - 1] + change.end_location.col])
            wrappers = _cond_wrappers(m_root, m_text, m_starts, {cond_line})
            wrapper = next((w for w in wrappers if w['orig'] == cond_text),
                           wrappers[0] if wrappers else None)
            if wrapper is None:
                skipped += 1  # the condition is not instrumented -> no id to patch it with
                continue
            exprs = [e for e in (change.cond_expr1, change.cond_expr2) if e]
            span = wrapper['span']
            patches.append({
                'id': wrapper['id'],
                'template': 'REPLACE_CONDITION',
                'function': wrapper['func'],
                'file': rel_path,
                'line': span[2],
                'col': span[3],
                'exprs': [_escape_expr(e, macros, local_vars) for e in exprs],
                'end_line': span[4],
                'end_col': span[5] + 1,
            })
            continue

        if func is None:
            skipped += 1
            continue

        # A rewrite is reported as the new text plus a checker that disables the original,
        # in that order and sharing the location's id.
        checker = None
        if (change.patch_type == 'INSERT_EXPR' and index < len(changes)
                and changes[index].patch_type == 'INSERT_NOT_NULL_CHECKER'
                and changes[index].id == change.id):
            checker = changes[index]
            index += 1
        elif change.patch_type == 'INSERT_NOT_NULL_CHECKER':
            checker = change
            change = None

        # --- INSERT_EXPR: statement(s) added where nothing was removed ----------------
        if checker is None:
            # Located at the original statement the new code goes in front of, or -- when it
            # goes at the end of the block -- at the last statement's end. A zero-width span
            # (start == end) marks such an after-insertion rather than a span to replace.
            span, _node, _ref = _stmt_metapro_range(change.inserted_location, before_root,
                                                    before_text, before_starts, m_root,
                                                    m_text, m_starts)
            insert_after = False
            if span is None:
                span, _node, _ref = _stmt_metapro_range(change.inserted_location, before_root,
                                                         before_text, before_starts, m_root,
                                                         m_text, m_starts, at_end=True)
                insert_after = True
            if span is None:
                skipped += 1
                continue
            if insert_after:
                line, col = span[4], span[5] + 1
                end_line, end_col = line, col
            else:
                line, col = span[2], span[3]
                end_line, end_col = span[4], span[5] + 1
            clean = _strip_blacklisted_calls(change.inserted_expr)
            if not clean:
                # nothing but a blacklisted (log/print) call -- drop the patch entirely
                continue
            patches.append({
                'template': 'INSERT_EXPR',
                'function': func,
                'file': rel_path,
                'line': line,
                'col': col,
                'exprs': [_escape_expr(_insert_expr_text(clean), macros, local_vars)],
                'end_line': end_line,
                'end_col': end_col,
            })
            continue

        # --- the original statement(s) are disabled, and replaced when there is new text --
        first_span, _first_node, _first_ref = _stmt_metapro_range(
            checker.start_location, before_root, before_text, before_starts, m_root,
            m_text, m_starts)
        last_span, last_node, last_ref = _stmt_metapro_range(
            checker.end_location, before_root, before_text, before_starts, m_root,
            m_text, m_starts, at_end=True)
        if first_span is None or last_span is None:
            skipped += 1
            continue
        end_line, end_col = last_span[4], last_span[5] + 1
        if (end_line, end_col) < (first_span[2], first_span[3]):
            # The two ends are located independently, each by closest text on its own line, so
            # a mismatched one can land before the start. Such a span patches the wrong code.
            skipped += 1
            continue
        if change is None:
            # A removal is disabled in place. metapro's instrumentation reaches past the
            # original statement (the filler `else if` chain it appends to an `if`), so trim
            # the end back to where the original statement's text ends.
            #
            # When the removed statement is itself an if/while/for/do, metapro also wraps its
            # *condition* inline (__metapro_replace_cond_c(id, "cond text", ..., func)), which
            # can make the instrumented text far longer than the original well before the body
            # even starts. _ref_end_linecol's char-count heuristic assumes equal length up to
            # the target and lands inside that wrapper call instead -- confirmed on
            # ffmpeg-42527915/libavcodec/vlc.c: removing `if (codes != localbuf) av_free(codes);`
            # trimmed to right after the wrapped condition's id argument, leaving `av_free`
            # itself un-disabled, so the patched binary still freed `codes` in vlc_common_end
            # and the caller's own new use of it (chained after vlc_common_end's call) crashed
            # with a heap-use-after-free. metapro leaves the body/consequence field's own text
            # untouched (at most adding braces around a brace-less one), so its node span in
            # the already-parsed metapro tree gives the true end directly, with no need to
            # count through the wrapped condition at all.
            trimmed = None
            if last_node is not None:
                body_field = {'if_statement': 'consequence', 'while_statement': 'body',
                              'for_statement': 'body', 'do_statement': 'body'}.get(last_node.type)
                body = last_node.child_by_field_name(body_field) if body_field else None
                if body is not None:
                    body_span = _node_span(body, m_text, m_starts)
                    trimmed = (body_span[4], body_span[5] + 1)
            if trimmed is None:
                trimmed = _ref_end_linecol(m_text, m_starts, last_span[0], last_ref)
            if trimmed is not None:
                end_line, end_col = trimmed
        loc_fields = {'function': func, 'file': rel_path,
                      'line': first_span[2], 'col': first_span[3],
                      'end_line': end_line, 'end_col': end_col}
        # Insert the replacement statement -- unless it was nothing but a blacklisted
        # (log/print) call, in which case the replace degrades to a plain removal (the
        # disabling INSERT_NOT_NULL_CHECKER "0" below still fires).
        clean = _strip_blacklisted_calls(change.inserted_expr) if change is not None else ''
        if clean:
            patches.append({'template': 'INSERT_EXPR', **loc_fields,
                            'exprs': [_escape_expr(_insert_expr_text(clean), macros, local_vars)]})
        patches.append({'template': 'INSERT_NOT_NULL_CHECKER', **loc_fields,
                        'exprs': [checker.new_condition]})

    # Several statements inserted at one point (e.g. a guard, a new declaration and a clamp
    # added together) can end up as one INSERT_EXPR per statement, all at the same location.
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

    new_env['METAPRO_TARGET_FUNCTIONS'] = 'all'
    new_env['METAPRO_DISABLE_CACHE'] = '1'
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

    # res = docker.checkout(project, bug_id, host_mount_path, install_dependency=True)
    # if not res:
    #     print(f'Failed to checkout {project}-{bug_id}')
    #     return False
    docker.start_container(bug_id)
    # res = checkout.setup_metapro(project, bug_id)
    # if not res:
    #     print(f'Failed to setup metapro for {project}-{bug_id}')
    #     return False
    
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
        with open(os.path.join(project_workdir, f'san2patch-no-opt-result_run{run_idx}.json'), 'w') as f:
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
    with open(os.path.join(project_workdir, f'san2patch-no-opt-result_run{run_idx}.json'), 'w') as f:
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
                                       f'san2patch-no-opt-result_run{run_idx}.json')
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
        out_path = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', f'rq1-san2patch-no-opt-result-{project}.json')
        with open(out_path, 'w') as f:
            json.dump({str(bug_id): metrics for bug_id, metrics in per_bug.items()}, f, indent=2)
        print(f'Wrote {out_path}', file=sys.stderr, flush=True)