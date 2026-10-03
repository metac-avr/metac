import difflib
import re
import tree_sitter as ts
from logging import getLogger

from .template import *


__LOGGER = getLogger(__name__)
COMPARE_RESULT = []
# One message per difference that was found but cannot be expressed with any patch template,
# so callers can report how much a comparison had to leave out. Reformatting is NOT in here:
# whitespace and comments are not differences at all (see _signature). Clear it together with
# COMPARE_RESULT.
SKIPPED = []
# Patch id of every location that has been patched, keyed by its (start line, start col,
# end line, end col) in the original code. Patches of one location share their id, so this
# is what keeps ids unique per location; clear it together with COMPARE_RESULT.
PATCH_IDS = {}

# Node types that carry no semantics and are therefore ignored while comparing.
__IGNORED_TYPES = ('comment',)
# Statements that are controlled by a condition, which is patchable on its own.
__CONDITION_TYPES = ('if_statement', 'while_statement', 'do_statement', 'for_statement',
                     'switch_statement')
# Statements that hold a statement list of their own instead of a single body: a change inside
# one is compared statement by statement, exactly like a block (see _narrowed_diffs), so a
# `case` that gains a statement is that one insertion and not a rewritten `switch`.
__STMT_CONTAINER_TYPES = ('compound_statement', 'case_statement', 'preproc_if', 'preproc_ifdef',
                          'preproc_else', 'preproc_elif', 'preproc_elifdef')
# The child of a container that says which statements it holds rather than being one of them: a
# `case` label, a preprocessor condition or macro name. Two containers with an equal header
# hold the same statements.
__CONTAINER_HEADER_FIELDS = ('value', 'condition', 'name')
# Alignment score of a statement pair that needs no patch at all, and of one that is equal
# except in a part that is patched on its own. Both are above any similarity score (<= 1.0),
# so unchanged statements are always preferred as the anchors of the alignment.
__EQUAL_SCORE = 3.0
__NARROWED_SCORE = 2.0
# Minimum similarity for two statements to be paired up as a replacement instead of
# being an unrelated statement each. Statements of a different kind (e.g. a `return`
# replaced by an `if`) must look much more alike to be paired up.
__SAME_TYPE_THRESHOLD = 0.4
__DIFF_TYPE_THRESHOLD = 0.7
# Condition of the checker that disables an original statement: never true, so the
# statement it wraps is never executed.
__DISABLE_COND = '0'
# The call metapro wraps every patchable condition in. Its first argument is the patch id of
# that condition.
__COND_WRAPPER = '__metapro_replace_cond_c'


def compare_nodes(node1: ts.Node, node2: ts.Node, code1: bytes, code2: bytes):
    # Handle parenthesized expressions
    if node1.type == 'parenthesized_expression':
        node1 = node1.named_child(0)
    if node2.type == 'parenthesized_expression':
        node2 = node2.named_child(0)

    #1: Compound stmt
    if node1.type == "compound_statement" and node2.type == "compound_statement":
        return compare_compound_stmt(node1, node2, code1, code2)

    #2: Anything else is equal when both subtrees are the same code, ignoring whitespace
    # and comments. Nothing to patch on its own: the caller decides what to report.
    return _signature(node1, code1) == _signature(node2, code2)


def compare_compound_stmt(node1: ts.Node, node2: ts.Node, code1: bytes, code2: bytes):
    """
    Compound statement comparison logic.

    The statement list of the original block is aligned with the statement list of the
    patched block, and every difference is reported with the templates that can express
    it, always at the location of the ORIGINAL statement(s) it applies to:

    1. Statement(s) added: an INSERT_EXPR that inserts them before the original statement
       the alignment put them in front of (before the statement following the insertion
       point, so the new code lands exactly where it was added).
    2. Statement(s) replaced: an INSERT_EXPR carrying the new statement(s), plus an
       INSERT_NOT_NULL_CHECKER with a never true `0` condition that disables the original
       statement(s) it replaces. Both are applied at the very same location -- the
       INSERT_EXPR inserts where the checker starts disabling -- and share its patch id.
    3. Statement(s) removed: an INSERT_NOT_NULL_CHECKER with a `0` condition that disables
       them.

    A change inside a statement (`int* a;` -> `int* a = NULL;`, an added initializer) is a
    replacement of the whole statement, never an insertion of the changed sub node. The
    exception is a change confined to a part of it that has a patch of its own (see
    _narrowed_diffs), which is compared on its own instead:

    * a nested statement list -- a block, a `case`, a preprocessor branch -- so
      `if (x) { a(); }` -> `if (x) { a(); b(); }` stays an insertion of `b();` into the inner
      block instead of a rewrite of the whole `if` statement;
    * a condition, which becomes a REPLACE_CONDITION (see _compare_condition), so
      `if (x)` -> `if (x && y)` leaves the statement itself alone.

    Returns True when both blocks are equal, and False when at least one patch was
    appended to COMPARE_RESULT.
    """
    stmts1 = _statements(node1)
    stmts2 = _statements(node2)
    infos1 = [_stmt_info(stmt, code1) for stmt in stmts1]
    infos2 = [_stmt_info(stmt, code2) for stmt in stmts2]
    if len(stmts1) == len(stmts2) and all(info1['signature'] == info2['signature']
                                         for info1, info2 in zip(infos1, infos2)):
        return True

    changed = False
    # Statements of a difference are patched as one run: consecutive differences share a
    # single INSERT_EXPR (and a single checker), the way metapro keys one expression per
    # patched location.
    old_run: list[ts.Node] = []
    new_run: list[ts.Node] = []

    for kind, i, j in _align_stmts(infos1, infos2, code1, code2):
        if kind in ('equal', 'narrowed'):
            # An unchanged statement ends the run of differences before it, and is the
            # original statement a pure insertion in front of it is anchored at.
            if old_run or new_run:
                changed |= _report_stmt_diff(node1, stmts1, i, old_run, new_run, code2)
                old_run, new_run = [], []
            if kind == 'narrowed':
                # The statement itself stays; only the parts of it that differ are patched.
                for part, part1, part2 in _narrowed_diffs(stmts1[i], stmts2[j], code1, code2):
                    if part == 'block':
                        changed |= not compare_compound_stmt(part1, part2, code1, code2)
                    else:
                        changed |= not _compare_condition(part1, part2, code1, code2)
            continue
        if i is not None:
            old_run.append(stmts1[i])
        if j is not None:
            new_run.append(stmts2[j])
    if old_run or new_run:
        changed |= _report_stmt_diff(node1, stmts1, len(stmts1), old_run, new_run, code2)

    return not changed


def _report_stmt_diff(block1: ts.Node, stmts1: list[ts.Node], next_index: int,
                      old_run: list[ts.Node], new_run: list[ts.Node], code2: bytes):
    """
    Report one run of consecutive differing statements and return True.

    `old_run` are the original statements of the run (empty for an insertion) and
    `new_run` the statements that take their place (empty for a removal). `stmts1` are all
    statements of the original block `block1`, and `next_index` is the index of the
    original statement that follows the run: the anchor of an insertion, which has no
    original statement of its own.
    """
    if new_run and not _insertable(new_run):
        # The new statements cannot be carried by an INSERT_EXPR, and disabling the
        # originals on their own would not be the change that was made, so the difference
        # is reported but left unpatched.
        location = _start_location(new_run[0])
        message = (f"{len(new_run)} new statement(s) at {location.line}:{location.col} of the "
                   f"patched code cannot be inserted")
        __LOGGER.warning(f"Diff found but not patchable: {message}")
        SKIPPED.append(message)
        return True

    # The run is patched at the original statements it changes, or -- with no original
    # statement to change -- in front of the statement the new ones were added before. Both
    # patches of a replacement are applied at that one location, so the INSERT_EXPR is
    # inserted exactly where the checker starts disabling the original statements, and both
    # share the location's patch id.
    if old_run:
        start = _start_location(old_run[0])
        end = _end_location(old_run[-1])
    else:
        start = end = _insert_location(block1, stmts1, next_index)
    patch_id = _patch_id(start, end)

    if new_run:
        if old_run:
            __LOGGER.info(f"Diff found: {len(old_run)} statement(s) replaced by "
                          f"{len(new_run)} statement(s) at {start.line}:{start.col} (id {patch_id})")
        else:
            __LOGGER.info(f"Diff found: {len(new_run)} statement(s) inserted at "
                          f"{start.line}:{start.col} (id {patch_id})")
        COMPARE_RESULT.append(InsertExprPatch(patch_id, _stmts_expr(new_run, code2), start))
    if old_run:
        # Disable the original statements: replaced ones are superseded by the INSERT_EXPR
        # above, removed ones are simply gone.
        if not new_run:
            __LOGGER.info(f"Diff found: {len(old_run)} statement(s) removed at "
                          f"{start.line}:{start.col}-{end.line}:{end.col} (id {patch_id})")
        COMPARE_RESULT.append(InsertNotNullCheckerPatch(patch_id, __DISABLE_COND, start, end))
    return bool(old_run or new_run)


def _align_stmts(infos1: list[dict], infos2: list[dict], code1: bytes, code2: bytes):
    """
    Align the statements of two blocks, keeping their order.

    Returns the alignment as a list of (kind, i, j) operations in source order, i indexing
    the statements of the original block and j those of the patched block:

    * 'equal'    -- the same statement in both blocks (no patch)
    * 'narrowed' -- the same statement except in a part that is patchable on its own: a
                    nested block or a condition (see _narrowed_diffs)
    * 'replace'  -- a statement that was rewritten
    * 'delete'   -- a statement only in the original block (j is None)
    * 'insert'   -- a statement only in the patched block (i is None)

    The pairing that scores highest wins, so unchanged statements (the highest scoring
    pairs) become the anchors of the alignment and the differences fall in between them.
    """
    count1, count2 = len(infos1), len(infos2)
    scores = {}

    def pair(i: int, j: int):
        if (i, j) not in scores:
            scores[(i, j)] = _pair_score(infos1[i], infos2[j], code1, code2)
        return scores[(i, j)]

    # best[i][j] is the score of the best alignment of the statements from i on with the
    # ones from j on. Leaving a statement unpaired is free, so the alignment pairs up as
    # much as it can.
    best = [[0.0] * (count2 + 1) for _ in range(count1 + 1)]
    for i in range(count1 - 1, -1, -1):
        for j in range(count2 - 1, -1, -1):
            score = max(best[i][j + 1], best[i + 1][j])
            paired = pair(i, j)
            if paired is not None:
                score = max(score, best[i + 1][j + 1] + paired[0])
            best[i][j] = score

    # Walk the table back down, preferring a pair over leaving statements unpaired.
    ops = []
    i = j = 0
    while i < count1 and j < count2:
        paired = pair(i, j)
        if paired is not None and best[i][j] == best[i + 1][j + 1] + paired[0]:
            ops.append((paired[1], i, j))
            i += 1
            j += 1
        elif best[i][j] == best[i][j + 1]:
            ops.append(('insert', None, j))
            j += 1
        else:
            ops.append(('delete', i, None))
            i += 1
    ops.extend(('delete', index, None) for index in range(i, count1))
    ops.extend(('insert', None, index) for index in range(j, count2))
    return ops


def _pair_score(info1: dict, info2: dict, code1: bytes, code2: bytes):
    """
    Score of pairing two statements with each other, and the kind of that pair, or None
    when the two statements are too different to belong together.
    """
    stmt1, stmt2 = info1['node'], info2['node']
    if info1['signature'] == info2['signature']:
        return __EQUAL_SCORE, 'equal'
    if (info1['narrowable'] and info2['narrowable']
            and _narrowed_diffs(stmt1, stmt2, code1, code2)):
        return __NARROWED_SCORE, 'narrowed'
    threshold = __SAME_TYPE_THRESHOLD if stmt1.type == stmt2.type else __DIFF_TYPE_THRESHOLD
    similarity = _similarity(info1['tokens'], info2['tokens'], threshold)
    if similarity >= threshold:
        return similarity, 'replace'
    return None


def _stmt_info(stmt: ts.Node, code: bytes):
    """Everything the alignment needs to know about one statement, walked only once."""
    return {
        'node': stmt,
        'signature': _signature(stmt, code),
        'tokens': _tokens(stmt, code),
        'narrowable': _narrowable(stmt),
    }


def _narrowable(node: ts.Node):
    """
    Whether a node holds a part that is patchable on its own -- a nested statement list or a
    condition -- i.e. whether a difference inside it could be narrowed down to that part.
    """
    if node.type in __STMT_CONTAINER_TYPES or _condition(node) is not None:
        return True
    return any(_narrowable(child) for child in node.children)


def _narrowed_diffs(node1: ts.Node, node2: ts.Node, code1: bytes, code2: bytes):
    """
    The parts to compare on their own when every difference between the two nodes sits in a
    part that has a patch of its own: a nested block, e.g. the body of an `if` or of a loop
    ('block'), or the condition of a control statement ('condition').

    Returns the differing parts as (kind, part1, part2), or an empty list when the nodes
    differ anywhere else, i.e. when the whole statement has to be treated as replaced. The
    nodes are known to differ.
    """
    if node1.type != node2.type:
        return []
    if node1.type in __STMT_CONTAINER_TYPES:
        # Both hold a statement list: compare those, as long as they are the same list -- a
        # different `case` label or preprocessor condition is a different container.
        header1, header2 = _container_header(node1), _container_header(node2)
        if (header1 is None) != (header2 is None):
            return []
        if (header1 is not None
                and _signature(header1, code1) != _signature(header2, code2)):
            return []
        return [('block', node1, node2)]
    children1 = _children(node1)
    children2 = _children(node2)
    if len(children1) != len(children2):
        return []
    condition1 = _condition(node1)
    condition2 = _condition(node2)

    narrowed = []
    for child1, child2 in zip(children1, children2):
        if child1.type != child2.type:
            return []
        if _signature(child1, code1) == _signature(child2, code2):
            continue
        if _is_node(child1, condition1) and _is_node(child2, condition2):
            narrowed.append(('condition', child1, child2))
            continue
        nested = _narrowed_diffs(child1, child2, code1, code2)
        if not nested:
            return []
        narrowed.extend(nested)
    return narrowed


def _condition(node: ts.Node):
    """The controlling condition of an `if`, a loop or a `switch`, or None for anything else."""
    if node.type not in __CONDITION_TYPES:
        return None
    return node.child_by_field_name('condition')


def _container_header(node: ts.Node):
    """
    The child that says which statements a statement container holds -- a `case` label, a
    preprocessor condition or macro name -- or None when it has none (a block, a `default:`
    label, a `#else`).
    """
    for field in __CONTAINER_HEADER_FIELDS:
        header = node.child_by_field_name(field)
        if header is not None:
            return header
    return None


def _is_node(node: ts.Node, other: ts.Node | None):
    """Whether two nodes are the same node of the same tree."""
    return (other is not None and node.type == other.type
            and node.start_byte == other.start_byte and node.end_byte == other.end_byte)


def _similarity(tokens1: list[str], tokens2: list[str], threshold: float):
    """
    How alike two statements look, as a 0..1 ratio over the tokens they are made of.

    Computing the ratio is quadratic in the number of tokens, so it is only computed for
    the statements its cheap upper bounds cannot already rule out; the others score 0.0.
    """
    matcher = difflib.SequenceMatcher(None, tokens1, tokens2, autojunk=False)
    if matcher.real_quick_ratio() < threshold or matcher.quick_ratio() < threshold:
        return 0.0
    return matcher.ratio()


def _signature(node: ts.Node, code: bytes):
    """
    Structural signature of a subtree: equal signatures mean equal code, ignoring
    whitespace and comments.
    """
    children = _children(node)
    if not children:
        return (node.type, bytes(code[node.start_byte:node.end_byte]))
    return (node.type, tuple(_signature(child, code) for child in children))


def _tokens(node: ts.Node, code: bytes):
    """The leaf tokens of a subtree, in source order."""
    children = _children(node)
    if not children:
        return [f'{node.type}:{_node_text(node, code)}']
    tokens = []
    for child in children:
        tokens.extend(_tokens(child, code))
    return tokens


def _statements(node: ts.Node):
    """
    The statements of a block, or of another statement container (see
    __STMT_CONTAINER_TYPES), without the comments between them and without the header that
    says what the container is.

    A label and the statement it carries are two entries, see _flatten_labels.
    """
    header = _container_header(node)
    stmts = []
    for child in node.named_children:
        if child.type in __IGNORED_TYPES or _is_node(child, header):
            continue
        stmts.extend(_flatten_labels(child))
    return stmts


def _flatten_labels(stmt: ts.Node):
    """
    A labeled statement as the label and the statement it owns, and anything else as itself.

    C hands a label the statement that follows it, so `restart: t = tptr[i++];` is one node. A
    patch inserting a statement between the two would otherwise be a rewrite of that node --
    emitting the label a second time where the original one is still in place, which the
    interpreter then runs into (mruby-42528301). Listed apart, the label pairs up with the label
    of the patched code and the insertion lands in front of the statement, which is where the
    patched code has it. Labels nest, so `a: b: stmt;` unfolds the same way.
    """
    if stmt.type != 'labeled_statement':
        return [stmt]
    label = stmt.child_by_field_name('label')
    flattened = [label] if label is not None else []
    for child in stmt.named_children:
        if child.type in __IGNORED_TYPES or _is_node(child, label):
            continue
        flattened.extend(_flatten_labels(child))
    return flattened


def _children(node: ts.Node):
    """
    The children of a node, without comments. Anonymous children are kept, so that tokens
    that carry meaning but no named node (`&&`, `++`, `=`, ...) are compared too.
    """
    return [child for child in node.children if child.type not in __IGNORED_TYPES]


def _insert_location(block1: ts.Node, stmts1: list[ts.Node], index: int):
    """
    Where to insert statements that replace nothing: in front of the original statement at
    `index`, or -- when they are added at the end of the block -- behind its last
    statement (right after the opening brace when the block is empty).
    """
    if index < len(stmts1):
        return _start_location(stmts1[index])
    if stmts1:
        return _end_location(stmts1[-1])
    brace = block1.child(0)
    if brace is not None and brace.type == '{':
        return _end_location(brace)
    return _start_location(block1)


def _stmts_expr(stmts: list[ts.Node], code: bytes):
    """
    The statements as one expression to insert: a single line, wrapped in a compound
    statement when there is more than one of them, so that the run is inserted as a single
    statement.
    """
    expr = ' '.join(_stmt_text(stmt, code) for stmt in stmts)
    if not expr.endswith((';', '}')):
        expr += ';'
    if len(stmts) > 1:
        expr = '{ ' + expr + ' }'
    return expr


def _insertable(stmts: list[ts.Node]):
    """
    Whether the statements can be inserted somewhere else as a single statement. A
    preprocessor directive needs a line of its own and a `case` label needs the switch it
    belongs to, so neither survives being folded into an inserted expression. A statement label
    (see _flatten_labels) is not a statement at all: emitting one would put the same label in the
    program twice, and an interpreted patch has nothing to jump to anyway.
    """
    return not any(stmt.type in ('case_statement', 'statement_identifier') or _has_preproc(stmt)
                   for stmt in stmts)


def _has_preproc(node: ts.Node):
    """Whether a subtree contains a preprocessor directive."""
    if node.type.startswith('preproc'):
        return True
    return any(_has_preproc(child) for child in node.children)


def _stmt_text(node: ts.Node, code: bytes):
    """
    The source text of a statement as a single line, with its comments removed. Only line
    breaks and the indentation around them are collapsed, never the spacing inside a line,
    so that string literals keep their content.
    """
    text = ''
    end = node.start_byte
    for comment in _comments(node):
        text += _slice_text(code, end, comment.start_byte)
        end = comment.end_byte
    text += _slice_text(code, end, node.end_byte)
    return re.sub(r'\s*\n\s*', ' ', text).strip()


def _comments(node: ts.Node):
    """Every comment inside a subtree, in source order."""
    comments = []
    for child in node.children:
        if child.type in __IGNORED_TYPES:
            comments.append(child)
        else:
            comments.extend(_comments(child))
    return comments


def _added_subcond(condition1: ts.Node, condition2: ts.Node, operator: str,
                   code1: bytes, code2: bytes):
    """
    How a condition was extended when the original is no operand of the rewritten one: a chain
    like `a && b && c` nests to the left, so an original of two or more operands is not a
    subtree of it once something is added at the front. The text tells what the tree cannot --
    the original surviving whole, with the new sub-condition joined to its front or back by
    `operator`, bare or parenthesized.

    Returns the (cond_expr1, cond_expr2) of the REPLACE_CONDITION -- the same shape the two
    operand cases produce -- or None when the original does not survive whole, i.e. when the
    whole condition was replaced.
    """
    text1 = _stmt_text(condition1, code1)
    text2 = _stmt_text(condition2, code2)
    separator = f' {operator} '
    for original in (text1, f'({text1})'):
        if text2.startswith(original + separator):
            return operator, text2[len(original) + len(separator):]
        if text2.endswith(separator + original):
            return text2[:-(len(separator) + len(original))], operator
    return None


def _operator(node: ts.Node, code: bytes):
    """
    The operator of a binary expression: what stands between its two operands. Read from the
    code rather than from `Node.value`, which is only recorded for a tree parsed with
    `record_values` (see parser.parse_code).

    Returns '' for anything without two operands. The count has to be checked first: asking
    for a child a node does not have hands back a node wrapping a null subtree rather than
    None, and reading its position crashes.
    """
    if node.named_child_count < 2:
        return ''
    left = node.named_child(0)
    right = node.named_child(1)
    return _slice_text(code, left.end_byte, right.start_byte).strip()


def _node_text(node: ts.Node, code: bytes):
    return _slice_text(code, node.start_byte, node.end_byte)


def _slice_text(code: bytes, start_byte: int, end_byte: int):
    return code[start_byte:end_byte].decode('utf-8', errors='replace')


def _start_location(node: ts.Node):
    """Where a node starts, as a 1-based line and a 0-based column."""
    return SourceLocation(node.start_point[0] + 1, node.start_point[1])


def _end_location(node: ts.Node):
    """Where a node ends, as a 1-based line and a 0-based column past its last character."""
    return SourceLocation(node.end_point[0] + 1, node.end_point[1])


def _patch_id(start: SourceLocation, end: SourceLocation):
    """
    The patch id of one location, handed out in order of appearance. Patches that target the
    same span of the original code share their id, the way metapro carries one expression per
    id and template.
    """
    key = (start.line, start.col, end.line, end.col)
    if key not in PATCH_IDS:
        PATCH_IDS[key] = _free_patch_id()
    return PATCH_IDS[key]


def _cond_patch_id(wrapper: ts.Node | None, code: bytes,
                   start: SourceLocation, end: SourceLocation):
    """
    The patch id of a condition: the id metapro gave it, read out of the instrumentation call
    that wraps it (see _metapro_cond_wrapper), because that is the id the patcher expects a
    REPLACE_CONDITION for. A condition of code that is not instrumented falls back to a
    location id.
    """
    cond_id = _metapro_cond_id(wrapper, code) if wrapper is not None else None
    if cond_id is None:
        return _patch_id(start, end)

    key = (start.line, start.col, end.line, end.col)
    if PATCH_IDS.get(key) == cond_id:
        return cond_id
    # The id belongs to this condition, so a location that was handed it earlier has to move
    # out of the way, together with the patches already reported for that location.
    taken = [other for other, other_id in PATCH_IDS.items() if other_id == cond_id]
    PATCH_IDS[key] = cond_id
    for other in taken:
        PATCH_IDS[other] = _free_patch_id()
        __LOGGER.info(f"Patch id {cond_id} is metapro's, moving the patches at "
                      f"{other[0]}:{other[1]} to id {PATCH_IDS[other]}")
        for patch in COMPARE_RESULT:
            if patch.id == cond_id and patch.patch_type != 'REPLACE_CONDITION':
                patch.id = PATCH_IDS[other]
    return cond_id


def _free_patch_id():
    """The lowest patch id that no location uses yet."""
    used = set(PATCH_IDS.values())
    patch_id = 1
    while patch_id in used:
        patch_id += 1
    return patch_id


def _metapro_cond_wrapper(condition: ts.Node, code: bytes):
    """
    The metapro instrumentation call around a condition, or None when the code is not
    instrumented. metapro rewrites every condition it can patch into

        __metapro_replace_cond_c(<patch id>, "<original condition>",
                                 (unsigned int)(<original condition>), "<function>")

    and it is that call, not the condition node around it, that a REPLACE_CONDITION patch is
    reported at. The outermost call wins: a condition nested in another one has an id of its
    own, but the condition being compared here is the one that owns the outer call.
    """
    if condition.type == 'call_expression':
        function = condition.child_by_field_name('function')
        if function is not None and _node_text(function, code) == __COND_WRAPPER:
            return condition
    for child in _children(condition):
        wrapper = _metapro_cond_wrapper(child, code)
        if wrapper is not None:
            return wrapper
    return None


def _metapro_cond_id(wrapper: ts.Node, code: bytes):
    """The patch id metapro passes as the first argument of its instrumentation call."""
    arguments = wrapper.child_by_field_name('arguments')
    if arguments is None:
        return None
    args = [child for child in arguments.named_children if child.type not in __IGNORED_TYPES]
    if not args:
        return None
    patch_id = _node_text(args[0], code).strip()
    return int(patch_id) if patch_id.isdigit() else None


def compare_if_stmt(node1: ts.Node, node2: ts.Node, code1: bytes, code2: bytes):
    """
    If statement comparison logic.

    This function compares only condition is different and find the REPLACE_CONDITION pattern.
    """
    return _compare_condition(node1.named_child(0), node2.named_child(0), code1, code2)


def _compare_condition(condition1: ts.Node, condition2: ts.Node, code1: bytes, code2: bytes):
    """
    Condition comparison logic, for the condition of any statement controlled by one (see
    __CONDITION_TYPES, and _narrowed_diffs which reports a change confined to a condition).

    This function compares only condition is different and find the REPLACE_CONDITION
    pattern. The parentheses around the condition are not part of it, so a condition the
    grammar parenthesizes (every one but a `for` condition) is unwrapped first -- both to
    recognise a new sub-condition added with `&&`/`||` and to keep the patched expression
    free of them.
    """
    if condition1.type == 'parenthesized_expression':
        condition1 = condition1.named_child(0)
    if condition2.type == 'parenthesized_expression':
        condition2 = condition2.named_child(0)
    res = compare_nodes(condition1, condition2, code1, code2)
    if res:
        return True
    else:
        # The patch is applied at the original condition: at metapro's instrumentation call
        # when the code is instrumented, which is also where its patch id comes from.
        wrapper = _metapro_cond_wrapper(condition1, code1)
        patched = wrapper if wrapper is not None else condition1
        start_location = _start_location(patched)
        end_location = _end_location(patched)
        patch_id = _cond_patch_id(wrapper, code1, start_location, end_location)
        operator = _operator(condition2, code2) if condition2.type == 'binary_expression' else ''
        if operator in ('&&', '||'):
            subcond_1 = condition2.named_child(0)
            subcond_2 = condition2.named_child(1)
            if compare_nodes(condition1, subcond_1, code1, code2):
                # New cond is added AFTER the original condition
                patch = ReplaceCondPatch(patch_id, start_location, end_location, operator, _stmt_text(subcond_2, code2))
            elif compare_nodes(condition1, subcond_2, code1, code2):
                # New cond is added BEFORE the original condition
                patch = ReplaceCondPatch(patch_id, start_location, end_location, _stmt_text(subcond_1, code2), operator)
            else:
                added = _added_subcond(condition1, condition2, operator, code1, code2)
                if added is not None:
                    # New cond is added to a chain of conditions, which is no operand of it
                    patch = ReplaceCondPatch(patch_id, start_location, end_location, *added)
                else:
                    # Completely different condition, replace the original condition with the new one
                    patch = ReplaceCondPatch(patch_id, start_location, end_location, _stmt_text(condition2, code2))
        else:
            # Completely different condition, replace the original condition with the new one
            patch = ReplaceCondPatch(patch_id, start_location, end_location, _stmt_text(condition2, code2))
        COMPARE_RESULT.append(patch)
        return False