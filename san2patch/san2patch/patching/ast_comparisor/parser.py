import tree_sitter as ts
import tree_sitter_c as tsc


try:
    __LANGUAGE = ts.Language(tsc.language())
except TypeError:
    # Builds before the language name became implicit still want it passed in.
    __LANGUAGE = ts.Language(tsc.language(), 'c')

__PARSER = ts.Parser()
if hasattr(__PARSER, 'set_language'):
    __PARSER.set_language(__LANGUAGE)
else:
    __PARSER.language = __LANGUAGE

# How much source to hand the parser per read when parsing through a callback.
__READ_SIZE = 1 << 16


def parse_code(code: bytes|str, record_values: bool = False):
    """
    Parse C code and return the root node of its tree.

    `record_values` selects how the tree is built. Parsing straight from the buffer lets the
    parser record `Node.value` / `Node.value_2` (and keep the source for `Node.text`), but it
    records them into a fixed 10000 entry table per tree, filled without a bounds check (see
    node_value_keys in py-tree-sitter/tree_sitter/core/lib/src/tree.h and ts_add_value in
    parser.c), so anything bigger overflows it and corrupts the heap -- one instrumented file
    in benchmarks/arvo needs 223884 entries. Parsing through a read callback skips that table
    altogether, which is why it is the default; comparing needs no recorded values, it reads
    the code it is given (see compare.py).
    """
    if isinstance(code, str):
        code = code.encode('utf-8')
    if record_values:
        return __PARSER.parse(code).root_node
    return __PARSER.parse(lambda offset, _point: code[offset:offset + __READ_SIZE]).root_node

def parse_file(file_path: str, record_values: bool = False):
    with open(file_path, 'rb') as f:
        code = f.read()
    return parse_code(code, record_values)