from enum import Enum
import tree_sitter as ts


class SourceLocation:
    def __init__(self, line: int, col: int):
        self.line = line
        self.col = col

class Patch:
    def __init__(self, patch_type: str, id: int):
        self.patch_type = patch_type
        self.id = id


class InsertExprPatch(Patch):
    def __init__(self, id: int, inserted_expr: str, inserted_location: SourceLocation):
        super().__init__("INSERT_EXPR", id)
        self.inserted_expr = inserted_expr
        self.inserted_location = inserted_location


class InsertNotNullCheckerPatch(Patch):
    def __init__(self, id: int, new_condition: str, start_location: SourceLocation, end_location: SourceLocation):
        super().__init__("INSERT_NOT_NULL_CHECKER", id)
        self.new_condition = new_condition
        self.start_location = start_location
        self.end_location = end_location


class ReplaceCondPatch(Patch):
    def __init__(self, id: int, start_location: SourceLocation, end_location: SourceLocation, cond_expr1: str, cond_expr2: str = ''):
        super().__init__("REPLACE_CONDITION", id)
        self.cond_expr1 = cond_expr1
        self.cond_expr2 = cond_expr2
        self.start_location = start_location
        self.end_location = end_location
