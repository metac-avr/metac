#pragma once

#include <string>
#include <vector>

/*
    Collect every macro definition AND every enum constant reachable while
    compiling `code` (as `filename` with `args`), recursively expand each macro
    body using the FINAL/LATEST definition of every referenced macro, and merge
    the result into the JSON file at `outJsonPath` (keyed by name).

    Macro semantics (per project requirements):
      - Function-like macros are included.
      - #undef'd macros are KEPT and flagged ("undefined": true), not removed.
      - Redefined macros collapse to their last surviving definition.
      - Expansion is best-effort: macros whose bodies use `#`, `##` or
        __VA_ARGS__ (variadic) are NOT expanded; they are emitted with their raw
        body and "needs_manual": true so they can be handled explicitly later.

    Enum semantics:
      - Every enum constant is recorded with its integer value and enclosing
        enum tag. Scoped enums (enum class/struct) are keyed as "Enum::Name".
      - A macro shadows an enum constant of the same name: if a "macro" record
        already exists under a key, the enum constant is not written over it.

    The JSON is an object mapping name -> record. Macro records:
      {
        "NAME": {
          "kind": "macro", "name": "NAME", "file": "...", "line": 12,
          "function_like": false, "variadic": false, "params": [...],
          "raw_body": "...", "expanded_body": "...",
          "undefined": false, "needs_manual": false
        }
      }
    Enum-constant records mirror the macro record shape (so a single schema
    parses both) with the constant's integer value used as the body, plus the
    enum-specific extras "enum", "scoped" and "value":
      {
        "NAME": {
          "kind": "enum_constant", "name": "NAME", "file": "...", "line": 12,
          "function_like": false, "variadic": false, "params": [],
          "raw_body": "2", "expanded_body": "2",
          "undefined": false, "needs_manual": false,
          "enum": "Color", "scoped": false, "value": "2"
        }
      }
*/
void collectMacrosToJson(const std::string& code,
                         const std::vector<std::string>& args,
                         const std::string& filename,
                         const std::string& outJsonPath);
