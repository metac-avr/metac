"""Tool factory functions for ARVO solver agents.

Each factory takes a container_id and returns an AutoGen FunctionTool
bound to that container via closure.

Tools:
  - bash:                Execute arbitrary commands inside the container.
  - view/search:         Lightweight compatibility shims for paper tool API.
  - str_replace_edit:    Precise text replacement in container files.
  - insert_probe:        Exact-anchor insertion of caller-provided probes.
  - revert_*:            Edit-history rollback shims plus full reset support.
  - mutate_poc:          Create a variant file from text/base64/hex/byte edits.
  - run_variant:         Execute one named variant via the repro command.
  - run_probed:          Build and execute one or more variants after probing.
  - check_vul:           Re-run the original PoC verification command.
  - submit:              Extract the current git diff from the repo.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import shlex
from dataclasses import dataclass, field

from autogen_core.tools import FunctionTool

from arvo.benchmark import (
    BUILD_CMD,
    POC_PATH,
    REPRO_CMD,
    TOOL_EVENT_LOG,
    project_dir,
    variant_path,
)
from arvo.config import BUILD_TIMEOUT, DOCKER_EXEC_TIMEOUT, MAX_OUTPUT_LENGTH
from arvo.timing import track_current
from arvo.docker_tools import (
    build_project,
    exec_cmd,
    read_file,
    read_file_bytes,
    reset_source,
    write_file,
)

logger = logging.getLogger(__name__)


@dataclass
class _EditState:
    """Track edits made through compatibility editing tools."""

    history: list[tuple[str, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Probe diffs: what each run_probed build actually contained
# ---------------------------------------------------------------------------

#: container id -> (host directory, round, repo root) where run_probed leaves the diff of
#: each build's probes.  Set by the pipeline around one Analyzer round; see
#: set_probe_snapshot_target().
_PROBE_SNAPSHOTS: dict[str, tuple[str, int, str]] = {}
_PROBE_SNAPSHOT_COUNTS: dict[tuple[str, int], int] = {}

#: The diff San2Patch takes of a patch (runpatch_graph.py, ArvoValidator branch): git's
#: ``cpp`` hunk-header driver for every file, zero context lines (``-U0``), and only the
#: source files the patch *modifies* (its filter_diff_by_extension).  Zero context is what
#: the metapro config generator expects (it applies the diff with ``git apply
#: --unidiff-zero``), and keeps a hunk to exactly the lines the patch changed.
SOURCE_DIFF_EXTENSIONS = (".c", ".cc", ".cpp", ".h")
_DIFF_CPP_ATTRIBUTES_PATH = "/tmp/.arvo_diff_cpp_attributes"


def source_diff(container_id: str, repo_root: str) -> str:
    """The source tree's San2Patch-style diff against HEAD.

    Read-only: unlike the old ``--intent-to-add`` staging, nothing is written to the
    index, so a diff can be taken mid-analysis and ``reset_source`` still restores a
    clean tree.  New files are left out, as San2Patch leaves them out.
    """
    pathspec = " ".join(f"'*{ext}'" for ext in SOURCE_DIFF_EXTENSIONS)
    cmd = (
        f"printf '* diff=cpp\\n' > {_DIFF_CPP_ATTRIBUTES_PATH} && "
        f"cd {repo_root} && NO_COLOR=1 git -c core.attributesFile={_DIFF_CPP_ATTRIBUTES_PATH} "
        f"--no-pager diff --no-color -U0 --patch --diff-filter=M -- {pathspec}"
    )
    exit_code, stdout, _stderr = exec_cmd(container_id, cmd)
    if exit_code != 0 or not stdout:
        return ""
    # Byte-for-byte apart from a final newline: stripping would corrupt hunk line counts.
    return stdout if stdout.endswith("\n") else stdout + "\n"


def probe_diff(container_id: str, repo_root: str) -> str:
    """The Analyzer's probes as a diff -- the same diff a patch gets (source_diff)."""
    return source_diff(container_id, repo_root)


#: container id -> where run_probed applies probes to a prebuilt binary instead of
#: rebuilding (PATCH_MODE metapro and combined).  Set by the pipeline around one Analyzer round.
_METAPRO_PROBE_TARGETS: dict[str, dict] = {}
_METAPRO_PROBE_COUNTS: dict[tuple[str, int], int] = {}


def set_metapro_probe_target(
    container_id: str, *, project: str, local_id: int | str, fuzz_target: str,
    repo_root: str, round_num: int, mode: str = "metapro",
) -> None:
    """Have run_probed in *container_id* insert the probes into a prebuilt binary instead
    of building the project.

    *mode* ``metapro``: with metapro only (arvo.metapro.run_probes); a probe it cannot
    insert is reported back.  ``combined``: metapro, then Dyninst (arvo.dyninst.run_probes)
    when metapro cannot insert or run the probes, then the usual build when Dyninst cannot
    either -- the order the Patcher's validation uses.
    """
    _METAPRO_PROBE_TARGETS[container_id] = {
        "project": project, "local_id": local_id, "fuzz_target": fuzz_target,
        "repo_root": repo_root, "round_num": round_num, "mode": mode,
    }


def clear_metapro_probe_target(container_id: str) -> None:
    _METAPRO_PROBE_TARGETS.pop(container_id, None)


def set_probe_snapshot_target(container_id: str, out_dir: str, round_num: int, repo_root: str) -> None:
    """Have run_probed in *container_id* save each build's probe diff under *out_dir*."""
    _PROBE_SNAPSHOTS[container_id] = (out_dir, round_num, repo_root)


def clear_probe_snapshot_target(container_id: str) -> None:
    _PROBE_SNAPSHOTS.pop(container_id, None)


def _save_probe_snapshot(container_id: str) -> None:
    target = _PROBE_SNAPSHOTS.get(container_id)
    if target is None:
        return
    out_dir, round_num, repo_root = target
    key = (container_id, round_num)
    _PROBE_SNAPSHOT_COUNTS[key] = _PROBE_SNAPSHOT_COUNTS.get(key, 0) + 1
    try:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, f"analyzer_r{round_num}_build{_PROBE_SNAPSHOT_COUNTS[key]}.diff")
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write(probe_diff(container_id, repo_root))
    except Exception as exc:  # a lost snapshot must never fail the Analyzer's build
        logger.warning("could not save probe diff for %s: %s", container_id[:12], exc)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _truncate_output(text: str) -> str:
    """Truncate tool output while preserving both head and tail."""
    if len(text) <= MAX_OUTPUT_LENGTH:
        return text
    half = MAX_OUTPUT_LENGTH // 2
    return text[:half] + "\n\n... [output truncated] ...\n\n" + text[-half:]


_SANITIZER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("heap-buffer-overflow", re.compile(r"heap-buffer-overflow", re.I)),
    ("stack-buffer-overflow", re.compile(r"stack-buffer-overflow", re.I)),
    ("global-buffer-overflow", re.compile(r"global-buffer-overflow", re.I)),
    ("use-after-free", re.compile(r"use-after-free", re.I)),
    ("double-free", re.compile(r"double-free", re.I)),
    (
        "null-pointer-dereference",
        re.compile(r"SEGV on unknown address.*0x0|null pointer|null-dereference", re.I | re.S),
    ),
    ("stack-overflow", re.compile(r"stack-overflow", re.I)),
    (
        "integer-overflow",
        re.compile(r"integer overflow|runtime error:.*overflow", re.I | re.S),
    ),
    (
        "undefined-behavior",
        re.compile(r"UndefinedBehaviorSanitizer|runtime error:", re.I),
    ),
    (
        "use-of-uninitialized-value",
        re.compile(r"use-of-uninitialized-value|MemorySanitizer", re.I),
    ),
    ("memory-leak", re.compile(r"detected memory leaks|LeakSanitizer", re.I)),
    ("SEGV", re.compile(r"AddressSanitizer: SEGV|SEGV on unknown address", re.I)),
    ("sanitizer-error", re.compile(r"AddressSanitizer|UndefinedBehaviorSanitizer", re.I)),
]


def _detect_sanitizer_type(output: str) -> str:
    """Return a compact sanitizer class for tool feedback."""
    for name, pattern in _SANITIZER_PATTERNS:
        if pattern.search(output):
            return name
    return "none"


def _format_run_output(exit_code: int, stdout: str, stderr: str) -> str:
    combined = stdout
    if stderr:
        combined = combined + "\n" + stderr if combined else stderr
    sanitizer = _detect_sanitizer_type(combined)
    return _truncate_output(
        f"[exit code: {exit_code}]\n[sanitizer: {sanitizer}]\n{combined}"
    )


def _resolve_variant_path(
    variant_id: str,
    *,
    ext: str = "",
    poc_path: str = POC_PATH,
) -> str:
    """Resolve logical variant identifiers to container paths."""
    value = (variant_id or "").strip()
    if not value or value in {"original", "orig", "poc"}:
        return poc_path
    if "/" in value:
        return value

    if value.startswith("variant_") or value.startswith("r"):
        filename = value
    else:
        filename = f"variant_{value}"
    if ext and not filename.endswith(ext):
        filename = f"{filename}{ext}"
    return variant_path(filename)


def _append_tool_event(container_id: str, event: dict) -> None:
    """Persist structured tool provenance inside the benchmark container."""
    event_path = TOOL_EVENT_LOG
    try:
        existing = read_file(container_id, event_path)
    except FileNotFoundError:
        existing = ""
    line = json.dumps(event, sort_keys=True, ensure_ascii=True)
    write_file(container_id, event_path, existing + line + "\n")


_FPRINTF_STDERR_RE = re.compile(r"\bfprintf\s*\(\s*stderr\s*,")


def rewrite_probe_code(code: str) -> str:
    """Write probes to fd 2 directly: ``fprintf(stderr, ...)`` -> ``dprintf(2, ...)``.

    ``stderr`` is a global of the C library; a probe that references it cannot be
    expressed as a metapro binary patch, while ``dprintf(2, ...)`` names nothing but
    a function and a constant.  It is also unbuffered, so a probe's line is out before
    a crash right after it.
    """
    return _FPRINTF_STDERR_RE.sub("dprintf(2,", code)


def _expand_probe_newlines(output: str) -> str:
    """Turn a literal ``\\n`` in PROBE output into a line break.

    The model's probe format strings often arrive escaped twice (``\\\\n`` in the
    tool-call JSON), so the program prints a backslash and an ``n`` and every probe of
    a run lands on one line.  Only lines carrying a PROBE are touched.
    """
    return "\n".join(
        line.replace("\\n", "\n") if "PROBE:" in line else line
        for line in output.split("\n")
    )


#: Lines the metapro runtime prints when it, not the program, fails (see
#: contrafix-metapro-validate.py METAPRO_RUNTIME_ERROR_RE).  Never shown to a model: it
#: would try to work around an interpreter it cannot see instead of fixing the program.
_METAPRO_RUNTIME_LINE_RE = re.compile(
    r"^.*(interpreter[\w/.-]*\.c:\d+: ERROR:|\.inst: symbol lookup error:"
    r"|\.inst: error while loading shared libraries).*$\n?", re.M)

METAPRO_RUNTIME_NOTE = (
    "[The run stopped inside the binary-patching runtime that inserts the probes, not in "
    "the program. This says nothing about the bug: keep each probe to one simple "
    "`dprintf(2, \"PROBE: ...\\n\", ...);` printing plain scalar values or pointers, or move it.]"
)


def scrub_metapro_runtime(text: str) -> str:
    """Drop the metapro runtime's own error lines from *text*."""
    return _METAPRO_RUNTIME_LINE_RE.sub("", text)


def _extract_probe_lines(output: str) -> str:
    """Return only probe lines from a run, preserving their original order."""
    lines = [line for line in output.splitlines() if "PROBE:" in line]
    return "\n".join(lines) if lines else "<no PROBE lines>"


_BUILD_ERROR_RE = re.compile(
    r"(?:^|\s)(?:error:|fatal error:|undefined reference|"
    r"No such file or directory|Error \d+|\*\*\* )", re.I,
)


def summarize_build_output(output: str, success: bool, max_chars: int = 4000) -> str:
    """Compress ``arvo compile`` output before it reaches an agent.

    ARVO runs OSS-Fuzz's ``build.sh`` under ``set -x``, so the trace is
    enormous: a successful libxml2 build emits ~140k characters (~35k tokens),
    ffmpeg ~2.5M.  The Analyzer may build dozens of times in one conversation
    and every tool result stays in its context — feeding the raw log in
    exhausted a 272k-token budget after only a few builds.

    The command trace carries no information when the build succeeds, so
    success collapses to a single line.  On failure the compiler diagnostics
    are what matter, so those lines are kept along with the tail.
    """
    lines = output.splitlines()
    if success:
        return f"Build succeeded. ({len(lines)} lines of build log suppressed.)"

    errors = [ln for ln in lines if _BUILD_ERROR_RE.search(ln)]
    parts = ["Build FAILED."]
    if errors:
        parts.append("## Error lines\n" + "\n".join(errors[-40:]))
    parts.append("## Last 40 lines\n" + "\n".join(lines[-40:]))
    text = "\n".join(parts)
    if len(text) > max_chars:
        text = text[: max_chars // 2] + "\n... [truncated] ...\n" + text[-max_chars // 2:]
    return text


# ---------------------------------------------------------------------------
# bash tool
# ---------------------------------------------------------------------------


#: Commands that compile the project, whichever way an agent spells it.
_BUILD_COMMAND_RE = re.compile(r"\barvo\s+compile\b|\bbuild\.py\b|(?:^|[;&|(]\s*|\s)(?:make|cmake|ninja)\b")
#: The benchmark's PoC run (``arvo``, not ``arvo compile``): it runs the prebuilt
#: /out/<fuzz_target> without rebuilding, i.e. the binary from before any edit.
_REPRO_COMMAND_RE = re.compile(r"(?:^|[;&|(]\s*)arvo(?:\s+(?!compile)\S|\s*$|\s*[;&|)])")


def make_bash_tool(
    container_id: str,
    *,
    block_builds: bool = False,
    block_repro: bool = False,
) -> FunctionTool:
    """Create a bash execution tool bound to a specific container.

    *block_builds* refuses any command that builds the project: under PATCH_MODE
    metapro and combined nothing is built before a patch reaches its PoC validation
    (probes go into a prebuilt binary, see run_probed).  *block_repro* (the Patcher's copy) also refuses the
    direct PoC run, which without a rebuild would only show the unpatched binary.
    """

    def bash(command: str) -> str:
        """Execute a bash command inside the container."""
        if block_builds and _BUILD_COMMAND_RE.search(command):
            return ("[refused] Building the project is disabled in this run: patches are "
                    "validated against the PoC after you submit them, with no build before "
                    "that. Read and edit the source instead.")
        if block_repro and _REPRO_COMMAND_RE.search(command):
            return ("[refused] Running the PoC directly is disabled in this run: the prebuilt "
                    "binary does not include your edits. Your patch is run against the PoC "
                    "after you submit it.")
        is_build = BUILD_CMD in command
        timeout = BUILD_TIMEOUT if is_build else DOCKER_EXEC_TIMEOUT
        # An agent-issued build costs as much as a pipeline build; record it
        # so it is not silently absorbed into the enclosing agent span.
        with track_current(
            "tool.build" if is_build else "tool.bash", kind="detail",
            tool="bash", container=container_id[:12],
        ):
            exit_code, stdout, stderr = exec_cmd(container_id, command, timeout=timeout)
        combined = stdout
        if stderr:
            combined = combined + "\n" + stderr if combined else stderr
        # A direct `arvo compile` dumps the whole set -x build trace (~35k
        # tokens for libxml2).  Summarise it here too, or an agent can blow
        # its own context budget by bypassing run_probed/check_vul.
        if is_build:
            combined = summarize_build_output(combined, exit_code == 0)
        result = f"[exit code: {exit_code}]\n{combined}"
        return _truncate_output(result)

    return FunctionTool(
        bash,
        description=(
            "Execute a bash command in the container and return exit code + output. "
            "Typical tools include cat, grep/find/ls, python3, git, and sometimes rg. "
            "For file creation use heredoc: cat > path << 'EOF'\\ncontent\\nEOF"
        ),
    )


# ---------------------------------------------------------------------------
# Compatibility file-view / search tools
# ---------------------------------------------------------------------------


#: A whole-file ``view`` is the single largest consumer of agent context.
#: Measured over a 20-instance run: 62 view results totalling 3.7M characters
#: (~928k tokens), averaging ~60k characters each — i.e. clipped at
#: MAX_OUTPUT_LENGTH.  The files involved are simply large (libxml2's parser.c
#: is 14,108 lines, tree.c 9,884), and a handful of such reads exhausts a
#: 272k-token request budget; five of twenty instances died that way.
#: Reading in windows costs the agent an extra call but keeps its context
#: proportional to what it actually needs.
VIEW_DEFAULT_LINES = 400
VIEW_MAX_LINES = 1200


def make_view_tool(container_id: str) -> FunctionTool:
    """Compatibility shim for the paper's view(path) interface."""

    def view(
        path: str,
        start_line: int = 1,
        num_lines: int = VIEW_DEFAULT_LINES,
    ) -> str:
        """Return a numbered window of a file."""
        try:
            content = read_file(container_id, path)
        except FileNotFoundError as exc:
            return f"Error: {exc}"

        lines = content.splitlines()
        total = len(lines)
        if total == 0:
            return f"{path}: <empty file>"

        try:
            start = max(1, int(start_line))
            count = int(num_lines)
        except (TypeError, ValueError):
            start, count = 1, VIEW_DEFAULT_LINES
        if count <= 0:
            count = VIEW_DEFAULT_LINES
        count = min(count, VIEW_MAX_LINES)

        if start > total:
            return f"{path}: {total} lines total; start_line={start} is past the end."

        end = min(total, start + count - 1)
        body = "\n".join(
            f"{idx:>6}\t{lines[idx - 1]}" for idx in range(start, end + 1)
        )
        header = f"{path}: {total} lines total, showing {start}-{end}."
        if end < total:
            header += (
                f" To continue, call view(path, start_line={end + 1}). "
                "Use search() to locate a region instead of paging through."
            )
        return _truncate_output(f"{header}\n{body}")

    return FunctionTool(
        view,
        description=(
            "View a window of a container file with line numbers. Returns "
            f"{VIEW_DEFAULT_LINES} lines from start_line by default (max "
            f"{VIEW_MAX_LINES}); the header reports the file's total length. "
            "Source files here run to thousands of lines, so locate the region "
            "of interest with search() first, then view that range — do not "
            "page through a whole file."
        ),
    )



def make_search_tool(container_id: str, project: str = "") -> FunctionTool:
    """Compatibility shim for the paper's search(pattern, path) interface."""

    # Default to the project tree.  Searching all of /src also walks the
    # fuzzer toolchain and vendored dependency sources, which buries real
    # hits under thousands of irrelevant ones.
    default_path = project_dir(project) if project else "/src"

    def search(pattern: str, path: str = "") -> str:
        """Search text in a file or directory using rg, falling back to grep."""
        path = path or default_path
        cmd = (
            "if command -v rg >/dev/null 2>&1; then "
            "rg -n --no-heading --color never "
            f"{shlex.quote(pattern)} {shlex.quote(path)}; "
            "else grep -RIn -- "
            f"{shlex.quote(pattern)} {shlex.quote(path)}; "
            "fi"
        )
        exit_code, stdout, stderr = exec_cmd(container_id, cmd)
        combined = stdout
        if stderr:
            combined = combined + "\n" + stderr if combined else stderr
        return _truncate_output(f"[exit code: {exit_code}]\n{combined}")

    return FunctionTool(
        search,
        description=(
            "Search for a regex/text pattern under a container path using rg when "
            "available, otherwise grep. Compatibility shim for the paper interface."
        ),
    )


# ---------------------------------------------------------------------------
# str_replace editing tool
# ---------------------------------------------------------------------------

_SNIPPET_CONTEXT = 4  # lines of context to show around the edit


def make_str_replace_tool(
    container_id: str,
    edit_state: _EditState | None = None,
    rewrite_probes: bool = False,
) -> FunctionTool:
    """Create a str_replace editing tool bound to a specific container.

    *rewrite_probes* (the Analyzer's copy, which also inserts probes with it) applies
    rewrite_probe_code() to new_str.
    """

    state = edit_state or _EditState()

    def str_replace_edit(file_path: str, old_str: str, new_str: str) -> str:
        """Replace old_str with new_str in a file inside the container."""
        if rewrite_probes:
            new_str = rewrite_probe_code(new_str)
        # This tool IS ContraFix's patch-application step: the Patcher writes
        # its fix straight into the source rather than emitting a diff for a
        # separate apply pass.  Timing it here is what makes a SAN2PATCH-style
        # "Patch time" (apply) separable from "Gen time" (the LLM producing
        # the edit), which the enclosing patch.agent span cannot distinguish.
        with track_current(
            "tool.apply", kind="detail",
            tool="str_replace_edit", container=container_id[:12],
        ):
            return _str_replace_edit(file_path, old_str, new_str)

    def _str_replace_edit(file_path: str, old_str: str, new_str: str) -> str:
        try:
            file_content = read_file(container_id, file_path)
        except FileNotFoundError as exc:
            return f"Error: {exc}"

        occurrences = file_content.count(old_str)
        if occurrences == 0:
            return (
                f"Error: old_str not found verbatim in {file_path}. "
                "Read the file first with bash('cat -n <path>') and "
                "copy the exact text including whitespace and tabs."
            )
        if occurrences > 1:
            lines: list[str] = []
            pos = 0
            for _ in range(occurrences):
                idx = file_content.find(old_str, pos)
                line_num = file_content.count("\n", 0, idx) + 1
                lines.append(str(line_num))
                pos = idx + len(old_str)
            return (
                f"Error: old_str appears {occurrences} times in {file_path} "
                f"(at lines {', '.join(lines)}). "
                "Include more surrounding context to make it unique."
            )

        state.history.append((file_path, file_content))
        updated = file_content.replace(old_str, new_str, 1)
        write_file(container_id, file_path, updated)

        display_content = updated.expandtabs()
        display_lines = display_content.splitlines()
        replace_start = file_content.find(old_str)
        start_line = file_content.count("\n", 0, replace_start)
        snippet_start = max(0, start_line - _SNIPPET_CONTEXT)
        snippet_end = min(
            len(display_lines),
            start_line + new_str.count("\n") + 1 + _SNIPPET_CONTEXT,
        )
        snippet_lines = [
            f"{i + 1:>6}\t{display_lines[i]}"
            for i in range(snippet_start, snippet_end)
        ]
        snippet = "\n".join(snippet_lines)
        return (
            f"Successfully edited {file_path}. Snippet around the change:\n"
            f"{snippet}\n"
            "Review the changes and make further edits if needed."
        )

    return FunctionTool(
        str_replace_edit,
        description=(
            "Replace exact text in a container file. old_str must appear "
            "exactly once (include surrounding lines for uniqueness). "
            "Use bash('cat -n <path>') to read the file first."
        ),
    )


def make_insert_probe_tool(
    container_id: str,
    edit_state: _EditState | None = None,
) -> FunctionTool:
    """Create a probe insertion tool with exact-anchor semantics."""

    state = edit_state or _EditState()

    def insert_probe(
        file_path: str,
        anchor: str,
        probe_code: str,
        placement: str = "before",
    ) -> str:
        """Insert caller-provided probe code before/after an exact anchor."""
        try:
            file_content = read_file(container_id, file_path)
        except FileNotFoundError as exc:
            return f"Error: {exc}"

        occurrences = file_content.count(anchor)
        if occurrences == 0:
            return (
                f"Error: anchor not found verbatim in {file_path}. "
                "Read the file first and copy an exact unique anchor."
            )
        if occurrences > 1:
            return (
                f"Error: anchor appears {occurrences} times in {file_path}. "
                "Provide more surrounding context so the insertion point is unique."
            )

        probe_code = rewrite_probe_code(probe_code)
        normalized_probe = probe_code
        if normalized_probe and not normalized_probe.endswith("\n"):
            normalized_probe += "\n"

        if placement == "before":
            replacement = normalized_probe + anchor
        elif placement == "after":
            replacement = anchor + "\n" + normalized_probe
        elif placement == "replace":
            replacement = normalized_probe
        else:
            return "Error: placement must be one of before, after, replace."

        state.history.append((file_path, file_content))
        updated = file_content.replace(anchor, replacement, 1)
        write_file(container_id, file_path, updated)
        probe_id = hashlib.sha256(
            f"{file_path}\0{anchor}\0{probe_code}".encode("utf-8")
        ).hexdigest()[:12]
        _append_tool_event(
            container_id,
            {
                "tool": "insert_probe",
                "probe_id": probe_id,
                "file_path": file_path,
                "placement": placement,
                "anchor_sha256": hashlib.sha256(anchor.encode("utf-8")).hexdigest(),
                "probe_sha256": hashlib.sha256(
                    probe_code.encode("utf-8")
                ).hexdigest(),
                "has_probe_prefix": "PROBE:" in probe_code,
            },
        )

        display_lines = updated.expandtabs().splitlines()
        insert_start = file_content.find(anchor)
        start_line = file_content.count("\n", 0, insert_start)
        snippet_start = max(0, start_line - _SNIPPET_CONTEXT)
        snippet_end = min(
            len(display_lines),
            start_line + normalized_probe.count("\n") + 2 + _SNIPPET_CONTEXT,
        )
        snippet = "\n".join(
            f"{i + 1:>6}\t{display_lines[i]}"
            for i in range(snippet_start, snippet_end)
        )
        warning = ""
        if "PROBE:" not in probe_code:
            warning = "\nWarning: probe_code does not contain the PROBE: prefix."
        return (
            f"Inserted probe {probe_id} in {file_path}. "
            "A manifest entry was written to "
            f"{TOOL_EVENT_LOG}.\n"
            "Snippet around insertion:\n"
            f"{snippet}{warning}"
        )

    return FunctionTool(
        insert_probe,
        description=(
            "Insert explicit caller-provided probe code before/after an exact "
            "unique anchor in a source file. The tool does not choose what to "
            "observe; the Analyzer must provide the dprintf(2, ...) probe."
        ),
    )


# ---------------------------------------------------------------------------
# Compatibility revert tools
# ---------------------------------------------------------------------------


def make_revert_last_edit_tool(
    container_id: str,
    edit_state: _EditState | None = None,
) -> FunctionTool:
    """Create a compatibility revert_last_edit tool."""

    state = edit_state or _EditState()

    def revert_last_edit() -> str:
        """Revert the most recent str_replace_edit performed through the shim."""
        if not state.history:
            return "No tracked edit history is available to revert."
        file_path, previous_content = state.history.pop()
        # Undoing an application is application work too.
        with track_current(
            "tool.apply", kind="detail",
            tool="revert_last_edit", container=container_id[:12],
        ):
            write_file(container_id, file_path, previous_content)
        return f"Reverted last tracked edit in {file_path}."

    return FunctionTool(
        revert_last_edit,
        description=(
            "Revert the most recent tracked text edit. Compatibility shim for the "
            "paper interface; only edits made through str_replace_edit are tracked."
        ),
    )



def make_revert_all_edits_tool(
    container_id: str,
    edit_state: _EditState | None = None,
) -> FunctionTool:
    """Create a compatibility revert_all_edits tool."""

    state = edit_state or _EditState()

    def revert_all_edits() -> str:
        """Reset the container workspace to a clean source state."""
        with track_current(
            "tool.apply", kind="detail",
            tool="revert_all_edits", container=container_id[:12],
        ):
            success, output = reset_source(container_id)
        state.history.clear()
        prefix = "Successfully reverted all edits." if success else "Failed to revert all edits."
        return _truncate_output(f"{prefix}\n{output}")

    return FunctionTool(
        revert_all_edits,
        description=(
            "Reset the container workspace to a clean git state. Compatibility shim "
            "for the paper interface."
        ),
    )


# ---------------------------------------------------------------------------
# Compatibility mutation / execution tools
# ---------------------------------------------------------------------------


def make_mutate_poc_tool(container_id: str) -> FunctionTool:
    """Create a compatibility mutate_poc tool."""

    def _decode_content(content: str, encoding: str) -> bytes:
        if encoding == "text":
            return content.encode("utf-8")
        if encoding == "base64":
            return base64.b64decode(content)
        if encoding == "hex":
            return bytes.fromhex(content)
        raise ValueError("encoding must be one of text, base64, hex")

    def _decode_op_bytes(op: dict) -> bytes:
        if "data_hex" in op:
            return bytes.fromhex(str(op["data_hex"]))
        if "data_base64" in op:
            return base64.b64decode(str(op["data_base64"]))
        if "data_text" in op:
            return str(op["data_text"]).encode("utf-8")
        raise ValueError(
            "byte operation must provide data_hex, data_base64, or data_text"
        )

    def _apply_byte_edits(source_path: str, edits_json: str) -> bytes:
        data = bytearray(read_file_bytes(container_id, source_path))
        parsed = json.loads(edits_json)
        edits = parsed if isinstance(parsed, list) else [parsed]

        for edit in edits:
            if not isinstance(edit, dict):
                raise ValueError("each edit must be a JSON object")
            op = str(edit.get("op", ""))
            if op == "set_byte":
                offset = int(edit["offset"])
                value = int(edit["value"])
                if offset < 0 or offset >= len(data):
                    raise ValueError(f"set_byte offset {offset} is out of range")
                if value < 0 or value > 255:
                    raise ValueError("set_byte value must be in [0, 255]")
                data[offset] = value
            elif op == "replace_bytes":
                offset = int(edit["offset"])
                replacement = _decode_op_bytes(edit)
                length = int(edit.get("length", len(replacement)))
                if offset < 0 or offset + length > len(data):
                    raise ValueError(
                        f"replace_bytes range {offset}:{offset + length} "
                        "is out of range"
                    )
                data[offset : offset + length] = replacement
            elif op == "insert_bytes":
                offset = int(edit["offset"])
                insertion = _decode_op_bytes(edit)
                if offset < 0 or offset > len(data):
                    raise ValueError(f"insert_bytes offset {offset} is out of range")
                data[offset:offset] = insertion
            elif op == "delete_range":
                offset = int(edit["offset"])
                length = int(edit["length"])
                if offset < 0 or length < 0 or offset + length > len(data):
                    raise ValueError(
                        f"delete_range {offset}:{offset + length} is out of range"
                    )
                del data[offset : offset + length]
            elif op == "replace_text":
                text = bytes(data).decode("utf-8", errors="surrogateescape")
                old = str(edit["old"])
                new = str(edit["new"])
                count = int(edit.get("count", 1))
                if old not in text:
                    raise ValueError("replace_text old string not found")
                text = text.replace(old, new, count)
                data = bytearray(text.encode("utf-8", errors="surrogateescape"))
            else:
                raise ValueError(
                    "unsupported edit op; use set_byte, replace_bytes, "
                    "insert_bytes, delete_range, or replace_text"
                )
        return bytes(data)

    def mutate_poc(
        path: str,
        filename: str,
        content: str = "",
        encoding: str = "text",
        edits_json: str = "",
    ) -> str:
        """Create a variant from explicit content or structured byte edits."""
        target = filename if filename.startswith("/") else variant_path(filename)
        try:
            if edits_json:
                data = _apply_byte_edits(path, edits_json)
                source = f"byte edits from {path}"
            else:
                data = _decode_content(content, encoding)
                source = f"{encoding} content"
        except Exception as exc:
            return f"Error: failed to create variant: {exc}"

        write_file(container_id, target, data)
        digest = hashlib.sha256(data).hexdigest()
        preview = data[:64].hex()
        if edits_json:
            try:
                mutation_spec: dict | list = json.loads(edits_json)
            except json.JSONDecodeError:
                mutation_spec = {"edits_json_sha256": hashlib.sha256(
                    edits_json.encode("utf-8")
                ).hexdigest()}
        else:
            mutation_spec = {
                "encoding": encoding,
                "content_sha256": hashlib.sha256(
                    content.encode("utf-8")
                ).hexdigest(),
            }
        _append_tool_event(
            container_id,
            {
                "tool": "mutate_poc",
                "source_path": path,
                "target_path": target,
                "source": source,
                "bytes": len(data),
                "sha256": digest,
                "mutation_spec": mutation_spec,
            },
        )
        return (
            f"Created variant file at {target} from {source}.\n"
            f"bytes={len(data)} sha256={digest}\n"
            f"preview_hex_64={preview}\n"
            "Recorded mutation provenance in "
            f"{TOOL_EVENT_LOG}"
        )

    return FunctionTool(
        mutate_poc,
        description=(
            "Create a PoC variant file from explicit text/base64/hex content or "
            "from structured edits to an existing PoC. For byte edits pass "
            "edits_json, e.g. [{\"op\":\"set_byte\",\"offset\":12,\"value\":1}] "
            "or [{\"op\":\"replace_bytes\",\"offset\":4,\"length\":2,"
            "\"data_hex\":\"0001\"}]. The agent chooses offsets and values; "
            "the tool validates/applies the edit and records provenance."
        ),
    )



def make_run_variant_tool(
    container_id: str,
    repro_cmd_template: str = "",
    *,
    ext: str = "",
) -> FunctionTool:
    """Create a compatibility run_variant tool."""

    def run_variant(variant_id: str) -> str:
        """Execute a named variant using the provided repro template."""
        if not repro_cmd_template:
            return "Error: no repro command template configured for run_variant()."
        variant_name = _resolve_variant_path(variant_id, ext=ext)
        cmd = repro_cmd_template.replace("{poc}", variant_name)
        with track_current(
            "tool.test", kind="detail",
            tool="run_variant", container=container_id[:12],
        ):
            exit_code, stdout, stderr = exec_cmd(container_id, cmd)
        combined = stdout
        if stderr:
            combined = combined + "\n" + stderr if combined else stderr
        sanitizer = _detect_sanitizer_type(combined)
        _append_tool_event(
            container_id,
            {
                "tool": "run_variant",
                "variant_id": variant_id,
                "variant_path": variant_name,
                "command": cmd,
                "exit_code": exit_code,
                "sanitizer": sanitizer,
            },
        )
        return _truncate_output(
            f"[exit code: {exit_code}]\n"
            f"[sanitizer: {sanitizer}]\n"
            f"{combined}"
        )

    return FunctionTool(
        run_variant,
        description=(
            "Execute one generated variant under the current repro command. "
            "The tool resolves logical variant ids, classifies sanitizer output, "
            "and records the run in the provenance log."
        ),
    )



def make_run_probed_tool(
    container_id: str,
    repro_cmd_template: str = "",
    *,
    ext: str = "",
    poc_path: str = POC_PATH,
) -> FunctionTool:
    """Create a compatibility run_probed tool."""

    def _format_run(variant_id: str, variant_path: str, command: str, exit_code, output: str) -> str:
        output = _expand_probe_newlines(output)
        sanitizer = _detect_sanitizer_type(output)
        probe_lines = _extract_probe_lines(output)
        _append_tool_event(
            container_id,
            {
                "tool": "run_probed",
                "variant_id": variant_id,
                "variant_path": variant_path,
                "command": command,
                "exit_code": exit_code,
                "sanitizer": sanitizer,
                "probe_line_count": 0 if probe_lines == "<no PROBE lines>" else len(
                    probe_lines.splitlines()
                ),
            },
        )
        return _truncate_output(
            f"[exit code: {exit_code}]\n"
            f"[sanitizer: {sanitizer}]\n"
            f"{output}\n"
            "## Extracted PROBE lines\n"
            f"{probe_lines}"
        )

    def _probe_attempt(ids: list[str], target: dict) -> tuple:
        """Name this run_probed call and collect its probe diff and inputs.

        Returns ``(attempt_key, diff, inputs, names)``: *inputs* are the (name, content)
        pairs a rewriter runs, *names* one ``(variant_id, path, name)`` per requested id,
        with ``name`` None for an input that could not be read.
        """
        key = (container_id, target["round_num"])
        _METAPRO_PROBE_COUNTS[key] = _METAPRO_PROBE_COUNTS.get(key, 0) + 1
        attempt_key = f"analyzer_r{target['round_num']}_probe{_METAPRO_PROBE_COUNTS[key]}"
        diff = probe_diff(container_id, target["repo_root"])

        inputs, names = [], []
        for vid in ids:
            path = _resolve_variant_path(vid, ext=ext, poc_path=poc_path)
            name = re.sub(r"[^\w.-]", "_", "original" if path == poc_path else os.path.basename(path))
            try:
                inputs.append((name, read_file_bytes(container_id, path)))
                names.append((vid, path, name))
            except Exception as exc:
                names.append((vid, path, None))
                logger.warning("run_probed: cannot read %s: %s", path, exc)
        return attempt_key, diff, inputs, names

    def _metapro_probe_report(target: dict, diff: str, attempt_key: str, inputs: list) -> dict:
        from arvo import metapro as metapro_validator  # imported here: it is mode-specific

        with track_current(
            "tool.metapro_probe", kind="detail",
            tool="run_probed", container=container_id[:12],
        ):
            try:
                return metapro_validator.run_probes(
                    target["project"], target["local_id"], target["fuzz_target"],
                    diff, attempt_key, inputs,
                )
            except metapro_validator.MetaproUnavailable as exc:
                return {"ok": False, "stage": "unavailable", "error": str(exc), "runs": []}

    def _dyninst_probe_report(target: dict, diff: str, attempt_key: str, inputs: list) -> dict:
        from arvo import dyninst as dyninst_validator  # imported here: it is mode-specific

        with track_current(
            "tool.dyninst_probe", kind="detail",
            tool="run_probed", container=container_id[:12],
        ):
            try:
                dyninst_validator.prepare(target["project"], target["local_id"], target["fuzz_target"])
                return dyninst_validator.run_probes(
                    target["project"], target["local_id"], target["fuzz_target"],
                    diff, attempt_key, inputs,
                )
            except dyninst_validator.DyninstUnavailable as exc:
                return {"ok": False, "stage": "unavailable", "error": str(exc), "runs": []}

    def _format_probe_runs(header: str, report: dict, names: list, command: str) -> str:
        runs = {r.get("variant"): r for r in report.get("runs", [])}
        outputs = [header]
        for vid, path, name in names:
            outputs.append(f"## Variant {vid}")
            run = runs.get(name) if name else None
            if run is None or not run.get("ok"):
                outputs.append(f"Error: could not run {path} on the probed binary.")
                continue
            output = scrub_metapro_runtime(run.get("output", ""))
            if run.get("runtime_error"):
                output = output.rstrip("\n") + "\n" + METAPRO_RUNTIME_NOTE
            outputs.append(_format_run(vid, path, command, run.get("exit_code"), output))
        return _truncate_output("\n".join(outputs))

    def _run_probed_metapro(ids: list[str], target: dict) -> str:
        """PATCH_MODE metapro: insert the probes into the instrumented binary with metapro
        and run the inputs on it -- no rebuild.  A probe metapro cannot express is
        reported back to the Analyzer; the project is never built as a fallback."""
        attempt_key, diff, inputs, names = _probe_attempt(ids, target)
        report = _metapro_probe_report(target, diff, attempt_key, inputs)
        header = (
            f"## Probes (inserted into the prebuilt binary with metapro, no rebuild: "
            f"{report.get('config_size', 0)} insert site(s))"
        )
        if not report.get("ok"):
            return _truncate_output(
                f"{header}\nmetapro could not apply the probes (stage: {report.get('stage')}): "
                f"{report.get('error', '')}\n"
                "Probes must be plain `dprintf(2, \"PROBE: ...\\n\", ...);` statements placed "
                "inside function bodies. Simplify or move them, then call run_probed again."
            )
        return _format_probe_runs(header, report, names, f"metapro:{attempt_key}")

    def _run_probed_combined(ids: list[str], target: dict) -> str | None:
        """PATCH_MODE combined: metapro first, then Dyninst when metapro could not insert
        the probes or its runtime could not run them.  Returns None when Dyninst could not
        either, and the caller builds the project instead.  The header names neither
        rewriter, as the Patcher is never told which one validated its patch."""
        attempt_key, diff, inputs, names = _probe_attempt(ids, target)

        report = _metapro_probe_report(target, diff, attempt_key, inputs)
        if report.get("ok") and not any(r.get("runtime_error") for r in report.get("runs", [])):
            header = "## Probes (inserted into the prebuilt binary, no rebuild)"
            return _format_probe_runs(header, report, names, f"metapro:{attempt_key}")
        logger.info("run_probed: metapro could not run the probes (%s: %s), trying dyninst",
                    report.get("stage"), str(report.get("error", ""))[:200])

        report = _dyninst_probe_report(target, diff, attempt_key, inputs)
        if report.get("ok"):
            header = "## Probes (inserted into the prebuilt binary, no rebuild)"
            return _format_probe_runs(header, report, names, f"dyninst:{attempt_key}")
        logger.info("run_probed: dyninst could not run the probes (%s: %s), building instead",
                    report.get("stage"), str(report.get("error", ""))[:200])
        return None

    def _run_one(variant_id: str) -> str:
        if not repro_cmd_template:
            return "Error: no repro command template configured for run_probed()."
        if "{poc}" not in repro_cmd_template:
            return (
                "Error: repro command template does not contain {poc}; "
                f"configured command was: {repro_cmd_template}"
            )
        variant_name = _resolve_variant_path(
            variant_id,
            ext=ext,
            poc_path=poc_path,
        )
        cmd = repro_cmd_template.replace("{poc}", variant_name)
        with track_current(
            "tool.test", kind="detail",
            tool="run_probed", container=container_id[:12],
        ):
            exit_code, stdout, stderr = exec_cmd(container_id, cmd)
        combined = stdout
        if stderr:
            combined = combined + "\n" + stderr if combined else stderr
        return _format_run(variant_id, variant_name, cmd, exit_code, combined)

    def run_probed(variant_ids: str = "") -> str:
        """Build once, then execute one or more variants for probe inspection."""
        _save_probe_snapshot(container_id)
        target = _METAPRO_PROBE_TARGETS.get(container_id)
        if target is not None:
            ids = [v.strip() for v in variant_ids.split(",") if v.strip()] or ["original"]
            if target["mode"] != "combined":
                return _run_probed_metapro(ids, target)
            probed = _run_probed_combined(ids, target)
            if probed is not None:
                return probed
        with track_current(
            "tool.build", kind="detail",
            tool="run_probed", container=container_id[:12],
        ):
            build_ok, build_out = build_project(container_id)
        outputs = ["## Build", summarize_build_output(build_out, build_ok)]
        if not build_ok:
            return _truncate_output("\n".join(outputs))
        ids = [v.strip() for v in variant_ids.split(",") if v.strip()] or ["original"]
        for vid in ids:
            outputs.append(f"## Variant {vid}")
            outputs.append(_run_one(vid))
        return _truncate_output("\n".join(outputs))

    return FunctionTool(
        run_probed,
        description=(
            "Build the project, then execute one or more logical PoC ids to collect "
            "probe output. Use original for the original PoC, variant_1 for "
            "/tmp/variant_1, or an absolute path. The tool extracts PROBE "
            "lines and records per-run sanitizer/probe metadata."
        ),
    )



def make_check_vul_tool(container_id: str) -> FunctionTool:
    """Create a compatibility check_vul tool."""

    def check_vul() -> str:
        """Rebuild, then re-run the benchmark's original vulnerability check."""
        # The rebuild is not optional.  ARVO images ship a prebuilt
        # /out/<fuzz_target>, and `arvo` runs that binary without rebuilding,
        # so calling it straight after an edit reports the *previous* build's
        # behaviour — an agent would see "still crashing" for a patch that
        # actually fixed the bug, or vice versa.
        with track_current(
            "tool.build", kind="detail",
            tool="check_vul", container=container_id[:12],
        ):
            build_ok, build_out = build_project(container_id)
        if not build_ok:
            _append_tool_event(
                container_id,
                {"tool": "check_vul", "command": BUILD_CMD, "exit_code": 1,
                 "sanitizer": "build-failed"},
            )
            return _truncate_output(
                "[build failed — the vulnerability check did not run]\n"
                + summarize_build_output(build_out, False)
            )

        with track_current(
            "tool.test", kind="detail",
            tool="check_vul", container=container_id[:12],
        ):
            exit_code, stdout, stderr = exec_cmd(container_id, REPRO_CMD)
        combined = stdout
        if stderr:
            combined = combined + "\n" + stderr if combined else stderr
        sanitizer = _detect_sanitizer_type(combined)
        _append_tool_event(
            container_id,
            {
                "tool": "check_vul",
                "command": f"{BUILD_CMD} && {REPRO_CMD}",
                "exit_code": exit_code,
                "sanitizer": sanitizer,
            },
        )
        return _truncate_output(
            f"[build: ok]\n[exit code: {exit_code}]\n"
            f"[sanitizer: {sanitizer}]\n{combined}"
        )

    return FunctionTool(
        check_vul,
        description=(
            "Rebuild the project and re-run the original PoC. Exit code 0 with no "
            "sanitizer output means the vulnerability no longer reproduces."
        ),
    )



def make_submit_tool(container_id: str, project: str = "") -> FunctionTool:
    """Create a compatibility submit tool."""

    def submit() -> str:
        """Return the current git diff for the project under repair."""
        # Scoped to /src/<project>.  /src is not a git repository in ARVO
        # images, and its subdirectories include the fuzzer toolchain
        # (/src/aflplusplus) and vendored dependencies — an ffmpeg image has
        # ten repos.  Taking "the first child repo with a .git" would pick
        # aflplusplus for libxml2, which sorts first.
        root = project_dir(project) if project else "/src"
        cmd = f"cd {root} && git --no-pager diff --no-ext-diff"
        exit_code, stdout, stderr = exec_cmd(container_id, cmd)
        combined = stdout
        if stderr:
            combined = combined + "\n" + stderr if combined else stderr
        return _truncate_output(f"[exit code: {exit_code}]\n{combined}")

    return FunctionTool(
        submit,
        description=(
            "Return the current git diff from the benchmark repo. Compatibility shim "
            "for the paper interface."
        ),
    )
