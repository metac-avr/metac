"""Adversarial differential analysis pipeline for the ARVO solver.

Architecture:
  Stage 0: Setup (start container, build, verify original PoC crashes)
  Stage 1: Adversarial Loop (Mutate -> Analyze -> Patch -> Verify -> feedback)
           The Analyze stage discovers violated safety properties from crash
           differentials.  Properties guide subsequent Patch and Mutate stages.
           Saves every patch that passes the original PoC as a candidate.
  Stage 2: Selection (if multiple candidates, Selector picks the most robust one)

The Patcher agent edits source files directly via tools.  The pipeline
extracts the resulting patch with ``git --no-pager diff`` — the LLM never
generates unified-diff text itself.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import tempfile

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.messages import ToolCallRequestEvent
from autogen_ext.models.openai import OpenAIChatCompletionClient

from arvo.agents import create_analyzer, create_model_client, create_mutator, create_patcher, create_selector
from arvo import dyninst as dyninst_validator
from arvo import tools as arvo_tools
from arvo import metapro as metapro_validator
from arvo.config import (
    ABLATION_SKIP_ANALYZER,
    ABLATION_SKIP_MUTATOR,
    ABLATION_SKIP_MUTATION_EXP,
    ABLATION_SKIP_PATCHER_EXP,
    MAX_ADVERSARIAL_ROUNDS,
    MAX_MUTATION_RETRIES,
    MAX_MUTATION_VARIANTS,
    MAX_PATCHER_RETRIES,
    PATCHES_PER_ROUND,
    PATCHER_TEMPERATURE,
    PATCH_MODE,
    VARIANT_GATE,
)
from arvo.experience import (
    extract_vuln_type,
    format_experience_prompt,
    format_mutation_prompt,
    retrieve_experiences,
    retrieve_mutation_experiences,
    save_experience,
    save_mutation_experience,
)
from arvo.docker_tools import (
    apply_patch,
    build_project,
    copy_from_container,
    copy_to_container,
    exec_cmd,
    prepare_image,
    read_file_bytes,
    reset_source,
    run_custom_repro,
    run_repro,
    start_container,
    start_patcher_containers,
    stop_container,
    stop_containers,
    write_file,
)
from arvo.benchmark import WORK_DIR, project_dir
from arvo.dataset import bootstrap_instance
from arvo.repro_parser import ReproCommand, parse_repro_command, sniff_poc_type
from arvo.timing import StageTimer, set_current, track
from arvo.trajectory import (
    append_agent_trajectory,
    init_trajectory,
    save_timing,
    summarize_token_usage,
)

logger = logging.getLogger(__name__)

# Maximum retries for transient API errors (connection reset, timeout, etc.)
_API_RETRY_MAX = 3
_API_RETRY_DELAY = 30  # seconds


async def _run_with_retry(agent, task: str, retries: int = _API_RETRY_MAX):
    """Run an agent with automatic retry on transient API errors."""
    for attempt in range(1, retries + 1):
        try:
            return await agent.run(task=task)
        except (Exception,) as exc:
            exc_name = type(exc).__name__
            # Only retry on connection / timeout / server errors
            retriable = any(kw in exc_name for kw in ("Connection", "Timeout", "Server")) or \
                         any(kw in str(exc) for kw in ("Connection", "disconnected", "timed out", "502", "503", "529"))
            if retriable and attempt < retries:
                logger.warning(
                    "API error (%s), retrying agent %s in %ds (attempt %d/%d): %s",
                    exc_name, agent.name, _API_RETRY_DELAY, attempt, retries, str(exc)[:200],
                )
                await asyncio.sleep(_API_RETRY_DELAY)
                continue
            raise


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _has_sanitizer_error(output: str) -> bool:
    """Check if output contains ANY sanitizer error indicator."""
    indicators = [
        "ERROR: AddressSanitizer",
        "ERROR: MemorySanitizer",
        "ERROR: UndefinedBehaviorSanitizer",
        "ERROR: LeakSanitizer",
        "ERROR: ThreadSanitizer",
        "SUMMARY: AddressSanitizer",
        "SUMMARY: MemorySanitizer",
        "SUMMARY: UndefinedBehaviorSanitizer",
        "runtime error:",
    ]
    return any(ind in output for ind in indicators)


def _matches_vuln_type(output: str, orig_vuln_type: str) -> bool:
    """Check if *output* triggers the SAME vulnerability type as the original PoC.

    A variant is considered a "same-bug crash" only when its sanitizer output
    maps to the same canonical vulnerability type (via ``extract_vuln_type``).
    This prevents counting unrelated sanitizer errors as valid crash
    reproductions, which would confuse the differential analysis.

    Falls back to ``_has_sanitizer_error`` when the original vuln type is
    ``"unknown"`` (no pattern matched for the original PoC).
    """
    if orig_vuln_type == "unknown":
        # Cannot narrow — accept any sanitizer error
        return _has_sanitizer_error(output)
    variant_type = extract_vuln_type(output)
    return variant_type == orig_vuln_type


def _truncate(text: str, max_len: int = 3000) -> str:
    """Truncate text for prompt inclusion, keeping head and tail."""
    if len(text) <= max_len:
        return text
    half = max_len // 2
    return text[:half] + "\n... [truncated] ...\n" + text[-half:]


def _get_extension(path: str) -> str:
    """Get file extension from a path."""
    import posixpath
    _, ext = posixpath.splitext(path)
    return ext if ext else ""


def _extract_selected_index(selector_output: str) -> int | None:
    """Extract the selected candidate number from Selector output."""
    match = re.search(r'SELECTED:\s*(\d+)', selector_output)
    if match:
        return int(match.group(1))
    return None


def _content_to_str(content) -> str:
    """Normalise an AutoGen message .content to a plain string.

    AutoGen may return content as a ``str`` or as a ``list`` of content
    blocks (dicts with ``"text"`` keys, or other types).  This helper
    handles both cases and preserves newlines.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                parts.append(item.get("text", ""))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    return str(content) if content else ""


def _safe_instance_id(instance_id: str) -> str:
    """Sanitize instance_id for host filesystem paths."""
    return instance_id.replace("/", "_").replace("\\", "_")


def prepare_log_path(results_dir: str, instance_id: str) -> str:
    """Where ``prepare_image``'s full log for *instance_id* is written."""
    return os.path.join(
        results_dir, "prepare_logs", f"{_safe_instance_id(instance_id)}.log"
    )


def _extract_bash_command(arguments) -> str:
    """Extract the ``command`` argument from a tool call payload."""
    if isinstance(arguments, dict):
        cmd = arguments.get("command")
        return cmd if isinstance(cmd, str) else ""
    if isinstance(arguments, str):
        try:
            parsed = json.loads(arguments)
            if isinstance(parsed, dict):
                cmd = parsed.get("command")
                return cmd if isinstance(cmd, str) else ""
        except json.JSONDecodeError:
            return ""
    return ""


def _build_mutation_strategy_summary(
    crash_reports: list[dict],
    mutation_attempt_records: list[dict],
) -> str:
    """Build a semantic-level mutation strategy summary from available data.

    Extracts what mutation strategies were used and what the crash/non-crash
    differential reveals about the vulnerability boundary, without an extra
    LLM call.
    """
    parts: list[str] = []

    # Summarise from Mutator's assistant_summary (its own reasoning)
    for rec in mutation_attempt_records:
        trace = rec.get("mutation_trace", {})
        if isinstance(trace, dict):
            summary = trace.get("assistant_summary", "")
            if summary:
                parts.append(summary[:800])
                break  # Use the first non-empty summary

    # Extract differential insight from crash vs non-crash
    crashed = [r for r in crash_reports if r.get("crashed")]
    safe = [r for r in crash_reports if not r.get("crashed")]

    if crashed or safe:
        parts.append(
            f"Differential: {len(crashed)} inputs crashed, "
            f"{len(safe)} did not."
        )
        # Summarise variant-level info compactly (name + vuln_type only)
        for r in crashed[:3]:
            parts.append(f"  Crash: {r.get('variant', '?')} [{r.get('vuln_type', '?')}]")
        for r in safe[:3]:
            parts.append(f"  Safe:  {r.get('variant', '?')} [{r.get('vuln_type', '?')}]")

    return "\n".join(parts)[:2000]


def _extract_mutator_trace(messages) -> dict:
    """Extract mutator operations from trajectory messages.

    Returns a compact trace that can be persisted and reused in prompts.
    """
    commands: list[str] = []
    for msg in messages or []:
        if not isinstance(msg, ToolCallRequestEvent):
            continue
        for fc in msg.content:
            if getattr(fc, "name", "") != "bash":
                continue
            cmd = _extract_bash_command(getattr(fc, "arguments", ""))
            if cmd:
                commands.append(cmd)

    # Keep only mutation-relevant shell commands to reduce noise.
    mutation_cmds = [
        c for c in commands
        if "/tmp/variant_" in c or "/tmp/mutate.py" in c
    ]
    variant_generation: dict[str, list[str]] = {}
    for cmd in mutation_cmds:
        # Track which command produced which variant path(s).
        for match in re.findall(r"/tmp/variant_[^ \n\t\"'`;|)]+", cmd):
            import posixpath
            base = posixpath.basename(match)
            variant_generation.setdefault(base, []).append(cmd)

    assistant_summary = ""
    for msg in reversed(messages or []):
        text = _content_to_str(getattr(msg, "content", ""))
        if text and text.strip():
            assistant_summary = _truncate(text.strip(), 2000)
            break

    return {
        "num_bash_calls": len(commands),
        "mutation_commands": mutation_cmds[:30],
        "variant_generation": {k: v[:5] for k, v in variant_generation.items()},
        "assistant_summary": assistant_summary,
    }


def _persist_mutation_attempt_artifacts(
    container_id: str,
    results_dir: str,
    instance_id: str,
    round_num: int,
    attempt_num: int,
    crash_reports: list[dict],
    trace: dict,
) -> dict:
    """Persist mutation attempt artifacts for offline replay/analysis."""
    safe_id = _safe_instance_id(instance_id)
    attempt_dir = os.path.join(
        results_dir,
        "mutation_artifacts",
        safe_id,
        f"round_{round_num}",
        f"attempt_{attempt_num}",
    )
    variants_dir = os.path.join(attempt_dir, "variants")
    repro_dir = os.path.join(attempt_dir, "repro_outputs")
    os.makedirs(variants_dir, exist_ok=True)
    os.makedirs(repro_dir, exist_ok=True)

    persisted_reports: list[dict] = []
    for r in crash_reports:
        variant = r.get("variant", "")
        src_path = r.get("path", "")
        variant_host_path = os.path.join(variants_dir, variant) if variant else ""
        copied_ok = False
        copy_msg = "missing source path"
        if src_path and variant_host_path:
            copied_ok, copy_msg = copy_from_container(
                container_id, src_path, variant_host_path
            )

        repro_log_path = os.path.join(repro_dir, f"{variant}.log") if variant else ""
        if repro_log_path:
            with open(repro_log_path, "w", encoding="utf-8") as f:
                f.write(r.get("raw_output", ""))

        persisted_reports.append({
            "variant": variant,
            "container_path": src_path,
            "host_variant_path": variant_host_path,
            "variant_copied": copied_ok,
            "variant_copy_message": copy_msg,
            "repro_log_path": repro_log_path,
            "exit_code": r.get("exit_code"),
            "crashed": r.get("crashed"),
            "vuln_type": r.get("vuln_type", "unknown"),
            "file_sha256": r.get("file_sha256", ""),
            "mutation_how": r.get("mutation_how", ""),
            "mutation_commands": r.get("mutation_commands", []),
            "output_snippet": r.get("output", ""),
        })

    metadata = {
        "instance_id": instance_id,
        "round": round_num,
        "attempt": attempt_num,
        "num_variants": len(crash_reports),
        "num_crashed": sum(1 for x in crash_reports if x.get("crashed")),
        "num_not_crashed": sum(1 for x in crash_reports if not x.get("crashed")),
        "trace": trace,
        "variants": persisted_reports,
    }
    meta_path = os.path.join(attempt_dir, "metadata.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    return {
        "artifact_dir": attempt_dir,
        "metadata_path": meta_path,
        "num_variants": metadata["num_variants"],
        "num_crashed": metadata["num_crashed"],
        "num_not_crashed": metadata["num_not_crashed"],
    }


def _persist_patch_attempt(
    patch_dir: str,
    patch_log: list[dict] | None,
    patcher_key: str,
    round_num: int,
    attempt_num: int,
    diff: str,
    status: str,
    feedback: str = "",
    func_diff: str = "",
    variant_result: dict | None = None,
    metapro_result: dict | None = None,
) -> dict | None:
    """Save one Patcher attempt's diff to disk, whatever its outcome.

    *status* is one of ``verified``, ``repro_failed``, ``variant_failed``,
    ``build_failed``, ``empty``.  *variant_result* is the variant gate's
    ``_test_variants_against_patch`` result, when it ran.  Every attempt is kept, including in-round retries and diffs
    that duplicate another Patcher's, so the full sample set can be
    evaluated offline.  *func_diff* (``git diff -W``) goes to a sibling
    ``.func.diff`` file.  ``selected`` starts False; ``_mark_selected`` sets
    it on the attempt the pipeline returns.

    Returns the recorded entry, or None when *patch_dir* is unset.
    """
    if not patch_dir:
        return None
    os.makedirs(patch_dir, exist_ok=True)
    stem = f"{patcher_key or 'patcher'}_attempt{attempt_num}"
    diff_path = os.path.join(patch_dir, f"{stem}.diff") if diff else ""
    if diff_path:
        with open(diff_path, "w", encoding="utf-8") as f:
            f.write(diff)
    func_diff_path = os.path.join(patch_dir, f"{stem}.func.diff") if func_diff else ""
    if func_diff_path:
        with open(func_diff_path, "w", encoding="utf-8") as f:
            f.write(func_diff)
    entry = {
        "patcher": patcher_key,
        "round": round_num + 1,
        "attempt": attempt_num,
        "status": status,
        "verified": status == "verified",
        "diff_path": diff_path,
        "func_diff_path": func_diff_path,
        "feedback": feedback,
        "variant_test": variant_result or {},
        "metapro": metapro_result or {},
        "selected": False,
    }
    _write_attempt_json(patch_dir, entry)
    if patch_log is not None:
        patch_log.append(entry)
    return entry


def _write_attempt_json(patch_dir: str, entry: dict) -> None:
    """Write one attempt's ``<patcher>_attempt<n>.json``."""
    stem = f"{entry['patcher'] or 'patcher'}_attempt{entry['attempt']}"
    with open(os.path.join(patch_dir, f"{stem}.json"), "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=2, ensure_ascii=False)


def _mark_selected(patch_dir: str, patch_log: list[dict], selected: dict | None) -> None:
    """Flag *selected* (a ``patch_log`` entry) as the attempt the pipeline returned.

    ``patch_log`` entries are shared with ``index.json`` and the result's
    ``all_patches``, so both pick the flag up when next written.  When two
    Patchers produced the same diff, only the one kept by deduplication in
    ``_patch_parallel`` carries it.
    """
    if not patch_dir or selected is None:
        return
    for entry in patch_log:
        entry["selected"] = entry is selected
    _write_attempt_json(patch_dir, selected)
    _write_patch_index(patch_dir, patch_log)


def _write_patch_index(patch_dir: str, patch_log: list[dict]) -> None:
    """Write ``index.json`` listing every patch attempt recorded so far."""
    if not patch_dir or not patch_log:
        return
    os.makedirs(patch_dir, exist_ok=True)
    with open(os.path.join(patch_dir, "index.json"), "w", encoding="utf-8") as f:
        json.dump(patch_log, f, indent=2, ensure_ascii=False)


def _read_func_diff(entry: dict | None) -> str:
    """The function-context diff (``git diff -W``) saved for a patch attempt, or ""."""
    path = (entry or {}).get("func_diff_path", "")
    if not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        logger.warning("Could not read %s", path, exc_info=True)
        return ""


def _get_repo_root(container_id: str, project: str) -> str:
    """Return the source repo for *project*, i.e. ``/src/<project>``.

    ARVO has no ``secb``-style script to parse, and guessing is unsafe: /src
    is not a git repository, and "the first .git under /src" resolves to the
    fuzzer toolchain (/src/aflplusplus sorts before /src/libxml2) or to a
    vendored dependency (an ffmpeg image carries ten repos, including its own
    copy of libxml2).  The project name from overview.csv is authoritative.
    """
    root = project_dir(project)
    exit_code, _, _ = exec_cmd(container_id, f"test -d {root}/.git")
    if exit_code != 0:
        logger.warning(
            "%s is not a git repository; source reset and diff collection "
            "will not work", root,
        )
    return root


# ---------------------------------------------------------------------------
# Variant collection (after Mutator agent finishes)
# ---------------------------------------------------------------------------


def _collect_variant_results(
    container_id: str,
    repro_cmd: ReproCommand,
    round_num: int = 0,
    orig_vuln_type: str = "unknown",
    mutation_trace: dict | None = None,
) -> list[dict]:
    """Scan /tmp/variant_* files and run each, collecting crash reports.

    The ``round_num`` is prefixed to variant names so that variants from
    different rounds have unique identifiers in ``all_crash_reports``.

    A variant is marked ``crashed=True`` only when its sanitizer output
    matches the SAME vulnerability type as the original PoC (determined
    by ``orig_vuln_type``).  This prevents unrelated sanitizer errors from
    polluting the crash/no-crash differential used by the Analyzer.
    """
    # List variant files
    exit_code, stdout, _ = exec_cmd(
        container_id, "ls -1 /tmp/variant_* 2>/dev/null"
    )
    if exit_code != 0 or not stdout.strip():
        logger.warning("No variant files found in %s", WORK_DIR)
        return []

    variant_paths = [p.strip() for p in stdout.strip().splitlines() if p.strip()]
    crash_reports: list[dict] = []

    import posixpath

    for vpath in variant_paths:
        base_name = posixpath.basename(vpath)
        variant_name = f"r{round_num}_{base_name}"
        # Persist the file with a round-prefixed name so it survives across
        # rounds and can be used in cumulative variant robustness testing.
        persisted_path = f"{WORK_DIR}/{variant_name}"
        exec_cmd(container_id, f"cp '{vpath}' '{persisted_path}'")

        try:
            if repro_cmd.poc_type == "script":
                cmd = f"bash {persisted_path}"
            else:
                cmd = repro_cmd.build_cmd(persisted_path)
            exit_code, output = run_custom_repro(container_id, cmd)
            crashed = _matches_vuln_type(output, orig_vuln_type)
            variant_type = extract_vuln_type(output)
            h_exit, h_out, _ = exec_cmd(
                container_id, f"sha256sum '{persisted_path}' | awk '{{print $1}}'"
            )
            file_sha256 = h_out.strip() if h_exit == 0 else ""
            gen_map = mutation_trace.get("variant_generation", {}) if isinstance(mutation_trace, dict) else {}
            mutation_cmds = gen_map.get(base_name, []) if isinstance(gen_map, dict) else []
            mutation_how = " | ".join(mutation_cmds[:2]) if mutation_cmds else (
                mutation_trace.get("assistant_summary", "")[:300]
                if isinstance(mutation_trace, dict) else ""
            )
            crash_reports.append({
                "round": round_num,
                "base_variant": base_name,
                "variant": variant_name,
                "path": persisted_path,
                "exit_code": exit_code,
                "raw_output": output,
                "output": _truncate(output),
                "crashed": crashed,
                "vuln_type": variant_type,
                "file_sha256": file_sha256,
                "mutation_how": mutation_how,
                "mutation_commands": mutation_cmds[:3],
            })
            logger.info(
                "Variant %s: exit=%d, crashed=%s (orig_type=%s, variant_type=%s)",
                variant_name, exit_code, crashed,
                orig_vuln_type, variant_type,
            )
        except Exception as e:
            logger.warning("Failed to run variant %s: %s", variant_name, e)

    return crash_reports


# ---------------------------------------------------------------------------
# Mutation stage
# ---------------------------------------------------------------------------


async def _mutate(
    model_client: OpenAIChatCompletionClient,
    container_id: str,
    repro_cmd: ReproCommand,
    orig_poc: str,
    orig_output: str,
    instance: dict,
    round_num: int,
    prev_patch: str = "",
    prev_feedback: str = "",
    prev_crash_reports: list[dict] | None = None,
    property_info: str = "",
    mutation_guidance: str = "",
    orig_vuln_type: str = "unknown",
    traj_path: str = "",
    timer: StageTimer | None = None,
) -> tuple[list[dict], dict]:
    """Generate and execute PoC variants.

    Returns ``(crash_reports, mutation_trace)``.
    """
    logger.info(
        "Round %d: Mutating PoC (type=%s, targeted=%s)",
        round_num, repro_cmd.poc_type, round_num > 0,
    )

    targeted = round_num > 0
    ext = _get_extension(repro_cmd.poc_path)

    # Clean up temporary Mutator artifacts but keep persisted round-prefixed
    # variant files (r<N>_variant_*) so they remain available for cumulative
    # robustness testing across rounds.
    exec_cmd(container_id, "rm -f /tmp/mutate.py")
    # Remove only the raw variant_* files (Mutator's output), not r<N>_ prefixed ones
    exec_cmd(
        container_id,
        "for f in /tmp/variant_*; do [ -e \"$f\" ] && rm -f \"$f\"; done",
    )

    mutator = create_mutator(
        model_client,
        container_id,
        project=instance["project_name"],
        num_variants=MAX_MUTATION_VARIANTS,
        poc_path=repro_cmd.poc_path,
        poc_type=repro_cmd.poc_type,
        repro_cmd=repro_cmd.cmd_template or f"{repro_cmd.binary} {repro_cmd.args} {{poc}}",
        ext=ext,
        targeted=targeted,
    )

    # Build the task prompt
    if targeted:
        prev_crashes_text = ""
        variant_corpus_text = ""
        if prev_crash_reports:
            for r in prev_crash_reports:
                if r["crashed"]:
                    prev_crashes_text += f"- {r['variant']} (exit={r['exit_code']}): CRASHED\n"
                else:
                    prev_crashes_text += f"- {r['variant']}: did NOT crash\n"
                variant_corpus_text += (
                    f"- {r.get('path', '')} "
                    f"[{'CRASHED' if r.get('crashed') else 'NO-CRASH'}]\n"
                )

        task = f"""\
Generate {MAX_MUTATION_VARIANTS} TARGETED PoC variants for this vulnerability.

## Bug Description
{instance.get('bug_report', 'N/A')}

## Original PoC ({repro_cmd.poc_path}, type={repro_cmd.poc_type})
{_truncate(orig_poc) if repro_cmd.poc_type == 'text' else f'Binary file ({len(orig_poc)} bytes). Use bash to examine: xxd /tmp/poc | head -20'}

## Original sanitizer output
```
{_truncate(orig_output)}
```

## Previous Patch Attempt (insufficient)
```diff
{_truncate(prev_patch, 1500)}
```

## Patch Failure Feedback
{prev_feedback}

## Previous Variant Results
{prev_crashes_text}

## Existing Variant Corpus (reuse as mutation seeds)
{variant_corpus_text if variant_corpus_text else "No previous variants available."}

## Unresolved Safety Properties
{property_info if property_info else "No property analysis available yet."}

{mutation_guidance}

Create variants that specifically probe code paths the previous patch did NOT cover.
If unresolved safety properties are listed above, design variants targeting their boundary conditions.
Prefer mutating existing variant files under /tmp/r*_variant_* to form
clear parent->child mutation chains. Keep both crash and non-crash variants.
"""
    else:
        poc_display = _truncate(orig_poc) if repro_cmd.poc_type == "text" else \
            f"Binary file. Use bash to examine: xxd {repro_cmd.poc_path} | head -20"
        task = f"""\
Generate {MAX_MUTATION_VARIANTS} PoC variants for this vulnerability.

## Bug Description
{instance.get('bug_report', 'N/A')}

## Original PoC ({repro_cmd.poc_path}, type={repro_cmd.poc_type})
{poc_display}

## Sanitizer Report
```
{_truncate(orig_output)}
```

{mutation_guidance}

Create variants that trigger the same vulnerability through different code paths.
"""

    with track(
        timer, "mutate.agent", kind="detail", round_num=round_num,
        container=container_id[:12],
    ):
        result = await _run_with_retry(mutator, task)

    # Save trajectory
    if traj_path and result.messages:
        append_agent_trajectory(traj_path, f"mutator_r{round_num}", result.messages)
    mutation_trace = _extract_mutator_trace(result.messages)
    with track(timer, "mutate.run_variants", kind="detail", round_num=round_num):
        crash_reports = _collect_variant_results(
            container_id, repro_cmd, round_num=round_num,
            orig_vuln_type=orig_vuln_type,
            mutation_trace=mutation_trace,
        )

    logger.info(
        "Round %d mutation: %d variants found, %d crashed",
        round_num,
        len(crash_reports),
        sum(1 for r in crash_reports if r["crashed"]),
    )
    return crash_reports, mutation_trace


# ---------------------------------------------------------------------------
# Analysis stage (differential property discovery)
# ---------------------------------------------------------------------------


async def _analyze(
    analyzer: AssistantAgent,
    container_id: str,
    repo_root: str,
    orig_output: str,
    all_crash_reports: list[dict],
    new_crash_reports: list[dict],
    instance: dict,
    round_num: int,
    repro_cmd_str: str = "",
    prev_patch: str = "",
    prev_feedback: str = "",
    traj_path: str = "",
    timer: StageTimer | None = None,
    probe_dir: str = "",
) -> str:
    """Differential property discovery: deduce safety properties from crash reports.

    With *probe_dir*, the probes are kept as diffs there: ``analyzer_r<k>_build<j>.diff``
    for what each ``run_probed`` build contained, ``analyzer_r<k>_final.diff`` for the
    tree as the Analyzer left it -- taken before the reset below throws them away.

    The *analyzer* agent is reused across rounds so it retains memory of
    previous tool calls and reasoning.  On round 0 we send the full context;
    on subsequent rounds we send only the incremental information (new
    variants, patch feedback) and ask the agent to refine its analysis.

    The Analyzer may insert diagnostic probes (dprintf(2, ...)) into source code,
    build, and run the PoC to observe runtime values.  After the Analyzer
    finishes, the pipeline calls reset_source() to remove all probe edits
    before Patchers run.

    Returns the property_report text (structured markdown).
    """
    logger.info("Analyzing: differential property discovery (round %d)", round_num)

    probe_instructions = f"""
## Build & Run Instructions (for dynamic probes)
- Prefer `insert_probe(file_path, anchor, probe_code, placement)` for probes.
- Repro command template: `{repro_cmd_str}`
- After inserting probes, call `run_probed("original")` or \
`run_probed("original,variant_1,variant_2")` to build once and observe PROBE \
output on selected inputs.
- You may iterate: insert probes, build, run, analyse, insert more probes.
""" if repro_cmd_str else ""
    if probe_instructions and PATCH_MODE == "metapro":
        probe_instructions += """\
- run_probed does NOT rebuild the project here: it inserts your probes into the \
prebuilt binary with a binary patcher. Write each probe as one plain \
`dprintf(2, "PROBE: ...\\n", ...);` statement inside a function body; anything else \
(new control flow, edits to existing code) may not be insertable.
"""
    elif probe_instructions and PATCH_MODE == "combined":
        probe_instructions += """\
- run_probed first tries to insert your probes into the prebuilt binary without \
rebuilding, and rebuilds the project only when that is not possible. Write each probe \
as one plain `dprintf(2, "PROBE: ...\\n", ...);` statement inside a function body so it \
can be inserted.
"""

    if round_num == 0:
        # --- First round: full context ---
        crash_summary = f"### Original PoC crash\n```\n{_truncate(orig_output)}\n```\n\n"
        for report in all_crash_reports:
            status = "CRASHED" if report["crashed"] else "DID NOT CRASH"
            mutation_line = report.get("mutation_how", "")
            mutation_text = mutation_line if mutation_line else "N/A"
            crash_summary += (
                f"### {report['variant']} ({status}, exit={report['exit_code']})\n"
                f"Mutation lineage: {mutation_text}\n"
                f"```\n{report['output']}\n```\n\n"
            )

        task = f"""\
Analyse the following crash reports and derive violated safety properties.

## Bug Description
{instance.get('bug_report', 'N/A')}

## Crash Reports
{crash_summary}

The source code is in {repo_root}/. Read relevant files to understand the \
code semantics and derive precise safety properties.
{probe_instructions}
Use dynamic probes to verify your hypotheses about the root cause before \
finalising the Property Analysis Report.
"""
    else:
        # --- Subsequent rounds: incremental context only ---
        new_crash_summary = ""
        for report in new_crash_reports:
            status = "CRASHED" if report["crashed"] else "DID NOT CRASH"
            mutation_line = report.get("mutation_how", "")
            mutation_text = mutation_line if mutation_line else "N/A"
            new_crash_summary += (
                f"### {report['variant']} ({status}, exit={report['exit_code']})\n"
                f"Mutation lineage: {mutation_text}\n"
                f"```\n{report['output']}\n```\n\n"
            )

        task = f"""\
New round of analysis. Here are the NEW variant crash reports from this round:

## New Crash Reports
{new_crash_summary if new_crash_summary else "No new variants this round."}

## Previous Patch Attempt
```diff
{_truncate(prev_patch, 1500)}
```

## Patch Feedback
{prev_feedback}
{probe_instructions}
Refine your previous property analysis based on the new evidence. Some \
properties may have been addressed by the previous patch; focus on those \
that remain unresolved. Use dynamic probes if needed to verify remaining \
hypotheses. Produce an updated Property Analysis Report.
"""

    if probe_dir:
        arvo_tools.set_probe_snapshot_target(container_id, probe_dir, round_num, repo_root)
    if PATCH_MODE in ("metapro", "combined"):
        # run_probed inserts the probes into a prebuilt binary instead of building:
        # metapro only, or (combined) metapro, then dyninst, then a build (arvo.tools).
        arvo_tools.set_metapro_probe_target(
            container_id, project=instance["project_name"], local_id=instance["local_id"],
            fuzz_target=instance["fuzz_target"], repo_root=repo_root, round_num=round_num,
            mode=PATCH_MODE,
        )
    try:
        with track(
            timer, "analyze.agent", kind="detail", round_num=round_num,
            container=container_id[:12],
        ):
            result = await _run_with_retry(analyzer, task)
    finally:
        arvo_tools.clear_probe_snapshot_target(container_id)
        arvo_tools.clear_metapro_probe_target(container_id)

    # Save trajectory
    if traj_path and result.messages:
        append_agent_trajectory(traj_path, f"analyzer_r{round_num}", result.messages)

    with track(timer, "analyze.reset", kind="detail", round_num=round_num):
        if probe_dir:
            try:
                os.makedirs(probe_dir, exist_ok=True)
                with open(os.path.join(probe_dir, f"analyzer_r{round_num}_final.diff"), "w",
                          encoding="utf-8", errors="replace") as f:
                    f.write(arvo_tools.probe_diff(container_id, repo_root))
            except OSError as exc:
                logger.warning("could not save the Analyzer's final probe diff: %s", exc)

        # Clean up any probe edits the Analyzer inserted
        reset_source(container_id, project_root=repo_root)

        # Verify the reset actually produced a clean workspace
        _exit, _status_out, _ = exec_cmd(
            container_id, f"cd {repo_root} && git status --porcelain"
        )
        if _exit == 0 and _status_out.strip():
            logger.warning(
                "Workspace not clean after reset_source, forcing second reset. "
                "Dirty files: %s", _status_out.strip()[:200],
            )
            reset_source(container_id, project_root=repo_root)

    # Extract the Property Analysis Report from Analyzer messages.
    property_report = ""
    _REPORT_MARKER = "# Property Analysis Report"

    if result.messages:
        for msg in reversed(result.messages):
            text = _content_to_str(getattr(msg, "content", ""))
            if _REPORT_MARKER in text:
                property_report = text
                break

        if not property_report:
            for msg in reversed(result.messages):
                text = _content_to_str(getattr(msg, "content", ""))
                if text and len(text) > 100:
                    property_report = text
                    break

    logger.info(
        "Analyzer produced property report of %d chars", len(property_report)
    )
    return property_report


def _build_property_feedback(
    property_report: str,
    variant_result: dict,
    all_crash_reports: list[dict],
) -> str:
    """Cross-reference property report with variant test results to build
    property-level feedback for the next round.

    Returns a feedback string guiding subsequent Mutator and Patcher.
    """
    lines: list[str] = []

    total = variant_result.get("total", 0)
    still_crashed = variant_result.get("still_crashed", 0)

    lines.append(
        f"The patch passed the original PoC but {still_crashed}/{total} "
        f"variant PoCs still trigger sanitizer errors."
    )

    # List variants that still crash
    details = variant_result.get("details", [])
    crashed_variants = [d["variant"] for d in details if d.get("crashed_after_patch")]
    if crashed_variants:
        lines.append("")
        lines.append("Variants still crashing after patch:")
        for v in crashed_variants:
            # Find the original crash report for context
            orig = next((r for r in all_crash_reports if r["variant"] == v), None)
            if orig:
                lines.append(f"- {v}: {_truncate(orig.get('output', ''), 300)}")
            else:
                lines.append(f"- {v}")

    if property_report:
        lines.append("")
        lines.append("## Property-Level Assessment")
        lines.append(
            "The following property analysis was performed before patching. "
            "Some properties may have been addressed, but the remaining "
            "crashes suggest at least some properties are still violated:"
        )
        lines.append(property_report)

    lines.append("")
    lines.append(
        "Generate a more comprehensive fix that addresses ALL identified "
        "safety properties, especially those related to the still-crashing variants."
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Patch stage (parallel beam-search patching)
# ---------------------------------------------------------------------------


def _build_patcher_task(
    repo_root: str,
    orig_output: str,
    all_crash_reports: list[dict],
    new_crash_reports: list[dict],
    instance: dict,
    round_num: int,
    property_report: str = "",
    all_patches_feedback: list[dict] | None = None,
    experience_prompt: str = "",
) -> str:
    """Build the task prompt for a Patcher agent.

    This is extracted from the old ``_patch`` so that every parallel Patcher
    receives the same prompt (but may produce different edits due to high
    temperature sampling).
    """
    property_section = ""
    if property_report:
        property_section = f"""
## Property Analysis
{property_report}

The above properties were derived from differential analysis of crash vs \
non-crash variants. Ensure ALL HIGH-confidence properties hold after your fix.
"""

    # Build historical patch feedback section
    history_section = ""
    if all_patches_feedback:
        history_section = "\n## Historical Patch Attempts (all failed or insufficient)\n"
        for i, pf in enumerate(all_patches_feedback, 1):
            history_section += f"""
### Attempt {i} (round {pf.get('round', '?')})
```diff
{_truncate(pf.get('patch', ''), 1000)}
```
Feedback: {_truncate(pf.get('feedback', ''), 500)}
"""

    if round_num == 0 and not all_patches_feedback:
        # --- First round, no history ---
        crash_summary = f"## Original PoC crash\n```\n{_truncate(orig_output)}\n```\n\n"
        for report in all_crash_reports:
            status = "CRASHED" if report["crashed"] else "DID NOT CRASH"
            crash_summary += (
                f"## {report['variant']} ({status}, exit={report['exit_code']})\n"
                f"```\n{report['output']}\n```\n\n"
            )

        task = f"""\
Analyse and fix this vulnerability.

## Bug Description
{instance.get('bug_report', 'N/A')}

## Crash Reports
{crash_summary}

{property_section}

{experience_prompt}

Read the relevant source files, identify the root cause, and edit the \
code to fix the vulnerability. The source code is in {repo_root}/.
"""
    else:
        # --- Subsequent rounds or rounds with history ---
        new_crash_summary = ""
        for report in new_crash_reports:
            status = "CRASHED" if report["crashed"] else "DID NOT CRASH"
            new_crash_summary += (
                f"## {report['variant']} ({status}, exit={report['exit_code']})\n"
                f"```\n{report['output']}\n```\n\n"
            )

        # On round 0 with history (shouldn't normally happen), include full context
        if round_num == 0:
            crash_summary = f"## Original PoC crash\n```\n{_truncate(orig_output)}\n```\n\n"
            for report in all_crash_reports:
                status = "CRASHED" if report["crashed"] else "DID NOT CRASH"
                crash_summary += (
                    f"## {report['variant']} ({status}, exit={report['exit_code']})\n"
                    f"```\n{report['output']}\n```\n\n"
                )
            task = f"""\
Analyse and fix this vulnerability.

## Bug Description
{instance.get('bug_report', 'N/A')}

## Crash Reports
{crash_summary}

{history_section}

{property_section}

{experience_prompt}

Read the relevant source files, identify the root cause, and edit the \
code to fix the vulnerability. The source code is in {repo_root}/.
"""
        else:
            task = f"""\
Previous patches were insufficient. The source has been reset to the \
original state. You need to produce a NEW, more comprehensive fix.

## Bug Description
{instance.get('bug_report', 'N/A')}

## Original PoC crash
```
{_truncate(orig_output)}
```

## New Variant Crash Reports
{new_crash_summary if new_crash_summary else "No new variants this round."}

{history_section}

{property_section}

{experience_prompt}

Analyse why previous patches were insufficient and produce a better fix. \
Read the source files before editing. The source code is in {repo_root}/.
"""

    return task


#: Attributes file selecting git's built-in ``cpp`` hunk-header driver for C/C++.
#: git's default heuristic treats any column-0 identifier as a function start,
#: so a ``goto`` label such as ``fail:`` would cut ``--function-context`` short.
_DIFF_ATTRIBUTES_PATH = "/tmp/.arvo_diff_attributes"
_DIFF_ATTRIBUTES = "*.c diff=cpp\\n*.h diff=cpp\\n*.cc diff=cpp\\n*.cpp diff=cpp\\n*.cxx diff=cpp\\n*.hpp diff=cpp\\n*.hxx diff=cpp\\n*.inc diff=cpp\\n"


def _git_diff(
    container_id: str, repo_root: str, function_context: bool = False,
) -> str:
    """Return the patch's ``git diff``: San2Patch's zero-context diff (see
    ``arvo.tools.source_diff``), which every validation mode and the final
    re-application use.

    Uses ``NO_COLOR=1`` and ``--no-color`` to guarantee the output has no
    ANSI escape codes, which would corrupt the diff when re-applied.

    With *function_context* (``git diff -W``) each hunk is widened to the
    whole enclosing function.  That output is for human/offline review only.
    """
    if function_context:
        exit_code, stdout, _stderr = exec_cmd(
            container_id,
            f"printf '{_DIFF_ATTRIBUTES}' > {_DIFF_ATTRIBUTES_PATH} && "
            f"cd {repo_root} && NO_COLOR=1 git "
            f"-c core.attributesFile={_DIFF_ATTRIBUTES_PATH} "
            "--no-pager diff --no-color --function-context",
        )
        if exit_code != 0 or not stdout:
            return ""
        return stdout if stdout.endswith("\n") else (stdout + "\n")

    return arvo_tools.source_diff(container_id, repo_root)


#: ``_validate_without_build`` status for a patch whose PoC passed under metapro.
#: It is not a verdict: the caller goes on to build the patch and run the variant
#: gate on that build, as San2Patch builds before its functionality test.
METAPRO_POC_PASSED = "metapro_poc_passed"
#: The same for a patch whose PoC passed under Dyninst.
DYNINST_POC_PASSED = "dyninst_poc_passed"


def _validate_with_dyninst(
    project: str,
    local_id: int | str,
    fuzz_target: str,
    diff: str,
    attempt_key: str,
    patcher_name: str,
    timer: StageTimer | None,
    round_num: int,
    attempt: int,
    container_id: str,
    fall_through: bool = False,
    after_metapro: dict | None = None,
) -> tuple[str, bool, str, dict] | None:
    """The dyninst branch of :func:`_validate_without_build`, with the same contract.

    The bug's one-time base build is timed apart (``verify.dyninst_setup``) so it does
    not land in the first attempt's Test time.  The PIC archive a run rebuilds on its first
    Dyninst call is not: it is part of that call's ``verify.dyninst``, as San2Patch counts
    it in its dyninst_patch() time (see arvo.dyninst).

    *fall_through* (combined mode) returns None instead of a failure status when Dyninst
    reached no verdict on the patch, so the caller moves on to conv. *after_metapro* is
    the metapro report that sent the patch here, kept in the report for the record.
    """
    try:
        with track(
            timer, "verify.dyninst_setup", kind="detail", round_num=round_num,
            attempt=attempt, agent=patcher_name, container=container_id[:12],
        ):
            dyninst_validator.prepare(project, local_id, fuzz_target)
        with track(
            timer, "verify.dyninst", kind="detail", round_num=round_num,
            attempt=attempt, agent=patcher_name, container=container_id[:12],
        ):
            report = dyninst_validator.validate(
                project, local_id, fuzz_target, diff, attempt_key,
            )
    except dyninst_validator.DyninstUnavailable as e:
        logger.error("%s: %s", patcher_name, e)
        return "dyninst_unavailable", False, "", {"ok": False, "stage": "unavailable",
                                                  "error": str(e)}
    if after_metapro is not None:
        report["after_metapro"] = {k: after_metapro.get(k) for k in ("stage", "error", "out_dir")}

    if report.get("ok"):
        logger.info(
            "%s patch passed the PoC under dyninst (%d patched functions); building it "
            "for the variant gate",
            patcher_name, report.get("config_size", 0),
        )
        return DYNINST_POC_PASSED, False, "", report

    if report.get("stage") == "test":
        # libpatch.so was built and the PoC did not pass: a wrong patch.  As in San2Patch's
        # dyninst_binary_patch(), that includes a run Dyninst itself could not finish
        # (report["mechanism_failure"]); only a libpatch.so that could not be built is no
        # verdict.
        log_path = os.path.join(report.get("out_dir", ""), "poc-test.log")
        output = ""
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                output = f.read()
        except OSError:
            pass
        feedback = (
            "Patch applies but verification failed: the PoC still triggers the "
            f"vulnerability.\nRepro output:\n{_truncate(output, 1500)}"
        )
        logger.warning(
            "%s patch did not pass the PoC; defer improvement to next adversarial round",
            patcher_name,
        )
        return "dyninst_poc_failed", False, feedback, report

    # locate / patch (or the validator itself failing): Dyninst reached no verdict on the
    # patch.  As with metapro, the model is not told: it would learn to
    # write Dyninst-shaped patches.
    logger.warning(
        "%s: dyninst could not apply the patch (%s: %s)",
        patcher_name, report.get("stage"), report.get("error", "")[:200],
    )
    if fall_through:
        return None
    return f"dyninst_{report.get('stage', 'failed')}_failed", False, "", report


def _validate_without_build(
    mode: str,
    project: str,
    local_id: int | str,
    fuzz_target: str,
    diff: str,
    attempt_key: str,
    patcher_name: str,
    timer: StageTimer | None,
    round_num: int,
    attempt: int,
    container_id: str,
) -> tuple[str, bool, str, dict] | None:
    """Validate a diff against the PoC without building it: the metapro and dyninst modes.

    Returns ``(status, verified, feedback, report)``, or None in ``combined``
    when neither metapro nor dyninst could apply the patch and the caller should
    fall back to conv.  A PoC that passes comes back as :data:`METAPRO_POC_PASSED` (or
    :data:`DYNINST_POC_PASSED`), never as verified: only the PoC is checked here.
    The feedback follows San2Patch, which tells the model only that the PoC
    still crashes and retries silently on everything else: a model that learned
    to write metapro-shaped patches would no longer be generating the same
    patches as in the other modes.
    """
    if mode == "dyninst":
        return _validate_with_dyninst(
            project, local_id, fuzz_target, diff, attempt_key, patcher_name,
            timer, round_num, attempt, container_id,
        )

    try:
        with track(
            timer, "verify.metapro", kind="detail", round_num=round_num,
            attempt=attempt, agent=patcher_name, container=container_id[:12],
        ):
            report = metapro_validator.validate(
                project, local_id, fuzz_target, diff, attempt_key,
            )
    except metapro_validator.MetaproUnavailable as e:
        # A bug without an instrumented build cannot be validated this way at all;
        # say so rather than reporting every patch for it as wrong.
        logger.error("%s: %s", patcher_name, e)
        return "metapro_unavailable", False, "", {"ok": False, "stage": "unavailable",
                                                  "error": str(e)}

    if report.get("ok"):
        logger.info(
            "%s patch passed the PoC under metapro (%d patch sites); building it "
            "for the variant gate",
            patcher_name, report.get("config_size", 0),
        )
        return METAPRO_POC_PASSED, False, "", report

    if report.get("stage") == "test":
        # The patch was applied and the PoC still crashes: a wrong patch, the same
        # verdict conv's repro gate reaches, so the model is told.  (A run the metapro
        # runtime itself could not finish comes back as stage "runtime", not here; its
        # lines are scrubbed anyway, so the model never sees the interpreter.)
        log_path = os.path.join(report.get("out_dir", ""), "poc-test.log")
        output = ""
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                output = arvo_tools.scrub_metapro_runtime(f.read())
        except OSError:
            pass
        feedback = (
            "Patch applies but verification failed: the PoC still triggers the "
            f"vulnerability.\nRepro output:\n{_truncate(output, 1500)}"
        )
        logger.warning(
            "%s patch did not pass the PoC; defer improvement to next adversarial round",
            patcher_name,
        )
        return "metapro_poc_failed", False, feedback, report

    # config / binary-patch stage: the patch could not be expressed or applied.
    logger.warning(
        "%s: metapro could not apply the patch (%s: %s)",
        patcher_name, report.get("stage"), report.get("error", "")[:200],
    )
    if mode == "combined":
        # Next rewriter: Dyninst, and conv (None) when it cannot apply the patch either.
        logger.info("%s: combined mode, trying dyninst", patcher_name)
        return _validate_with_dyninst(
            project, local_id, fuzz_target, diff, attempt_key, patcher_name,
            timer, round_num, attempt, container_id,
            fall_through=True, after_metapro=report,
        )
    return f"metapro_{report.get('stage', 'failed')}_failed", False, "", report


async def _patch_single(
    patcher: AssistantAgent,
    container_id: str,
    repo_root: str,
    project: str,
    task: str,
    orig_vuln_type: str = "unknown",
    model_client: OpenAIChatCompletionClient | None = None,
    traj_path: str = "",
    patcher_key: str = "",
    timer: StageTimer | None = None,
    round_num: int = 0,
    patch_dir: str = "",
    patch_log: list[dict] | None = None,
    repro_cmd: ReproCommand | None = None,
    variant_reports: list[dict] | None = None,
    local_id: int | str = "",
    fuzz_target: str = "",
) -> dict:
    """Run a single Patcher agent and verify it under ``PATCH_MODE``.

    The Patcher edits files via tools bound to *container_id*.  Once it
    finishes, its ``git diff`` is collected (for recording only, never
    re-applied) and the patch is validated the way ``PATCH_MODE`` says:

      conv      build in place (``arvo compile``, i.e. San2Patch's build.py),
                run ``arvo`` against the PoC, then the variant gate.  The build
                is mandatory: ``arvo`` runs ``/out/<fuzz_target>`` without
                rebuilding, so skipping it would judge the pre-patch binary.
      metapro   hand the diff to ``arvo.metapro``, which runs the PoC against
                the binary-patched instrumented build in place of conv's build
                and repro.  A patch that passes is then built in place and the
                variant gate runs on that build, as San2Patch builds a
                metapro-verified patch for its functionality test.
      dyninst   hand the diff to ``arvo.dyninst``, which swaps the patched
                functions into the running target and runs the PoC, in place
                of conv's build and repro; a patch that passes is then built
                for the variant gate, as under metapro.
      combined  metapro, then dyninst when metapro could not apply the patch,
                then conv when dyninst could not either (a PoC that still
                crashes under either rewriter is a wrong patch, not a rewriter
                that could not express it, and ends the attempt).

    Verifying conv in the SAME container where the edits were made avoids the
    error-prone step of re-applying diffs to a different container.

    Every attempt's diff (including in-round retries) is written to
    *patch_dir* and appended to *patch_log*.

    Returns a dict with keys: ``diff``, ``verified``, ``feedback``,
    ``variant_result`` (empty when the variant gate did not run), and for a
    verified patch ``attempt``, its ``patch_log`` entry.
    """
    def _record(
        attempt_idx: int, diff: str, status: str,
        feedback: str = "", func_diff: str = "",
        variant_result: dict | None = None,
        metapro_result: dict | None = None,
    ) -> dict | None:
        return _persist_patch_attempt(
            patch_dir, patch_log, patcher_key, round_num,
            attempt_idx + 1, diff, status, feedback, func_diff, variant_result,
            metapro_result,
        )

    for attempt in range(1 + MAX_PATCHER_RETRIES):
        # Ensure clean git state before edits
        reset_source(container_id, project_root=repo_root)

        with track(
            timer, "patch.agent", kind="detail", round_num=round_num,
            attempt=attempt + 1, agent=patcher.name,
            container=container_id[:12],
        ):
            result = await _run_with_retry(patcher, task)

        # Save trajectory
        if traj_path and patcher_key and result.messages:
            suffix = f"_retry{attempt}" if attempt > 0 else ""
            append_agent_trajectory(
                traj_path, f"{patcher_key}{suffix}", result.messages,
            )

        # Diagnostic: log what the Patcher actually did
        if result.messages:
            tool_calls = 0
            edit_calls = 0
            for msg in result.messages:
                content = _content_to_str(getattr(msg, "content", ""))
                if isinstance(msg, ToolCallRequestEvent):
                    tool_calls += len(msg.content)
                if "str_replace_edit" in content or "Successfully edited" in content:
                    edit_calls += 1
            last_text = ""
            for msg in reversed(result.messages):
                text = _content_to_str(getattr(msg, "content", ""))
                if text and len(text) > 20:
                    last_text = text[:500]
                    break
            logger.info(
                "%s diagnostics: %d messages, ~%d tool calls, ~%d edit-related, "
                "last msg: %.300s",
                patcher.name, len(result.messages), tool_calls, edit_calls,
                last_text.replace("\n", " | "),
            )

        # --- Gate 1: non-empty diff ---
        _gs_exit, _gs_out, _ = exec_cmd(
            container_id, f"cd {repo_root} && git status --short"
        )
        if _gs_exit == 0:
            logger.info(
                "%s git status after editing: %s",
                patcher.name,
                _gs_out.strip()[:300] if _gs_out.strip() else "(clean)",
            )

        patch_diff = _git_diff(container_id, repo_root)
        # Taken now, before the build can touch the tree; saved to disk only.
        func_diff = (
            _git_diff(container_id, repo_root, function_context=True)
            if patch_diff and patch_dir else ""
        )

        if not patch_diff:
            _record(attempt, "", "empty", "No changes made")
            if attempt < MAX_PATCHER_RETRIES and model_client is not None:
                logger.warning(
                    "%s produced no git diff, retrying within round (attempt %d/%d)",
                    patcher.name, attempt + 1, 1 + MAX_PATCHER_RETRIES,
                )
                patcher = create_patcher(
                    model_client, container_id, project=project,
                    name=patcher.name,
                )
                task = (
                    "Your previous attempt produced NO source code changes. "
                    "You MUST use the str_replace_edit tool to edit files — "
                    "do NOT just describe changes verbally.\n\n" + task
                )
                continue
            else:
                logger.warning("%s produced no git diff (final)", patcher.name)
                return {"diff": "", "verified": False, "feedback": "No changes made"}

        # --- metapro / dyninst: check the PoC on the patched binary, no build ---
        # Set when metapro passed the PoC: that stands in for Gate 3, and the
        # build below serves the variant gate only.
        metapro_report: dict | None = None
        if PATCH_MODE in ("metapro", "combined", "dyninst"):
            outcome = _validate_without_build(
                mode=PATCH_MODE, project=project, local_id=local_id,
                fuzz_target=fuzz_target, diff=patch_diff,
                attempt_key=f"{patcher_key or 'patcher'}_attempt{attempt + 1}",
                patcher_name=patcher.name, timer=timer, round_num=round_num,
                attempt=attempt + 1, container_id=container_id,
            )
            if outcome is not None and outcome[0] in (METAPRO_POC_PASSED, DYNINST_POC_PASSED):
                metapro_report = outcome[3]
            elif outcome is not None:
                status, verified, feedback, report = outcome
                entry = _record(attempt, patch_diff, status, feedback, func_diff,
                                metapro_result=report)
                result = {
                    "diff": patch_diff, "verified": verified, "feedback": feedback,
                    "metapro_result": report,
                    "variant_result": {},
                }
                if verified:
                    result["attempt"] = entry
                return result
            # Otherwise metapro or dyninst passed the PoC, or (combined) neither could
            # apply this patch and conv takes over; either way the patch is built next.

        # --- Gate 2: build in-place ---
        with track(
            timer, "verify.build", kind="detail", round_num=round_num,
            attempt=attempt + 1, agent=patcher.name,
            container=container_id[:12],
        ):
            build_ok, build_msg = build_project(container_id)
        if not build_ok:
            _record(
                attempt, patch_diff, "build_failed",
                f"Build failed:\n{_truncate(build_msg)}", func_diff,
                metapro_result=metapro_report,
            )
            if attempt < MAX_PATCHER_RETRIES and model_client is not None:
                logger.warning(
                    "%s diff failed to build, retrying within round (attempt %d/%d)",
                    patcher.name, attempt + 1, 1 + MAX_PATCHER_RETRIES,
                )
                patcher = create_patcher(
                    model_client, container_id, project=project,
                    name=patcher.name,
                )
                task = (
                    "Your previous patch FAILED to compile. Build errors:\n"
                    f"```\n{_truncate(build_msg, 2000)}\n```\n"
                    "Fix the compilation errors and produce a corrected patch.\n\n"
                    + task
                )
                continue
            else:
                logger.warning("%s build failed, retries exhausted", patcher.name)
                return {
                    "diff": patch_diff,
                    "verified": False,
                    "feedback": f"Build failed:\n{_truncate(build_msg)}",
                    "metapro_result": metapro_report or {},
                }

        # --- Gate 3: in-place repro verification (like MemRepair) ---
        if metapro_report is not None:
            # metapro (or dyninst) already ran the PoC against this patch; San2Patch
            # likewise skips its vulnerability test once metapro has passed it.
            repro_exit, repro_out = 0, ""
            sanitizer_error = False
        else:
            with track(
                timer, "verify.repro", kind="detail", round_num=round_num,
                attempt=attempt + 1, agent=patcher.name,
                container=container_id[:12],
            ):
                repro_exit, repro_out = run_repro(container_id)
            sanitizer_error = _matches_vuln_type(repro_out, orig_vuln_type)
        # ARVO's oracle is simply "exit 0".  Verified on asan and ubsan bugs:
        # a vulnerable build exits 1 with a sanitizer report, a developer-fixed
        # build exits 0 with none.  There is no per-instance accepted non-zero
        # exit code as there was in SEC-bench.
        exit_ok = repro_exit == 0

        if exit_ok and not sanitizer_error:
            # --- Gate 4: the Mutator's variants against the same build ---
            variant_result: dict = {}
            if variant_reports and repro_cmd is not None:
                with track(
                    timer, "verify.variants", kind="detail", round_num=round_num,
                    attempt=attempt + 1, agent=patcher.name,
                    container=container_id[:12],
                ):
                    variant_result = _test_variants_against_patch(
                        container_id, repro_cmd, variant_reports, orig_vuln_type,
                    )
                if variant_result["still_crashed"]:
                    feedback = _build_property_feedback(
                        "", variant_result, variant_reports,
                    )
                    _record(
                        attempt, patch_diff, "variant_failed", feedback, func_diff,
                        variant_result=variant_result,
                        metapro_result=metapro_report,
                    )
                    logger.warning(
                        "%s patch passed the original PoC but %d/%d variants still "
                        "crash; defer improvement to next adversarial round",
                        patcher.name, variant_result["still_crashed"],
                        variant_result["total"],
                    )
                    return {
                        "diff": patch_diff, "verified": False, "feedback": feedback,
                        "variant_result": variant_result,
                        "metapro_result": metapro_report or {},
                    }

            logger.info(
                "%s patch VERIFIED %s%s",
                patcher.name,
                f"(PoC by {metapro_report.get('method', 'metapro')}, then built)"
                if metapro_report is not None
                else f"in-place (exit={repro_exit}, no sanitizer error)",
                f", {variant_result['total']} variants clean" if variant_result else "",
            )
            entry = _record(
                attempt, patch_diff, "verified", func_diff=func_diff,
                variant_result=variant_result,
                metapro_result=metapro_report,
            )
            return {
                "diff": patch_diff, "verified": True, "feedback": "",
                "attempt": entry, "variant_result": variant_result,
                "metapro_result": metapro_report or {},
            }
        else:
            reasons: list[str] = []
            if sanitizer_error:
                reasons.append("same-type sanitizer still triggers")
            if not exit_ok:
                reasons.append(f"exit_code={repro_exit}, expected 0")
            reason_text = "; ".join(reasons) if reasons else "verification gate not satisfied"
            feedback = (
                f"Patch builds but verification failed: {reason_text}.\n"
                f"Repro output:\n{_truncate(repro_out, 1500)}"
            )
            _record(attempt, patch_diff, "repro_failed", feedback, func_diff)
            logger.warning(
                "%s patch did not pass verification; defer improvement to next adversarial round",
                patcher.name,
            )
            return {"diff": patch_diff, "verified": False, "feedback": feedback}

    return {"diff": "", "verified": False, "feedback": "All retries exhausted"}


async def _patch_parallel(
    model_client: OpenAIChatCompletionClient,
    main_container_id: str,
    image: str,
    repo_root: str,
    project: str,
    task: str,
    orig_vuln_type: str = "unknown",
    count: int = PATCHES_PER_ROUND,
    traj_path: str = "",
    round_num: int = 0,
    timer: StageTimer | None = None,
    patch_dir: str = "",
    patch_log: list[dict] | None = None,
    repro_cmd: ReproCommand | None = None,
    variant_reports: list[dict] | None = None,
    local_id: int | str = "",
    fuzz_target: str = "",
) -> list[dict]:
    """Launch *count* Patcher agents in parallel containers.

    Each Patcher runs in its own container with in-place verification
    (build + repro, like MemRepair, then the variant gate when
    *variant_reports* is given).  Returns a list of result dicts with keys:
    ``diff``, ``verified``, ``feedback``.  Diffs are deduplicated.
    """
    logger.info("Starting %d parallel Patcher containers", count)
    with track(timer, "patch.container_setup", kind="detail", round_num=round_num):
        container_ids = start_patcher_containers(image, count)
    if variant_reports:
        # The variant gate runs on each Patcher's own build in every mode. The
        # variants live in the main container, where the Mutator made them;
        # Patcher containers start from the image with /tmp/poc only.
        with track(timer, "patch.copy_variants", kind="detail", round_num=round_num):
            _copy_variants(main_container_id, container_ids, variant_reports)

    # Create a high-temperature model client for diverse sampling
    hot_client = create_model_client(temperature=PATCHER_TEMPERATURE)

    try:
        patchers = [
            create_patcher(hot_client, cid, project=project, name=f"Patcher_{i}")
            for i, cid in enumerate(container_ids)
        ]

        tasks = [
            _patch_single(
                p, cid, repo_root, project, task,
                orig_vuln_type=orig_vuln_type,
                model_client=hot_client,
                traj_path=traj_path,
                patcher_key=f"patcher_r{round_num}_{i}",
                timer=timer,
                round_num=round_num,
                patch_dir=patch_dir,
                patch_log=patch_log,
                repro_cmd=repro_cmd,
                variant_reports=variant_reports,
                local_id=local_id,
                fuzz_target=fuzz_target,
            )
            for i, (p, cid) in enumerate(zip(patchers, container_ids))
        ]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect and deduplicate
        seen: set[str] = set()
        patch_results: list[dict] = []
        for i, r in enumerate(raw_results):
            if isinstance(r, Exception):
                logger.warning("Patcher_%d failed with exception: %s", i, r)
                continue
            if not isinstance(r, dict) or not r.get("diff"):
                continue
            normalized = r["diff"].strip()
            if normalized not in seen:
                seen.add(normalized)
                patch_results.append(r)

        num_verified = sum(1 for r in patch_results if r.get("verified"))
        logger.info(
            "Parallel patching: %d diffs collected (%d verified) from %d patchers",
            len(patch_results), num_verified, count,
        )
        return patch_results

    finally:
        with track(timer, "patch.container_stop", kind="detail", round_num=round_num):
            stop_containers(container_ids)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _copy_variants(
    src_container_id: str, dst_container_ids: list[str], reports: list[dict],
) -> None:
    """Copy each report's variant file to the same path in every destination container.

    A variant that cannot be copied is logged and left out; the variant gate
    then reports it as untested rather than failing the patch over it.
    """
    with tempfile.TemporaryDirectory(prefix="contrafix-variants-") as tmp:
        for report in reports:
            path = report.get("path", "")
            if not path:
                continue
            host_path = os.path.join(tmp, os.path.basename(path))
            ok, msg = copy_from_container(src_container_id, path, host_path)
            if not ok:
                logger.warning("Cannot copy variant %s out of %s: %s",
                               path, src_container_id[:12], msg)
                continue
            for cid in dst_container_ids:
                ok, msg = copy_to_container(cid, host_path, path)
                if not ok:
                    logger.warning("Cannot copy variant %s into %s: %s",
                                   path, cid[:12], msg)


def _test_variants_against_patch(
    container_id: str,
    repro_cmd: ReproCommand,
    all_crash_reports: list[dict],
    orig_vuln_type: str = "unknown",
) -> dict:
    """After a patch passes the original PoC, test all previous variants.

    Uses ``_matches_vuln_type`` to check whether variants still trigger
    the SAME vulnerability type after patching (consistent with how
    variants are classified during collection).

    Returns {'total': N, 'still_crashed': M, 'details': [...]}.
    """
    details = []
    still_crashed = 0

    for report in all_crash_reports:
        vpath = report.get("path", "")
        if not vpath:
            continue

        try:
            check_code, _, _ = exec_cmd(
                container_id, f"test -f {vpath} && echo ok"
            )
            if check_code != 0:
                logger.warning(
                    "Variant %s missing from %s; not tested",
                    report["variant"], container_id[:12],
                )
                continue
            if repro_cmd.poc_type == "script":
                cmd = f"bash {vpath}"
            else:
                cmd = repro_cmd.build_cmd(vpath)
            exit_code, output = run_custom_repro(container_id, cmd)
            crashed = _matches_vuln_type(output, orig_vuln_type)
            if crashed:
                still_crashed += 1
            details.append({
                "variant": report["variant"],
                "crashed_after_patch": crashed,
                "exit_code": exit_code,
            })
        except Exception as e:
            logger.warning("Failed to test variant %s after patch: %s", report["variant"], e)

    return {
        "total": len(details),
        "still_crashed": still_crashed,
        "details": details,
    }


# ---------------------------------------------------------------------------
# Selector
# ---------------------------------------------------------------------------


async def _select_best_patch(
    model_client: OpenAIChatCompletionClient,
    candidates: list[dict],
    traj_path: str = "",
) -> dict:
    """Use the Selector agent to pick the best patch from candidates."""
    if len(candidates) == 1:
        return candidates[0]

    candidates_text = ""
    for i, c in enumerate(candidates):
        candidates_text += f"""\
### Candidate {i + 1} (from round {c['round']})

**Patch:**
```diff
{_truncate(c['patch'], 1500)}
```

---
"""

    task = f"""\
Select the best patch from the following {len(candidates)} candidates.

{candidates_text}

Which candidate is the most robust and correct fix?
"""

    selector = create_selector(model_client)
    result = await _run_with_retry(selector, task)

    # Save trajectory
    if traj_path and result.messages:
        append_agent_trajectory(traj_path, "selector", result.messages)

    response = _content_to_str(
        result.messages[-1].content if result.messages else ""
    )

    idx = _extract_selected_index(response)
    if idx is not None and 1 <= idx <= len(candidates):
        selected = candidates[idx - 1]
        selected["selector_reason"] = response
        return selected

    # Fallback: pick the first candidate (all equally verified)
    best = candidates[0]
    best["selector_reason"] = "Fallback: selected first candidate."
    return best


# ---------------------------------------------------------------------------
# Main pipeline entry point
# ---------------------------------------------------------------------------


async def solve_instance(
    instance: dict,
    model_client: OpenAIChatCompletionClient,
    results_dir: str = "results",
) -> dict:
    """Run the adversarial pipeline for one ARVO instance.

    Args:
        instance: An instance dict from ``arvo.dataset.load_instances``.
        model_client: The shared LLM client.
        results_dir: Directory for result and trajectory files.

    Returns:
        A result dict with status, patch, metadata, etc.
    """
    instance_id = instance["instance_id"]
    logger.info("=" * 60)
    logger.info("Solving instance: %s", instance_id)
    logger.info("=" * 60)

    # Wall-clock timing for every pipeline stage; attached to the result
    # dict on every return path, including the error ones.  Installing it as
    # the current timer lets arvo.tools record the builds and PoC runs that
    # agents trigger themselves (check_vul, run_probed, run_variant).
    timer = StageTimer()
    set_current(timer)

    # Initialize trajectory file
    traj_path = os.path.join(results_dir, f"{instance_id}.traj.json")
    init_trajectory(traj_path, instance_id)

    container_id = None
    project = instance["project_name"]
    patch_dir = os.path.join(
        results_dir, "patch_artifacts", _safe_instance_id(instance_id)
    )
    try:
        # === Stage 0: Environment Setup ===
        # The prepared image is San2Patch's environment with the bug already
        # built and the upstream history (which holds the developer's fix)
        # stripped.  main.py prepares it before the instance clock starts, so
        # this normally just finds it.
        with track(timer, "setup.prepare_image"):
            image = prepare_image(
                project, instance["local_id"], instance["fuzz_target"],
                log_path=prepare_log_path(results_dir, instance_id),
            )
        logger.info("Starting container from image: %s", image)
        with track(timer, "setup.container"):
            container_id = start_container(image)

        # Build the project
        with track(timer, "setup.build"):
            build_ok, build_msg = build_project(container_id)
        if not build_ok:
            logger.error("Initial build failed for %s", instance_id)
            return {
                "instance_id": instance_id,
                "status": "build_failed",
                "error": _truncate(build_msg, 500),
                "token_usage": summarize_token_usage(traj_path),
                "timing": timer.summary(),
            }

        # ARVO's CSV carries no crash report or exit code, so they are
        # produced here by running the PoC once.  This doubles as the sanity
        # check that the bug reproduces before any agent is started.
        with track(timer, "setup.bootstrap"):
            reproduced, boot_msg = bootstrap_instance(instance, container_id)
        orig_exit_code = instance["exit_code"]
        orig_output = instance["sanitizer_report"]
        if not reproduced:
            logger.error("Bootstrap failed: %s", boot_msg)
            return {
                "instance_id": instance_id,
                "status": "no_repro",
                "error": _truncate(boot_msg, 1000),
                "token_usage": summarize_token_usage(traj_path),
                "timing": timer.summary(),
            }
        logger.info("Bootstrap: %s", boot_msg)

        # Parse repro command and get repo root
        repro_cmd = parse_repro_command(
            instance.get("secb_sh", ""), instance.get("fuzz_target", ""),
        )
        repo_root = _get_repo_root(container_id, project)
        logger.info("Repo root: %s", repo_root)

        # Read original PoC content.  ARVO's PoC has no file extension, so
        # classify it by content rather than by name.
        try:
            poc_bytes = read_file_bytes(container_id, repro_cmd.poc_path)
            repro_cmd.poc_type = sniff_poc_type(poc_bytes)
            orig_poc = (
                poc_bytes.decode("utf-8", errors="replace")
                if repro_cmd.poc_type == "text"
                else f"<binary PoC, {len(poc_bytes)} bytes>"
            )
            logger.info(
                "PoC: %d bytes, classified as %s",
                len(poc_bytes), repro_cmd.poc_type,
            )
        except Exception as e:
            logger.warning("Could not read PoC %s: %s", repro_cmd.poc_path, e)
            orig_poc = "<PoC unavailable>"

        # Determine the canonical vulnerability type from the original crash
        orig_vuln_type = extract_vuln_type(orig_output)
        logger.info("Original vulnerability type: %s", orig_vuln_type)

        # === Stage 1: Adversarial Loop ===
        candidates = []
        all_crash_reports: list[dict] = []
        all_patches_feedback: list[dict] = []  # cross-round failed patch history
        mutation_attempt_records: list[dict] = []
        # Every diff any Patcher produced, verified or not (see _persist_patch_attempt)
        all_generated_patches: list[dict] = []
        prev_property_report = ""
        experience_prompt = ""

        # Analyzer retains conversation history across rounds (cross-round memory).
        # Patchers are created fresh each round inside _patch_parallel.
        # E2 ablation: no variants, Analyzer uses single-crash prompt.
        analyzer_repro_cmd = (
            repro_cmd.cmd_template
            or f"{repro_cmd.binary} {repro_cmd.args} {{poc}}"
        )
        analyzer_agent = create_analyzer(
            model_client,
            container_id,
            project=project,
            single_crash=ABLATION_SKIP_MUTATOR,
            repro_cmd=analyzer_repro_cmd,
            ext=_get_extension(repro_cmd.poc_path),
            poc_path=repro_cmd.poc_path,
        )

        # Only force single round when BOTH Mutator and Analyzer are skipped (E1).
        # E2 (no Mutator but has Analyzer) still benefits from multi-round:
        # Analyzer can refine its analysis based on patch failure feedback.
        effective_rounds = (
            1 if (ABLATION_SKIP_MUTATOR and ABLATION_SKIP_ANALYZER)
            else MAX_ADVERSARIAL_ROUNDS
        )

        for round_num in range(effective_rounds):
            logger.info("=== Adversarial Round %d/%d ===", round_num + 1, effective_rounds)

            # --- Step 1: Mutate (with crash-validation gate) ---
            prev_patch = all_patches_feedback[-1]["patch"] if all_patches_feedback else ""
            prev_feedback = all_patches_feedback[-1]["feedback"] if all_patches_feedback else ""

            round_crash_reports = []
            if not ABLATION_SKIP_MUTATOR:
                # Retrieve mutation strategy guidance (static hints + past experiences)
                mutation_guidance = ""
                if round_num == 0:
                    vuln_type = extract_vuln_type(
                        instance.get("sanitizer_report", orig_output)
                    )
                    if not ABLATION_SKIP_MUTATION_EXP:
                        with track(
                            timer, "mutate.retrieve_experience", kind="detail",
                            round_num=round_num,
                        ):
                            mut_experiences = retrieve_mutation_experiences(
                                results_dir=results_dir,
                                current_instance_id=instance_id,
                                repo=instance.get("repo", ""),
                                sanitizer_report=instance.get("sanitizer_report", orig_output),
                                bug_description=instance.get("bug_description", ""),
                            )
                        mutation_guidance = format_mutation_prompt(vuln_type, mut_experiences)
                    else:
                        # Ablation: skip retrieved experiences but keep static hints
                        mutation_guidance = format_mutation_prompt(vuln_type, [])

                mutation_feedback = ""
                for mutation_attempt in range(1 + MAX_MUTATION_RETRIES):
                    # Clean up previous attempt's variant files before retrying
                    if mutation_attempt > 0:
                        exec_cmd(
                            container_id,
                            "for f in /tmp/variant_*; do "
                            '[ -e "$f" ] && rm -f "$f"; done',
                        )
                        logger.info(
                            "Mutation gate not satisfied, retrying (attempt %d/%d)",
                            mutation_attempt + 1, 1 + MAX_MUTATION_RETRIES,
                        )

                    with track(
                        timer, "mutate", round_num=round_num,
                        attempt=mutation_attempt + 1,
                    ):
                        round_crash_reports, mutation_trace = await _mutate(
                            model_client=model_client,
                            container_id=container_id,
                            repro_cmd=repro_cmd,
                            orig_poc=orig_poc,
                            orig_output=orig_output,
                            instance=instance,
                            round_num=round_num,
                            prev_patch=prev_patch,
                            prev_feedback=(prev_feedback + "\n" + mutation_feedback).strip(),
                            prev_crash_reports=all_crash_reports if round_num > 0 else None,
                            property_info=prev_property_report if round_num > 0 else "",
                            mutation_guidance=mutation_guidance,
                            orig_vuln_type=orig_vuln_type,
                            traj_path=traj_path,
                            timer=timer,
                        )
                    with track(
                        timer, "mutate.persist", kind="detail",
                        round_num=round_num, attempt=mutation_attempt + 1,
                    ):
                        artifact_info = _persist_mutation_attempt_artifacts(
                            container_id=container_id,
                            results_dir=results_dir,
                            instance_id=instance_id,
                            round_num=round_num,
                            attempt_num=mutation_attempt + 1,
                            crash_reports=round_crash_reports,
                            trace=mutation_trace,
                        )
                    mutation_attempt_records.append({
                        "round": round_num,
                        "attempt": mutation_attempt + 1,
                        "artifact_dir": artifact_info.get("artifact_dir", ""),
                        "metadata_path": artifact_info.get("metadata_path", ""),
                        "num_variants": artifact_info.get("num_variants", 0),
                        "num_crashed": artifact_info.get("num_crashed", 0),
                        "num_not_crashed": artifact_info.get("num_not_crashed", 0),
                        "mutation_trace": mutation_trace,
                    })

                    num_crashed = sum(1 for r in round_crash_reports if r["crashed"])
                    num_not_crashed = sum(1 for r in round_crash_reports if not r["crashed"])

                    if num_crashed > 0 and num_not_crashed > 0:
                        logger.info(
                            "Mutation gate passed: %d crashed, %d did not crash",
                            num_crashed, num_not_crashed,
                        )
                        break

                    if num_crashed == 0:
                        mutation_feedback = (
                            "IMPORTANT: None of your previous variants triggered the "
                            f"target vulnerability ({orig_vuln_type}). You MUST produce "
                            "at least 1 variant that crashes with the SAME sanitizer "
                            "error type as the original PoC. Re-examine the original "
                            "PoC and sanitizer output carefully."
                        )
                    elif num_not_crashed == 0:
                        mutation_feedback = (
                            "IMPORTANT: ALL of your variants crashed — you also need "
                            "at least 1 variant that does NOT crash. The differential "
                            "between crashing and non-crashing inputs is essential for "
                            "root cause analysis. Try creating a variant that is "
                            "slightly below the trigger threshold (e.g. smaller input, "
                            "valid boundary values, correct field lengths)."
                        )

            all_crash_reports.extend(round_crash_reports)

            # --- Step 2: Analyze (property discovery) ---
            property_report = ""
            if not ABLATION_SKIP_ANALYZER:
                with track(timer, "analyze", round_num=round_num):
                    property_report = await _analyze(
                        analyzer=analyzer_agent,
                        container_id=container_id,
                        repo_root=repo_root,
                        orig_output=orig_output,
                        all_crash_reports=all_crash_reports,
                        new_crash_reports=round_crash_reports,
                        instance=instance,
                        round_num=round_num,
                        repro_cmd_str=analyzer_repro_cmd,
                        prev_patch=prev_patch,
                        prev_feedback=prev_feedback,
                        traj_path=traj_path,
                        timer=timer,
                        probe_dir=os.path.join(
                            results_dir, "probe_artifacts", _safe_instance_id(instance_id)
                        ),
                    )

            # --- Step 3: Parallel Patch (beam search) ---
            # Retrieve similar past fixes from the experience knowledge base
            if round_num == 0 and not ABLATION_SKIP_PATCHER_EXP:
                with track(
                    timer, "patch.retrieve_experience", kind="detail",
                    round_num=round_num,
                ):
                    experiences = retrieve_experiences(
                        results_dir=results_dir,
                        current_instance_id=instance_id,
                        repo=instance.get("repo", ""),
                        sanitizer_report=instance.get("sanitizer_report", orig_output),
                        bug_description=instance.get("bug_description", ""),
                    )
                experience_prompt = format_experience_prompt(experiences)

            task_prompt = _build_patcher_task(
                repo_root=repo_root,
                orig_output=orig_output,
                all_crash_reports=all_crash_reports,
                new_crash_reports=round_crash_reports,
                instance=instance,
                round_num=round_num,
                property_report=property_report,
                all_patches_feedback=all_patches_feedback if all_patches_feedback else None,
                experience_prompt=experience_prompt,
            )

            # Wall-clock for the whole beam: the Patchers run concurrently,
            # so this is less than the sum of the per-Patcher details.
            with track(timer, "patch", round_num=round_num):
                patch_results = await _patch_parallel(
                    model_client=model_client,
                    main_container_id=container_id,
                    image=image,
                    repo_root=repo_root,
                    project=project,
                    task=task_prompt,
                    orig_vuln_type=orig_vuln_type,
                    count=PATCHES_PER_ROUND,
                    traj_path=traj_path,
                    round_num=round_num,
                    timer=timer,
                    patch_dir=patch_dir,
                    patch_log=all_generated_patches,
                    repro_cmd=repro_cmd,
                    variant_reports=list(all_crash_reports) if VARIANT_GATE else None,
                    local_id=instance["local_id"],
                    fuzz_target=instance["fuzz_target"],
                )
            _write_patch_index(patch_dir, all_generated_patches)

            if not patch_results:
                logger.warning("Round %d: no diffs produced by any Patcher", round_num + 1)
                all_patches_feedback.append({
                    "patch": "",
                    "feedback": (
                        "No Patcher produced any source code changes. "
                        "Make sure to use the str_replace_edit tool to edit source files."
                    ),
                    "round": round_num + 1,
                })
                prev_property_report = property_report
                continue

            # --- Step 4: Process in-place verification results ---
            # Verified patches go directly into candidates (no main-container
            # rebuild): the in-place build, PoC run and variant gate are the
            # verification.
            round_has_verified = False
            for pr in patch_results:
                if pr["verified"]:
                    candidates.append({
                        "patch": pr["diff"],
                        "attempt": pr.get("attempt"),
                        "round": round_num + 1,
                        "analysis": "",
                        "property_report": property_report,
                        "variant_test_result": pr.get("variant_result", {}),
                        "metapro_result": pr.get("metapro_result", {}),
                    })
                    round_has_verified = True
                    logger.info(
                        "Round %d: verified patch added to candidates",
                        round_num + 1,
                    )
                else:
                    # Failed in-place verification
                    all_patches_feedback.append({
                        "patch": pr.get("diff", ""),
                        "feedback": pr.get("feedback", ""),
                        "round": round_num + 1,
                    })

            if round_has_verified:
                logger.info("Round %d: verified candidate found -- stopping early", round_num + 1)
                break

            prev_property_report = property_report

        # === Stage 2: Selection ===
        if not candidates:
            last_fb = all_patches_feedback[-1] if all_patches_feedback else {}
            _san_report = instance.get("sanitizer_report", orig_output)
            _vuln_type = extract_vuln_type(_san_report)
            with track(timer, "save_experience"):
                save_mutation_experience(
                    results_dir=results_dir,
                    instance_id=instance_id,
                    repo=instance.get("repo", ""),
                    project_name=instance.get("project_name", ""),
                    vuln_type=_vuln_type,
                    crash_reports=all_crash_reports,
                    sanitizer_report=_san_report,
                    bug_description=instance.get("bug_description", ""),
                    mutation_strategy_summary=_build_mutation_strategy_summary(
                        all_crash_reports, mutation_attempt_records,
                    ),
                )
            return {
                "instance_id": instance_id,
                "status": "failed",
                "patch_mode": PATCH_MODE,
                "rounds": MAX_ADVERSARIAL_ROUNDS,
                "last_patch": last_fb.get("patch", ""),
                "last_feedback": last_fb.get("feedback", ""),
                "property_report": prev_property_report,
                "num_variants_total": len(all_crash_reports),
                "mutation_artifact_root": os.path.join(
                    results_dir, "mutation_artifacts", _safe_instance_id(instance_id)
                ),
                "patch_artifact_root": patch_dir,
                "all_patches": all_generated_patches,
                "token_usage": summarize_token_usage(traj_path),
                "timing": timer.summary(),
            }

        if len(candidates) == 1:
            selected = candidates[0]
        else:
            logger.info("Selecting best patch from %d candidates", len(candidates))
            with track(timer, "select", num_candidates=len(candidates)):
                selected = await _select_best_patch(
                    model_client, candidates, traj_path=traj_path,
                )

        _mark_selected(patch_dir, all_generated_patches, selected.get("attempt"))
        func_patch = _read_func_diff(selected.get("attempt"))

        # Re-apply the selected patch for final state
        with track(timer, "finalize"):
            reset_source(container_id, project_root=repo_root)
            apply_patch(container_id, selected["patch"], project_root=repo_root)
            if not func_patch:
                # No per-attempt copy (patch_dir unset, or the read failed):
                # take it from the re-applied tree, before the build touches it.
                func_patch = _git_diff(container_id, repo_root, function_context=True)
            build_project(container_id)

        # Save successful experience to knowledge base (patch + mutation)
        _san_report = instance.get("sanitizer_report", orig_output)
        _vuln_type = extract_vuln_type(_san_report)
        with track(timer, "save_experience"):
            save_experience(
                results_dir=results_dir,
                instance_id=instance_id,
                repo=instance.get("repo", ""),
                project_name=instance.get("project_name", ""),
                sanitizer_report=_san_report,
                bug_description=instance.get("bug_description", ""),
                patch=selected["patch"],
                property_report=selected.get("property_report", ""),
            )
            save_mutation_experience(
                results_dir=results_dir,
                instance_id=instance_id,
                repo=instance.get("repo", ""),
                project_name=instance.get("project_name", ""),
                vuln_type=_vuln_type,
                crash_reports=all_crash_reports,
                sanitizer_report=_san_report,
                bug_description=instance.get("bug_description", ""),
                mutation_strategy_summary=_build_mutation_strategy_summary(
                    all_crash_reports, mutation_attempt_records,
                ),
            )

        return {
            "instance_id": instance_id,
            "status": "success",
            "patch": selected["patch"],
            "func_patch": func_patch,
            "selected_round": selected["round"],
            "total_rounds": min(selected["round"], MAX_ADVERSARIAL_ROUNDS),
            "num_candidates": len(candidates),
            "patch_mode": PATCH_MODE,
            "variant_robustness": selected.get("variant_test_result", {}),
            "metapro_result": selected.get("metapro_result", {}),
            "selector_reason": selected.get("selector_reason", ""),
            "property_report": selected.get("property_report", ""),
            "num_variants_total": len(all_crash_reports),
            "mutation_artifact_root": os.path.join(
                results_dir, "mutation_artifacts", _safe_instance_id(instance_id)
            ),
            "patch_artifact_root": patch_dir,
            "all_patches": all_generated_patches,
            "token_usage": summarize_token_usage(traj_path),
            "timing": timer.summary(),
        }

    except Exception as e:
        logger.exception("Unexpected error solving %s", instance_id)
        # Try to salvage the last patch attempt if available
        _apf = locals().get("all_patches_feedback", [])
        _last_patch = ""
        if _apf:
            _last_patch = _apf[-1].get("patch", "")
        return {
            "instance_id": instance_id,
            "status": "error",
            "error": str(e),
            "last_patch": _last_patch,
            "patch_artifact_root": patch_dir,
            "all_patches": locals().get("all_generated_patches", []),
            "token_usage": summarize_token_usage(traj_path),
            "timing": timer.summary(),
        }
    finally:
        set_current(None)
        # Persist timings here too: on an instance timeout the coroutine is
        # cancelled and never returns a result dict, so this is the only
        # place the numbers can be saved.
        try:
            save_timing(traj_path, timer.summary())
        except Exception:  # never let bookkeeping mask the real failure
            logger.warning("Could not persist timing for %s", instance_id, exc_info=True)
        try:
            _write_patch_index(patch_dir, locals().get("all_generated_patches", []))
        except Exception:
            logger.warning("Could not persist patch index for %s", instance_id, exc_info=True)
        if container_id:
            stop_container(container_id)
