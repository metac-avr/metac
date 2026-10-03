"""Entry point for the ARVO multi-agent vulnerability solver.

Usage:
    # Run all instances that pass the ARVO filters
    python -m arvo.main

    # Run a specific instance
    python -m arvo.main --instance_id libxml2-42510333

    # Run one project, or specific bug ids
    python -m arvo.main --project libxml2 mruby
    python -m arvo.main --local_id 42510333 42517443

    # Run the 5-project mini benchmark
    python -m arvo.main --mini

    # Run a range of instances
    python -m arvo.main --start 0 --end 10
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone

from arvo.agents import create_model_client
from arvo.config import (
    ARVO_EXCLUDED_PROJECTS,
    INSTANCE_TIMEOUT,
    REMOVE_PREPARED_IMAGE,
    RESULTS_DIR,
)
from arvo.dataset import load_instances
from arvo.docker_tools import prepare_image, remove_prepared_image
from arvo.minibenchmark import ARVO_MINI
from arvo.pipeline import prepare_log_path, solve_instance
from arvo.trajectory import load_timing, summarize_token_usage

os.makedirs(RESULTS_DIR, exist_ok=True)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            os.path.join(RESULTS_DIR, "solver.log"), mode="a"
        ),
    ],
)
# Suppress autogen_core.events — it serialises full LLM conversation history
# (including system prompts and tool results) into single log lines, producing
# 100KB+ lines that bloat the log to ~50MB per instance and can OOM the process.
logging.getLogger("autogen_core.events").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


def _salvage_last_patch_from_traj(instance_id: str) -> str:
    """Try to extract the last patcher's diff from the trajectory file.

    When a run is interrupted (timeout/error), the traj file may still
    contain patcher messages with str_replace_edit calls.  We look for
    the last patcher agent that produced a non-empty git diff in its
    bash tool results.
    """
    safe_name = instance_id.replace("/", "_").replace("\\", "_")
    traj_path = os.path.join(RESULTS_DIR, f"{safe_name}.traj.json")
    try:
        with open(traj_path, "r", encoding="utf-8") as f:
            traj = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return ""

    # Iterate patcher agents in reverse order to find the last diff
    agents = traj.get("agents", {})
    patcher_keys = sorted(
        [k for k in agents if k.startswith("patcher_")],
        reverse=True,
    )
    for key in patcher_keys:
        msgs = agents[key]
        for msg in reversed(msgs):
            content = msg.get("content", "") or ""
            if "diff --git" in content and len(content) > 50:
                idx = content.index("diff --git")
                diff = content[idx:].strip()
                if diff:
                    logger.info("Salvaged patch from %s (%d chars)", key, len(diff))
                    return diff
    return ""


def save_result(result: dict) -> None:
    """Save a single instance result to a JSON file."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    instance_id = result.get("instance_id", "unknown")
    # Sanitize filename
    safe_name = instance_id.replace("/", "_").replace("\\", "_")
    path = os.path.join(RESULTS_DIR, f"{safe_name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    logger.info("Result saved to %s", path)

    # Also save the patch separately if successful, plus its function-context
    # form (`git diff -W`, each hunk widened to the enclosing function)
    if result.get("status") == "success" and result.get("patch"):
        patch_path = os.path.join(RESULTS_DIR, f"{safe_name}.diff")
        with open(patch_path, "w", encoding="utf-8") as f:
            f.write(result["patch"])
        logger.info("Patch saved to %s", patch_path)
        if result.get("func_patch"):
            func_patch_path = os.path.join(RESULTS_DIR, f"{safe_name}.func.diff")
            with open(func_patch_path, "w", encoding="utf-8") as f:
                f.write(result["func_patch"])
            logger.info("Function-context patch saved to %s", func_patch_path)


def print_summary(results: list[dict]) -> None:
    """Print a summary of all results."""
    total = len(results)
    success = sum(1 for r in results if r.get("status") == "success")
    failed = sum(1 for r in results if r.get("status") == "failed")
    errors = sum(1 for r in results if r.get("status") == "error")
    build_failed = sum(1 for r in results if r.get("status") == "build_failed")
    no_repro = sum(1 for r in results if r.get("status") == "no_repro")
    prepare_failed = sum(1 for r in results if r.get("status") == "prepare_failed")

    print("\n" + "=" * 60)
    print("ARVO Adversarial Solver Summary")
    print("=" * 60)
    print(f"Total instances:    {total}")
    if total:
        print(f"Successfully fixed: {success} ({100*success/total:.1f}%)")
    print(f"Patch failed:       {failed}")
    print(f"Build failed:       {build_failed}")
    print(f"No repro:           {no_repro}")
    print(f"Prepare failed:     {prepare_failed}")
    print(f"Errors:             {errors}")
    print("=" * 60)

    if success > 0:
        successful = [r for r in results if r.get("status") == "success"]
        avg_rounds = sum(r.get("selected_round", 1) for r in successful) / success
        avg_candidates = sum(r.get("num_candidates", 1) for r in successful) / success
        print(f"Avg selected round:  {avg_rounds:.1f}")
        print(f"Avg candidates:      {avg_candidates:.1f}")

    # Print details for failed/error instances
    problem_instances = [
        r for r in results if r.get("status") != "success"
    ]
    if problem_instances:
        print(f"\nFailed/Error instances ({len(problem_instances)}):")
        for r in problem_instances:
            print(f"  - {r.get('instance_id', '?')}: {r.get('status', '?')}")


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="ARVO multi-agent vulnerability solver"
    )
    parser.add_argument(
        "--instance_id",
        type=str,
        default=None,
        help="Run a specific instance by its ID (e.g. libxml2-42510333)",
    )
    parser.add_argument(
        "--project",
        type=str,
        nargs="*",
        default=None,
        help="Restrict to these projects",
    )
    parser.add_argument(
        "--local_id",
        type=str,
        nargs="*",
        default=None,
        help="Restrict to these ARVO localIds",
    )
    parser.add_argument(
        "--mini",
        action="store_true",
        help="Run the mini benchmark (5 bugs per project)",
    )
    parser.add_argument(
        "--no_filters",
        action="store_true",
        help="Skip the standard ARVO row filters (language/ubuntu/patch-url)",
    )
    parser.add_argument(
        "--start",
        type=int,
        default=None,
        help="Start index for range of instances",
    )
    parser.add_argument(
        "--end",
        type=int,
        default=None,
        help="End index (exclusive) for range of instances",
    )
    args = parser.parse_args()

    # Ensure results directory exists
    os.makedirs(RESULTS_DIR, exist_ok=True)

    logger.info("Loading ARVO overview.csv ...")
    local_ids = args.local_id
    projects = args.project
    if args.mini:
        mini_ids = sorted({i for ids in ARVO_MINI.values() for i in ids})
        local_ids = (local_ids or []) + mini_ids
        logger.info("Mini benchmark: %d bug ids", len(mini_ids))

    instances = load_instances(
        projects=projects,
        local_ids=local_ids,
        apply_filters=not args.no_filters,
    )
    logger.info(
        "Loaded %d instances (excluded projects: %s)",
        len(instances), sorted(ARVO_EXCLUDED_PROJECTS) or "none",
    )

    if args.instance_id:
        instances = [i for i in instances if i["instance_id"] == args.instance_id]
        if not instances:
            logger.error(
                "Instance %s not found. It may be filtered out — try "
                "--no_filters, or check ARVO_EXCLUDED_PROJECTS.",
                args.instance_id,
            )
            sys.exit(1)
        logger.info("Running single instance: %s", args.instance_id)
    elif args.start is not None or args.end is not None:
        start = args.start if args.start is not None else 0
        end = args.end if args.end is not None else len(instances)
        instances = instances[start:end]
        logger.info("Running instances [%d, %d)", start, end)

    if not instances:
        logger.error("No instances selected")
        sys.exit(1)

    # Create shared model client
    model_client = create_model_client()

    # Process instances sequentially
    results = []
    start_time = datetime.now(timezone.utc)

    for i, instance in enumerate(instances):
        instance_id = instance["instance_id"]
        logger.info(
            "Processing instance %d/%d: %s", i + 1, len(instances), instance_id
        )

        # Skip if already solved
        safe_name = instance_id.replace("/", "_").replace("\\", "_")
        result_path = os.path.join(RESULTS_DIR, f"{safe_name}.json")
        if os.path.exists(result_path):
            try:
                with open(result_path, "r") as f:
                    prev = json.load(f)
                logger.info("Skipping %s (already processed)", instance_id)
                results.append(prev)
                continue
            except (json.JSONDecodeError, ValueError):
                logger.warning("Corrupted JSON for %s, removing and re-running", instance_id)
                os.remove(result_path)

        # Preparing the image is a one-off per bug (apt, clang-12, a configure
        # build) and not part of solving, so it runs before the instance clock.
        # A failure is not saved as a result: it is an environment problem, and
        # the next run should try again rather than skip the instance.
        try:
            prepare_image(
                instance["project_name"], instance["local_id"], instance["fuzz_target"],
                log_path=prepare_log_path(RESULTS_DIR, instance_id),
            )
        except Exception as e:
            logger.exception("Could not prepare the image for %s — skipping", instance_id)
            results.append({
                "instance_id": instance_id,
                "status": "prepare_failed",
                "error": str(e),
            })
            continue

        try:
            result = await asyncio.wait_for(
                solve_instance(instance, model_client, results_dir=RESULTS_DIR),
                timeout=INSTANCE_TIMEOUT or None,
            )
        except asyncio.TimeoutError:
            logger.error(
                "Instance %s timed out after %d seconds", instance_id, INSTANCE_TIMEOUT
            )
            safe_name = instance_id.replace("/", "_").replace("\\", "_")
            traj_path = os.path.join(RESULTS_DIR, f"{safe_name}.traj.json")
            result = {
                "instance_id": instance_id,
                "status": "timeout",
                "error": f"Timed out after {INSTANCE_TIMEOUT}s",
                "last_patch": _salvage_last_patch_from_traj(instance_id),
                "token_usage": summarize_token_usage(traj_path),
                "timing": load_timing(traj_path),
            }
        except Exception as e:
            logger.exception("Unhandled exception for %s — skipping", instance_id)
            safe_name = instance_id.replace("/", "_").replace("\\", "_")
            traj_path = os.path.join(RESULTS_DIR, f"{safe_name}.traj.json")
            result = {
                "instance_id": instance_id,
                "status": "error",
                "error": str(e),
                "last_patch": _salvage_last_patch_from_traj(instance_id),
                "token_usage": summarize_token_usage(traj_path),
                "timing": load_timing(traj_path),
            }
        save_result(result)
        results.append(result)
        if REMOVE_PREPARED_IMAGE:
            remove_prepared_image(instance["local_id"])

    elapsed = datetime.now(timezone.utc) - start_time
    logger.info("Total elapsed time: %s", elapsed)
    print_summary(results)


if __name__ == "__main__":
    asyncio.run(main())
