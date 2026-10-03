"""Aggregate ContraFix stage timings into SAN2PATCH-style columns.

SAN2PATCH reports ``Gen / Patch / Build / Test / Func test`` per instance.
ContraFix's stages do not line up one-to-one, so this module defines the
mapping explicitly:

Build and Test cover only the verification of a finished patch: the gates
``_patch_single`` runs after the Patcher agent returns.  Anything before that
point is producing the patch and counts as Gen — the Mutator and Analyzer in
full, and the Patcher's own ``check_vul`` builds and PoC runs, which it makes
while its patch is still being written.  The one Patcher tool call split out
is the source edit itself, as Patch.

Each round launches ``PATCHES_PER_ROUND`` Patchers at once, each in its own
container, and rounds run one after another.  Every Patcher-side quantity
(Gen_patcher, Patch, Build, Test) is therefore totalled per Patcher, averaged
over that round's Patchers, and summed over rounds: the time one Patcher of
the beam spends, not the beam's combined work.  Build averages only the
Patchers that reached Gate 2 and Test only those that reached Gate 3, since
those columns measure what verifying one patch costs.

===================  ========================================================
Gen time             Producing the patch.  ``Gen_context``: the whole
                     ``mutate`` + ``analyze`` stages, their tool calls
                     included.  ``Gen_patcher``: ``patch.agent`` (the Patcher
                     LLM reading source, deciding the edit and trying it out
                     with ``check_vul``), net of Patch time, as a per-round
                     Patcher mean.  The split is reported because the first
                     half is what ContraFix adds over a plain LLM patcher.
Patch time           Applying the patch: ``tool.apply`` inside ``patch.agent``.
                     ContraFix's Patcher writes its fix straight into the
                     source with ``str_replace_edit`` instead of emitting a
                     diff for a separate apply pass, so the application step
                     is those tool calls — not a separable pipeline stage.  It
                     is therefore small (~1s), the counterpart of a baseline's
                     ``git apply``, not of its LLM time.
Build time           Gate 2: ``verify.build``, the ``arvo compile`` of the
                     finished patch.
Test time            Gate 3: ``verify.repro``, the PoC run against that build,
                     plus Gate 4: ``verify.variants``, the Mutator's
                     variants run against it (the variant gate).  Under
                     ``--mode metapro`` it is ``verify.metapro`` instead:
                     deriving the patch config, applying it to the
                     instrumented binary and running the PoC, with no build.
                     Under ``--mode dyninst`` it is ``verify.dyninst``:
                     building libpatch.so and running the PoC with it swapped
                     in (the one-time ``verify.dyninst_setup`` is left out).
Func test time      No counterpart.  ARVO ships no functional test suite.
===================  ========================================================

Because the edits happen *inside* the Patcher's agent span, counting them in
both Patch and Gen_patcher would double-count.  They are therefore subtracted
from ``patch.agent``, attributed by container id plus time containment.  The
verification gates run after the span closes, so Gen + Patch + Build + Test is
a disjoint partition of the solving work.

Excluded from all columns and reported separately as ``Overhead``:
``setup.prepare_image`` (normally a lookup: main.py prepares each bug's
image before the instance clock), ``setup.container`` and
``patch.container_*`` (Docker start/stop), ``patch.copy_variants``
(copying the Mutator's variants into the Patcher containers),
``setup.build`` (the baseline compile of the unpatched project),
``setup.bootstrap`` (running the PoC once to produce a crash report, which
ARVO's CSV does not carry -- the only genuinely ARVO-porting-specific item,
and ~0.2s), ``mutate.persist`` and ``save_experience`` (artifact bookkeeping),
and ``finalize`` (re-applying the selected patch and rebuilding, which
duplicates work already done in place).  ``--build-includes-setup`` moves
``setup.build`` into Build for baselines that report a project's whole
compile cost.

Results produced before apply timing existed carry no ``tool.apply`` events,
so the edit cost is still buried inside ``patch.agent``.  ``--impute``
reconstructs it from the Patchers' edit-call counts in the trajectory
multiplied by twice that instance's own mean ``tool.bash`` round-trip (one
edit is a read_file + write_file pair).  Those rows are marked ``estimated`` —
re-run the instance for measured numbers.

Usage::

    python -m arvo.timing_report results_libxml2_full_time
    python -m arvo.timing_report results_dir --impute
    python -m arvo.timing_report results_dir --csv --raw > timing.csv
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import statistics

GEN_STAGES = ("mutate", "analyze")
PATCHER_SPAN = "patch.agent"
AGENT_SPANS = ("mutate.agent", "analyze.agent", PATCHER_SPAN)
OVERHEAD_STAGES = (
    "setup.prepare_image", "setup.container", "setup.build", "setup.bootstrap",
    "patch.container_setup", "patch.container_stop", "patch.copy_variants",
    "mutate.persist", "save_experience", "finalize",
)
#: ContraFix's patch-application step: the Patcher writes edits into the source
#: through these tools instead of emitting a diff for a separate apply pass.
APPLY_STAGE = "tool.apply"
APPLY_TOOLS = ("str_replace_edit", "revert_last_edit", "revert_all_edits")


def _enclosing_span(event: dict, spans: list[dict]) -> dict | None:
    """Find the agent span that a tool event ran inside.

    Matches on container id first (parallel Patchers overlap in time but use
    different containers), then on time containment.
    """
    best = None
    for s in spans:
        if s.get("container") and event.get("container"):
            if s["container"] != event["container"]:
                continue
        if s["start"] <= event["start"] and event["end"] <= s["end"] + 1e-6:
            # Innermost wins if spans ever nest.
            if best is None or s["start"] > best["start"]:
                best = s
    return best


def _patcher_key(event: dict) -> tuple:
    """Identify one Patcher run: its round plus the container it edits in."""
    return (event.get("round"), event.get("container") or event.get("agent"))


def _mean_per_round(per_patcher: dict[tuple, dict], field: str,
                    reached: str | None = None) -> float:
    """Average *field* over each round's parallel Patchers, summed over rounds.

    A round starts its Patchers at once, so the round costs one Patcher's time,
    not their sum; rounds run one after another, so those add up.  With
    *reached*, only Patchers that ran that gate at least once are averaged, and
    a round where none did contributes nothing.
    """
    by_round: dict = {}
    for (rnd, _), p in per_patcher.items():
        if reached is None or p[reached]:
            by_round.setdefault(rnd, []).append(p[field])
    return sum(statistics.mean(v) for v in by_round.values())


def instance_columns(timing: dict, *, build_includes_setup: bool = False) -> dict:
    """Reduce one instance's timing dict to the SAN2PATCH-style columns."""
    events = timing.get("events", [])
    spans = [e for e in events if e["stage"] in AGENT_SPANS]

    def total(*stages: str) -> float:
        return sum(e["duration"] for e in events if e["stage"] in stages)

    # Per-Patcher totals.  A Patcher's retries reuse its container within the
    # round, so they run one after another and are summed into that Patcher.
    per_patcher: dict[tuple, dict] = {}

    def patcher(event: dict) -> dict:
        return per_patcher.setdefault(
            _patcher_key(event),
            {"gen": 0.0, "patch": 0.0, "build": 0.0, "test": 0.0,
             "n_build": 0, "n_test": 0},
        )

    for e in events:
        if e["stage"] == PATCHER_SPAN:
            patcher(e)["gen"] += e["duration"]
        elif e["stage"] == "verify.build":
            patcher(e)["build"] += e["duration"]
            patcher(e)["n_build"] += 1
        elif e["stage"] == "verify.repro":
            patcher(e)["test"] += e["duration"]
            patcher(e)["n_test"] += 1
        elif e["stage"] == "verify.variants":
            patcher(e)["test"] += e["duration"]
        elif e["stage"] in ("verify.metapro", "verify.dyninst"):
            # metapro replaces Gate 2 and Gate 3 at once: the patch is applied to
            # the instrumented binary and the PoC run against it, with no source
            # build, so the whole span is Test time and Build stays empty.
            patcher(e)["test"] += e["duration"]
            patcher(e)["n_test"] += 1

    # Split the Patcher's edits out of its span so the columns stay disjoint.
    # Its check_vul builds and PoC runs stay in Gen_patcher: they happen while
    # the patch is still being written.  Edits by the Mutator or Analyzer are
    # probing, not applying a patch, so they are left in Gen_context.
    unattributed = 0.0
    n_apply_events = 0
    for e in events:
        if e["stage"] != APPLY_STAGE:
            continue
        n_apply_events += 1
        owner = _enclosing_span(e, spans)
        if owner is None:
            # Outside every agent span, so it cannot be tied to a Patcher.
            # Left out of Patch; main() reports how much.
            unattributed += e["duration"]
        elif owner["stage"] == PATCHER_SPAN:
            p = patcher(owner)
            p["patch"] += e["duration"]
            p["gen"] -= e["duration"]
    for p in per_patcher.values():
        p["gen"] = max(p["gen"], 0.0)

    # Gen_patcher and Patch average every Patcher: each one spends that time.
    # Build and Test measure what verifying one patch costs, so they average
    # only the Patchers that got that far — one that produced no diff never
    # reaches Gate 2, and one whose patch failed to build never reaches Gate 3.
    cols = {
        "patch": _mean_per_round(per_patcher, "patch"),
        "build": _mean_per_round(per_patcher, "build", reached="n_build"),
        "test": _mean_per_round(per_patcher, "test", reached="n_test"),
    }
    gen_llm = _mean_per_round(per_patcher, "gen")

    # The baseline compile of the unpatched project.  It is a real build, but
    # it validates the environment rather than a patch, so it sits in
    # Overhead by default; move it into Build when the baseline reports a
    # project's whole compile cost.
    overhead_stages = list(OVERHEAD_STAGES)
    if build_includes_setup:
        cols["build"] += total("setup.build")
        overhead_stages.remove("setup.build")

    # Mutator and Analyzer: the whole stage, tool calls included.
    gen_ctx = total(*GEN_STAGES)

    # An instance that never reached the Patcher (failed setup, timed out
    # while mutating) has no edits to split out, so missing apply events there
    # do not mean the result predates apply timing.
    n_rounds = len({rnd for rnd, _ in per_patcher})

    return {
        "gen": gen_ctx + gen_llm,
        **cols,
        "func_test": None,          # no counterpart in ARVO
        "select": total("select"),
        "overhead": total(*overhead_stages),
        "total_wall": timing.get("total_wall_seconds", 0.0),
        "estimated": False,
        # Sub-breakdown of Gen
        "gen_ctx": gen_ctx,
        "gen_llm": gen_llm,
        # Diagnostics
        "patcher_rounds": n_rounds,
        "patchers_per_round": len(per_patcher) / n_rounds if n_rounds else 0.0,
        "unattributed": unattributed,
        "has_apply_timings": n_apply_events > 0 or not per_patcher,
    }


# ---------------------------------------------------------------------------
# Imputation for results collected before apply timing existed
# ---------------------------------------------------------------------------


def _per_call_cost(timing: dict, stage: str) -> float:
    """Mean duration of one *stage* occurrence, or 0.0 if it never ran.

    Reads the event list rather than the ``detail_seconds`` / ``detail_counts``
    aggregates so a timing dict with inconsistent or missing aggregates (a
    truncated or hand-edited result) yields 0.0 instead of raising.
    """
    durations = [e["duration"] for e in timing.get("events", [])
                 if e.get("stage") == stage]
    if durations:
        return statistics.mean(durations)
    # Fall back to the aggregates for results whose events were trimmed.
    counts = timing.get("detail_counts", {})
    seconds = timing.get("detail_seconds", {})
    n = counts.get(stage, 0)
    return seconds.get(stage, 0.0) / n if n else 0.0


_PATCHER_TRAJ_KEY = re.compile(r"^patcher_r(\d+)_(\d+)")


def _count_patcher_applies(traj_path: str) -> dict:
    """Count the Patchers' edit calls (what ``arvo.tools`` times as tool.apply).

    Returns ``{"total": n, "per_round": {round: n}, "patchers": {round: n}}``,
    or ``{}`` if the trajectory is unreadable.  Trajectory keys look like
    ``patcher_r0_1``, with a ``_retry1`` suffix for retries, which belong to
    the same Patcher.  Mutator and Analyzer edits are ignored: they stay in
    Gen, so there is nothing to reconstruct for them.
    """
    try:
        with open(traj_path, encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}

    per_round: dict[int, int] = {}
    patchers: dict[int, set] = {}
    for agent_key, messages in data.get("agents", {}).items():
        m = _PATCHER_TRAJ_KEY.match(agent_key)
        if not m:
            continue
        rnd = int(m.group(1))
        patchers.setdefault(rnd, set()).add(m.group(2))
        per_round[rnd] = per_round.get(rnd, 0) + sum(
            1
            for msg in messages
            for tc in msg.get("tool_calls") or []
            if tc.get("function", {}).get("name", "") in APPLY_TOOLS
        )
    return {
        "total": sum(per_round.values()),
        "per_round": per_round,
        "patchers": {rnd: len(ids) for rnd, ids in patchers.items()},
    }


def impute_columns(cols: dict, timing: dict, traj_path: str) -> dict:
    """Fill in the Patchers' edit time for results that predate apply timing.

    One str_replace_edit is a read_file + write_file round-trip, i.e. two
    container round-trips where a bash call is one, so the instance's own mean
    bash call is the closest available yardstick.
    """
    counts = _count_patcher_applies(traj_path)
    if not counts.get("total"):
        return cols

    # Columns are per-round Patcher means (see instance_columns), so the
    # imputed count is too.  The number of Patchers in a round comes from the
    # timing events (every Patcher records a patch.agent span, even one that
    # never edited); the trajectory's own count is the fallback.
    measured: dict = {}
    for e in timing.get("events", []):
        if e.get("stage") == PATCHER_SPAN:
            measured.setdefault(e.get("round"), set()).add(_patcher_key(e))
    mean_applies = sum(
        n / (len(measured.get(rnd, ())) or counts["patchers"][rnd])
        for rnd, n in counts["per_round"].items()
    )

    apply_cost = 2 * _per_call_cost(timing, "tool.bash")
    applies = mean_applies * apply_cost
    out = dict(cols)
    out["patch"] = cols["patch"] + applies
    out["gen_llm"] = max(cols["gen_llm"] - applies, 0.0)
    out["gen"] = cols["gen_ctx"] + out["gen_llm"]
    out["estimated"] = True
    out["imputed_applies"] = counts["total"]
    out["apply_cost"] = apply_cost
    return out


# ---------------------------------------------------------------------------


def load_results(results_dir: str, *, impute: bool = False,
                 build_includes_setup: bool = False) -> list[tuple[str, dict, dict]]:
    """Return ``(instance_id, result, columns)`` for every timed result."""
    raw = []
    for path in sorted(glob.glob(os.path.join(results_dir, "*.json"))):
        if path.endswith(".traj.json"):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                result = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        timing = result.get("timing")
        if not timing:
            continue
        raw.append((path, result, timing))

    rows = []
    for path, result, timing in raw:
        cols = instance_columns(timing, build_includes_setup=build_includes_setup)
        if impute and not cols["has_apply_timings"]:
            traj = path[:-len(".json")] + ".traj.json"
            cols = impute_columns(cols, timing, traj)
        rows.append((
            result.get("instance_id", os.path.basename(path)), result, cols,
        ))
    return rows


_COLS = ("gen", "patch", "build", "test", "select", "overhead", "total_wall",
         "gen_ctx", "gen_llm")
_HEADERS = ("Gen", "Patch", "Build", "Test", "Select", "Overhead", "Total",
            "Gen_context", "Gen_patcher")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("results_dir")
    ap.add_argument("--csv", action="store_true", help="emit CSV instead of a table")
    ap.add_argument("--raw", action="store_true",
                    help="print full float precision instead of 2 decimals")
    ap.add_argument("--impute", action="store_true",
                    help="estimate the Patchers' edit (Patch) time for results "
                         "collected before apply timing existed")
    ap.add_argument("--build-includes-setup", action="store_true",
                    help="count the baseline compile of the unpatched project "
                         "(setup.build) as Build time instead of Overhead")
    ap.add_argument("--status", default="", help="only include this status (e.g. success)")
    args = ap.parse_args()

    rows = load_results(args.results_dir, impute=args.impute,
                        build_includes_setup=args.build_includes_setup)
    if args.status:
        rows = [r for r in rows if r[1].get("status") == args.status]
    if not rows:
        print(f"No timed results in {args.results_dir}")
        return

    def fmt(v: float) -> str:
        return repr(v) if args.raw else f"{v:.2f}"

    stale = [i for i, _, c in rows
             if not c["has_apply_timings"] and not c["estimated"]]
    est = [i for i, _, c in rows if c["estimated"]]
    sep = "," if args.csv else "\t"
    print(sep.join(("id", "status") + _HEADERS + ("FuncTest", "Measured")))
    for instance_id, result, c in rows:
        cells = [fmt(c[k]) for k in _COLS]
        # "libxml2-42531126" -> "42531126"; the project is the results dir.
        short_id = instance_id.rsplit("-", 1)[-1]
        print(sep.join(
            [short_id, result.get("status", "?")] + cells
            + ["n/a", "estimated" if c["estimated"] else "measured"]
        ))

    if args.csv:
        return

    print()
    for label, fn in (("mean", statistics.mean), ("median", statistics.median)):
        cells = [fmt(fn([c[k] for _, _, c in rows])) for k in _COLS]
        print(sep.join([label, f"n={len(rows)}"] + cells + ["n/a", ""]))

    if stale:
        print(
            f"\nWARNING: {len(stale)}/{len(rows)} results predate apply timing "
            "(no tool.apply events), so Patch reads 0.00 and the application "
            "cost is still inside Gen.  Re-run for measured numbers, or pass "
            "--impute to estimate from trajectory tool-call counts."
        )
    if est:
        n_a = sum(c["imputed_applies"] for _, _, c in rows if c["estimated"])
        acosts = [c["apply_cost"] for _, _, c in rows if c["estimated"]]
        print(
            f"\nESTIMATED: {len(est)}/{len(rows)} rows had {n_a} patch "
            f"applications (per-apply cost {statistics.mean(acosts):.3f}s, from "
            "this run's own mean container round-trip) imputed from trajectory "
            "tool-call counts.  Not measurements."
        )
    reached = [c for _, _, c in rows if c["patcher_rounds"]]
    if reached:
        per_round = statistics.mean(c["patchers_per_round"] for c in reached)
        rounds = statistics.mean(c["patcher_rounds"] for c in reached)
        print(
            f"\nNote: Gen_patcher/Patch/Build/Test are per-Patcher means within a "
            f"round ({per_round:.1f} concurrent Patchers per round), summed over "
            f"rounds ({rounds:.1f} per instance that reached patching)."
        )
    unattr = sum(c["unattributed"] for _, _, c in rows)
    if unattr > 0.5:
        print(
            f"\nNote: {unattr:.1f}s of edit time fell outside any agent span, "
            "so it could not be tied to a Patcher and is not in Patch."
        )


if __name__ == "__main__":
    main()
