"""Build solver instances from ARVO's ``overview.csv``.

SEC-bench hands the solver a HuggingFace row that already contains everything
the pipeline needs.  ARVO's CSV is thinner: it identifies the bug and the
build target, but carries no crash report and no exit code, because those are
properties of running the container rather than of the dataset.

So an ARVO instance is assembled in two stages:

  * :func:`load_instances` — static fields, straight from the CSV.
  * :func:`bootstrap_instance` — runtime fields, filled by running ``arvo``
    once in the container.  This doubles as the sanity check that the bug
    reproduces before any agent touches it.

Field mapping (SEC-bench -> ARVO):

    instance_id       f"{project}-{localId}"       derived
    project_name      project                      direct
    repo              repo_addr                    direct
    secb_sh           contents of /usr/bin/arvo    read from the container
    sanitizer_report  --                           runtime (bootstrap)
    exit_code         --                           runtime (bootstrap)
    bug_report        --                           synthesised from the report
    bug_description   --                           no equivalent; left empty

Columns such as ``fix_commit``, ``patch_url`` and ``patched file`` are the
ground truth.  They are loaded into the instance for evaluation and logging
but MUST NOT reach any agent prompt.  They are grouped under the ``_oracle``
key so that leaking one takes a deliberate act rather than a typo.
"""

from __future__ import annotations

import logging

from arvo.config import ARVO_EXCLUDED_PROJECTS, ARVO_FILTERS, OVERVIEW_CSV

logger = logging.getLogger(__name__)


def _clean(value) -> str:
    """CSV cells are often NaN; render them as empty strings."""
    import pandas as pd

    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    return str(value).strip()


def load_instances(
    csv_path: str = OVERVIEW_CSV,
    *,
    projects: list[str] | None = None,
    local_ids: list[str] | None = None,
    apply_filters: bool = True,
    exclude_projects: set[str] | None = None,
) -> list[dict]:
    """Load and filter ARVO rows into solver instance dicts.

    The default filters mirror ``benchmarks/arvo/scripts/*.py`` so the
    instance set matches MetaC's existing tooling: 6138 rows -> 1291.
    """
    import pandas as pd

    df = pd.read_csv(csv_path)
    total = len(df)

    if apply_filters:
        for column, expected in ARVO_FILTERS.items():
            df = df[df[column] == expected]

    excluded = ARVO_EXCLUDED_PROJECTS if exclude_projects is None else exclude_projects
    if excluded:
        df = df[~df["project"].isin(excluded)]

    if projects:
        df = df[df["project"].isin(projects)]
    if local_ids:
        wanted = {str(i) for i in local_ids}
        df = df[df["localId"].astype(str).isin(wanted)]

    logger.info(
        "Loaded %d/%d rows from %s (filters=%s, excluded=%s)",
        len(df), total, csv_path, apply_filters, sorted(excluded),
    )
    return [_row_to_instance(row) for _, row in df.iterrows()]


def _row_to_instance(row) -> dict:
    project = _clean(row["project"])
    local_id = _clean(row["localId"])
    return {
        # --- identity -----------------------------------------------------
        "instance_id": f"{project}-{local_id}",
        "local_id": local_id,
        "project_name": project,
        "repo": _clean(row.get("repo_addr")),
        # --- build/run contract -------------------------------------------
        "fuzz_target": _clean(row.get("fuzz_target")),
        "sanitizer": _clean(row.get("sanitizer")),
        # --- filled in by bootstrap_instance() ----------------------------
        "secb_sh": "",
        "sanitizer_report": "",
        "exit_code": 0,
        "bug_report": "",
        # ARVO has no prose bug description.  The prompts treat it as
        # optional and fall back to the sanitizer report.
        "bug_description": "",
        # --- ground truth: evaluation only, never shown to an agent -------
        "_oracle": {
            "fix_commit": _clean(row.get("fix_commit")),
            "patch_url": _clean(row.get("patch_url")),
            "patched_file": _clean(row.get("patched file")),
            "patched_line": _clean(row.get("patched line")),
            "patch_template": _clean(row.get("patch template")),
            "issue_url": _clean(row.get("report")),
        },
    }


def bootstrap_instance(instance: dict, container_id: str) -> tuple[bool, str]:
    """Fill the runtime fields by reproducing the crash once.

    Returns ``(reproduced, message)``.  A False result means the bug did not
    trigger a sanitizer report in its own vulnerable image, so the instance is
    unusable — there is nothing for the pipeline to verify a patch against.

    Called on a container of the prepared image, after the initial build, so
    the report comes from San2Patch's build of the source the agents see.
    """
    from arvo.benchmark import ARVO_WRAPPER
    from arvo.docker_tools import read_file, run_repro
    from arvo.pipeline import _has_sanitizer_error  # noqa: PLC0415  (cycle)

    try:
        instance["secb_sh"] = read_file(container_id, ARVO_WRAPPER)
    except Exception as e:
        logger.warning("Could not read %s: %s", ARVO_WRAPPER, e)
        instance["secb_sh"] = ""

    exit_code, output = run_repro(container_id)
    instance["exit_code"] = exit_code
    instance["sanitizer_report"] = output
    instance["bug_report"] = _summarize_report(instance, output)

    reproduced = _has_sanitizer_error(output)
    if not reproduced:
        return False, (
            f"{instance['instance_id']}: no sanitizer error from the original "
            f"PoC (exit={exit_code}). Output tail:\n{output[-1500:]}"
        )
    return True, f"reproduced (exit={exit_code})"


def _summarize_report(instance: dict, output: str) -> str:
    """A prompt-safe stand-in for SEC-bench's ``bug_report``.

    Built only from the observed crash plus non-revealing CSV columns.  The
    issue tracker URL is included because it names the bug without disclosing
    the fix; ``fix_commit``, ``patch_url`` and ``patched file`` are not.
    """
    header = [
        f"Project: {instance['project_name']}",
        f"Fuzz target: {instance['fuzz_target']}",
        f"Sanitizer: {instance['sanitizer']}",
        f"OSS-Fuzz issue: {instance['_oracle'].get('issue_url') or 'N/A'}",
    ]
    return "\n".join(header) + "\n\nCrash report:\n" + output.strip()
