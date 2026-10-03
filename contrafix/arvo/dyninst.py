"""Validate a patch at binary level with Dyninst, as San2Patch's `--mode dyninst` does.

Same split as :mod:`arvo.metapro`: the Patcher's diff is written to the host and handed to
``scripts/contrafix-dyninst-validate.py``, which applies it onto the bug's own
``contrafix-dyninst-source/`` tree, builds the patched functions into a ``libpatch.so`` and
runs the PoC with them swapped into the target inside the bug's ``arvo-<bug_id>`` container.

That script needs the San2Patch package (``ArvoValidator.dyninst_patch/dyninst_test``) and
its dependencies, which this environment does not have, so it runs under
:data:`DYNINST_PYTHON` -- ``ARVO_DYNINST_PYTHON`` when set, else San2Patch's
``.venv`` when there is one, else ``python3``.

The container must have been checked out with ``checkout.py --setup-dyninst`` (Dyninst,
mutator_launch and the compiler wrapper).  The first validation of a bug builds
``contrafix-dyninst-source/`` once through that wrapper (:func:`prepare`); every later one
reuses that build.  The project PIC archive libpatch.so links against is built anew on each
run's first Dyninst call instead (``--fresh-pic``), and timed as part of that call, as
San2Patch builds one per run directory inside its first dyninst_patch().  One process is one
run (arvo.main solves one bug once), so "this process has not rebuilt it yet" is the test.

One bug's validations are serialised by a file lock: they share the tree, the binary and
the container.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import subprocess

from arvo.config import (
    ARVO_BENCHMARK_DIR,
    DYNINST_SETUP_TIMEOUT,
    DYNINST_TIMEOUT,
    METAC_ROOT,
)

logger = logging.getLogger(__name__)

VALIDATE_SCRIPT = os.path.join(ARVO_BENCHMARK_DIR, "scripts", "contrafix-dyninst-validate.py")

#: Per-attempt logs live under the bug's work directory, next to the script's own outputs
#: (``contrafix-dyninst/output``, ``contrafix-dyninst/dyninst-out``).
OUTPUT_DIR_NAME = "contrafix-dyninst"

MUTATOR_LAUNCH = "/opt/dyninst-tool/mutator_launch"


def _default_python() -> str:
    venv = os.path.join(METAC_ROOT, "san2patch", ".venv", "bin", "python")
    return venv if os.path.isfile(venv) else "python3"


DYNINST_PYTHON = os.environ.get("ARVO_DYNINST_PYTHON") or _default_python()


class DyninstUnavailable(RuntimeError):
    """A bug cannot be validated with Dyninst (no container, no Dyninst, no base build)."""


#: (project, local_id) whose PIC archive this process (this run) has already rebuilt.
_PIC_REBUILT: set[tuple[str, str]] = set()


def _fresh_pic_args(project: str, local_id: int | str) -> list[str]:
    return [] if (project, str(local_id)) in _PIC_REBUILT else ["--fresh-pic"]


def _pic_timeout(project: str, local_id: int | str) -> int:
    """Extra budget for a call that rebuilds the archive (a full PIC recompile of the project)."""
    return DYNINST_SETUP_TIMEOUT if _fresh_pic_args(project, local_id) else 0


def _note_pic(project: str, local_id: int | str, report: dict) -> None:
    """Remember a rebuild, so later calls of this run reuse the archive.  A call that never
    got as far (setup failed, timed out) leaves the next one to rebuild it."""
    if report.get("pic_rebuilt"):
        _PIC_REBUILT.add((project, str(local_id)))


def work_dir(project: str, local_id: int | str) -> str:
    return os.path.join(ARVO_BENCHMARK_DIR, "projects", project, str(local_id))


def _container_name(local_id: int | str) -> str:
    return f"arvo-{local_id}"


def _ensure_container(local_id: int | str) -> None:
    """Start the bug's arvo container, and check Dyninst is set up in it."""
    name = _container_name(local_id)
    inspect = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name],
        capture_output=True, text=True,
    )
    if inspect.returncode != 0:
        raise DyninstUnavailable(
            f"container {name} does not exist; check the bug out with "
            f"benchmarks/arvo/scripts/checkout.py --setup-dyninst first"
        )
    if inspect.stdout.strip() != "true":
        started = subprocess.run(["docker", "start", name], capture_output=True, text=True)
        if started.returncode != 0:
            raise DyninstUnavailable(
                f"could not start {name}: {(started.stderr or started.stdout).strip()}"
            )
    present = subprocess.run(["docker", "exec", name, "test", "-x", MUTATOR_LAUNCH],
                             capture_output=True, text=True)
    if present.returncode != 0:
        raise DyninstUnavailable(
            f"{name} has no Dyninst set up ({MUTATOR_LAUNCH} missing); check the bug out "
            f"with benchmarks/arvo/scripts/checkout.py --setup-dyninst"
        )


def check_available(project: str, local_id: int | str) -> None:
    """Raise :class:`DyninstUnavailable` unless the bug has what the base build needs."""
    bug_dir = work_dir(project, local_id)
    missing = [
        path for path in (
            os.path.join(bug_dir, "source"),
            os.path.join(bug_dir, "build.py"),
            os.path.join(bug_dir, "poc"),
        ) if not os.path.exists(path)
    ]
    if missing:
        raise DyninstUnavailable(
            f"{project}-{local_id}: missing {', '.join(missing)}; "
            f"check the bug out with benchmarks/arvo/scripts/checkout.py first"
        )
    if not os.path.isfile(VALIDATE_SCRIPT):
        raise DyninstUnavailable(f"{VALIDATE_SCRIPT} not found")


def _run_script(args: list[str], timeout: int) -> dict:
    """Run the validator script and return its JSON report (``ok``/``error`` on failure)."""
    cmd = [DYNINST_PYTHON, VALIDATE_SCRIPT, *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "stage": "timeout",
                "error": f"dyninst validation timed out after {timeout}s"}
    except OSError as e:
        return {"ok": False, "stage": "error", "error": f"cannot run {DYNINST_PYTHON}: {e}"}
    if proc.returncode != 0 or not proc.stdout.strip():
        tail = (proc.stderr or proc.stdout or "").strip()[-500:]
        return {"ok": False, "stage": "error",
                "error": f"validator exited {proc.returncode}: {tail}"}
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except ValueError:
        return {"ok": False, "stage": "error",
                "error": f"unreadable validator output: {proc.stdout[-500:]}"}


def _lock_path(project: str, local_id: int | str) -> str:
    return os.path.join(work_dir(project, local_id), ".contrafix-dyninst.lock")


def prepare(project: str, local_id: int | str, fuzz_target: str) -> float:
    """Build the bug's base binary and PIC archive, once.  Returns the seconds it took
    (about zero once built); raises :class:`DyninstUnavailable` when it cannot be built."""
    check_available(project, local_id)
    with open(_lock_path(project, local_id), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _ensure_container(local_id)
        report = _run_script(
            ["--project", project, "--bug-id", str(local_id), "--binary", fuzz_target,
             "--setup-only"],
            DYNINST_SETUP_TIMEOUT,
        )
    if not report.get("ok"):
        raise DyninstUnavailable(f"{project}-{local_id}: {report.get('error', 'setup failed')}")
    return float(report.get("setup_time", 0.0))


def validate(
    project: str,
    local_id: int | str,
    fuzz_target: str,
    diff: str,
    attempt_key: str,
) -> dict:
    """Apply *diff* with Dyninst and run the PoC against it.

    *attempt_key* names this attempt's output directory, so concurrent Patchers do not
    overwrite each other's logs.  Call :func:`prepare` first.

    Returns the subprocess's report: ``ok``, the ``stage`` it reached (``setup``,
    ``locate``, ``patch``, ``launch``, ``test`` or ``done``), ``config_size`` (patched
    functions), the stage times, ``error`` and ``out_dir``.  ``test`` is the only stage
    that judges the patch: it was applied and the PoC still crashes.
    """
    bug_dir = work_dir(project, local_id)
    out_dir = os.path.join(bug_dir, OUTPUT_DIR_NAME, "attempts", attempt_key)
    os.makedirs(out_dir, exist_ok=True)
    diff_path = os.path.join(out_dir, "patch.diff")
    with open(diff_path, "w", encoding="utf-8") as f:
        f.write(diff)

    with open(_lock_path(project, local_id), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _ensure_container(local_id)
        report = _run_script(
            ["--project", project, "--bug-id", str(local_id), "--binary", fuzz_target,
             "--diff", diff_path, "--out-dir", out_dir, *_fresh_pic_args(project, local_id)],
            DYNINST_TIMEOUT + _pic_timeout(project, local_id),
        )
    _note_pic(project, local_id, report)
    if report.get("stage") in ("error", "timeout"):
        logger.warning("dyninst validation failed to run for %s-%s: %s",
                       project, local_id, report.get("error", ""))
    report.setdefault("config_size", 0)
    report["out_dir"] = out_dir
    return report


#: Budget per input of a probe run, on top of DYNINST_TIMEOUT for the libpatch build:
#: each input gets 180s inside the container (contrafix-dyninst-validate.py PROBE_RUN_TIMEOUT).
PROBE_RUN_TIMEOUT = 210


def run_probes(
    project: str,
    local_id: int | str,
    fuzz_target: str,
    diff: str,
    attempt_key: str,
    inputs: list[tuple[str, bytes]],
) -> dict:
    """Swap the functions the Analyzer's probe *diff* touches into the base build with
    Dyninst and run each of *inputs* -- (name, content) pairs -- on it, in place of a rebuild.

    Same contract as :func:`arvo.metapro.run_probes`: ``ok`` when the probes went in
    (whatever the runs did), ``stage`` (``setup``, ``locate``, ``patch``, ``launch``,
    ``run`` or ``done``), ``runs`` -- one ``{variant, ok, exit_code, output}`` per input,
    in order -- and ``error``.  Call :func:`prepare` first.
    """
    bug_dir = work_dir(project, local_id)
    out_dir = os.path.join(bug_dir, OUTPUT_DIR_NAME, "probes", attempt_key)
    input_dir = os.path.join(out_dir, "inputs")
    os.makedirs(input_dir, exist_ok=True)
    diff_path = os.path.join(out_dir, "probe.diff")
    with open(diff_path, "w", encoding="utf-8") as f:
        f.write(diff)
    cmd_inputs = []
    for name, content in inputs:
        path = os.path.join(input_dir, name)
        with open(path, "wb") as f:
            f.write(content)
        cmd_inputs += ["--variant", path]

    with open(_lock_path(project, local_id), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _ensure_container(local_id)
        report = _run_script(
            ["--probe", "--project", project, "--bug-id", str(local_id),
             "--binary", fuzz_target, "--diff", diff_path, "--out-dir", out_dir, *cmd_inputs,
             *_fresh_pic_args(project, local_id)],
            DYNINST_TIMEOUT + PROBE_RUN_TIMEOUT * len(inputs) + _pic_timeout(project, local_id),
        )
    _note_pic(project, local_id, report)
    report.setdefault("runs", [])
    report["out_dir"] = out_dir
    return report
