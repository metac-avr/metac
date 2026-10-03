"""Validate a patch at binary level with metapro, as San2Patch's `--mode metapro` does.

San2Patch runs this from the host: the patch config is derived on the host (tree-sitter
over ``source/`` and ``metapro-source/``) and the patched binary is produced and run
inside the bug's ``arvo-<bug_id>`` container, which bind-mounts the MetaC tree.
ContraFix's own containers have neither that mount nor metapro, so the same split is
kept here: the Patcher's diff is written to the host and handed to
``scripts/contrafix-metapro-validate.py``.

That script is run as a subprocess, not imported: it depends on
``benchmarks/arvo/scripts/docker.py``, whose module name shadows the docker SDK this
package uses.

Everything a bug needs must already exist — ``metapro-source/``, ``metapro-out/``
and the ``arvo-<bug_id>`` container, all produced by MetaC's own tooling
(``run-metapro.py``, ``docker.py:checkout``).  A bug missing any of them raises
:class:`MetaproUnavailable` rather than being silently reported as unpatchable.

One bug's validations are serialised by a file lock: they share the staging tree, the
instrumented binary and the container.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import shutil
import subprocess

from arvo.config import ARVO_BENCHMARK_DIR, METAC_ROOT, METAPRO_TIMEOUT

logger = logging.getLogger(__name__)

VALIDATE_SCRIPT = os.path.join(ARVO_BENCHMARK_DIR, "scripts", "contrafix-metapro-validate.py")

#: Tree the diff is applied to while the config is derived.  Deliberately not
#: San2Patch's ``san2patch-source`` nor the ``contrafix-source`` that
#: rq1-2-contrafix-metac.py uses: those runs would otherwise overwrite each other's
#: staging tree whenever they touch the same bug.
STAGING_DIR_NAME = "contrafix-mode-source"

#: Per-attempt outputs (config, patched binary, logs) live under the bug's work
#: directory, because the container reaches the host only through that mount.
OUTPUT_DIR_NAME = "contrafix-metapro"

#: patcher-e9patch.py is not in the ARVO images; San2Patch copies it in before use.
PATCHER_SRC = os.path.join(METAC_ROOT, "metapro", "src", "binary", "patcher-e9patch.py")
PATCHER_DST = "/usr/local/bin/patcher-e9patch.py"


class MetaproUnavailable(RuntimeError):
    """A bug cannot be validated with metapro (no instrumented build, no container)."""


def work_dir(project: str, local_id: int | str) -> str:
    return os.path.join(ARVO_BENCHMARK_DIR, "projects", project, str(local_id))


def check_available(project: str, local_id: int | str, fuzz_target: str) -> None:
    """Raise :class:`MetaproUnavailable` unless the bug has everything metapro needs."""
    bug_dir = work_dir(project, local_id)
    missing = [
        path for path in (
            os.path.join(bug_dir, "source"),
            os.path.join(bug_dir, "metapro-source"),
            os.path.join(bug_dir, "metapro-out", "asan-bin", fuzz_target),
        ) if not os.path.exists(path)
    ]
    if missing:
        raise MetaproUnavailable(
            f"{project}-{local_id}: missing {', '.join(missing)}; "
            f"run benchmarks/arvo/scripts/run-metapro.py for this bug first"
        )
    if not os.path.isfile(VALIDATE_SCRIPT):
        raise MetaproUnavailable(f"{VALIDATE_SCRIPT} not found")


def _container_name(local_id: int | str) -> str:
    return f"arvo-{local_id}"


def _ensure_container(local_id: int | str) -> None:
    """Start the bug's arvo container, and put the binary patcher inside it.

    The container is MetaC's, not one of ours: it carries the bind mount and the
    metapro toolchain, and outlives any single run.  We only start it when stopped.
    """
    name = _container_name(local_id)
    inspect = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name],
        capture_output=True, text=True,
    )
    if inspect.returncode != 0:
        raise MetaproUnavailable(
            f"container {name} does not exist; check the bug out with "
            f"benchmarks/arvo/scripts/checkout.py first"
        )
    if inspect.stdout.strip() != "true":
        started = subprocess.run(["docker", "start", name], capture_output=True, text=True)
        if started.returncode != 0:
            raise MetaproUnavailable(
                f"could not start {name}: {(started.stderr or started.stdout).strip()}"
            )

    if not os.path.isfile(PATCHER_SRC):
        raise MetaproUnavailable(f"{PATCHER_SRC} not found")
    subprocess.run(["docker", "cp", PATCHER_SRC, f"{name}:{PATCHER_DST}"],
                   capture_output=True, text=True)
    subprocess.run(["docker", "exec", name, "chmod", "+x", PATCHER_DST],
                   capture_output=True, text=True)


def _ensure_staging_tree(bug_dir: str) -> str:
    """A copy of ``source/`` for the config generator to apply diffs onto.

    The generator restores every file it touches when it is done, so one tree serves
    every attempt; it is made once per bug and kept.
    """
    staging = os.path.join(bug_dir, STAGING_DIR_NAME)
    if not os.path.isdir(staging):
        shutil.copytree(os.path.join(bug_dir, "source"), staging)
    return staging


def validate(
    project: str,
    local_id: int | str,
    fuzz_target: str,
    diff: str,
    attempt_key: str,
) -> dict:
    """Derive a metapro config from *diff*, apply it and run the PoC against it.

    *attempt_key* names this attempt's output directory, so concurrent Patchers do not
    overwrite each other's config, binary and logs.

    Only the PoC is run here; the Mutator's variants are run by the caller on a
    regular build of the patch, as San2Patch runs its functionality test.

    Returns the subprocess's report: ``ok``, the ``stage`` it reached (``config``,
    ``patch``, ``test`` or ``done``), ``config_size``, the stage times, ``error`` and
    ``out_dir``.  Raises :class:`MetaproUnavailable` when the bug is not set up.
    """
    check_available(project, local_id, fuzz_target)
    bug_dir = work_dir(project, local_id)
    out_dir = os.path.join(bug_dir, OUTPUT_DIR_NAME, attempt_key)
    os.makedirs(out_dir, exist_ok=True)
    diff_path = os.path.join(out_dir, "patch.diff")
    with open(diff_path, "w", encoding="utf-8") as f:
        f.write(diff)

    # The staging tree, the instrumented binary and the container are per bug, so
    # attempts of the same bug take turns — including attempts in other processes.
    lock_path = os.path.join(bug_dir, ".contrafix-metapro.lock")
    with open(lock_path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _ensure_container(local_id)
        staging = _ensure_staging_tree(bug_dir)
        cmd = [
            "python3", VALIDATE_SCRIPT,
            "--project", project,
            "--bug-id", str(local_id),
            "--binary", fuzz_target,
            "--diff", diff_path,
            "--out-dir", out_dir,
            "--staging-dir", staging,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=METAPRO_TIMEOUT)
        except subprocess.TimeoutExpired:
            return {"ok": False, "stage": "timeout", "config_size": 0,
                    "config_time": 0.0, "patch_time": 0.0, "test_time": 0.0,
                    "error": f"metapro validation timed out after {METAPRO_TIMEOUT}s",
                    "out_dir": out_dir}

    if proc.returncode != 0 or not proc.stdout.strip():
        tail = (proc.stderr or proc.stdout or "").strip()[-500:]
        logger.warning("metapro validation failed to run for %s-%s: %s",
                       project, local_id, tail)
        return {"ok": False, "stage": "error", "config_size": 0,
                "config_time": 0.0, "patch_time": 0.0, "test_time": 0.0,
                "error": f"validator exited {proc.returncode}: {tail}", "out_dir": out_dir}

    try:
        report = json.loads(proc.stdout.strip().splitlines()[-1])
    except ValueError:
        return {"ok": False, "stage": "error", "config_size": 0,
                "config_time": 0.0, "patch_time": 0.0, "test_time": 0.0,
                "error": f"unreadable validator output: {proc.stdout[-500:]}",
                "out_dir": out_dir}
    report["out_dir"] = out_dir
    return report


#: Budget per input of a probe run, on top of METAPRO_TIMEOUT for the config and patch:
#: each input gets 300s inside the container (contrafix-metapro-validate.py POC_TIMEOUT).
PROBE_RUN_TIMEOUT = 330


def run_probes(
    project: str,
    local_id: int | str,
    fuzz_target: str,
    diff: str,
    attempt_key: str,
    inputs: list[tuple[str, bytes]],
) -> dict:
    """Insert the Analyzer's probe *diff* into the instrumented binary with metapro and run
    each of *inputs* -- (name, content) pairs -- on it, in place of a rebuild.

    Returns the subprocess's report: ``ok`` when the probes went in (whatever the runs
    did), ``stage`` (``config``, ``patch``, ``run`` or ``done``), ``runs`` -- one
    ``{variant, ok, exit_code, output}`` per input, in order -- and ``error``.  Raises
    :class:`MetaproUnavailable` when the bug is not set up.
    """
    check_available(project, local_id, fuzz_target)
    bug_dir = work_dir(project, local_id)
    out_dir = os.path.join(bug_dir, OUTPUT_DIR_NAME, attempt_key)
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

    lock_path = os.path.join(bug_dir, ".contrafix-metapro.lock")
    with open(lock_path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _ensure_container(local_id)
        staging = _ensure_staging_tree(bug_dir)
        cmd = [
            "python3", VALIDATE_SCRIPT, "--probe",
            "--project", project,
            "--bug-id", str(local_id),
            "--binary", fuzz_target,
            "--diff", diff_path,
            "--out-dir", out_dir,
            "--staging-dir", staging,
            *cmd_inputs,
        ]
        timeout = METAPRO_TIMEOUT + PROBE_RUN_TIMEOUT * len(inputs)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"ok": False, "stage": "timeout", "runs": [],
                    "error": f"metapro probe run timed out after {timeout}s", "out_dir": out_dir}

    try:
        report = json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        tail = (proc.stderr or proc.stdout or "").strip()[-500:]
        return {"ok": False, "stage": "error", "runs": [],
                "error": f"validator exited {proc.returncode}: {tail}", "out_dir": out_dir}
    report["out_dir"] = out_dir
    return report
