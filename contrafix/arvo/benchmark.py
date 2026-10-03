"""The ARVO container contract, in one place.

Every fact in this module was verified against real ``n132/arvo:<id>-vul``
containers (libxml2/asan, mruby/ubsan, gpac/asan, ndpi/asan, ffmpeg/asan);
see ``scripts/arvo_probe*.py`` and ``porting.md``.  The rest of the package
imports from here rather than hard-coding paths, so the SEC-bench→ARVO
differences stay reviewable in a single file.

Contract summary (SEC-bench -> ARVO):

    secb build      ->  arvo compile
    secb repro      ->  arvo                    (= ``arvo run``)
    secb patch      ->  git apply in /src/<project>   (no ARVO equivalent)
    /testcase/poc   ->  /tmp/poc
    /testcase/*     ->  /tmp/*
    /src            ->  /src/<project>          (/src is NOT a git repo)

Build and run follow San2Patch, not ARVO.  San2Patch's ArvoValidator builds each
bug with MetaC's ``benchmarks/arvo/projects/<project>/<id>/build.py``
(ASan+UBSan, -O0, a standalone libFuzzer main) with clang-12 in a container set
up by ``scripts/docker.py:checkout``, and runs the fuzz target on the PoC
directly.  ``arvo compile`` / ``arvo`` stay the names the rest of the package
calls, but in a prepared image ``/usr/bin/arvo`` is replaced by
:func:`render_arvo_wrapper`, which does exactly that.  Every build and PoC run
— pipeline gates, check_vul, run_probed, a bash ``arvo compile``, variant runs
through the wrapper's exports — therefore sees the San2Patch binary.

Preparation (``docker_tools.prepare_image``) runs once per bug and is committed
as an image, so every container of the bug starts from the same state.  It also
handles the one ARVO property with no SEC-bench analogue: the images ship the
full upstream git history, including the developer's fix commit, reachable via
``origin/*`` (porting.md §7.0).  Left in place, a Patcher agent can simply copy
the answer.
"""

from __future__ import annotations

import base64
import logging
import re
import shlex
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths — verified identical across all probed images
# ---------------------------------------------------------------------------

#: The original crashing input.  ``/usr/bin/arvo`` hard-codes this path.
POC_PATH = "/tmp/poc"

#: Where mutated PoCs live.  ``/tmp`` is overlayfs (not tmpfs), so files
#: survive for the lifetime of the container.
WORK_DIR = "/tmp"

#: Root of all source trees.  NOT itself a git repository — see §7.2.
SRC_ROOT = "/src"

#: Built fuzz targets.  Also contains the AFL toolchain on some images
#: (``OUT=/out`` is on ``PATH``), so never infer the target from a listing;
#: use the ``fuzz_target`` column of overview.csv, which matched 5/5 probes.
OUT_DIR = "/out"

#: The per-bug wrapper defining the build/run contract.
ARVO_WRAPPER = "/usr/bin/arvo"

PATCH_PATH = "/tmp/model_patch.diff"
TOOL_EVENT_LOG = "/tmp/.contrafix_tool_events.jsonl"


def variant_path(name: str) -> str:
    """Absolute path of a variant PoC (``variant_1`` -> ``/tmp/variant_1``)."""
    if name.startswith("/"):
        return name
    return f"{WORK_DIR}/{name}"


def project_dir(project: str) -> str:
    """Source repo for *project* (``libxml2`` -> ``/src/libxml2``).

    Only this directory may be reset.  ``/src`` holds unrelated git repos —
    the fuzzer toolchain (``/src/aflplusplus``) and vendored dependencies
    (an ffmpeg image has ten, including a second copy of libxml2).  Running
    ``git clean -fd`` across ``/src/*/`` destroys them (porting.md §7.2).
    """
    return f"{SRC_ROOT}/{project}"


# ---------------------------------------------------------------------------
# Image naming
# ---------------------------------------------------------------------------

ARVO_IMAGE_PREFIX = "n132/arvo"


def get_image_name(local_id: int | str, fixed: bool = False) -> str:
    """``42510333`` -> ``n132/arvo:42510333-vul`` (or ``-fix``).

    The ``-fix`` image is the developer-patched build.  It is an evaluation
    artifact only; the solver never runs against it.
    """
    return f"{ARVO_IMAGE_PREFIX}:{local_id}{'-fix' if fixed else '-vul'}"


def get_prepared_image_name(repo: str, local_id: int | str) -> str:
    """``42510333`` -> ``<repo>:42510333``, the image ``prepare_image`` commits."""
    return f"{repo}:{local_id}"


def local_id_from_instance(instance_id: str) -> str:
    """``libxml2-42510333`` -> ``42510333``."""
    return instance_id.rsplit("-", 1)[-1]


# ---------------------------------------------------------------------------
# Image preparation — runs once per bug; every container starts from the result
# ---------------------------------------------------------------------------

#: Where preparation puts the MetaC files a container needs.  They are
#: copied in, not bind-mounted: the MetaC tree also holds every bug's
#: ``dev.patch`` and fixed sources, which no agent may be able to read.
CONTRAFIX_DIR = "/contrafix"
BUILD_PY = f"{CONTRAFIX_DIR}/build.py"

#: San2Patch's container setup, in the order ``scripts/docker.py:checkout``
#: runs it (``install_dependency=True``).  ``setup_llvm.py`` points
#: ``/usr/local/bin/clang`` at clang-12, so this changes the compiler itself.
#: Every step needs the network.
DEPENDENCY_SETUP_CMDS = (
    "rm -rf /usr/local/include/c++/v1 /usr/local/lib/libc++.*",
    f"cd /src && bash {CONTRAFIX_DIR}/install-deps.sh",
    f"cd /src && python3 {CONTRAFIX_DIR}/setup_llvm.py",
    "apt-get install -y nano liblzma-dev",
)

#: §7.0 — drop the upstream history so the fix commit is not reachable.
#:
#: ``git clone`` + ``git reset --hard`` is ARVO's standard image recipe, so
#: every image keeps the remote branches and every commit made after the
#: vulnerable one.  Probed: 7-48 branches survive and ``git log
#: HEAD..origin/master`` lists the fix.  Re-initialising leaves exactly one
#: commit on ``master`` and costs 0.3-1.1s.
#:
#: ``git add -A`` respects .gitignore, so build artifacts are not committed
#: and ``git status --short`` stays clean — which ContraFix's Gate 1 relies on.
_STRIP_HISTORY = (
    "cd {project_dir} && rm -rf .git && git init -q && git add -A && "
    "git -c user.email=arvo@local -c user.name=arvo commit -qm base"
)

#: Fold the configure build's edits to tracked files into the base commit.
#:
#: build.py edits the tree it builds (ffmpeg's seds ``configure``), and every
#: later build runs ``--skip-configure`` on top of that edit.  San2Patch diffs
#: only the files a patch touched, so the edit never reaches its patches.
#: ContraFix diffs the whole repo, so left uncommitted the edit would appear in
#: every extracted patch and ``reset_source`` would revert it.
_COMMIT_BUILD_EDITS = (
    "cd {project_dir} && (git diff --quiet || "
    "git -c user.email=arvo@local -c user.name=arvo commit -qam 'baseline build')"
)

#: Teach git to ignore whatever the build generates inside the repo.
#:
#: ``_git_diff`` stages untracked files whose extension looks like source, so
#: that a patch which adds a new file is captured.  Some builds generate
#: *source* inside the work tree — mruby's proto fuzzer emits
#: ``genfiles/ruby.pb.cc`` and ``ruby.pb.h`` — and an extension test cannot
#: tell those from code the Patcher wrote.  Left alone they land in the
#: extracted patch: an observed mruby patch was 527KB, of which 99% was a
#: generated protobuf file.
#:
#: Recording them in ``.git/info/exclude`` (which ``--exclude-standard``
#: honours) fixes this at the source, and has a useful side effect:
#: ``git clean -fd`` does not remove ignored files without ``-x``, so
#: ``reset_source`` preserves build output and rebuilds stay incremental.
_RECORD_BUILD_ARTIFACTS = (
    "cd {project_dir} && "
    "git ls-files --others --exclude-standard | sed 's|^|/|' "
    ">> .git/info/exclude && "
    "git status --porcelain | wc -l"
)

#: San2Patch's build environment (ArvoValidator ``setup`` / ``build_test``).
SAN2PATCH_BUILD_ENV = {
    "CFLAGS": "-fsanitize=address,undefined -g -fno-sanitize-recover=all -fno-omit-frame-pointer",
    "CXXFLAGS": "-fsanitize=address,undefined -g -fno-sanitize-recover=all -fno-omit-frame-pointer",
    "LDFLAGS": "-fsanitize=address,undefined",
    "CC": "clang",
    "CXX": "clang++",
}

#: build.py's -j in San2Patch: ``setup`` configures and builds at 10,
#: ``build_test`` rebuilds at 1.  Parallelism does not change the binary, only
#: build time, so it is kept equal for timing comparisons.
SAN2PATCH_SETUP_JOBS = 10
SAN2PATCH_BUILD_JOBS = 1

#: San2Patch's PoC run environment (ArvoValidator ``vulnerability_test``).
SAN2PATCH_RUN_ENV = {
    "ASAN_OPTIONS": "detect_leaks=0:allocator_may_return_null=1",
    "UBSAN_OPTIONS": "print_stacktrace=1:abort_on_error=1",
    "LIBRARY_PATH": "/usr/local/lib:",
    "LD_LIBRARY_PATH": "/usr/local/lib:",
}

#: ``vulnerability_test`` kills the fuzz target inside the container after 180s.
POC_RUN_TIMEOUT = 180


def build_py_cmd(project: str, local_id: int | str, configure: bool) -> str:
    """The build.py invocation San2Patch uses, environment included.

    With *configure* this is ``setup()``'s first build; without it,
    ``build_test()``'s ``--skip-configure`` rebuild.  The fuzz target is written
    to ``/out/<fuzz_target>``, over ARVO's prebuilt binary, which is where every
    run command already looks.
    """
    env = " ".join(f"{k}={shlex.quote(v)}" for k, v in SAN2PATCH_BUILD_ENV.items())
    if configure:
        flags = f"-j {SAN2PATCH_SETUP_JOBS}"
    else:
        flags = f"--skip-configure -j {SAN2PATCH_BUILD_JOBS}"
    return (
        f"env {env} python3 {BUILD_PY} {project} {local_id} "
        f"{project_dir(project)} {flags} -o {OUT_DIR}"
    )


def render_arvo_wrapper(project: str, local_id: int | str, fuzz_target: str) -> str:
    """The ``/usr/bin/arvo`` a prepared image carries.

    ``arvo compile`` is San2Patch's rebuild; ``arvo`` (or ``arvo run``) runs the
    fuzz target on ``/tmp/poc`` the way ``vulnerability_test`` does.

    The run environment is exported at column 0 *after* the compile branch.
    ``build_variant_run_cmd`` and ``ReproCommand`` source exactly the
    ``^export`` lines, so variant runs get it, while a compile has already
    exec'd and runs without it, as San2Patch's builds do.  The run line keeps
    the ``/out/<target> /tmp/poc`` shape ``parse_wrapper_run_command`` reads.
    """
    exports = "\n".join(
        f"export {k}={shlex.quote(v)}" for k, v in SAN2PATCH_RUN_ENV.items()
    )
    return (
        "#!/bin/bash\n"
        "# Written by arvo.benchmark.render_arvo_wrapper: San2Patch's build and PoC run.\n"
        f"# ARVO's own wrapper is kept at {ARVO_WRAPPER}.orig.\n"
        'if [ "$1" = "compile" ]; then\n'
        f"  exec {build_py_cmd(project, local_id, configure=False)}\n"
        "fi\n"
        f"{exports}\n"
        f"exec timeout -s KILL {POC_RUN_TIMEOUT} {OUT_DIR}/{fuzz_target} {POC_PATH}\n"
    )


@dataclass
class PrepareResult:
    ok: bool
    output: str


def prepare_container(
    exec_cmd,
    container_id: str,
    project: str,
    local_id: int | str,
    fuzz_target: str,
    timeout: int,
) -> PrepareResult:
    """Turn a fresh ``n132/arvo`` container into San2Patch's environment.

    Expects build.py and San2Patch's setup scripts already copied to
    ``CONTRAFIX_DIR`` and the network available.  *exec_cmd* is
    ``docker_tools.exec_cmd``; it is injected so this module stays free of
    Docker imports.

    Stops at the first failing step: an image committed from a half-prepared
    container would build differently from San2Patch without saying so.
    """
    pdir = project_dir(project)
    wrapper = base64.b64encode(
        render_arvo_wrapper(project, local_id, fuzz_target).encode("utf-8")
    ).decode("ascii")
    steps = [
        *(
            (f"dependency setup {i}/{len(DEPENDENCY_SETUP_CMDS)}", cmd)
            for i, cmd in enumerate(DEPENDENCY_SETUP_CMDS, 1)
        ),
        ("strip history", _STRIP_HISTORY.format(project_dir=pdir)),
        # Remove ARVO's prebuilt target first, so a build.py that names its
        # output differently cannot leave the old binary to be run instead.
        (
            "baseline build",
            f"rm -f {OUT_DIR}/{fuzz_target} && "
            + build_py_cmd(project, local_id, configure=True),
        ),
        ("check fuzz target", f"test -x {OUT_DIR}/{fuzz_target}"),
        ("commit build edits", _COMMIT_BUILD_EDITS.format(project_dir=pdir)),
        ("exclude build artifacts", _RECORD_BUILD_ARTIFACTS.format(project_dir=pdir)),
        (
            "install wrapper",
            f"([ -f {ARVO_WRAPPER}.orig ] || cp {ARVO_WRAPPER} {ARVO_WRAPPER}.orig) && "
            f"printf %s {wrapper} | base64 -d > {ARVO_WRAPPER} && chmod +x {ARVO_WRAPPER}",
        ),
    ]

    outputs: list[str] = []
    for name, cmd in steps:
        rc, out, err = exec_cmd(container_id, cmd, timeout)
        outputs.append(f"[{name}] rc={rc}\n{out}{err}")
        if rc != 0:
            logger.error(
                "Preparation step '%s' failed in %s: %s",
                name, container_id[:12], (out + err)[-500:],
            )
            return PrepareResult(ok=False, output="\n".join(outputs))
    return PrepareResult(ok=True, output="\n".join(outputs))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

#: Both resolve to San2Patch's build and PoC run through the wrapper that
#: ``prepare_container`` installs; see ``render_arvo_wrapper``.
BUILD_CMD = "arvo compile"
REPRO_CMD = "arvo"


def reset_cmd(project: str) -> str:
    """Restore *project* to its state in the prepared image.

    ``git checkout -- .`` alone is not enough: a patch that adds files leaves
    them untracked (the libxml2 gold patch adds four), so ``git clean -fd`` is
    required.  Scoped to the single project directory — never ``/src/*/``.

    Cheap on every project kept in v1: after a build, ``git clean -fdn``
    reports 0 paths for libxml2, 1 for gpac, 2 for mruby.
    """
    pdir = project_dir(project)
    return f"cd {pdir} && git checkout -- . && git clean -fd; echo 'reset done'"


def build_variant_run_cmd(fuzz_target: str, poc_path: str) -> str:
    """Command to run *fuzz_target* against an arbitrary PoC.

    ``arvo run`` hard-codes both the target and ``/tmp/poc``, so variants
    cannot go through it.  Re-exporting the wrapper's sanitizer options and
    invoking the binary directly reproduces ``arvo run``, bar the wrapper's
    180s kill, which ``exec_cmd``'s own timeout stands in for.
    """
    return (
        f"source <(sed -n '/^export/p' {ARVO_WRAPPER}) && "
        f"{OUT_DIR}/{fuzz_target} {poc_path}"
    )


# ---------------------------------------------------------------------------
# Sanitizer classification
# ---------------------------------------------------------------------------

#: overview.csv ``sanitizer`` -> the wrapper's ``SANITIZER`` export.
#: Verified: the wrapper is generated per bug and agrees with the CSV
#: (ubsan bugs export ``SANITIZER=undefined``), so porting.md §7.9's concern
#: about a global constant does not apply.
SANITIZER_ENV = {"asan": "address", "ubsan": "undefined", "msan": "memory"}


def is_crash_exit(exit_code: int) -> bool:
    """Whether *exit_code* from ``arvo``/a fuzz target means "still crashing".

    Verified on asan and ubsan bugs, before and after the developer fix:
    vulnerable builds exit 1 with a sanitizer report, fixed builds exit 0
    with none.  porting.md §7.6 feared ubsan would exit 0 while crashing;
    it does not.
    """
    return exit_code != 0


def parse_wrapper_exports(wrapper_content: str) -> list[str]:
    """Collect the ``export`` lines that define the sanitizer environment."""
    return [
        line.strip()
        for line in wrapper_content.splitlines()
        if line.strip().startswith("export ")
    ]


_RUN_TARGET_RE = re.compile(r"(/out/[\w.\-+]+)\s+(/tmp/\S+)")


def parse_wrapper_run_command(wrapper_content: str) -> tuple[str, str]:
    """Extract ``(binary, poc_path)`` from the wrapper's run branch.

    The wrapper is a 27-line script whose run branch is a single line,
    ``/out/<fuzz_target> /tmp/poc``, repeated in the ``elif``/``else`` arms.
    Returns ``("", "")`` when it cannot be parsed, so callers can fall back
    to the ``fuzz_target`` column of overview.csv.
    """
    match = _RUN_TARGET_RE.search(wrapper_content)
    if match:
        return match.group(1), match.group(2)
    return "", ""
