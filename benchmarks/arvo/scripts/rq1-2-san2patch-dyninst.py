"""RQ1/RQ2 efficiency experiment for the Dyninst patch method.

Counterpart of rq1-2-san2patch-conv.py / rq1-2-san2patch-metac.py: no LLM is involved.
For each bug it takes the first patch San2Patch already judged plausible (the same
selection those scripts make), applies it to the bug's san2patch-source tree the way
the pipeline's own patching step would, and then drives ArvoValidator.dyninst_patch()
and dyninst_test() directly -- the same two calls dyninst_binary_patch() in
runpatch_graph.py makes (including its forced-whole-file retry).

Prerequisites, per bug (see benchmarks/arvo/scripts/checkout.py --setup-dyninst):
  * container arvo-<bug_id> is up, with Dyninst, mutator_launch and the compiler wrapper
    installed, and
  * ArvoValidator.setup()'s build has already run with that wrapper active, so that
    san2patch-deepseek/output/<fuzz_target> and the compile-invocation log exist.
Neither is done here.

Needs the san2patch environment (san2patch/.venv), since it imports ArvoValidator:
    san2patch/.venv/bin/python rq1-2-san2patch-dyninst.py -p libxml2 -j 8

Per-run result (project dir, result-san2patch-dyninst_run<i>.json) and the aggregated
per-project file rq1-boxplot.py reads (rq1-san2patch-dyninst-result-<project>.json):
    result        'Y' PoC no longer crashes | 'N' failed | 'N/A' no plausible patch
    patch_time    locating the patched functions in the diff + Dyninst loadLibrary/
                  replaceFunction (the [TIMING] patch_apply_ms of mutator_launch)
    build_time    compiling/linking libpatch.so (dyninst_patch())
    test_time     whole dyninst_test() call (launch + patch apply + PoC run)
    launch_time   Dyninst processCreate+image analysis (part of test_time; kept apart
                  because it is a per-session cost, not a per-patch one)
    run_time      the patched process running the PoC (part of test_time)
    retried       True if the first attempt hit a mechanism failure and was redone with
                  whole-file compilation; every time metric then covers both attempts
    pic_archive_time  one-time build of the project PIC archive (cached per bug, so
                  only the first run pays it; not part of any other metric)
"""
from argparse import ArgumentParser
import json
import multiprocessing as mp
import os
import re
import shutil
import subprocess as sp
import sys
import time
import traceback
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'san2patch'))

import pandas as pd

import minibenchmark
from san2patch.patching.validator import ArvoValidator, extract_patched_function_locations

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..'))
# The bug's work dir is used both on the host and inside the container by ArvoValidator, so it
# has to be spelled with the container-visible prefix (host_mount_path is mounted at /root/project).
CONTAINER_ROOT_DIR = '/root/project/metac'
OUTPUT_DIR = 'san2patch-deepseek'

_TIMING_RE = re.compile(r'launch_ms=([\d.]+) patch_apply_ms=([\d.]+) run_ms=([\d.]+)')
_DIFF_FILE_RE = re.compile(r'^\+\+\+ (?:b/)?(\S+)', re.M)


def _load_stage_result(san2patch_dir: str, i: int) -> dict:
    """<san2patch_dir>/result_stage_0_<i>.json -> {attempt_id: result_str} (as in the conv/metac scripts)."""
    result_path = os.path.join(san2patch_dir, f'result_stage_0_{i}.json')
    if not os.path.exists(result_path):
        return {}
    try:
        with open(result_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}
    flat = {}
    for strat in data.values():
        if not isinstance(strat, dict):
            continue
        for attempt_id, info in strat.get('attempts', {}).items():
            if isinstance(info, dict) and 'result' in info:
                flat[attempt_id] = info['result']
    return flat


def find_plausible_patch(project_workdir: str) -> Tuple[Optional[str], Optional[str]]:
    """(diff path, stage_id) of the first patch San2Patch judged plausible, same selection as the
    conv/metac scripts."""
    san2patch_dir = os.path.join(project_workdir, OUTPUT_DIR)
    for i in range(5):
        stage_dir = os.path.join(san2patch_dir, 'gen_diff', f'stage_0_{i}')
        if not os.path.exists(stage_dir):
            continue
        stage_results = _load_stage_result(san2patch_dir, i)
        for file in os.listdir(stage_dir):
            if file.endswith('.diff') and file != 'cur-patch.diff':
                attempt_id = file.split('.')[0].rsplit('cur-patch_', 1)[-1]
                if stage_results.get(attempt_id) in ('success', 'verify_failed'):
                    return os.path.join(stage_dir, file), f'stage_0_{i}'
    return None, None


def _diff_files(diff_path: str) -> List[str]:
    with open(diff_path, errors='replace') as f:
        return _DIFF_FILE_RE.findall(f.read())


def _restore_files(project_workdir: str, source_dir: str, files: List[str]):
    """Put the pristine copy of each file back, so a run never sees an earlier run's (or a
    crashed run's) patch."""
    for rel in files:
        src = os.path.join(project_workdir, 'source', rel)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(source_dir, rel))


def _apply_patch_to_source(diff_path: str, source_dir: str) -> Tuple[bool, str]:
    """Write the LLM patch into san2patch-source, as the pipeline does before it builds/tests."""
    res = sp.run(['patch', '-p1', '--no-backup-if-mismatch', '-i', diff_path], cwd=source_dir,
                 capture_output=True, text=True)
    return res.returncode == 0, res.stdout + res.stderr


# The global-data sync wrapper (see _DYN_RUNTIME_C in validator.py) is off by default now (see
# dyninst_patch()'s own docstring): a raw byte copy of a global whose type holds a heap pointer
# duplicates that pointer into both copies, and whichever side frees and replaces it, the sync can
# hand the other side a stale value it later frees again -- confirmed on php-src/42531112 (the
# wrapper made a call never return) and independently on libxml2/42517254 (ContraFix's own
# already-verified patch double-freed, in unrelated error-reporting code the patch never touches,
# only with the wrapper on). Real accuracy loss remains when it's off and a patched function
# genuinely needs a global initialised at runtime, but a spurious result is worse than that gap.


def _run_dyninst(pv: ArvoValidator, locations: List[Dict], sync_globals: bool = False):
    """dyninst_patch() then dyninst_test(), with the same forced-whole-file retry as
    dyninst_binary_patch() in runpatch_graph.py. Returns (ok, build_time, test_time, output)."""
    build_time = test_time = 0.
    outputs = []

    def once(force_whole_file: bool):
        nonlocal build_time, test_time
        # Fresh libpatch every time, so build_time is a real compile+link (the PIC archive one level up stays cached)
        shutil.rmtree(pv._dyninst_out_dir(), ignore_errors=True)
        ok, t, out = pv.dyninst_patch(locations, force_whole_file=force_whole_file, sync_globals=sync_globals)
        build_time += t
        outputs.append(out)
        if not ok:
            return False, out
        ok, t, out = pv.dyninst_test(locations)
        test_time += t
        outputs.append(out)
        return ok, out

    ok, out = once(False)
    if not ok and ('FAILED:' in out or 'symbol lookup error:' in out):
        outputs.append('[retry: forced whole-file compile for every location]')
        ok, out = once(True)
    return ok, build_time, test_time, '\n'.join(outputs)


def run_one(project: str, bug_id: int, fuzz_target: str, run_idx: int = 0):
    project_workdir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    result_path = os.path.join(project_workdir, f'result-san2patch-dyninst_run{run_idx}.json')
    log_path = os.path.join(project_workdir, OUTPUT_DIR, f'san2patch-dyninst-test_run{run_idx}.log')

    def write(result: str, **metrics):
        data = {'result': result, 'patch_time': '-', 'build_time': '-', 'test_time': '-',
                'launch_time': '-', 'run_time': '-', 'pic_archive_time': '-', 'retried': '-'}
        data.update(metrics)
        with open(result_path, 'w') as f:
            json.dump(data, f)
        return result == 'Y'

    diff_path, stage_id = find_plausible_patch(project_workdir)
    if not diff_path:
        print(f'[{project}-{bug_id}] no plausible patch found by san2patch, skip', file=sys.stderr, flush=True)
        return write('N/A')

    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    pv = ArvoValidator(
        project=project, bug_id=bug_id, work_dir=container_work_dir,
        binary=os.path.join(container_work_dir, OUTPUT_DIR, 'output', fuzz_target),
        poc=os.path.join(container_work_dir, 'poc'), stage_id=stage_id, output_dir=OUTPUT_DIR,
    )
    touched = _diff_files(diff_path)
    try:
        _restore_files(project_workdir, pv.source_dir, touched)
        ok, msg = _apply_patch_to_source(diff_path, pv.source_dir)
        if not ok:
            print(f'[{project}-{bug_id}] failed to apply {diff_path} to san2patch-source: {msg}',
                  file=sys.stderr, flush=True)
            return write('N')

        # Locate the patched functions (part of patch_time).
        t = time.time()
        locations = extract_patched_function_locations(diff_path, pv.source_dir)
        parse_time = time.time() - t
        if not locations:
            print(f'[{project}-{bug_id}] no patched function resolved from the diff', file=sys.stderr, flush=True)
            return write('N', patch_time=parse_time)

        # One-time per-bug PIC archive (cached on disk); kept out of every other metric.
        pic_time = 0.
        if not os.path.exists(pv._dyninst_pic_archive_path()):
            t = time.time()
            cc_log = pv._dyninst_read_cc_log()
            if not cc_log or pv._dyninst_ensure_pic_archive(cc_log, pv.source_dir) is None:
                print(f'[{project}-{bug_id}] could not build the PIC archive (is the compiler wrapper '
                      f'log present?)', file=sys.stderr, flush=True)
                return write('N')
            pic_time = time.time() - t

        ok, build_time, test_time, output = _run_dyninst(pv, locations)
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, 'w') as f:
            f.write(output)

        # Every attempt's [TIMING] line is summed, to match build_time/test_time (which cover the
        # forced-whole-file retry too when one happened).
        timing = _TIMING_RE.findall(output)
        if timing:
            launch_time = sum(float(t[0]) for t in timing) / 1000
            apply_time = sum(float(t[1]) for t in timing) / 1000
            run_time = sum(float(t[2]) for t in timing) / 1000
        else:
            launch_time = apply_time = run_time = '-'
        patch_time = parse_time + apply_time if isinstance(apply_time, float) else '-'

        print(f'[{project}-{bug_id}] dyninst {"passed" if ok else "failed"}', file=sys.stderr, flush=True)
        return write('Y' if ok else 'N', patch_time=patch_time, build_time=build_time, test_time=test_time,
                     launch_time=launch_time, run_time=run_time, pic_archive_time=pic_time,
                     retried='[retry:' in output)
    finally:
        _restore_files(project_workdir, pv.source_dir, touched)


def _on_worker_error(exc: BaseException):
    traceback.print_exception(type(exc), exc, exc.__traceback__)


_RESULT_METRICS = ('result', 'patch_time', 'build_time', 'test_time',
                   'launch_time', 'run_time', 'pic_archive_time', 'retried')
RUN_COUNT = 10


if __name__ == "__main__":
    parser = ArgumentParser(prog='rq1-2-san2patch-dyninst',
                            description='Time the Dyninst patch method on patches San2Patch already generated')
    parser.add_argument('-p', '--project', type=str, nargs='*', default=[],
                        help='Projects to run. Default: None')
    parser.add_argument('-b', '--bug-id', type=int, nargs='*', default=[],
                        help='Bug IDs to run. Default: None')
    parser.add_argument('-j', '--jobs', type=int, default=1,
                        help='Number of parallel jobs (bugs) to run. Default: 1')
    parser.add_argument('--use-msan', action='store_true', help='Use bugs which use MSAN. Default: False')
    parser.add_argument('-m', '--mini', action='store_true',
                        help='Run mini benchmark on a small set of 5 bugs per project. Default: False')
    parser.add_argument('-n', '--runs', type=int, default=RUN_COUNT,
                        help=f'Number of times to repeat the experiment per bug. Default: {RUN_COUNT}')
    args = parser.parse_args()

    projects: List[str] = args.project
    bug_ids: List[int] = args.bug_id
    if len(projects) == 0 and len(bug_ids) == 0:
        print('Either -p or -b option required', file=sys.stderr)
        exit(1)

    df = pd.read_csv(os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'overview.csv'))
    projects_dir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects')

    # final_result[project][bug_id][metric] -> [value_run0, value_run1, ...]
    final_result: Dict[str, Dict[int, Dict[str, list]]] = {}

    for run_idx in range(args.runs):
        print(f'=== Run {run_idx + 1}/{args.runs} ===', file=sys.stderr, flush=True)
        pool = mp.Pool(processes=args.jobs)
        run_bugs: Set[Tuple[str, int]] = set()
        for index, row in df.iterrows():
            project = row['project']
            bug_id = row['localId']
            if (row['submodule_bug'] != 'N' or row['language'] != 'c' or row['patch url available?'] != 'Y' or
                    row['ubuntu version'] != 20):
                continue
            if not args.use_msan and row['sanitizer'] == 'msan':
                continue
            if len(bug_ids) > 0 and bug_id not in bug_ids:
                continue
            if len(projects) > 0 and project not in projects:
                continue
            if args.mini and str(bug_id) not in minibenchmark.ARVO_MINI[project]:
                continue

            pool.apply_async(run_one, args=(project, bug_id, row['fuzz_target'], run_idx),
                             error_callback=_on_worker_error)
            run_bugs.add((project, bug_id))

        pool.close()
        pool.join()

        for project, bug_id in sorted(run_bugs):
            result_path = os.path.join(projects_dir, project, str(bug_id),
                                       f'result-san2patch-dyninst_run{run_idx}.json')
            try:
                with open(result_path) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                data = {}
            bug_result = final_result.setdefault(project, {}).setdefault(
                bug_id, {m: [] for m in _RESULT_METRICS})
            for metric in _RESULT_METRICS:
                bug_result[metric].append(data.get(metric))

    for project, per_bug in final_result.items():
        out_path = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', f'rq1-san2patch-dyninst-result-{project}.json')
        # Merge into the existing aggregate so a run over a subset of bugs never drops other bugs' results.
        merged: Dict[str, Dict[str, list]] = {}
        if os.path.exists(out_path):
            try:
                with open(out_path) as f:
                    merged = json.load(f)
            except (json.JSONDecodeError, OSError):
                merged = {}
        merged.update({str(bug_id): metrics for bug_id, metrics in per_bug.items()})
        with open(out_path, 'w') as f:
            json.dump(merged, f, indent=2)
        print(f'Wrote {out_path}', file=sys.stderr, flush=True)
