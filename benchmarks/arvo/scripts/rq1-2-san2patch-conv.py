from argparse import ArgumentParser
import bisect
import difflib
import json
from multiprocessing.pool import AsyncResult
import multiprocessing as mp
import os
import re
import shutil
import sys
import subprocess as sp
import time
import traceback
import xml.etree.ElementTree as ET
from typing import Dict, List, Set, Tuple

import pandas as pd

import docker
import minibenchmark

# gpac-383825169, gpac-42532224, gpac-42531310, ffmpeg-42527871, libxml2-424613315, libxml2-424229869
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','..','..'))
CONTAINER_ROOT_DIR = '/root/project/metac'

sys.path.insert(0, os.path.join(ROOT_DIR, 'san2patch', 'san2patch'))
from san2patch.patching.validator import _build_project  # noqa: E402


def clean_generated_source(work_dir:str, *names:str):
    """Remove the source tree copies a run leaves behind in the bug's work directory.

    Each run copies `source` into a working tree of its own and never takes it back out,
    so a bug ends up holding several full checkouts. `source` itself is the pristine
    reference the rest of the pipeline reads, so only the copies go.
    """
    for name in names:
        path = os.path.join(work_dir, name)
        if not os.path.isdir(path):
            continue
        print(f'Removing generated source directory {path}', file=sys.stderr, flush=True)
        shutil.rmtree(path, ignore_errors=True)


def patch(project:str, bug_id:int, diff_file_path:str):
    work_dir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    patch_source_dir = os.path.join(work_dir, 'san2patch-baseline-source')
    if os.path.exists(patch_source_dir):
        shutil.rmtree(patch_source_dir)
    shutil.copytree(os.path.join(work_dir, 'source'), patch_source_dir)

    # Initial build
    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    cont_patch_source_dir = os.path.join(container_work_dir, 'san2patch-baseline-source')
    cmd = ['python3', os.path.join(container_work_dir, 'build.py'), project, str(bug_id),
           cont_patch_source_dir, '-o', '/out/my', '-j', '10']
    # Configure with the same -pthread flags used by clean_build/build. The later
    # build() step runs with --skip-configure and reuses the Makefile generated
    # here, so configure and that build must agree on threading; otherwise the
    # link fails with "undefined reference to pthread_key_delete / DSO missing".
    new_env = dict()
    new_env['CFLAGS'] = '-pthread'
    new_env['CXXFLAGS'] = '-pthread'
    new_env['LDFLAGS'] = '-pthread'
    res = docker.exec_docker_cmd(cmd, bug_id, get_output=True, env=new_env)
    if res.returncode != 0:
        print(f'Failed to initial build baseline source for {project}-{bug_id} with error: {res.stdout.decode("utf-8")}', file=sys.stderr)
        return False, 0.
    
    cmd = ['git', 'apply', '--unidiff-zero', '--ignore-whitespace', diff_file_path]
    start_time = time.time()
    res = sp.run(cmd, cwd=patch_source_dir, capture_output=True)
    patch_time = time.time() - start_time
    if res.returncode != 0:
        print(f'Failed to apply patch for {project}-{bug_id} with error: {res.stderr.decode("utf-8")}', file=sys.stderr)
        return False, patch_time
    else:
        print(f'Patch applied successfully for {project}-{bug_id} in {patch_time:.2f} seconds', file=sys.stderr)
        return True, patch_time


def build(project:str, bug_id:int, san:str = 'asan'):
    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    patch_source_dir = os.path.join(container_work_dir, 'san2patch-baseline-source')
    # Shared with ArvoValidator.build_test() (dyninst's own build) -- see _build_project()'s
    # own docstring for why only the compile recipe, not the source tree, is unified.
    # jobs=1: build.py's own default (this call never specified -j before); extra_flags=
    # '-pthread': patch()'s own initial configuring build used -pthread for CFLAGS/CXXFLAGS/
    # LDFLAGS too, and this --skip-configure rebuild has to agree with the Makefile that
    # generated, or the link fails with "undefined reference to pthread_key_delete".
    start_time = time.time()
    ok, stderr = _build_project(f'arvo-{bug_id}', project, bug_id, container_work_dir,
                                patch_source_dir, '/out/my', san, jobs=1, skip_configure=True,
                                extra_flags='-pthread')
    build_time = time.time() - start_time
    if not ok:
        print(f'Failed to build patched source for {project}-{bug_id} with error: {stderr}', file=sys.stderr)
        return False, build_time
    else:
        print(f'Patched source built successfully for {project}-{bug_id} in {build_time:.2f} seconds', file=sys.stderr)
        return True, build_time
    

def test_poc(project:str, bug_id:int, binary:str, expect_fail = False, run_idx: int = 0):
    work_dir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))

    # Setup env var
    new_env = dict()
    new_env['ASAN_OPTIONS'] = 'detect_leaks=0'
    new_env['UBSAN_OPTIONS'] = 'abort_on_error=1:print_stacktrace=1'
    new_env['LIBRARY_PATH'] = '/usr/local/lib:' + new_env.get('LIBRARY_PATH', '')
    new_env['LD_LIBRARY_PATH'] = '/usr/local/lib:' + new_env.get('LD_LIBRARY_PATH', '')
    for k, v in new_env.items():
        print(f"export {k}='{v}'")

    # Setup test command
    san2patch_out_dir = os.path.join(work_dir, 'san2patch-deepseek')
    binary_path = os.path.join('/out/my', binary)

    # Run test
    with open(os.path.join(san2patch_out_dir, f'san2patch-test_run{run_idx}.log'), 'wb') as output_log:
        try:
            start_time = time.time()
            res = docker.exec_docker_cmd([binary_path, '/tmp/poc'], bug_id, env=new_env, get_output=True, timeout=300.)
            exec_time = time.time() - start_time
            output_log.write(res.stdout)
        except sp.TimeoutExpired as e:
            exec_time = 300.
            output_log.write(f'Execution timed out after 300 seconds.'.encode('utf-8'))
            print(f'Failed to run PoC due to timeout for {project}-{bug_id}')
            return False, exec_time
    if b'with RTLD_DEEPBIND flag' in res.stdout:
        print(f'Failed to run PoC: sanitizer aborted before the PoC ran for {project}-{bug_id}')
        return False, exec_time
    if b'AddressSanitizer' in res.stdout or res.returncode == 139:
        if expect_fail:
            print(f'Expected to fail for {project}-{bug_id}')
            return True, exec_time
        else:
            print(f'Failed to run PoC due to ASAN error for {project}-{bug_id}')
            return False, exec_time
    elif project != 'php-src' and (b'UndefinedBehaviorSanitizer' in res.stdout or
                                   b'runtime error' in res.stdout):
        if expect_fail:
            print(f'Expected to fail for {project}-{bug_id}')
            return True, exec_time
        else:
            print(f'Failed to run PoC due to UBSAN error for {project}-{bug_id}')
            return False, exec_time
    elif res.returncode == 134:
        print(f'Failed to run PoC due to terrible error in meta-program or interpreter for {project}-{bug_id}')
        return False, exec_time
    
    if expect_fail:
        print(f'Expected to fail but passed when testing for {project}-{bug_id}')
        return False, exec_time
    else:
        print(f'{project}-{bug_id} metapro patch test success with return code {res.returncode} in {exec_time:.2f} seconds')
        return True, exec_time # return code != 0 also success


def _load_stage_result(san2patch_dir: str, i: int) -> dict:
    """Read <san2patch_dir>/result_stage_0_<i>.json -> {attempt_id: result_str}.

    san2patch records each generated patch's outcome under
    <strategy>/attempts/<attempt_id>/result (e.g. 'success', 'func_test_failed',
    'build_failed'). The diff files are named cur-patch_<attempt_id>.diff, so the
    attempt_id is what we look up. The result file lives directly under san2patch/
    (a sibling of gen_diff/). Returns {} if it is missing or unreadable.
    """
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


def gen_plausible_patch_config_for_bug(project: str, bug_id: int, fuzz_target: str, san:str = 'asan',
                                       run_idx: int = 0):
    """Run one bug and drop the build tree it created.

    `patch()` copies `source` into `san2patch-baseline-source` and the build happens there,
    so the tree is only of use until the PoC has run. It is removed however the run ends --
    a failed build or a raised exception leaves one behind just as a success does.
    """
    work_dir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    try:
        return _gen_plausible_patch_config_for_bug(project, bug_id, fuzz_target, san, run_idx)
    finally:
        clean_generated_source(work_dir, 'san2patch-baseline-source')


def _gen_plausible_patch_config_for_bug(project: str, bug_id: int, fuzz_target: str, san:str = 'asan',
                                        run_idx: int = 0):
    """Generate a patch config for plausible patch by San2Patch of one bug.

    `run_idx` (0-based) names this call's result JSON/log distinctly from every other
    repetition of the same bug (see RUN_COUNT in __main__), so running the whole
    experiment RUN_COUNT times never overwrites a previous run's result.
    """
    project_workdir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    docker.stop_container(bug_id)
    docker.start_container(bug_id)
    
    # Find first plausible patch
    diff_file_path = ''
    for i in range(5):
        stage_dir = os.path.join(project_workdir, 'san2patch-deepseek', 'gen_diff', f'stage_0_{i}')
        if not os.path.exists(stage_dir):
            continue
        stage_results = _load_stage_result(os.path.join(project_workdir, 'san2patch-deepseek'), i)
        for file in os.listdir(stage_dir):
            if file.endswith('.diff') and file != 'cur-patch.diff':
                attempt_id = file.split('.')[0].rsplit('cur-patch_', 1)[-1]
                result = stage_results.get(attempt_id)
                if result in ('success', 'verify_failed'):
                    # Found a plausible patch
                    diff_file_path = os.path.join(stage_dir, file)
                    break
        else:
            continue
        break

    baseline_result_path = os.path.join(project_workdir, f'result-san2patch-baseline_run{run_idx}.json')

    if not diff_file_path:
        print(f'[{project}-{bug_id}] no plausible patch found by san2patch, skip generating patch config for plausible patch', file=sys.stderr, flush=True)
        with open(baseline_result_path, 'w') as f:
            json.dump({
                'result': 'N/A',
                'patch_time': '-',
                'build_time': '-',
                'test_time': '-',
            }, f)
        docker.stop_container(bug_id)
        return False
    
    # Patch
    patch_result, patch_time = patch(project, bug_id, diff_file_path)
    if not patch_result:
        print(f'[{project}-{bug_id}] failed to apply plausible patch generated by san2patch, skip generating patch config for plausible patch', file=sys.stderr, flush=True)
        with open(baseline_result_path, 'w') as f:
            json.dump({
                'result': 'N',
                'patch_time': patch_time,
                'build_time': '-',
                'test_time': '-',
            }, f)
        docker.stop_container(bug_id)
        return False
    
    # Build
    build_result, build_time = build(project, bug_id, san)
    if not build_result:
        print(f'[{project}-{bug_id}] failed to build source patched with plausible patch generated by san2patch, skip generating patch config for plausible patch', file=sys.stderr, flush=True)
        with open(baseline_result_path, 'w') as f:
            json.dump({
                'result': 'N',
                'patch_time': patch_time,
                'build_time': build_time,
                'test_time': '-',
            }, f)
        docker.stop_container(bug_id)
        return False

    # Test
    test_result, test_time = test_poc(project, bug_id, fuzz_target, run_idx=run_idx)
    if not test_result:
        print(f'[{project}-{bug_id}] failed to test source patched with plausible patch generated by san2patch, skip generating patch config for plausible patch', file=sys.stderr, flush=True)
    else:
        print(f'[{project}-{bug_id}] plausible patch generated by san2patch passed the test', file=sys.stderr, flush=True)

    with open(baseline_result_path, 'w') as f:
        json.dump({
            'result': 'Y' if test_result else 'N',
            'patch_time': patch_time,
            'build_time': build_time,
            'test_time': test_time,
        }, f)
    docker.stop_container(bug_id)
    print(f'[{project}-{bug_id}] success to test!', file=sys.stderr, flush=True)
    return test_result


def _on_worker_error(exc: BaseException):
    """pool.apply_async swallows worker exceptions; print the full traceback to
    stderr exactly like Python's default handler. multiprocessing attaches the
    worker-side stack as the exception's __cause__ (a RemoteTraceback), so this
    surfaces the original crash site, not just the main-process re-raise.
    """
    traceback.print_exception(type(exc), exc, exc.__traceback__)


# Metric keys read out of a run's result-san2patch-baseline_run<i>.json and collected
# into the boxplot-ready dict below (see __main__).
_RESULT_METRICS = ('result', 'patch_time', 'build_time', 'test_time')

# How many times to repeat the whole experiment per bug, so the boxplot has a real
# run-to-run distribution rather than one point per bug.
RUN_COUNT = 10


if __name__ == "__main__":
    parser = ArgumentParser(prog='run-san2patch', description='Run binary patcher to apply dev patch')
    parser.add_argument('-p', '--project', type=str, nargs='*', default=[],
                        help='Projects to checkout. Multiple projects available. Default: None')
    parser.add_argument('-b', '--bug-id', type=int, nargs='*', default=[],
                        help='Bug IDs to checkout. Multiple bug IDs available. Default: None')
    parser.add_argument('-j', '--jobs', type=int, default=1,
                        help='Number of parallel jobs to run. Default: 1')
    parser.add_argument('--use-msan', action='store_true',
                        help='Use bugs which use MSAN. Default: False')
    parser.add_argument('-m', '--mini', action='store_true',
                        help='Run mini benchmark on a small set of 5 bugs per project. Default: False')
    parser.add_argument('--dev-patch', action='store_true',
                        help='Generate patch config for developer patch instead of san2patch generated patches. Default: False')
    parser.add_argument('-n', '--runs', type=int, default=RUN_COUNT,
                        help=f'Number of times to repeat the experiment per bug. Default: {RUN_COUNT}')
    args = parser.parse_args()

    projects:List[str] = args.project
    bug_ids:List[int] = args.bug_id

    # TODO: Temporary do not run whole benchmark
    if len(projects) == 0 and len(bug_ids) == 0:
        print('Either -p or -b option required', file=sys.stderr)
        exit(1)

    # Filter dataframe based on arguments
    df = pd.read_csv(os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'overview.csv'))
    projects_dir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects')

    # Boxplot-ready results, kept separate per project (one plot per project) and per bug
    # within a project (one boxplot-input list of RUN_COUNT values per bug, per metric):
    #   final_result[project][bug_id][metric] -> [value_run0, value_run1, ...]
    final_result: Dict[str, Dict[int, Dict[str, list]]] = {}

    runned_bugs:Set[Tuple[str,int]] = set()
    for run_idx in range(args.runs):
        print(f'=== Run {run_idx + 1}/{args.runs} ===', file=sys.stderr, flush=True)
        pool = mp.Pool(processes=args.jobs)
        run_bugs: Set[Tuple[str, int]] = set()
        for index, row in df.iterrows():
            project = row['project']
            bug_id = row['localId']
            if (row['submodule_bug'] != 'N' or row['language'] != 'c' or row['patch url available?'] != 'Y' or
                row['ubuntu version'] != 20):
                # Excluded bugs
                continue
            if not args.use_msan and row['sanitizer'] == 'msan':
                # Exclude MSan
                continue
            if len(bug_ids) > 0 and bug_id not in bug_ids:
                # Test specified bugs only
                continue
            if len(projects) > 0 and project not in projects:
                # Test specified projects only
                continue
            if args.mini and str(bug_id) not in minibenchmark.ARVO_MINI[project]:
                # If mini benchmark, only run on a small set of bugs
                continue

            docker.start_container(bug_id)
            pool.apply_async(gen_plausible_patch_config_for_bug,
                             args=(project, bug_id, row['fuzz_target'], row['sanitizer'], run_idx),
                             error_callback=_on_worker_error)
            run_bugs.add((project, bug_id))

        pool.close()
        pool.join()
        runned_bugs |= run_bugs

        if args.dev_patch:
            continue

        # Read this run's per-bug result JSON (see gen_plausible_patch_config_for_bug)
        # and append each metric's value onto that bug's list.
        for project, bug_id in sorted(run_bugs):
            result_path = os.path.join(projects_dir, project, str(bug_id),
                                       f'result-san2patch-baseline_run{run_idx}.json')
            try:
                with open(result_path) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                data = {}
            bug_result = final_result.setdefault(project, {}).setdefault(
                bug_id, {m: [] for m in _RESULT_METRICS})
            for metric in _RESULT_METRICS:
                bug_result[metric].append(data.get(metric))

    if args.dev_patch:
        exit(0)

    # One JSON file per project (not a combined CSV), so each is a self-contained input to
    # that project's own boxplot: {"<bug_id>": {"<metric>": [RUN_COUNT values], ...}, ...}
    for project, per_bug in final_result.items():
        out_path = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', f'rq1-san2patch-conv-{project}.json')
        with open(out_path, 'w') as f:
            json.dump({str(bug_id): metrics for bug_id, metrics in per_bug.items()}, f, indent=2)
        print(f'Wrote {out_path}', file=sys.stderr, flush=True)