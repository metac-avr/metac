"""rq3-san2patch.py for ContraFix: every validation approach, repeated, per bug.

Runs ContraFix (contrafix/arvo) over the selected bugs once per validation approach
(--mode) and per repetition (-n), so the results carry a run-to-run distribution
rather than one point per bug -- ContraFix is not deterministic either.

Each (project, mode, run) triple gets its own results directory,
<results-root>/<project>/<mode>_run<i>: ContraFix keeps its experience knowledge base
per directory, so sharing one would let a repetition -- or another project -- feed on
the previous one's experiences.

Approaches run one after another for a bug: metapro and combined drive the bug's
arvo-<bug_id> container and its metapro-out/, and dyninst the same container and its
contrafix-dyninst-source/ (see contrafix/arvo/dyninst.py), which conv does not, but
which the approaches share with each other. Bugs within a batch still run in parallel
-- they have their own containers.

On a host that keeps no ARVO containers, --checkout has each bug checked out (with
metapro built inside the container) before it is solved, and --remove-container drops
the container again afterwards.

Usage:
    python rq3-contrafix.py -p libxml2 --mode all -n 10 -j 8
    python rq3-contrafix.py -b 42510333 --mode metapro -n 3
    python rq3-contrafix.py -p ndpi --mode metapro --checkout --remove-container -j 16
"""
from argparse import ArgumentParser
import importlib.util
import multiprocessing as mp
import os
import sys
from typing import List

import pandas as pd

import minibenchmark


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', '..'))
DEFAULT_RESULTS_ROOT = os.path.join(ROOT_DIR, 'contrafix', 'results_rq3')

# The validation approaches --mode all expands to, in the order they are run.
ALL_MODES = ('conv', 'metapro', 'dyninst', 'combined')

# How many times to repeat the whole experiment per bug. Matches rq3-san2patch.py.
RUN_COUNT = 10


def _load_runner():
    """Import run-contrafix.py, whose hyphenated name blocks a normal import."""
    path = os.path.join(SCRIPT_DIR, 'run-contrafix.py')
    spec = importlib.util.spec_from_file_location('run_contrafix', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules['run_contrafix'] = module
    spec.loader.exec_module(module)
    return module


def results_dir_for(results_root: str, project: str, mode: str, run_idx: int) -> str:
    return os.path.join(results_root, project, f'{mode}_run{run_idx}')


def run(project: str, bug_id: int, results_dir: str, mode: str, run_idx: int,
        keep_image: bool = False, resume: bool = False,
        checkout: bool = False, remove_container: bool = False):
    """One bug, one approach, one repetition."""
    runner = _load_runner()
    print(f'=== {project}-{bug_id} [{mode}, run {run_idx}] ===', file=sys.stderr, flush=True)
    return runner.run(project, bug_id, results_dir,
                      keep_image=keep_image, mode=mode, resume=resume,
                      checkout=checkout, remove_container=remove_container)


def _on_worker_error(exc: BaseException):
    print(f'rq3 worker raised: {exc!r}', file=sys.stderr)


if __name__ == "__main__":
    parser = ArgumentParser(prog='rq3-contrafix',
                            description='Run ContraFix under every validation approach, repeatedly')
    parser.add_argument('-p', '--project', type=str, nargs='*', default=[],
                        help='Projects to run. Multiple projects available. Default: None')
    parser.add_argument('-b', '--bug-id', type=int, nargs='*', default=[],
                        help='Bug IDs to run. Multiple bug IDs available. Default: None')
    parser.add_argument('-j', '--jobs', type=int, default=1,
                        help='Number of bugs to run in parallel. Default: 1')
    parser.add_argument('--use-msan', action='store_true',
                        help='Use bugs which use MSAN. Default: False')
    parser.add_argument('-m', '--mini', action='store_true',
                        help='Run mini benchmark on a small set of 5 bugs per project. Default: False')
    parser.add_argument('--mode', choices=['conv', 'metapro', 'dyninst', 'combined', 'all'],
                        default='metapro',
                        help="Validation approach, as San2Patch's rq3 script. 'all' runs every "
                             "approach. Default: metapro")
    parser.add_argument('-n', '--runs', type=int, default=RUN_COUNT,
                        help=f'Number of times to repeat the experiment per bug, for each mode. '
                             f'Default: {RUN_COUNT}')
    parser.add_argument('--results-root', type=str, default=DEFAULT_RESULTS_ROOT,
                        help=f'Parent of the per-(mode, run) results directories. '
                             f'Default: {DEFAULT_RESULTS_ROOT}')
    parser.add_argument('--checkout', action='store_true',
                        help="Check a bug out (container + metapro build) when it has no "
                             "arvo-<bug_id> container, via scripts/checkout.py. For hosts that "
                             "keep no checkouts. Default: False")
    parser.add_argument('--remove-container', action='store_true',
                        help="Delete the bug's arvo container once it is solved, to bound disk "
                             "use. Pair with --checkout. Default: False")
    parser.add_argument('--resume', action='store_true',
                        help='Within each (mode, run) directory, skip bugs that already have a '
                             'result, to carry on an interrupted run. Default: False')
    parser.add_argument('--keep-image', action='store_true',
                        help='Keep each bug\'s prepared contrafix-f2r image between repetitions. '
                             'Default: False (removed after every repetition, and prepared again '
                             'for the next one)')
    args = parser.parse_args()

    modes: List[str] = list(ALL_MODES) if args.mode == 'all' else [args.mode]
    projects: List[str] = args.project
    bug_ids: List[int] = args.bug_id
    results_root = os.path.abspath(args.results_root)

    if len(projects) == 0 and len(bug_ids) == 0:
        print('Either -p or -b option required', file=sys.stderr)
        exit(1)

    df = pd.read_csv(os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'overview.csv'))

    # One pool per (run, mode) batch: for a given bug the approaches share the
    # arvo-<bug_id> container and its metapro tree, so they have to run one after
    # another. With --mode all this is len(ALL_MODES) * args.runs batches.
    for run_idx in range(args.runs):
        for mode in modes:
            print(f'=== Run {run_idx + 1}/{args.runs} | mode {mode} ===',
                  file=sys.stderr, flush=True)

            pool = mp.Pool(processes=args.jobs)
            for index, row in df.iterrows():
                project = row['project']
                bug_id = row['localId']
                if (row['submodule_bug'] != 'N' or row['language'] != 'c' or
                        row['patch url available?'] != 'Y' or row['ubuntu version'] != 20):
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

                project_workdir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects',
                                               project, str(bug_id))
                os.makedirs(project_workdir, exist_ok=True)
                results_dir = results_dir_for(results_root, project, mode, run_idx)
                os.makedirs(results_dir, exist_ok=True)
                pool.apply_async(run, args=(project, bug_id, results_dir, mode, run_idx),
                                 kwds={'keep_image': args.keep_image, 'resume': args.resume,
                                       'checkout': args.checkout,
                                       'remove_container': args.remove_container},
                                 error_callback=_on_worker_error)

            pool.close()
            pool.join()
