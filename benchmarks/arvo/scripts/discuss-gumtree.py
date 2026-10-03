"""Compare MetaC and GumTree (see rq1-2-san2patch-gumtree.py) results: overall
mean/median total time and plausible-patch success rate/ratio, for san2patch.

Each rq1-2-san2patch-{metac,gumtree}.py script writes one JSON file per project:
    {"<bug_id>": {"<metric>": [value_run0, value_run1, ...], ...}, ...}
A run is only counted for the time statistics if every one of that method's metrics
is numeric for it (a '-'/'N/A' placeholder means that run didn't reach that stage).
For each method this prints three pooled-across-every-project statistics: the total
time *with* test_time (every parsed metric summed), *without* it (test_time
excluded, i.e. just patch/parse time) and *test time only* -- no plot is generated.

GumTree has no contrafix counterpart yet, so the ContraFix section is reported as 0
for both methods rather than a real/N-A mismatch between them.

'result' is 'Y' (plausible patch found and passed the test), 'N' (failed) or 'N/A'
(the method never produced a plausible patch to try at all; excluded from the ratio,
see bug_verdict). This also counts successes/failures per method and prints the
success ratio (dyninst/conv baselines are not part of this comparison).
"""
import glob
import json
import os
import sys
from collections import Counter
from typing import Dict, List

import numpy as np

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..'))
ARVO_DIR = os.path.join(ROOT_DIR, 'benchmarks', 'arvo')

# (method label, result-file glob pattern relative to ARVO_DIR, time metrics parsed per run).
# A run is only counted at all if every one of these metrics is numeric for it
# (a '-'/'N/A' placeholder means that run didn't reach that stage). GumTree has no
# rq1-2-contrafix-gumtree.py yet, so ContraFix is reported as 0 for both methods below.
EXPERIMENTS = [
    ('San2Patch', [
        ('MetaC', 'rq1-san2patch-result-*.json', ('parse_time', 'patch_time', 'test_time')),
        ('GumTree', 'rq1-san2patch-gumtree-result-*.json', ('parse_time', 'patch_time', 'test_time')),
    ]),
]

# Methods reported (as 0) for the ContraFix section -- see module docstring.
CONTRAFIX_PLACEHOLDER_METHODS = ['MetaC', 'GumTree']

# Subset of each method's parsed metrics (see EXPERIMENTS) summed for the "without
# test time" statistic -- i.e. every parsed metric except test_time.
PLOT_TIME_KEYS = {
    'MetaC': ('parse_time',),
    'GumTree': ('parse_time',),
}

# test_time alone (no patch/parse), for the "test time only" statistic.
TEST_ONLY_KEYS = {
    'MetaC': ('test_time',),
    'GumTree': ('test_time',),
}


def project_from_filename(path: str, pattern: str) -> str:
    prefix, suffix = pattern.split('*')
    name = os.path.basename(path)
    return name[len(prefix):len(name) - len(suffix)]


def load_method_times(pattern: str, parse_keys, plot_keys) -> Dict[str, List[float]]:
    """project -> flat list of per-run summed times (one float per bug-run where every
    metric in parse_keys is numeric; the value itself is the sum of only plot_keys)."""
    result: Dict[str, List[float]] = {}
    for path in sorted(glob.glob(os.path.join(ARVO_DIR, pattern))):
        project = project_from_filename(path, pattern)
        with open(path) as f:
            data = json.load(f)
        times: List[float] = []
        for bug_id, metrics in data.items():
            n_runs = len(metrics.get(parse_keys[0], []))
            for run_idx in range(n_runs):
                values = {k: metrics[k][run_idx] for k in parse_keys}
                if all(isinstance(v, (int, float)) for v in values.values()):
                    times.append(sum(values[k] for k in plot_keys))
        result[project] = times
    return result


def bug_verdict(bug_id: str, results: List[str]) -> str:
    """Collapse one bug's per-run 'result' list into a single verdict.

    Returns 'N/A' if every run is 'N/A' (no plausible patch ever generated -- excluded from
    the success ratio). Otherwise returns the majority non-N/A value ('Y' or 'N'), warning to
    stderr if the runs disagree (they're expected to be deterministic).
    """
    non_na = [r for r in results if r != 'N/A']
    if not non_na:
        return 'N/A'
    counts = Counter(non_na)
    if len(counts) > 1:
        print(f'[warn] bug {bug_id} has inconsistent results across runs: {counts}', file=sys.stderr)
    return counts.most_common(1)[0][0]


def count_success(pattern: str) -> Dict[str, int]:
    """{'success': n, 'fail': n, 'na': n} pooled across every project matching pattern."""
    counts = {'success': 0, 'fail': 0, 'na': 0}
    for path in sorted(glob.glob(os.path.join(ARVO_DIR, pattern))):
        with open(path) as f:
            data = json.load(f)
        for bug_id, metrics in data.items():
            verdict = bug_verdict(bug_id, metrics.get('result', []))
            if verdict == 'Y':
                counts['success'] += 1
            elif verdict == 'N':
                counts['fail'] += 1
            else:
                counts['na'] += 1
    return counts


def print_overall_stats(label: str, overall: List[float]) -> None:
    if overall:
        print(f'  {label}: mean={np.mean(overall):.2f}, median={np.median(overall):.2f} '
              f'(n={len(overall)})')
    else:
        print(f'  {label}: mean=N/A, median=N/A (n=0)')


def print_success_stats(counts: Dict[str, int]) -> None:
    cases = counts['success'] + counts['fail']
    ratio = counts['success'] / cases if cases else float('nan')
    print(f'  success={counts["success"]}, fail={counts["fail"]}, ratio={ratio:.2%} '
          f'(na={counts["na"]})')


def main():
    # method -> combined (every experiment pooled together) 'with'/'without'/'test_only' lists.
    combined: Dict[str, Dict[str, List[float]]] = {}
    combined_success: Dict[str, Dict[str, int]] = {}

    for experiment_name, methods in EXPERIMENTS:
        print(f'=== {experiment_name} ===')
        for name, pattern, parse_keys in methods:
            # "with test time": every parsed metric summed (parse_keys == plot_keys).
            with_test = load_method_times(pattern, parse_keys, parse_keys)
            overall_with = [t for times in with_test.values() for t in times]
            # "without test time": only the non-test-time subset summed.
            without_test = load_method_times(pattern, parse_keys, PLOT_TIME_KEYS[name])
            overall_without = [t for times in without_test.values() for t in times]
            # "test time only": just test_time, no patch/parse.
            test_only = load_method_times(pattern, parse_keys, TEST_ONLY_KEYS[name])
            overall_test_only = [t for times in test_only.values() for t in times]

            success_counts = count_success(pattern)

            print(f'{name}:')
            print_overall_stats('with test time', overall_with)
            print_overall_stats('without test time', overall_without)
            print_overall_stats('test time only', overall_test_only)
            print_success_stats(success_counts)

            method_totals = combined.setdefault(name, {'with': [], 'without': [], 'test_only': []})
            method_totals['with'].extend(overall_with)
            method_totals['without'].extend(overall_without)
            method_totals['test_only'].extend(overall_test_only)
            method_success = combined_success.setdefault(name, {'success': 0, 'fail': 0, 'na': 0})
            for key in method_success:
                method_success[key] += success_counts[key]
        print()

    # GumTree has no contrafix counterpart yet -- report 0 for both methods rather than
    # a real (MetaC)/N-A (GumTree) mismatch.
    print('=== ContraFix ===')
    for name in CONTRAFIX_PLACEHOLDER_METHODS:
        print(f'{name}:')
        print('  with test time: mean=0.00, median=0.00 (n=0)')
        print('  without test time: mean=0.00, median=0.00 (n=0)')
        print('  test time only: mean=0.00, median=0.00 (n=0)')
        print('  success=0, fail=0, ratio=0.00% (na=0)')
    print()

    # Combined across every experiment (San2Patch + ContraFix pooled together), per method.
    # ContraFix contributes nothing (see above), so this equals the San2Patch-only totals.
    print('=== Combined (San2Patch + ContraFix) ===')
    for name in combined:
        print(f'{name}:')
        print_overall_stats('with test time', combined[name]['with'])
        print_overall_stats('without test time', combined[name]['without'])
        print_overall_stats('test time only', combined[name]['test_only'])
        print_success_stats(combined_success[name])


if __name__ == '__main__':
    main()
