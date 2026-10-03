"""Read rq1-2-{san2patch,contrafix}-{metac,conv,dyninst}.py results and print overall
mean/median total time per method, for both san2patch and contrafix.

Each rq1-2-*-*.py script writes one JSON file per project:
    {"<bug_id>": {"<metric>": [value_run0, value_run1, ...], ...}, ...}
A run is only counted at all if every one of that method's metrics is numeric for it
(a '-'/'N/A' placeholder means that run didn't reach that stage). For each method this
prints two pooled-across-every-project statistics: the total time *with* test_time
(every parsed metric summed) and *without* it (test_time/run_time excluded, i.e. just
patch/build/parse time) -- no plot is generated.
"""
import glob
import json
import os
from typing import Dict, List

import numpy as np

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..'))
ARVO_DIR = os.path.join(ROOT_DIR, 'benchmarks', 'arvo')

# (method label, result-file glob pattern relative to ARVO_DIR, time metrics parsed per run).
# A run is only counted at all if every one of these metrics is numeric for it
# (a '-'/'N/A' placeholder means that run didn't reach that stage).
# dyninst has no rq1-2-{san2patch,contrafix}-dyninst.py yet; it is assumed to write the
# same per-run result format as conv (patch/build/run, no separate parse stage).
EXPERIMENTS = [
    ('San2Patch', [
        ('MetaC', 'rq1-san2patch-result-*.json', ('parse_time', 'patch_time', 'test_time')),
        ('DynInst', 'rq1-san2patch-dyninst-result-*.json', ('patch_time', 'build_time', 'run_time')),
        ('Conv', 'rq1-san2patch-conv-*.json', ('patch_time', 'build_time', 'test_time')),
    ]),
    ('ContraFix', [
        ('MetaC', 'rq1-contrafix-result-*.json', ('parse_time', 'patch_time', 'test_time')),
        ('DynInst', 'rq1-contrafix-dyninst-result-*.json', ('patch_time', 'build_time', 'run_time')),
        ('Conv', 'rq1-contrafix-conv-*.json', ('patch_time', 'build_time', 'test_time')),
    ]),
]

# Subset of each method's parsed metrics (see EXPERIMENTS) summed for the "without
# test time" statistic -- i.e. every parsed metric except test_time/run_time.
PLOT_TIME_KEYS = {
    'MetaC': ('parse_time', 'patch_time'),
    'DynInst': ('patch_time', 'build_time'),
    'Conv': ('patch_time', 'build_time'),
}

# test_time/run_time alone (no patch/build/parse), for the "test time only" statistic.
TEST_ONLY_KEYS = {
    'MetaC': ('test_time',),
    'DynInst': ('run_time',),
    'Conv': ('test_time',),
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


def print_overall_stats(label: str, overall: List[float], indent: str = '  ') -> None:
    if overall:
        print(f'{indent}{label}: mean={np.mean(overall):.2f}, median={np.median(overall):.2f} '
              f'(n={len(overall)})')
    else:
        print(f'{indent}{label}: mean=N/A, median=N/A (n=0)')


def main():
    # method -> combined (every experiment pooled together) 'with'/'without'/'test_only' lists.
    combined: Dict[str, Dict[str, List[float]]] = {}
    # method -> project -> combined (every experiment pooled together) lists, for the
    # per-project breakdown of the Combined section below.
    combined_by_project: Dict[str, Dict[str, Dict[str, List[float]]]] = {}

    for experiment_name, methods in EXPERIMENTS:
        print(f'=== {experiment_name} ===')
        for name, pattern, parse_keys in methods:
            # "with test time": every parsed metric summed (parse_keys == plot_keys).
            with_test = load_method_times(pattern, parse_keys, parse_keys)
            overall_with = [t for times in with_test.values() for t in times]
            # "without test time": only the non-test/run-time subset summed.
            without_test = load_method_times(pattern, parse_keys, PLOT_TIME_KEYS[name])
            overall_without = [t for times in without_test.values() for t in times]
            # "test time only": just test_time/run_time, no patch/build/parse.
            test_only = load_method_times(pattern, parse_keys, TEST_ONLY_KEYS[name])
            overall_test_only = [t for times in test_only.values() for t in times]

            print(f'{name}:')
            projects = sorted(set(with_test) | set(without_test) | set(test_only))
            for project in projects:
                print(f'  {project}:')
                print_overall_stats('with test time', with_test.get(project, []), indent='    ')
                print_overall_stats('without test time', without_test.get(project, []), indent='    ')
                print_overall_stats('test time only', test_only.get(project, []), indent='    ')
            print('  Overall:')
            print_overall_stats('with test time', overall_with, indent='    ')
            print_overall_stats('without test time', overall_without, indent='    ')
            print_overall_stats('test time only', overall_test_only, indent='    ')

            method_totals = combined.setdefault(name, {'with': [], 'without': [], 'test_only': []})
            method_totals['with'].extend(overall_with)
            method_totals['without'].extend(overall_without)
            method_totals['test_only'].extend(overall_test_only)

            method_projects = combined_by_project.setdefault(name, {})
            for project in projects:
                project_totals = method_projects.setdefault(project, {'with': [], 'without': [], 'test_only': []})
                project_totals['with'].extend(with_test.get(project, []))
                project_totals['without'].extend(without_test.get(project, []))
                project_totals['test_only'].extend(test_only.get(project, []))
        print()

    # Combined across every experiment (San2Patch + ContraFix pooled together), per
    # method, broken down by project (and then Overall, pooling every project too).
    print('=== Combined (San2Patch + ContraFix) ===')
    for name in combined:
        print(f'{name}:')
        for project in sorted(combined_by_project.get(name, {})):
            project_totals = combined_by_project[name][project]
            print(f'  {project}:')
            print_overall_stats('with test time', project_totals['with'], indent='    ')
            print_overall_stats('without test time', project_totals['without'], indent='    ')
            print_overall_stats('test time only', project_totals['test_only'], indent='    ')
        print('  Overall:')
        print_overall_stats('with test time', combined[name]['with'], indent='    ')
        print_overall_stats('without test time', combined[name]['without'], indent='    ')
        print_overall_stats('test time only', combined[name]['test_only'], indent='    ')


if __name__ == '__main__':
    main()
