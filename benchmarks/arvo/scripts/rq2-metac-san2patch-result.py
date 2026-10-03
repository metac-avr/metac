"""Read rq1-2-san2patch-metac.py results and report san2patch's plausible-patch success rate.

rq1-2-san2patch-metac.py writes one JSON file per project under ARVO_DIR:
    {"<bug_id>": {"result": [value_run0, value_run1, ...], ...}, ...}
'result' is 'Y' (plausible patch found and passed the test), 'N' (failed) or 'N/A' (san2patch
never produced a plausible patch to try at all). Patch generation is deterministic, so all
non-N/A runs of the same bug are expected to agree; a bug whose runs are all 'N/A' has no
verdict and is excluded from the counts entirely (neither a success nor a failure).

rq1-2-san2patch-conv.py writes the same shape of 'result' next to it
(rq1-san2patch-conv-<project>.json), from independently re-validating the same plausible
patch by applying it to source and rebuilding. A bug where metac says 'N' but conv also
says 'N' failed for a reason common to both (the underlying patch is bad), not because of
metac's binary-patching approach specifically -- so it is excluded from metac's fail count
rather than counted against metac.

This script counts successes/failures per project and overall, and writes every failed
(non-N/A, non-'Y', not conv-confirmed) case out to a JSON file for follow-up inspection.
"""
import glob
import json
import os
import sys
from argparse import ArgumentParser
from collections import Counter
from typing import Dict, List

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..'))
ARVO_DIR = os.path.join(ROOT_DIR, 'benchmarks', 'arvo')

RESULT_PATTERN = 'rq1-san2patch-result-*.json'
CONV_RESULT_PATTERN = 'rq1-san2patch-conv-*.json'


def project_from_filename(path: str, pattern: str) -> str:
    prefix, suffix = pattern.split('*')
    name = os.path.basename(path)
    return name[len(prefix):len(name) - len(suffix)]


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


def load_verdicts(pattern: str) -> Dict[str, Dict[str, str]]:
    """project -> {bug_id: verdict} using the same 'result' collapsing as bug_verdict."""
    verdicts: Dict[str, Dict[str, str]] = {}
    for path in sorted(glob.glob(os.path.join(ARVO_DIR, pattern))):
        project = project_from_filename(path, pattern)
        with open(path) as f:
            data = json.load(f)
        verdicts[project] = {bug_id: bug_verdict(bug_id, metrics.get('result', []))
                             for bug_id, metrics in data.items()}
    return verdicts


def main():
    parser = ArgumentParser(description="Report san2patch metac's plausible-patch success rate")
    parser.add_argument('-o', '--output', default=os.path.join(ARVO_DIR, 'rq2-san2patch-metac-failed-cases.json'),
                        help='Where to write the list of failed cases')
    args = parser.parse_args()

    paths = sorted(glob.glob(os.path.join(ARVO_DIR, RESULT_PATTERN)))
    if not paths:
        raise SystemExit('No rq1 result files found under ' + ARVO_DIR)

    conv_verdicts = load_verdicts(CONV_RESULT_PATTERN)

    # project -> {'success': n, 'fail': n, 'na': n, 'excluded': n}
    per_project: Dict[str, Dict[str, int]] = {}
    # project -> [bug_id, ...] whose verdict is 'N' and not conv-excluded
    failed_cases: Dict[str, List[str]] = {}

    for path in paths:
        project = project_from_filename(path, RESULT_PATTERN)
        with open(path) as f:
            data = json.load(f)

        counts = per_project.setdefault(project, {'success': 0, 'fail': 0, 'na': 0, 'excluded': 0})
        for bug_id, metrics in data.items():
            verdict = bug_verdict(bug_id, metrics.get('result', []))
            if verdict == 'Y':
                counts['success'] += 1
            elif verdict == 'N':
                conv_verdict = conv_verdicts.get(project, {}).get(bug_id)
                if conv_verdict == 'N':
                    # conv (source-level re-validation of the same patch) also failed,
                    # so this isn't a metac-specific failure -- don't count it as a fail.
                    counts['excluded'] += 1
                else:
                    counts['fail'] += 1
                    failed_cases.setdefault(project, []).append(bug_id)
            else:
                counts['na'] += 1

    total_success = sum(c['success'] for c in per_project.values())
    total_fail = sum(c['fail'] for c in per_project.values())
    total_na = sum(c['na'] for c in per_project.values())
    total_excluded = sum(c['excluded'] for c in per_project.values())
    total_cases = total_success + total_fail

    print(f'{"Project":<15}{"Success":>10}{"Fail":>8}{"Ratio":>10}{"(N/A excluded)":>18}{"(conv N excluded)":>20}')
    for project in sorted(per_project):
        counts = per_project[project]
        cases = counts['success'] + counts['fail']
        ratio = counts['success'] / cases if cases else float('nan')
        print(f'{project:<15}{counts["success"]:>10}{counts["fail"]:>8}{ratio:>10.2%}{counts["na"]:>18}{counts["excluded"]:>20}')

    overall_ratio = total_success / total_cases if total_cases else float('nan')
    print(f'{"Overall":<15}{total_success:>10}{total_fail:>8}{overall_ratio:>10.2%}{total_na:>18}{total_excluded:>20}')

    print(f'\nTotal successful cases: {total_success}')

    with open(args.output, 'w') as f:
        json.dump(failed_cases, f, indent=2)
    print(f'\nWrote failed cases to {args.output}')


if __name__ == '__main__':
    main()
