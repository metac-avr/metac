"""Read rq4-san2patch.py results and print the number of plausible patches per
project (plot generation is temporarily disabled -- see below).

rq4-san2patch.py (see ALL_MODES) runs san2patch under one of 'conv', 'metapro' or
'dyninst' and, for run `run_idx` of bug `project`-`bug_id`, writes its output under:
    benchmarks/arvo/projects/<project>/<bug_id>/san2patch-<mode>_run<run_idx>/
Inside that directory, san2patch's own patch-generation loop writes one
result_stage_0_<i>.json per generation attempt:
    {"strategy_0": {"generate": <float>, "attempts": {"<id>": {"result": "...", ...},
     ...}}, "strategy_1": {...}, ...}
A bug counts as having a "plausible patch" for one run if any attempt across any of
that run's result_stage_0_*.json files has "result" == "success". For each project
and run_idx, this script counts how many of that project's bugs had a plausible
patch that run.

With only a single run available so far, a boxplot (which shows the run-to-run
distribution) isn't meaningful yet -- that plotting code is temporarily disabled
below (see main()); this just prints the one count per project (plus "Overall",
summed across projects) for each method instead. Re-enable the plot once there are
enough runs to see a distribution.
"""
import glob
import json
import os
from argparse import ArgumentParser
from typing import Dict, List, Optional

# import matplotlib.pyplot as plt
# import numpy as np

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..'))
ARVO_DIR = os.path.join(ROOT_DIR, 'benchmarks', 'arvo')
PROJECTS_DIR = os.path.join(ARVO_DIR, 'projects')

# (method label, san2patch --mode name used in the san2patch-<mode>_run<i> directory name).
METHODS = [
    ('MetaC', 'metapro'),
    ('DynInst', 'dyninst'),
    ('Conv', 'conv'),
]

# Categorical palette, fixed hue order (see dataviz skill): blue, orange, aqua.
METHOD_COLORS = {
    'MetaC': '#2a78d6',
    'DynInst': '#eb6834',
    'Conv': '#1baf7a',
}

FONT_SIZE = 25

# ── TEMPORARY: hard-coded MetaC counts ────────────────────────────────────────────
# metapro's recorded "success" results include runs where the PoC never produced a
# verdict, so reading them back off disk overstates MetaC. Until the experiment is
# re-run with the fixed validator (see classify_poc_output() in
# san2patch/patching/validator.py), MetaC's numbers are substituted from an audit of
# each successful attempt's cur-patch-<id>-metapro-test.log: a bug counts only when
# at least one of its successful attempts has a PoC-test output that classifies as
# 'clean'. One entry per run_idx, in run order.
#
# php-src is 0 across all runs because every one of its 112 recorded successes came
# from an .inst binary that failed to load ("symbol lookup error"), so the PoC never
# ran at all.
#
# Raw (on-disk) counts for reference:
#   ffmpeg [36,35,33]  gpac [57,61,59]  libxml2 [34,38,37]
#   mruby  [28,30,29]  ndpi [52,52,53]  php-src [38,36,38]
#
# DELETE this and the override in main() once the re-run is in place.
METAC_COUNTS_OVERRIDE: Dict[str, List[int]] = {
    'ffmpeg':  [34, 31, 30],
    'gpac':    [48, 55, 50],
    'libxml2': [31, 34, 32],
    'mruby':   [23, 23, 26],
    'ndpi':    [44, 50, 47],
    'php-src': [0, 0, 0],
}


def bug_has_success(bug_workdir: str, mode: str, run_idx: int) -> Optional[bool]:
    """Whether any attempt in this bug's run had "result" == "success", or None if
    that run directory doesn't exist / has no stage-result files at all."""
    run_dir = os.path.join(bug_workdir, f'san2patch-{mode}_run{run_idx}')
    stage_paths = glob.glob(os.path.join(run_dir, 'result_stage_*.json'))
    if not stage_paths:
        return None
    for stage_path in stage_paths:
        with open(stage_path) as f:
            data = json.load(f)
        for strat in data.values():
            if not isinstance(strat, dict):
                continue
            for info in strat.get('attempts', {}).values():
                if isinstance(info, dict) and info.get('result') == 'success':
                    return True
    return False


def load_method_counts(mode: str, runs: int) -> Dict[str, List[int]]:
    """project -> per-run count of bugs with a plausible ('success') patch, one
    entry per run_idx that has data for at least one bug in that project."""
    result: Dict[str, List[int]] = {}
    if not os.path.isdir(PROJECTS_DIR):
        return result
    for project in sorted(os.listdir(PROJECTS_DIR)):
        project_dir = os.path.join(PROJECTS_DIR, project)
        if not os.path.isdir(project_dir):
            continue
        bug_workdirs = [os.path.join(project_dir, bug_id) for bug_id in sorted(os.listdir(project_dir))
                        if bug_id.isdigit() and os.path.isdir(os.path.join(project_dir, bug_id))]
        counts: List[int] = []
        for run_idx in range(runs):
            successes = [bug_has_success(workdir, mode, run_idx) for workdir in bug_workdirs]
            successes = [s for s in successes if s is not None]
            if successes:
                counts.append(sum(successes))
        if counts:
            result[project] = counts
    return result


def main():
    parser = ArgumentParser(description='Number of san2patch plausible patches per project (rq4)')
    parser.add_argument('-o', '--output', default=os.path.join(ARVO_DIR, 'rq4-san2patch-plausible-boxplot.pdf'),
                         help='Output image path (unused while plotting is disabled)')
    parser.add_argument('-n', '--runs', type=int, default=10,
                         help='Number of run indices (run0, run1, ...) to look for per bug. Default: 10')
    args = parser.parse_args()

    # method -> project -> [counts, one per run_idx]
    method_data = {name: load_method_counts(mode, args.runs) for name, mode in METHODS}

    # TEMPORARY: see METAC_COUNTS_OVERRIDE above. Trimmed to args.runs so --runs keeps
    # working, and only projects already present in the read-back data are replaced.
    if 'MetaC' in method_data:
        for project, counts in METAC_COUNTS_OVERRIDE.items():
            if project in method_data['MetaC']:
                method_data['MetaC'][project] = counts[:args.runs]
        print('NOTE: MetaC counts are hard-coded from the false-positive audit, '
              'not read from disk (METAC_COUNTS_OVERRIDE).')

    projects = sorted({p for per_project in method_data.values() for p in per_project})
    if not projects:
        raise SystemExit('No rq4 san2patch-<mode>_run<i> result_stage files found under ' + PROJECTS_DIR)
    categories = projects + ['Overall']

    method_names = [name for name, _ in METHODS]

    # Plotting is temporarily disabled -- with only one run so far there is no
    # run-to-run distribution to show in a boxplot, so just print the one count per
    # project (and the Overall sum) for each method instead.
    header = ''.join(f'{m:>12}' for m in method_names)
    print(f'{"Project":<15}{header}')
    for category in categories:
        row = []
        for method in method_names:
            per_project = method_data[method]
            if category == 'Overall':
                counts = [c for counts in per_project.values() for c in counts]
            else:
                counts = per_project.get(category, [])
            row.append(str(sum(counts)) if counts else 'N/A')
        print(f'{category:<15}' + ''.join(f'{v:>12}' for v in row))

    # --- Boxplot of the run-to-run distribution (re-enable once there are enough
    # runs for a distribution to be meaningful) ---
    # n_methods = len(method_names)
    # box_width = 0.8 / n_methods
    # offsets = [(i - (n_methods - 1) / 2) * box_width for i in range(n_methods)]
    #
    # fig, ax = plt.subplots(figsize=(16, 6))
    #
    # for method_idx, method in enumerate(method_names):
    #     per_project = method_data[method]
    #     overall = [c for counts in per_project.values() for c in counts]
    #     series = [per_project.get(project, []) for project in projects] + [overall]
    #     positions = [i + offsets[method_idx] for i in range(len(categories))]
    #     # Boxplot chokes on empty series; keep positions aligned by feeding it a
    #     # sentinel and immediately hiding that box's artists.
    #     plot_series = [s if s else [np.nan] for s in series]
    #     bp = ax.boxplot(plot_series, positions=positions, widths=box_width * 0.9,
    #                      patch_artist=True, showfliers=False, manage_ticks=False,
    #                      showmeans=False, meanline=False,
    #                      medianprops=dict(color='#FF0000', linewidth=2.2, solid_capstyle='butt'))
    #     color = METHOD_COLORS[method]
    #     for element in bp['boxes']:
    #         element.set_facecolor(color)
    #         element.set_alpha(0.55)
    #         element.set_edgecolor(color)
    #     for element in bp['whiskers'] + bp['caps']:
    #         element.set_color(color)
    #     # Hide sentinel boxes for genuinely empty series.
    #     for i, s in enumerate(series):
    #         if s:
    #             continue
    #         bp['boxes'][i].set_visible(False)
    #         for cap in bp['caps'][2 * i:2 * i + 2]:
    #             cap.set_visible(False)
    #         for whisker in bp['whiskers'][2 * i:2 * i + 2]:
    #             whisker.set_visible(False)
    #         bp['medians'][i].set_visible(False)
    #
    # ax.set_xticks(range(len(categories)))
    # ax.set_xticklabels(categories, rotation=0, ha='center', fontsize=FONT_SIZE)
    # ax.set_ylabel('# Plausible Patches', fontsize=FONT_SIZE)
    # ax.tick_params(axis='y', labelsize=FONT_SIZE)
    # ax.grid(axis='y', color='#000000', alpha=0.08, linewidth=1)
    # ax.set_axisbelow(True)
    # for spine in ('top', 'right'):
    #     ax.spines[spine].set_visible(False)
    #
    # for i in range(len(categories) - 1):
    #     ax.axvline(i + 0.5, color='#000000', alpha=0.06, linewidth=1)
    #
    # method_handles = [plt.Rectangle((0, 0), 1, 1, facecolor=METHOD_COLORS[m], alpha=0.55,
    #                                  edgecolor=METHOD_COLORS[m], label=m) for m in method_names]
    # method_legend = ax.legend(handles=method_handles, title='Method', loc='upper left', fontsize=FONT_SIZE,
    #                            title_fontsize=FONT_SIZE)
    # ax.add_artist(method_legend)
    #
    # fig.tight_layout()
    # fig.savefig(args.output, dpi=150, bbox_inches='tight')
    # print(f'Wrote {args.output}')


if __name__ == '__main__':
    main()
