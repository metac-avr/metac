"""Read rq4-san2patch.py results and draw a grouped bar chart of MetaC's and
Combined's total sequential runtime difference from 'conv' per project.

rq4-san2patch.py (see ALL_MODES) runs san2patch under one of 'conv', 'metapro' or
'combined' and, for run `run_idx` of bug `project`-`bug_id`, writes its output under:
    benchmarks/arvo/projects/<project>/<bug_id>/san2patch-<mode>_run<run_idx>/
Inside that directory, san2patch's own patch-generation loop writes one
result_stage_0_<i>.json per generation attempt (see _load_stage_result in
rq1-2-san2patch-*.py):
    {"strategy_0": {"generate": <float>, "attempts": {"<id>": {"patch": <float>,
     "build": <float>, "result": "...", ...}, ...}}, "strategy_1": {...}, ...}
This script treats every float found anywhere in every result_stage_0_*.json under
a (project, bug_id, mode, run_idx) directory as time spent on that run (patch time,
build time, generate time, and any other per-attempt timing -- everything numeric),
sums them into that run's total time, and then -- unlike a boxplot, which shows the
run-to-run distribution -- adds up every one of those run totals for a given project
and method into a single number: how long the entire experiment (every bug, every
run) would take to finish if run sequentially, back to back.

Rather than plotting each method's own total, this draws MetaC's and Combined's
total *minus* conv's total -- a negative bar means that method is faster than conv
for that project (time reduced), a positive bar means it's slower (time increased).
conv itself is the baseline these are measured against, so it isn't drawn.
"""
import glob
import json
import os
from argparse import ArgumentParser
from collections import Counter
from typing import Dict, List, Optional

import matplotlib.pyplot as plt

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..'))
ARVO_DIR = os.path.join(ROOT_DIR, 'benchmarks', 'arvo')
PROJECTS_DIR = os.path.join(ARVO_DIR, 'projects')

# (method label, san2patch --mode name used in the san2patch-<mode>_run<i> directory name).
METHODS = [
    ('Combined', 'combined'),
    ('MetaC', 'metapro'),
    ('Conv', 'conv'),
]

# conv is the baseline every other method's total is diffed against -- it is loaded
# like any other method (for the subtraction) but is not itself drawn as a bar.
BASELINE_METHOD = 'Conv'

# Categorical palette, fixed hue order (see dataviz skill): blue, aqua, yellow.
# Combined uses yellow (palette slot 4), not orange (slot 2) -- orange is DynInst's
# color in every other rq1/rq4 plot, and reusing it here for a different method
# would read as the same series across plots.
METHOD_COLORS = {
    'MetaC': '#2a78d6',
    'Combined': '#eda100',
    'Conv': '#1baf7a',
}

FONT_SIZE = 25


def sum_floats(value) -> float:
    """Recursively sum every float/int leaf in a JSON value (dict/list/scalar).

    Booleans are excluded (bool is a subclass of int in Python but not a timing).
    """
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, dict):
        return sum(sum_floats(v) for v in value.values())
    if isinstance(value, list):
        return sum(sum_floats(v) for v in value)
    return 0.0


def load_run_time(bug_workdir: str, mode: str, run_idx: int) -> float:
    """Total time (sum of every numeric value) across all result_stage_0_*.json
    files under <bug_workdir>/san2patch-<mode>_run<run_idx>/, or None if that run
    directory doesn't exist or has no stage-result files at all."""
    run_dir = os.path.join(bug_workdir, f'san2patch-{mode}_run{run_idx}')
    stage_paths = glob.glob(os.path.join(run_dir, 'result_stage_*.json'))
    if not stage_paths:
        return None
    total = 0.0
    for stage_path in stage_paths:
        with open(stage_path) as f:
            data = json.load(f)
        total += sum_floats(data)
    return total


# Per-stage time keys, on top of the 'patch' key every attempt carries (the initial
# patch application/loading, common to all three stages). dyninst's own stage is
# split across three separate keys (dyninst_extract, dyninst_patch, dyninst_test) --
# all three must be added together to get dyninst's actual stage time, not just one.
# conv's 'build' and 'vulnerability' are incurred (and so counted) whenever that
# stage ran at all, regardless of whether it passed -- but 'functionality' (the
# functional test) only ever runs, and so is only ever counted, when 'result' is
# 'success' or 'func_test_failed' (a build_failed/vuln_test_failed attempt never
# reached the functional test, confirmed by the data: 'functionality' never appears
# on those results).
STAGE_TIME_KEYS = {
    'metapro': ('metapro_patch_gen', 'metapro_patch', 'metapro_test'),
    'dyninst': ('dyninst_extract', 'dyninst_patch', 'dyninst_test'),
    'conv': ('build', 'vulnerability'),
}
FUNCTIONAL_TEST_RESULTS = ('success', 'func_test_failed')


def attempt_stage_time(info: dict, stage: str) -> float:
    """Total time (seconds) this attempt spent in `stage`: the shared 'patch' key
    plus every one of that stage's own time keys present on the attempt (dyninst's
    three dyninst_* keys are all added together, not just dyninst_patch), plus
    conv's 'functionality' time when the functional test actually ran."""
    total = info.get('patch', 0.0) if isinstance(info.get('patch'), (int, float)) else 0.0
    for key in STAGE_TIME_KEYS[stage]:
        value = info.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            total += value
    if stage == 'conv' and info.get('result') in FUNCTIONAL_TEST_RESULTS:
        value = info.get('functionality')
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            total += value
    return total


def classify_combined_attempt(info: dict) -> str:
    """Which underlying method actually produced this combined-mode attempt.

    combined mode tries metapro first, falls back to dyninst if metapro failed, and
    falls back further to conv (source patch + rebuild) if dyninst also failed -- so
    the attempt's own entry only carries the keys of the stage(s) it actually reached:
    'build' only appears once the conv fallback ran, 'dyninst_patch' only once the
    dyninst fallback ran, and an attempt that never needed a fallback has just the
    metapro_* keys.
    """
    if 'build' in info:
        return 'conv'
    if 'dyninst_patch' in info:
        return 'dyninst'
    if 'metapro_patch' in info:
        return 'metapro'
    return 'unknown'


def count_combined_method_usage(mode: str, runs: int) -> Dict[str, Counter]:
    """project -> Counter of {'metapro'/'dyninst'/'conv'/'unknown': n} over every
    attempt in every result_stage_*.json under every san2patch-<mode>_run<i>
    directory for that project."""
    counts_by_project: Dict[str, Counter] = {}
    if not os.path.isdir(PROJECTS_DIR):
        return counts_by_project
    for project in sorted(os.listdir(PROJECTS_DIR)):
        project_dir = os.path.join(PROJECTS_DIR, project)
        if not os.path.isdir(project_dir):
            continue
        counts: Counter = Counter()
        for bug_id in sorted(os.listdir(project_dir)):
            bug_workdir = os.path.join(project_dir, bug_id)
            if not bug_id.isdigit() or not os.path.isdir(bug_workdir):
                continue
            for run_idx in range(runs):
                run_dir = os.path.join(bug_workdir, f'san2patch-{mode}_run{run_idx}')
                for stage_path in glob.glob(os.path.join(run_dir, 'result_stage_*.json')):
                    with open(stage_path) as f:
                        data = json.load(f)
                    for strat in data.values():
                        if not isinstance(strat, dict):
                            continue
                        for info in strat.get('attempts', {}).values():
                            if isinstance(info, dict):
                                counts[classify_combined_attempt(info)] += 1
        if counts:
            counts_by_project[project] = counts
    return counts_by_project


def sum_stage_times(mode: str, runs: int) -> Dict[str, Dict[str, float]]:
    """project -> {'metapro'/'dyninst'/'conv'/'generate': total seconds}, classifying
    every attempt (see classify_combined_attempt) and summing its full stage time
    (see attempt_stage_time -- dyninst's three dyninst_* keys all added together).
    'generate' (the patch-generation time an LLM/analysis step spends producing the
    candidate patch, see rq1-2-san2patch-*.py) lives once per *strategy*, shared by
    every attempt under it -- so it is summed once per strategy, not re-added for
    each of that strategy's attempts."""
    totals_by_project: Dict[str, Dict[str, float]] = {}
    if not os.path.isdir(PROJECTS_DIR):
        return totals_by_project
    for project in sorted(os.listdir(PROJECTS_DIR)):
        project_dir = os.path.join(PROJECTS_DIR, project)
        if not os.path.isdir(project_dir):
            continue
        totals: Dict[str, float] = {'metapro': 0.0, 'dyninst': 0.0, 'conv': 0.0, 'generate': 0.0}
        for bug_id in sorted(os.listdir(project_dir)):
            bug_workdir = os.path.join(project_dir, bug_id)
            if not bug_id.isdigit() or not os.path.isdir(bug_workdir):
                continue
            for run_idx in range(runs):
                run_dir = os.path.join(bug_workdir, f'san2patch-{mode}_run{run_idx}')
                for stage_path in glob.glob(os.path.join(run_dir, 'result_stage_*.json')):
                    with open(stage_path) as f:
                        data = json.load(f)
                    for strat in data.values():
                        if not isinstance(strat, dict):
                            continue
                        generate_time = strat.get('generate')
                        if isinstance(generate_time, (int, float)) and not isinstance(generate_time, bool):
                            totals['generate'] += generate_time
                        for info in strat.get('attempts', {}).values():
                            if not isinstance(info, dict):
                                continue
                            stage = classify_combined_attempt(info)
                            if stage in totals:
                                totals[stage] += attempt_stage_time(info, stage)
        if any(totals.values()):
            totals_by_project[project] = totals
    return totals_by_project


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


def count_plausible_patches(mode: str, runs: int) -> Dict[str, int]:
    """project -> number of (bug, run) pairs with a plausible ('success') patch,
    summed across every run_idx that has data for that bug."""
    counts: Dict[str, int] = {}
    if not os.path.isdir(PROJECTS_DIR):
        return counts
    for project in sorted(os.listdir(PROJECTS_DIR)):
        project_dir = os.path.join(PROJECTS_DIR, project)
        if not os.path.isdir(project_dir):
            continue
        total = 0
        for bug_id in sorted(os.listdir(project_dir)):
            bug_workdir = os.path.join(project_dir, bug_id)
            if not bug_id.isdigit() or not os.path.isdir(bug_workdir):
                continue
            for run_idx in range(runs):
                if bug_has_success(bug_workdir, mode, run_idx):
                    total += 1
        if total:
            counts[project] = total
    return counts


def load_method_times(mode: str, runs: int) -> Dict[str, List[float]]:
    """project -> flat list of total times, one per (bug_id, run_idx) that has data."""
    result: Dict[str, List[float]] = {}
    if not os.path.isdir(PROJECTS_DIR):
        return result
    for project in sorted(os.listdir(PROJECTS_DIR)):
        project_dir = os.path.join(PROJECTS_DIR, project)
        if not os.path.isdir(project_dir):
            continue
        times: List[float] = []
        for bug_id in sorted(os.listdir(project_dir)):
            bug_workdir = os.path.join(project_dir, bug_id)
            if not bug_id.isdigit() or not os.path.isdir(bug_workdir):
                continue
            for run_idx in range(runs):
                run_time = load_run_time(bug_workdir, mode, run_idx)
                if run_time is not None:
                    times.append(run_time)
        if times:
            result[project] = times
    return result


def main():
    parser = ArgumentParser(description='Total sequential runtime diff vs conv for MetaC and Combined (rq4)')
    parser.add_argument('-o', '--output', default=os.path.join(ARVO_DIR, 'rq4-san2patch-combined-total-time.pdf'),
                         help='Output image path')
    parser.add_argument('-n', '--runs', type=int, default=10,
                         help='Number of run indices (run0, run1, ...) to look for per bug. Default: 10')
    parser.add_argument('--split-php', action='store_true',
                         help='Draw php-src in its own separate output file (see --php-output) '
                              'instead of as a subplot of the main figure. Default: off '
                              '(one all-in-one figure, same as before).')
    parser.add_argument('--php-output', default=None,
                         help='Output image path for the php-src-only plot when --split-php is '
                              'given. Default: <output>-php<ext>')
    parser.add_argument('--overall-output', default=None,
                         help='Output image path for the Overall-only plot when --split-php is '
                              'given. Default: <output>-overall<ext>')
    args = parser.parse_args()
    if args.php_output is None:
        base, ext = os.path.splitext(args.output)
        args.php_output = f'{base}-php{ext}'
    if args.overall_output is None:
        base, ext = os.path.splitext(args.output)
        args.overall_output = f'{base}-overall{ext}'

    # method -> project -> [times]
    method_data = {name: load_method_times(mode, args.runs) for name, mode in METHODS}

    projects = sorted({p for per_project in method_data.values() for p in per_project})
    if not projects:
        raise SystemExit('No rq4 san2patch-<mode>_run<i> result_stage files found under ' + PROJECTS_DIR)

    # How many combined-mode attempts actually landed on each underlying method
    # (metapro tried first, falling back to dyninst then conv -- see
    # classify_combined_attempt), per project and overall.
    combined_mode = dict(METHODS)['Combined']
    usage_by_project = count_combined_method_usage(combined_mode, args.runs)
    overall_usage: Counter = Counter()
    for counts in usage_by_project.values():
        overall_usage.update(counts)

    def print_usage(label: str, counts: Counter) -> None:
        total = sum(counts.values())
        print(f'{label}:')
        for name in ('metapro', 'dyninst', 'conv', 'unknown'):
            n = counts.get(name, 0)
            ratio = n / total if total else float('nan')
            print(f'  {name:<8}: {n} ({ratio:.2%})')
        print(f'  {"total":<8}: {total}')

    print('=== Combined mode: underlying method usage (every attempt, every run) ===')
    for project in sorted(usage_by_project):
        print_usage(project, usage_by_project[project])
    print_usage('Overall', overall_usage)

    # How much time was actually spent in each stage (metapro/dyninst/conv), per
    # project and overall, in hours -- dyninst's dyninst_extract + dyninst_patch +
    # dyninst_test are all added together here, not just dyninst_patch alone, and
    # 'generate' (patch generation, once per strategy) and conv's 'functionality'
    # (only when the functional test actually ran) are included too.
    stage_times_by_project = sum_stage_times(combined_mode, args.runs)
    overall_stage_times: Dict[str, float] = {'metapro': 0.0, 'dyninst': 0.0, 'conv': 0.0, 'generate': 0.0}
    for totals in stage_times_by_project.values():
        for stage, seconds in totals.items():
            overall_stage_times[stage] += seconds

    def print_stage_times(label: str, totals: Dict[str, float]) -> None:
        print(f'{label}:')
        for stage in ('generate', 'metapro', 'dyninst', 'conv'):
            print(f'  {stage:<8}: {totals[stage] / 3600:.2f} hours')

    print('\n=== Combined mode: time spent per stage ===')
    for project in sorted(stage_times_by_project):
        print_stage_times(project, stage_times_by_project[project])
    print_stage_times('Overall', overall_stage_times)

    # How many (bug, run) pairs had a plausible ("success") patch in combined mode,
    # per project and overall.
    plausible_by_project = count_plausible_patches(combined_mode, args.runs)
    print('\n=== Combined mode: number of plausible patches ===')
    for project in sorted(plausible_by_project):
        print(f'  {project:<10}: {plausible_by_project[project]}')
    print(f'  {"Overall":<10}: {sum(plausible_by_project.values())}')

    # Total sequential runtime (every bug, every run, back to back) per method,
    # in hours -- the sum (not the distribution) of every individual run time.
    HOUR = 3600.0
    total_hours = {name: {project: sum(times) / HOUR for project, times in per_project.items()}
                    for name, per_project in method_data.items()}
    for name, _ in METHODS:
        overall = sum(total_hours[name].values())
        print(f'{name}: total sequential time = {overall:.2f} hours '
              f'(n={sum(len(times) for times in method_data[name].values())} runs)')

    # Per-project (and Overall) total minus conv's total -- what's actually drawn.
    # conv itself is excluded from METHODS here since it's the baseline (always 0).
    baseline_hours = total_hours.get(BASELINE_METHOD, {})
    baseline_overall = sum(baseline_hours.values())
    diff_hours = {
        name: {project: hours - baseline_hours.get(project, 0.0) for project, hours in per_project.items()}
        for name, per_project in total_hours.items() if name != BASELINE_METHOD
    }
    overall_diff_by_method = {name: sum(total_hours[name].values()) - baseline_overall for name in diff_hours}
    for name, overall_diff in overall_diff_by_method.items():
        print(f'{name}: total diff vs {BASELINE_METHOD} = {overall_diff:+.2f} hours')

    # php-src's total dwarfs every other project's, and 'Overall' (every project's
    # total summed together) dwarfs php-src in turn -- either would flatten the rest
    # to near-invisible bars on a shared y-axis, so both are dropped from the main
    # figure and given their own axes/figure with their own y-scale: php-src on the
    # left, the main grid of projects in the middle, 'Overall' on the right.
    SPLIT_PROJECT = 'php-src'
    has_split = SPLIT_PROJECT in projects
    categories = [p for p in projects if p != SPLIT_PROJECT]

    # Only the non-baseline methods are drawn -- conv is what everything is diffed
    # against, so its own bar would always be exactly 0.
    method_names = [name for name in diff_hours]
    n_methods = len(method_names)
    box_width = 0.8 / n_methods
    offsets = [(i - (n_methods - 1) / 2) * box_width for i in range(n_methods)]

    def draw_group(axis, group_categories):
        """Draw each non-baseline method's time-diff-vs-conv bar for each category in
        group_categories. 'Overall' is the total diff across every project pooled
        together (php-src included), not a per-project sum, so it matches the
        overall totals printed above exactly."""
        for method_idx, method in enumerate(method_names):
            per_project = diff_hours[method]
            heights = [overall_diff_by_method[method] if cat == 'Overall' else per_project.get(cat, 0.0)
                       for cat in group_categories]
            positions = [i + offsets[method_idx] for i in range(len(group_categories))]
            color = METHOD_COLORS[method]
            axis.bar(positions, heights, width=box_width * 0.9,
                     color=color, alpha=0.55, edgecolor=color)

    def style_axis(axis, n_categories):
        axis.tick_params(axis='y', labelsize=FONT_SIZE)
        axis.grid(axis='y', color='#000000', alpha=0.08, linewidth=1)
        axis.axhline(0, color='#000000', alpha=0.35, linewidth=1.2)
        axis.set_axisbelow(True)
        for spine in ('top', 'right'):
            axis.spines[spine].set_visible(False)
        for i in range(n_categories - 1):
            axis.axvline(i + 0.5, color='#000000', alpha=0.06, linewidth=1)

    method_handles = [plt.Rectangle((0, 0), 1, 1, facecolor=METHOD_COLORS[m], alpha=0.55,
                                     edgecolor=METHOD_COLORS[m], label=m) for m in method_names]

    def draw_side(axis, item_key, label, show_ylabel=True):
        """Draw one single-category side plot (php-src or Overall) with its own axes."""
        draw_group(axis, [item_key])
        style_axis(axis, 1)
        axis.set_xticks([0])
        axis.set_xticklabels([label], rotation=0, ha='center', fontsize=FONT_SIZE)
        if show_ylabel:
            axis.set_ylabel('Time Diff vs Conv (hours)', fontsize=FONT_SIZE)

    if args.split_php:
        # Independent figures/files, each with its own y-scale: php-src (if present),
        # the main grid of projects, and Overall.
        MAIN_FIG_WIDTH = 16
        fig, ax = plt.subplots(figsize=(MAIN_FIG_WIDTH, 6))
        draw_group(ax, categories)
        style_axis(ax, len(categories))
        ax.set_xticks(range(len(categories)))
        ax.set_xticklabels(categories, rotation=0, ha='center', fontsize=FONT_SIZE)
        ax.set_ylabel('Time Diff vs Conv (hours)', fontsize=FONT_SIZE)
        method_legend = ax.legend(handles=method_handles, title='Method', fontsize=FONT_SIZE,
                                   title_fontsize=FONT_SIZE)
        ax.add_artist(method_legend)
        fig.tight_layout()
        fig.savefig(args.output, dpi=150, bbox_inches='tight')
        print(f'Wrote {args.output}')

        # Size each side figure so its bars are exactly as wide (in inches) as a bar
        # in the main figure: measure the main axes' plot area and margins (in
        # inches, after tight_layout) and give the side figure the same margins plus
        # one category-width's worth of plot area, rather than an arbitrary figsize.
        pos = ax.get_position()
        left_margin_in = pos.x0 * MAIN_FIG_WIDTH
        right_margin_in = (1 - pos.x1) * MAIN_FIG_WIDTH
        per_category_in = (pos.width * MAIN_FIG_WIDTH) / len(categories)
        side_fig_width = left_margin_in + per_category_in + right_margin_in

        if has_split:
            fig_php, ax_php = plt.subplots(figsize=(side_fig_width, 6))
            draw_side(ax_php, SPLIT_PROJECT, 'php')
            fig_php.tight_layout()
            fig_php.savefig(args.php_output, dpi=150, bbox_inches='tight')
            print(f'Wrote {args.php_output}')

        fig_overall, ax_overall = plt.subplots(figsize=(side_fig_width, 6))
        draw_side(ax_overall, 'Overall', 'Overall')
        fig_overall.tight_layout()
        fig_overall.savefig(args.overall_output, dpi=150, bbox_inches='tight')
        print(f'Wrote {args.overall_output}')
    else:
        # One all-in-one figure: php-src (if present) as a narrower subplot on the
        # left and Overall as one on the right, each with its own y-scale, around the
        # main grid of projects in the middle -- php-src/Overall sharing the main
        # grid's y-axis would flatten every project's bar to near-invisible given
        # their much larger totals.
        width_ratios = ([1] if has_split else []) + [len(categories)] + [1]
        axes = plt.subplots(1, len(width_ratios), figsize=(16, 6),
                             gridspec_kw={'width_ratios': width_ratios})[1]
        if has_split:
            ax_split, ax, ax_overall = axes
        else:
            ax, ax_overall = axes
        fig = ax.figure

        draw_group(ax, categories)
        style_axis(ax, len(categories))
        ax.set_xticks(range(len(categories)))
        ax.set_xticklabels(categories, rotation=0, ha='center', fontsize=FONT_SIZE)
        # The ylabel goes on the leftmost subplot only -- php-src's, when present,
        # otherwise the main grid's.
        if not has_split:
            ax.set_ylabel('Time Diff vs Conv (hours)', fontsize=FONT_SIZE)

        if has_split:
            draw_side(ax_split, SPLIT_PROJECT, 'php')

        draw_side(ax_overall, 'Overall', 'Overall', show_ylabel=False)

        method_legend = ax.legend(handles=method_handles, title='Method', fontsize=FONT_SIZE,
                                   title_fontsize=FONT_SIZE)
        ax.add_artist(method_legend)

        fig.tight_layout()
        fig.savefig(args.output, dpi=150, bbox_inches='tight')
        print(f'Wrote {args.output}')


if __name__ == '__main__':
    main()
