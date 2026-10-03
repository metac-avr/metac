"""Read rq4-san2patch.py results and draw a grouped bar chart of each method's total
sequential runtime difference from 'conv' per project.

rq4-san2patch.py (see ALL_MODES) runs san2patch under one of 'conv', 'metapro' or
'dyninst' and, for run `run_idx` of bug `project`-`bug_id`, writes its output under:
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

Rather than plotting each method's own total, this draws each non-conv method's
total *minus* conv's total -- a negative bar means that method is faster than conv
for that project (time reduced), a positive bar means it's slower (time increased).
conv itself is the baseline these are measured against, so it isn't drawn.
"""
import glob
import json
import os
import re
from argparse import ArgumentParser
from typing import Dict, List

import matplotlib.pyplot as plt

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..'))
ARVO_DIR = os.path.join(ROOT_DIR, 'benchmarks', 'arvo')
PROJECTS_DIR = os.path.join(ARVO_DIR, 'projects')

# (method label, san2patch --mode name used in the san2patch-<mode>_run<i> directory name).
METHODS = [
    ('MetaC', 'metapro'),
    ('DynInst', 'dyninst'),
    ('Conv', 'conv'),
]

# conv is the baseline every other method's total is diffed against -- it is loaded
# like any other method (for the subtraction) but is not itself drawn as a bar.
BASELINE_METHOD = 'Conv'

# Categorical palette, fixed hue order (see dataviz skill): blue, orange, aqua.
METHOD_COLORS = {
    'MetaC': '#2a78d6',
    'DynInst': '#eb6834',
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


_MS_RE = re.compile(r'(\d+)\s*ms')


def parse_metapro_log_seconds(log_path: str) -> float:
    """Sum the 'N ms' duration in each of a metapro.log's last 3 lines (the
    "generated"/"clean built"/"built" summary lines), in seconds. Ignores the log's
    own timestamps -- only the reported durations are used. Returns 0.0 if the file
    is missing, has fewer than 3 lines, or none of the last 3 lines contain a
    duration."""
    if not os.path.exists(log_path):
        return 0.0
    with open(log_path, errors='replace') as f:
        lines = f.readlines()
    total_ms = 0
    for line in lines[-3:]:
        if 'clean built' in line: continue
        match = _MS_RE.search(line)
        if match:
            total_ms += int(match.group(1))
    return total_ms / 1000.0


def load_metapro_overhead_hours() -> Dict[str, float]:
    """project -> total metapro.log setup time (hours), summed once per bug (not
    per run -- metapro's one-time instrumentation/build step is shared by every
    run of that bug, see rq1-2-san2patch-metac.py)."""
    result: Dict[str, float] = {}
    if not os.path.isdir(PROJECTS_DIR):
        return result
    for project in sorted(os.listdir(PROJECTS_DIR)):
        project_dir = os.path.join(PROJECTS_DIR, project)
        if not os.path.isdir(project_dir):
            continue
        total_seconds = 0.0
        for bug_id in sorted(os.listdir(project_dir)):
            bug_workdir = os.path.join(project_dir, bug_id)
            if not bug_id.isdigit() or not os.path.isdir(bug_workdir):
                continue
            total_seconds += parse_metapro_log_seconds(os.path.join(bug_workdir, 'metapro.log'))
        if total_seconds:
            result[project] = total_seconds / 3600.0
    return result


def main():
    parser = ArgumentParser(description='Total sequential runtime per project for each san2patch validation mode (rq4)')
    parser.add_argument('-o', '--output', default=os.path.join(ARVO_DIR, 'rq4-san2patch-total-time.pdf'),
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

    # MetaC's own total above doesn't include the one-time metapro.log setup cost
    # (instrumentation + clean/incremental builds) each bug pays before any run --
    # add it in and see whether MetaC is still faster than conv overall. Print-only;
    # doesn't touch the plot.
    if 'MetaC' in total_hours:
        metapro_overhead_hours = load_metapro_overhead_hours()
        metac_hours = total_hours['MetaC']
        metac_with_overhead = {
            project: metac_hours.get(project, 0.0) + metapro_overhead_hours.get(project, 0.0)
            for project in set(metac_hours) | set(metapro_overhead_hours)
        }
        print('\nMetaC including metapro.log setup time (generated + clean built + built):')
        for project in sorted(metac_with_overhead):
            metac_total = metac_with_overhead[project]
            conv_total = baseline_hours.get(project, 0.0)
            overhead = metapro_overhead_hours.get(project, 0.0)
            diff = metac_total - conv_total
            print(f'  {project}: metac={metac_total:.2f}h (+{overhead:.2f}h metapro setup), '
                  f'conv={conv_total:.2f}h, diff={diff:+.2f}h')
        overall_metac_with_overhead = sum(metac_with_overhead.values())
        overall_overhead = sum(metapro_overhead_hours.values())
        overall_diff_with_overhead = overall_metac_with_overhead - baseline_overall
        print(f'  Overall: metac={overall_metac_with_overhead:.2f}h (+{overall_overhead:.2f}h metapro setup), '
              f'conv={baseline_overall:.2f}h, diff={overall_diff_with_overhead:+.2f}h')

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
