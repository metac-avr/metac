"""Read rq1-2-san2patch-{metac,conv,dyninst}.py results and draw a grouped boxplot.

Each rq1-2-san2patch-*.py script writes one JSON file per project:
    {"<bug_id>": {"<metric>": [value_run0, value_run1, ...], ...}, ...}
This script sums each run's time-related metrics into a single "total time"
value (dropping runs where any of those metrics is a non-numeric placeholder
like '-' or 'N/A', i.e. the run didn't reach that stage) and draws one boxplot
per project (plus one "Overall" box pooling every project) with three
side-by-side boxes: metac, dyninst and conv.
"""
import glob
import json
import os
import re
from argparse import ArgumentParser
from typing import Dict, List

import matplotlib.pyplot as plt
import numpy as np

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..'))
ARVO_DIR = os.path.join(ROOT_DIR, 'benchmarks', 'arvo')

# (method label, result-file glob pattern relative to ARVO_DIR, time metrics parsed per run).
# A run is only counted at all if every one of these metrics is numeric for it
# (a '-'/'N/A' placeholder means that run didn't reach that stage).
# dyninst has no rq1-2-san2patch-dyninst.py yet; it is assumed to write the same
# per-run result format as conv (patch/build/test, no separate parse stage).
METHODS = [
    ('MetaC', 'rq1-san2patch-result-*.json', ('parse_time', 'patch_time', 'test_time')),
    ('DynInst', 'rq1-san2patch-dyninst-result-*.json', ('patch_time', 'build_time', 'run_time')),
    ('Conv', 'rq1-san2patch-conv-*.json', ('patch_time', 'build_time', 'test_time')),
]

# Subset of each method's parsed metrics (see METHODS) that is actually summed into
# the plotted "total time". Metrics left out here are still parsed and validated
# above -- e.g. test_time is currently excluded from the plot but already parsed,
# so flipping it back on later is a one-line change here, not a re-parse.
PLOT_TIME_KEYS = {
    'MetaC': ('parse_time', 'patch_time'),
    'DynInst': ('patch_time', 'build_time'),
    'Conv': ('patch_time', 'build_time'),
}

# test_time-only variant of PLOT_TIME_KEYS, for the separate test_time-only boxplot
# (same METHODS/parse_keys validation as the main plot, just a different summed subset).
TEST_TIME_KEYS = {
    'MetaC': ('test_time',),
    'DynInst': ('run_time',),
    'Conv': ('test_time',),
}

# Categorical palette, fixed hue order (see dataviz skill): blue, orange, aqua.
METHOD_COLORS = {
    'MetaC': '#2a78d6',
    'DynInst': '#eb6834',
    'Conv': '#1baf7a',
}

FONT_SIZE = 25


def project_from_filename(path: str, pattern: str) -> str:
    prefix, suffix = pattern.split('*')
    name = os.path.basename(path)
    return name[len(prefix):len(name) - len(suffix)]


def load_method_times(pattern: str, parse_keys, plot_keys) -> Dict[str, List[float]]:
    """project -> flat list of per-run plotted times (one float per bug-run where every
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


def make_boxplot(plot_time_keys, output, php_output, split_php, ylabel='Time (sec)'):
    """Build and save one grouped boxplot (plus its php-src split, if applicable) for
    the given per-method 'plot_time_keys' subset (see PLOT_TIME_KEYS / TEST_TIME_KEYS).
    Identical in layout/styling regardless of which metrics are summed."""
    # method -> project -> [times]
    method_data = {name: load_method_times(pattern, keys, plot_time_keys[name])
                    for name, pattern, keys in METHODS}

    projects = sorted({p for per_project in method_data.values() for p in per_project})
    if not projects:
        raise SystemExit('No rq1 result files found under ' + ARVO_DIR)

    # Overall (every project pooled together) mean/median per method -- the same
    # population plotted in the 'Overall' box.
    for name, _, _ in METHODS:
        overall = [t for times in method_data[name].values() for t in times]
        if overall:
            print(f'{name}: overall mean={np.mean(overall):.2f}, median={np.median(overall):.2f} '
                  f'(n={len(overall)})')
        else:
            print(f'{name}: overall mean=N/A, median=N/A (n=0)')

    # php-src's runtime dwarfs every other project's, which would flatten them to
    # near-invisible boxes on a shared y-axis -- so it is dropped from the main
    # figure and given its own separate figure/file with its own y-scale.
    SPLIT_PROJECT = 'php-src'
    has_split = SPLIT_PROJECT in projects
    main_projects = [p for p in projects if p != SPLIT_PROJECT]
    categories = main_projects + ['Overall']

    method_names = [name for name, _, _ in METHODS]
    n_methods = len(method_names)
    box_width = 0.8 / n_methods
    offsets = [(i - (n_methods - 1) / 2) * box_width for i in range(n_methods)]

    def draw_group(axis, group_categories):
        """Draw the three method boxes for each category in group_categories.
        'Overall' pools every project's data (php-src included)."""
        for method_idx, method in enumerate(method_names):
            per_project = method_data[method]
            overall = [t for times in per_project.values() for t in times]
            series = [overall if cat == 'Overall' else per_project.get(cat, []) for cat in group_categories]
            positions = [i + offsets[method_idx] for i in range(len(group_categories))]
            # Boxplot chokes on empty series; keep positions aligned by feeding it a
            # sentinel and immediately hiding that box's artists.
            plot_series = [s if s else [np.nan] for s in series]
            bp = axis.boxplot(plot_series, positions=positions, widths=box_width * 0.9,
                               patch_artist=True, showfliers=False, manage_ticks=False,
                               showmeans=False, meanline=False,
                               medianprops=dict(color='#FF0000', linewidth=2.2, solid_capstyle='butt'))
            color = METHOD_COLORS[method]
            for element in bp['boxes']:
                element.set_facecolor(color)
                element.set_alpha(0.55)
                element.set_edgecolor(color)
            for element in bp['whiskers'] + bp['caps']:
                element.set_color(color)
            # Hide sentinel boxes for genuinely empty series.
            for i, s in enumerate(series):
                if s:
                    continue
                bp['boxes'][i].set_visible(False)
                for cap in bp['caps'][2 * i:2 * i + 2]:
                    cap.set_visible(False)
                for whisker in bp['whiskers'][2 * i:2 * i + 2]:
                    whisker.set_visible(False)
                bp['medians'][i].set_visible(False)

    def style_axis(axis, n_categories):
        axis.tick_params(axis='y', labelsize=FONT_SIZE)
        axis.grid(axis='y', color='#000000', alpha=0.08, linewidth=1)
        axis.set_axisbelow(True)
        for spine in ('top', 'right'):
            axis.spines[spine].set_visible(False)
        for i in range(n_categories - 1):
            axis.axvline(i + 0.5, color='#000000', alpha=0.06, linewidth=1)

    method_handles = [plt.Rectangle((0, 0), 1, 1, facecolor=METHOD_COLORS[m], alpha=0.55,
                                     edgecolor=METHOD_COLORS[m], label=m) for m in method_names]

    if has_split and split_php:
        # Two independent figures/files, each with its own y-scale.
        MAIN_FIG_WIDTH = 16
        fig, ax = plt.subplots(figsize=(MAIN_FIG_WIDTH, 6))
        draw_group(ax, categories)
        style_axis(ax, len(categories))
        ax.set_xticks(range(len(categories)))
        ax.set_xticklabels(categories, rotation=0, ha='center', fontsize=FONT_SIZE)
        ax.set_ylabel(ylabel, fontsize=FONT_SIZE)
        method_legend = ax.legend(handles=method_handles, title='Method', fontsize=FONT_SIZE,
                                   title_fontsize=FONT_SIZE)
        ax.add_artist(method_legend)
        fig.tight_layout()
        fig.savefig(output, dpi=150, bbox_inches='tight')
        print(f'Wrote {output}')

        # Size the php-only figure so its one box is exactly as wide (in inches) as a
        # box in the main figure: measure the main axes' plot area and margins (in
        # inches, after tight_layout) and give the php figure the same margins plus
        # one category-width's worth of plot area, rather than an arbitrary figsize.
        pos = ax.get_position()
        left_margin_in = pos.x0 * MAIN_FIG_WIDTH
        right_margin_in = (1 - pos.x1) * MAIN_FIG_WIDTH
        per_category_in = (pos.width * MAIN_FIG_WIDTH) / len(categories)
        php_fig_width = left_margin_in + per_category_in + right_margin_in

        fig_php, ax_php = plt.subplots(figsize=(php_fig_width, 6))
        draw_group(ax_php, [SPLIT_PROJECT])
        style_axis(ax_php, 1)
        ax_php.set_xticks([0])
        ax_php.set_xticklabels(['php'], rotation=0, ha='center', fontsize=FONT_SIZE)
        ax_php.set_ylabel(ylabel, fontsize=FONT_SIZE)
        # php_legend = ax_php.legend(handles=method_handles, title='Method', fontsize=FONT_SIZE,
        #                             title_fontsize=FONT_SIZE, bbox_to_anchor=(1.02, 1))
        fig_php.tight_layout()
        fig_php.savefig(php_output, dpi=150, bbox_inches='tight')
        print(f'Wrote {php_output}')
    else:
        # One all-in-one figure: php-src (if present) as a narrower subplot on the
        # left, with its own y-scale, followed by the main grid of projects + Overall
        # -- php-src on the right of Overall reads as if it were just another project
        # in that grid, which is confusing given its very different scale.
        if has_split:
            fig, (ax_split, ax) = plt.subplots(1, 2, figsize=(16, 6),
                                                gridspec_kw={'width_ratios': [1, len(categories)], 'wspace': 0.15})
        else:
            fig, ax = plt.subplots(figsize=(16, 6))
            ax_split = None

        draw_group(ax, categories)
        style_axis(ax, len(categories))
        ax.set_xticks(range(len(categories)))
        ax.set_xticklabels(categories, rotation=0, ha='center', fontsize=FONT_SIZE)
        # The ylabel goes on the leftmost subplot only -- php-src's, when present.
        if not has_split:
            ax.set_ylabel(ylabel, fontsize=FONT_SIZE)

        if has_split:
            draw_group(ax_split, [SPLIT_PROJECT])
            style_axis(ax_split, 1)
            ax_split.set_xticks([0])
            ax_split.set_xticklabels(['php'], rotation=0, ha='center', fontsize=FONT_SIZE)
            ax_split.set_ylabel(ylabel, fontsize=FONT_SIZE)

        method_legend = ax.legend(handles=method_handles, title='Method', fontsize=FONT_SIZE,
                                   title_fontsize=FONT_SIZE)
        ax.add_artist(method_legend)

        fig.tight_layout()
        fig.savefig(output, dpi=150, bbox_inches='tight')
        print(f'Wrote {output}')


def main():
    parser = ArgumentParser(description='Boxplot of san2patch validation-mode runtimes per project')
    parser.add_argument('-o', '--output', default=os.path.join(ARVO_DIR, 'rq1-san2patch-boxplot.pdf'),
                         help='Output image path')
    parser.add_argument('--split-php', action='store_true',
                         help='Draw php-src in its own separate output file (see --php-output) '
                              'instead of as a subplot of the main figure. Default: off '
                              '(one all-in-one figure, same as before).')
    parser.add_argument('--php-output', default=None,
                         help='Output image path for the php-src-only plot when --split-php is '
                              'given. Default: <output>-php<ext>')
    args = parser.parse_args()
    if args.php_output is None:
        base, ext = os.path.splitext(args.output)
        args.php_output = f'{base}-php{ext}'

    print('=== Plotted time (plotted metrics; see PLOT_TIME_KEYS) ===')
    make_boxplot(PLOT_TIME_KEYS, args.output, args.php_output, args.split_php)

    # Separate boxplot using only test_time, same layout/styling as the main one.
    base, ext = os.path.splitext(args.output)
    test_output = f'{base}-test-time{ext}'
    php_base, php_ext = os.path.splitext(args.php_output)
    test_php_output = f'{php_base}-test-time{php_ext}'
    print('\n=== test_time only ===')
    make_boxplot(TEST_TIME_KEYS, test_output, test_php_output, args.split_php, ylabel='Test Time (sec)')


if __name__ == '__main__':
    main()
