#!/bin/bash
# Run the rq3 experiment (every validation mode, repeated) one project at a time.
#
# Per project:
#   1. checkout  rq3-contrafix-checkout.py creates arvo-<bug_id> with metapro built inside,
#                and dyninst too for the modes that use it (dyninst, combined, all).
#                Only for the modes that use that container (every mode but conv).
#                A bug whose container is already set up is skipped (FRESH_CHECKOUT=1 redoes it).
#                For the dyninst modes, prepare-dyninst-builds.py then builds each bug's dyninst
#                base (contrafix-dyninst-source/) once, so no run pays for it.
#   2. prepare   prepare-contrafix-images.py builds contrafix-f2r/arvo:<bug_id> at a lower
#                parallelism, so step 3 only hits the image cache (KEEP_IMAGE=1).
#   3. rq3       rq3-contrafix.py runs every mode, every repetition.
#   4. cleanup   cleanup-contrafix-images.sh drops what contrafix left behind (CLEANUP_AFTER).
#
# arvo-<bug_id> containers are kept, so a later run reuses them in step 1.
#
# Results: $RESULTS_ROOT/<project>/<mode>_run<i>.  Logs: $LOG_DIR, one file per project per step.
#
# Usage:
#   ./rq3-contrafix-pipeline.sh                              # every project, every mode, 1 run
#   MODE=metapro RUNS=3 ./rq3-contrafix-pipeline.sh libxml2  # one project, one mode
#   JOBS=16 CHECKOUT_JOBS=4 PREPARE_JOBS=4 ./rq3-contrafix-pipeline.sh
#   FRESH_CHECKOUT=1 ./rq3-contrafix-pipeline.sh             # rebuild containers (after changing metapro)
#   CLEANUP_AFTER=all ./rq3-contrafix-pipeline.sh            # also drop the prepared images
#   nohup ./rq3-contrafix-pipeline.sh &                      # logs are written by the script itself
set -uo pipefail  # pipefail: `python3 ... | tee` reports python's exit status

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

MODE="${MODE:-conv}"                     # conv | metapro | dyninst | combined
RUNS="${RUNS:-1}"                       # repetitions per mode
JOBS="${JOBS:-8}"                       # bugs solved in parallel (step 3)
# Steps 1 and 2 are mostly apt and downloads, so they fail on the network before the CPU.
# A failed checkout leaves a container without libclang-cpp, which only shows up later as
# "Could not find CLANG" in metapro's cmake configure.
CHECKOUT_JOBS="${CHECKOUT_JOBS:-$(( JOBS / 2 > 0 ? JOBS / 2 : 1 ))}"
PREPARE_JOBS="${PREPARE_JOBS:-8}"
# Keep prepared images between repetitions.  With 0, every repetition rebuilds them
# (3-4GB per bug otherwise stays on disk until cleanup).
KEEP_IMAGE="${KEEP_IMAGE:-1}"
# After each project:  containers = drop contrafix's containers, keep the image cache
#                      all        = drop the images too
#                      none       = keep everything
CLEANUP_AFTER="${CLEANUP_AFTER:-containers}"
FRESH_CHECKOUT="${FRESH_CHECKOUT:-0}"
RESULTS_ROOT="${RESULTS_ROOT:-$ROOT_DIR/contrafix/results_rq3}"
LOG_DIR="${LOG_DIR:-$SCRIPT_DIR/pipeline-logs}"

case "$MODE" in
    metapro)              NEEDS_CONTAINER=1; NEEDS_DYNINST=0 ;;
    dyninst|combined|all) NEEDS_CONTAINER=1; NEEDS_DYNINST=1 ;;
    *)                    NEEDS_CONTAINER=0; NEEDS_DYNINST=0 ;;
esac
# The python contrafix runs the dyninst validator with (arvo/dyninst.py DYNINST_PYTHON):
# it needs the San2Patch package.
DYNINST_PYTHON="${ARVO_DYNINST_PYTHON:-}"
if [ -z "$DYNINST_PYTHON" ]; then
    DYNINST_PYTHON=python3
    [ -x "$ROOT_DIR/san2patch/.venv/bin/python" ] && DYNINST_PYTHON="$ROOT_DIR/san2patch/.venv/bin/python"
fi

PROJECTS=("$@")
[ ${#PROJECTS[@]} -eq 0 ] && PROJECTS=(libxml2 mruby gpac ndpi ffmpeg php-src)

export PYTHONUNBUFFERED=1               # so `tail -f` on the logs shows progress
RUN_ID="rq3-$(date '+%Y%m%d-%H%M%S')"
mkdir -p "$LOG_DIR"
echo "logs: $LOG_DIR/$RUN_ID*, mode=$MODE runs=$RUNS jobs=$JOBS (checkout=$CHECKOUT_JOBS, prepare=$PREPARE_JOBS)"
exec > >(tee -a "$LOG_DIR/$RUN_ID.log") 2>&1

log() { echo "[$(date '+%F %T')] $*"; }

# The bugs a project contributes: the same ARVO filters rq3-contrafix.py applies.
bug_ids() {
    python3 - "$1" <<'EOF'
import os, sys
import pandas as pd
project = sys.argv[1]
csv = os.path.join(os.environ['ROOT_DIR'], 'benchmarks', 'arvo', 'overview.csv')
df = pd.read_csv(csv)
df = df[(df.project == project) & (df.submodule_bug == 'N') & (df.language == 'c') &
        (df['patch url available?'] == 'Y') & (df['ubuntu version'] == 20) &
        (df.sanitizer != 'msan')]
print(' '.join(str(i) for i in df.localId))
EOF
}

# Status counts of every <mode>_run<i> directory of a project.
summarize() {
    python3 - "$1" "$2" <<'EOF'
import collections, glob, json, os, sys
out_dir, project = sys.argv[1], sys.argv[2]
per_mode = {}
for run_dir in sorted(glob.glob(os.path.join(out_dir, '*_run*'))):
    counts = collections.Counter()
    for path in glob.glob(os.path.join(run_dir, f'{project}-*.json')):
        if path.endswith('.traj.json'):
            continue
        try:
            with open(path) as f:
                counts[json.load(f).get('status', 'unknown')] += 1
        except (OSError, ValueError):
            counts['unreadable'] += 1
    if counts:
        per_mode[os.path.basename(run_dir)] = dict(sorted(counts.items()))
print('; '.join(f'{k}: {v}' for k, v in per_mode.items()) or 'no results')
EOF
}

export ROOT_DIR
cd "$SCRIPT_DIR" || exit 1
for project in "${PROJECTS[@]}"; do
    ids=$(bug_ids "$project")
    count=$(wc -w <<< "$ids")
    out_dir="$RESULTS_ROOT/$project"
    mkdir -p "$out_dir"
    plog="$LOG_DIR/$RUN_ID-$project"

    # 1. checkout
    if [ "$NEEDS_CONTAINER" = "1" ]; then
        log "$project: checking out $count bugs (jobs=$CHECKOUT_JOBS)"
        checkout_flags=(-p "$project" -j "$CHECKOUT_JOBS" --skip-pull)
        [ "$FRESH_CHECKOUT" != "1" ] && checkout_flags+=(--skip-ready)
        [ "$NEEDS_DYNINST" = "1" ] && checkout_flags+=(--setup-dyninst)
        python3 rq3-contrafix-checkout.py "${checkout_flags[@]}" 2>&1 | tee "$plog-1-checkout.log"
        log "$project: checkout exit=$?"
        reused=$(grep -cE 'already set up with metapro( and dyninst)?, skipping checkout' "$plog-1-checkout.log") || reused=0
        log "$project: reused $reused / $count existing containers"
        # A failed apt install does not fail the checkout (docker.checkout only logs it).
        dep_fail=$(grep -c 'Failed to install dependencies' "$plog-1-checkout.log") || dep_fail=0
        [ "$dep_fail" != "0" ] && log "$project: !!! dependency install failed for $dep_fail bugs; rerun with a lower CHECKOUT_JOBS"

        if [ "$NEEDS_DYNINST" = "1" ]; then
            # A bug already built returns at once, so a rerun only fills in the failures.
            log "$project: building dyninst bases (jobs=$PREPARE_JOBS, python=$DYNINST_PYTHON)"
            "$DYNINST_PYTHON" prepare-dyninst-builds.py -p "$project" -j "$PREPARE_JOBS" \
                2>&1 | tee "$plog-1-dyninst.log"
            dyn_rc=$?
            log "$project: dyninst bases exit=$dyn_rc"
            [ "$dyn_rc" != "0" ] && log "$project: !!! some dyninst bases were not built; those bugs end as dyninst_unavailable"
        fi
    else
        log "$project: mode=$MODE does not use arvo-<bug_id> containers, skipping checkout"
    fi

    # 2. prepare (existing images are skipped, so a rerun only fills in the failures)
    rq3_flags=()
    if [ "$KEEP_IMAGE" = "1" ]; then
        rq3_flags+=(--keep-image)
        log "$project: preparing images (jobs=$PREPARE_JOBS)"
        python3 prepare-contrafix-images.py -p "$project" -j "$PREPARE_JOBS" \
            --log-dir "$out_dir/prepare-logs" 2>&1 | tee "$plog-2-prepare.log"
        prep_rc=$?
        log "$project: prepare exit=$prep_rc"
        [ "$prep_rc" != "0" ] && log "$project: !!! some images were not prepared; rerun with a lower PREPARE_JOBS"
    fi

    # 3. rq3
    log "$project: rq3 (mode=$MODE, runs=$RUNS, jobs=$JOBS, keep-image=$KEEP_IMAGE, results=$out_dir)"
    python3 rq3-contrafix.py -p "$project" --mode "$MODE" -n "$RUNS" -j "$JOBS" \
        "${rq3_flags[@]+"${rq3_flags[@]}"}" \
        --results-root "$RESULTS_ROOT" 2>&1 | tee "$plog-3-rq3.log"
    log "$project: rq3 exit=$?"

    # 4. cleanup (only this project's bug ids)
    case "$CLEANUP_AFTER" in
        none) ;;
        containers|all)
            cleanup_flags=(-y --ids "$ids")
            [ "$CLEANUP_AFTER" = "containers" ] && cleanup_flags+=(-c)
            log "$project: cleanup (CLEANUP_AFTER=$CLEANUP_AFTER)"
            ./cleanup-contrafix-images.sh "${cleanup_flags[@]}" 2>&1 | tee "$plog-4-cleanup.log"
            ;;
        *)
            log "$project: !!! unknown CLEANUP_AFTER=$CLEANUP_AFTER (none|containers|all), skipping cleanup"
            ;;
    esac

    log "$project: done  $(summarize "$out_dir" "$project")"
done
