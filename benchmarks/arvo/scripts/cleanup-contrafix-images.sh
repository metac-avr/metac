#!/usr/bin/env bash
# Remove the prepared images contrafix commits per bug (contrafix-f2r/arvo:<bug_id>) and the
# containers started from them.
#
# Each image is the ARVO base image plus apt, clang-12 and a configure build, committed
# (prepare_image in contrafix/arvo/docker_tools.py), so they pile up at 3-4GB apiece. They are
# left behind when REMOVE_PREPARED_IMAGE (config.py) is off or a run is interrupted. Removing
# them costs only preparation time: the next run prepares them again.
#
# The containers are the main/Patcher ones contrafix starts, with random names
# (nostalgic_khorana and the like), so they are found by the image they reference.
#
# Base images (n132/arvo:<id>-vul) are not touched; see cleanup-arvo-containers.sh --images.
#
# By default nothing is removed, only the targets are listed. Pass -y to remove them.
#
# Usage: ./cleanup-contrafix-images.sh [-y] [-c] [-j N] [--repo REPO] [--ids "id..."]
#   -y, --yes              remove for real (default: preview)
#   -c, --containers-only  remove the containers, keep the images. The images are a cache
#                          that takes tens of minutes per bug to rebuild; use this to free
#                          some disk without losing it.
#   -j N                   removals in parallel (default: 8)
#   --repo REPO            image repository (default: $ARVO_PREPARED_IMAGE_REPO or contrafix-f2r/arvo)
#   --ids "id1 id2 ..."    only these bugs (default: the whole repository), e.g. to clean up
#                          one project once it is done.
set -uo pipefail

APPLY=0
CONTAINERS_ONLY=0
JOBS=8
REPO="${ARVO_PREPARED_IMAGE_REPO:-contrafix-f2r/arvo}"
IDS=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        -y|--yes)               APPLY=1; shift ;;
        -c|--containers-only)   CONTAINERS_ONLY=1; shift ;;
        -j)                     JOBS="$2"; shift 2 ;;
        --repo)                 REPO="$2"; shift 2 ;;
        --ids)                  read -r -a IDS <<< "$2"; shift 2 ;;
        -h|--help)              sed -n '2,25p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *)                      echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

# A running contrafix would lose the images it prepared, so warn first. Nothing is killed:
# what to stop is the user's call.
#
# The pattern only matches the processes that use the images (arvo.main and the runners
# that start it). The rq3 pipeline script is left out on purpose: it calls this script at a
# safe point after each project, and a wider pattern would warn about it every time.
RUNNING=$(pgrep -fa 'arvo\.main|rq3-contrafix\.py|run-contrafix\.py' 2>/dev/null \
    | grep -v "cleanup-contrafix-images" | grep -v "^$$ ")
if [ -n "$RUNNING" ]; then
    echo "!!! contrafix processes are still running. Stop them first:"
    echo "$RUNNING" | sed 's/^/    /'
    echo
fi

mapfile -t ALL_IMAGES < <(docker images "$REPO" --format '{{.Repository}}:{{.Tag}}' | sort)

# With --ids, keep only those bugs. Ids with no image are dropped silently.
IMAGES=()
if [ "${#IDS[@]}" -eq 0 ]; then
    IMAGES=("${ALL_IMAGES[@]+"${ALL_IMAGES[@]}"}")
else
    declare -A WANT_ID=()
    for id in "${IDS[@]}"; do WANT_ID["$id"]=1; done
    for img in "${ALL_IMAGES[@]+"${ALL_IMAGES[@]}"}"; do
        [ -n "${WANT_ID[${img##*:}]:-}" ] && IMAGES+=("$img")
    done
fi

# docker rmi only succeeds once the containers holding an image are gone. A container
# references its image either as repo:tag or by image ID, so match both. The repo:tag prefix
# match below also catches containers whose image is already gone (no ID to match then).
declare -A WANTED=()
for img in "${IMAGES[@]+"${IMAGES[@]}"}"; do WANTED["$img"]=1; done
while IFS=$'\t' read -r iid itag; do
    [ -z "$iid" ] && continue
    [ -n "${WANTED[$itag]:-}" ] && WANTED["${iid#sha256:}"]=1
done < <(docker images "$REPO" --no-trunc --format '{{.ID}}\t{{.Repository}}:{{.Tag}}')

CONTAINERS=()
while IFS=$'\t' read -r cname cimage; do
    [ -z "$cname" ] && continue
    key="${cimage#sha256:}"
    if [ -n "${WANTED[$cimage]:-}${WANTED[$key]:-}" ]; then
        CONTAINERS+=("$cname")
    elif [ "${#IDS[@]}" -eq 0 ] && [ "${cimage#"$REPO":}" != "$cimage" ]; then
        # The image is gone (so not in WANTED) but the reference still names this repository.
        # Left alone when --ids narrows the run, since which bug it belongs to is not certain.
        CONTAINERS+=("$cname")
    fi
done < <(docker ps -a --format '{{.Names}}\t{{.Image}}')

if [ "$CONTAINERS_ONLY" = 1 ]; then
    echo "targets: ${#CONTAINERS[@]} containers (${#IMAGES[@]} images kept)"
else
    echo "targets: ${#IMAGES[@]} $REPO images, ${#CONTAINERS[@]} containers using them"
fi

if [ "${#CONTAINERS[@]}" -eq 0 ] && { [ "$CONTAINERS_ONLY" = 1 ] || [ "${#IMAGES[@]}" -eq 0 ]; }; then
    echo "nothing to remove."
    exit 0
fi

if [ "$APPLY" = 0 ]; then
    echo
    echo "--- preview (nothing removed) ---"
    if [ "$CONTAINERS_ONLY" = 0 ] && [ "${#IMAGES[@]}" -gt 0 ]; then
        for img in "${IMAGES[@]}"; do
            printf '  %s\t%s\n' "$img" "$(docker images "$img" --format '{{.Size}}' | head -1)"
        done | head -60
        [ "${#IMAGES[@]}" -gt 60 ] && echo "  ... and $(( ${#IMAGES[@]} - 60 )) more"
    fi
    [ "${#CONTAINERS[@]}" -gt 0 ] && printf '  container %s\n' "${CONTAINERS[@]}" | head -20
    [ "${#CONTAINERS[@]}" -gt 20 ] && echo "  ... and $(( ${#CONTAINERS[@]} - 20 )) more"
    echo
    echo "Run again with -y to remove them."
    exit 0
fi

echo
if [ "${#CONTAINERS[@]}" -gt 0 ]; then
    echo "removing containers (-j $JOBS)..."
    printf '%s\n' "${CONTAINERS[@]}" | xargs -r -P "$JOBS" -n 4 docker rm -f >/dev/null 2>&1
fi

if [ "$CONTAINERS_ONLY" = 1 ]; then
    LEFT_C=0
    for name in "${CONTAINERS[@]}"; do
        docker inspect "$name" >/dev/null 2>&1 && LEFT_C=$((LEFT_C + 1))
    done
    echo
    if [ "$LEFT_C" -eq 0 ]; then
        echo "done: ${#CONTAINERS[@]} containers removed (${#IMAGES[@]} images kept)."
    else
        echo "warning: ${LEFT_C} containers are still there."
        exit 1
    fi
    exit 0
fi

echo "removing images (-j $JOBS)..."
printf '%s\n' "${IMAGES[@]}" | xargs -r -P "$JOBS" -n 4 docker rmi >/dev/null 2>&1

# Do not pass over what is left (held by another container, has child images, ...).
LEFT=()
for img in "${IMAGES[@]}"; do
    [ -n "$(docker images -q "$img" 2>/dev/null)" ] && LEFT+=("$img")
done

echo
if [ "${#LEFT[@]}" -eq 0 ]; then
    echo "done: ${#IMAGES[@]} images removed."
else
    echo "warning: ${#LEFT[@]} images are still there (another container may hold them):"
    printf '  %s\n' "${LEFT[@]}" | head -20
    exit 1
fi
