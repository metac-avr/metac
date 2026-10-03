"""Check out the arvo-<bug_id> containers ContraFix's rq3 runs need, reusing ready ones.

checkout.py is shared with San2Patch and keeps changing on the dyninst side, so the rq3-only
behaviour lives here instead, on top of checkout.py's own functions (imported, never edited):

  --skip-ready  leave a bug alone when its container already exists with metapro set up
                (metapro_ready). With --setup-dyninst such a container only gets dyninst
                added when it lacks it, and is never recreated.
  --skip-pull   do not pull the ARVO image; use the one already on this host. Without it the
                pull in docker.checkout retries every 60 seconds forever on a host with no
                registry access.
  --skip-setup  only create the container (and dyninst, with --setup-dyninst): no copy_source,
                no setup_metapro -- for callers that build metapro themselves, as
                rq1-2-contrafix-metac.py does.

Unlike checkout.py's __main__, this builds metapro (setup_metapro) after a fresh checkout
unless --skip-setup is given -- the rq3 metapro/combined modes need it inside the container -- and never removes
the containers it made. cmake and Dyninst's elfutils come from tools/ (through the bind
mount) instead of being downloaded per bug, and /src/dyninst is removed once dyninst is set up.

rq3-contrafix-pipeline.sh counts reused containers by the "already set up with metapro" message.
"""

import argparse
import json
import multiprocessing as mp
import os
import subprocess as sp
import sys
import traceback
from typing import List

import pandas as pd

import checkout
import docker
import minibenchmark
from checkout import CONTAINER_ROOT_DIR, ROOT_DIR

# What setup_metapro leaves in a container (metapro's `make install`); together with copy_source's
# source/ and poc in the bug's work directory, a container holding all of it needs neither again.
METAPRO_INSTALLED_FILES = (
    '/usr/local/bin/metapro',
    '/usr/local/bin/metapro-tcc',
    '/usr/local/bin/metapro-e9patch',
    '/usr/local/bin/patcher-e9patch.py',
    '/usr/local/bin/dwarf_index.py',
    '/usr/local/lib/libmetapro-runtime-c.so',
)
DYNINST_INSTALLED_FILES = (
    '/opt/dyninst-tool/mutator_launch',
    '/usr/local/bin/clang.real',
    '/usr/local/bin/clang++.real',
)
TOOLS_CMAKE_DIR = os.path.join(CONTAINER_ROOT_DIR, 'tools', 'cmake-3.31.11-linux-x86_64')
TOOLS_ELFUTILS = 'elfutils-0.186.tar.bz2'


def _work_dir(project: str, bug_id: int) -> str:
    return os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))


def metapro_ready(project: str, bug_id: int) -> bool:
    """Whether arvo-<bug_id> already exists with metapro set up. A stopped container is started
    first, since the check runs inside it. Only the installed files are checked, not their age:
    after changing metapro, run without --skip-ready."""
    if not docker.container_exists(bug_id):
        return False
    if sp.run(['docker', 'start', f'arvo-{bug_id}'], stdout=sp.DEVNULL, stderr=sp.DEVNULL).returncode != 0:
        return False
    if not all(docker.check_file_exist(path, bug_id) for path in METAPRO_INSTALLED_FILES):
        return False
    if docker.exec_docker_cmd(['metapro', '-h'], bug_id, get_output=True).returncode != 0:
        return False
    work_dir = _work_dir(project, bug_id)
    return os.path.isdir(os.path.join(work_dir, 'source')) and os.path.isfile(os.path.join(work_dir, 'poc'))


def dyninst_ready(bug_id: int) -> bool:
    """Whether setup_dyninst already ran in the (running) container."""
    return all(docker.check_file_exist(path, bug_id) for path in DYNINST_INSTALLED_FILES)


def install_cmake(bug_id: int) -> None:
    """Put tools/'s cmake 3.31 into /usr/local, so setup_metapro/setup_dyninst find it installed
    and skip their own per-bug download. Leaves things to them when tools/ has no copy."""
    res = docker.exec_docker_cmd(['cmake', '--version'], bug_id, get_output=True)
    if res.returncode == 0 and '3.31' in res.stdout.decode('utf-8'):
        return
    if not docker.check_file_exist(f'{TOOLS_CMAKE_DIR}/bin/cmake', bug_id):
        return
    for sub in ('bin', 'share'):
        docker.exec_docker_cmd(['cp', '-rf', f'{TOOLS_CMAKE_DIR}/{sub}', '/usr/local'], bug_id, get_output=True)


def add_dyninst(project: str, bug_id: int) -> bool:
    """setup_dyninst, then drop its source and build trees (~0.5GB per container): everything used
    afterwards is installed under /usr/local and /opt/dyninst-tool. Kept on failure, for the log."""
    install_cmake(bug_id)
    ok = checkout.setup_dyninst(project, bug_id)
    if ok:
        docker.exec_docker_cmd(['rm', '-rf', '/src/dyninst', '/src/dyninst-poc'], bug_id, get_output=True)
    return ok


class _NoPull:
    """Stands in for docker.py's `subprocess` so docker.checkout's pull is a no-op (--skip-pull).
    Done from here so this does not depend on docker.checkout having a skip_pull parameter."""

    def __getattr__(self, name):
        return getattr(sp, name)

    @staticmethod
    def run(cmd, *args, **kwargs):
        if list(cmd[:2]) == ['docker', 'pull']:
            return sp.CompletedProcess(cmd, 0)
        return sp.run(cmd, *args, **kwargs)


def run(project: str, bug_id: int, host_mount_path: str, skip_pull: bool, skip_ready: bool,
        setup_dyninst: bool, skip_setup: bool = False):
    """Returns (metapro_ok, dyninst_ok); None for a step that did not run."""
    if skip_ready and metapro_ready(project, bug_id):
        if not setup_dyninst or dyninst_ready(bug_id):
            with_dyninst = ' and dyninst' if setup_dyninst else ''
            print(f'Container for {project}-{bug_id} already set up with metapro{with_dyninst}, skipping checkout')
            return None, None
        print(f'Container for {project}-{bug_id} already set up with metapro, adding dyninst only')
        return None, add_dyninst(project, bug_id)

    if skip_pull:
        image = f'n132/arvo:{bug_id}-vul'
        if sp.run(['docker', 'image', 'inspect', image], stdout=sp.DEVNULL, stderr=sp.DEVNULL).returncode != 0:
            # `docker run` would pull a missing image itself, and hang the same way the pull does.
            print(f'{image} is not on this host; cannot check out {project}-{bug_id} with --skip-pull')
            return False, None
    checkout_res = docker.checkout(project, bug_id, host_mount_path, install_dependency=True)
    if checkout_res is not None and checkout_res is not True:
        return False, None
    if skip_setup:
        metapro_ok = None
    else:
        metapro_ok = checkout.copy_source(project, bug_id)
    if metapro_ok:
        install_cmake(bug_id)
        metapro_ok = checkout.setup_metapro(project, bug_id)
    dyninst_ok = add_dyninst(project, bug_id) if setup_dyninst else None
    return metapro_ok, dyninst_ok


def _except_handler(e: Exception):
    print(f'Error occurred: {e}')
    traceback.print_exception(type(e), e, e.__traceback__)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('-p', '--project', nargs='*', default=[], help='Projects to check out')
    parser.add_argument('-b', '--bug-id', type=int, nargs='*', default=[], help='Bug IDs to check out')
    parser.add_argument('-j', '--jobs', type=int, default=1, help='Bugs checked out in parallel')
    parser.add_argument('-m', '--mini', action='store_true', help='Mini benchmark bugs only')
    parser.add_argument('--skip-pull', action='store_true', help='Use the ARVO image already on this host')
    parser.add_argument('--skip-ready', action='store_true',
                        help='Reuse a container that already has metapro (and, with --setup-dyninst, dyninst)')
    parser.add_argument('--setup-dyninst', action='store_true', help='Also set up dyninst in the container')
    parser.add_argument('--skip-setup', action='store_true',
                        help='Create the container only: no copy_source, no setup_metapro')
    args = parser.parse_args()

    with open(os.path.join(ROOT_DIR, 'config.json')) as f:
        host_mount_path = json.load(f)['host_mount_path']

    # setup_dyninst reads this; the tarball under tools/ is reached through the bind mount.
    if 'DYNINST_ELFUTILS_TARBALL' not in os.environ and os.path.isfile(os.path.join(ROOT_DIR, 'tools', TOOLS_ELFUTILS)):
        os.environ['DYNINST_ELFUTILS_TARBALL'] = os.path.join(CONTAINER_ROOT_DIR, 'tools', TOOLS_ELFUTILS)
    if args.skip_pull:
        docker.sp = _NoPull()

    # The same bugs checkout.py picks (MSan excluded).
    df = pd.read_csv(os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'overview.csv'))
    df = df[(df.submodule_bug == 'N') & (df.language == 'c') & (df['patch url available?'] == 'Y') &
            (df['ubuntu version'] == 20) & (df.sanitizer != 'msan')]
    bugs = []
    for _, row in df.iterrows():
        project, bug_id = row['project'], int(row['localId'])
        if args.bug_id and bug_id not in args.bug_id:
            continue
        if args.project and project not in args.project:
            continue
        if args.mini and str(bug_id) not in minibenchmark.ARVO_MINI[project]:
            continue
        os.makedirs(_work_dir(project, bug_id), exist_ok=True)
        bugs.append((project, bug_id))

    mp.set_start_method('fork')  # the workers inherit the _NoPull swap above
    with mp.Pool(processes=args.jobs) as pool:
        results = {bug: pool.apply_async(run, (*bug, host_mount_path, args.skip_pull, args.skip_ready,
                                               args.setup_dyninst, args.skip_setup),
                                         error_callback=_except_handler)
                   for bug in bugs}
        pool.close()
        pool.join()

    failed_metapro: List[str] = []
    failed_dyninst: List[str] = []
    for (project, bug_id), res in results.items():
        try:
            metapro_ok, dyninst_ok = res.get()
        except Exception:
            metapro_ok, dyninst_ok = False, None
        if metapro_ok is False:
            failed_metapro.append(f'{project}-{bug_id}')
        if dyninst_ok is False:
            failed_dyninst.append(f'{project}-{bug_id}')
    if failed_metapro:
        print(f'Checkout/metapro setup failed for {len(failed_metapro)} bugs: {" ".join(failed_metapro)}')
    if failed_dyninst:
        print(f'Dyninst setup failed for {len(failed_dyninst)} bugs: {" ".join(failed_dyninst)}')
    return 1 if failed_metapro or failed_dyninst else 0


if __name__ == '__main__':
    sys.exit(main())
