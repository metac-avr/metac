from argparse import ArgumentParser
import json
from multiprocessing.pool import AsyncResult
import os
import shutil
import subprocess as sp
import multiprocessing as mp
import sys
import time
from typing import Dict, List, Tuple
import pandas as pd

import docker
import minibenchmark


ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','..','..'))
CONTAINER_ROOT_DIR = '/root/project/metac'

def clean_generated_source(work_dir:str, *names:str):
    """Remove the source tree copies a run leaves behind in the bug's work directory.

    Each run copies `source` into a working tree of its own and never takes it back out,
    so a bug ends up holding several full checkouts. `source` itself is the pristine
    reference the rest of the pipeline reads, so only the copies go.
    """
    for name in names:
        path = os.path.join(work_dir, name)
        if not os.path.isdir(path):
            continue
        print(f'Removing generated source directory {path}')
        shutil.rmtree(path, ignore_errors=True)

def get_patch_loc(project:str, bug_id:int):
    overview_csv = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'overview.csv')
    df = pd.read_csv(overview_csv, dtype={'patched line':str})
    row = df[(df['project'] == project) & (df['localId'] == bug_id)]
    if row.empty:
        print(f'Cannot find patch location for project {project} bug {bug_id} in overview.csv')
        return None, None, None
    file:List[str] = row['patched file'].values[0].split(',')
    try:
        __line:List[str] = row['patched line'].values[0].split(',')
    except AttributeError:
        print(f'Error when parsing line in bug {project}-{bug_id}')
        return None, None, None
    if len(file) == 1 and len(__line) > 1:
        # If there is only one patched file but multiple patched lines, duplicate the file path
        file = file * len(__line)
    line = [int(l) for l in __line]
    return file, line, row['fuzz_target'].values[0]

def run(project:str, bug_id:int, binary:str, sanitizer:str, skip_checkout:bool=False):
    # Parse config file
    config_path = os.path.join(ROOT_DIR, 'config.json')
    if not os.path.exists(config_path):
        raise FileNotFoundError(f'Configuration file not found at {config_path}, please create based on config.template.json!')
    with open(config_path, 'r') as f:
        config = json.load(f)
    host_mount_path = config['host_mount_path']

    # Checkout container
    if not skip_checkout:
        res = docker.checkout(project, bug_id, host_mount_path, install_dependency=True)
        if not res:
            print(f'Failed to checkout {project}-{bug_id}')
            return False
    res = sp.run(['docker', 'restart', f'arvo-{bug_id}'], stdout=sp.PIPE, stderr=sp.STDOUT)
    
    work_dir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    file, line, binary = get_patch_loc(project, bug_id)
    if file is None:
        print(f'Cannot find patch location for project {project} bug {bug_id}, skip')
        docker.stop_container(bug_id)
        return False
    # if os.path.exists(os.path.join(work_dir, 'san2patch')) and not os.path.exists(os.path.join(work_dir, 'san2patch_backup')):
    #     shutil.copytree(os.path.join(work_dir, 'san2patch'), os.path.join(work_dir, 'san2patch_backup'), dirs_exist_ok=True)
        
    print(f'Run san2patch for project {project}-{bug_id}')
                
    cmd = ['python3', os.path.join(ROOT_DIR, 'san2patch', 'run-arvo.py'), project, str(bug_id),
            binary, sanitizer,
            # 'gpt-4o',
            # 'qwen-3-coder-next',
            # 'qwen-3-coder',
            # 'claude-opus-5',
            # 'gpt-5.6-sol',
            'deepseek-v4-pro',
            '--raise-exception',
            '-o', os.path.join(work_dir, 'san2patch-deepseek'),
            '-r', '--halt-on-success']
    # print(f'Running command: {" ".join(cmd)}')
    try:
        with open(os.path.join(work_dir, 'san2patch.log'), 'wb') as f:
            res = sp.run(cmd, stdout=f, stderr=f)
        if res.returncode != 0:
            print(f"Failed to run san2patch for project {project}-{bug_id}, see {os.path.join(work_dir, 'san2patch.log')}")
            docker.stop_container(bug_id)
            return False

        docker.stop_container(bug_id)
        # docker.cleanup_container(bug_id)
        print(f'Successfully run san2patch for project {project}-{bug_id}')
        return True
    finally:
        # san2patch copies `source` into `san2patch-source` (patcher.py) on every run
        clean_generated_source(work_dir, 'san2patch-source')
    
if __name__ == "__main__":
    parser = ArgumentParser(prog='run-san2patch', description='Run binary patcher to apply dev patch')
    parser.add_argument('-p', '--project', type=str, nargs='*', default=[],
                        help='Projects to checkout. Multiple projects available. Default: None')
    parser.add_argument('-b', '--bug-id', type=int, nargs='*', default=[],
                        help='Bug IDs to checkout. Multiple bug IDs available. Default: None')
    parser.add_argument('-j', '--jobs', type=int, default=1,
                        help='Number of parallel jobs to run. Default: 1')
    parser.add_argument('--use-msan', action='store_true',
                        help='Use bugs which use MSAN. Default: False')
    parser.add_argument('--skip-checkout', action='store_true',
                        help='Skip checkout and directly run metapro. Default: False')
    parser.add_argument('-m', '--mini', action='store_true',
                        help='Run mini benchmark on a small set of 5 bugs per project. Default: False')
    args = parser.parse_args()

    projects:List[str] = args.project
    bug_ids:List[int] = args.bug_id

    # TODO: Temporary do not run whole benchmark
    if len(projects) == 0 and len(bug_ids) == 0:
        print('Either -p or -b option required', file=sys.stderr)
        exit(1)

    # Filter dataframe based on arguments
    df = pd.read_csv(os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'overview.csv'))
    new_df = pd.DataFrame(columns=['localId', 'project', 'result', 'gen time', 'clean build time', 'build time'])
    async_results:Dict[Tuple[str,int],AsyncResult] = dict()
    
    pool = mp.Pool(processes=args.jobs)
    for index, row in df.iterrows():
        project = row['project']
        bug_id = row['localId']
        if (row['submodule_bug'] != 'N' or row['language'] != 'c' or row['patch url available?'] != 'Y' or
            row['ubuntu version'] != 20):
            # Excluded bugs
            continue
        if not args.use_msan and row['sanitizer'] == 'msan':
            # Exclude MSan
            continue
        if len(bug_ids) > 0 and bug_id not in bug_ids:
            # Test specified bugs only
            continue
        if len(projects) > 0 and project not in projects:
            # Test specified projects only
            continue
        if args.mini and str(bug_id) not in minibenchmark.ARVO_MINI[project]:
            # If mini benchmark, only run on a small set of bugs
            continue

        project_workdir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
        os.makedirs(project_workdir, exist_ok=True)
        pool.apply_async(run, args=(project, bug_id, row['fuzz_target'], row['sanitizer']), kwds={'skip_checkout': args.skip_checkout})
        # run(project, bug_id, args.skip_checkout)
    
    pool.close()
    pool.join()