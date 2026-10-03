from argparse import ArgumentParser
import json
from multiprocessing.pool import AsyncResult
import os
import subprocess as sp
import multiprocessing as mp
import sys
import time
from typing import Dict, List, Tuple
import pandas as pd

import docker
import checkout


ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','..','..'))
CONTAINER_ROOT_DIR = '/root/project/metac'

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

def run(project:str, bug_id:int, skip_checkout:bool=False, is_ubsan:bool=False, skip_patch:bool=False, perfect_fl:bool=False):
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
            return False, 0., 0., 0., 0.
    docker.stop_container(bug_id)
    docker.start_container(bug_id)
    res = checkout.setup_metapro(project, bug_id)
    if not res:
        print(f'Failed to install metapro in {project}-{bug_id}')
        return False, 0., 0., 0., 0.
    
    work_dir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    container_work_dir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    file, line, binary = get_patch_loc(project, bug_id)
    if file is None:
        print(f'Cannot find patch location for project {project} bug {bug_id}, skip')
        return False, 0., 0., 0., 0.
    
    # Copy source code
    docker.exec_docker_cmd(['rm', '-rf', os.path.join(container_work_dir, 'source'),
                            os.path.join(container_work_dir, 'metapro-source')], bug_id)
    docker.exec_docker_cmd(['cp', '-rf', f'/src/{project}', os.path.join(container_work_dir, 'source')], bug_id)
    if os.path.exists(os.path.join(work_dir, 'compile_commands.json')):
        os.remove(os.path.join(work_dir, 'compile_commands.json'))

    # run metapro
    build_script = os.path.join(container_work_dir, 'build.py')
    new_env = os.environ.copy()
    if 'CXXFLAGS' in new_env:
        # Remove libc++ flags
        if '-stdlib=libc++' in new_env['CXXFLAGS']:
            new_env['CXXFLAGS'] = new_env['CXXFLAGS'].replace('-stdlib=libc++', '')
    new_env['CC'] = 'clang'
    new_env['CXX'] = 'clang++'
    new_env['LDFLAGS'] = '-pthread'
    new_env['UBSAN_OPTIONS'] = 'print_stacktrace=1:abort_on_error=1'
    new_env['ASAN_OPTIONS'] = 'detect_leaks=0'

    # TODO: Add CodeQL FL
    fl_file = os.path.join(container_work_dir, 'perfect-fl.txt')
    host_fl_file = os.path.join(work_dir, 'perfect-fl.txt')
    with open(host_fl_file, 'w') as f:
        for __file, __line in zip(file, line):
            f.write(f'{__file}:{__line}\n')
    cmd = ['metapro', container_work_dir, project, f"'python {build_script} {project} {bug_id} <source>'",
           '-output-dir', os.path.join(container_work_dir, "metapro-out"),
           '-source-dir', os.path.join(container_work_dir, 'source'), '-skip-cpp', '-log-mode', 'debug',
           '-remove-metapro-src-out-dir',
        #    '-wo-templates', 'REPLACE_CONDITION'
        ]
    if is_ubsan:
        cmd += ['-build-with-ubsan']
    else:
        cmd += ['-build-with-asan']
    if bug_id in (42513169, 42538183):
        # Some mruby bugs depends on the bear compile sequence
        cmd += ['-build-options', 'DMRB_USE_BIGINT']
    # cmd += ['-no-nop-inst']
    if perfect_fl:
        cmd += ['-fl', 'generic', '-fl-file', fl_file]
    else:
        cmd += ['-fl', 'all']
    
    print(f'Running metapro for project {project}-{bug_id}')
    start_time = time.time()
    res = docker.exec_docker_cmd(cmd, bug_id, cwd=container_work_dir, env=new_env,
                                 get_output=os.path.join(work_dir, 'metapro.log'))
    exec_time = time.time() - start_time
    gen_time, clean_build_time, build_time = 0., 0., 0.
    with open(os.path.join(work_dir, 'metapro.log'), 'r') as f:
        for line in f:
            if 'Meta-program generated in' in line:
                tokens = line.strip().split()
                gen_time = int(tokens[-2]) / 1000 # convert to second
            elif 'Meta-program built in' in line:
                tokens = line.strip().split()
                build_time = int(tokens[-2]) / 1000 # convert to second
            elif 'Meta-program clean built in' in line:
                tokens = line.strip().split()
                clean_build_time = int(tokens[-2]) / 1000 # convert to second
    if res.returncode != 0:
        print(f"Failed to run metapro for project {project}-{bug_id}, see {os.path.join(work_dir, 'metapro.log')}")
        return False, gen_time, clean_build_time, build_time, 0.
    
    # Run DynInst to apply the dev patch in binary level (w/ ASAN)
    patch_time = 0.
    if not skip_patch:
        print(f'Run binary patcher to apply the dev patch for project {project}-{bug_id}')
        metapro_out_dir = os.path.join(container_work_dir, 'metapro-out')
        dev_patch_path = os.path.join(container_work_dir, 'dev-patch-binary.json')
        if not os.path.exists(dev_patch_path):
            print(f'Cannot find dev patch file for project {project}-{bug_id}, skip patching')
            return True, gen_time, clean_build_time, build_time, 0.
        dev_patches = set()
        with open(dev_patch_path, 'r') as f:
            dev_patch = json.load(f)
            for patch in dev_patch:
                if patch['template'] in ('INSERT_EXPR', 'INSERT_NOT_NULL_CHECKER'):
                    dev_patches.add(f'{patch["id"]}:{patch["function"]}:{patch["file"]}:{patch["line"]}:{patch["col"]}:{patch["end_line"]}:{patch["end_col"]}')
        if len(dev_patches) == 0:
            # No insert patch, skip
            print(f'No insert patch for project {project}-{bug_id}, skip patching')
            return True, gen_time, clean_build_time, build_time, 0.
                
        if project != 'ffmpeg':
            start_time = time.time()
            cmd = ['patcher.py', container_work_dir, os.path.join(metapro_out_dir, 'asan-bin', binary),
                os.path.join(metapro_out_dir, 'asan-bin')]
            for patch in dev_patches:
                cmd += ['-p', patch]
            # print(f'Running command: {" ".join(cmd)}')
            res = docker.exec_docker_cmd(cmd, bug_id, cwd=container_work_dir, env=new_env,
                                        get_output=os.path.join(work_dir, 'binary-patcher-asan.log'))
            patch_time = time.time() - start_time
            if res.returncode != 0:
                print(f"Failed to apply patch (w/ ASAN) for project {project}-{bug_id}, see {os.path.join(work_dir, 'binary-patcher-asan.log')}")
                return False, gen_time, clean_build_time, build_time, patch_time

        # Run DynInst to apply the dev patch in binary level (w/o ASAN)
        cmd = ['patcher.py', container_work_dir, os.path.join(metapro_out_dir, 'bin', binary),
               os.path.join(metapro_out_dir, 'bin')]
        for patch in dev_patches:
            cmd += ['-p', patch]
        # print(f'Running command: {" ".join(cmd)}')
        res = docker.exec_docker_cmd(cmd, bug_id, cwd=container_work_dir, env=new_env,
                                    get_output=os.path.join(work_dir, 'binary-patcher.log'))
        if res.returncode != 0:
            print(f"Failed to apply patch (w/o ASAN) for project {project}-{bug_id}, see {os.path.join(work_dir, 'binary-patcher.log')}")
            return False, gen_time, clean_build_time, build_time, patch_time
    
    # docker.cleanup_container(bug_id)
    print(f'Successfully run metapro for project {project}-{bug_id}')
    return True, gen_time, clean_build_time, build_time, patch_time
    
if __name__ == "__main__":
    parser = ArgumentParser(prog='run-metapro', description='Run metapro to generate meta-program with lyso FL result')
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
    parser.add_argument('--skip-patch', action='store_true',
                        help='Skip instrumenting meta program binary to apply dev patch. Default: False')
    parser.add_argument('--perfect-fl', action='store_true',
                        help='Use perfect FL result for metapro. Default: False')
    args = parser.parse_args()

    projects:List[str] = args.project
    bug_ids:List[int] = args.bug_id

    # TODO: Temporary do not run whole benchmark
    if len(projects) == 0 and len(bug_ids) == 0:
        print('Either -p or -b option required', file=sys.stderr)
        exit(1)

    # Filter dataframe based on arguments
    df = pd.read_csv(os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'overview.csv'))
    new_df = pd.DataFrame(columns=['localId', 'project', 'result', 'gen time', 'clean build time', 'build time', 'patch time'])
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

        project_workdir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
        os.makedirs(project_workdir, exist_ok=True)
        res = pool.apply_async(run, args=(project, bug_id), kwds={'skip_checkout': args.skip_checkout, 'is_ubsan': row['sanitizer'] == 'ubsan',
                                                                  'skip_patch': args.skip_patch, 'perfect_fl': args.perfect_fl})
        async_results[(project, bug_id,)] = res
        # run(project, bug_id, args.skip_checkout)
    
    pool.close()
    pool.join()

    for (project, bug_id), res in async_results.items():
        res.wait()
        success, gen_time, clean_build_time, build_time, patch_time = res.get()
        new_df.loc[len(new_df)] = {
            'localId': bug_id,
            'project': project,
            'result': 'Y' if success else 'N',
            'gen time': gen_time,
            'clean build time': clean_build_time,
            'build time': build_time,
            'patch time': patch_time,
        }
    
    new_df.to_csv(os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'metapro-build-result.csv'))