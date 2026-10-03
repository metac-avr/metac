from argparse import ArgumentParser
import json
import os
import multiprocessing as mp
import sys
from typing import List
import pandas as pd

import docker
import checkout


def test_vul(project:str, bug_id:int, binary:str, san:str):
    # Parse config file
    print(f'Testing vulnerable version of {project} - Bug {bug_id}...')
    config_path = os.path.join(docker.ROOT_DIR, 'config.json')
    if not os.path.exists(config_path):
        raise FileNotFoundError(f'Configuration file not found at {config_path}, please create based on config.template.json!')
    with open(config_path, 'r') as f:
        config = json.load(f)
    host_mount_path = config['host_mount_path']

    project_workdir = os.path.join(docker.ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    os.makedirs(project_workdir, exist_ok=True)
    
    # Checkout vulnerable version
    res = docker.checkout(project, bug_id, host_mount_path, install_dependency=True, fixed_version=False)
    if not res:
        print(f'Failed to checkout {project}-{bug_id}')
        docker.cleanup_container(bug_id, remove_image=False, fixed_version=False)
        return False
    
    # Build
    print(f'Building {project} - Bug {bug_id}...')
    new_env = {
        'CC': 'clang',
        'CXX': 'clang++'
    }
    if san=='asan':
        new_env['CFLAGS'] = '-fsanitize=address -fno-omit-frame-pointer'
        new_env['CXXFLAGS'] = '-fsanitize=address -fno-omit-frame-pointer'
        new_env['LDFLAGS'] = '-fsanitize=address'
    else:
        new_env['CFLAGS'] = '-fsanitize=undefined -fno-omit-frame-pointer -fno-sanitize-recover=all'
        new_env['CXXFLAGS'] = '-fsanitize=undefined -fno-omit-frame-pointer -fno-sanitize-recover=all'
        new_env['LDFLAGS'] = '-fsanitize=undefined'

    with open(os.path.join(project_workdir, 'build.log'), 'w') as f:
        res = docker.exec_docker_cmd(['python',
                                      f'/root/project/metac/benchmarks/arvo/projects/{project}/{bug_id}/build.py',
                                      project, str(bug_id), f'/src/{project}', '-o', '/out/my', '-j', '50'],
                                      bug_id, cwd='/src', env=new_env, get_output=f)
    if res.returncode != 0:
        print(f'Failed to build original version for {project} - Bug {bug_id}!')
        docker.cleanup_container(bug_id, remove_image=False, fixed_version=False)
        return False
    print(f'Successfully built original version for {project} - Bug {bug_id}.')
    
    # Check vulnerability trigger
    print(f'Checking vulnerability trigger for {project} - Bug {bug_id}...')
    new_env = {
        'ASAN_OPTIONS': 'detect_leaks=0',
        'UBSAN_OPTIONS': 'abort_on_error=1:print_stacktrace=1'
    }
    with open(os.path.join(project_workdir, 'test.log'), 'w') as f:
        res = docker.exec_docker_cmd([f'/out/my/{binary}', '/tmp/poc'], bug_id, get_output=f, env=new_env)
        if res.returncode == 0:
            print(f'Vulnerability not triggered for {project}-{bug_id}!')
            docker.cleanup_container(bug_id, remove_image=False, fixed_version=False)
            return False
    docker.cleanup_container(bug_id, remove_image=False, fixed_version=False)
    return True

def test_fixed(project:str, bug_id:int, binary:str, san:str):
    print(f'Testing fixed version of {project} - Bug {bug_id}...')
    # Parse config file
    config_path = os.path.join(docker.ROOT_DIR, 'config.json')
    if not os.path.exists(config_path):
        raise FileNotFoundError(f'Configuration file not found at {config_path}, please create based on config.template.json!')
    with open(config_path, 'r') as f:
        config = json.load(f)
    host_mount_path = config['host_mount_path']

    project_workdir = os.path.join(docker.ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    os.makedirs(project_workdir, exist_ok=True)
    
    # Checkout fixed version
    res = docker.checkout(project, bug_id, host_mount_path, install_dependency=True, fixed_version=True)
    if not res:
        print(f'Failed to checkout {project}-{bug_id} fixed version')
        docker.cleanup_container(bug_id, remove_image=True, fixed_version=True)
        return False
    
    # Build
    print(f'Building {project} - Bug {bug_id} fixed version...')
    new_env = {
        'CC': 'clang',
        'CXX': 'clang++'
    }
    if san=='asan':
        new_env['CFLAGS'] = '-fsanitize=address -fno-omit-frame-pointer'
        new_env['CXXFLAGS'] = '-fsanitize=address -fno-omit-frame-pointer'
        new_env['LDFLAGS'] = '-fsanitize=address'
    else:
        new_env['CFLAGS'] = '-fsanitize=undefined -fno-omit-frame-pointer -fno-sanitize-recover=all'
        new_env['CXXFLAGS'] = '-fsanitize=undefined -fno-omit-frame-pointer -fno-sanitize-recover=all'
        new_env['LDFLAGS'] = '-fsanitize=undefined'
        
    with open(os.path.join(project_workdir, 'build-fixed.log'), 'w') as f:
        res = docker.exec_docker_cmd(['python',
                                      f'/root/project/metac/benchmarks/arvo/projects/{project}/{bug_id}/build.py',
                                      project, str(bug_id), f'/src/{project}', '-o', '/out/my', '-j', '50'],
                                      bug_id, cwd='/src', env=new_env, get_output=f, fixed_version=True)
    if res.returncode != 0:
        print(f'Failed to build fixed version for {project} - Bug {bug_id}!')
        docker.cleanup_container(bug_id, remove_image=True, fixed_version=True)
        return False
    
    # Check vulnerability trigger
    print(f'Checking vulnerability trigger for {project} - Bug {bug_id} fixed version...')
    new_env = {
        'ASAN_OPTIONS': 'detect_leaks=0',
        'UBSAN_OPTIONS': 'abort_on_error=1:print_stacktrace=1'
    }
    with open(os.path.join(project_workdir, 'test-fixed.log'), 'w') as f:
        res = docker.exec_docker_cmd([f'/out/my/{binary}', '/tmp/poc'], bug_id, get_output=f,
                                     env=new_env, fixed_version=True)
        if res.returncode != 0:
            print(f'Vulnerability still triggered for {project}-{bug_id} fixed version!')
            docker.cleanup_container(bug_id, remove_image=True, fixed_version=True)
            return False
    docker.cleanup_container(bug_id, remove_image=True, fixed_version=True)
    return True

def run(project:str, bug_id:int, binary:str, san:str, failed_list:List[str], passed_list:List[str], skip_fixed_test:bool=False):
    print(f'Testing {project} - Bug {bug_id}...')
    vul_result = test_vul(project, bug_id, binary, san)
    if skip_fixed_test:
        fixed_result = True
    else:
        fixed_result = test_fixed(project, bug_id, binary, san)
    if not vul_result:
        print(f'- {project} - Bug {bug_id} terribly passed vulnerable test!')
        failed_list.append(f'{project}:{bug_id}')
    elif vul_result and not fixed_result:
        print(f'- {project} - Bug {bug_id} failed both vulnerable and fixed test!')
        failed_list.append(f'{project}:{bug_id}')
    else:
        print(f'- {project} - Bug {bug_id} passed the test successfully')
        passed_list.append(f'{project}:{bug_id}')

if __name__ == '__main__':
    parser = ArgumentParser(prog='test-container', description='Test container works')
    parser.add_argument('-p', '--project', type=str, nargs='*', default=[],
                        help='Projects to checkout. Multiple projects available. Default: None')
    parser.add_argument('-b', '--bug-id', type=int, nargs='*', default=[],
                        help='Bug IDs to checkout. Multiple bug IDs available. Default: None')
    parser.add_argument('-j', '--jobs', type=int, default=1,
                        help='Number of parallel jobs to run. Default: 1')
    parser.add_argument('--use-msan', action='store_true',
                        help='Use bugs which use MSAN. Default: False')
    parser.add_argument('--skip-fixed-test', action='store_true', help='Skip fixed version test', dest='skip_fixed_test')
    args = parser.parse_args()

    projects:List[str] = args.project
    bug_ids:List[int] = args.bug_id

    # TODO: Temporary do not run whole benchmark
    if len(projects) == 0 and len(bug_ids) == 0 and not args.pilot_test:
        print('Either -p or -b option required', file=sys.stderr)
        exit(1)

    # Filter dataframe based on arguments
    df = pd.read_csv(os.path.join(docker.ROOT_DIR, 'benchmarks', 'arvo', 'overview.csv'))
    
    pool = mp.Pool(processes=args.jobs)
    failed_list = mp.Manager().list()
    passed_list = mp.Manager().list()
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

        pool.apply_async(run, args=(project, bug_id, row['fuzz_target'], row['sanitizer'], failed_list, passed_list),
                         kwds={'skip_fixed_test': args.skip_fixed_test})
        # run(project, bug_id, failed_list)

    pool.close()
    pool.join()

    if len(failed_list) != 0:
        print('The following project-bug pairs failed the test:')
        for item in failed_list:
            print(item)
    else:
        print('All tests passed successfully!')

    if len(passed_list) != 0:
        print('The following project-bug pairs passed the test:')
        for item in passed_list:
            print(item)