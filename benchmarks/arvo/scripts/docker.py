from argparse import ArgumentParser
import os
import sys
from time import sleep
from typing import Dict, List, TextIO, Union
import subprocess as sp
import multiprocessing as mp
import pandas as pd


ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','..','..'))

def exec_docker_cmd(cmd:List[str], bug_id:int, cwd:str = '/src', env:Dict[str,str] = None,
                    get_output:Union[bool,str,TextIO] = False, fixed_version:bool = False, timeout:float = None):
    exec_cmd = ['docker', 'exec', '-w', cwd]
    if env is not None:
        for k, v in env.items():
            exec_cmd += ['-e', f'{k}="{v}"']
    if fixed_version:
        exec_cmd += [f'arvo-{bug_id}-fix'] + cmd
    else:
        exec_cmd += [f'arvo-{bug_id}'] + cmd
    if isinstance(get_output, str):
        with open(get_output, 'w') as f:
            return sp.run(' '.join(exec_cmd), shell=True, executable='/bin/bash', stdout=f, stderr=f, timeout=timeout)
    elif isinstance(get_output, bool):
        if not get_output:
            return sp.run(' '.join(exec_cmd), shell=True, executable='/bin/bash', timeout=timeout)
        else:
            return sp.run(' '.join(exec_cmd), shell=True, executable='/bin/bash', stdout=sp.PIPE, stderr=sp.STDOUT, timeout=timeout)
    else:
        return sp.run(' '.join(exec_cmd), shell=True, executable='/bin/bash', stdout=get_output, stderr=get_output, timeout=timeout)

def check_file_exist(file_path:str, bug_id:int, fixed_version:bool = False):
    res = exec_docker_cmd(['test', '-e', file_path], bug_id, fixed_version=fixed_version)
    return res.returncode == 0

def checkout(project:str, bug_id:int, host_mount_path:str, install_dependency:bool=True, fixed_version:bool=False):
    print(f'Checking out {project} - Bug {bug_id}...')
    project_workdir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    output_log = os.path.join(project_workdir, f'checkout.log')
    with open(output_log, 'w') as f:
        if fixed_version:
            cmd = ['docker', 'pull', f'n132/arvo:{bug_id}-fix']
        else:
            cmd = ['docker', 'pull', f'n132/arvo:{bug_id}-vul']
        print(f'Pulling Docker image...', file=f)
        while True:
            res = sp.run(cmd, stdout=f, stderr=f)
            if res.returncode != 0:
                print(f'Failed to pull Docker image for {project} - Bug {bug_id}!', file=f)
                print(f'Failed to pull Docker image for {project} - Bug {bug_id}!')
                sleep(60.)
            else:
                break
        
        if fixed_version:
            container_name = f'arvo-{bug_id}-fix'
            cmd = ['docker', 'run', '-itd', '--name', container_name,
                '-v', f'{host_mount_path}:/root/project',
                '--restart', 'always',
                f'n132/arvo:{bug_id}-fix', 'bash']
        else:
            container_name = f'arvo-{bug_id}'
            cmd = ['docker', 'run', '-itd', '--name', container_name,
                '-v', f'{host_mount_path}:/root/project',
                '--restart', 'always',
                f'n132/arvo:{bug_id}-vul', 'bash']
        print(f'Creating Docker container...', file=f)
        res = sp.run(cmd, stdout=sp.PIPE, stderr=sp.STDOUT)
        f.write(res.stdout.decode('utf-8'))
        if res.returncode != 0:
            if b'The container name' in res.stdout and b'is already in use' in res.stdout:
                # Container already exists, remove and try again
                print(f'Container already exists. Removing...', file=f)
                sp.run(['docker', 'stop', container_name], stdout=f, stderr=f)
                cmd_rm = ['docker', 'rm', '-f', container_name]
                sp.run(cmd_rm, stdout=f, stderr=f)
                f.flush()
                print(f'Retrying to create Docker container...', file=f)
                res = sp.run(cmd, stdout=f, stderr=f)
                f.flush()
                if res.returncode != 0:
                    print(f'Failed to create Docker container for {project} - Bug {bug_id} after retrying!', file=f)
                    print(f'Failed to create Docker container for {project} - Bug {bug_id} after retrying!')
                    return False
                else:
                    print(f'Successfully created Docker container for {project} - Bug {bug_id} after retrying.', file=f)
                    print(f'Successfully created Docker container for {project} - Bug {bug_id} after retrying.')
            else:
                print(f'Failed to create Docker container for {project} - Bug {bug_id}!', file=f)
                print(f'Failed to create Docker container for {project} - Bug {bug_id}!')
                return False
        else:
            print(f'Successfully created Docker container for {project} - Bug {bug_id}.', file=f)
            print(f'Successfully created Docker container for {project} - Bug {bug_id}.')
        
        if install_dependency:
            exec_docker_cmd(['rm', '-rf', '/usr/local/include/c++/v1', '/usr/local/lib/libc++.*'], bug_id, get_output=True,
                            fixed_version=fixed_version)
            # Install dependencies with apt
            print(f'Installing dependencies via apt for {project} - Bug {bug_id}', file=f)
            res = exec_docker_cmd(['/root/project/metac/install-deps.sh'], bug_id, get_output=True,
                                  fixed_version=fixed_version)
            f.write(res.stdout.decode('utf-8'))
            if res.returncode != 0:
                print(f'Failed to install dependencies with apt in container for {project} - Bug {bug_id}!', file=f)
                print(f'Failed to install dependencies with apt in container for {project} - Bug {bug_id}!')
                return False
            res = exec_docker_cmd(['python3', '/root/project/metac/setup_llvm.py'], bug_id, get_output=True,
                                  fixed_version=fixed_version)
            f.write(res.stdout.decode('utf-8'))
            if res.returncode != 0:
                print(f'Failed to setup clang for {project} - Bug {bug_id}!', file=f)
                print(f'Failed to setup clang for {project} - Bug {bug_id}!')
                return False
            
        # Some containers miss some required dependencies, try to install with apt-get if not exist
        res = exec_docker_cmd(['apt-get', 'install', '-y', 'nano', 'liblzma-dev'], bug_id, get_output=True,
                        fixed_version=fixed_version)
        if res.returncode != 0:
            print(f'Failed to install required dependencies for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to install required dependencies for {project} - Bug {bug_id}!')
            return False
        return True
    
def cleanup_container(bug_id:int, remove_image:bool = False, fixed_version:bool = False):
    if fixed_version:
        container_name = f'arvo-{bug_id}-fix'
    else:
        container_name = f'arvo-{bug_id}'
    sp.run(['docker', 'stop', container_name], stdout=sp.PIPE, stderr=sp.STDOUT)
    sp.run(['docker', 'rm', container_name], stdout=sp.PIPE, stderr=sp.STDOUT)
    if remove_image:
        if fixed_version:
            cmd = ['docker', 'rmi', f'n132/arvo:{bug_id}-fix']
        else:
            cmd = ['docker', 'rmi', f'n132/arvo:{bug_id}-vul']
        sp.run(cmd, stdout=sp.PIPE, stderr=sp.STDOUT)

def start_container(bug_id:int, fixed_version:bool = False):
    if fixed_version:
        container_name = f'arvo-{bug_id}-fix'
    else:
        container_name = f'arvo-{bug_id}'
    res = sp.run(['docker', 'start', container_name], stdout=sp.PIPE, stderr=sp.STDOUT)
    if res.returncode != 0:
        print(f'Failed to start Docker container for Bug {bug_id}!')
        return False
    else:
        print(f'Successfully started Docker container for Bug {bug_id}.')
        return True
    
def stop_container(bug_id:int, fixed_version:bool = False):
    if fixed_version:
        container_name = f'arvo-{bug_id}-fix'
    else:
        container_name = f'arvo-{bug_id}'
    res = sp.run(['docker', 'stop', container_name], stdout=sp.PIPE, stderr=sp.STDOUT)
    if res.returncode != 0:
        print(f'Failed to stop Docker container for Bug {bug_id}!')
        return False
    else:
        print(f'Successfully stopped Docker container for Bug {bug_id}.')
        return True
    
def container_exists(bug_id:int, fixed_version:bool = False):
    if fixed_version:
        container_name = f'arvo-{bug_id}-fix'
    else:
        container_name = f'arvo-{bug_id}'
    res = sp.run(['docker', 'ps', '-a', '--filter', f'name={container_name}', '--format', '{{.Names}}'], stdout=sp.PIPE, stderr=sp.STDOUT)
    output = res.stdout.decode('utf-8').strip()
    return output == container_name
    
if __name__ == "__main__":
    parser = ArgumentParser(prog='run-san2patch', description='Run binary patcher to apply dev patch')
    parser.add_argument('task', type=str, choices=['start', 'stop'], help='Task to perform')
    parser.add_argument('-p', '--project', type=str, nargs='*', default=[],
                        help='Projects to checkout. Multiple projects available. Default: None')
    parser.add_argument('-b', '--bug-id', type=int, nargs='*', default=[],
                        help='Bug IDs to checkout. Multiple bug IDs available. Default: None')
    parser.add_argument('-j', '--jobs', type=int, default=1,
                        help='Number of parallel jobs to run. Default: 1')
    args = parser.parse_args()

    projects:List[str] = args.project
    bug_ids:List[int] = args.bug_id

    # TODO: Temporary do not run whole benchmark
    if len(projects) == 0 and len(bug_ids) == 0:
        print('Either -p or -b option required', file=sys.stderr)
        exit(1)


    # Filter dataframe based on arguments
    df = pd.read_csv(os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'overview.csv'))
    
    pool = mp.Pool(processes=args.jobs)
    for index, row in df.iterrows():
        project = row['project']
        bug_id = row['localId']
        if (row['submodule_bug'] != 'N' or row['language'] != 'c' or row['patch url available?'] != 'Y' or
            row['ubuntu version'] != 20):
            # Excluded bugs
            continue
        if len(bug_ids) > 0 and bug_id not in bug_ids:
            # Test specified bugs only
            continue
        if len(projects) > 0 and project not in projects:
            # Test specified projects only
            continue

        if not container_exists(bug_id):
            print(f'Container {project}-{bug_id} does not exist. Skip.')
        else:
            if args.task == 'start':
                pool.apply_async(start_container, args=(bug_id,))
            elif args.task == 'stop':
                pool.apply_async(stop_container, args=(bug_id,))

    pool.close()
    pool.join()