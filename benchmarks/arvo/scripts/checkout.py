import os
import shlex
import shutil
from typing import List, Tuple
import pandas as pd
import subprocess as sp
import traceback

import docker
import minibenchmark


ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','..','..'))
CONTAINER_ROOT_DIR = '/root/project/metac'

def copy_source(project:str, bug_id:int, fixed_version:bool = False):
    print(f'Copy source code for {project}-{bug_id}')
    container_workdir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    if fixed_version:
        target_dir = os.path.join(container_workdir, 'source-fix')
    else:
        target_dir = os.path.join(container_workdir, 'source')
    if os.path.exists(target_dir):
        shutil.rmtree(target_dir)
    res = docker.exec_docker_cmd(['cp', '-rf', f'/src/{project}', target_dir], bug_id,
                                 fixed_version=fixed_version)
    if res.returncode != 0:
        print(f'Failed to copy source code for {project}-{bug_id}')
        print(res.stdout.decode('utf-8'))
        return False
    docker.exec_docker_cmd(['cp', '/tmp/poc', container_workdir], bug_id, fixed_version=fixed_version)
    print(f'Success to copy source code for {project}-{bug_id}')
    return True

def setup_metapro(project:str, bug_id:int):
    # Copy metapro source
    print(f'Setting up metapro for {project} - Bug {bug_id}...')
    project_workdir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    output_log = os.path.join(project_workdir, f'metapro-setup.log')
    with open(output_log, 'w') as f:
        # Install cmake
        res = docker.exec_docker_cmd(['cmake', '--version'], bug_id, get_output=True)
        if res.returncode != 0 or '3.31' not in res.stdout.decode('utf-8'):
            res = docker.exec_docker_cmd(['wget', 'https://github.com/Kitware/CMake/releases/download/v3.31.11/cmake-3.31.11-linux-x86_64.tar.gz'],
                                        bug_id, get_output=True)
            if res.returncode != 0:
                print(f'Failed to download cmake for {project} - Bug {bug_id}!', file=f)
                print(f'Failed to download cmake for {project} - Bug {bug_id}!')
                return False
            docker.exec_docker_cmd(['tar', '-xf', 'cmake-3.31.11-linux-x86_64.tar.gz'], bug_id, get_output=True)
            res = docker.exec_docker_cmd(['cp', '-rf', '/src/cmake-3.31.11-linux-x86_64/bin',
                                    '/usr/local'], bug_id, get_output=True)
            if res.returncode != 0:
                print(f'Failed to install cmake for {project} - Bug {bug_id}!', file=f)
                print(f'Failed to install for {project} - Bug {bug_id}!')
                f.write(res.stdout.decode('utf-8'))
                return False
            res = docker.exec_docker_cmd(['cp', '-rf', '/src/cmake-3.31.11-linux-x86_64/share',
                                    '/usr/local'], bug_id, get_output=True)
            if res.returncode != 0:
                print(f'Failed to install cmake for {project} - Bug {bug_id}!', file=f)
                print(f'Failed to install for {project} - Bug {bug_id}!')
                f.write(res.stdout.decode('utf-8'))
                return False
            
        # Copy metapro source
        docker.exec_docker_cmd(['rm', '-rf', '/src/metapro'], bug_id, get_output=True)
        cmd = ['docker', 'cp', os.path.join(ROOT_DIR, 'metapro'), f'arvo-{bug_id}:/src/metapro']
        print(f'Copying metapro source code to container...', file=f)
        res = sp.run(cmd, stdout=sp.PIPE, stderr=sp.STDOUT)
        if res.returncode != 0:
            print(f'Failed to copy metapro source code to container for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to copy metapro source code to container for {project} - Bug {bug_id}!')
            return False
        docker.exec_docker_cmd(['rm', '-rf', '/src/metapro/build'], bug_id, get_output=True)
        docker.exec_docker_cmd(['mkdir', '-p', '/src/metapro/build'], bug_id, get_output=True)
            
        # Install tree-sitter
        new_env = {
            'CFLAGS': '-ggdb -O0',
            'CXXFLAGS': '-ggdb -O0'
        }
        res = docker.exec_docker_cmd(['make', 'install'], bug_id, cwd='/src/metapro/tree-sitter/c', get_output=True, env=new_env)
        if res.returncode != 0:
            print(f'Failed to build tree-sitter-c in container for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to build tree-sitter-c in container for {project} - Bug {bug_id}!')
            f.write(res.stdout.decode('utf-8'))
            return False
        res = docker.exec_docker_cmd(['make', 'install'], bug_id, cwd='/src/metapro/tree-sitter/cpp', get_output=True, env=new_env)
        if res.returncode != 0:
            print(f'Failed to build tree-sitter-cpp in container for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to build tree-sitter-cpp in container for {project} - Bug {bug_id}!')
            f.write(res.stdout.decode('utf-8'))
            return False
        res = docker.exec_docker_cmd(['make', 'install'], bug_id, cwd='/src/metapro/tree-sitter/tree-sitter', get_output=True, env=new_env)
        if res.returncode != 0:
            print(f'Failed to build tree-sitter in container for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to build tree-sitter in container for {project} - Bug {bug_id}!')
            f.write(res.stdout.decode('utf-8'))
            return False
        
        # Build and install metapro
        new_env = {
            # 'CFLAGS': '-fsanitize=address,undefined',
            # 'CXXFLAGS': '-fsanitize=address,undefined',
            # 'LDFLAGS': '-fsanitize=address,undefined -pthread',
            'CFLAGS': '', 'CXXFLAGS': ''
        }
        res = docker.exec_docker_cmd(['cmake', '-DCMAKE_BUILD_TYPE=Debug',
                                      '..'], bug_id,
                                     cwd='/src/metapro/build', get_output=True, env=new_env)
        f.write(res.stdout.decode('utf-8'))
        if res.returncode != 0:
            print(f'Failed to configure metapro in container for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to configure metapro in container for {project} - Bug {bug_id}!')
            return False
        f.write('configure metapro successfully.\n')
        res = docker.exec_docker_cmd(['make', '-j', '4'], bug_id, cwd='/src/metapro/build', get_output=True)
        f.write(res.stdout.decode('utf-8'))
        if res.returncode != 0:
            print(f'Failed to build metapro in container for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to build metapro in container for {project} - Bug {bug_id}!')
            return False
        f.write('build metapro successfully.\n')
        res = docker.exec_docker_cmd(['make', 'install'], bug_id, cwd='/src/metapro/build', get_output=True)
        if res.returncode != 0:
            print(f'Failed to install metapro in container for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to install metapro in container for {project} - Bug {bug_id}!')
            f.write(res.stdout.decode('utf-8'))
            return False
        
        # Test metapro
        res = docker.exec_docker_cmd(['metapro', '-h'], bug_id, get_output=True)
        if res.returncode != 0:
            print(f'Metapro installed but not work for {project} - Bug {bug_id}!', file=f)
            print(f'Metapro installed but not work for {project} - Bug {bug_id}!')
            f.write(res.stdout.decode('utf-8'))
            return False
        
        print(f'Successfully set up metapro in container for {project} - Bug {bug_id}.', file=f)
        print(f'Successfully set up metapro in container for {project} - Bug {bug_id}.')
        f.write(res.stdout.decode('utf-8'))
        return True

def setup_gumtree(project:str, bug_id:int):
    """Install gumtree (3.0.0) and srcml (1.0.0) in the container, for
    rq1-2-san2patch-gumtree.py's deterministic AST-diff patch-config
    generation (see that script's own module docstring for why these exact
    versions: GumTree 3.0.0 cannot read the XML srcml 1.1.0+ emits). Neither
    ships with the container image nor gets installed by install-deps.sh, so
    each container needs both laid down here -- gumtree.py's own
    docker.checkout() re-creates the container from a clean image on every
    run, so this cannot be a one-off manual `docker exec`; it has to run
    every time, same as setup_metapro()/setup_dyninst() alongside it."""
    print(f'Setting up gumtree/srcml for {project} - Bug {bug_id}...')
    project_workdir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    output_log = os.path.join(project_workdir, f'gumtree-setup.log')
    with open(output_log, 'w') as f:
        # A JRE is gumtree.jar's only runtime dependency; srcml also needs libarchive13,
        # which the base image doesn't carry and apt won't pull in for a bare `dpkg -i`.
        res = docker.exec_docker_cmd(['apt-get', 'install', '-y', 'default-jre-headless', 'libarchive13', 'unzip'],
                                     bug_id, get_output=True)
        f.write(res.stdout.decode('utf-8'))
        if res.returncode != 0:
            print(f'Failed to install JRE/libarchive13 for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to install JRE/libarchive13 for {project} - Bug {bug_id}!')
            return False

        res = docker.exec_docker_cmd(
            ['wget', '-q', 'https://github.com/srcML/srcML/releases/download/v1.0.0/srcml_1.0.0-1_ubuntu20.04.deb',
             '-O', '/tmp/srcml.deb'], bug_id, get_output=True)
        f.write(res.stdout.decode('utf-8'))
        if res.returncode != 0:
            print(f'Failed to download srcml for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to download srcml for {project} - Bug {bug_id}!')
            return False
        res = docker.exec_docker_cmd(['dpkg', '-i', '/tmp/srcml.deb'], bug_id, get_output=True)
        f.write(res.stdout.decode('utf-8'))
        if res.returncode != 0:
            print(f'Failed to install srcml for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to install srcml for {project} - Bug {bug_id}!')
            return False

        res = docker.exec_docker_cmd(
            ['wget', '-q', 'https://github.com/GumTreeDiff/gumtree/releases/download/v3.0.0/gumtree-3.0.0.zip',
             '-O', '/tmp/gumtree.zip'], bug_id, get_output=True)
        f.write(res.stdout.decode('utf-8'))
        if res.returncode != 0:
            print(f'Failed to download gumtree for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to download gumtree for {project} - Bug {bug_id}!')
            return False
        # exec_docker_cmd() space-joins its cmd list before handing it to the host's own shell
        # (shell=True) -- an unquoted '&&'-chained -c argument gets word-split there and the
        # tail after '&&' runs on the HOST, not in the container. shlex.quote() keeps the whole
        # -c argument one token so the container's own bash -c sees the chain intact.
        install_cmd = ('cd /opt && unzip -oq /tmp/gumtree.zip && '
                        'ln -sf /opt/gumtree-3.0.0/bin/gumtree /usr/local/bin/gumtree')
        res = docker.exec_docker_cmd(['bash', '-c', shlex.quote(install_cmd)], bug_id, get_output=True)
        f.write(res.stdout.decode('utf-8'))
        if res.returncode != 0:
            print(f'Failed to install gumtree for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to install gumtree for {project} - Bug {bug_id}!')
            return False

        res = docker.exec_docker_cmd(['srcml', '--version'], bug_id, get_output=True)
        f.write(res.stdout.decode('utf-8'))
        if res.returncode != 0 or b'srcml 1.0.0' not in res.stdout:
            print(f'srcml installed but not working for {project} - Bug {bug_id}!', file=f)
            print(f'srcml installed but not working for {project} - Bug {bug_id}!')
            return False

        print(f'Successfully set up gumtree/srcml in container for {project} - Bug {bug_id}.', file=f)
        print(f'Successfully set up gumtree/srcml in container for {project} - Bug {bug_id}.')
        return True

def setup_dyninst(project:str, bug_id:int):
    """Build Dyninst (the `dyninst` submodule -- must already be checked out
    via `git submodule update --init dyninst`, same assumption setup_metapro()
    makes about the `metapro` submodule) from source inside the container,
    build mutator_launch against it, and install the compiler-invocation
    logger (dyninst-cc-wrapper.sh) in place of the container's real
    clang/clang++ so ArvoValidator.setup()'s own real build -- run later, by
    the graph, which this function never touches -- captures a full,
    accurate cc_invocations.log for free instead of needing a separate,
    redundant rebuild.
    """
    print(f'Setting up dyninst for {project} - Bug {bug_id}...')
    project_workdir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    output_log = os.path.join(project_workdir, f'dyninst-setup.log')
    with open(output_log, 'w') as f:
        # Install cmake (same version check/install as setup_metapro(), kept
        # self-contained here since setup_dyninst() may run without
        # setup_metapro() ever having run for this container).
        res = docker.exec_docker_cmd(['cmake', '--version'], bug_id, get_output=True)
        if res.returncode != 0 or '3.31' not in res.stdout.decode('utf-8'):
            # Many containers fetching this from GitHub at once risks the same kind of
            # contention that made elfutils's own download flaky under concurrency (see
            # DYNINST_ELFUTILS_TARBALL below) -- reuse a local copy if CMAKE_TARBALL names
            # one, same convention.
            local_cmake = os.environ.get('CMAKE_TARBALL')
            if local_cmake and os.path.exists(local_cmake):
                res = sp.run(['docker', 'cp', local_cmake, f'arvo-{bug_id}:/src/cmake-3.31.11-linux-x86_64.tar.gz'],
                             stdout=sp.PIPE, stderr=sp.STDOUT)
            else:
                res = docker.exec_docker_cmd(['wget', 'https://github.com/Kitware/CMake/releases/download/v3.31.11/cmake-3.31.11-linux-x86_64.tar.gz'],
                                            bug_id, get_output=True)
            if res.returncode != 0:
                print(f'Failed to download cmake for {project} - Bug {bug_id}!', file=f)
                print(f'Failed to download cmake for {project} - Bug {bug_id}!')
                return False
            docker.exec_docker_cmd(['tar', '-xf', 'cmake-3.31.11-linux-x86_64.tar.gz'], bug_id, get_output=True)
            res = docker.exec_docker_cmd(['cp', '-rf', '/src/cmake-3.31.11-linux-x86_64/bin',
                                    '/usr/local'], bug_id, get_output=True)
            if res.returncode != 0:
                print(f'Failed to install cmake for {project} - Bug {bug_id}!', file=f)
                print(f'Failed to install cmake for {project} - Bug {bug_id}!')
                f.write(res.stdout.decode('utf-8'))
                return False
            res = docker.exec_docker_cmd(['cp', '-rf', '/src/cmake-3.31.11-linux-x86_64/share',
                                    '/usr/local'], bug_id, get_output=True)
            if res.returncode != 0:
                print(f'Failed to install cmake for {project} - Bug {bug_id}!', file=f)
                print(f'Failed to install cmake for {project} - Bug {bug_id}!')
                f.write(res.stdout.decode('utf-8'))
                return False

        # Dyninst's own build dependencies (see dyninst/cmake/{Boost,ThreadingBuildingBlocks,
        # ElfUtils,LibIberty}.cmake -- verified directly against this project's own
        # CMakeCache.txt this session): boost >=1.70 (only atomic/chrono/
        # date_time/filesystem/thread/timer/system -- confirmed against
        # Dyninst's own "-- Boost libraries:" cmake configure output --
        # are actually linked), TBB, libelf, libiberty.
        # Specific boost-*-dev packages, not libboost-all-dev: the meta-
        # package also pulls in libboost-mpi-dev -> libopenmpi-dev ->
        # libibverbs-dev, none of which Dyninst needs -- and having
        # libibverbs-dev present changes some *projects'* own configure
        # scripts (observed: ndpi's bundled libpcap auto-enables its RDMA
        # backend when libibverbs-dev is available, which then fails to
        # link since ndpi's own libpcap smoke test doesn't add -libverbs --
        # a real build breakage in the later, unrelated ArvoValidator.setup()
        # step, from a dependency this step alone introduced).
        # libiberty-dev, not binutils-dev: on Debian/Ubuntu (confirmed on an
        # Ubuntu 20.04 ARVO image) binutils-dev does not actually ship
        # libiberty.a/.so -- it's a separate package, and cmake's
        # FindLibIberty.cmake fails with "missing: LibIberty_LIBRARIES"
        # without it. binutils-dev is kept too since some other images may
        # split it the other way.
        res = docker.exec_docker_cmd(['apt-get', 'update'], bug_id, get_output=True)
        res = docker.exec_docker_cmd(
            ['apt-get', 'install', '-y',
             'libboost-atomic-dev', 'libboost-chrono-dev', 'libboost-date-time-dev',
             'libboost-filesystem-dev', 'libboost-thread-dev', 'libboost-timer-dev',
             'libboost-system-dev', 'libtbb-dev', 'libelf-dev',
             'binutils-dev', 'libiberty-dev'],
            bug_id, get_output=True)
        if res.returncode != 0:
            print(f'Failed to install Dyninst build dependencies for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to install Dyninst build dependencies for {project} - Bug {bug_id}!')
            f.write(res.stdout.decode('utf-8'))
            return False

        # Copy dyninst submodule source + our mutator_launch source
        docker.exec_docker_cmd(['rm', '-rf', '/src/dyninst', '/src/dyninst-poc'], bug_id, get_output=True)
        for name in ('dyninst', 'dyninst-poc'):
            cmd = ['docker', 'cp', os.path.join(ROOT_DIR, name), f'arvo-{bug_id}:/src/{name}']
            print(f'Copying {name} source code to container...', file=f)
            res = sp.run(cmd, stdout=sp.PIPE, stderr=sp.STDOUT)
            if res.returncode != 0:
                print(f'Failed to copy {name} source code to container for {project} - Bug {bug_id}!', file=f)
                print(f'Failed to copy {name} source code to container for {project} - Bug {bug_id}!')
                return False
        docker.exec_docker_cmd(['mkdir', '-p', '/src/dyninst/build'], bug_id, get_output=True)

        # Optional offline elfutils: with STERILE_BUILD=OFF (below) Dyninst downloads elfutils from
        # sourceware.org during `make`, and when many containers are set up at once that server resets
        # the connections ("HTTP/2 stream ... INTERNAL_ERROR") -- every retry then hits the same wall.
        # If DYNINST_ELFUTILS_TARBALL names a copy of elfutils-<version>.tar.bz2 visible in the container,
        # point this container's *copy* of Dyninst's ElfUtils.cmake at it instead (the repository's
        # dyninst sources are untouched).
        tarball = os.environ.get('DYNINST_ELFUTILS_TARBALL')
        if tarball:
            sed_cmd = ("sed -i 's|URL https://sourceware.org/elfutils/ftp/[^ ]*|URL file://" + tarball +
                       "|' /src/dyninst/cmake/ElfUtils.cmake")
            res = docker.exec_docker_cmd(['bash', '-c', shlex.quote(sed_cmd)], bug_id, get_output=True)
            if res.returncode != 0:
                print(f'Failed to point Dyninst at the local elfutils tarball for {project} - Bug {bug_id}!', file=f)
                print(f'Failed to point Dyninst at the local elfutils tarball for {project} - Bug {bug_id}!')
                return False

        # Build and install Dyninst itself (Release, /usr/local -- matches
        # this project's own reference build, confirmed against its CMakeCache.txt).
        # STERILE_BUILD=OFF: Dyninst defaults to refusing to download/build
        # its own elfutils and instead requires the container's system
        # libelf/libdwarf to already meet its minimum version (>=0.186) --
        # ARVO base images vary in their apt-available libelf version (some
        # ship older than that, with no newer version apt-installable
        # without adding an external repo), so this lets Dyninst fetch and
        # build a compatible elfutils itself instead of failing configure.
        # CMAKE_{C,CXX}_COMPILER=gcc/g++: elfutils's own bundled build
        # (cmake/ElfUtils.cmake) hard-refuses any compiler whose
        # CMAKE_*_COMPILER_ID isn't "GNU" ("ElfUtils will only build with
        # the GNU compiler") -- ARVO containers default CC/CXX to clang, so
        # the whole Dyninst configure has to be pinned to gcc/g++ instead
        # (Dyninst itself has no clang-specific requirement; this only
        # affects how Dyninst -- and the tools built against it, like
        # mutator_launch -- get compiled, not the target project's own real
        # build, which dyninst-cc-wrapper.sh never touches).
        # env clears CFLAGS/CXXFLAGS: ARVO containers export clang-only
        # flags (e.g. -gline-tables-only) globally for the project's own
        # sanitizer build; docker exec inherits them, and gcc rejects them
        # outright ("unrecognized debug output level") -- irrelevant to
        # Dyninst's own build anyway, so cleared rather than filtered.
        gnu_env = {'CFLAGS': '', 'CXXFLAGS': ''}
        res = docker.exec_docker_cmd(['cmake', '-DCMAKE_BUILD_TYPE=Release',
                                      '-DCMAKE_INSTALL_PREFIX=/usr/local',
                                      '-DSTERILE_BUILD=OFF',
                                      '-DCMAKE_C_COMPILER=gcc',
                                      '-DCMAKE_CXX_COMPILER=g++', '..'],
                                     bug_id, cwd='/src/dyninst/build', get_output=True, env=gnu_env)
        f.write(res.stdout.decode('utf-8'))
        if res.returncode != 0:
            print(f'Failed to configure dyninst in container for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to configure dyninst in container for {project} - Bug {bug_id}!')
            return False
        f.write('configure dyninst successfully.\n')
        res = docker.exec_docker_cmd(['make', '-j', os.environ.get('DYNINST_MAKE_JOBS', '4')],
                                     bug_id, cwd='/src/dyninst/build', get_output=True, env=gnu_env)
        f.write(res.stdout.decode('utf-8'))
        if res.returncode != 0:
            print(f'Failed to build dyninst in container for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to build dyninst in container for {project} - Bug {bug_id}!')
            return False
        f.write('build dyninst successfully.\n')
        res = docker.exec_docker_cmd(['make', 'install'], bug_id, cwd='/src/dyninst/build', get_output=True, env=gnu_env)
        if res.returncode != 0:
            print(f'Failed to install dyninst in container for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to install dyninst in container for {project} - Bug {bug_id}!')
            f.write(res.stdout.decode('utf-8'))
            return False

        # Build mutator_launch against the just-installed Dyninst (also gcc/g++,
        # to link against a matching-ABI Dyninst build; same CFLAGS/CXXFLAGS
        # clearing as above -- build.sh invokes g++ directly).
        res = docker.exec_docker_cmd(['bash', 'build.sh'], bug_id, cwd='/src/dyninst-poc', get_output=True, env=gnu_env)
        f.write(res.stdout.decode('utf-8'))
        if res.returncode != 0:
            print(f'Failed to build mutator_launch for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to build mutator_launch for {project} - Bug {bug_id}!')
            return False
        f.write('build mutator_launch successfully.\n')

        # Deploy our tool to a fixed, well-known container path (referenced
        # by ArvoValidator.dyninst_patch()/dyninst_test() -- see validator.py).
        docker.exec_docker_cmd(['mkdir', '-p', '/opt/dyninst-tool'], bug_id, get_output=True)
        res = docker.exec_docker_cmd(['cp', '/src/dyninst-poc/mutator_launch', '/opt/dyninst-tool/mutator_launch'],
                                     bug_id, get_output=True)
        if res.returncode != 0:
            print(f'Failed to deploy mutator_launch for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to deploy mutator_launch for {project} - Bug {bug_id}!')
            f.write(res.stdout.decode('utf-8'))
            return False

        # Install the compiler-invocation logger in place of the real
        # clang/clang++ (see dyninst-cc-wrapper.sh's own header comment for
        # why: so ArvoValidator.setup()'s own later, real build captures
        # cc_invocations.log for free). `/usr/local/bin` resolves first on
        # this image's PATH (verified directly this session), so that is
        # where CC=clang / CXX=clang++ actually land -- renaming the real
        # binaries there to *.real and putting the wrapper in their place
        # catches every invocation regardless of which script or tool made it.
        wrapper_src = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'scripts', 'dyninst-cc-wrapper.sh')
        cmd = ['docker', 'cp', wrapper_src, f'arvo-{bug_id}:/usr/local/bin/dyninst-cc-wrapper.sh']
        res = sp.run(cmd, stdout=sp.PIPE, stderr=sp.STDOUT)
        if res.returncode != 0:
            print(f'Failed to copy dyninst-cc-wrapper.sh for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to copy dyninst-cc-wrapper.sh for {project} - Bug {bug_id}!')
            return False
        docker.exec_docker_cmd(['chmod', '+x', '/usr/local/bin/dyninst-cc-wrapper.sh'], bug_id, get_output=True)
        install_cmd = (
            'cd /usr/local/bin && '
            'for c in clang clang++; do '
            '  if [ ! -e "$c.real" ]; then mv "$c" "$c.real"; fi; '
            '  ln -sf dyninst-cc-wrapper.sh "$c"; '
            'done'
        )
        # exec_docker_cmd joins argv with spaces and runs it through a host shell, so the
        # -c script must be quoted or everything after the first `&&` runs on the HOST
        # (which is how this step once silently no-op'd in the container).
        res = docker.exec_docker_cmd(['bash', '-c', shlex.quote(install_cmd)], bug_id, get_output=True)
        if res.returncode != 0:
            print(f'Failed to install compiler wrapper for {project} - Bug {bug_id}!', file=f)
            print(f'Failed to install compiler wrapper for {project} - Bug {bug_id}!')
            f.write(res.stdout.decode('utf-8'))
            return False

        # Sanity checks
        res = docker.exec_docker_cmd(['/opt/dyninst-tool/mutator_launch'], bug_id, get_output=True)
        # mutator_launch with no args prints its own usage and exits 1 -- a
        # clean "usage:" on stderr (captured into stdout here) means it runs
        # and can find its own shared libraries; anything else is a real setup problem.
        if b'usage:' not in res.stdout:
            print(f'mutator_launch installed but not working for {project} - Bug {bug_id}!', file=f)
            print(f'mutator_launch installed but not working for {project} - Bug {bug_id}!')
            f.write(res.stdout.decode('utf-8'))
            return False
        res = docker.exec_docker_cmd(['clang', '--version'], bug_id, get_output=True)
        if res.returncode != 0:
            print(f'Compiler wrapper installed but clang --version failed for {project} - Bug {bug_id}!', file=f)
            print(f'Compiler wrapper installed but clang --version failed for {project} - Bug {bug_id}!')
            f.write(res.stdout.decode('utf-8'))
            return False

        print(f'Successfully set up dyninst in container for {project} - Bug {bug_id}.', file=f)
        print(f'Successfully set up dyninst in container for {project} - Bug {bug_id}.')
        return True

def prepare_dyninst_target(project: str, bug_id: int, sanitizer: str, fuzz_target: str,
                            output_dir: str = 'dyninst-out', stage_id: str = 'stage_0_0',
                            jobs: int = 8) -> Tuple[bool, str]:
    """Get an already-checked-out container to a built target binary, ready for
    ArvoValidator.dyninst_patch()/dyninst_test(): copy source, set up Dyninst +
    mutator_launch + the compiler-invocation wrapper, then build the project with
    exactly the per-bug sanitizer ARVO recorded (overview.csv's 'sanitizer' column)
    via ArvoValidator.build_test() -- not ArvoValidator.setup(), which also runs
    San2Patch's own project functionality test suite (php_run_tests/fate/do.sh),
    a step this dyninst prep has no use for and would otherwise pay for nothing.

    The single path both San2Patch's and ContraFix's dyninst experiments should go
    through from now on, so their built binaries can't again drift the way San2Patch's
    ArvoValidator.setup() (blanket address+undefined) and ContraFix's old standalone
    setup_case.py (its own separate inline copy of this same per-bug sanitizer logic)
    did before this was unified.

    Caller is responsible for docker.checkout() (with whatever retry/reuse/disk-space
    policy fits its own batch run) before calling this -- this function only prepares
    a container that already exists.
    """
    project_workdir = os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))
    container_workdir = os.path.join(CONTAINER_ROOT_DIR, 'benchmarks', 'arvo', 'projects', project, str(bug_id))

    if not copy_source(project, bug_id):
        return False, 'copy_source failed'

    if not setup_dyninst(project, bug_id):
        return False, 'setup_dyninst failed (see dyninst-setup.log)'

    # setup_dyninst()'s symlink swap has, once, silently not stuck (see its own comment) --
    # verify the wrapper is really active before trusting the build about to run to actually
    # capture cc-invocations.log, and reinstall if not.
    # exec_docker_cmd joins argv with spaces and runs it through a host shell (see
    # setup_dyninst()'s own install_cmd comment) -- every multi-word -c script here must be
    # shlex.quote()'d or it silently runs (partly) on the HOST instead of in the container.
    verify_cmd = 'readlink /usr/local/bin/clang; readlink /usr/local/bin/clang++'
    r = docker.exec_docker_cmd(['bash', '-c', shlex.quote(verify_cmd)], bug_id, get_output=True)
    if r.stdout.decode('utf-8').split() != ['dyninst-cc-wrapper.sh', 'dyninst-cc-wrapper.sh']:
        reinstall_cmd = (
            'cd /usr/local/bin && for c in clang clang++; do '
            '[ -e "$c.real" ] || mv "$c" "$c.real"; ln -sf dyninst-cc-wrapper.sh "$c"; done'
        )
        docker.exec_docker_cmd(['bash', '-c', shlex.quote(reinstall_cmd)], bug_id, get_output=True)
        r = docker.exec_docker_cmd(['bash', '-c', shlex.quote('readlink /usr/local/bin/clang')],
                                   bug_id, get_output=True)
        if r.stdout.decode('utf-8').strip() != 'dyninst-cc-wrapper.sh':
            return False, 'compiler wrapper could not be installed'

    # libibverbs-dev makes libpcap's own configure enable its RDMA backend, which then fails
    # to link in ndpi's libpcap smoke test -- see setup_dyninst()'s comment on how installing
    # Dyninst's own boost dependencies can pull this in as a side effect. Harmless no-op removal
    # for every other project.
    libibverbs_cmd = 'dpkg -s libibverbs-dev >/dev/null 2>&1 && apt-get remove -y libibverbs-dev || true'
    docker.exec_docker_cmd(['bash', '-c', shlex.quote(libibverbs_cmd)], bug_id, get_output=True)

    # ArvoValidator.__init__ only records self.source_dir's path -- populating it is normally
    # San2Patch's own ArvoPatcher.__init__'s job, which this lightweight prep never goes
    # through, so do it here instead (mirrors ContraFix's old setup_case.py doing the same
    # copy by hand).
    source_dir = os.path.join(project_workdir, 'san2patch-source')
    if os.path.exists(source_dir):
        shutil.rmtree(source_dir)
    shutil.copytree(os.path.join(project_workdir, 'source'), source_dir)

    import sys
    sys.path.insert(0, os.path.join(ROOT_DIR, 'san2patch', 'san2patch', 'patching'))
    from validator import ArvoValidator

    pv = ArvoValidator(project=project, bug_id=bug_id, work_dir=container_workdir, binary=fuzz_target,
                        poc=os.path.join(container_workdir, 'poc'), stage_id=stage_id, output_dir=output_dir)
    ok, err = pv.build_test(sanitizer, skip_configure=False, jobs=jobs)
    if not ok:
        return False, f'build_test failed: {err}'

    cc_log = docker.exec_docker_cmd(['wc', '-l', '/opt/dyninst-tool/cc-invocations.log'], bug_id, get_output=True)
    cc_lines = cc_log.stdout.decode('utf-8').split()[0] if cc_log.returncode == 0 else '0'
    out_path = os.path.join(project_workdir, output_dir, 'output')
    outs = os.listdir(out_path) if os.path.isdir(out_path) else []
    if not outs or not cc_lines.isdigit() or int(cc_lines) == 0:
        return False, f'build produced no output or empty cc log (outputs={outs}, cc_lines={cc_lines})'

    return True, f'outputs={len(outs)}, cc_lines={cc_lines}'

if __name__ == '__main__':
    def __run(project:str, bug_id:int, skip_metapro_setup:bool = False, skip_cleanup:bool = False,
              fixed_version:bool = False, setup_dyninst_flag:bool = False):
        global host_mount_path
        metapro_setup_res = None
        dyninst_setup_res = None
        checkout_res = docker.checkout(project, bug_id, host_mount_path, install_dependency=True, fixed_version=fixed_version)
        if checkout_res is None or checkout_res == True:
            # copy_source() stays unconditional -- source/ is needed by dyninst setup too, only
            # setup_metapro() (the metapro tool build, ~1-2 min) is metapro-specific. Commented
            # out for now to cut build time on dyninst-only re-runs; uncomment (or add a
            # metapro-specific flag) when metapro-based experiments need this path again.
            if not skip_metapro_setup:
                metapro_setup_res = copy_source(project, bug_id, fixed_version=fixed_version)
                # metapro_setup_res = setup_metapro(project, bug_id)
            if setup_dyninst_flag:
                dyninst_setup_res = setup_dyninst(project, bug_id)
        if not skip_cleanup:
            docker.cleanup_container(bug_id, fixed_version=fixed_version)
        return checkout_res, metapro_setup_res, dyninst_setup_res

    def __except_handler(e:Exception):
        print(f'Error occurred: {str(e)}')
        traceback.print_exc()

    import argparse
    import json
    import multiprocessing as mp
    
    parser = argparse.ArgumentParser(prog='arvo-checkout',
                                     description='Checkout specific projects or bug IDs from the Arvo benchmark suite.')
    parser.add_argument('-p', '--project', type=str, nargs='*', default=[],
                        help='Projects to checkout. Multiple projects available. Default: None')
    parser.add_argument('-b', '--bug-id', type=int, nargs='*', default=[],
                        help='Bug IDs to checkout. Multiple bug IDs available. Default: None')
    parser.add_argument('-j', '--jobs', type=int, default=1,
                        help='Number of parallel jobs to run for checkout. Default: 1')
    parser.add_argument('--use-msan', action='store_true',
                        help='Use bugs which use MSAN. Default: False')
    parser.add_argument('--skip-setup', action='store_true',
                        help='Skip the setup step. Default: False')
    parser.add_argument('--setup-dyninst', action='store_true',
                        help='Also build dyninst + mutator_launch and install the compiler '
                             'wrapper in the container (see setup_dyninst()). Opt-in (unlike '
                             '--skip-setup for metapro) since this is a new, still-experimental '
                             'addition that existing metapro-only checkouts should not pay the '
                             'extra build cost for by default. Default: False')
    parser.add_argument('--skip-cleanup', action='store_true',
                        help='Skip clean-up created containers. Default: False')
    parser.add_argument('-f', '--fixed', action='store_true',
                        help='Checkout fixed verison instead of buggy version')
    parser.add_argument('-m', '--mini', action='store_true',
                        help='Run mini benchmark on a small set of 5 bugs per project. Default: False')
    
    args = parser.parse_args()
    projects:List[str] = args.project
    bug_ids:List[int] = args.bug_id

    # Parse config file
    config_path = os.path.join(ROOT_DIR, 'config.json')
    if not os.path.exists(config_path):
        raise FileNotFoundError(f'Configuration file not found at {config_path}, please create based on config.template.json!')
    with open(config_path, 'r') as f:
        config = json.load(f)
    host_mount_path = config['host_mount_path']

    df = pd.read_csv(os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'overview.csv'))

    pool = mp.Pool(processes=args.jobs)
    async_result = dict()
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
        if project not in async_result:
            async_result[project] = dict()
        cur_res = pool.apply_async(__run, args=(project, bug_id), error_callback=__except_handler,
                                   kwds={'skip_metapro_setup': args.skip_setup, 'skip_cleanup': args.skip_cleanup,
                                         'fixed_version': args.fixed, 'setup_dyninst_flag': args.setup_dyninst})
        async_result[project][bug_id] = cur_res

    pool.close()
    pool.join()

    fail_result = []
    fail_dyninst_result = []
    for project, bug_dict in async_result.items():
        for bug_id, res in bug_dict.items():
            checkout_res, metapro_setup_res, dyninst_setup_res = res.get()
            if metapro_setup_res is not None and not metapro_setup_res:
                fail_result.append(f'{project}-{bug_id}')
            if dyninst_setup_res is not None and not dyninst_setup_res:
                fail_dyninst_result.append(f'{project}-{bug_id}')

    if len(fail_dyninst_result) > 0:
        with open(os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'failed_dyninst_setups.csv'), 'w') as f:
            f.write('project,bug_id\n')
            for item in fail_dyninst_result:
                project, bug_id = item.split('-')
                f.write(f'{project},{bug_id}\n')
        print(f'Dyninst setup failed for {len(fail_dyninst_result)} projects')

    if len(fail_result) > 0:
        with open(os.path.join(ROOT_DIR, 'benchmarks', 'arvo', 'failed_metapro_setups.csv'), 'w') as f:
            f.write('project,bug_id\n')
            for item in fail_result:
                project, bug_id = item.split('-')
                f.write(f'{project},{bug_id}\n')
        print(f'Metapro setup failed for {len(fail_result)} projects')