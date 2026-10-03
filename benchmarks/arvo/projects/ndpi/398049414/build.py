import os
import shutil
import subprocess as sp
from argparse import ArgumentParser
import sys


parser = ArgumentParser(prog='build.py', description='Build libtiff')
parser.add_argument('project', help='The project to build')
parser.add_argument('bug_id', type=int, help='The bug id to build')
parser.add_argument('source_dir', help='Directory of the libtiff source code to build')
parser.add_argument('-o', '--out-dir', type=str, help='Output directory to store the built library and binary. Do not save if not specified.', default=None)
parser.add_argument('-j', '--jobs', type=int, help='Number of parallel jobs to use for building', default=1)
parser.add_argument('-w', '--workdir', type=str, help='Working directory. Default is the current directory.', default='.')
parser.add_argument('-s', '--skip-configure', action='store_true', help='Skip the configure step', dest='skip_configure')
parser.add_argument('--skip-build-driver', action='store_true', help='Skip building the fuzzer driver', dest='skip_build_driver')
args = parser.parse_args()

new_env = os.environ.copy()
new_env['CFLAGS'] = (f'-g -DNDEBUG {os.environ.get("CFLAGS", "")} -Wno-error=enum-constexpr-conversion '
                     '-Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations '
                     '-Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=vla-cxx-extension '
                     '-Wno-error=unknown-warning-option -O0 ')
new_env['CXXFLAGS'] = (f'-g -DNDEBUG {os.environ.get("CXXFLAGS", "")} -Wno-error=enum-constexpr-conversion '
                       '-Wno-error=incompatible-function-pointer-types -Wno-error=int-conversion -Wno-error=deprecated-declarations '
                       '-Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=vla-cxx-extension '
                       '-Wno-error=unknown-warning-option -O0 ')
if 'LDFLAGS' not in new_env:
    new_env['LDFLAGS'] = ''
new_env['LDFLAGS'] += ' -L/usr/local/lib '
if '-stdlib=libc++' in new_env['CXXFLAGS']:
    new_env['CXXFLAGS'] = new_env['CXXFLAGS'].replace('-stdlib=libc++', '')
if args.out_dir is not None:
    os.makedirs(args.out_dir, exist_ok=True)
# Parse clang flags via llvm-config
res = sp.run(['llvm-config', '--cflags'], stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
new_env['CFLAGS'] += res.stdout.strip()
res = sp.run(['llvm-config', '--cxxflags'], stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
new_env['CXXFLAGS'] += res.stdout.strip()
if '-std=c++14' in new_env['CXXFLAGS']:
    new_env['CXXFLAGS'] = new_env['CXXFLAGS'].replace('-std=c++14', '')
res = sp.run(['llvm-config', '--ldflags'], stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
new_env['LDFLAGS'] += res.stdout.strip()
new_env['LIB_FUZZING_ENGINE'] = '/src/libfuzzer/standalone/libFuzzerStandalone.a'
new_env['CFLAGS'] += ' -Wno-unknown-warning-option '
new_env['CXXFLAGS'] += ' -Wno-unknown-warning-option '

# Configure
if not args.skip_configure:
    print('build libpcap...')
    temp_env = new_env.copy()
    temp_env['AFL_NOOPT'] = '1'
    temp_env['CC'] = os.environ.get('CC', 'clang')
    temp_env['CXX'] = os.environ.get('CXX', 'clang++')
    if os.path.exists('/src/libpcap-1.9.1'):
        shutil.rmtree('/src/libpcap-1.9.1')
    sp.run(['tar', '-xzf', 'libpcap-1.9.1.tar.gz'], cwd='/src')
    res = sp.run(['./configure', '--disable-shared'], cwd='/src/libpcap-1.9.1', env=temp_env)
    if res.returncode != 0:
        print('Error: configuring libpcap failed', file=sys.stderr)
        exit(1)
    res = sp.run(['make', f'-j{args.jobs}'], cwd='/src/libpcap-1.9.1', env=temp_env)
    if res.returncode != 0:
        print('Error: building libpcap failed', file=sys.stderr)
        exit(1)
    res = sp.run(['make', 'install'], cwd='/src/libpcap-1.9.1', env=temp_env)

    sp.run(['sed', '-i', 's|const unsigned char \*data|const char \*data|g',
            '/src/libfuzzer/standalone/StandaloneFuzzTargetMain.c'])
    sp.run(['sed', '-i', 's|unsigned char \*buf = (unsigned char\*)malloc(len);|char \*buf = (char\*)malloc(len);|g',
            '/src/libfuzzer/standalone/StandaloneFuzzTargetMain.c'])
    mutate_exist = False
    with open('/src/libfuzzer/standalone/StandaloneFuzzTargetMain.c', 'r') as f:
        for line in f:
            if 'LLVMFuzzerMutate' in line:
                mutate_exist = True
                break
    if not mutate_exist:
        with open('/src/libfuzzer/standalone/StandaloneFuzzTargetMain.c', 'a') as f:
            f.write('\n#include <stdint.h>\n')
            f.write('size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize) { return 1; }\n')
    res = sp.run(['clang', '-o', 'StandaloneFuzzTargetMain.o', '-c', 'StandaloneFuzzTargetMain.c'],
                 cwd='/src/libfuzzer/standalone')
    if res.returncode != 0:
        print(f'Error: compiling libfuzzer standalone failed', file=sys.stderr)
        exit(1)
    res = sp.run(['ar', 'rcs', 'libFuzzerStandalone.a', 'StandaloneFuzzTargetMain.o'], cwd='/src/libfuzzer/standalone')

    # nDPI's configure.ac appends its own -O2 to NDPI_CFLAGS, and that lands *after* the -O0 in
    # CFLAGS above, so it wins and the library is built optimised. Locals then live in registers
    # across statement boundaries, which a binary-level patch cannot reach: metapro writes a
    # variable through its memory slot, so a following statement that consumes the register keeps
    # the old value (ndpi-42514124 copied with a stale length and reproduced its own bug). Strip
    # the optimisation flags configure.ac adds -- ours already carry -O0 -- from configure.ac and
    # from a pre-generated configure, before autogen regenerates it.
    for _f in ('configure.ac', 'configure'):
        _p = os.path.join(args.source_dir, _f)
        if os.path.exists(_p):
            sp.run(['sed', '-i', '-E', r's/(NDPI_CFLAGS="[^"]*)[[:space:]]+-O[0-9s]+/\1/g', _p])

    print('autogen...')
    temp_env = new_env.copy()
    temp_env['LDFLAGS'] += '-L/usr/local/lib -lpcap '
    temp_env['RANLIB'] = 'llvm-ranlib'
    # Drop --with-only-libndpi so configure also builds example/ and tests/
    # (needed by tests/do*.sh). json-c is apt-installed, and the -lpcap check
    # passes because the build env carries -fsanitize=address.
    res = sp.run(['sh', 'autogen.sh', '--enable-fuzztargets', '--enable-tls-sigs'],
                 env=temp_env, cwd=args.source_dir)
    if res.returncode != 0:
        print('Error: autogen.sh failed', file=sys.stderr)
        exit(1)
    sp.run(['make', 'clean'], env=new_env, cwd=args.source_dir)

# Build
print('build...')
res = sp.run(['make', f'-j{args.jobs}'], env=new_env, cwd=args.source_dir)
if res.returncode != 0:
    print('Error: rake failed', file=sys.stderr)
    exit(1)

# Rebuild the test binaries without -DNDEBUG. ndpi's test programs wrap
# side-effecting ndpi_*() calls in assert(), e.g.
#   assert(ndpi_init_serializer(&s, fmt) != -1);
# Under -DNDEBUG assert() discards its argument, so those calls never run and the
# tests operate on uninitialized state -- ndpiReader (tests/do.sh) SEGVs at startup
# and unit (tests/do-unit.sh) hits an ASan bad-free. Rebuild each test binary the
# do*.sh suites run with -DNDEBUG stripped. libndpi keeps -DNDEBUG, so the fuzz/PoC
# binaries and bug reproduction are unchanged. Best-effort: a rebuild failure (e.g.
# a target absent in some ndpi version) only disables that test binary, not the build.
for _ex_dir, _ex_target in (('example', 'ndpiReader'),
                            (os.path.join('tests', 'unit'), 'unit'),
                            (os.path.join('tests', 'dga'), 'dga_evaluate')):
    _d = os.path.join(args.source_dir, _ex_dir)
    if not os.path.exists(os.path.join(_d, 'Makefile')):
        continue
    # Strip -DNDEBUG from BOTH the generated Makefile (Makefiles that hard-assign
    # "CFLAGS=...-DNDEBUG...") and the build env (Makefiles that append "CFLAGS+=..."
    # to the inherited env). Don't override CFLAGS on the make command line -- that
    # would discard the Makefile's own -I include flags.
    sp.run(['sed', '-i', 's/-DNDEBUG//g', os.path.join(_d, 'Makefile')], env=new_env)
    _env = new_env.copy()
    _env['CFLAGS'] = _env.get('CFLAGS', '').replace('-DNDEBUG', '')
    _env['CXXFLAGS'] = _env.get('CXXFLAGS', '').replace('-DNDEBUG', '')
    sp.run(['make', 'clean'], env=_env, cwd=_d)
    if sp.run(['make', f'-j{args.jobs}', _ex_target], env=_env, cwd=_d).returncode != 0:
        print(f'Warning: could not rebuild {_ex_dir}/{_ex_target} without -DNDEBUG '
              '(its test suite may fail)', file=sys.stderr)

# Build fuzz driver
if not args.skip_build_driver and args.out_dir is not None:
    print('copy fuzzers...')
    for file in os.listdir(os.path.join(args.source_dir, 'fuzz')):
        if file.startswith('fuzz') and '.' not in file:
            shutil.copy2(os.path.join(args.source_dir, 'fuzz', file), args.out_dir)
        if file.endswith('.zip'):
            shutil.copy2(os.path.join(args.source_dir, 'fuzz', file), args.out_dir)
        if file.endswith('.dict'):
            shutil.copy2(os.path.join(args.source_dir, 'fuzz', file), args.out_dir)
        if file.endswith('.options'):
            shutil.copy2(os.path.join(args.source_dir, 'fuzz', file), args.out_dir)
    shutil.copy2(os.path.join(args.source_dir, 'example', 'protos.txt'), args.out_dir)
    shutil.copy2(os.path.join(args.source_dir, 'example', 'categories.txt'), args.out_dir)
    shutil.copy2(os.path.join(args.source_dir, 'example', 'risky_domains.txt'), args.out_dir)
    shutil.copy2(os.path.join(args.source_dir, 'example', 'ja4_fingerprints.csv'), args.out_dir)
    shutil.copy2(os.path.join(args.source_dir, 'example', 'sha1_fingerprints.csv'), args.out_dir)
    shutil.copy2(os.path.join(args.source_dir, 'example', 'config.txt'), args.out_dir)
    shutil.copy2(os.path.join(args.source_dir, 'lists', 'public_suffix_list.dat'), args.out_dir)
    shutil.copy2(os.path.join(args.source_dir, 'fuzz', 'ipv4_addresses.txt'), args.out_dir)
    shutil.copy2(os.path.join(args.source_dir, 'fuzz', 'bd_param.txt'), args.out_dir)
    shutil.copy2(os.path.join(args.source_dir, 'fuzz', 'splt_param.txt'), args.out_dir)
    shutil.copy2(os.path.join(args.source_dir, 'fuzz', 'random_list.list'), args.out_dir)
    os.makedirs(os.path.join(args.out_dir, 'lists'), exist_ok=True)
    for file in os.listdir(os.path.join(args.source_dir, 'lists')):
        if file.endswith('.list') and file != '100_malware.list':
            shutil.copy2(os.path.join(args.source_dir, 'lists', file), os.path.join(args.out_dir, 'lists'))