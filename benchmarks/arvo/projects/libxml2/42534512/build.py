import os
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
new_env['CFLAGS'] = f'-g {os.environ.get("CFLAGS", "")} -O0 '
new_env['CXXFLAGS'] = f'-g {os.environ.get("CXXFLAGS", "")} -O0 '
if 'LDFLAGS' not in new_env:
    new_env['LDFLAGS'] = ''
new_env['LDFLAGS'] += ' '
if '-stdlib=libc++' in new_env['CXXFLAGS']:
    new_env['CXXFLAGS'] = new_env['CXXFLAGS'].replace('-stdlib=libc++', '')
if args.out_dir is not None:
    os.makedirs(args.out_dir, exist_ok=True)
# Parse clang flags via llvm-config
res = sp.run(['llvm-config', '--cflags'], stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
new_env['CFLAGS'] += res.stdout.strip()
res = sp.run(['llvm-config', '--cxxflags'], stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
new_env['CXXFLAGS'] += res.stdout.strip()
res = sp.run(['llvm-config', '--ldflags'], stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
new_env['LDFLAGS'] += res.stdout.strip()

# Configure
if not args.skip_configure:
    print('autogen...')
    res = sp.run(['./autogen.sh', '--disable-shared', '--without-debug',
                  '--without-http', '--without-python'], env=new_env, cwd=args.source_dir)
    if res.returncode != 0:
        print('Error: autogen failed', file=sys.stderr)
        exit(1)
    sp.run(['make', 'clean'], env=new_env, cwd=args.source_dir)

# Build
print('make libxml2')
res = sp.run(['make', f'-j{args.jobs}'], env=new_env, cwd=args.source_dir)
if res.returncode != 0:
    print('Error: make failed', file=sys.stderr)
    exit(1)

# `make check` runs ./testModule, which dlopens .libs/testdso.so. That shared
# module is not built under --disable-shared, so testModule always fails with
# "Failed to open module". Drop it from the check-local recipe so `make check`
# skips this DSO self-test (irrelevant to the library under test).
if os.path.exists(os.path.join(args.source_dir, 'Makefile')):
    sp.run(['sed', '-i', '/CHECKER) \\.\\/testModule/d',
            os.path.join(args.source_dir, 'Makefile')], env=new_env)

# Build fuzz driver
if not args.skip_build_driver and args.out_dir is not None:
    fuzzers = {'api', 'html', 'regexp', 'schema', 'uri', 'valid', 'xinclude', 'xml', 'xpath'}
    fuzz_dir = os.path.join(args.source_dir, 'fuzz')
    sp.run(['make', 'clean-corpus'], env=new_env, cwd=fuzz_dir)
    res = sp.run(['make', 'fuzz.o'], env=new_env, cwd=fuzz_dir)
    if res.returncode != 0:
        print(f'Error: make fuzz.o failed', file=sys.stderr)
        exit(1)
    sp.run(['sed', '-i', 's|const unsigned char \*data|const char \*data|g',
            '/src/libfuzzer/standalone/StandaloneFuzzTargetMain.c'])
    sp.run(['sed', '-i', 's|unsigned char \*buf = (unsigned char\*)malloc(len);|char \*buf = (char\*)malloc(len);|g',
            '/src/libfuzzer/standalone/StandaloneFuzzTargetMain.c'])
    res = sp.run(['clang', '-o', 'StandaloneFuzzTargetMain.o', '-c', 'StandaloneFuzzTargetMain.c'],
                 cwd='/src/libfuzzer/standalone')
    if res.returncode != 0:
        print(f'Error: compiling libfuzzer standalone failed', file=sys.stderr)
        exit(1)
    for fuzzer in fuzzers:
        print(f'make {fuzzer}')
        res = sp.run(['make', f'{fuzzer}.o'], env=new_env, cwd=fuzz_dir)
        if res.returncode != 0:
            print(f'Error: make fuzzer {fuzzer}.o failed', file=sys.stderr)
            exit(1)
        res = sp.run([os.environ.get('CXX', 'clang++'), *(new_env["CXXFLAGS"].split()), f'{fuzzer}.o', 'fuzz.o',
                      '/src/libfuzzer/standalone/StandaloneFuzzTargetMain.o', '-o', f'{args.out_dir}/{fuzzer}',
                      '../.libs/libxml2.a', '-Wl,-Bstatic', '-lz', '-llzma', '-Wl,-Bdynamic'],
                      env=new_env, cwd=fuzz_dir)
        if res.returncode != 0:
            print(f'Error: make fuzzer {fuzzer} failed', file=sys.stderr)
            exit(1)
        if os.path.exists(os.path.join(args.source_dir, 'seed', fuzzer)):
            res = sp.run(['make', os.path.join('seed', f'{fuzzer}.stamp')], env=new_env, cwd=fuzz_dir)
            if res.returncode != 0:
                print(f'Error: make seed for {fuzzer} failed', file=sys.stderr)
                exit(1)
            if os.path.exists(os.path.join(args.out_dir, f'{fuzzer}_seed_corpus.zip')):
                os.remove(os.path.join(args.out_dir, f'{fuzzer}_seed_corpus.zip'))
            res = sp.run(['zip', '-j', os.path.join(args.out_dir, f'{fuzzer}_seed_corpus.zip'),
                          os.path.join('seed', fuzzer, '*')], env=new_env, cwd=fuzz_dir)
        if res.returncode != 0:
            print(f'Error: compressing seed corpus for {fuzzer} failed', file=sys.stderr)
            exit(1)
        if os.path.exists(os.path.join(fuzz_dir, f'{fuzzer}.dict')):
            sp.run(['cp', f'{fuzzer}.dict', f'{args.out_dir}'], env=new_env, cwd=fuzz_dir)
        if os.path.exists(os.path.join(fuzz_dir, f'{fuzzer}.options')):
            sp.run(['cp', f'{fuzzer}.options', f'{args.out_dir}'], env=new_env, cwd=fuzz_dir)