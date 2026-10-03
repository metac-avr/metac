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
new_env['CFLAGS'] = f'-g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION {os.environ.get("CFLAGS", "")} -D_GNU_SOURCE -O0 '
new_env['CXXFLAGS'] = f'-g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION {os.environ.get("CXXFLAGS", "")} -D_GNU_SOURCE -O0 '
if 'LDFLAGS' not in new_env:
    new_env['LDFLAGS'] = ''
new_env['LDFLAGS'] += ' '
if '-stdlib=libc++' in new_env['CXXFLAGS']:
    new_env['CXXFLAGS'] = new_env['CXXFLAGS'].replace('-stdlib=libc++', '')
if args.out_dir is not None:
    os.makedirs(args.out_dir, exist_ok=True)

# Configure
if not args.skip_configure:
    print('configure...')
    res = sp.run((f'./configure --static-build '
                  f'--extra-cflags="{new_env["CFLAGS"]}" --extra-ldflags="{new_env["LDFLAGS"]} {new_env["CFLAGS"]}"'),
                  env=new_env, cwd=args.source_dir, shell=True)
    if res.returncode != 0:
        print('Error: configure failed', file=sys.stderr)
        exit(1)
    sp.run(['make', 'clean'], env=new_env, cwd=args.source_dir)

# Build
print('make gpac')
res = sp.run(['make', f'-j{args.jobs}'], env=new_env, cwd=args.source_dir)
if res.returncode != 0:
    print('Error: make failed', file=sys.stderr)
    exit(1)

# Build fuzz driver
if not args.skip_build_driver and args.out_dir is not None:
    sp.run(['sed', '-i', 's|const unsigned char \*data|const char \*data|g',
            '/src/libfuzzer/standalone/StandaloneFuzzTargetMain.c'])
    sp.run(['sed', '-i', 's|unsigned char \*buf = (unsigned char\*)malloc(len);|char \*buf = (char\*)malloc(len);|g',
            '/src/libfuzzer/standalone/StandaloneFuzzTargetMain.c'])
    sp.run([os.environ.get('CC', 'clang'), '-c', '-o', '/src/libfuzzer/standalone/StandaloneFuzzTargetMain.o',
            '/src/libfuzzer/standalone/StandaloneFuzzTargetMain.c'], env=new_env)
    print(f'make fuzzer')
    for fuzzer in ('fuzz_parse',):
        res = sp.run([os.environ.get('CC', 'clang'), *(new_env["CFLAGS"].split()),
                      '-I./include', '-I./', '-DGPAC_HAVE_CONFIG_H', '-c', '-o', f'/src/testsuite/oss-fuzzers/{fuzzer}.o',
                      f'/src/testsuite/oss-fuzzers/{fuzzer}.c'],
                     env=new_env, cwd=args.source_dir)
        res = sp.run([os.environ.get('CXX', 'clang++'), *(new_env["CXXFLAGS"].split()), *(new_env["LDFLAGS"].split()),
                f'/src/testsuite/oss-fuzzers/{fuzzer}.o',
                '/src/libfuzzer/standalone/StandaloneFuzzTargetMain.o',
                '-o', f'{args.out_dir}/{fuzzer}', './bin/gcc/libgpac_static.a', '-lssl', '-lcrypto',
                '-lm', '-lz', '-lpthread', '-llzma', '-ldl', '-DGPAC_HAVE_CONFIG_H'],
            env=new_env, cwd=args.source_dir)
        if res.returncode != 0:
            print(f'Error: make fuzzer failed', file=sys.stderr)
            exit(1)
        if os.path.exists(os.path.join(args.out_dir, 'testsuite', 'oss-fuzzers', f'{fuzzer}_corpus')):
            sp.run(['zip', '-q', '-j', f'{args.out_dir}/{fuzzer}_seed_corpus.zip',
                    f'/src/testsuite/oss-fuzzers/{fuzzer}_corpus/*'], cwd=args.source_dir)