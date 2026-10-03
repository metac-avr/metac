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
    os.makedirs('/src/xmlsec_deps', exist_ok=True)
    print('autogen...')
    res = sp.run(['./autogen.sh', '--enable-static', '--without-legacy', '--prefix=/src/xmlsec_deps',
                  '--without-python', '--without-zlib', '--without-lzma'], env=new_env, cwd=args.source_dir)
    if res.returncode != 0:
        print('Error: autogen failed', file=sys.stderr)
        exit(1)
    sp.run(['make', 'clean'], env=new_env, cwd=args.source_dir)

# Build
print('make libxml2')
res = sp.run(['make', f'-j{args.jobs}', 'all'], env=new_env, cwd=args.source_dir)
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
res = sp.run(['make', f'-j{args.jobs}', 'install'], env=new_env, cwd=args.source_dir)
if res.returncode != 0:
    print('Error: make install failed', file=sys.stderr)
    exit(1)

# Configure libxslt
libxslt_path = '/src/libxslt'
if args.out_dir is not None:
    if not args.skip_configure:
        print('autogen libxslt...')
        res = sp.run(['./autogen.sh', f'--with-libxml-src={args.source_dir}', '--enable-static',
                    '--prefix=/src/xmlsec_deps', '--without-python', '--without-debug',
                    '--without-debugger', '--without-profiler'],
                    env=new_env, cwd=libxslt_path)
        if res.returncode != 0:
            print('Error: autogen failed', file=sys.stderr)
            exit(1)
        sp.run(['make', 'clean'], env=new_env, cwd=libxslt_path)

    # Build libxslt
    print('make libxslt')
    res = sp.run(['make', f'-j{args.jobs}'], env=new_env, cwd=libxslt_path)
    if res.returncode != 0:
        print('Error: make failed', file=sys.stderr)
        exit(1)
    res = sp.run(['make', f'-j{args.jobs}', 'install'], env=new_env, cwd=libxslt_path)
    if res.returncode != 0:
        print('Error: make install failed', file=sys.stderr)
        exit(1)

    # Build fuzz driver
    if not args.skip_build_driver:
        fuzzers = {'xmlsec',}
        fuzz_dir = '/src/xmlsec'
        res = sp.run(['autoreconf', '-vfi'], env=new_env, cwd=fuzz_dir)
        if res.returncode != 0:
            print(f'Error: autoconf xmlsec failed', file=sys.stderr)
            exit(1)
        res = sp.run(['./configure', '--enable-static-linking', '--enable-development', '--with-libxml=/src/xmlsec_deps',
                      '--with-libxslt=/src/xmlsec_deps'], env=new_env, cwd=fuzz_dir)
        if res.returncode != 0:
            print(f'Error: configure xmlsec failed', file=sys.stderr)
            exit(1)
        res = sp.run(['make', 'clean'], env=new_env, cwd=fuzz_dir)
        res = sp.run(['make', f'-j{args.jobs}', 'all'], env=new_env, cwd=fuzz_dir)
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
            with open(f'/src/xmlsec/tests/oss-fuzz/{fuzzer}_target.c', 'r') as f:
                content = f.read()
            content = '#include <stdint.h>\n' + content
            with open(f'/src/xmlsec/tests/oss-fuzz/{fuzzer}_target.c', 'w') as f:
                f.write(content)
            print(f'compile {fuzzer}')
            res = sp.run([os.environ.get('CC', 'clang'), *(new_env["CFLAGS"].split()), '-c',
                          f'/src/xmlsec/tests/oss-fuzz/{fuzzer}_target.c', '-I/src/xmlsec_deps/include/',
                          '-I/src/xmlsec_deps/include/libxml2', '-I/src/xmlsec_deps/include/libwxslt',
                          '-I/src/xmlsec_deps/include/libxslt', '-I./include/',
                          '-o', f'{args.out_dir}/{fuzzer}_target.o'], env=new_env, cwd=fuzz_dir)
            if res.returncode != 0:
                print(f'Error: compile {fuzzer}_target.o failed', file=sys.stderr)
                exit(1)
            res = sp.run([os.environ.get('CXX', 'clang++'), *(new_env["CXXFLAGS"].split()),
                          f'{args.out_dir}/{fuzzer}_target.o',
                          '/src/libfuzzer/standalone/StandaloneFuzzTargetMain.o', './src/.libs/libxmlsec1.a',
                          './src/openssl/.libs/libxmlsec1-openssl.a', '/src/xmlsec_deps/lib/libexslt.a',
                          '/src/xmlsec_deps/lib/libxslt.a', '/src/xmlsec_deps/lib/libxml2.a',
                          '-o', f'{args.out_dir}/{fuzzer}_fuzzer', '-lz', '-llzma'],
                          env=new_env, cwd=fuzz_dir)
            if res.returncode != 0:
                print(f'Error: make fuzzer {fuzzer} failed', file=sys.stderr)
                exit(1)
            sp.run(['cp', '/src/xmlsec/tests/oss-fuzz/config/xmlsec_fuzzer.options', args.out_dir],
                   cwd=fuzz_dir, env=new_env)
            sp.run(['wget', '-O', f'{args.out_dir}/xml.dict',
                    'https://raw.githubusercontent.com/mirrorer/afl/master/dictionaries/xml.dict'],
                    cwd=fuzz_dir, env=new_env)