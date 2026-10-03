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
new_env['CFLAGS'] = f'-g -DNDEBUG {os.environ.get("CFLAGS", "")} -Wno-error=unknown-warning-option -O0 '
new_env['CXXFLAGS'] = f'-g -DNDEBUG {os.environ.get("CXXFLAGS", "")} -Wno-error=unknown-warning-option -O0 '
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
new_env['LD'] = os.environ.get('CC', 'clang')
new_env['LDFLAGS'] += ' ' + new_env['CFLAGS']

# Configure
if not args.skip_configure:
    cc = new_env.get('CC', 'clang')
    cxx = new_env.get('CXX', 'clang++')
    new_env['CC'] = 'clang'
    new_env['CXX'] = 'clang++'
    print('build libprotobuf-mutator...')
    if os.path.exists('/src/LPM/CMakeCache.txt'):
        os.remove('/src/LPM/CMakeCache.txt')
    res = sp.run(['cmake', '-GNinja', '/src/libprotobuf-mutator', '-GNinja',
                  '-DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON', '-DLIB_PROTO_MUTATOR_TESTING=OFF',
                  '-DCMAKE_BUILD_TYPE=Release'], env=new_env, cwd='/src/LPM')
    if res.returncode != 0:
        print('Error: configuring libprotobuf-mutator failed', file=sys.stderr)
        exit(1)
    res = sp.run(['ninja'], env=new_env, cwd='/src/LPM')
    if res.returncode != 0:
        print('Error: building libprotobuf-mutator failed', file=sys.stderr)
        exit(1)
    sp.run(['rake', 'clean'], env=new_env, cwd=args.source_dir)
    new_env['CC'] = cc
    new_env['CXX'] = cxx

# Build
print('rake...')
res = sp.run(['rake', '-m'], env=new_env, cwd=args.source_dir)
if res.returncode != 0:
    print('Error: rake failed', file=sys.stderr)
    exit(1)

# Build fuzz driver
if not args.skip_build_driver and args.out_dir is not None:
    sp.run(['sed', '-i', 's|const unsigned char \*data|const char \*data|g',
                '/src/libfuzzer/standalone/StandaloneFuzzTargetMain.c'])
    sp.run(['sed', '-i', 's|unsigned char \*buf = (unsigned char\*)malloc(len);|char \*buf = (char\*)malloc(len);|g',
            '/src/libfuzzer/standalone/StandaloneFuzzTargetMain.c'])
    res = sp.run(['clang', '-o', 'StandaloneFuzzTargetMain.o', '-c', 'StandaloneFuzzTargetMain.c'],
                 cwd='/src/libfuzzer/standalone')
    if res.returncode != 0:
        print(f'Error: compiling libfuzzer standalone failed', file=sys.stderr)
        exit(1)

    with open(os.path.join(args.source_dir, 'oss-fuzz', 'config', 'mruby_fuzzer.options'), 'w') as f:
        f.write("""[libfuzzer]
dict = mruby.dict
only_ascii = 1
""")
    shutil.copy2(os.path.join(args.source_dir, 'oss-fuzz', 'config', 'mruby_fuzzer.options'),
                 os.path.join(args.source_dir, 'oss-fuzz', 'config', 'mruby_proto_fuzzer.options'))

    print(f'make fuzzer')
    res = sp.run([os.environ.get('CC', 'clang'), '-c', *(new_env['CFLAGS'].split()), '-Iinclude',
                  os.path.join(args.source_dir, 'oss-fuzz', 'mruby_fuzzer.c'), '-o',
                  os.path.join(args.out_dir, 'mruby_fuzzer.o')], env=new_env, cwd=args.source_dir)
    if res.returncode != 0:
        print(f'Error: make fuzzer failed', file=sys.stderr)
        exit(1)
    res = sp.run([os.environ.get('CXX', 'clang++'), *(new_env["CXXFLAGS"].split()),
                  os.path.join(args.out_dir, 'mruby_fuzzer.o'),
                  '/src/libfuzzer/standalone/StandaloneFuzzTargetMain.o', '-o', f'{args.out_dir}/mruby_fuzzer',
                  '-lm', os.path.join(args.source_dir, 'build', 'host', 'lib', 'libmruby.a')],
                  env=new_env, cwd=args.source_dir)
    if res.returncode != 0:
        print(f'Error: make fuzzer failed', file=sys.stderr)
        exit(1)

    print('make proto fuzzer')
    shutil.rmtree(os.path.join(args.source_dir, 'genfiles'), ignore_errors=True)
    os.makedirs(os.path.join(args.source_dir, 'genfiles'), exist_ok=True)
    res = sp.run(['/src/LPM/external.protobuf/bin/protoc', f'--proto_path={args.source_dir}/oss-fuzz',
                  'ruby.proto', f'--cpp_out={args.source_dir}/genfiles'], cwd=args.source_dir, env=new_env)
    if res.returncode != 0:
        print(f'Error: generating protobuf failed', file=sys.stderr)
        exit(1)
    res = sp.run([os.environ.get('CXX', 'clang++'), '-c', *(new_env["CXXFLAGS"].split()),
                  os.path.join(args.source_dir, 'genfiles', 'ruby.pb.cc'), '-o',
                  os.path.join(args.source_dir, 'genfiles', 'ruby.pb.o'), '-I/src/LPM/external.protobuf/include'],
                  env=new_env, cwd=args.source_dir)
    if res.returncode != 0:
        print(f'Error: compiling protobuf failed', file=sys.stderr)
        exit(1)
    res = sp.run([os.environ.get('CXX', 'clang++'), *(new_env["CXXFLAGS"].split()),
                  f'-I{args.source_dir}/include', '-I/src/LPM/external.protobuf/include',
                  os.path.join(args.source_dir, 'oss-fuzz', 'mruby_proto_fuzzer.cpp'),
                  os.path.join(args.source_dir, 'genfiles', 'ruby.pb.o'),
                  os.path.join(args.source_dir, 'oss-fuzz', 'proto_to_ruby.cpp'),
                  f'-I{args.source_dir}/genfiles', '-I/src/libprotobuf-mutator',
                  '-lz', '-lm', '/src/LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a',
                  '/src/LPM/src/libprotobuf-mutator.a', '/src/LPM/external.protobuf/lib/libprotobuf.a',
                  f'{args.source_dir}/build/host/lib/libmruby.a', '/src/libfuzzer/standalone/StandaloneFuzzTargetMain.o',
                  '-o', f'{args.out_dir}/mruby_proto_fuzzer'], env=new_env, cwd=args.source_dir)
    if res.returncode != 0:
        print(f'Error: make proto fuzzer failed', file=sys.stderr)
        exit(1)
    shutil.copy2(os.path.join(args.source_dir, 'oss-fuzz', 'config', 'mruby_proto_fuzzer.options'), args.out_dir)
    shutil.copy2(os.path.join(args.source_dir, 'oss-fuzz', 'config', 'mruby.dict'), args.out_dir)
    shutil.copy2(os.path.join(args.source_dir, 'oss-fuzz', 'config', 'mruby_fuzzer.options'), args.out_dir)
    sp.run(['zip', '-rq', os.path.join(args.out_dir, 'mruby_fuzzer_seed_corpus'), '/src/mruby_seeds'], cwd=args.source_dir)