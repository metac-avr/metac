import os
import subprocess as sp
from argparse import ArgumentParser
import sys
import shutil


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
new_env['CFLAGS'] = f'-g -O0 -DPROFITABILITY_CHECKS=0 -fno-sanitize=object-size {os.environ.get("CFLAGS", "")} '
new_env['CXXFLAGS'] = f'-g -O0 -DPROFITABILITY_CHECKS=0 -fno-sanitize=object-size {os.environ.get("CXXFLAGS", "")} '
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
new_env['LD_LIBRARY_PATH'] = '/usr/local/lib:' + new_env.get('LD_LIBRARY_PATH', '')
new_env['LIBRARY_PATH'] = '/usr/local/lib:' + new_env.get('LIBRARY_PATH', '')
if 'LIB_FUZZING_ENGINE' in new_env:
    del new_env['LIB_FUZZING_ENGINE']
if 'FUZZING_ENGINE' in new_env:
    del new_env['FUZZING_ENGINE']

# Configure
if not args.skip_configure:
    print('buildconf...')
    res = sp.run(['./buildconf',], env=new_env, cwd=args.source_dir)
    if res.returncode != 0:
        print('Error: buildconf failed', file=sys.stderr)
        exit(1)
    print('configure...')
    res = sp.run(['./configure', '--disable-all', '--enable-debug-assertions', '--enable-option-checking=fatal',
                  '--enable-fuzzer', '--enable-exif', '--enable-opcache', '--without-pcre-jit', '--disable-cgi',
                  '--disable-phpdbg', '--with-pic'],
                  env=new_env, cwd=args.source_dir)
    if res.returncode != 0:
        print('Error: configure failed', file=sys.stderr)
        exit(1)
    sp.run(['make', 'clean'], env=new_env, cwd=args.source_dir)

# Build
print('make php-src')
res = sp.run(['make', f'-j{args.jobs}'], env=new_env, cwd=args.source_dir)
if res.returncode != 0:
    print('Error: make failed', file=sys.stderr)
    exit(1)

# Build fuzz driver
if not args.skip_build_driver and args.out_dir is not None:
    print('Copy fuzz driver and dict')
    sp.run(['sapi/cli/php', 'sapi/fuzzer/generate_all.php'], env=new_env, cwd=args.source_dir)
    sp.run(['cp', 'sapi/fuzzer/dict/unserialize', os.path.join(args.out_dir, 'php-fuzz-unserialize.dict')],
           env=new_env, cwd=args.source_dir)
    sp.run(['cp', 'sapi/fuzzer/dict/parser', os.path.join(args.out_dir, 'php-fuzz-parser.dict')],
           env=new_env, cwd=args.source_dir)
    sp.run(['cp', 'sapi/fuzzer/json.dict', os.path.join(args.out_dir, 'php-fuzz-json.dict')],
           env=new_env, cwd=args.source_dir)
    
    fuzzers = {'php-fuzz-json', 'php-fuzz-exif', 'php-fuzz-unserialize', 'php-fuzz-unserializehash',
               'php-fuzz-parser', 'php-fuzz-execute'}
    for fuzzer in fuzzers:
        sp.run(['cp', f'sapi/fuzzer/{fuzzer}', args.out_dir], env=new_env, cwd=args.source_dir)
    sp.run(['cp', 'sapi/fuzzer/php-fuzz-function-jit', args.out_dir], env=new_env, cwd=args.source_dir)
    sp.run(['cp', 'sapi/fuzzer/php-fuzz-tracing-jit', args.out_dir], env=new_env, cwd=args.source_dir)
    if os.path.exists(os.path.join(args.out_dir, 'modules')):
        shutil.rmtree(os.path.join(args.out_dir, 'modules'))
    os.mkdir(os.path.join(args.out_dir, 'modules'))
    sp.run(['cp', 'modules/opcache.so', os.path.join(args.out_dir, 'modules')], env=new_env, cwd=args.source_dir)
    
    for fuzzer in os.listdir(os.path.join(args.source_dir, 'sapi', 'fuzzer', 'corpus')):
        if os.path.exists(os.path.join(args.out_dir, f'php-fuzz-{fuzzer}_seed_corpus.zip')):
            os.remove(os.path.join(args.out_dir, f'php-fuzz-{fuzzer}_seed_corpus.zip'))
        sp.run(f'zip -q -j {os.path.join(args.out_dir, f"php-fuzz-{fuzzer}_seed_corpus.zip")} {os.path.join(args.source_dir, f"sapi/fuzzer/corpus/{fuzzer}/*")}',
               env=new_env, cwd=args.source_dir, shell=True)