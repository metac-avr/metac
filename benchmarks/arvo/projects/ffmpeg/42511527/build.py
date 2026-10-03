import os
import shutil
import subprocess as sp
from argparse import ArgumentParser
import sys
from typing import List


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
if '-std=c++14' in new_env['CXXFLAGS']:
    new_env['CXXFLAGS'] = new_env['CXXFLAGS'].replace('-std=c++14', '')
res = sp.run(['llvm-config', '--ldflags'], stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
new_env['LDFLAGS'] += res.stdout.strip()
new_env['LIB_FUZZING_ENGINE'] = '/src/libfuzzer/standalone/libFuzzerStandalone.a'

ffmpeg_dep_dir = '/src/ffmpeg_deps'
os.makedirs(ffmpeg_dep_dir, exist_ok=True)
new_env['PATH'] = f'{ffmpeg_dep_dir}/bin:' + new_env['PATH']
new_env['LD_LIBRARY_PATH'] = f'{ffmpeg_dep_dir}/lib:' + new_env.get('LD_LIBRARY_PATH', '')

# Configure
if not args.skip_configure:
    print('build alsa...')
    if os.path.exists('/src/alsa-lib-1.1.0'):
        shutil.rmtree('/src/alsa-lib-1.1.0')
    sp.run('tar -xf "alsa-lib-1.1.0.tar.bz2"', cwd='/src', shell=True)
    for file in os.listdir('/src'):
        if file.startswith('alsa-lib-') and os.path.isdir(os.path.join('/src', file)):
            alsa_dir = os.path.join('/src', file)
            break
    res = sp.run(['./configure', '--disable-shared', '--enable-static', f'--prefix={ffmpeg_dep_dir}'],
                 cwd=alsa_dir, env=new_env)
    if res.returncode != 0:
        print('Error: configuring alsa failed', file=sys.stderr)
        exit(1)
    sp.run(['make', 'clean'], cwd=alsa_dir, env=new_env)
    res = sp.run(['make', f'-j{args.jobs}', 'all'], cwd=alsa_dir, env=new_env)
    if res.returncode != 0:
        print('Error: building alsa failed', file=sys.stderr)
        exit(1)
    res = sp.run(['make', 'install'], cwd=alsa_dir, env=new_env)

    print('build fdk-aac...')
    res = sp.run(['autoreconf', '-fiv'], env=new_env, cwd='/src/fdk-aac')
    temp_env = new_env.copy()
    temp_env['CXXFLAGS'] += ' -fno-sanitize=shift-base,signed-integer-overflow '
    res = sp.run(['./configure', f'--prefix={ffmpeg_dep_dir}', '--disable-shared'], env=temp_env, cwd='/src/fdk-aac')
    if res.returncode != 0:
        print('Error: configuring fdk-aac failed', file=sys.stderr)
        exit(1)
    sp.run(['make', 'clean'], env=new_env, cwd='/src/fdk-aac')
    res = sp.run(['make', f'-j{args.jobs}', 'all'], env=new_env, cwd='/src/fdk-aac')
    if res.returncode != 0:
        print('Error: building fdk-aac failed', file=sys.stderr)
        exit(1)
    res = sp.run(['make', f'-j{args.jobs}', 'install'], env=new_env, cwd='/src/fdk-aac')
    if res.returncode != 0:
        print('Error: building fdk-aac failed', file=sys.stderr)
        exit(1)

    print('build libXext...')
    res = sp.run(['./autogen.sh'], env=new_env, cwd='/src/libXext')
    res = sp.run(['./configure', f'--prefix={ffmpeg_dep_dir}', '--enable-static'], env=new_env, cwd='/src/libXext')
    if res.returncode != 0:
        print('Error: configuring libXext failed', file=sys.stderr)
        exit(1)
    sp.run(['make', 'clean'], env=new_env, cwd='/src/libXext')
    res = sp.run(['make', f'-j{args.jobs}'], env=new_env, cwd='/src/libXext')
    if res.returncode != 0:
        print('Error: building libXext failed', file=sys.stderr)
        exit(1)
    res = sp.run(['make', f'-j{args.jobs}', 'install'], env=new_env, cwd='/src/libXext')
    if res.returncode != 0:
        print('Error: building libXext failed', file=sys.stderr)
        exit(1)

    print('build libva...')
    res = sp.run(['./autogen.sh'], env=new_env, cwd='/src/libva')
    res = sp.run(['./configure', f'--prefix={ffmpeg_dep_dir}', '--enable-static', '--disable-shared'],
                 env=new_env, cwd='/src/libva')
    if res.returncode != 0:
        print('Error: configuring libva failed', file=sys.stderr)
        exit(1)
    sp.run(['make', 'clean'], env=new_env, cwd='/src/libva')
    res = sp.run(['make', f'-j{args.jobs}', 'all'], env=new_env, cwd='/src/libva')
    if res.returncode != 0:
        print('Error: building libva failed', file=sys.stderr)
        exit(1)
    res = sp.run(['make', f'-j{args.jobs}', 'install'], env=new_env, cwd='/src/libva')
    if res.returncode != 0:
        print('Error: building libva failed', file=sys.stderr)
        exit(1)

    print('build libvdpau...')
    res = sp.run(['./autogen.sh'], env=new_env, cwd='/src/libvdpau')
    res = sp.run(['./configure', f'--prefix={ffmpeg_dep_dir}', '--enable-static', '--disable-shared'],
                 env=new_env, cwd='/src/libvdpau')
    if res.returncode != 0:
        print('Error: configuring libvdpau failed', file=sys.stderr)
        exit(1)
    sp.run(['make', 'clean'], env=new_env, cwd='/src/libvdpau')
    res = sp.run(['make', f'-j{args.jobs}', 'all'], env=new_env, cwd='/src/libvdpau')
    if res.returncode != 0:
        print('Error: building libvdpau failed', file=sys.stderr)
        exit(1)
    res = sp.run(['make', f'-j{args.jobs}', 'install'], env=new_env, cwd='/src/libvdpau')
    if res.returncode != 0:
        print('Error: building libvdpau failed', file=sys.stderr)
        exit(1)

    print('build libvpx...')
    temp_env = new_env.copy()
    temp_env['LDFLAGS'] += ' ' + temp_env['CXXFLAGS'] + ' '
    res = sp.run(['./configure', f'--prefix={ffmpeg_dep_dir}', '--disable-examples', '--disable-unit-tests',
                  '--size-limit=12288x12288', '--extra-cflags=-DVPX_MAX_ALLOCABLE_MEMORY=1073741824'],
                 env=temp_env, cwd='/src/libvpx')
    if res.returncode != 0:
        print('Error: configuring libvpx failed', file=sys.stderr)
        exit(1)
    sp.run(['make', 'clean'], env=new_env, cwd='/src/libvpx')
    res = sp.run(['make', f'-j{args.jobs}', 'all'], env=new_env, cwd='/src/libvpx')
    if res.returncode != 0:
        print('Error: building libvpx failed', file=sys.stderr)
        exit(1)
    res = sp.run(['make', f'-j{args.jobs}', 'install'], env=new_env, cwd='/src/libvpx')
    if res.returncode != 0:
        print('Error: building libvpx failed', file=sys.stderr)
        exit(1)

    print('build ogg...')
    res = sp.run(['./autogen.sh'], env=new_env, cwd='/src/ogg')
    res = sp.run(['./configure', f'--prefix={ffmpeg_dep_dir}', '--enable-static', '--disable-crc'],
                 env=new_env, cwd='/src/ogg')
    if res.returncode != 0:
        print('Error: configuring ogg failed', file=sys.stderr)
        exit(1)
    sp.run(['make', 'clean'], env=new_env, cwd='/src/ogg')
    res = sp.run(['make', f'-j{args.jobs}'], env=new_env, cwd='/src/ogg')
    if res.returncode != 0:
        print('Error: building ogg failed', file=sys.stderr)
        exit(1)
    res = sp.run(['make', f'-j{args.jobs}', 'install'], env=new_env, cwd='/src/ogg')
    if res.returncode != 0:
        print('Error: building ogg failed', file=sys.stderr)
        exit(1)

    print('build opus...')
    res = sp.run(['./autogen.sh'], env=new_env, cwd='/src/opus')
    res = sp.run(['./configure', f'--prefix={ffmpeg_dep_dir}', '--enable-static'],
                 env=new_env, cwd='/src/opus')
    if res.returncode != 0:
        print('Error: configuring opus failed', file=sys.stderr)
        exit(1)
    sp.run(['make', 'clean'], env=new_env, cwd='/src/opus')
    res = sp.run(['make', f'-j{args.jobs}', 'all'], env=new_env, cwd='/src/opus')
    if res.returncode != 0:
        print('Error: building opus failed', file=sys.stderr)
        exit(1)
    res = sp.run(['make', f'-j{args.jobs}', 'install'], env=new_env, cwd='/src/opus')
    if res.returncode != 0:
        print('Error: building opus failed', file=sys.stderr)
        exit(1)

    print('build theora...')
    temp_env = new_env.copy()
    temp_env['CFLAGS'] += ' -fPIC '
    temp_env['LDFLAGS'] += f' -L{ffmpeg_dep_dir}/lib '
    temp_env['CPPFLAGS'] = f'{temp_env["CXXFLAGS"]} -I{ffmpeg_dep_dir}/include '
    temp_env['LD_LIBRARY_PATH'] = f'{ffmpeg_dep_dir}/lib:' + temp_env.get('LD_LIBRARY_PATH', '')
    res = sp.run(['./autogen.sh'], env=temp_env, cwd='/src/theora')
    if res.returncode != 0:
        print('Error: autogen theora failed', file=sys.stderr)
        exit(1)
    res = sp.run(['./configure', f'--prefix={ffmpeg_dep_dir}', '--enable-static', '--disable-examples',
                  f'--with-ogg={ffmpeg_dep_dir}'], env=new_env, cwd='/src/theora')
    if res.returncode != 0:
        print('Error: configuring theora failed', file=sys.stderr)
        exit(1)
    sp.run(['make', 'clean'], env=new_env, cwd='/src/theora')
    res = sp.run(['make', f'-j{args.jobs}'], env=new_env, cwd='/src/theora')
    if res.returncode != 0:
        print('Error: building theora failed', file=sys.stderr)
        exit(1)
    res = sp.run(['make', f'-j{args.jobs}', 'install'], env=new_env, cwd='/src/theora')
    if res.returncode != 0:
        print('Error: building theora failed', file=sys.stderr)
        exit(1)

    print('build vorbis...')
    res = sp.run(['./autogen.sh'], env=new_env, cwd='/src/vorbis')
    res = sp.run(['./configure', f'--prefix={ffmpeg_dep_dir}', '--enable-static'],
                 env=new_env, cwd='/src/vorbis')
    if res.returncode != 0:
        print('Error: configuring vorbis failed', file=sys.stderr)
        exit(1)
    sp.run(['make', 'clean'], env=new_env, cwd='/src/vorbis')
    res = sp.run(['make', f'-j{args.jobs}'], env=new_env, cwd='/src/vorbis')
    if res.returncode != 0:
        print('Error: building vorbis failed', file=sys.stderr)
        exit(1)
    res = sp.run(['make', f'-j{args.jobs}', 'install'], env=new_env, cwd='/src/vorbis')
    if res.returncode != 0:
        print('Error: building vorbis failed', file=sys.stderr)
        exit(1)

    print('configure...')
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

    sp.run(f'rm -rf {ffmpeg_dep_dir}/lib/*.so.*', shell=True)
    sp.run(f'rm -rf {ffmpeg_dep_dir}/lib/*.so', shell=True)
    temp_env = new_env.copy()
    temp_env['PKG_CONFIG_PATH'] = f'{ffmpeg_dep_dir}/lib/pkgconfig:' + temp_env.get('PKG_CONFIG_PATH', '')
    # disabled ossfuzz auto-sanitize: stop FFmpeg configure from injecting -fsanitize when
    # --enable-ossfuzz is set and CFLAGS carries no -fsanitize= (non-ASan builds).
    sp.run(['sed', '-i', r's/^enabled ossfuzz && ! echo/disabled ossfuzz \&\& ! echo/', 'configure'], cwd=args.source_dir)
    res = sp.run((f'./configure --cc={temp_env.get("CC", "clang")} --cxx={temp_env.get("CXX", "clang++")} '
                  f'--ld="{temp_env.get("CXX", "clang++")} {temp_env["CXXFLAGS"]} -std=c++11" '
                  f'--extra-cflags="-I{ffmpeg_dep_dir}/include {temp_env["CFLAGS"]}" --extra-ldflags="-L{ffmpeg_dep_dir}/lib" '
                  f'--prefix={ffmpeg_dep_dir} --pkg-config-flags="--static" --samples=/src/fate-suite '
                  f'--enable-ossfuzz --libfuzzer=/src/libfuzzer/standalone/libFuzzerStandalone.a '
                  f'--optflags=-O0 --enable-gpl --enable-libass --enable-libfdk-aac --enable-libfreetype '
                  '--enable-libopus --enable-libtheora --enable-libvorbis --enable-libvpx --enable-nonfree '
                  '--disable-muxers --disable-protocols --disable-demuxer=rtp,rtsp,sdp --disable-devices --disable-shared'),
                  env=temp_env, cwd=args.source_dir, shell=True)
    if res.returncode != 0:
        print('Error: configure failed', file=sys.stderr)
        exit(1)
    sp.run(['make', 'clean'], env=new_env, cwd=args.source_dir)

# Build
print('build...')
res = sp.run(['make', f'-j{args.jobs}', 'install'], env=new_env, cwd=args.source_dir)
if res.returncode != 0:
    print('Error: make failed', file=sys.stderr)
    exit(1)

# Build fuzz driver
if not args.skip_build_driver and args.out_dir is not None:
    print('build fuzzers...')
    # test_sample_dir = os.path.join(args.source_dir, 'fate-suite')
    # new_env['TEST_SAMPLES_PATH'] = test_sample_dir
    # res = sp.run(['make', 'fate-rsync', f'SAMPLES={test_sample_dir}', f'-j{args.jobs}'], env=new_env, cwd=args.source_dir)
    # if res.returncode != 0:
    #     print('Error: building fuzz driver failed', file=sys.stderr)
    #     exit(1)
    
    fuzz_target_source = os.path.join(args.source_dir, 'tools', 'target_dec_fuzzer.c')
    new_env['TEMP_VAR_CODEC'] = 'AV_CODEC_ID_H264'
    new_env['TEMP_VAR_CODEC_TYPE'] = 'VIDEO'

    fuzzer = 'FLASHSV2'
    print(f'  build decoder {fuzzer} fuzzer...')
    fuzz_binary = f'ffmpeg_AV_CODEC_ID_{fuzzer}_fuzzer'
    symbol = fuzzer.lower()
    with open(os.path.join(args.out_dir, f'{fuzz_binary}.options'), 'w') as f:
        f.write('[libfuzzer]\nmax_len = 1000000\n')
    res = sp.run(['make', f'tools/target_dec_{symbol}_fuzzer', f'-j{args.jobs}'], env=new_env, cwd=args.source_dir)
    if res.returncode != 0:
        print(f'Error: building {fuzz_binary} failed', file=sys.stderr)
        exit(1)
    shutil.copy(os.path.join(args.source_dir, 'tools', f'target_dec_{symbol}_fuzzer'),
                os.path.join(args.out_dir, fuzz_binary))

    # bsf_fuzzer:List[str] = []
    # decoder_fuzzer:List[str] = []
    # with open(os.path.join(args.source_dir, 'config.h'), 'r') as f:
    #     for line in f:
    #         if 'BSF 1' in line:
    #             fuzzer = line.replace('#define CONFIG_', '').replace('_BSF 1', '').strip()
    #             bsf_fuzzer.append(fuzzer)
    #         elif 'DECODER 1' in line:
    #             fuzzer = line.replace('#define CONFIG_', '').replace('_DECODER 1', '').strip()
    #             decoder_fuzzer.append(fuzzer)

    # for fuzzer in bsf_fuzzer:
    #     print(f'  build BSF {fuzzer} fuzzer...')
    #     fuzz_binary = f'ffmpeg_BSF_{fuzzer}_fuzzer'
    #     symbol = fuzzer.lower()
    #     with open(os.path.join(args.out_dir, f'{fuzz_binary}.options'), 'w') as f:
    #         f.write('[libfuzzer]\nmax_len = 1000000\n')
    #     res = sp.run(['make', f'tools/target_bsf_{symbol}_fuzzer', f'-j{args.jobs}'], env=new_env, cwd=args.source_dir)
    #     if res.returncode != 0:
    #         print(f'Error: building {fuzz_binary} failed', file=sys.stderr)
    #         exit(1)
    #     shutil.copy(os.path.join(args.source_dir, 'tools', f'target_bsf_{symbol}_fuzzer'),
    #                 os.path.join(args.out_dir, fuzz_binary))
    # for fuzzer in decoder_fuzzer:
        # print(f'  build decoder {fuzzer} fuzzer...')
        # fuzz_binary = f'ffmpeg_AV_CODEC_ID_{fuzzer}_fuzzer'
        # symbol = fuzzer.lower()
        # with open(os.path.join(args.out_dir, f'{fuzz_binary}.options'), 'w') as f:
        #     f.write('[libfuzzer]\nmax_len = 1000000\n')
        # res = sp.run(['make', f'tools/target_dec_{symbol}_fuzzer', f'-j{args.jobs}'], env=new_env, cwd=args.source_dir)
        # if res.returncode != 0:
        #     print(f'Error: building {fuzz_binary} failed', file=sys.stderr)
        #     exit(1)
        # shutil.copy(os.path.join(args.source_dir, 'tools', f'target_dec_{symbol}_fuzzer'),
        #             os.path.join(args.out_dir, fuzz_binary))
        
    # print(f'  build demuxer fuzzer...')
    # fuzz_binary = 'ffmpeg_DEMUXER_fuzzer'
    # with open(os.path.join(args.out_dir, f'{fuzz_binary}.options'), 'w') as f:
    #     f.write('[libfuzzer]\nmax_len = 1000000\n')
    # res = sp.run(['make', 'tools/target_dem_fuzzer', f'-j{args.jobs}'], env=new_env, cwd=args.source_dir)
    # if res.returncode != 0:
    #     print(f'Error: building {fuzz_binary} failed', file=sys.stderr)
    #     exit(1)
    # shutil.copy(os.path.join(args.source_dir, 'tools', 'target_dem_fuzzer'),
    #             os.path.join(args.out_dir, fuzz_binary))
    
    # res = sp.run(['zip', '-q', '-r', os.path.join(args.out_dir, f'{fuzz_binary}'), 'fate-suite'], cwd=args.source_dir)
    # if res.returncode != 0:
    #     print(f'Error: packaging {fuzz_binary} failed', file=sys.stderr)
    #     exit(1)
    # res = sp.run(['zip', '-q', '-r', os.path.join(args.out_dir, 'ffmpeg_AV_CODEC_ID_HEVC_fuzzer_seed_corpus.zip'),
    #               'fate-suite/hevc', 'fate-suite/hevc-conformance'], cwd=args.source_dir)

    # print(f'  build IO demuxer fuzzer...')
    # fuzz_binary = 'ffmpeg_IO_DEMUXER_fuzzer'
    # res = sp.run(['make', 'tools/target_io_dem_fuzzer', f'-j{args.jobs}'], env=new_env, cwd=args.source_dir)
    # if res.returncode != 0:
    #     print(f'Error: building {fuzz_binary} failed', file=sys.stderr)
    #     exit(1)
    # shutil.copy(os.path.join(args.source_dir, 'tools', 'target_io_dem_fuzzer'),
    #             os.path.join(args.out_dir, fuzz_binary))
    # temp_src = '/src/temp-src' # Copy to temp dir to prevent modifying the original build dir
    # if os.path.exists(temp_src):
    #     shutil.rmtree(temp_src)
    # shutil.copytree(args.source_dir, temp_src, ignore=shutil.ignore_patterns('*.o', '*.a', '*.so'))
    # temp_env = new_env.copy()
    # temp_env['PKG_CONFIG_PATH'] = f'{ffmpeg_dep_dir}/lib/pkgconfig:' + temp_env.get('PKG_CONFIG_PATH', '')
    # res = sp.run((f'./configure --cc={temp_env.get("CC", "clang")} --cxx={temp_env.get("CXX", "clang++")} '
    #               f'--ld="{temp_env.get("CXX", "clang++")} {temp_env["CXXFLAGS"]} -std=c++11" '
    #               f'--extra-cflags="-I{ffmpeg_dep_dir}/include {temp_env["CFLAGS"]}" --extra-ldflags="-L{ffmpeg_dep_dir}/lib" '
    #               f'--prefix={ffmpeg_dep_dir} --pkg-config-flags="--static" '
    #               f'--enable-ossfuzz --libfuzzer=/src/libfuzzer/standalone/libFuzzerStandalone.a '
    #               f'--optflags=-O0 --enable-gpl --disable-encoders --disable-filters --disable-parsers '
    #               '--disable-decoders --disable-hwaccels --disable-bsfs --disable-vaapi --disable-vdpau --disable-crystalhd '
    #               '--disable-v4l2_m2m --disable-cuda_llvm --enable-demuxers --disable-demuxer=rtp,rtsp,sdp '
    #               '--disable-muxers --disable-protocols --disable-devices --disable-shared'),
    #               env=temp_env, cwd=temp_src, shell=True)
    # if res.returncode != 0:
    #     print('Error: configure failed', file=sys.stderr)
    #     exit(1)
    # demuxer_fuzzers = []
    # with open(os.path.join(temp_src, 'config.h'), 'r') as f:
    #     for line in f:
    #         if 'DEMUXER 1' in line:
    #             fuzzer = line.replace('#define CONFIG_', '').replace('_DEMUXER 1', '').strip()
    #             demuxer_fuzzers.append(fuzzer)
    # for fuzzer in demuxer_fuzzers:
    #     print(f'  build demuxer {fuzzer} fuzzer...')
    #     fuzz_binary = f'ffmpeg_dem_{fuzzer}_fuzzer'
    #     symbol = fuzzer.lower()
    #     res = sp.run(['make', f'tools/target_dem_{fuzzer.lower()}_fuzzer', f'-j{args.jobs}'], env=new_env, cwd=temp_src)
    #     if res.returncode != 0:
    #         print(f'Error: building {fuzz_binary} failed', file=sys.stderr)
    #         exit(1)
    #     shutil.copy(os.path.join(temp_src, 'tools', f'target_dem_{fuzzer.lower()}_fuzzer'),
    #                 os.path.join(args.out_dir, fuzz_binary))