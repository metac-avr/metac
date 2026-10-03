import base64
import json
import os
import re
import shlex
import subprocess as sp
import xml.etree.ElementTree as ET
from abc import abstractmethod
from pathlib import Path
import shutil
import time
from typing import Dict, List, Optional, Set, Tuple

from dotenv import load_dotenv

from san2patch.context import San2PatchValidatorManager
from san2patch.dataset.base_dataset import BaseDataset
from san2patch.utils.cmd import BaseCommander
from san2patch.utils.docker import DockerHelper
from san2patch.utils.logger import MyLoggerLevelEnum


# The sanitizer runtime kills the process when a library is dlopen'd with
# RTLD_DEEPBIND, before any of the target's own code runs. php-src trips this
# loading opcache.so: Zend/zend_portability.h only drops that flag for GCC's
# __SANITIZE_ADDRESS__ or clang's memory_sanitizer, and clang 12 sets neither for
# -fsanitize=address. The PoC never executes, so neither "crash" nor "no crash"
# is a valid verdict -- the run has to be reported as a failure instead of a pass.
SANITIZER_STARTUP_ABORT_RE = r"You are trying to dlopen a .+ with RTLD_DEEPBIND flag"

# ── PoC-test output classification ────────────────────────────────────────────────
# Shared by vulnerability_test() and metapro_test(): both ask the same question of a
# PoC run ("did the patch stop the crash?") and both used to answer it from a short,
# hand-maintained list of markers, which let several classes of failure be read as
# "no crash" and so as a working patch.

# Harnesses colour their output (gpac especially), so a marker can sit behind an
# escape sequence rather than at the start of a line.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Every way the sanitizers or the fuzzing harness report that the target died on the
# input. Deliberately broad: a missed crash becomes a false "patch works".
POC_CRASH_RE = re.compile(
    r"ERROR: \w*Sanitizer:"              # ASan/UBSan/LSan/MSan/TSan error header
    r"|SUMMARY: \w*Sanitizer:"           # ... and its summary line
    r"|\w*Sanitizer:DEADLYSIGNAL"        # AddressSanitizer:DEADLYSIGNAL
    r"|WARNING: \w*Sanitizer failed to allocate"   # allocator_may_return_null=1
    r"|\w*Sanitizer CHECK failed"        # sanitizer runtime internal failure
    r"|runtime error:"                   # UBSan with no report block
    r"|malloc failure erroneously reported"
    r"|ERROR: libFuzzer:"                # deadly signal / out-of-memory / timeout
    r"|SUMMARY: libFuzzer:"
)

# The process never got to run the PoC (or died outside it), so the run says nothing
# about the patch. These strings come from the loader, the sanitizer runtime or the
# shell -- not from target output -- so matching them cannot misread a healthy run.
POC_HARNESS_ERROR_RE = re.compile(
    SANITIZER_STARTUP_ABORT_RE           # ASan refusing dlopen(RTLD_DEEPBIND)
    + r"|symbol lookup error"            # unresolved symbol at startup
    + r"|undefined symbol"
    + r"|error while loading shared libraries"
    + r"|cannot open shared object file"
    + r"|cannot execute binary file"
    + r"|Text file busy"                 # ETXTBSY: a previous run still holds it
    + r"|CHECK failed: .*sanitizer_"     # sanitizer runtime bailing out at init
)


def classify_poc_output(output: str, ret_code: int) -> str:
    """Classify one PoC run as 'crash', 'harness' or 'clean'.

    'crash'   -- the target still dies on the input: the patch did not work.
    'harness' -- the run never produced a verdict (loader error, death by a signal
                 no sanitizer reported, ...). Must not be read as either outcome.
    'clean'   -- the input was processed without a crash report.

    Order matters: a crash report is conclusive even when the process also exits by
    signal, so it is tested first.
    """
    text = _ANSI_RE.sub("", output or "")
    if POC_CRASH_RE.search(text):
        return "crash"
    if POC_HARNESS_ERROR_RE.search(text):
        return "harness"
    # bash/timeout report a signal death as 128+signum. SIGSEGV(139) and SIGABRT(134)
    # usually come with a report caught above; SIGILL(132), SIGBUS(135) and SIGFPE(136)
    # do not, and are exactly how a bad binary rewrite manifests. Without this they
    # reach the "ran to completion" case and count as a working patch.
    if isinstance(ret_code, int) and ret_code > 128:
        return "harness"
    return "clean"


class BaseValidator(BaseCommander):
    def __init__(self, vuln_id: str, project_name: str, *args, **kwargs):
        super().__init__(*args, **kwargs)

        load_dotenv(override=True)

        self.vuln_id = vuln_id
        self.project_name = project_name

    @abstractmethod
    def setup(self):
        raise NotImplementedError

    @abstractmethod
    def patch(self):
        raise NotImplementedError

    @abstractmethod
    def build_test(self):
        raise NotImplementedError

    @abstractmethod
    def build_func(self):
        raise NotImplementedError

    @abstractmethod
    def functionality_test(self):
        raise NotImplementedError

    @abstractmethod
    def vulnerability_test(self):
        raise NotImplementedError

    @abstractmethod
    def run(self):
        raise NotImplementedError


class FinalTestValidator(BaseValidator):
    name = "final-test"

    def __init__(
        self,
        vuln_data,
        stage_id,
        experiment_name: str | None = None,
        docker_id: str | None = None,
        *args,
        **kwargs,
    ):
        super().__init__(vuln_data["bug_id"], vuln_data["subject"], *args, **kwargs)

        self.stage_id = stage_id

        self.main_dir = (Path(os.getenv("DATASET_FINAL_DIR")) / self.name).resolve()

        self.binary_path: str = vuln_data["binary_path"]
        self.crash_input: str = vuln_data["crash_input"]
        if len(vuln_data["exploit_file_list"]) == 0:
            self.exploit_file = None
        else:
            self.exploit_file: str = vuln_data["exploit_file_list"][0].split("/")[-1]

        # Inside the host
        if experiment_name is not None:
            self.gen_diff_dir = os.path.join(
                self.main_dir, f"gen_diff_{experiment_name}"
            )
        else:
            self.gen_diff_dir = os.path.join(self.main_dir, "gen_diff")

        self.container_id = docker_id or San2PatchValidatorManager().docker_id

        self.run_dir = os.path.join(self.gen_diff_dir, self.vuln_id, self.stage_id)

        # Inside the docker
        self.data_dir = f"/san2patch-benchmark/{self.project_name}/{self.vuln_id}"
        self.experiment_dir = (
            f"/experiment/san2patch-benchmark/{self.project_name}/{self.vuln_id}"
        )
        self.experiment_func_dir = (
            f"/experiment_func/san2patch-benchmark/{self.project_name}/{self.vuln_id}"
        )
        # self.reproduce_cmd = f"./{self.data_dir}/test.sh {self.exploit_file}".strip()
        # self.reproduce_cmd = f"./test.sh {self.exploit_file}".strip()

    def setup(self):
        self.logger.info("Setting up the docker container for validating patch...")

        if self.container_id is None:
            self.container_id = DockerHelper().get_benchmark_container_id()

        if self.container_id is None or self.container_id == "":
            raise ValueError("Container not found.")

        # Remove all diff files from the previous run inside the docker
        # The remove script is in "/experiment/san2patch-benchmark/clear.sh"
        # self.run_cmd(f'docker exec {self.container_id} bash -c "cd /experiment/san2patch-benchmark && ./clear.sh"', cwd=self.main_dir, quiet=True)

        # Remove just the diff file for the current vuln_id
        self.run_cmd(
            f'docker exec {self.container_id} bash -c "ls {self.experiment_dir}/{self.vuln_id}.diff && rm -f {self.experiment_dir}/{self.vuln_id}.diff"',
            cwd=self.main_dir,
            quiet=True,
        )

        # Check if the data directory exists
        ret_code, _, _ = self.run_cmd(
            f'docker exec {self.container_id} bash -c "ls {self.experiment_dir}"',
            cwd=self.main_dir,
            quiet=True,
        )

        if ret_code != 0:
            raise ValueError("Data directory not found.")

        # Reset the git repository
        self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.experiment_dir}/src && git reset --hard"',
            cwd=self.main_dir,
            quiet=True,
        )

        self.logger.debug(f"Container ID: {self.container_id}")
        self.logger.debug("Docker container setup completed.")

    def patch(self):
        self.logger.info("Applying the patch...")

        host_patch_file = os.path.join(
            self.gen_diff_dir, self.vuln_id, self.stage_id, f"{self.vuln_id}.diff"
        )
        docker_patch_file = os.path.join(self.experiment_dir, f"{self.vuln_id}.diff")

        # Copy generated patch file into the container
        self.run_cmd(
            f"docker cp {host_patch_file} {self.container_id}:{docker_patch_file}",
            cwd=self.main_dir,
            expect_error=True,
        )

        # Apply the patch
        ret, _, stderr = self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.experiment_dir}/src && git apply --ignore-whitespace {docker_patch_file}"',
            cwd=self.main_dir,
            pipe=True,
            expect_error=True,
        )
        _, _, _ = self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.experiment_func_dir}/src && git reset --hard && git apply --ignore-whitespace {docker_patch_file}"',
            cwd=self.main_dir,
            pipe=True,
            expect_error=True,
        )

        if ret != 0:
            self.logger.error("Patch failed to apply.")
            return False, stderr

        else:
            self.logger.info("Patch applied successfully.")
            return True, None

    def build_test(self):
        self.logger.info("Building the project...")

        ret_code_c, _, stderr_c = self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.data_dir} && ./config.sh"',
            cwd=self.main_dir,
            pipe=True,
            expect_error=True,
        )
        ret_code_b, _, stderr_b = self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.data_dir} && ./build.sh"',
            cwd=self.main_dir,
            pipe=True,
            expect_error=True,
        )

        if ret_code_c != 0 or ret_code_b != 0:
            self.logger.error("Build failed.")

            return False, stderr_c if ret_code_c != 0 else stderr_b

        else:
            self.logger.info("Build completed.")

            return True, None

    def build_func(self):
        self.logger.info("Building the project...")

        ret_code_c, _, stderr_c = self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.data_dir} && ./config_func.sh"',
            cwd=self.main_dir,
            pipe=True,
            expect_error=True,
        )
        ret_code_b, _, stderr_b = self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.data_dir} && ./build_func.sh"',
            cwd=self.main_dir,
            pipe=True,
            expect_error=True,
        )

        if ret_code_c != 0 or ret_code_b != 0:
            self.logger.error(f"Build failed. {self.vuln_id}")

            return False, stderr_c if ret_code_c != 0 else stderr_b

        else:
            self.logger.info(f"Build completed. {self.vuln_id}")

            return True, None

    def functionality_test(self):
        self.logger.info("Testing the functionality...")

        # Build the project
        self.build_func()

        # Just run the test_func.sh in data_dir
        ret_code, _, stderr = self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.data_dir} && ./test_func.sh"',
            cwd=self.main_dir,
            pipe=True,
            expect_error=True,
        )

        if ret_code != 0:
            self.logger.error(f"Functionality test failed. {self.vuln_id}")
            return False, stderr
        else:
            self.logger.success(f"Functionality test passed. {self.vuln_id}")
            return True, None

    def vulnerability_test(self):
        self.logger.info("Testing the vulnerability...")

        # Try 1: Copy the error output to the host
        docker_vuln_out_file = os.path.join(
            self.experiment_dir, "src", self.binary_path + ".out"
        )
        host_vuln_out_file = os.path.join(self.run_dir, f"{self.vuln_id}.vuln.out")

        self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.data_dir} && ./test.sh {self.exploit_file}"',
            cwd=self.main_dir,
            expect_error=True,
        )

        # Copy sanitizer output to the host
        self.run_cmd(
            f"docker cp {self.container_id}:{docker_vuln_out_file} {host_vuln_out_file}",
            cwd=self.main_dir,
        )

        try:
            with open(host_vuln_out_file, "r", errors="ignore") as f_stderr:
                stderr = f_stderr.read()

                sanitizer_re_1 = r"ERROR: .+Sanitizer:"
                sanitizer_re_2 = r"SUMMARY: .+Sanitizer:"
                sanitizer_re_3 = r"runtime error:"
                # libFuzzer's own signal handler catches aborts/signals the
                # sanitizers never report -- a failed assertion, for instance.
                sanitizer_re_4 = r"libFuzzer: deadly signal"

                if re.search(SANITIZER_STARTUP_ABORT_RE, stderr):
                    self.logger.error(
                        f"Sanitizer aborted the process before the PoC ran; "
                        f"vulnerability test is inconclusive. {self.vuln_id}"
                    )
                    return False, stderr

                # Check if the sanitizer is found
                if (
                    re.search(sanitizer_re_1, stderr)
                    or re.search(sanitizer_re_2, stderr)
                    or re.search(sanitizer_re_3, stderr)
                    or re.search(sanitizer_re_4, stderr)
                ):
                    self.logger.error(f"Sanitizer detected the crash. {self.vuln_id}")
                    self.logger.error(f"Patch was not successful. {self.vuln_id}")

                    san_output = BaseDataset.get_only_san_output(stderr)

                    return False, san_output
                else:
                    self.logger.success(f"Crash not found. {self.vuln_id}")
                    self.logger.success(f"Vulnerability test passed. {self.vuln_id}")

                    return True, None
        except FileNotFoundError:
            self.logger.error(
                "Sanitizer output not found. Please check the test.sh script."
            )

            return False, None

    def run(self):
        self.setup()
        self.patch()
        self.build_test()
        self.vulnerability_test()


def _build_project(container_id: str, project: str, bug_id: int, work_dir_container: str,
                   source_dir_container: str, output_path_container: str, san: str,
                   jobs: int = 8, skip_configure: bool = True,
                   extra_flags: str = '') -> Tuple[bool, Optional[str]]:
    """Compile `project` (via its own build.py) inside `container_id`, with the per-bug
    sanitizer ARVO recorded (overview.csv's 'sanitizer' column) and the flag recipe every
    build path in this pipeline shares, so their tested binaries diverge as little as their
    build.py's own project-specific flags force them to. Used by ArvoValidator.build_test()
    (dyninst's own-unpatched-tree build, later binary-patched) and by rq1-2-san2patch-conv.py's
    build() (the conv baseline's already-source-patched-tree rebuild) alike -- what those two
    callers do NOT share is which source tree gets built or where the result goes, since one
    needs an unpatched binary to patch afterwards and the other needs the fix already compiled
    in; only the compile recipe itself is unified here.

    extra_flags: appended to CFLAGS/CXXFLAGS/LDFLAGS after the shared recipe, for a caller's
    own additional requirements (e.g. conv's '-pthread', needed so its --skip-configure rebuild
    agrees with the Makefile its own initial configuring build generated with -pthread already
    in the mix).

    Returns (ok, stderr_or_none) -- same shape as ArvoValidator.metapro_patch().
    """
    if san == 'ubsan':
        san_flag = '-fsanitize=undefined'
    elif san == 'asan':
        san_flag = '-fsanitize=address'
    else:
        # msan or anything else this pipeline was never set up to build for -- fall back to
        # the old combined behaviour rather than silently mis-testing it.
        san_flag = '-fsanitize=address,undefined'
    # -O0 and -ferror-limit=0 always, -fno-sanitize-recover=all only for ubsan: matches
    # metapro's own project-build flags (metapro/src/main.cpp's buildWithAsan/buildWithUBsan
    # branches -- it never adds -fno-sanitize-recover=all to its asan branch, only its ubsan
    # one) as closely as CC/CXX=clang (vs metapro-tcc/metapro-tcxx, unavoidably different)
    # allows, so every method's tested project binary diverges as little as possible for a
    # fair comparison between patching mechanisms.
    recover_flag = ' -fno-sanitize-recover=all' if san == 'ubsan' else ''
    extra = f' {extra_flags}' if extra_flags else ''
    cflags = f'{san_flag} -g -O0 -ferror-limit=0{recover_flag} -fno-omit-frame-pointer{extra}'
    env = {
        'CFLAGS': cflags,
        'CXXFLAGS': cflags,
        'LDFLAGS': f'{san_flag}{extra}',
        'CC': 'clang',
        'CXX': 'clang++',
    }
    configure_flag = ' --skip-configure' if skip_configure else ''
    cmd = ['docker', 'exec']
    for k, v in env.items():
        cmd += ['-e', f'{k}={v}']
    cmd += [container_id, 'bash', '-c',
           f'python3 {work_dir_container}/build.py {project} {bug_id} {source_dir_container}'
           f'{configure_flag} -j {jobs} -o {output_path_container}']
    res = sp.run(cmd, stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
    if res.returncode != 0:
        return False, res.stdout
    return True, None


class ArvoValidator(BaseValidator):
    name = "arvo-test"
    failed_test_num:Dict[str, Set[str]] = dict()
    # ndpi's unit tests abort via assert() instead of naming a failure, so they
    # are tracked by this single sentinel rather than a per-test name.
    NDPI_UNIT_FAILED = '<unit-tests-failed>'

    def __init__(
        self,
        project:str,
        bug_id:int,
        work_dir:str,
        binary:str,
        poc:str,
        stage_id,
        output_dir:str='san2patch',
        *args,
        **kwargs,
    ):
        super().__init__(bug_id, project, *args, **kwargs)

        self.stage_id = stage_id

        # Name of the per-bug output directory (run-arvo.py's -o/--output).
        # Everything this validator writes lives under {work_dir}/{output_dir}.
        self.output_dir = output_dir
        self.main_dir = os.path.join(work_dir, output_dir, 'final')
        os.makedirs(self.main_dir, exist_ok=True)
        self.work_dir = work_dir

        # Absolute path to the fuzz target inside the container
        # ({work_dir}/san2patch/output/{name}), used to run it directly.
        self.binary_path = binary
        # Bare file name ("html", ...). os.path.join() drops everything before an
        # absolute component, so binary_path must never be joined onto a directory.
        self.binary_name = os.path.basename(binary)
        self.crash_input = poc
        self.exploit_file = poc.split("/")[-1]
        self.project = project
        self.bug_id = bug_id

        # Inside the host
        self.gen_diff_dir = os.path.join(work_dir, output_dir, "gen_diff")

        self.container_id = f'arvo-{bug_id}'

        self.run_dir = os.path.join(self.gen_diff_dir, self.stage_id)
        self.source_dir = os.path.join(work_dir, 'san2patch-source')
        self.setuped = False

        # Inside the docker
        # self.data_dir = f"/san2patch-benchmark/{self.project_name}/{self.vuln_id}"
        # self.experiment_dir = (
        #     f"/experiment/san2patch-benchmark/{self.project_name}/{self.vuln_id}"
        # )
        # self.experiment_func_dir = (
        #     f"/experiment_func/san2patch-benchmark/{self.project_name}/{self.vuln_id}"
        # )
        # self.reproduce_cmd = f"./{self.data_dir}/test.sh {self.exploit_file}".strip()
        # self.reproduce_cmd = f"./test.sh {self.exploit_file}".strip()

    def setup(self, san):
        self.logger.info("Setting up the docker container for validating patch...")

        if self.container_id is None or self.container_id == "":
            raise ValueError("Container not found.")

        # Remove all diff files from the previous run inside the docker
        # The remove script is in "/experiment/san2patch-benchmark/clear.sh"
        # self.run_cmd(f'docker exec {self.container_id} bash -c "cd /experiment/san2patch-benchmark && ./clear.sh"', cwd=self.main_dir, quiet=True)
        env = dict()
        # Build with exactly the sanitizer ARVO recorded this bug as needing (overview.csv's
        # 'sanitizer' column via run-arvo.py's required `sanitizer` CLI arg -> self.sanitizer ->
        # here), not a blanket address+undefined for every case. Combining both unconditionally
        # makes the build trip UBSan on unrelated, pre-existing undefined behavior elsewhere in
        # the codebase whenever a PoC happens to fall through to that code path -- a false "N"
        # for a patch that has nothing to do with that file, on a bug ARVO itself only ever
        # classified as e.g. asan. It also roughly doubles compiled code size (both sanitizers'
        # instrumentation on every check) versus building with the one sanitizer actually needed,
        # which inflates Dyninst's binary-analysis (launch_time) and build time for no benefit.
        # See _dyninst_run_mutator()'s external_symbolizer_path= comment for the matching fix on
        # the read side (that fork-vs-ptrace hang can fire on a genuine asan/ubsan hit too).
        if san == 'ubsan':
            san_flag = '-fsanitize=undefined'
        elif san == 'asan':
            san_flag = '-fsanitize=address'
        else:
            # msan or anything else this pipeline was never set up to build for -- fall back to
            # the old combined behaviour rather than silently mis-testing it.
            san_flag = '-fsanitize=address,undefined'
        env['CFLAGS'] = f'{san_flag} -g -fno-sanitize-recover=all -fno-omit-frame-pointer'
        env['CXXFLAGS'] = f'{san_flag} -g -fno-sanitize-recover=all -fno-omit-frame-pointer'
        env['LDFLAGS'] = san_flag
        env['CC'] = 'clang'
        env['CXX'] = 'clang++'
        
        cmd = f'docker exec '
        for e, v in env.items():
            cmd += f'-e {e}="{v}" '
        # Fix path construction: check if self.output_dir is absolute
        if os.path.isabs(self.output_dir):
            output_path = self.output_dir
        else:
            output_path = f"{self.work_dir}/{self.output_dir}"
        cmd += f'{self.container_id} bash -c "python3 {self.work_dir}/build.py {self.project_name} {self.bug_id} {self.source_dir} -j 10 -o {output_path}/output"'
        ret_code_b, _, stderr_b = self.run_cmd(
            cmd,
            cwd=self.source_dir,
            pipe=True,
            expect_error=True,
            env=env,
        )
        if ret_code_b != 0:
            self.logger.error("Initial build failed.")
            self.logger.debug(stderr_b)
            return False, stderr_b

        else:
            if self.project_name == 'ffmpeg':
                # ffmpeg test
                cmd = f'docker exec -w {self.source_dir} '
                for e, v in env.items():
                    cmd += f'-e {e}="{v}" '
                cmd += f'{self.container_id} bash -c "python3 /root/project/metac/benchmarks/arvo/scripts/gen-fate-supported.py {self.bug_id} {self.source_dir} --force -j 10"'
                ret_code_b, _, _ = self.run_cmd(
                    cmd,
                    cwd=self.source_dir,
                    pipe=True,
                    expect_error=True,
                )
                self.failed_test_num[self.vuln_id] = set()
                if os.path.exists(os.path.join(self.work_dir, "fate-failed.txt")):
                    with open(os.path.join(self.work_dir, "fate-failed.txt"), "r") as f:
                        for line in f:
                            self.failed_test_num[self.vuln_id].add(line.strip())
            elif self.project_name == 'gpac':
                self._patch_gpac_route_receive_logs()
                cmd = f'docker exec -w {self.source_dir}/testsuite '
                for e, v in env.items():
                    cmd += f'-e {e}="{v}" '
                cmd += f'{self.container_id} bash -c "./make_tests.sh -clean"'
                ret_code, _, _ = self.run_cmd(cmd, cwd=self.source_dir, pipe=True, expect_error=True)
                if ret_code != 0:
                    self.logger.error("Initial functionality test clean failed.")
                    return False, None
                cmd = f'docker exec -w {self.source_dir}/testsuite '
                for e, v in env.items():
                    cmd += f'-e {e}="{v}" '
                cmd += f'{self.container_id} bash -c "PATH={self.source_dir}/bin/gcc:\\$PATH ./make_tests.sh -p=0 -no-hash"'
                ret_code, stdout_test, stderr_test = self.run_cmd(cmd, cwd=self.source_dir, pipe=True, expect_error=True)
                self.failed_test_num[self.vuln_id] = set()
                for line in (stdout_test + stderr_test).splitlines():
                    if 'play:Fail' in line:
                        test_name = line.split(':')[0].strip()
                        self.failed_test_num[self.vuln_id].add(test_name)
                    elif 'run:HashFail' in line:
                        test_name = line.split(':')[0].strip()
                        self.failed_test_num[self.vuln_id].add(test_name)
            elif self.project_name == 'libxml2':
                _FAIL = re.compile(r'^(?:Result for|File)\s+(\./test/\S+)', re.M)
                cmd = f'docker exec -w {self.source_dir} '
                for e, v in env.items():
                    cmd += f'-e {e}="{v}" '
                cmd += f'{self.container_id} bash -c "make check -j10 -k"'
                ret_code_b, stdout, stderr = self.run_cmd(
                    cmd,
                    cwd=self.source_dir,
                    pipe=True,
                    expect_error=True,
                )
                failed_tests = _FAIL.findall(stderr)
                self.failed_test_num[self.vuln_id] = set(failed_tests)
            elif self.project_name == 'mruby':
                cmd = f'docker exec -w {self.source_dir} '
                for e, v in env.items():
                    cmd += f'-e {e}="{v}" '
                cmd += f'{self.container_id} bash -c "rake test"'
                ret_code, _, _ = self.run_cmd(cmd, cwd=self.source_dir, pipe=True, expect_error=True)
                self.failed_test_num[self.vuln_id] = set()
                if ret_code != 0:
                    self.logger.error("Initial functionality test failed.")
                    return False, None
            elif self.project_name == 'php-src':
                failed_tests, _ = self.php_run_tests(timeout=60 * 60)
                if failed_tests is None:
                    self.logger.error("Initial functionality test failed.")
                    return False, None
                self.failed_test_num[self.vuln_id] = failed_tests
            elif self.project_name == 'ndpi':
                # OK, SKIP or ERROR
                _FAIL = re.compile(r'^(\S+)\s+ERROR', re.M)
                cmd = f'docker exec -w {self.source_dir} -e NDPI_DISABLE_FUZZY=1 -e CXXFLAGS= '
                for e, v in env.items():
                    if e == 'CXXFLAGS':
                        continue
                    cmd += f'-e {e}="{v}" '
                cmd += f'{self.container_id} bash -c "./tests/do.sh"'
                ret_code, stdout, stderr = self.run_cmd(cmd, cwd=self.source_dir, pipe=True, expect_error=True)
                self.failed_test_num[self.vuln_id] = set(_FAIL.findall(stdout))
                cmd = f'docker exec -w {self.source_dir} -e NDPI_DISABLE_FUZZY=1 -e CXXFLAGS= '
                for e, v in env.items():
                    if e == 'CXXFLAGS':
                        continue
                    cmd += f'-e {e}="{v}" '
                cmd += f'{self.container_id} bash -c "./tests/do-unit.sh"'
                ret_code, stdout, stderr = self.run_cmd(cmd, cwd=self.source_dir, pipe=True, expect_error=True)
                if ret_code != 0:
                    self.failed_test_num[self.vuln_id].add(self.NDPI_UNIT_FAILED)
            else:
                cmd = f'docker exec -w {self.source_dir} '
                for e, v in env.items():
                    cmd += f'-e {e}="{v}" '
                cmd += f'{self.container_id} bash -c "make check -j10 -k"'
                ret_code_b, _, _ = self.run_cmd(
                    cmd,
                    cwd=self.source_dir,
                    pipe=True,
                    expect_error=True,
                )
                self.failed_test_num[self.vuln_id] = set()
                if ret_code_b != 0:
                    self.logger.error("Initial functionality test build failed.")
                    return False, stderr_b
            self.logger.info("Initial build success.")
            return True, None

        # Remove just the diff file for the current vuln_id
        self.run_cmd(
            f'docker exec {self.container_id} bash -c "ls {self.experiment_dir}/{self.vuln_id}.diff && rm -f {self.experiment_dir}/{self.vuln_id}.diff"',
            cwd=self.main_dir,
            quiet=True,
        )

        # Check if the data directory exists
        ret_code, _, _ = self.run_cmd(
            f'docker exec {self.container_id} bash -c "ls {self.experiment_dir}"',
            cwd=self.main_dir,
            quiet=True,
        )

        if ret_code != 0:
            raise ValueError("Data directory not found.")

        # Reset the git repository
        self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.experiment_dir}/src && git reset --hard"',
            cwd=self.main_dir,
            quiet=True,
        )

        self.logger.debug(f"Container ID: {self.container_id}")
        self.logger.debug("Docker container setup completed.")

    def _patch_gpac_route_receive_logs(self):
        """gpac's testsuite (a submodule cloned fresh per checkout) runs network
        ROUTE/DASH tests as a backgrounded 'receive' subtest that keeps listening
        until the sender's stream ends; when multicast doesn't work in this sandboxed
        docker setup the receiver never sees EOS and make_tests.sh's test_end just
        blocks on `wait` forever, so the receiver keeps appending to its real log file
        indefinitely -- one such stuck run filled an entire 14T disk with ~12.8TB of
        deleted-but-still-open log data before being noticed.

        Route the 'receive' subtest's log to /dev/null instead, so a hung receiver
        can no longer grow disk usage no matter how long it runs. Idempotent (skips
        already-patched files) and safe to run before every gpac functional test.
        """
        # Built as a base64 payload and decoded inside the container so none of the
        # sed script's own quoting/escaping has to survive the host shell -> docker
        # exec -> container bash quoting chain.
        inner_script = (
            f'cd "{self.source_dir}/testsuite" && '
            'grep -q \'log_subtest="/dev/null"\' make_tests.sh || '
            'sed -i \'/log_subtest="\\$LOGS_DIR\\/\\$TEST_NAME-logs-\\$subtest_idx-\\$2\\.txt"/a'
            '\\ if [ "$2" = "receive" ]; then log_subtest="/dev/null"; fi\' make_tests.sh'
        )
        b64 = base64.b64encode(inner_script.encode()).decode()
        cmd = f"docker exec {self.container_id} bash -c 'echo {b64} | base64 -d | bash'"
        self.run_cmd(cmd, cwd=self.source_dir, pipe=True, expect_error=True, quiet=True)

    def get_patched_files(self, docker_patch_file):
        """Return the repo-relative paths a patch modifies, without touching
        the working tree.

        `git apply --numstat` inspects the patch and prints one line per file
        as "<added>\\t<deleted>\\t<path>", so the third tab-separated column is
        the path. Binary files report "-" for the counts but still list the
        path.
        """
        ret, stdout, stderr = self.run_cmd(
            f'docker exec {self.container_id} bash -c "git apply --numstat --ignore-whitespace {docker_patch_file}"',
            cwd=self.source_dir,
            pipe=True,
            expect_error=True,
        )
        if ret != 0:
            self.logger.error(f"Failed to list patched files: {stderr}")
            return []

        files = []
        for line in stdout.splitlines():
            cols = line.split("\t")
            if len(cols) >= 3 and cols[2]:
                files.append(cols[2])
        return files

    def patch(self):
        self.logger.info("Applying the patch...")

        host_patch_file = os.path.join(
            self.gen_diff_dir, self.stage_id, f"cur-patch.diff"
        )
        docker_patch_file = host_patch_file

        # Record which files the patch touches so we can revert exactly these
        # files after testing (see revert()).
        self.patched_files = self.get_patched_files(docker_patch_file)
        self.logger.debug(f"Patched files: {self.patched_files}")

        # Apply the patch
        ret, _, stderr = self.run_cmd(
            f'docker exec -w {self.source_dir} {self.container_id} bash -c "git apply --ignore-whitespace {docker_patch_file}"',
            cwd=self.source_dir,
            pipe=True,
            expect_error=True,
        )

        if ret != 0 and ret != 1:
            self.logger.error("Patch failed to apply.")
            return False, stderr

        else:
            self.logger.info("Patch applied successfully.")
            return True, None

    def revert(self):
        """Restore the patched files to their original contents.

        The patcher edits files in the patched repo (san2patch-source), so we
        revert by copying each modified file back from the pristine original
        repo (source). Call this after testing to revert to the original source.
        """
        files = getattr(self, "patched_files", None)
        if not files:
            self.logger.debug("No patched files recorded; nothing to revert.")
            return True, None

        original_dir = os.path.join(self.work_dir, "source")
        for file in files:
            src = os.path.join(original_dir, file)
            dst = os.path.join(self.source_dir, file)
            ret, _, stderr = self.run_cmd(
                f'cp "{src}" "{dst}"',
                cwd=self.source_dir,
                pipe=True,
                expect_error=True,
            )
            if ret != 0:
                self.logger.error(f"Failed to revert {file}: {stderr}")
                return False, stderr

        self.logger.info("Reverted patched files to original.")
        return True, None

    def build_test(self, san:str = 'asan', skip_configure: bool = True, jobs: int = 1):
        self.logger.info("Building the project...")
        # Fix path construction: check if self.output_dir is absolute
        if os.path.isabs(self.output_dir):
            output_path = self.output_dir
        else:
            output_path = f"{self.work_dir}/{self.output_dir}"
        # skip_configure defaults True to match every pre-existing caller (all mid-graph
        # re-verify rebuilds, run after setup() already configured the tree once). The
        # checkout.py-side dyninst prep path (a fresh container, never configured) passes
        # False so build.py runs its ./configure step here instead.
        ok, stderr_b = _build_project(
            self.container_id, self.project_name, self.vuln_id, self.work_dir,
            self.source_dir, f'{output_path}/output', san, jobs=jobs, skip_configure=skip_configure,
        )
        if not ok:
            self.logger.error("Build failed.")
            return False, stderr_b
        else:
            self.logger.info("Build completed.")
            return True, None

    def build_func(self):
        return True, None
        self.logger.info("Building the project...")

        ret_code_c, _, stderr_c = self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.data_dir} && ./config_func.sh"',
            cwd=self.main_dir,
            pipe=True,
            expect_error=True,
        )
        ret_code_b, _, stderr_b = self.run_cmd(
            f'docker exec {self.container_id} bash -c "cd {self.data_dir} && ./build_func.sh"',
            cwd=self.main_dir,
            pipe=True,
            expect_error=True,
        )

        if ret_code_c != 0 or ret_code_b != 0:
            self.logger.error(f"Build failed. {self.vuln_id}")

            return False, stderr_c if ret_code_c != 0 else stderr_b

        else:
            self.logger.info(f"Build completed. {self.vuln_id}")

            return True, None

    # Environment php-src's test suite runs under. Kept in one place so the
    # baseline recorded by setup() and every later functionality_test() run are
    # directly comparable -- a test that only fails because the two runs used
    # different sanitizer options would otherwise look like a regression.
    PHP_TEST_ENV = {
        'NO_INTERACTION': '1',
        'NO_COLOR': '1',
        'ASAN_OPTIONS': 'detect_leaks=0:allocator_may_return_null=1',
        'UBSAN_OPTIONS': 'print_stacktrace=1:abort_on_error=1',
        'LIBRARY_PATH': '/usr/local/lib:',
        'LD_LIBRARY_PATH': '/usr/local/lib:',
    }

    # The suite prints a line per test for ~22k tests, so the raw log runs to
    # megabytes. Only a tail of it is ever handed back, to keep graph state small.
    PHP_LOG_TAIL = 20000

    def php_run_tests(self, timeout: int):
        """Run php-src's suite via `make test`; return (failed test paths, output).

        Returns (None, output) if the run produced no report at all, which is a
        harness failure rather than a set of failing tests.

        Results come from run-tests.php's JUnit XML instead of its stdout: stdout
        interleaves an in-place progress counter with the result lines, while the
        XML gives one <testcase> per test with an explicit <failure>/<error> child.

        The suite runs serially. Parallel mode (-j) is unusable for this build:
        configure runs with --disable-cgi, so run-tests.php leaves $php_cgi null,
        isset() on a null entry is false, and each worker then reads an undefined
        $php_cgi on the first CGI test and escalates that warning to a fatal error.
        Serial mode initialises $php_cgi up front and skips those tests cleanly.
        """
        junit_file = os.path.join(self.work_dir, 'php-junit.xml')
        if os.path.exists(junit_file):
            os.remove(junit_file)

        env = dict(self.PHP_TEST_ENV)
        env['TEST_PHP_JUNIT'] = junit_file

        cmd = f'docker exec -w {self.source_dir} '
        for e, v in env.items():
            cmd += f'-e {e}="{v}" '
        cmd += f'''{self.container_id} bash -c "make test TEST_PHP_ARGS='-q'"'''
        # `make test` exits non-zero whenever any test fails, so its return code
        # says nothing beyond "the suite ran"; the report is the actual result.
        _, stdout, stderr = self.run_cmd(
            cmd,
            cwd=self.source_dir,
            pipe=True,
            expect_error=True,
            timeout=timeout,
        )
        output = stdout + stderr

        if not os.path.exists(junit_file):
            self.logger.error("php test suite produced no JUnit report.")
            return None, output

        failed = set()
        try:
            tree = ET.parse(junit_file)
        except ET.ParseError as e:
            self.logger.error(f"Cannot parse php JUnit report: {e}")
            return None, output

        for testcase in tree.iter('testcase'):
            # name is "<path>.phpt (<description>)"; the path alone is the stable id.
            name = testcase.get('name', '').split(' (')[0].strip()
            # PASS/XFAIL/XLEAK carry no child and SKIP adds <skipped>; only
            # FAIL/LEAK (<failure>) and BORK (<error>) count as failures.
            if not name:
                continue
            if testcase.find('failure') is not None or testcase.find('error') is not None:
                failed.add(name)
        return failed, output

    def functionality_test(self):
        self.logger.info("Testing the functionality...")
        TIMEOUT = 60*60 # 1 hour

        env = dict()
        env['ASAN_OPTIONS'] = 'detect_leaks=0:allocator_may_return_null=1'
        env['UBSAN_OPTIONS'] = 'print_stacktrace=1:abort_on_error=1'
        env['LIBRARY_PATH'] = '/usr/local/lib:' + env.get('LIBRARY_PATH', '')
        env['LD_LIBRARY_PATH'] = '/usr/local/lib:' + env.get('LD_LIBRARY_PATH', '')

        # Just run the test_func.sh in data_dir
        if self.project_name == 'ffmpeg':
            cmd = f'docker exec -w {self.source_dir} '
            for e, v in env.items():
                cmd += f'-e {e}="{v}" '
            cmd += f'{self.container_id} bash -c "python3 /root/project/metac/benchmarks/arvo/scripts/gen-fate-supported.py {self.bug_id} {self.source_dir} -j 10"'
            ret_code, _, stderr = self.run_cmd(
                cmd,
                cwd=self.main_dir,
                pipe=True,
                expect_error=True,
                timeout=TIMEOUT,
            )
            if os.path.exists(os.path.join(self.work_dir, "fate-failed.txt")):
                with open(os.path.join(self.work_dir, "fate-failed.txt"), "r") as f:
                    for line in f:
                        if line.strip() not in self.failed_test_num[self.vuln_id]:
                            self.logger.error(f'Functionality test failed. {self.vuln_id}, new failed test: {line.strip()}')
                            return False, stderr
        elif self.project_name == 'gpac':
            self._patch_gpac_route_receive_logs()
            cmd = f'docker exec -w {self.source_dir}/testsuite '
            for e, v in env.items():
                cmd += f'-e {e}="{v}" '
            cmd += f'{self.container_id} bash -c "./make_tests.sh -clean"'
            ret_code, _, _ = self.run_cmd(cmd, cwd=self.source_dir, pipe=True, expect_error=True)
            if ret_code != 0:
                self.logger.error("Functionality test clean failed.")
                return False, None
            cmd = f'docker exec -w {self.source_dir}/testsuite '
            for e, v in env.items():
                cmd += f'-e {e}="{v}" '
            cmd += f'{self.container_id} bash -c "PATH={self.source_dir}/bin/gcc:\\$PATH ./make_tests.sh -p=0 -no-hash"'
            ret_code, stdout, stderr = self.run_cmd(cmd, cwd=self.source_dir, pipe=True, expect_error=True, timeout=TIMEOUT,)
            for line in (stdout + stderr).splitlines():
                if 'play:Fail' in line:
                    test_name = line.split(':')[0].strip()
                    if test_name not in self.failed_test_num[self.vuln_id]:
                        self.logger.error(f'Functionality test failed. {self.vuln_id}, new failed test: {test_name}')
                        return False, stderr
                elif 'run:HashFail' in line:
                    test_name = line.split(':')[0].strip()
                    if test_name not in self.failed_test_num[self.vuln_id]:
                        self.logger.error(f'Functionality test failed. {self.vuln_id}, new failed test: {test_name}')
                        return False, stderr
        elif self.project_name == 'libxml2':
            _FAIL = re.compile(r'^(?:Result for|File)\s+(\./test/\S+)', re.M)
            cmd = f'docker exec -w {self.source_dir} '
            for e, v in env.items():
                cmd += f'-e {e}="{v}" '
            cmd += f'{self.container_id} bash -c "make check -j10 -k"'
            ret_code_b, stdout, stderr = self.run_cmd(
                cmd,
                cwd=self.source_dir,
                pipe=True,
                expect_error=True,
                timeout=TIMEOUT,
            )
            failed_tests = _FAIL.findall(stderr)
            for test in failed_tests:
                if test not in self.failed_test_num[self.vuln_id]:
                    self.logger.error(f'Functionality test failed. {self.vuln_id}, new failed test: {test}')
                    return False, stderr
        elif self.project_name == 'mruby':
            cmd = f'docker exec -w {self.source_dir} '
            for e, v in env.items():
                cmd += f'-e {e}="{v}" '
            cmd += '-e LDFLAGS="-fsanitize=address,undefined" '
            cmd += f'{self.container_id} bash -c "rake test"'
            ret_code, _, stderr = self.run_cmd(cmd, cwd=self.source_dir, pipe=True, expect_error=True, timeout=TIMEOUT,)
            if ret_code != 0:
                self.logger.error("Functionality test failed.")
                return False, stderr
        elif self.project_name == 'php-src':
            failed_tests, output = self.php_run_tests(timeout=TIMEOUT)
            if failed_tests is None:
                self.logger.error(f"Functionality test failed. {self.vuln_id}")
                return False, output[-self.PHP_LOG_TAIL:]
            new_failed = sorted(failed_tests - self.failed_test_num[self.vuln_id])
            if new_failed:
                self.logger.error(f'Functionality test failed. {self.vuln_id}, new failed test: {new_failed[0]}')
                return False, 'New failing tests:\n' + '\n'.join(new_failed)
        elif self.project_name == 'ndpi':
            _FAIL = re.compile(r'^(\S+)\s+ERROR', re.M)
            cmd = f'docker exec -w {self.source_dir} -e NDPI_DISABLE_FUZZY=1 -e CXXFLAGS= '
            for e, v in env.items():
                if e == 'CXXFLAGS':
                    continue
                cmd += f'-e {e}="{v}" '
            cmd += f'{self.container_id} bash -c "./tests/do.sh"'
            ret_code, stdout, stderr = self.run_cmd(cmd, cwd=self.source_dir, pipe=True, expect_error=True, timeout=TIMEOUT,)
            for test_name in _FAIL.findall(stdout):
                if test_name not in self.failed_test_num[self.vuln_id]:
                    self.logger.error(f'Functionality test failed. {self.vuln_id}, new failed test: {test_name}')
                    return False, stderr
            cmd = f'docker exec -w {self.source_dir} -e NDPI_DISABLE_FUZZY=1 -e CXXFLAGS= '
            for e, v in env.items():
                if e == 'CXXFLAGS':
                    continue
                cmd += f'-e {e}="{v}" '
            cmd += f'{self.container_id} bash -c "./tests/do-unit.sh"'
            ret_code, stdout, stderr = self.run_cmd(cmd, cwd=self.source_dir, pipe=True, expect_error=True, timeout=TIMEOUT,)
            if ret_code != 0 and self.NDPI_UNIT_FAILED not in self.failed_test_num[self.vuln_id]:
                self.logger.error(f'Functionality test failed. {self.vuln_id}, unit tests failed')
                return False, stderr
        else:
            cmd = f'docker exec -w {self.source_dir} '
            for e, v in env.items():
                cmd += f'-e {e}="{v}" '
            cmd += f'{self.container_id} bash -c "make check -j 10 -k"'
            ret_code, _, stderr = self.run_cmd(
                cmd,
                cwd=self.main_dir,
                pipe=True,
                expect_error=True,
                timeout=TIMEOUT,
            )

            if ret_code != 0:
                self.logger.error(f"Functionality test failed. {self.vuln_id}")
                return False, stderr
            
        self.logger.success(f"Functionality test passed. {self.vuln_id}")
        return True, None

    def vulnerability_test(self):
        self.logger.info("Testing the vulnerability...")

        # Try 1: Copy the error output to the host
        # docker_vuln_out_file = os.path.join(
        #     self.experiment_dir, "src", self.binary_path + ".out"
        # )
        host_vuln_out_file = os.path.join(self.run_dir, "vuln.out")
        if os.path.exists(host_vuln_out_file):
            os.remove(host_vuln_out_file)
        env = dict()
        env['ASAN_OPTIONS'] = 'detect_leaks=0:allocator_may_return_null=1'
        env['UBSAN_OPTIONS'] = 'print_stacktrace=1:abort_on_error=1'
        env['LIBRARY_PATH'] = '/usr/local/lib:' + env.get('LIBRARY_PATH', '')
        env['LD_LIBRARY_PATH'] = '/usr/local/lib:' + env.get('LD_LIBRARY_PATH', '')

        def print_output(file_path:str):
            try:
                with open(file_path, "r", errors="ignore") as f:
                    content = f.read()
                    self.logger.debug(f"Vulnerability test output ({file_path}):\n{content}")
            except FileNotFoundError:
                self.logger.debug(f"Output file {file_path} not found.")

        # The fuzz binary runs inside the container with a *container-side*
        # `timeout`. A host-side timeout alone is not enough: `docker exec` does
        # not forward signals to the in-container process, so a host timeout
        # would leave the binary running inside the container. Because the
        # output dir is bind-mounted, that leftover process keeps the executable
        # open and later overwrites of it fail with ETXTBSY ("Text file busy").
        # `timeout -s KILL` kills the binary where it actually runs.
        cmd = f'docker exec '
        for e, v in env.items():
            cmd += f'-e {e}="{v}" '
        cmd += f'{self.container_id} bash -c "timeout -s KILL 180 {self.binary_path} {self.crash_input}"'
        vuln_timeout = 60 * 3  # 3 minutes timeout for vulnerability test
        
        # Fix path construction: check if self.output_dir is absolute
        if os.path.isabs(self.output_dir):
            output_path = self.output_dir
        else:
            output_path = f"{self.work_dir}/{self.output_dir}"
            
        return_code, _, _ = self.run_cmd(
            cmd,
            cwd=os.path.join(output_path, 'output'),
            expect_error=True,
            stdout_file=host_vuln_out_file,
            stderr_file=host_vuln_out_file,
            env=env,
            pipe=True,
            timeout=vuln_timeout + 30,  # outer guard, slightly longer than the container-side timeout
        )
        # if return_code == -1:
        #     self.logger.error(f"Vulnerability test failed by external reason. {self.vuln_id}")
        #     print_output(host_vuln_out_file)
        #     return False, None
        # elif return_code == 124:
        #     self.logger.error(f"Vulnerability test timed out. {self.vuln_id}")
        #     print_output(host_vuln_out_file)
        #     return False, None
        # elif return_code == 134:
        #     self.logger.error(f"Vulnerability test killed by signal or ABORT. {self.vuln_id}")
        #     print_output(host_vuln_out_file)
        #     return False, None
        # elif return_code == 139:
        #     self.logger.error(f"Vulnerability test throw SEGFAULT. {self.vuln_id}")
        #     print_output(host_vuln_out_file)
        #     return False, None
        # elif return_code == 1:
        #     self.logger.error(f"Vulnerability test failed by functional error. {self.vuln_id}")
        #     print_output(host_vuln_out_file)
        #     return False, None
        # elif return_code == 0:
        #     self.logger.info(f"Vulnerability test completed with return code {return_code}. {self.vuln_id}")
        #     return True, None
        # else:
        #     self.logger.warning(f"Vulnerability test completed with unexpected return code {return_code}. {self.vuln_id}")
        #     print_output(host_vuln_out_file)
        #     return False, None
        if return_code in (-1, 124, 137):
            self.logger.error(f"Vulnerability test timed out or unexpected error. {self.vuln_id}")
            return False, None

        # Copy sanitizer output to the host
        # self.run_cmd(
        #     f"docker cp {self.container_id}:{docker_vuln_out_file} {host_vuln_out_file}",
        #     cwd=self.main_dir,
        # )

        try:
            with open(host_vuln_out_file, "r", errors="ignore") as f_stderr:
                stderr = f_stderr.read()
                # if self.logger.isEnabledFor(MyLoggerLevelEnum.DEBUG.value):
                #     self.logger.debug(f"Vulnerability test stderr:\n{stderr}")

                # With allocator_may_return_null=1, ASAN returns NULL for an
                # allocation it refuses and prints this WARNING instead of an
                # ERROR/SUMMARY block; POC_CRASH_RE matches it, and it is kept here
                # because get_only_san_output() cannot extract a range from it.
                alloc_fail_re = r"WARNING: .+Sanitizer failed to allocate"

                verdict = classify_poc_output(stderr, return_code)

                # Checked first: with no verdict the absence of a crash signature
                # below would otherwise be read as "the patch works".
                if verdict == 'harness':
                    self.logger.error(
                        f"Vulnerability test produced no verdict "
                        f"(ret_code={return_code}); the PoC did not run to a "
                        f"result. {self.vuln_id}"
                    )
                    print_output(host_vuln_out_file)
                    return False, stderr

                # Check if the sanitizer is found
                if verdict == 'crash':
                    self.logger.error(f"Sanitizer detected the crash. {self.vuln_id}")
                    self.logger.error(f"Patch was not successful. {self.vuln_id}")

                    san_output = BaseDataset.get_only_san_output(stderr)
                    if not san_output:
                        # The allocation-failure WARNING is a standalone line
                        # with no ERROR/SUMMARY block, so get_only_san_output
                        # cannot extract a range; fall back to the warning lines.
                        san_output = "\n".join(
                            line for line in stderr.splitlines()
                            if re.search(alloc_fail_re, line)
                        ) or None

                    return False, san_output
                else:
                    self.logger.success(f"Crash not found. {self.vuln_id}")
                    self.logger.success(f"Vulnerability test passed. {self.vuln_id}")
                    print_output(host_vuln_out_file)

                    return True, None
        except FileNotFoundError:
            self.logger.success(f"Output file not found, crash not found. {self.vuln_id}")
            self.logger.success(f"Vulnerability test passed. {self.vuln_id}")
            print_output(host_vuln_out_file)

            return True, None
        
    def verify(self):
        verifier_path = os.path.join(self.work_dir, '..', '..', '..', 'scripts', 'patch-verifier-perfect.py')
        verifier_path = os.path.abspath(verifier_path)
        ground_truth_path = os.path.join(self.work_dir, 'dev.patch')
        gen_patch_file = os.path.join(self.gen_diff_dir, self.stage_id, f"cur-patch.diff")
        source_dir = os.path.join(self.work_dir, 'metapro-source') # preprocessed source code

        ret_code, stdout, stderr = self.run_cmd(
            f'python3 {verifier_path} {ground_truth_path} {gen_patch_file} {source_dir}',
            cwd=self.work_dir,
            pipe=True,
            expect_error=True,
        )
        if ret_code != 0:
            self.logger.error(f"Patch verification failed: {stderr}")
            return False, stderr
        else:
            result = json.loads(stdout)
            if result.get('confidence', '') == 'low':
                self.logger.warning("Patch verification confidence is low.")
            self.logger.info(f"Patch verification succeeded. Result: {result.get('equivalent', False)}")
            if result.get('equivalent', False) == False:
                self.logger.debug(f'Patch is not equal: {result.get("reason", "unknown")}')
            return True, result.get('equivalent', False)

    def preprocess_patcher(self):
        PATCHER_SRC = '/root/project/metac/metapro/src/binary/patcher-e9patch.py'
        PATCHER_DST = '/usr/local/bin/patcher-e9patch.py'
        self.run_cmd(
            f'docker exec -w {self.work_dir} {self.container_id} '
            f'bash -c "cp {PATCHER_SRC} {PATCHER_DST}"',
            cwd=self.work_dir,
            pipe=True,
        )
        self.run_cmd(
            f'docker exec -w {self.work_dir} {self.container_id} '
            f'bash -c "chmod +x {PATCHER_DST}"',
            cwd=self.work_dir,
            pipe=True,
        )
        
        # With E9Patch, we do not need to preprocess
        # cmd = ['binary_prep.py', os.path.join(container_work_dir, 'metapro-out', 'bin', binary)]
        # res = docker.exec_docker_cmd(cmd, bug_id, cwd=container_work_dir,
        #                              get_output=os.path.join(container_work_dir, 'binary_prep.log'))
        return True

    def _patcher_env(self):
        """Environment the binary patcher runs under (shared by every patcher call)."""
        new_env = os.environ.copy()
        if 'CXXFLAGS' in new_env:
            # Remove libc++ flags
            if '-stdlib=libc++' in new_env['CXXFLAGS']:
                new_env['CXXFLAGS'] = new_env['CXXFLAGS'].replace('-stdlib=libc++', '')
        new_env['CC'] = 'clang'
        new_env['CXX'] = 'clang++'
        new_env['LDFLAGS'] = '-pthread'
        new_env['UBSAN_OPTIONS'] = 'print_stacktrace=1:abort_on_error=1'
        new_env['ASAN_OPTIONS'] = 'detect_leaks=0'
        return new_env

    def _patch_specs(self, dev_patch:list) -> Set[str]:
        """Turn a patch config into the `-p ID:FUNC:FILE:...:TEMPLATE` specs the patcher takes.

        A REPLACE emits an INSERT_EXPR (new statement) and an INSERT_NOT_NULL_CHECKER ('0'
        disabler) at the *same* id/location -- one e9patch site (the runtime does both, keyed
        by id). Collapse them into a single spec (keyed by location, without the template) and
        keep the wrap template, which both inserts and skips; a lone INSERT_EXPR stays an
        insert. Emitting both as separate specs makes e9patch reject the second ("instruction
        already queued for patching").
        """
        loc_template = {}
        for patch_entry in dev_patch:
            if patch_entry['template'] not in ('INSERT_EXPR', 'INSERT_NOT_NULL_CHECKER'):
                continue
            key = (f'{patch_entry["id"]}:{patch_entry["function"]}:{patch_entry["file"]}:'
                f'{patch_entry["line"]}:{patch_entry["col"]}:'
                f'{patch_entry["end_line"]}:{patch_entry["end_col"]}')
            if key not in loc_template or patch_entry['template'] == 'INSERT_NOT_NULL_CHECKER':
                loc_template[key] = patch_entry['template']
        return {f'{key}:{template}' for key, template in loc_template.items()}

    def metapro_patch(self, patch_config_path:str|list):
        new_env = self._patcher_env()

        metapro_out_dir = os.path.join(self.work_dir, 'metapro-out')
        if isinstance(patch_config_path, str):
            with open(patch_config_path, 'r') as f:
                patch_config_path = json.load(f)
        dev_patches = self._patch_specs(patch_config_path)

        if len(dev_patches) == 0:
            # No insert patch, skip
            # shutil.copy(os.path.join(metapro_out_dir, 'bin', binary),
            # Fix path construction: check if self.output_dir is absolute
            if os.path.isabs(self.output_dir):
                output_path = self.output_dir
            else:
                output_path = f"{self.work_dir}/{self.output_dir}"
            shutil.copy(os.path.join(metapro_out_dir, 'asan-bin', self.binary_name),
                        os.path.join(output_path, f'{self.binary_name}.inst'))
            return True, 0., 'Do not have to patch, skip'

        # Run Binary patcher to apply the dev patch in binary level (w/o ASAN)
        # Fix path construction: check if self.output_dir is absolute
        if os.path.isabs(self.output_dir):
            output_path = self.output_dir
        else:
            output_path = f"{self.work_dir}/{self.output_dir}"
        san2patch_out_dir = os.path.join(output_path)
        BINARY_PATCHER = 'patcher-e9patch.py'
        # patcher_cmd = [BINARY_PATCHER, self.work_dir, os.path.join(metapro_out_dir, 'bin', self.binary),
        patcher_cmd = [BINARY_PATCHER, self.work_dir,
            os.path.join(metapro_out_dir, 'asan-bin', self.binary_name),
            san2patch_out_dir]
        for patch in dev_patches:
            patcher_cmd += ['-p', patch]
        # patcher_cmd.append('-v')

        cmd = f'docker exec -w {self.work_dir} '
        for e, v in new_env.items():
            cmd += f'-e {e}="{v}" '
        cmd += f'{self.container_id} {" ".join(patcher_cmd)}'

        start_time = time.time()
        ret_code, stdout, _ = self.run_cmd(
            cmd,
            cwd=self.work_dir,
            pipe=True,
            stderr_pipe=False,
            expect_error=True,
            env=new_env,
        )
        patch_time = time.time() - start_time
        if ret_code != 0:
            return False, patch_time, stdout

        return True, patch_time, stdout

    def metapro_runtime_env(self, patch_config_path:list) -> Dict[str,str]:
        """The METAPRO_* environment that makes a patched binary apply `patch_config_path`.

        e9patch only installs the *call sites*; which patch runs there, and what
        expression it evaluates, is decided at run time by these variables. So the
        same patched binary serves every candidate patch -- only this env changes.
        """
        new_env = dict()
        target_funcs = set()
        patch_ids = set()
        for patch_entry in patch_config_path:
            func = patch_entry['function']
            target_funcs.add(func)
            patch_id:int = patch_entry['id']
            patch_template:str = patch_entry['template']
            patch_ids.add(patch_id)
            exprs = patch_entry['exprs']
            if patch_template == 'INSERT_EXPR':
                new_env[f'METAPRO_EXPR_{patch_id}'] = exprs[0]
            elif patch_template == 'INSERT_NOT_NULL_CHECKER':
                new_env[f'METAPRO_PATCH_NOT_NULL_CHECKER_EXPR_{patch_id}'] = exprs[0]
            elif patch_template == 'REPLACE_CONDITION':
                new_env[f'METAPRO_PATCH_COND_{patch_id}'] = exprs[0]
                if len(exprs) > 1:
                    new_env[f'METAPRO_PATCH_COND_{patch_id}_2'] = exprs[1]

        patch_id_str = ''
        for p_id in patch_ids:
            patch_id_str += str(p_id) + ','
        patch_id_str = patch_id_str.rstrip(',')
        new_env['METAPRO_PATCH_ID'] = patch_id_str

        new_env['METAPRO_TARGET_FUNCTIONS'] = ''
        for func in target_funcs:
            new_env['METAPRO_TARGET_FUNCTIONS'] += func + ','
        new_env['METAPRO_TARGET_FUNCTIONS'] = new_env['METAPRO_TARGET_FUNCTIONS'].rstrip(',')
        new_env['METAPRO_OUTPUT_DIR'] = os.path.join(self.work_dir, 'metapro-out')
        # new_env['METAPRO_DEBUG_OUTPUT_FILE'] = os.path.join(self.work_dir, 'metapro-debug.log')
        new_env['ASAN_OPTIONS'] = 'detect_leaks=0'
        new_env['UBSAN_OPTIONS'] = 'abort_on_error=1:print_stacktrace=1'
        new_env['LIBRARY_PATH'] = '/usr/local/lib:' + new_env.get('LIBRARY_PATH', '')
        new_env['LD_LIBRARY_PATH'] = '/usr/local/lib:' + new_env.get('LD_LIBRARY_PATH', '')
        # new_env['METAPRO_DEBUG_PRINT_VAR_TABLE'] = '1'
        # new_env['METAPRO_DEBUG_PRINT_VAR_INSERT'] = '1'
        return new_env

    def metapro_test(self, patch_config_path:str|list, expect_fail = False):
        # Setup env var
        if isinstance(patch_config_path, str):
            with open(patch_config_path, 'r') as f:
                patch_config_path = json.load(f)
        new_env = self.metapro_runtime_env(patch_config_path)
        if os.path.exists(os.path.join(self.work_dir, 'metapro-debug.log')):
            os.remove(os.path.join(self.work_dir, 'metapro-debug.log'))

        # Setup test command
        # Fix path construction: check if self.output_dir is absolute
        if os.path.isabs(self.output_dir):
            output_path = self.output_dir
        else:
            output_path = f"{self.work_dir}/{self.output_dir}"
        san2patch_out_dir = os.path.join(output_path)
        # patcher-e9patch.py writes {output_dir}/{basename}.inst, so match that name.
        binary_path = os.path.join(san2patch_out_dir, f'{self.binary_name}.inst')
        self.logger.debug(f"Testing binary: {binary_path}")

        # Run test. The binary runs under a *container-side* `timeout`: `docker exec`
        # does not forward signals, so a host-side timeout alone would leave the binary
        # running in the container, holding `{binary}.inst` open (ETXTBSY on the next
        # patch). The host timeout is only an outer guard.
        POC_TIMEOUT = 300
        cmd = f'docker exec -w /src '
        for e, v in new_env.items():
            cmd += f'-e {e}="{v}" '
        cmd += f'{self.container_id} bash -c "timeout -s KILL {POC_TIMEOUT} {binary_path} /tmp/poc"'

        start_time = time.time()
        # stderr_pipe=False: the sanitizers report on stderr, so both streams have to be
        # searched -- merging them keeps the report intact next to the program's output.
        ret_code, output, _ = self.run_cmd(
            cmd,
            cwd=self.work_dir,
            pipe=True,
            expect_error=True,
            env=new_env,
            timeout=POC_TIMEOUT + 30,  # outer guard, slightly longer than the container-side one
            stderr_pipe=False,
        )
        exec_time = time.time() - start_time
        # run_cmd never raises: -1 is its host-side timeout / launch failure, and
        # `timeout -s KILL` reports 124 (expired) or 137 (killed).
        if ret_code in (-1, 124, 137):
            return False, float(POC_TIMEOUT), output
        
        verdict = classify_poc_output(output, ret_code)
        if verdict == 'crash':
            # The PoC still crashes the patched binary.
            return expect_fail, exec_time, output
        if verdict == 'harness':
            # No verdict: the binary never ran the PoC, or died in a way no sanitizer
            # reported. Neither "crash" nor "no crash" is true, so fail rather than
            # let a non-result count as a working patch.
            self.logger.error("Metapro PoC test produced no verdict "
                              f"(ret_code={ret_code}); treating as failure.")
            return False, exec_time, output

        # The PoC ran to completion; a non-zero return code also counts as success.
        return not expect_fail, exec_time, output


    def run(self, san):
        self.setup(san)
        self.patch()
        self.build_test(san)
        self.vulnerability_test()
        self.revert()

    def _dyninst_out_dir(self) -> str:
        """Per-(bug, output_dir, stage) directory for dyninst_patch()'s own
        build artifacts (libpatch .c/.o/.so, trimmed PIC archive). Lives
        under self.work_dir like gen_diff_dir/source_dir, so it's valid
        unchanged on both host and in-container (see the module-level
        docstring below dyninst_patch()/dyninst_test() for why)."""
        output_path = self.output_dir if os.path.isabs(self.output_dir) else os.path.join(self.work_dir, self.output_dir)
        return os.path.join(output_path, 'dyninst-out', str(self.stage_id))

    def _dyninst_pic_archive_path(self) -> str:
        """Cached once per (bug, output_dir) -- shared across every
        stage/attempt of the same real run, since it only depends on the
        project's own build (the compile-invocation log), not on which
        location is being patched."""
        output_path = self.output_dir if os.path.isabs(self.output_dir) else os.path.join(self.work_dir, self.output_dir)
        return os.path.join(output_path, 'dyninst-out', 'libpic.v2.a')

    def _dyninst_read_cc_log(self) -> list:
        ret_code, stdout, _ = self.run_cmd(
            f'docker exec {self.container_id} cat {DYNINST_CC_LOG}',
            pipe=True,
            expect_error=True,
        )
        if ret_code != 0:
            return []
        return _parse_cc_log(stdout)

    def _dyninst_ensure_pic_archive(self, cc_invocations: list, project_root_container: str) -> Optional[str]:
        archive_path = self._dyninst_pic_archive_path()
        if os.path.exists(archive_path):
            return archive_path
        script_path = os.path.join(os.path.dirname(archive_path), 'build-pic-archive.sh')
        ok = _build_pic_archive(self.container_id, cc_invocations, project_root_container, archive_path, script_path)
        return archive_path if ok and os.path.exists(archive_path) else None

    def dyninst_patch(self, locations: List[Dict], force_whole_file: bool = False,
                      sync_globals: bool = True) -> Tuple[bool, float, str]:
        """Build a single libpatch.so covering every location in `locations`,
        by replaying each file's real captured compile invocation (see
        dyninst-cc-wrapper.sh / setup_dyninst() in checkout.py) with the
        already-patched source, linked against a cached, whole-project PIC
        archive. Mirrors metapro_patch()'s contract exactly: returns
        (ok, elapsed_seconds, output).

        locations: [{'file': path relative to self.source_dir,
                     'function': str,
                     'patched_path': host-and-container path to the
                         already-patched copy of that file (under
                         self.source_dir)}, ...]
        -- exactly extract_patched_functions_from_diff()'s own output shape.

        force_whole_file: skip extraction and compile every file whole (the
        already-patched file directly) instead. A clean extraction compile
        can still be missing something outside its own closure and only fail
        later, at this function's own final link or at dyninst_test()'s
        loadLibrary() -- meant for dyninst_binary_patch()'s own retry in that
        case, not for a first attempt.

        sync_globals: keep libpatch.so's copies of file-scope variables in step with the running
        program's around every call of a patched function (see _DYN_RUNTIME_C), which is what
        makes a patched function that reads run-time-initialised tables see them. The sync itself
        is a raw byte copy, so a global whose *type* holds a heap pointer would duplicate that
        pointer's value into both copies -- whichever side later frees and replaces it, the sync
        could hand the other side a stale value it then frees again -- so _build_sync_tab() leaves
        any such global out (via a DWARF type walk; see _dyn_pointer_containing_globals()), and
        also leaves out any global that is not from the patched file(s) themselves (the archive
        pulls in unrelated files' objects, and with them their globals, purely to resolve calls out
        of the patched file -- see _build_sync_tab()'s own docstring). A patched function that
        itself needs the *current value* of an excluded pointer field (confirmed on libxml2's
        dict.c: its core hash table is inherently pointer-based) still sees it uninitialised --
        closing that gap needs the sync to stop copying and instead make libpatch.so's global
        alias the program's real memory, which is a larger change than this filtering is.
        """
        t0 = time.time()
        # self.source_dir (san2patch-source), not /src/<project>: San2Patch's
        # own build (self.setup() -> build.py) compiles the project from its
        # OWN patched-source copy, not the container's default ARVO checkout
        # -- confirmed directly (cc_invocations.log's captured CWD for every
        # ndpi/42508904 compile was .../san2patch-source/example, never
        # /src/ndpi/example). Using /src/<project> here (the older
        # arvo-san2patch prototype's own build location, which built
        # in-place under /src instead) made every compile-invocation lookup
        # below silently fail to match anything, misreporting a mechanism
        # failure ("no captured compile invocation") on every location.
        project_root_container = self.source_dir
        out_dir = self._dyninst_out_dir()
        os.makedirs(out_dir, exist_ok=True)

        cc_invocations = self._dyninst_read_cc_log()
        if not cc_invocations:
            return (False, time.time() - t0,
                    f'FAILED: no compile invocations captured at {DYNINST_CC_LOG} -- '
                    f'is dyninst-cc-wrapper.sh installed? (see setup_dyninst() in checkout.py)')

        pic_archive = self._dyninst_ensure_pic_archive(cc_invocations, project_root_container)
        if pic_archive is None:
            return False, time.time() - t0, 'FAILED: could not build the project PIC archive'

        # Functions whose names a macro generates become the symbols they expand to. dyninst_test()
        # replaces exactly these, so what was resolved here is left next to libpatch.so for it.
        resolved_path = os.path.join(out_dir, 'resolved-locations.json')
        if os.path.exists(resolved_path):
            os.remove(resolved_path)
        resolved, notes = _dyninst_expand_macro_named_functions(
            self.container_id, cc_invocations, project_root_container, out_dir, locations)
        with open(resolved_path, 'w') as f:
            json.dump({'input': locations, 'resolved': resolved}, f)

        ok, _, output = _dyninst_compile_and_link(
            self.container_id, cc_invocations, pic_archive, resolved,
            out_dir, project_root_container,
            binary_path_container=self.binary_path,
            force_whole_file=force_whole_file,
            sync_globals=sync_globals,
        )
        if notes:
            output = '\n'.join(notes) + '\n' + output
        return ok, time.time() - t0, output

    def dyninst_test(self, locations: List[Dict], timeout: int = 180) -> Tuple[bool, float, str]:
        """Launch self.binary_path suspended via Dyninst, swap in
        dyninst_patch()'s libpatch.so for every function in `locations`,
        resume, and run the PoC. Mirrors metapro_test()'s contract exactly:
        returns (ok, elapsed_seconds, output). ok=True means the patch held
        (the PoC ran without a crash signature)."""
        out_dir = self._dyninst_out_dir()
        so_container = os.path.join(out_dir, 'libpatch.so')
        # The functions to replace are the ones dyninst_patch() resolved from `locations` (a
        # macro-generated name becomes the symbols it expands to).
        try:
            with open(os.path.join(out_dir, 'resolved-locations.json')) as f:
                saved = json.load(f)
            if saved.get('input') == json.loads(json.dumps(locations)):
                locations = saved['resolved']
        except (OSError, ValueError):
            pass
        # dyninst_patch() leaves sync.tab/sync.funcs when it built the global-data sync wrappers;
        # those functions are then replaced by their wrapper (`old=new`), the others directly.
        sync_tab = os.path.join(out_dir, 'sync.tab')
        wrapped = set()
        if os.path.exists(sync_tab) and os.path.exists(os.path.join(out_dir, 'sync.funcs')):
            with open(os.path.join(out_dir, 'sync.funcs')) as f:
                wrapped = {line.strip() for line in f if line.strip()}
        so_func_pairs = [(so_container, f"{loc['function']}={_DYN_WRAP_PREFIX}{loc['function']}"
                          if loc['function'] in wrapped else loc['function']) for loc in locations]
        return _dyninst_run_mutator(
            self.container_id, self.binary_path, self.crash_input, so_func_pairs,
            timeout=timeout, project=self.project, sync_tab=sync_tab if wrapped else None,
        )


# ============================================================================
# Dyninst-based binary patching -- module-level helpers for
# ArvoValidator.dyninst_patch()/dyninst_test() above.
# ============================================================================
#
# Ported from arvo-san2patch (a separate prototype project) into MetaC
# proper, so `--mode dyninst` runs through the real do_dyninst() graph path
# (san2patch/san2patch/patching/graph/runpatch_graph.py) instead of a
# standalone script. dyninst_patch()/dyninst_test() mirror metapro_patch()/
# metapro_test()'s contract exactly: both return
# (ok: bool, elapsed_seconds: float, output: str).
#
# Unlike metapro (which installs call sites into whatever pv.build_test()
# already produced, via e9patch), dyninst_patch replays the *exact* compile
# invocation captured for each source file by dyninst-cc-wrapper.sh (see
# setup_dyninst() in checkout.py, which installs it as the container's real
# clang/clang++ before pv.setup()'s own real build runs -- so the log is
# populated for free, no separate rebuild needed) to compile a standalone
# libpatch.so per patch, then loads it into the running target via Dyninst
# (dyninst-poc/mutator_launch) and swaps in the patched function(s).
#
# self.work_dir is bind-mounted at an identical absolute path on host and
# inside the container (see docker.py's `-v host_mount_path:/root/project`,
# and metapro_patch()'s own host-side shutil.copy() of a path it also passes
# to `docker exec -w`) -- every path built under self.work_dir (via
# ArvoValidator._dyninst_out_dir()/_dyninst_pic_archive_path()) is valid,
# unchanged, on both sides, so no host<->container path translation is
# needed for any of it. MUTATOR_LAUNCH/DYNINSTAPI_RT_LIB/DYNINST_CC_LOG below
# are fixed, container-only paths instead (installed once per container by
# setup_dyninst(), outside the bind-mounted repo tree).

MUTATOR_LAUNCH = '/opt/dyninst-tool/mutator_launch'
DYNINSTAPI_RT_LIB = '/usr/local/lib/libdyninstAPI_RT.so'
DYNINST_CC_LOG = '/opt/dyninst-tool/cc-invocations.log'
# Parallelism for _build_pic_archive()'s compile replay. That replay is a full
# PIC recompile of the project and is by far the most expensive thing dyninst
# does -- the first dyninst_patch() of an ffmpeg bug spends ~1.8 h in it, against
# ~26 s for every later call in the same bug.
DYNINST_PIC_BUILD_JOBS = 10


# --- hunk parser: diff -> [(file, function), ...] ---
#
# Turns a unified diff (MetaC's cur-patch.diff, produced by
# branch_generate_patch()'s `git diff --no-index` -- see runpatch_graph.py)
# into an ordered, de-duplicated list of (file, function) pairs touched by
# it, via hunk-header context and content matching. A heuristic, not a
# parser -- double-check anything that looks off.

_DYNINST_HUNK_RE = re.compile(r'^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@\s*(.*)$')
_DYNINST_HUNK_NEW_START_RE = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)')
_DYNINST_FUNC_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(')

# Extensions _extract_patched_sites() will even try to resolve a function in. Anything else
# (observed: php-src's ext/opcache/jit/dynasm/dasm_x86.lua, a Lua script DynASM runs at build
# time to help generate the JIT's assembler templates -- never itself compiled by clang/clang++,
# so it never appears in cc-invocations.log) can never have a "captured compile invocation",
# which _dyninst_compile_and_link() treats as a hard failure for the *whole* patch -- even when
# the same diff also touches a real, resolvable .c function that extracted and compiled fine.
# Silently dropping the hunk here instead (same as an unresolvable hunk already is, a few lines
# down) lets those other locations still go through; a diff that turns out to touch nothing but
# a non-source file then falls through to the same "no patched function resolved" outcome a
# diff with no hunks at all already gets, rather than aborting the whole dyninst_patch() call.
_DYNINST_SOURCE_EXTENSIONS = {'.c', '.h', '.cc', '.cpp', '.cxx', '.C', '.hh', '.hpp', '.hxx', '.inc', '.inl'}

# php-src defines every exposed function/method through these macros
# (Zend/zend_API.h) instead of writing the real symbol name directly:
#   ZEND_FUNCTION(name)          -> void zif_<name>(...)
#   ZEND_METHOD(classname, name) -> void zim_<classname>_<name>(...)
# (PHP_FUNCTION/PHP_METHOD are plain aliases, same file.) A lexical scanner
# with no preprocessor would otherwise report the function's name as the
# literal macro name -- wrong at the binary level (Dyninst looks up
# zim_A_B, not "ZEND_METHOD") and ambiguous besides (many methods in one
# file all textually start with the same macro name).
_DYNINST_PHP_FUNC_MACROS = {'ZEND_FUNCTION': 'zif', 'PHP_FUNCTION': 'zif'}
_DYNINST_PHP_METHOD_MACROS = {'ZEND_METHOD': 'zim', 'PHP_METHOD': 'zim'}


def _dyninst_resolve_php_macro_name(name: str, candidate: str) -> Optional[str]:
    """If `name` is a known php-src function/method-definition macro found in
    `candidate` (the raw "NAME(args) {" signature text), return the real
    linkable symbol its expansion defines. Returns None for anything else,
    including a macro found with the wrong argument count (treated as not a
    match rather than guessed at)."""
    prefix = _DYNINST_PHP_FUNC_MACROS.get(name) or _DYNINST_PHP_METHOD_MACROS.get(name)
    if prefix is None:
        return None
    idx = candidate.find(name)
    if idx == -1:
        return None
    rest = candidate[idx + len(name):].lstrip()
    if not rest.startswith('('):
        return None
    depth = 0
    end = None
    for j, ch in enumerate(rest):
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                end = j
                break
    if end is None:
        return None
    args = [a.strip() for a in rest[1:end].split(',')]
    if name in _DYNINST_PHP_FUNC_MACROS and len(args) == 1 and args[0]:
        return f'zif_{args[0]}'
    if name in _DYNINST_PHP_METHOD_MACROS and len(args) == 2 and all(args):
        return f'zim_{args[0]}_{args[1]}'
    return None


def _dyninst_func_name_from_signature(candidate: str) -> Optional[str]:
    """_DYNINST_FUNC_RE's match on a signature/context text, with php-src's
    function macros expanded to their real symbol name. Returns None if no
    identifier-then-"(" is found at all."""
    fm = _DYNINST_FUNC_RE.search(candidate)
    if not fm:
        return None
    name = fm.group(1)
    return _dyninst_resolve_php_macro_name(name, candidate) or name


def _strip_c_comments_and_strings(text: str) -> str:
    """Blank out comments and string/char literal contents (so braces inside
    them don't confuse the brace-depth scan below), preserving line numbers
    exactly (block comments become the same count of newlines).

    Single-pass scanner, not independent regexes: a string like "://"
    contains "//", and a "//" line comment can contain a stray "'" --
    whichever construct (//, /* */, ", ') starts first at a given position
    must be consumed as a unit before looking further, or a later
    construct's delimiter gets misread as belonging to an earlier one and
    swallows real code."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ''
        if c == '/' and nxt == '/':
            j = text.find('\n', i)
            i = n if j == -1 else j
        elif c == '/' and nxt == '*':
            j = text.find('*/', i + 2)
            end = n if j == -1 else j + 2
            out.append('\n' * text[i:end].count('\n'))
            i = end
        elif c == '"' or c == "'":
            quote = c
            j = i + 1
            while j < n and text[j] != quote:
                j += 2 if text[j] == '\\' and j + 1 < n else 1
            j = min(j + 1, n)
            out.append(quote + quote)
            i = j
        else:
            out.append(c)
            i += 1
    return ''.join(out)


_DYNINST_PP_IF_RE = re.compile(r'^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$')
_DYNINST_CPLUSPLUS_RE = re.compile(r'\b__cplusplus\b')


def _blank_cplusplus_only_lines(clean_text: str) -> str:
    """Blank (keeping the newline, so line numbers do not move) every line that only a C++ compiler
    would see, i.e. that sits in an `#if`/`#ifdef` branch which requires `__cplusplus`.

    _parse_function_ranges() counts braces and knows nothing about the preprocessor, so a C++-only
    `extern "C" {` whose closing `}` sits far below (e.g. mruby's vm.c: the opener at the top and
    the closer at the very end, both under `#if ... defined(__cplusplus)`) leaves every function one
    level too deep and none of them is found. Those lines are never compiled for a C target anyway.

    Only branches that are certainly C++-only are blanked: `#ifdef __cplusplus`, or an `#if` whose
    condition mentions `__cplusplus` without `!` or `||`. The `#else` of `#ifndef __cplusplus` is
    C++-only too; the `#else` of a C++-only branch is the C branch and is kept.
    """
    out = []
    stack = []  # one [kind, blank_this_branch] per open #if; kind: 'cpp' | 'notcpp' | 'other'
    for line in clean_text.split('\n'):
        m = _DYNINST_PP_IF_RE.match(line)
        if m:
            d, cond = m.group(1), m.group(2)
            if d in ('if', 'ifdef', 'ifndef'):
                mentions = _DYNINST_CPLUSPLUS_RE.search(cond) is not None
                negated = d == 'ifndef' or '!' in cond
                if mentions and not negated and '||' not in cond:
                    stack.append(['cpp', True])
                elif mentions and negated and '||' not in cond and '&&' not in cond:
                    stack.append(['notcpp', False])
                else:
                    stack.append(['other', False])
            elif d == 'else' and stack:
                kind = stack[-1][0]
                stack[-1][1] = kind == 'notcpp'
            elif d == 'elif' and stack:
                stack[-1] = ['other', False]
            elif d == 'endif' and stack:
                stack.pop()
            out.append('')
            continue
        out.append('' if any(frame[1] for frame in stack) else line)
    return '\n'.join(out)


def _clean_for_parse(text: str) -> str:
    """What _parse_function_ranges() should be fed: comments and strings blanked, then the lines
    only a C++ compiler would see blanked too (see _blank_cplusplus_only_lines)."""
    return _blank_cplusplus_only_lines(_strip_c_comments_and_strings(text))


def _parse_function_ranges(clean_text: str) -> List[Tuple[str, int, int]]:
    """Return [(name, start_line, end_line)] for top-level C function
    definitions in clean_text (1-indexed, inclusive), found by tracking
    brace depth and treating a 0->1 transition as a function body start when
    the accumulated text since the last statement/blank line looks like a
    "name(...)" signature. clean_text must already have comments and
    string/char literals blanked out (see _strip_c_comments_and_strings) so
    their braces don't perturb the depth count."""
    lines = clean_text.split('\n')
    depth = 0
    functions = []
    sig_buf = []
    sig_start_line = None
    cur_name = None
    cur_start = None
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        opens = line.count('{')
        closes = line.count('}')
        if depth == 0 and opens > 0:
            prefix = line.split('{', 1)[0]
            candidate = ' '.join(sig_buf + [prefix])
            resolved_name = _dyninst_func_name_from_signature(candidate)
            if resolved_name and not candidate.rstrip().endswith(';'):
                cur_name = resolved_name
                # Use the signature's first line, not the brace-opening line,
                # as the range start -- a hunk that only touches a
                # multi-line parameter list (no body changes) must still
                # anchor inside this function, not fall in the gap before it.
                cur_start = sig_start_line if sig_start_line is not None else i
            else:
                cur_name = None
                cur_start = None
            sig_buf = []
            sig_start_line = None
        elif depth == 0:
            # A blank line between a complete `name(...)` signature and the `{` on the next
            # non-blank line does not end the signature: it is what a comment line (e.g. the
            # `// FIXME` San2Patch adds in front of a function's opening brace) turns into
            # once comments are blanked out.
            blank_before_brace = (
                stripped == '' and sig_buf and sig_buf[-1].rstrip().endswith(')') and
                next((l.strip() for l in lines[i:] if l.strip()), '').startswith('{'))
            if not blank_before_brace and (
                    stripped == '' or stripped.endswith(';') or stripped == '}' or stripped.startswith('#')):
                sig_buf = []
                sig_start_line = None
            else:
                if not sig_buf:
                    sig_start_line = i
                sig_buf.append(line)
        depth += opens - closes
        if depth <= 0 and cur_start is not None and (opens > 0 or closes > 0):
            if cur_name:
                functions.append((cur_name, cur_start, i))
            cur_name = None
            cur_start = None
            depth = 0  # guard against stray unmatched braces dragging depth negative
    return functions


def extract_patched_functions_from_diff(diff_path: str, source_root: str) -> List[Tuple[str, str]]:
    """Return an ordered, de-duplicated list of (file, function) pairs
    touched by `diff_path` -- see _extract_patched_sites(), which does the work."""
    pairs: List[Tuple[str, str]] = []
    for file_rel, func_name, _line, _start in _extract_patched_sites(diff_path, source_root):
        if (file_rel, func_name) not in pairs:
            pairs.append((file_rel, func_name))
    return pairs


def extract_patched_function_locations(diff_path: str, source_root: str) -> List[Dict]:
    """Like extract_patched_functions_from_diff(), but in the shape ArvoValidator.dyninst_patch()/
    dyninst_test() take: [{'file', 'function', 'patched_path', 'line'}, ...] with one entry per
    patched function *definition* (two functions that both read `FUNC` in a template file are two
    entries), `line` being a line of the hunk inside it in the patched file. The line is what lets
    dyninst_patch() turn a macro-generated name (`FUNC(vps)`) into the symbol(s) it really expands to."""
    return [{'file': file_rel, 'function': func_name, 'patched_path': os.path.join(source_root, file_rel),
             'line': line}
            for file_rel, func_name, line, _start in _extract_patched_sites(diff_path, source_root)]


def _extract_patched_sites(diff_path: str, source_root: str) -> List[Tuple[str, str, int, Optional[int]]]:
    """Return an ordered, de-duplicated list of (file, function, hunk_line, function_start_line)
    touched by `diff_path` (MetaC's cur-patch.diff), resolved against
    the source tree at `source_root` (self.source_dir).

    hunk_line / function_start_line are lines of the file at source_root, which is the *patched*
    tree in both callers: the hunk's own new-side start line, and the first line of the definition
    that contains it (None when no definition of that name contains it).

    For each hunk, resolves the enclosing C function by brace-depth scanning
    source_root/<file> around the hunk's first actually-removed ('-') line.
    The hunk header's own "nearest enclosing line" text (after the second
    "@@") is only a fallback -- it's unreliable for multi-line signatures
    and for hunks that touch macros/declarations instead of function
    bodies."""
    if not os.path.exists(diff_path):
        return []

    _range_cache = {}

    def _ranges_for(file_rel):
        if file_rel not in _range_cache:
            src_path = os.path.join(source_root, file_rel)
            if os.path.exists(src_path):
                with open(src_path, errors='replace') as sf:
                    text = sf.read()
                ranges = _parse_function_ranges(_clean_for_parse(text))
                _range_cache[file_rel] = (ranges, text.split('\n'))
            else:
                _range_cache[file_rel] = ([], [])
        return _range_cache[file_rel]

    with open(diff_path, errors='replace') as f:
        lines = f.readlines()

    cur_file = None
    results = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i].rstrip('\n')
        if line.startswith('+++ '):
            p = line[4:].strip()
            if p.startswith('b/'):
                p = p[2:]
            # Never a real compile unit dyninst could have a captured invocation for -- see
            # _DYNINST_SOURCE_EXTENSIONS' comment. cur_file stays None, so the `if m and
            # cur_file:` check below skips every hunk against this file same as if it weren't
            # a valid diff target at all.
            cur_file = p if os.path.splitext(p)[1] in _DYNINST_SOURCE_EXTENSIONS else None
            i += 1
            continue
        m = _DYNINST_HUNK_RE.match(line)
        if m and cur_file:
            old_start = int(m.group(1))
            context_text = m.group(2)
            old_line_cursor = old_start
            anchor_line = old_start
            found_removed = False
            needle = None
            removed_lines, added_lines = [], []
            j = i + 1
            while j < n and not lines[j].startswith('@@') and not lines[j].startswith('diff --git'):
                hl = lines[j]
                if hl.startswith('-') and not hl.startswith('---'):
                    if not found_removed:
                        anchor_line = old_line_cursor
                        needle = hl[1:].strip()
                        found_removed = True
                    removed_lines.append(hl[1:])
                    old_line_cursor += 1
                elif hl.startswith('+'):
                    added_lines.append(hl[1:])
                elif not hl.startswith('+'):
                    old_line_cursor += 1
                j += 1

            ranges, src_lines = _ranges_for(cur_file)

            # Hunks that change no code: a pure re-indentation/whitespace edit, or an edit inside a
            # multi-line `#define` body (the removed line ends in a backslash continuation). Neither
            # changes the behaviour of any function, and the second one used to be resolved to the
            # macro's own name (a "function" that does not exist in the binary).
            if removed_lines and added_lines and \
                    ''.join(''.join(removed_lines).split()) == ''.join(''.join(added_lines).split()):
                i = j
                continue
            if found_removed and 0 < anchor_line <= len(src_lines) and \
                    src_lines[anchor_line - 1].rstrip().endswith('\\'):
                i = j
                continue

            # Content-based match first: which function's body actually
            # contains the hunk's first removed line. Robust to any offset
            # between the diff's stated hunk line numbers and the checked-
            # out source. Only trusted when the needle is non-trivial and
            # uniquely identifies one function; otherwise falls through to
            # the anchor-line/context-text logic below.
            func_name = None
            if needle:
                matches = [name for name, s, e in ranges if needle in '\n'.join(src_lines[s - 1:e])]
                if len(matches) == 1:
                    func_name = matches[0]

            # A single-line needle can legitimately appear in more than one
            # function, leaving the content match ambiguous. When that
            # happens, trust the hunk header's own funcname *if* it names a
            # function that actually exists in this file.
            if func_name is None and context_text:
                resolved = _dyninst_func_name_from_signature(context_text)
                if resolved and any(resolved == name for name, _, _ in ranges):
                    func_name = resolved

            if func_name is None:
                for name, start, end in ranges:
                    if start <= anchor_line <= end:
                        func_name = name
                        break
            # No unvalidated final fallback to a bare context_text guess:
            # any name that check would produce was already tried, with the
            # same `any(... in ranges)` validation, above -- reaching here
            # means it already failed that check (or context_text was
            # empty), so retrying it unvalidated can only accept a name
            # proven not to be a real function body in this file.

            if func_name:
                new_start = _DYNINST_HUNK_NEW_START_RE.match(line)
                hunk_line = int(new_start.group(1)) if new_start else anchor_line
                func_start = next((st for name, st, en in ranges
                                   if name == func_name and st <= hunk_line <= en), None)
                site = (cur_file, func_name, hunk_line, func_start)
                if not any(r[:2] == site[:2] and r[3] == site[3] for r in results):
                    results.append(site)
            i = j
            continue
        i += 1
    return results


# --- extract-libpatch: build a minimal standalone .c for one file's patched
# function(s), instead of recompiling the whole file it lives in. ---
#
# Extracts the target function's body plus the transitive closure of any
# *static* (file-local) helper functions it calls in the same source file
# (those can't be resolved by linking against the project's PIC archive,
# since `static` = internal linkage -- the only way to get their code into
# the standalone .so is to include their source directly). Non-static
# dependencies are left alone: they resolve normally at link time against
# the existing PIC archive.
#
# Built by taking the WHOLE original file and deleting only the *bodies* of
# functions outside the needed closure -- not by hand-picking a "leading
# #include block" -- so every other top-level line (comments, #include,
# #define, #if/#else/#endif, struct/typedef/global declarations) survives
# verbatim, in its original position and preprocessor nesting (a #define
# can legitimately sit between two function definitions, not just at the
# top of the file).

_DYNINST_C_KEYWORDS = {
    'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'default', 'break',
    'continue', 'return', 'goto', 'sizeof', 'typedef', 'struct', 'union',
    'enum', 'static', 'extern', 'const', 'volatile', 'void', 'char', 'short',
    'int', 'long', 'float', 'double', 'signed', 'unsigned', 'inline',
    'register', 'auto', 'restrict', 'NULL', 'true', 'false', 'bool',
    'this', 'class', 'public', 'private', 'protected', 'namespace',
    'template', 'typename', 'new', 'delete', 'virtual', 'override',
}


def _dyninst_function_map(text: str) -> Dict[str, Dict]:
    """name -> {start, end, text, static} for every top-level C function
    definition in `text` (1-indexed inclusive line range)."""
    clean = _clean_for_parse(text)
    funcs = _parse_function_ranges(clean)
    lines = text.split('\n')
    out = {}
    for name, s, e in funcs:
        body_text = '\n'.join(lines[s - 1:e])
        sig_part = body_text.split('{', 1)[0]
        is_static = re.search(r'\bstatic\b', sig_part) is not None
        out[name] = {'start': s, 'end': e, 'text': body_text, 'static': is_static}
    return out


def build_libpatch(src_path: str, func_names) -> Tuple[str, List[str]]:
    """Returns (libpatch_source: str, included_functions: list[str]).

    func_names: a single function name, or a list of them -- when a file has
    more than one patched location, seeding the closure walk with all of
    them at once and de-duplicating produces ONE combined extraction instead
    of one per function, so the caller compiles+links this file exactly
    once regardless of how many of its functions are patched."""
    if isinstance(func_names, str):
        func_names = [func_names]

    with open(src_path, 'r', errors='replace') as f:
        text = f.read()

    func_map = _dyninst_function_map(text)
    for func_name in func_names:
        if func_name not in func_map:
            raise ValueError(f"function '{func_name}' not found in {src_path}")

    needed = []
    seen = set()
    queue = list(func_names)
    while queue:
        name = queue.pop(0)
        if name in seen:
            continue
        seen.add(name)
        if name not in func_map:
            continue
        needed.append(name)
        ids = set(re.findall(r'\b[A-Za-z_]\w*\b', func_map[name]['text'])) - _DYNINST_C_KEYWORDS
        for ident in sorted(ids):
            if ident == name:
                continue
            if ident in func_map and func_map[ident]['static'] and ident not in seen:
                queue.append(ident)

    needed_set = set(needed)
    target_set = set(func_names)

    # Mark every line belonging to a function we're NOT keeping, so the
    # reconstruction below can drop just those bodies and keep everything
    # else exactly where and as it was in the original file.
    lines = text.split('\n')
    drop = [False] * (len(lines) + 2)
    for name, info in func_map.items():
        if name not in needed_set:
            for ln in range(info['start'], info['end'] + 1):
                drop[ln] = True

    # A requested target that's `static` has no caller left in this TU
    # (whatever called it in the original file wasn't extracted -- it lives
    # in the process Dyninst is patching, not in this .c) -- clang/gcc treat
    # that as a plain unused static function and drop it entirely even at
    # -O0. __attribute__((used)) is the standard way to keep an internal-
    # linkage symbol emitted regardless -- needed only for the requested
    # targets themselves; helper functions pulled in by the closure are, by
    # construction, referenced from within it.
    attr_before = {func_map[name]['start'] for name in needed
                   if name in target_set and func_map[name]['static']}

    body_lines = []
    for i, line in enumerate(lines, start=1):
        if drop[i]:
            continue
        if i in attr_before:
            body_lines.append('__attribute__((used))')
        body_lines.append(line)

    out = [
        f"/* Auto-generated by validator.py's build_libpatch(): {', '.join(func_names)} extracted from",
        f" * {src_path}: the whole file, minus the bodies of every function",
        f" * outside {', '.join(func_names)}'s own static-dependency closure. */",
    ]
    out.extend(body_lines)

    return '\n'.join(out), needed


# --- compile-invocation log + PIC archive ---

_DYNINST_LINK_CONFLICTS_WITH_SHARED = {'-no-pie', '-pie'}
_DYNINST_HEADER_EXTS = ('.h', '.hpp', '.hxx', '.hh', '.H')


def _parse_cc_log(log_text: str) -> List[Dict]:
    """Same format dyninst-cc-wrapper.sh writes."""
    invocations = []
    cur = None
    for line in log_text.splitlines():
        if line == '==CC_INVOCATION==':
            cur = {'cwd': '', 'argv0': '', 'args': []}
        elif line == '==END==':
            if cur is not None:
                invocations.append(cur)
            cur = None
        elif cur is not None and line.startswith('CWD: '):
            cur['cwd'] = line[len('CWD: '):]
        elif cur is not None and line.startswith('ARGV0: '):
            cur['argv0'] = line[len('ARGV0: '):]
        elif cur is not None and line.startswith('ARG: '):
            cur['args'].append(line[len('ARG: '):])
    return invocations


def _find_invocation_for_source(invocations: List[Dict], source_basename: str, project_root: str) -> Optional[Dict]:
    """Last -c invocation that actually compiles source_basename within
    project_root (a container path, e.g. /src/<project>)."""
    matches = []
    for inv in invocations:
        if inv['cwd'] != project_root and not inv['cwd'].startswith(project_root + '/'):
            continue
        args = inv['args']
        if '-c' not in args:
            continue
        for arg in args:
            if not arg.startswith('-') and os.path.basename(arg) == source_basename:
                matches.append(inv)
                break
    return matches[-1] if matches else None


def _strip_c_and_o(args: List[str], source_basename: str) -> List[str]:
    """Remove -c, the -o/<path> pair, the source-file arg, and anything that
    would fight with the -shared link we're about to do instead."""
    out = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg == '-c':
            continue
        if arg == '-o':
            skip_next = True
            continue
        if arg.startswith('-o') and len(arg) > 2:
            continue
        if not arg.startswith('-') and os.path.basename(arg) == source_basename:
            continue
        if arg in _DYNINST_LINK_CONFLICTS_WITH_SHARED:
            continue
        out.append(arg)
    return out


def _find_invocation_via_includer(container_id: str, invocations: List[Dict], header_basename: str,
                                   project_root_container: str):
    """A header (or a .c *template* that another .c file #includes, e.g. ffmpeg's
    mpv_reconstruct_mb_template.c) is never compiled standalone in a real build, so
    the cc log has no entry naming it directly. Find a .c/.cpp file elsewhere in the
    project that #includes it and return THAT file's captured invocation, its
    basename and its path: sibling files in one project share the same build's
    -I/-D flags almost always. For a header the flags are all that is used (the
    header's own extracted text is what gets compiled); for a .c template the
    including file itself is what gets compiled, since the template alone is not a
    translation unit."""
    if not project_root_container:
        return None, None, None
    pattern = rf'#\s*include\s*["<][^">]*{re.escape(header_basename)}[">]'
    res = sp.run(['docker', 'exec', container_id, 'grep', '-rlE', pattern, project_root_container],
                 stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
    if res.returncode not in (0, 1) or not res.stdout.strip():
        return None, None, None
    for includer in res.stdout.splitlines():
        includer_basename = os.path.basename(includer.strip())
        if os.path.splitext(includer_basename)[1] not in ('.c', '.cc', '.cpp', '.cxx', '.C'):
            continue
        inv = _find_invocation_for_source(invocations, includer_basename, project_root_container)
        if inv is not None:
            return inv, includer_basename, includer.strip()
    return None, None, None


def _shared_link_libs_only(container_id: str, flags: List[str]) -> List[str]:
    """Keep only the library flags that a *shared object* can actually link: those with a shared
    library (lib<name>.so, or a versioned lib<name>.so.N by full path) in the -L directories or the
    system ones. A static lib (lib<name>.a) is not usable: it is not PIC, and linking it makes
    the whole `-shared` link fail ("relocation ... can not be used when making a shared object").
    Project-internal libraries (relative -L dirs such as -Llibavcodec) are dropped for the same reason.
    Libraries are wrapped in --as-needed so only the ones the patch's code really uses become
    dependencies of libpatch.so."""
    dirs = [f[2:] for f in flags if f.startswith('-L') and f[2:].startswith('/')]
    names = [f[2:] for f in flags if f.startswith('-l')]
    keep = [f for f in flags if f.startswith('/') and f.endswith('.so')]
    search = ' '.join(shlex.quote(d) for d in dirs + ['/usr/lib/x86_64-linux-gnu', '/lib/x86_64-linux-gnu',
                                                        '/usr/lib', '/usr/local/lib'])
    script = (f'for n in {" ".join(shlex.quote(n) for n in names)}; do for d in {search}; do '
              f'if [ -e "$d/lib$n.so" ]; then echo "$d/lib$n.so"; break; fi; '
              f'p=$(ls "$d"/lib$n.so.* 2>/dev/null | head -1); if [ -n "$p" ]; then echo "$p"; break; fi; done; done')
    res = sp.run(['docker', 'exec', container_id, 'bash', '-c', script], stdout=sp.PIPE, stderr=sp.DEVNULL, text=True)
    resolved = res.stdout.split() if res.returncode == 0 else []
    libs = keep + resolved
    if not libs:
        return []
    # Full paths, not -l<name>: with the project's own static-lib directories in -L, `-lvpx` would
    # find the non-PIC libvpx.a there before it ever looks at a shared libvpx.so.
    return ['-Wl,--as-needed'] + libs + ['-Wl,--no-as-needed']


def _find_link_invocation_for_binary(invocations: List[Dict], target_basename: str, project_root: str) -> Optional[Dict]:
    """Last non-'-c' invocation in this project whose '-o <name>' names the
    fuzz target binary we're about to patch -- the real final link that
    produced it, as opposed to any of the many '-c' compiles that produced
    its individual objects."""
    matches = []
    for inv in invocations:
        if inv['cwd'] != project_root and not inv['cwd'].startswith(project_root + '/'):
            continue
        args = inv['args']
        if '-c' in args or '-o' not in args:
            continue
        o_idx = args.index('-o')
        if o_idx + 1 < len(args) and os.path.basename(args[o_idx + 1]) == target_basename:
            matches.append(inv)
    return matches[-1] if matches else None


def _extract_extra_link_libs(link_inv_args: List[str], project_root_container: str) -> List[str]:
    """Pull only genuine third-party system library flags/paths out of the
    real link invocation that built the target binary: -l*/-L* flags, and
    absolute .so/.a paths outside the project's own source tree. Deliberately
    excludes the project's own .a/.o build output (already covered, in
    carefully-trimmed form, by our own extracted objects + PIC archive) and
    the libFuzzer driver archive (the already-running target process is the
    one thing supplying main()/LLVMFuzzerTestOneInput here, not this .so)."""
    out = []
    skip_next = False
    for arg in link_inv_args:
        if skip_next:
            skip_next = False
            continue
        if arg == '-o':
            skip_next = True
            continue
        if arg.startswith('-l') or arg.startswith('-L'):
            out.append(arg)
        elif (arg.startswith('/') and arg.endswith(('.so', '.a'))
              and not (project_root_container and arg.startswith(project_root_container))
              and 'libfuzzer' not in arg.lower() and 'libfuzzingengine' not in arg.lower()):
            out.append(arg)
    return out


def _defined_symbols(container_id: str, obj_container: str) -> Tuple[bool, set]:
    """(ok, {symbol names DEFINED in this object}) -- everything `nm -P`
    reports with a type other than 'U' (undefined) or 'w'/'v' (weak/
    undefined weak), i.e. every symbol this .o itself provides a body/
    storage for, functions and file-scope data alike."""
    res = sp.run(['docker', 'exec', container_id, 'nm', '-P', obj_container],
                 stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
    if res.returncode != 0:
        return False, set()
    names = set()
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] not in ('U', 'w', 'v'):
            names.add(parts[0])
    return True, names


def _pic_archive_trim(container_id: str, pic_archive_container: str, out_dir_container: str,
                       full_exclude_members: List[str], strip_symbols_by_member: Dict[str, set]) -> str:
    """Trimmed copy of the PIC archive, so it can be linked alongside
    freshly-compiled replacements without colliding.

    The archive is built once per (bug, output_dir) by replaying every
    captured compile of the whole project (see _build_pic_archive), including
    the very files the patched functions were extracted from -- both that
    archive member and the freshly-compiled object then define the same
    symbol name. Which one Dyninst's findFunction/findVariable actually
    resolves to at runtime is not guaranteed consistent between runs, so the
    archive's copy of anything we've redefined needs to be gone, not just
    "usually shadowed".

    Two different levels of "gone", by why each file is here:
      full_exclude_members: archive members (see _pic_member_name) of the files that fell back to
        whole-file compilation.
        Our own object already has 100% of that file's content, so the whole
        archive member is redundant -- `ar d` it.
      strip_symbols_by_member: {archive member: {symbol, ...}} for files
        where extraction succeeded -- our object only has the extracted
        function(s) plus their static closure, NOT the rest of that file.
        Deleting the whole archive member here would also delete symbols we
        never redefined and still need. Instead, extract just that one
        archive member and `objcopy --redefine-sym` the names we've
        redefined to a shadowed alias, then put the member back --
        everything else in the file stays linkable from the archive as
        before. --redefine-sym rather than --strip-symbol: the archive's own
        copy of the function usually still has intra-file relocations
        pointing at it -- objcopy refuses to strip a symbol a relocation
        still names, but redefining it updates those relocations to the new
        name instead.

    ar's `d` only removes the first match; a member can appear more than
    once in the archive (two capture-time compiles of the same file) -- this
    loops per file until none remain."""
    trimmed = os.path.join(out_dir_container, 'libpic_trimmed.a')
    workdir = os.path.join(out_dir_container, 'artrim_work')
    cmds = [f'mkdir -p {shlex.quote(workdir)}',
            f'cp {shlex.quote(pic_archive_container)} {shlex.quote(trimmed)}']

    def _delete_all(member):
        return (f'while ar t {shlex.quote(trimmed)} | grep -qx {shlex.quote(member)}; do '
                f'ar d {shlex.quote(trimmed)} {shlex.quote(member)}; done')

    for member in full_exclude_members:
        cmds.append(_delete_all(member))

    for member, symbols in strip_symbols_by_member.items():
        if not symbols:
            continue
        extracted = os.path.join(workdir, member)
        redefine_flags = ' '.join(f'--redefine-sym={shlex.quote(s)}={shlex.quote("__pic_archive_shadowed_" + s)}'
                                   for s in symbols)
        cmds.append(
            f'if ar t {shlex.quote(trimmed)} | grep -qx {shlex.quote(member)}; then '
            f'(cd {shlex.quote(workdir)} && ar x {shlex.quote(trimmed)} {shlex.quote(member)}) && '
            f'objcopy {redefine_flags} {shlex.quote(extracted)} && '
            f'{_delete_all(member)} && '
            f'ar r {shlex.quote(trimmed)} {shlex.quote(extracted)}; '
            f'fi'
        )

    # A big project (observed: php-src's Zend engine) can need enough archive members trimmed
    # that joining every command into one `bash -c` argument overflows the kernel's execve()
    # argument+environment size limit (ARG_MAX, ~2MB) -- 'OSError: [Errno 7] Argument list too
    # long'. Writing the same commands to a script file sidesteps that entirely (same fix, same
    # reason, as _build_pic_archive()'s script_path a bit above -- out_dir_container is a path
    # under ArvoValidator.work_dir, identical on host and in-container, so plain Python I/O here
    # needs no docker cp).
    script_path = os.path.join(out_dir_container, 'trim-pic-archive.sh')
    with open(script_path, 'w') as f:
        f.write('#!/bin/bash\nset -e\n' + '\n'.join(cmds) + '\n')
    res = sp.run(['docker', 'exec', container_id, 'bash', script_path], stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
    if res.returncode != 0:
        raise RuntimeError(f'failed to trim PIC archive: {res.stdout}')
    return trimmed


def _pic_object_path(inv: Dict) -> Optional[str]:
    """Absolute path of the .picobj that _pic_recompile_cmd() makes for this captured compile
    (its original -o, resolved against the invocation's cwd, plus '.picobj'); None without a -o."""
    args = inv['args']
    orig_o = None
    for i, a in enumerate(args):
        if a == '-o' and i + 1 < len(args):
            orig_o = args[i + 1]
        elif a.startswith('-o') and len(a) > 2:
            orig_o = a[2:]
    if orig_o is None:
        return None
    return os.path.normpath(os.path.join(inv['cwd'], orig_o + '.picobj'))


def _pic_member_name(path: str, project_root: str) -> str:
    """Name a PIC object goes by in libpic.a. Archive members are keyed by name alone, so the bare
    file name is not enough: a project can hold several objects with the same name in different
    directories (ffmpeg: libavcodec/qpeldsp.o next to libavcodec/x86/qpeldsp.o), and `ar` lets
    the later one silently replace the earlier -- losing e.g. every ff_*_old_c symbol the C object
    defined. The path relative to the project root, with '/' turned into '__', is unique."""
    rel = os.path.relpath(path, project_root)
    return rel.replace(os.sep, '__')


def _pic_recompile_cmd(inv: Dict) -> Optional[str]:
    """Same invocation (cwd/argv0/flags/source), minus its original -o, plus
    -fPIC -DPIC -fvisibility=hidden and a new -o ending in .picobj (so it
    never collides with the original non-PIC object the real build produced).

    -DPIC: some projects (ffmpeg's x86 SIMD headers) gate their own PIC-safe
    addressing macros on `#if defined(PIC)`, not on how the file was
    actually compiled -- replaying with -fPIC alone still emits non-PIC-safe
    relocations for globals touched from hand-written inline asm.
    -fvisibility=hidden: without it, ld refuses a PC32 relocation against a
    preemptible (default-visibility) symbol in a shared object even though
    -fPIC is already on. Since every .o in this archive ends up combined
    into one final .so together with the patched file, hiding their
    internal symbols is safe."""
    args = inv['args']
    new_args = []
    skip_next = False
    orig_o = None
    for i, a in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if a == '-o':
            if i + 1 < len(args):
                orig_o = args[i + 1]
            skip_next = True
            continue
        if a.startswith('-o') and len(a) > 2:
            orig_o = a[2:]
            continue
        new_args.append(a)
    if orig_o is None:
        return None
    # This tool's own compiles are logged by the wrapper too (an earlier archive build's replays,
    # and every libpatch compile). Replaying those would make `x.o.picobj.picobj` copies of objects
    # already in the archive and objects of the patches themselves.
    if orig_o.endswith('.picobj') or '/dyninst-out/' in os.path.join(inv['cwd'], orig_o) or \
            os.path.basename(orig_o).startswith('libpatch_'):
        return None
    pic_o = orig_o + '.picobj'
    cmd = [inv['argv0']] + new_args + ['-fPIC', '-DPIC', '-fvisibility=hidden', '-o', pic_o]
    cmd_str = ' '.join(shlex.quote(c) for c in cmd)
    return f'cd {shlex.quote(inv["cwd"])} && {cmd_str}'


def _build_pic_archive(container_id: str, cc_invocations: List[Dict], project_root_container: str,
                        archive_path: str, script_path: str,
                        jobs: int = DYNINST_PIC_BUILD_JOBS) -> bool:
    """Build a project-wide, PIC-recompiled static archive by replaying every
    captured compile invocation with -fPIC added, so build_libpatch()'s
    standalone per-file .so can link against it to resolve cross-file
    references.

    Why this is needed: ARVO/OSS-Fuzz project builds are typically
    --disable-shared, so no PIC object of the project exists anywhere.
    Without one, a standalone .so for one patched file can't resolve calls
    into the rest of the project -- not even by exporting symbols from the
    target executable, because some cross-file symbols have ELF hidden
    visibility, which by definition can never be resolved from outside the
    shared object/archive that defines it. Linking against a PIC archive of
    the project's own code resolves everything (hidden or not) at build time
    instead, inside our own .so -- no runtime dependency on the target
    process for symbol resolution.

    archive_path/script_path must be paths under ArvoValidator.work_dir
    (identical on host and in-container, see the module docstring above) --
    the script is written via plain Python I/O here, then run via
    `docker exec ... bash <that same path>`, no docker cp needed."""
    compiles = [inv for inv in cc_invocations if '-c' in inv['args']]
    if not compiles:
        return False

    cmds = []
    for inv in compiles:
        c = _pic_recompile_cmd(inv)
        if c:
            cmds.append(c)
    if not cmds:
        return False

    os.makedirs(os.path.dirname(archive_path), exist_ok=True)
    stage_dir = os.path.join(os.path.dirname(archive_path), 'pic-members')
    # A `force` rebuild (archive_path missing/stale) must start from nothing:
    # `ar rcs` replacing a same-named member doesn't guarantee which
    # occurrence it replaces once the archive already has more than one
    # member sharing that name.
    if os.path.exists(archive_path):
        os.remove(archive_path)

    # Some logged invocations are transient configure-time probe compiles
    # whose source no longer exists post-build -- guarded per-file below
    # rather than aborting the whole replay for them.
    #
    # Hand-written x86 SIMD in some projects (observed: ffmpeg) lives in
    # standalone .asm files assembled by nasm, never gcc/g++/clang -- our
    # wrapper only ever sees those aliases, so these compiles are invisible
    # to the cc log and never get PIC-recompiled above. The plain .o sitting
    # next to each .asm source is NOT link-safe for a shared object: PIC is
    # opt-in for x86 nasm output, via -DPIC, which only the project's own
    # --enable-pic configure flag would have added. Rather than accept the
    # non-PIC object (which the final -shared link then rejects), reassemble
    # each .asm with nasm -DPIC ourselves. Falls back to the plain .o only
    # if reassembly itself fails.
    guarded_cmds = [f'{{ {c} ; }} || echo "[build-pic-archive] skip (failed): {c}"' for c in cmds]
    script = (
        '#!/bin/bash\n' +
        # Start from no .picobj at all: files left by an earlier archive build (of this tree) would
        # otherwise be picked up by the `find` below as if they were fresh compiles.
        f"find '{project_root_container}' -name '*.picobj' -delete\n" +
        # Replay the captured compiles -j DYNINST_PIC_BUILD_JOBS at a time rather than
        # one per script line: this is the bulk of the archive build and every command
        # writes its own `-o <src>.o.picobj`, so they cannot collide. The commands go
        # through a quoted heredoc so nothing in them is expanded here, and
        # `bash -c 'eval "$0"'` takes a whole line as a single argument -- which keeps
        # their quoting intact and avoids xargs -I's replace-string length limit (the
        # captured ffmpeg compile lines are long enough to hit it).
        f"cat > /tmp/piccmds.$$ <<'__PIC_CMDS_EOF__'\n" +
        '\n'.join(guarded_cmds) + '\n' +
        "__PIC_CMDS_EOF__\n" +
        f"xargs -a /tmp/piccmds.$$ -d '\\n' -P {jobs} -n 1 bash -c 'eval \"$0\"'\n" +
        f"find '{project_root_container}' -name '*.picobj' > /tmp/picobjs.$$\n"
        # Objects are told apart by their full path (see _pic_member_name), never by basename:
        # ffmpeg has libavcodec/qpeldsp.o (C) and libavcodec/x86/qpeldsp.o (nasm) side by side
        # and both are needed.
        f"PCFG=''; [ -f '{project_root_container}/config.asm' ] && PCFG='-P{project_root_container}/config.asm'\n"
        f"find '{project_root_container}' -name '*.asm' | while read -r asm; do\n"
        f"    dir=$(dirname \"$asm\")\n"
        f"    picobj=\"${{asm%.asm}}.o.picobj\"\n"
        f"    if nasm -f elf64 -g -F dwarf -DPIC -I'{project_root_container}/' -I\"$dir/\" $PCFG -o \"$picobj\" \"$asm\" 2>&1; then\n"
        f"        grep -qxF \"$picobj\" /tmp/picobjs.$$ || echo \"$picobj\" >> /tmp/picobjs.$$\n"
        f"    else\n"
        f"        echo \"[build-pic-archive] asm reassemble (-DPIC) failed, falling back to non-PIC original: $asm\"\n"
        f"        o=\"${{asm%.asm}}.o\"\n"
        f"        [ -f \"$o\" ] && echo \"$o\" >> /tmp/picobjs.$$\n"
        f"    fi\n"
        f"done\n"
        # Fallback for C/C++ sources that never showed up in the cc log at
        # all (root cause not pinned down for a handful of ffmpeg files
        # despite an identical wrapper/PATH setup to every captured file).
        # If the *original* build already produced a .o for a source with no
        # .picobj here, grab that .o directly rather than leaving the
        # symbols it defines permanently missing -- most such projects
        # already carry -fPIC project-wide independent of our env.
        f"for ext in c cc cpp; do\n"
        f"  find '{project_root_container}' -name \"*.$ext\" | while read -r src; do\n"
        f"    o=\"${{src%.$ext}}.o\"\n"
        f"    [ -f \"$o\" ] && [ ! -f \"$o.picobj\" ] || continue\n"
        f"    echo \"$o\" >> /tmp/picobjs.$$\n"
        f"  done\n"
        f"done\n"
        # Stage every object under its unique member name, then archive the staged names.
        f"STAGE='{stage_dir}'; rm -rf \"$STAGE\"; mkdir -p \"$STAGE\"\n"
        f"sort -u /tmp/picobjs.$$ | while read -r f; do\n"
        f"    rel=\"${{f#'{project_root_container}'/}}\"\n"
        f"    name=\"${{rel//\\//__}}\"\n"
        f"    ln -f \"$f\" \"$STAGE/$name\" 2>/dev/null || cp \"$f\" \"$STAGE/$name\"\n"
        f"    echo \"$STAGE/$name\"\n"
        f"done > /tmp/picstaged.$$\n"
        f"xargs -a /tmp/picstaged.$$ ar rcs '{archive_path}'\n"
        f"rm -rf \"$STAGE\" /tmp/picobjs.$$ /tmp/picstaged.$$ /tmp/piccmds.$$\n"
    )

    with open(script_path, 'w') as f:
        f.write(script)

    res = sp.run(['docker', 'exec', container_id, 'bash', script_path], stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
    if res.returncode != 0 or not os.path.exists(archive_path):
        return False
    # An `ar rcs` with zero members still produces a valid-looking 8-byte
    # archive (just the "!<arch>\n" magic) -- a wrong project_root_container
    # (the .picobj files land under wherever cc_invocations.log's own cwd
    # entries point, which is NOT necessarily project_root_container; only
    # the *fallback* find-based passes below search under it) can silently
    # produce exactly this, and since dyninst_patch()'s caller only checks
    # os.path.exists() before reusing the cache, a first bad build would
    # otherwise poison every later attempt for this bug until the file is
    # deleted by hand. Treating "no members" as a failure here instead means
    # a subsequent call (e.g. after fixing whatever caused zero .picobj
    # files to be found) naturally gets a fresh, real rebuild.
    if os.path.getsize(archive_path) <= 8:
        os.remove(archive_path)
        return False
    return True


# --- Keeping the patched code's file-scope data in step with the running program -------------------
#
# libpatch.so is a recompiled copy of (part of) the patched file plus the PIC archive, so every
# writable file-scope variable those objects define exists TWICE in the process: the program's own
# copy, which its normal code initialises and updates, and libpatch.so's copy, which nothing ever
# touches. A patched function reading a table the program built at run time (ffmpeg's `static VLC
# sf_vlc`, php's TLS contexts, ...) then sees zeroes. Copying the values once when libpatch.so is
# loaded cannot help -- the process is still suspended before main() at that point, so nothing has
# been initialised yet -- so the copies are kept in step around every call of a patched function:
# each replaced function is entered through a small assembly wrapper (signature independent: it saves
# and restores every argument register and leaves the stack arguments alone) that copies program ->
# libpatch.so before the body runs and, through a hijacked return address, libpatch.so -> program
# when it returns (see _DYN_RUNTIME_C). Which variables to copy is worked out from the two ELF symbol
# tables (_build_sync_tab): every writable data symbol libpatch.so defines that has a same-named,
# same-sized counterpart in the target binary.

_DYN_WRAP_PREFIX = '__dyn_wrap_'

_DYN_RUNTIME_C = r"""#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

extern void __dyn_exit_tramp(void);
void __dyn_enter(void **slot);
void *__dyn_leave(char *rsp_after_ret);

/* sync_out: whether this entry is copied back to the program on the way out. Off for a global
   whose type holds a pointer -- the copy is a raw byte copy, and writing one of those back would
   duplicate a heap address into the program's own copy; whichever side later frees and replaces
   it, the next sync-in could then hand the *other* side a stale value it frees again. Reading the
   program's current value in (sync_in runs unconditionally) is what a patched function that reads
   a global initialised at runtime needs and stays safe either way -- it is specifically writing a
   pointer field *back* that creates the second, dangling reference. See _build_sync_tab(). */
struct dyn_ent { char *so; char *exe; size_t n; int sync_out; };
static struct dyn_ent *__dyn_tab;
static size_t __dyn_ntab;
static int __dyn_inited;
#define DYN_MAX_DEPTH 512
static void *__dyn_slots[DYN_MAX_DEPTH];
static void *__dyn_rets[DYN_MAX_DEPTH];
static int __dyn_depth;

/* Plain copy loop, not memcpy(): under ASan a global's symbol size includes its redzone, and
   ASan's memcpy interceptor would report reading past the variable. This file is built with
   -fno-sanitize=all -fno-builtin so nothing turns the loop back into a memcpy call. */
static void __dyn_copy(char *dst, const char *src, size_t n) {
  size_t k = 0;
  if ((((size_t)dst | (size_t)src) & 7) == 0)
    for (; k + 8 <= n; k += 8) *(unsigned long *)(dst + k) = *(const unsigned long *)(src + k);
  for (; k < n; k++) dst[k] = src[k];
}

static int __dyn_first_phdr(struct dl_phdr_info *info, size_t size, void *data) {
  *(ElfW(Addr) *)data = info->dlpi_addr;
  return 1;
}

static void __dyn_init(void) {
  const char *path = getenv("DYN_SYNC_TAB");
  Dl_info di;
  FILE *f;
  unsigned long so_off, exe_va, sz;
  int sync_out;
  size_t cap = 0;
  ElfW(Addr) bias = 0;
  __dyn_inited = 1;
  if (!path || !(f = fopen(path, "r"))) return;
  if (!dladdr((void *)__dyn_enter, &di)) { fclose(f); return; }
  dl_iterate_phdr(__dyn_first_phdr, &bias);
  while (fscanf(f, "%lx %lx %lu %d", &so_off, &exe_va, &sz, &sync_out) == 4) {
    if (__dyn_ntab == cap) {
      cap = cap ? cap * 2 : 256;
      __dyn_tab = (struct dyn_ent *)realloc(__dyn_tab, cap * sizeof(struct dyn_ent));
      if (!__dyn_tab) { __dyn_ntab = 0; fclose(f); return; }
    }
    __dyn_tab[__dyn_ntab].so = (char *)di.dli_fbase + so_off;
    __dyn_tab[__dyn_ntab].exe = (char *)(bias + exe_va);
    __dyn_tab[__dyn_ntab].n = sz;
    __dyn_tab[__dyn_ntab].sync_out = sync_out;
    __dyn_ntab++;
  }
  fclose(f);
}

static void __dyn_sync_in(void) {
  for (size_t i = 0; i < __dyn_ntab; i++) __dyn_copy(__dyn_tab[i].so, __dyn_tab[i].exe, __dyn_tab[i].n);
}
static void __dyn_sync_out(void) {
  for (size_t i = 0; i < __dyn_ntab; i++)
    if (__dyn_tab[i].sync_out) __dyn_copy(__dyn_tab[i].exe, __dyn_tab[i].so, __dyn_tab[i].n);
}

void __dyn_enter(void **slot) {
  if (!__dyn_inited) __dyn_init();
  /* A wrapped call that was left by longjmp() (mruby raises exceptions that way) never reached its
     exit trampoline. Its frame lies below (at a lower address than) the frame we are being called
     from, so such entries are dead: drop them, and if that empties the stack write the dead call's
     state back to the program first, as its exit would have. */
  int stale = 0;
  while (__dyn_depth > 0 && __dyn_depth <= DYN_MAX_DEPTH && __dyn_slots[__dyn_depth - 1] < (void *)slot) {
    __dyn_depth--;
    stale = 1;
  }
  if (stale && __dyn_depth == 0) __dyn_sync_out();
  if (__dyn_depth >= DYN_MAX_DEPTH) return;
  if (__dyn_depth == 0) __dyn_sync_in();
  __dyn_slots[__dyn_depth] = (void *)slot;
  __dyn_rets[__dyn_depth] = *slot;
  __dyn_depth++;
  *slot = (void *)__dyn_exit_tramp;
}

void *__dyn_leave(char *rsp_after_ret) {
  void *slot = (void *)(rsp_after_ret - 8);
  int i = __dyn_depth - 1;
  while (i > 0 && __dyn_slots[i] != slot) i--;
  void *ret = __dyn_rets[i];
  __dyn_depth = i;
  if (__dyn_depth == 0) __dyn_sync_out();
  return ret;
}

/* Every wrapped function returns here (its return address was replaced in __dyn_enter). Only the
   registers a return value can live in are preserved. */
__asm__(
".text\n"
".globl __dyn_exit_tramp\n"
".type __dyn_exit_tramp,@function\n"
"__dyn_exit_tramp:\n"
"    subq $64, %rsp\n"
"    movq %rax, 0(%rsp)\n"
"    movq %rdx, 8(%rsp)\n"
"    movdqu %xmm0, 16(%rsp)\n"
"    movdqu %xmm1, 32(%rsp)\n"
"    leaq 64(%rsp), %rdi\n"
"    call __dyn_leave@PLT\n"
"    movq %rax, %r11\n"
"    movq 0(%rsp), %rax\n"
"    movq 8(%rsp), %rdx\n"
"    movdqu 16(%rsp), %xmm0\n"
"    movdqu 32(%rsp), %xmm1\n"
"    addq $64, %rsp\n"
"    jmp *%r11\n"
".size __dyn_exit_tramp, .-__dyn_exit_tramp\n"
);
"""

_DYN_WRAP_TEMPLATE = """    .text
    .globl {prefix}{f}
    .type {prefix}{f},@function
{prefix}{f}:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    pushq %rax
    subq $136, %rsp
    movdqu %xmm0, 0(%rsp)
    movdqu %xmm1, 16(%rsp)
    movdqu %xmm2, 32(%rsp)
    movdqu %xmm3, 48(%rsp)
    movdqu %xmm4, 64(%rsp)
    movdqu %xmm5, 80(%rsp)
    movdqu %xmm6, 96(%rsp)
    movdqu %xmm7, 112(%rsp)
    leaq 8(%rbp), %rdi
    call __dyn_enter@PLT
    movdqu 0(%rsp), %xmm0
    movdqu 16(%rsp), %xmm1
    movdqu 32(%rsp), %xmm2
    movdqu 48(%rsp), %xmm3
    movdqu 64(%rsp), %xmm4
    movdqu 80(%rsp), %xmm5
    movdqu 96(%rsp), %xmm6
    movdqu 112(%rsp), %xmm7
    addq $136, %rsp
    popq %rax
    popq %r9
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    popq %rbp
    jmp {f}@PLT
    .size {prefix}{f}, .-{prefix}{f}
"""


def _dyn_sync_footer(funcs: List[str]) -> str:
    """C appended to the translation unit that defines `funcs`: a used-array so the compiler keeps
    the (possibly `static`, otherwise unreferenced) functions, and one assembly wrapper per function."""
    keep = '__attribute__((used)) static void *const __dyn_keep_funcs[] = { ' + \
           ', '.join(f'(void *){f}' for f in funcs) + ' };\n'
    asm = ''.join(_DYN_WRAP_TEMPLATE.format(prefix=_DYN_WRAP_PREFIX, f=f) for f in funcs)
    body = '\n'.join('"' + l.replace('\\', '\\\\').replace('"', '\\"') + '\\n"' for l in asm.split('\n') if l)
    return '\n' + keep + '__asm__(\n' + body + '\n);\n'


def _elf_symbols(path: str) -> List[Dict]:
    """Defined symbols of a 64-bit little-endian ELF file's .symtab, each with the name of the section
    it lives in and the source file (STT_FILE entry) it follows. Read directly instead of through
    readelf/nm so that no output parsing is involved."""
    import struct
    with open(path, 'rb') as f:
        data = f.read()
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        return []
    e_shoff, = struct.unpack_from('<Q', data, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', data, 0x3A)
    secs = [struct.unpack_from('<IIQQQQIIQQ', data, e_shoff + i * e_shentsize) for i in range(e_shnum)]

    def cstr(off):
        return data[off:data.index(b'\0', off)].decode('utf-8', 'replace')

    shstr_off = secs[e_shstrndx][4]
    names = [cstr(shstr_off + sec[0]) for sec in secs]
    syms = []
    for sec in secs:
        if sec[1] != 2:  # SHT_SYMTAB
            continue
        str_off, off, size = secs[sec[6]][4], sec[4], sec[5]
        cur_file = ''
        for k in range(size // 24):
            st_name, st_info, _, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', data, off + k * 24)
            typ = st_info & 0xf
            name = cstr(str_off + st_name) if st_name else ''
            if typ == 4:  # STT_FILE
                cur_file = name
                continue
            if st_shndx == 0 or st_shndx >= 0xff00:
                continue
            syms.append({'name': name, 'value': st_value, 'size': st_size, 'type': typ,
                         'sec': names[st_shndx], 'file': cur_file})
    return syms


_DYN_SYNC_SKIP_PREFIXES = ('__asan', '___asan', '__ubsan', '__sancov', '__dyn_', '_GLOBAL_', '__dso_handle',
                           'completed.', '__TMC_END__', '__data_start', 'data_start', '_DYNAMIC')


def _dyn_sync_eligible(sym: Dict) -> bool:
    """A variable worth keeping in step: an object with storage in plain .data/.bss. Sections that
    hold relocated pointers (.data.rel*, .init_array, ...) are left alone on purpose: their contents
    point into the module that owns them, and copying the program's would send libpatch.so's own
    code through the program's (unpatched) functions."""
    if sym['type'] != 1 or sym['size'] == 0:
        return False
    sec = sym['sec']
    if not (sec in ('.data', '.bss') or (sec.startswith('.data.') and not sec.startswith('.data.rel'))
            or sec.startswith('.bss.')):
        return False
    name = sym['name']
    return bool(name) and not name.startswith(_DYN_SYNC_SKIP_PREFIXES) and 'asan' not in name


# A global whose *type* holds a pointer (a struct field, not the variable's own storage class)
# must never be synced: the sync copy is a raw byte copy, and copying such a field duplicates a
# heap address into two independent storage locations. Whichever side later frees and replaces
# it, the next sync can hand the other side that stale value, which it then frees again -- a
# double-free the patch never caused (confirmed on libxml2/42517254: ContraFix's own already-
# verified patch crashed only with this filter absent, in unrelated error-reporting code --
# xmlLastError, a struct with a `char *message` field -- that the patch itself never touches).
# _dyn_sync_eligible()'s own section check (excluding .data.rel*) only catches pointers the
# *compiler* relocated there; a plain heap pointer set at runtime sits in ordinary .data/.bss like
# any scalar and needs the type information DWARF carries (from this build's -g3) to catch.
_DYN_POINTER_SCAN_PY = r'''
import sys
from elftools.elf.elffile import ELFFile

def ref_type(die, cu):
    attr = die.attributes.get('DW_AT_type')
    if attr is None:
        return None
    return die.dwarfinfo.get_DIE_from_refaddr(attr.value + cu.cu_offset)

def has_pointer(die, cu, seen):
    if die is None or die.offset in seen:
        return False
    seen.add(die.offset)
    if die.tag == 'DW_TAG_pointer_type':
        return True
    if die.tag in ('DW_TAG_typedef', 'DW_TAG_const_type', 'DW_TAG_volatile_type',
                   'DW_TAG_restrict_type', 'DW_TAG_array_type'):
        return has_pointer(ref_type(die, cu), cu, seen)
    if die.tag in ('DW_TAG_structure_type', 'DW_TAG_union_type', 'DW_TAG_class_type'):
        return any(c.tag == 'DW_TAG_member' and has_pointer(ref_type(c, cu), cu, seen)
                   for c in die.iter_children())
    return False

with open(sys.argv[1], 'rb') as f:
    elf = ELFFile(f)
    if elf.has_dwarf_info():
        dwarf = elf.get_dwarf_info()
        for cu in dwarf.iter_CUs():
            for die in cu.get_top_DIE().iter_children():
                if die.tag != 'DW_TAG_variable':
                    continue
                name = die.attributes.get('DW_AT_name')
                if not name or 'DW_AT_declaration' in die.attributes or 'DW_AT_location' not in die.attributes:
                    continue
                try:
                    flagged = has_pointer(ref_type(die, cu), cu, set())
                except Exception:
                    flagged = True  # an unresolvable type is excluded from sync, not risked
                if flagged:
                    print(name.value.decode('utf-8', 'replace'))
'''


def _dyn_pointer_containing_globals(container_id: str, so_path_container: str) -> Optional[Set[str]]:
    """Names of every global in so_path_container (built with -g3, so its DWARF is present) whose
    *type* holds a pointer anywhere (recursively through typedefs/structs/arrays). None (not an
    empty set) if the scan itself could not run -- e.g. no pyelftools in this container -- so the
    caller can fall back to not filtering rather than silently syncing everything as if none did."""
    res = sp.run(['docker', 'exec', container_id, 'python3', '-c', _DYN_POINTER_SCAN_PY, so_path_container],
                 stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
    if res.returncode != 0:
        return None
    return set(res.stdout.split())


def _build_sync_tab(exe_path: str, so_path: str, container_id: Optional[str] = None,
                     patched_file_stems: Optional[Set[str]] = None) -> List[str]:
    """Lines `<libpatch.so symbol offset> <program symbol address> <size>` (hex, hex, decimal) for every
    variable libpatch.so defines that also exists, with the same name and size, in the program.
    A name that is ambiguous in the program is resolved by the source file the symbol came from and
    skipped if that does not settle it.

    patched_file_stems: when given, a global is only kept if it belongs to one of these source
    files (by stem, matching build_libpatch()'s naming) -- the whole *project*'s PIC archive gets
    linked into libpatch.so to resolve calls out of the patched file, and every archive member the
    linker pulls in to do that brings its own globals along, entirely unrelated to the patch.

    container_id: when given (with so_path a container-visible path), a global whose type holds a
    pointer (see _dyn_pointer_containing_globals()) is marked sync-in-only, its 4th column 0
    instead of 1: __dyn_sync_in() still refreshes libpatch.so's copy with the program's current
    value on every wrapped call (what a patched function that reads a global initialised at
    runtime needs), but __dyn_sync_out() never copies it back, which is what caused a double-free
    in practice -- copying a pointer field out duplicates a heap address into the program's own
    copy, and whichever side later frees and replaces it, the next sync-in can hand the other side
    a stale value it frees again. If the scan can't run in that container, every global here is
    marked sync-out same as before (unfiltered), not excluded.
    """
    import collections
    exe = collections.defaultdict(list)
    for sym in _elf_symbols(exe_path):
        if _dyn_sync_eligible(sym):
            exe[(sym['name'], sym['size'])].append(sym)

    def stem(path):
        base = os.path.splitext(os.path.basename(path))[0]
        base = base[len('libpatch_'):] if base.startswith('libpatch_') else base
        return base[:-len('_wf')] if base.endswith('_wf') else base

    pointer_names = _dyn_pointer_containing_globals(container_id, so_path) if container_id else None

    lines, seen = [], set()
    for sym in _elf_symbols(so_path):
        if not _dyn_sync_eligible(sym) or sym['value'] in seen:
            continue
        if patched_file_stems is not None and not (sym['file'] and stem(sym['file']) in patched_file_stems):
            continue
        cands = exe.get((sym['name'], sym['size']))
        if not cands:
            continue
        if len(cands) > 1:
            cands = [c for c in cands if c['file'] and sym['file'] and stem(c['file']) == stem(sym['file'])]
            if len(cands) != 1:
                continue
        seen.add(sym['value'])
        sync_out = 0 if pointer_names is not None and sym['name'] in pointer_names else 1
        lines.append(f"{sym['value']:x} {cands[0]['value']:x} {sym['size']} {sync_out}")
    return lines


# --- macro-generated function names ------------------------------------------------------
#
# A template file such as ffmpeg's cbs_h266_syntax_template.c or hevcdsp_template.c defines its
# functions through a macro (`static int FUNC(vps)(...)`), and the .c file that #includes it defines
# FUNC differently for each inclusion (read/write, or one per bit depth). What the binary has is
# the expansion (cbs_h266_read_vps, cbs_h266_write_vps / put_hevc_pel_uni_pixels_8, _9, _10, _12), so
# the text-level name the hunk parser finds (`FUNC`) is useless to Dyninst. The names are recovered
# from the compiler's own view: the translation unit is preprocessed with the project's real flags,
# and the functions of the output whose lines come from the patched definition are the ones patched.

_DYNINST_LINEMARKER_RE = re.compile(r'^#\s*(\d+)\s+"((?:[^"\\]|\\.)*)"')
_DYNINST_DEP_FLAGS_WITH_ARG = {'-MF', '-MT', '-MQ'}
_DYNINST_DEP_FLAGS = {'-MD', '-MMD', '-MP', '-M', '-MM', '-MG'}


def _dyninst_is_macro_named(text: str, name: str, func_start: int) -> bool:
    """True when the definition starting at line func_start of `text` spells its name as a
    macro call -- `NAME(args) (` -- instead of a plain `name(`."""
    header = []
    for line in text.split('\n')[func_start - 1:func_start + 30]:
        header.append(line)
        if '{' in line:
            break
    return re.search(rf'\b{re.escape(name)}\s*\(\s*[^()]*\)\s*\(', ' '.join(header)) is not None


def _dyninst_expanded_names(i_text: str, cwd: str, template_path: str, line: int) -> List[str]:
    """Names of the functions defined in the preprocessed text `i_text` (linemarkers kept) whose
    body was written on line `line` of template_path, in order of appearance."""
    want = os.path.realpath(template_path)
    origin = []          # per output line: (real path of the source file, its line) or None
    clean = []
    cur_file, cur_line = None, 0
    file_cache: Dict[str, str] = {}
    for out_line in i_text.split('\n'):
        m = _DYNINST_LINEMARKER_RE.match(out_line)
        if m:
            cur_line = int(m.group(1))
            path = m.group(2).replace('\\"', '"')
            if path not in file_cache:
                file_cache[path] = os.path.realpath(path if os.path.isabs(path) else os.path.join(cwd, path))
            cur_file = file_cache[path]
            origin.append(None)
            clean.append('')
            continue
        origin.append((cur_file, cur_line))
        clean.append(out_line)
        cur_line += 1
    names = []
    for name, start, end in _parse_function_ranges(_clean_for_parse('\n'.join(clean))):
        lines_here = [o[1] for o in origin[start - 1:end] if o and o[0] == want]
        if lines_here and min(lines_here) <= line <= max(lines_here) and name not in names:
            names.append(name)
    return names


def _dyninst_expand_macro_named_functions(container_id: str, cc_invocations: List[Dict],
                                           project_root_container: str, out_dir: str,
                                           locations: List[Dict]) -> Tuple[List[Dict], List[str]]:
    """Replace every location whose function is defined through a name-generating macro by one
    location per symbol it expands to (see the block comment above). Locations without a 'line'
    and ordinary functions are returned unchanged. Returns (locations, notes)."""
    notes: List[str] = []
    resolved: List[Dict] = []
    cache: Dict[Tuple[str, int], List[str]] = {}
    for loc in locations:
        line = loc.get('line')
        patched_path = loc.get('patched_path')
        if not line or not patched_path or not os.path.exists(patched_path):
            resolved.append(loc)
            continue
        with open(patched_path, errors='replace') as f:
            text = f.read()
        func_start = next((st for name, st, en in _parse_function_ranges(_clean_for_parse(text))
                           if name == loc['function'] and st <= line <= en), None)
        if func_start is None or not _dyninst_is_macro_named(text, loc['function'], func_start):
            resolved.append(loc)
            continue

        basename = os.path.basename(loc['file'])
        key = (patched_path, line)
        if key not in cache:
            cache[key] = []
            tu_path = patched_path
            inv = _find_invocation_for_source(cc_invocations, basename, project_root_container)
            if inv is None:
                inv, _includer_basename, includer_path = _find_invocation_via_includer(
                    container_id, cc_invocations, basename, project_root_container)
                tu_path = includer_path
            if inv is None:
                notes.append(f"{loc['file']}: '{loc['function']}' is a macro-generated name and no compile "
                             f"invocation could be found to expand it")
            else:
                args = []
                skip = False
                for arg in _strip_c_and_o(inv['args'], os.path.basename(tu_path)):
                    if skip:
                        skip = False
                    elif arg in _DYNINST_DEP_FLAGS_WITH_ARG:
                        skip = True
                    elif arg not in _DYNINST_DEP_FLAGS:
                        args.append(arg)
                out_i = os.path.join(out_dir, f'expand_{os.path.splitext(basename)[0]}_{line}.i')
                res = sp.run(['docker', 'exec', '-w', inv['cwd'], container_id, inv['argv0']] + args +
                             ['-E', '-o', out_i, tu_path], stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
                if res.returncode != 0 or not os.path.exists(out_i):
                    notes.append(f"{loc['file']}: preprocessing {os.path.basename(tu_path)} to expand "
                                 f"'{loc['function']}' failed:\n{res.stdout}")
                else:
                    with open(out_i, errors='replace') as f:
                        cache[key] = _dyninst_expanded_names(f.read(), inv['cwd'], patched_path, line)
                    os.remove(out_i)
        names = cache[key]
        if not names:
            notes.append(f"{loc['file']}: '{loc['function']}' is generated by a macro and could not be "
                         f"expanded to a symbol name")
            resolved.append(loc)
            continue
        notes.append(f"{loc['file']}:{line}: macro-generated '{loc['function']}' is {', '.join(names)}")
        for name in names:
            new_loc = dict(loc, function=name)
            if not any(r['file'] == new_loc['file'] and r['function'] == name for r in resolved):
                resolved.append(new_loc)
    return resolved, notes


def _dyninst_compile_and_link(container_id: str, cc_invocations: List[Dict], pic_archive_container: str,
                               locations: List[Dict], out_dir: str, project_root_container: str,
                               binary_path_container: Optional[str] = None,
                               force_whole_file: bool = False,
                               sync_globals: bool = True) -> Tuple[bool, float, str]:
    """Build a single libpatch.so covering every (file, function) in
    `locations`: one compiled .o per unique file (multiple patched functions
    in the same file share one combined extraction/compile), linked together
    with one trimmed PIC archive into a single final .so -- as opposed to
    compiling+linking once per function/location, which makes loadLibrary()
    cost (and build time) scale with function count for no reason.

    locations: [{'file': path relative to project_root_container,
                 'function': str,
                 'patched_path': host-and-container path to the already-
                     patched copy of that file (under self.source_dir)}, ...]

    force_whole_file: skip the extraction attempt for every file and compile
    each one whole (the already-patched file directly) instead. A clean
    extraction compile no longer guarantees a usable result -- build_libpatch
    keeps almost the whole file minus unneeded function bodies, so a closure
    missing something can still compile fine and only fail later, at this
    function's own final link (a colliding archive member) or at
    dyninst_test()'s loadLibrary() (an undefined symbol the -shared link
    tolerates but Dyninst's own resolver does not). Meant for
    dyninst_binary_patch()'s own retry in that case.

    sync_globals: build the patched functions with the wrappers that keep libpatch.so's copy of
    every file-scope variable in step with the running program's (see the block comment above
    _DYN_RUNTIME_C); writes out_dir/sync.tab and out_dir/sync.funcs for dyninst_test().

    Returns (ok, elapsed_seconds, output) -- matches pv.metapro_patch()'s
    return shape exactly."""
    t0 = time.time()
    output_lines = []
    os.makedirs(out_dir, exist_ok=True)
    for stale in ('sync.tab', 'sync.funcs'):
        if os.path.exists(os.path.join(out_dir, stale)):
            os.remove(os.path.join(out_dir, stale))
    sync_active = sync_globals
    wrapped_funcs: List[str] = []
    rt_o = None

    def _run(cmd, cwd):
        res = sp.run(['docker', 'exec', '-w', cwd, container_id] + cmd,
                      stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
        return res.returncode == 0, res.stdout

    # Group locations by file, preserving first-seen order (so the .o's end
    # up in the final link command in a deterministic, reproducible order).
    funcs_by_file: Dict[str, Dict] = {}
    for loc in locations:
        entry = funcs_by_file.setdefault(loc['file'], {'patched_path': loc['patched_path'], 'functions': []})
        entry['functions'].append(loc['function'])

    obj_containers = []
    full_exclude_members = []         # whole-file fallback: our object IS the whole file
    strip_symbols_by_member = {}      # extraction succeeded: only these names are redefined
    link_inv = link_base_args = None  # first file's invocation, reused for the final link's flags

    for src_rel, info in funcs_by_file.items():
        patched_path = info['patched_path']
        func_names = info['functions']
        source_basename = os.path.basename(src_rel)
        is_header = os.path.splitext(source_basename)[1] in _DYNINST_HEADER_EXTS

        inv = _find_invocation_for_source(cc_invocations, source_basename, project_root_container)
        strip_basename = source_basename
        via_includer_path = None  # a non-header file compiled through the .c file that #includes it
        if inv is None:
            inv, includer_basename, includer_path = _find_invocation_via_includer(
                container_id, cc_invocations, source_basename, project_root_container)
            if inv is not None:
                strip_basename = includer_basename
                if is_header:
                    output_lines.append(f'{source_basename}: header has no compile invocation of its own -- '
                                         f'reusing flags from a #include-ing .c/.cpp file instead')
                else:
                    via_includer_path = includer_path
                    patched_path = includer_path
                    output_lines.append(f'{source_basename}: no compile invocation of its own (it is #included '
                                         f'by {includer_basename}) -- compiling {includer_basename}, which '
                                         f'includes the patched copy, instead')
        if inv is None:
            output_lines.append(f'FAILED: no captured compile invocation for {source_basename} '
                                 f'(is dyninst-cc-wrapper.sh installed before the build ran? see setup_dyninst())')
            return False, time.time() - t0, '\n'.join(output_lines)
        base_args = _strip_c_and_o(inv['args'], strip_basename)
        # This file's own object in the PIC archive, i.e. the one our freshly compiled object
        # replaces. Not for a header: its flags come from an including file's compile, but that
        # file's object is not something we redefine.
        pic_member = None
        if strip_basename == source_basename or via_includer_path:
            pic_path = _pic_object_path(inv)
            if pic_path:
                pic_member = _pic_member_name(pic_path, project_root_container)
        is_cxx = os.path.splitext(source_basename)[1] in ('.cc', '.cpp', '.cxx', '.C')
        if link_inv is None:
            link_inv, link_base_args = inv, base_args
            if sync_active and is_cxx:
                sync_active = False
            if sync_active:
                rt_c = os.path.join(out_dir, 'libpatch_dynrt.c')
                rt_o = os.path.join(out_dir, 'libpatch_dynrt.o')
                with open(rt_c, 'w') as f:
                    f.write(_DYN_RUNTIME_C)
                ok_rt, rt_out = _run([inv['argv0']] + base_args + ['-O1', '-g', '-fPIC', '-fno-builtin', '-fno-sanitize=all',
                                                                     # the project's own -Werror/-W flags are none of this file's business
                                                                     '-w', '-Wno-error', '-c', '-o', rt_o, rt_c], inv['cwd'])
                if not ok_rt:
                    sync_active = False
                    rt_o = None
                    output_lines.append(f'global-data sync disabled: its runtime did not compile:\n{rt_out}')

        # -fpatchable-function-entry=5 pads each replacement function's
        # entry with 5 NOPs so Dyninst has guaranteed safe space to write a
        # trampoline jump into, instead of having to relocate real
        # instructions out of the way. Skipped for C++: breaks linking of
        # heavily-templated code (__patchable_function_entries referencing
        # symbols later discarded as duplicate COMDATs).
        extra = [] if is_cxx else ['-fpatchable-function-entry=5']
        # Only plain .c files whose target functions are defined in the file itself (not a header's
        # text, and not a template reached through its includer).
        wrap_eligible = sync_active and not is_cxx and not is_header and not via_includer_path
        wrap_this = wrap_eligible

        stem = os.path.splitext(strip_basename if via_includer_path else source_basename)[0]
        out_o = os.path.join(out_dir, f'libpatch_{stem}.o')

        ok = False
        compile_out = ''
        # A header has no "whole file" to fall back to compiling standalone
        # (its target function has no caller within the header itself), so
        # headers always go through extraction, even on a forced-whole-file
        # retry -- it's the only valid path there is.
        if (not force_whole_file and not via_includer_path) or is_header:
            try:
                libpatch_src, included = build_libpatch(patched_path, func_names)
            except ValueError as e:
                output_lines.append(f'FAILED: {e}')
                return False, time.time() - t0, '\n'.join(output_lines)

            out_c = os.path.join(out_dir, f'libpatch_{stem}.c')
            with open(out_c, 'w') as f:
                f.write(libpatch_src + (_dyn_sync_footer(func_names) if wrap_this else ''))

            output_lines.append(f'{source_basename}: extracted {len(included)} function(s) for '
                                 f'{len(func_names)} target(s): {", ".join(included)}')
            cmd = [inv['argv0']] + base_args + extra + ['-O0', '-g3', '-fPIC', '-c', '-o', out_o, out_c]
            ok, compile_out = _run(cmd, inv['cwd'])
            if not ok and wrap_this:
                # Maybe the wrappers are what does not compile (a target name the file does not
                # define under that name): retry plain, and give up syncing for this file.
                with open(out_c, 'w') as f:
                    f.write(libpatch_src)
                ok_plain, plain_out = _run(cmd, inv['cwd'])
                if ok_plain:
                    ok, compile_out, wrap_this = True, plain_out, False
                    output_lines.append(f'{source_basename}: compiled only without the global-data sync wrappers')
        if not ok and is_header:
            output_lines.append(f'FAILED: extraction compile failed for header {source_basename}, and a '
                                 f'header has no whole-file fallback to try instead:\n{compile_out}')
            return False, time.time() - t0, '\n'.join(output_lines)
        if not ok:
            # The extracted closure may be missing a dependency
            # build_libpatch() can't see (a file-scope static struct/
            # typedef/array), or may just be too large to be worth chasing.
            # Fall back to compiling the whole already-patched file instead
            # of the extracted subset -- same flags, only the input source
            # changes. One fallback covers every function in this file.
            if force_whole_file:
                output_lines.append(f'{source_basename}: forced whole-file compile (retry)')
            else:
                output_lines.append(f'{source_basename}: extraction compile failed, '
                                     f'falling back to whole-file compile:\n{compile_out}')
            wrap_this = wrap_eligible
            cmd = [inv['argv0']] + base_args + extra + ['-O0', '-g3', '-fPIC', '-c', '-o', out_o, patched_path]
            ok = False
            if wrap_this:
                # Compile a one-line wrapper file that #includes the patched file, so the wrappers can
                # be appended to the same translation unit (they name the file's static functions).
                wf_c = os.path.join(out_dir, f'libpatch_{stem}_wf.c')
                with open(wf_c, 'w') as f:
                    f.write(f'#include "{patched_path}"\n' + _dyn_sync_footer(func_names))
                ok, whole_out = _run(cmd[:-1] + [wf_c], inv['cwd'])
                if not ok:
                    wrap_this = False
                    output_lines.append(f'{source_basename}: whole-file compile with the global-data sync wrappers failed, '
                                         f'retrying without them')
            if not ok:
                ok, whole_out = _run(cmd, inv['cwd'])
            if not ok:
                output_lines.append(f'FAILED: whole-file compile for {source_basename} also failed:\n{whole_out}')
                return False, time.time() - t0, '\n'.join(output_lines)
            output_lines.append(f'{source_basename}: whole-file fallback compiled -> {out_o}')
            if pic_member:
                full_exclude_members.append(pic_member)
        else:
            output_lines.append(f'{source_basename}: compiled -> {out_o}')
            # Redefine every symbol OUR object actually defines in the
            # archive's copy -- not just `included` (the function names).
            # build_libpatch() keeps the whole file minus unneeded function
            # *bodies*, so file-scope static data comes along too whenever
            # anything in the closure touches it, and that's just as
            # duplicated between our object and the archive's copy of the
            # same file as the functions are. Querying our own compiled
            # object for its defined symbols is exact by construction,
            # unlike trying to predict from source text which globals ended
            # up needed.
            ok_syms, syms = _defined_symbols(container_id, out_o)
            if pic_member:
                strip_symbols_by_member[pic_member] = syms if ok_syms else set(included)
        obj_containers.append(out_o)
        if wrap_this:
            wrapped_funcs.extend(func_names)

    if wrapped_funcs and rt_o:
        obj_containers.append(rt_o)

    try:
        trimmed_archive = _pic_archive_trim(container_id, pic_archive_container, out_dir,
                                             full_exclude_members, strip_symbols_by_member)
    except RuntimeError as e:
        output_lines.append(f'FAILED: {e}')
        return False, time.time() - t0, '\n'.join(output_lines)

    extra_link_libs = []
    if binary_path_container:
        target_basename = os.path.basename(binary_path_container)
        target_link_inv = _find_link_invocation_for_binary(cc_invocations, target_basename, project_root_container)
        if target_link_inv is not None:
            extra_link_libs = _extract_extra_link_libs(target_link_inv['args'], project_root_container)
            if extra_link_libs:
                output_lines.append(f'{target_basename}: reusing external library flags from its own real '
                                     f'link invocation: {" ".join(extra_link_libs)}')
        else:
            # The target's own link is not in the log (ffmpeg's fuzz targets are linked and renamed by
            # its own build, so no captured `-o <target>` matches). Fall back to the external
            # libraries the project's other real links used, so e.g. a demuxer that reaches libxml2
            # code through the PIC archive gets -lxml2 instead of failing at loadLibrary() with an
            # undefined symbol. Configure-time probes (outputs outside the project tree, or named
            # conftest/a.out) are skipped, since they test libraries that may not exist, and so are
            # this tool's own links.
            seen = set()
            for inv in cc_invocations:
                args = inv['args']
                if '-c' in args or '-o' not in args or any(out_dir in a for a in args):
                    continue
                if inv['cwd'] != project_root_container and not inv['cwd'].startswith(project_root_container + '/'):
                    continue
                o_idx = args.index('-o')
                if o_idx + 1 >= len(args):
                    continue
                out_path = os.path.normpath(os.path.join(inv['cwd'], args[o_idx + 1]))
                out_name = os.path.basename(out_path)
                if not out_path.startswith(project_root_container + '/') or out_name.startswith(('conftest', 'a.out')):
                    continue
                for flag in _extract_extra_link_libs(args, project_root_container):
                    if flag not in seen:
                        seen.add(flag)
                        extra_link_libs.append(flag)
            extra_link_libs = _shared_link_libs_only(container_id, extra_link_libs)
            if extra_link_libs:
                output_lines.append(f'{target_basename}: no link invocation of its own in the log -- using the '
                                     f'shared-library flags of the project\'s other real links: '
                                     f'{" ".join(extra_link_libs)}')

    out_so = os.path.join(out_dir, 'libpatch.so')
    link_cmd = ([link_inv['argv0']] + link_base_args +
                ['-O0', '-g3', '-shared', '-fPIC', '-Wl,--allow-multiple-definition',
                 # The PIC archive replays the real build with -fPIC added,
                 # but some hand-tuned x86 SIMD/intrinsics code still emits
                 # absolute (non-PC-relative) relocations against const
                 # tables even under -fPIC -- ld's normal response is to
                 # refuse them outright. This libpatch.so is a one-shot
                 # artifact Dyninst loads once for a single PoC run, not a
                 # real shared library other processes share, so trading
                 # away the ASLR/RELRO hardening -z text normally provides
                 # is a fine trade for not having to make 100% of a
                 # SIMD-heavy codebase's object code truly PIC just to link
                 # it in here.
                 '-Wl,-z,notext',
                 '-Wl,--defsym=__init_array_start=0', '-Wl,--defsym=__init_array_end=0',
                 '-o', out_so] + obj_containers + [trimmed_archive] + extra_link_libs +
                (['-ldl'] if wrapped_funcs and rt_o else []))
    ok, link_out = _run(link_cmd, link_inv['cwd'])
    if not ok:
        output_lines.append(f'FAILED: final link failed:\n{link_out}')
        return False, time.time() - t0, '\n'.join(output_lines)
    output_lines.append(f'linked {len(obj_containers)} object(s) -> {out_so}')

    if wrapped_funcs and rt_o:
        lines = []
        if binary_path_container and os.path.exists(binary_path_container):
            patched_file_stems = {os.path.splitext(os.path.basename(f))[0] for f in funcs_by_file}
            try:
                lines = _build_sync_tab(binary_path_container, out_so, container_id, patched_file_stems)
            except Exception as e:  # never let the sync table break an otherwise good build
                output_lines.append(f'global-data sync table could not be built: {e}')
        if lines:
            with open(os.path.join(out_dir, 'sync.tab'), 'w') as f:
                f.write('\n'.join(lines) + '\n')
            with open(os.path.join(out_dir, 'sync.funcs'), 'w') as f:
                f.write('\n'.join(wrapped_funcs) + '\n')
            output_lines.append(f'global-data sync: {len(wrapped_funcs)} wrapped function(s), '
                                 f'{len(lines)} variable(s) kept in step with the program '
                                 f'({sum(int(l.split()[2]) for l in lines)} bytes)')
        else:
            output_lines.append('global-data sync: no variable of libpatch.so has a counterpart in the program, '
                                 'wrappers left unused')

    return True, time.time() - t0, '\n'.join(output_lines)


_DYNINST_TIMING_RE = re.compile(r'launch_ms=([\d.]+) patch_apply_ms=([\d.]+) run_ms=([\d.]+) total_ms=([\d.]+)')


def _dyninst_run_mutator(container_id: str, binary_path_container: str, poc_path_container: str,
                          so_func_pairs: List[Tuple[str, str]], timeout: int = 180,
                          project: Optional[str] = None,
                          sync_tab: Optional[str] = None) -> Tuple[bool, float, str]:
    """Launch `binary_path_container` suspended via Dyninst, swap in every
    (so, function) pair, resume, run the PoC, and report whether it still
    crashes. A pair's function may be `old=new` when the replacement has a
    different name (the global-data sync wrappers); sync_tab is the table
    those wrappers read (DYN_SYNC_TAB).

    Returns (ok, elapsed_seconds, output) -- matches pv.metapro_test()'s
    return shape. ok=True means "patched process ran the PoC without a crash
    signature" (i.e. the patch held)."""
    t0 = time.time()
    mutator_args = [str(len(so_func_pairs))]
    for so, func in so_func_pairs:
        mutator_args += [so, func]

    cmd = [
        'docker', 'exec',
        '-e', f'DYNINSTAPI_RT_LIB={DYNINSTAPI_RT_LIB}',
        # Same runtime env pv.metapro_test() runs the patched binary under
        # (see ArvoValidator.metapro_runtime_env()). detect_leaks=0 matters
        # here specifically: LeakSanitizer's post-run leak check is
        # incompatible with being launched suspended under ptrace (Dyninst's
        # own mechanism) and fatally errors out otherwise -- unrelated to
        # whether the actual patch held, but it would corrupt the result if
        # left enabled. detect_odr_violation=0 matters when libpatch.so had to be built by
        # whole-file fallback (build_libpatch()'s extraction failed): the whole file's own
        # non-static globals (php-src's Zend engine has plenty, e.g. zend_standard_class_def,
        # pcre_globals) come along and get their own ASan-instrumented copy in libpatch.so,
        # which is a real, deliberate duplicate -- not a build bug -- but ASan's ODR checker
        # aborts on sight of two same-name/size/location globals from different modules.
        #
        # external_symbolizer_path= (both lines) matters for a completely different reason:
        # on a crash, the sanitizer runtime normally resolves the backtrace's addresses to
        # file/line by forking an external llvm-symbolizer subprocess. The target here is
        # always ptrace-stopped by Dyninst's launch-suspended mechanism (that is how
        # mutator_launch works at all), and a forked child of a ptrace-traced process hangs
        # for 10-60+ seconds before that fork's own ptrace-stop event gets resolved -- this
        # is a generic ptrace-vs-forking-symbolizer interaction, confirmed by reproducing the
        # exact same multi-second hang with plain `strace -f` standing in for Dyninst, i.e. it
        # has nothing to do with Dyninst's own instrumentation. Blanking the path skips the
        # external fork entirely (backtrace frames fall back to raw addresses). That loses
        # nothing this file's own crash classification needs: every string it greps for
        # ('AddressSanitizer', 'ERROR'/'ABORTING', 'UndefinedBehaviorSanitizer', 'runtime
        # error:') is printed from the sanitizer's own compile-time-embedded source location
        # or the shadow-memory check itself, not from the symbolized backtrace -- see the
        # `crashed = (...)` check a little further down in this same function.
        '-e', 'ASAN_OPTIONS=detect_leaks=0:detect_odr_violation=0:external_symbolizer_path=',
        '-e', 'UBSAN_OPTIONS=abort_on_error=1:print_stacktrace=1:external_symbolizer_path=',
        *(['-e', f'DYN_SYNC_TAB={sync_tab}'] if sync_tab else []),
        container_id, MUTATOR_LAUNCH,
        *mutator_args, binary_path_container, poc_path_container,
    ]
    # Dyninst analyses the target and libpatch.so with several threads, and its parser sometimes trips
    # an internal assertion (`Parser.C ... Assertion ... failed`) -- observed only when many
    # launches run at once, and the very same libpatch.so then loads fine on the next try. That
    # says nothing about the patch (no function was replaced), so such a launch is simply repeated.
    # A killed `docker exec` client does not kill the process it started inside the container --
    # docker does not forward that signal across the exec boundary. Left alone, a timed-out launch
    # (or its target, resumed under Dyninst's ptrace) keeps running and competing for CPU with every
    # later launch in the same container, so a single slow analysis can cascade into the rest of that
    # container's launches also timing out. Both are named uniquely enough within one container (one
    # binary per bug) that killing by basename cannot hit an unrelated process.
    target_basename = os.path.basename(binary_path_container)

    def _kill_stale():
        sp.run(['docker', 'exec', container_id, 'pkill', '-9', '-f', 'mutator_launch'],
               stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        sp.run(['docker', 'exec', container_id, 'pkill', '-9', '-f', target_basename],
               stdout=sp.DEVNULL, stderr=sp.DEVNULL)

    _kill_stale()  # a previous call's timeout may have left this container's launch still running
    output = ''
    for attempt in range(3):
        try:
            res = sp.run(cmd, stdout=sp.PIPE, stderr=sp.STDOUT, text=True, errors='replace', timeout=timeout)
        except sp.TimeoutExpired as e:
            _kill_stale()
            return False, time.time() - t0, f'TIMEOUT after {timeout}s:\n{(e.stdout or "")}'
        output = res.stdout
        if re.search(r'mutator_launch: .*Assertion .* failed', output) and 'replaceFunction OK' not in output:
            continue
        break
    elapsed = time.time() - t0

    if 'FAILED:' in output:
        return False, elapsed, output  # mechanism itself failed (function/so not found, replaceFunction failed, ...)

    if 'symbol lookup error:' in output:
        # The dynamic loader's own error when the resumed process calls into
        # our libpatch.so and hits a symbol it never resolved. A mechanism
        # failure exactly like 'FAILED:' above, not a verdict on the patch --
        # letting it fall through to the crash-signature check below would
        # silently report it as a clean PASS even though the patched code
        # never actually ran.
        return False, elapsed, output

    # Same crash signatures pv.metapro_test() checks, so a verdict here
    # means the same thing there -- ASan/UBSan output, or libFuzzer's own
    # "caught a deadly signal" report (php-src excluded from the UBSan-text
    # check too: its own normal output can contain "runtime error:"-like
    # text unrelated to a real bug).
    #
    # Also checks for a plain libc assert() failure, which metapro_test()
    # doesn't need to: that relies on libFuzzer's signal handler printing
    # "libFuzzer: deadly signal" before the process dies, but under
    # Dyninst's suspend/resume/ptrace-based launch that handler does not
    # reliably fire (same class of issue as LeakSanitizer's post-run check
    # above).
    crashed = (
        ('AddressSanitizer' in output and ('ERROR' in output or 'ABORTING' in output))
        or (project != 'php-src' and ('UndefinedBehaviorSanitizer' in output or 'runtime error:' in output))
        or 'libFuzzer: deadly signal' in output
        or re.search(r"Assertion `.*' failed", output) is not None
    )
    ok = ('replaceFunction OK' in output) and not crashed
    return ok, elapsed, output
