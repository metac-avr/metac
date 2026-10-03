import os
import subprocess
import sys
from abc import ABC
from typing import NamedTuple

from san2patch.context import San2PatchLogger


class ProcessRunRet(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


class BaseCommander(ABC):
    def __init__(self, quiet=False):
        self.quiet = quiet
        self.logger = San2PatchLogger().logger

    def docker_cmd(
        self, cmd: str | list[str], container_id: str, pipe: bool = False
    ) -> ProcessRunRet:
        if not self.quiet:
            self.logger.debug(f"Running CMD: {cmd} in container {container_id}")

        try:
            if not pipe:
                result = subprocess.run(
                    ["docker", "exec", container_id] + cmd,
                    check=True,
                    text=True,
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                )
            else:
                result = subprocess.run(
                    ["docker", "exec", container_id] + cmd,
                    check=True,
                    text=True,
                    capture_output=True,
                )

            return ProcessRunRet(result.returncode, result.stdout, result.stderr)

        except subprocess.CalledProcessError as e:
            self.logger.error(
                f"Error occurred while running CMD: {cmd} in container {container_id}"
            )
            self.logger.error(e)

            return ProcessRunRet(e.returncode, e.stdout, e.stderr)

    def run_cmd(
        self,
        cmd: str | list[str],
        input: str | None = None,
        cwd: str = "./",
        pipe: bool = False,
        quiet: bool = None,
        timeout: int | None = None,
        stdout_file: str | None = None,
        stderr_file: str | None = None,
        expect_error: bool = False,
        env: dict | None = None,
        stderr_pipe: bool = True,
    ) -> ProcessRunRet:
        """Run `cmd` through the shell and return (returncode, stdout, stderr).

        `stderr_pipe` only applies together with `pipe=True`, the mode that captures
        output at all. Left at True the two streams are captured separately, as before.
        Set it to False to redirect stderr into stdout instead: the whole output then
        arrives interleaved in the second return value and the third is always "".
        Use that for commands whose interesting output is split across both streams
        (e.g. a sanitizer report on stderr next to the program's own stdout).
        """
        if quiet is None:
            quiet = self.quiet

        __env = os.environ.copy()
        for key, value in (env or {}).items():
            __env[key] = value

        if not quiet:
            self.logger.debug(f"Running CMD: {cmd} at {cwd}")
        result = None

        def _to_text(output: str | bytes | None) -> str:
            if output is None:
                return ""
            if isinstance(output, bytes):
                return output.decode("utf-8", errors="ignore")
            return output

        # Captured output to flush in `finally`. Populated on both the success
        # path (from `result`) and the error paths (from the exception), so the
        # stdout/stderr files are written even when the command exits non-zero
        # (e.g. a crashing binary run with expect_error=True).
        out_stdout = None
        out_stderr = None
        try:
            if quiet:
                result = subprocess.run(
                    cmd,
                    input=input,
                    shell=True,
                    cwd=cwd,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout,
                    env=__env,
                )
            elif not pipe:
                result = subprocess.run(
                    cmd,
                    input=input,
                    shell=True,
                    cwd=cwd,
                    check=True,
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                    timeout=timeout,
                    env=__env,
                )
            else:
                result = subprocess.run(
                    cmd,
                    input=input,
                    shell=True,
                    cwd=cwd,
                    check=True,
                    # Without stderr_pipe the child writes both streams into one pipe,
                    # so `stderr` comes back as None -> _to_text() turns it into "".
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE if stderr_pipe else subprocess.STDOUT,
                    timeout=timeout,
                    env=__env,
                )

            if result is not None:
                out_stdout = _to_text(result.stdout)
                out_stderr = _to_text(result.stderr)
            return ProcessRunRet(result.returncode, out_stdout or "", out_stderr or "")

        except subprocess.CalledProcessError as e:
            out_stdout, out_stderr = _to_text(e.stdout), _to_text(e.stderr)
            if not expect_error:
                self.logger.error(f"Error occurred while running CMD: {cmd} at {cwd}")
                self.logger.error(f"stdout: {e.stdout}")
                self.logger.error(f"stderr: {e.stderr}")

            return ProcessRunRet(e.returncode, out_stdout, out_stderr)

        except subprocess.TimeoutExpired as e:
            out_stdout, out_stderr = _to_text(e.stdout), _to_text(e.stderr)
            self.logger.error(f"Timeout occurred while running CMD: {cmd} at {cwd}")
            self.logger.error(e)

            return ProcessRunRet(-1, out_stdout, out_stderr)
        except Exception as e:
            self.logger.error(f"Unexpected error occurred while running CMD: {cmd} at {cwd}")
            self.logger.error(e)

            return ProcessRunRet(-1, "", str(e))

        finally:
            # Flush whatever output was captured, regardless of whether the
            # command succeeded or raised (non-zero exit, timeout). `out_stdout`
            # / `out_stderr` are set on every path that produced output; they
            # stay None only for the quiet/inherited-stdio modes (DEVNULL or
            # sys.stdout), where there is nothing captured to write.
            if stdout_file and out_stdout is not None:
                self.logger.debug(f"Flushing stdout to {stdout_file}")
                with open(stdout_file, "a") as f:
                    f.write(out_stdout)
            if stderr_file and out_stderr is not None:
                self.logger.debug(f"Flushing stderr to {stderr_file}")
                with open(stderr_file, "a") as f:
                    f.write(out_stderr)
