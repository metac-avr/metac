"""Docker container interaction tools for the ARVO solver.

Differences from ``src/docker_tools.py`` (SEC-bench), all verified against
real ARVO containers:

  - Image naming: ``n132/arvo:<localId>-vul``, prepared once per bug into
            ``<PREPARED_IMAGE_REPO>:<localId>`` (``prepare_image``)
  - Build:  ``arvo compile``            (not ``secb build``)
  - Repro:  ``arvo``                    (not ``secb repro``)
            In a prepared image both are San2Patch's: build.py and a direct
            run of the fuzz target (see ``arvo.benchmark``).
  - Patch:  ``git apply`` in ``/src/<project>``; ARVO has no ``secb patch``
  - Reset:  scoped to ``/src/<project>``.  ``/src`` is not a git repo, and
            iterating ``/src/*/`` would clean the fuzzer toolchain and
            vendored dependency repos (up to ten of them).
"""

from __future__ import annotations

import fcntl
import logging
import os
import posixpath
import re
import shlex
import subprocess
import tempfile

import docker

from arvo.benchmark import (
    BUILD_CMD,
    BUILD_PY,
    CONTRAFIX_DIR,
    PATCH_PATH,
    REPRO_CMD,
    get_image_name,
    get_prepared_image_name,
    prepare_container,
    project_dir,
    reset_cmd,
)
from arvo.config import (
    ARVO_BENCHMARK_DIR,
    BUILD_TIMEOUT,
    CONTAINER_MEM_LIMIT,
    CONTAINER_NETWORK_MODE,
    DOCKER_API_TIMEOUT,
    DOCKER_EXEC_TIMEOUT,
    E9PATCH_DEB,
    INSTALL_DEPS_SCRIPT,
    PREPARE_TIMEOUT,
    PREPARED_IMAGE_REPO,
    SETUP_LLVM_SCRIPT,
)

logger = logging.getLogger(__name__)

_client: docker.DockerClient | None = None

# ---------------------------------------------------------------------------
# Output cleaning — strip ANSI escapes and control chars from container output
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
_CR_RE = re.compile(r'\r')
_BRACKETED_PASTE_RE = re.compile(r'\x1B\[\?2004[lh]')
_OSC_RE = re.compile(r'\x1B\][0-9;]*[a-zA-Z0-9:\s@\-_./]*\x07')


def _clean_output(text: str) -> str:
    """Remove ANSI escapes and control characters from container output."""
    text = _ANSI_RE.sub('', text)
    text = _CR_RE.sub('', text)
    text = _BRACKETED_PASTE_RE.sub('', text)
    text = _OSC_RE.sub('', text)
    return text


def _get_client() -> docker.DockerClient:
    """Lazy-initialize and return the Docker client.

    `timeout` is per API call, not per session, so a long one costs nothing on
    the calls that are quick; it is only committing a prepared image that needs
    more than docker-py's 60s default (see DOCKER_API_TIMEOUT).
    """
    global _client
    if _client is None:
        _client = docker.from_env(timeout=DOCKER_API_TIMEOUT)
    return _client


def start_container(image: str) -> str:
    """Start a detached container from a prepared image (see ``prepare_image``).

    The image already carries everything a container needs — San2Patch's
    toolchain, the stripped history, the baseline build and the wrapper — so
    the main container and every Patcher container start identical and ready.

    Returns the container ID.
    """
    client = _get_client()
    container = client.containers.run(
        image,
        command="sleep infinity",
        detach=True,
        # ARVO images ship the upstream remotes.  Even with the local history
        # stripped, an online container lets an agent fetch the fix from
        # `repo_addr`.  The LLM API is called from the host, so the container
        # needs no network of its own.
        network_mode=CONTAINER_NETWORK_MODE,
        mem_limit=CONTAINER_MEM_LIMIT,
    )
    logger.info("Started container %s from image %s", container.short_id, image)
    return container.id


def prepare_image(
    project: str,
    local_id: int | str,
    fuzz_target: str,
    log_path: str = "",
) -> str:
    """Return the prepared image for a bug, building it on first use.

    The image is ``n132/arvo:<localId>-vul`` set up the way San2Patch's
    ``arvo-<localId>`` container is, with the bug built once by its build.py
    (``arvo.benchmark.prepare_container``), then committed.  Preparing in a
    throwaway container and starting every agent container from the commit
    keeps the network confined to setup, and makes the per-container cost a
    plain start instead of apt, clang-12 and a configure build each time.

    An existing image is reused as is; remove it to prepare again.  A file lock
    keeps concurrent solvers of the same bug from preparing it twice.  The full
    preparation log goes to *log_path* when given.
    """
    tag = get_prepared_image_name(PREPARED_IMAGE_REPO, local_id)
    client = _get_client()

    lock_path = os.path.join(tempfile.gettempdir(), f"contrafix-prepare-{local_id}.lock")
    with open(lock_path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            client.images.get(tag)
            return tag
        except docker.errors.ImageNotFound:
            pass

        build_py = os.path.join(
            ARVO_BENCHMARK_DIR, "projects", project, str(local_id), "build.py"
        )
        files = {
            build_py: BUILD_PY,
            INSTALL_DEPS_SCRIPT: f"{CONTRAFIX_DIR}/install-deps.sh",
            SETUP_LLVM_SCRIPT: f"{CONTRAFIX_DIR}/setup_llvm.py",
        }
        missing = [path for path in files if not os.path.isfile(path)]
        if missing:
            raise FileNotFoundError(
                f"Cannot prepare {project}-{local_id}: missing {', '.join(missing)}"
            )
        # Optional: without it install-deps.sh downloads the .deb itself.
        if os.path.isfile(E9PATCH_DEB):
            files[E9PATCH_DEB] = f"{CONTRAFIX_DIR}/tools/{os.path.basename(E9PATCH_DEB)}"

        base = get_image_name(local_id)
        logger.info("Preparing %s from %s (one-off; this can take a while)", tag, base)
        # Default network: apt, clang-12 and some dependency builds download.
        container = client.containers.run(
            base, command="sleep infinity", detach=True, mem_limit=CONTAINER_MEM_LIMIT,
        )
        try:
            exec_cmd(container.id, f"mkdir -p {CONTRAFIX_DIR}/tools")
            for src, dst in files.items():
                ok, msg = copy_to_container(container.id, src, dst)
                if not ok:
                    raise RuntimeError(f"Cannot copy {src} into {container.short_id}: {msg}")

            result = prepare_container(
                exec_cmd, container.id, project, local_id, fuzz_target, PREPARE_TIMEOUT,
            )
            if log_path:
                os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
                with open(log_path, "w", encoding="utf-8") as f:
                    f.write(result.output)
            if not result.ok:
                raise RuntimeError(
                    f"Preparing {tag} failed"
                    + (f" (log: {log_path})" if log_path else "")
                    + f":\n{result.output[-2000:]}"
                )

            repository, _, image_tag = tag.rpartition(":")
            container.commit(repository=repository, tag=image_tag)
            logger.info("Prepared %s", tag)
        finally:
            stop_container(container.id)
    return tag


def remove_prepared_image(local_id: int | str) -> None:
    """Delete a bug's prepared image; the ``n132/arvo`` base image is kept.

    Takes ``prepare_image``'s lock, so it cannot race a preparation of the same
    bug.  Every container of the instance must already be stopped.  Failures
    are logged, not raised: a leftover image costs disk, not correctness.
    """
    tag = get_prepared_image_name(PREPARED_IMAGE_REPO, local_id)
    lock_path = os.path.join(tempfile.gettempdir(), f"contrafix-prepare-{local_id}.lock")
    with open(lock_path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            _get_client().images.remove(tag)
            logger.info("Removed prepared image %s", tag)
        except docker.errors.ImageNotFound:
            pass
        except Exception as e:
            logger.warning("Could not remove prepared image %s: %s", tag, e)


def exec_cmd(
    container_id: str,
    cmd: str,
    timeout: int = DOCKER_EXEC_TIMEOUT,
) -> tuple[int, str, str]:
    """Execute a command inside a container.

    Returns (exit_code, stdout, stderr).
    """
    client = _get_client()
    container = client.containers.get(container_id)

    # Wrap in `timeout` so a hanging fuzz target cannot stall the pipeline.
    wrapped = f"timeout {timeout} bash -c {shlex.quote(cmd)}"
    exit_code, output = container.exec_run(
        ["bash", "-c", wrapped],
        demux=True,
        environment={"TIMEOUT": str(timeout)},
    )

    stdout = _clean_output(output[0].decode("utf-8", errors="replace")) if output[0] else ""
    stderr = _clean_output(output[1].decode("utf-8", errors="replace")) if output[1] else ""

    if exit_code == 124:
        stderr += f"\n[TIMEOUT] Command killed after {timeout}s"

    return exit_code, stdout, stderr


def read_file(container_id: str, path: str) -> str:
    """Read a file from inside the container using cat."""
    path = _resolve(container_id, path)
    exit_code, stdout, stderr = exec_cmd(container_id, f"cat '{path}'")
    if exit_code != 0:
        raise FileNotFoundError(
            f"Failed to read {path} in container: {stderr}"
        )
    return stdout


def read_file_bytes(container_id: str, path: str) -> bytes:
    """Read a file from inside the container without text decoding."""
    fd, tmp_path = tempfile.mkstemp()
    os.close(fd)
    try:
        result = subprocess.run(
            ["docker", "cp", f"{container_id}:{path}", tmp_path],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            msg = (result.stderr or result.stdout or "docker cp failed").strip()
            raise FileNotFoundError(
                f"Failed to read {path} in container: {msg}"
            )
        with open(tmp_path, "rb") as fh:
            return fh.read()
    finally:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass


def _resolve(container_id: str, path: str) -> str:
    """Resolve a relative path against the container's working directory.

    ARVO images do not agree on ``WorkingDir``: it is ``/src/<project>`` for
    libxml2 but plain ``/src`` for mruby, gpac and ffmpeg.  SEC-bench could
    assume relative paths landed in the project directory; here they must be
    resolved explicitly, or an agent's ``tree.c`` write lands in ``/src``.
    """
    if posixpath.isabs(path):
        return path
    exit_code, cwd, _ = exec_cmd(container_id, "pwd")
    if exit_code == 0 and cwd.strip():
        resolved = posixpath.join(cwd.strip(), path)
        logger.debug("Resolved relative path %s -> %s", path, resolved)
        return resolved
    return path


def write_file(container_id: str, path: str, content: str | bytes) -> None:
    """Write content to a file inside the container via ``docker cp``.

    Following MemRepair's approach: write to a host temp file, then use the
    ``docker cp`` CLI command to copy it into the container.  This avoids
    the ``put_archive`` SDK API which does not respect the container's
    WORKDIR and has caused silent write-to-wrong-path bugs.
    """
    path = _resolve(container_id, path)

    parent_dir = posixpath.dirname(path)
    exec_cmd(container_id, f"mkdir -p '{parent_dir}'")

    if isinstance(content, str):
        content_bytes = content.encode("utf-8")
    else:
        content_bytes = content

    fd, tmp_path = tempfile.mkstemp()
    try:
        os.write(fd, content_bytes)
        os.close(fd)
        result = subprocess.run(
            ["docker", "cp", tmp_path, f"{container_id}:{path}"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            logger.warning("docker cp failed: %s", result.stderr)
        else:
            logger.debug("Wrote %d bytes to %s", len(content_bytes), path)
    finally:
        os.unlink(tmp_path)


def copy_from_container(container_id: str, src_path: str, dst_path: str) -> tuple[bool, str]:
    """Copy a file from container to host via ``docker cp``.

    Returns ``(success, message)``.
    """
    os.makedirs(os.path.dirname(dst_path) or ".", exist_ok=True)
    result = subprocess.run(
        ["docker", "cp", f"{container_id}:{src_path}", dst_path],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        msg = (result.stderr or result.stdout or "docker cp failed").strip()
        logger.warning(
            "docker cp from container failed (%s -> %s): %s",
            src_path, dst_path, msg,
        )
        return False, msg
    return True, "ok"


def copy_to_container(container_id: str, src_path: str, dst_path: str) -> tuple[bool, str]:
    """Copy a host file into a container via ``docker cp``.

    Needed to move variant PoCs from the main container to the Patcher
    containers: a Patcher container is started from the image and therefore
    has only ``/tmp/poc``, not the variants the Mutator produced elsewhere.
    """
    result = subprocess.run(
        ["docker", "cp", src_path, f"{container_id}:{dst_path}"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        msg = (result.stderr or result.stdout or "docker cp failed").strip()
        logger.warning("docker cp to container failed (%s): %s", dst_path, msg)
        return False, msg
    return True, "ok"


def start_patcher_containers(image: str, count: int) -> list[str]:
    """Start *count* containers for parallel Patcher agents.

    Each Patcher builds and reproduces in its own container (``_patch_single``
    runs ``build_project`` + ``run_repro``), so these are full working
    environments, not read-only source mirrors.  *image* is the bug's prepared
    image, the same one the main container runs.

    Returns a list of container IDs.
    """
    ids: list[str] = []
    for i in range(count):
        cid = start_container(image)
        logger.info("Patcher container %d/%d: %s", i + 1, count, cid[:12])
        ids.append(cid)
    return ids


def stop_containers(container_ids: list[str]) -> None:
    """Stop and remove a batch of containers (best-effort)."""
    for cid in container_ids:
        stop_container(cid)


def stop_container(container_id: str) -> None:
    """Stop and remove a container."""
    client = _get_client()
    try:
        container = client.containers.get(container_id)
        container.stop(timeout=10)
        container.remove(force=True)
        logger.info("Stopped and removed container %s", container_id[:12])
    except docker.errors.NotFound:
        logger.warning("Container %s not found during cleanup", container_id[:12])
    except Exception as e:
        logger.warning("Error cleaning up container %s: %s", container_id[:12], e)


# ---------------------------------------------------------------------------
# ARVO-specific operations
# ---------------------------------------------------------------------------


def build_project(container_id: str) -> tuple[bool, str]:
    """Run ``arvo compile`` inside the container.

    In a prepared image that is San2Patch's ``build.py --skip-configure``
    rebuild, which writes the fuzz target to ``/out/<fuzz_target>``.

    Returns (success: bool, output: str).
    """
    exit_code, stdout, stderr = exec_cmd(
        container_id, BUILD_CMD, timeout=BUILD_TIMEOUT
    )
    combined = stdout + "\n" + stderr
    success = exit_code == 0
    if not success:
        logger.warning("Build failed (exit %d): %s", exit_code, combined[-500:])
    return success, combined


def run_repro(container_id: str) -> tuple[int, str]:
    """Run ``arvo`` and return (exit_code, combined_output).

    Always call ``build_project`` first when the source may have changed:
    ``arvo`` runs ``/out/<target>`` as last built and does not rebuild, so a
    stale binary silently reports "still crashing" for a patch that in fact
    fixed the bug.
    """
    exit_code, stdout, stderr = exec_cmd(container_id, REPRO_CMD)
    combined = stdout + "\n" + stderr
    return exit_code, combined


def build_and_repro(container_id: str) -> tuple[bool, int, str]:
    """Rebuild, then reproduce.  Returns (build_ok, repro_exit, output).

    The pairing that callers almost always want; using it removes the chance
    of judging a patch against the previous build's binary.
    """
    build_ok, build_out = build_project(container_id)
    if not build_ok:
        return False, -1, build_out
    exit_code, output = run_repro(container_id)
    return True, exit_code, output


def run_custom_repro(
    container_id: str,
    cmd: str,
) -> tuple[int, str]:
    """Run a custom repro command string.

    Args:
        container_id: The Docker container ID.
        cmd: The full command to execute, normally from
             ``ReproCommand.build_cmd`` (which re-exports the sanitizer
             options and invokes ``/out/<target>`` against a variant PoC).

    Returns (exit_code, combined_output).
    """
    exit_code, stdout, stderr = exec_cmd(container_id, cmd)
    combined = stdout + "\n" + stderr
    return exit_code, combined


def apply_patch(
    container_id: str,
    patch_content: str,
    project: str = "",
    project_root: str = "",
) -> tuple[bool, str]:
    """Apply a patch inside ``/src/<project>``.

    ARVO has no ``secb patch`` equivalent, so this runs ``git apply`` directly,
    trying progressively more permissive strategies (as PatchEval's port does).

    Returns (success: bool, output: str).
    """
    root = project_root or project_dir(project)
    write_file(container_id, PATCH_PATH, patch_content)

    strategies = [
        f"cd {root} && git apply --check {PATCH_PATH} && git apply {PATCH_PATH}",
        # The pipeline's own diffs have zero context (San2Patch's -U0, see
        # arvo.tools.source_diff), which git apply rejects without --unidiff-zero.
        f"cd {root} && git apply --unidiff-zero {PATCH_PATH}",
        f"cd {root} && git apply --3way {PATCH_PATH}",
        f"cd {root} && git apply -C0 {PATCH_PATH}",
        f"cd {root} && git apply -C0 --3way {PATCH_PATH}",
        f"cd {root} && patch -p1 < {PATCH_PATH}",
    ]

    outputs = []
    for i, cmd in enumerate(strategies):
        exit_code, stdout, stderr = exec_cmd(container_id, cmd)
        combined = stdout + "\n" + stderr
        if exit_code == 0:
            logger.info("Patch applied with strategy %d", i + 1)
            return True, combined
        outputs.append(f"--- strategy {i + 1} ---\n{combined}")
        logger.debug("Patch strategy %d failed: %s", i + 1, combined[-200:])

    logger.warning("All patch apply strategies failed")
    return False, "\n".join(outputs)


def reset_source(
    container_id: str,
    project: str = "",
    project_root: str = "",
) -> tuple[bool, str]:
    """Reset ``/src/<project>`` to its post-bootstrap state.

    Both steps are required:
      - ``git checkout -- .`` restores tracked modifications;
      - ``git clean -fd`` removes files the agent added.  A patch that adds
        files leaves them behind otherwise (the libxml2 gold patch adds four),
        and they would carry into the next attempt.

    Scoped to one directory on purpose.  ``/src`` is not a repository, and
    ``/src/*/`` holds the fuzzer toolchain and vendored dependency repos —
    cleaning those destroys the toolchain build.

    Returns (success: bool, output: str).
    """
    if project_root:
        cmd = f"cd {project_root} && git checkout -- . && git clean -fd; echo 'reset done'"
    else:
        cmd = reset_cmd(project)

    exit_code, stdout, stderr = exec_cmd(container_id, cmd)
    combined = stdout + "\n" + stderr
    success = exit_code == 0
    if not success:
        logger.warning("reset_source failed (exit %d): %s", exit_code, combined[-500:])
    return success, combined
