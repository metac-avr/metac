"""Parse the repro command out of an ARVO container's ``/usr/bin/arvo``.

SEC-bench's ``secb_sh`` was a general shell script whose ``repro()`` body had
to be parsed heuristically.  ARVO's wrapper is far simpler: a generated,
27-line script with nine ``export`` lines and a run branch that is always a
single ``/out/<fuzz_target> /tmp/poc``.  Verified on five bugs across four
projects; the target always matched the ``fuzz_target`` column of
overview.csv.

The important consequence is that ``arvo run`` is unusable for mutated PoCs:
both the binary and ``/tmp/poc`` are hard-coded.  Running a variant means
re-creating the wrapper's environment and invoking the binary directly, which
is what :meth:`ReproCommand.build_cmd` emits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from arvo.benchmark import (
    ARVO_WRAPPER,
    OUT_DIR,
    POC_PATH,
    parse_wrapper_exports,
    parse_wrapper_run_command,
)


@dataclass
class ReproCommand:
    """Structured representation of an ARVO repro command."""

    binary: str                          # e.g. "/out/xml"
    args: str = ""                       # ARVO targets take only the PoC path
    poc_path: str = POC_PATH             # "/tmp/poc"
    poc_type: str = "binary"             # "text" | "binary" | "script"
    exports: list[str] = field(default_factory=list)
    cmd_template: str = ""               # full command with a {poc} placeholder

    def build_cmd(self, poc_path: str | None = None) -> str:
        """Full command string, optionally against a different PoC.

        Re-exports the sanitizer options from ``/usr/bin/arvo`` before running
        the target.  Sourcing the wrapper at run time (rather than baking in
        the parsed values) keeps the environment exact even if a bug's wrapper
        carries an option this parser does not model.
        """
        target = poc_path or self.poc_path
        if self.cmd_template:
            return self.cmd_template.replace("{poc}", target)
        parts = [self.binary]
        if self.args:
            parts.append(self.args)
        parts.append(target)
        return (
            f"source <(sed -n '/^export/p' {ARVO_WRAPPER}) && " + " ".join(parts)
        )

    @property
    def fuzz_target(self) -> str:
        """Bare target name (``/out/xml`` -> ``xml``)."""
        return self.binary.rsplit("/", 1)[-1] if self.binary else ""


# File extensions considered as text-based PoC
_TEXT_EXTENSIONS = {
    ".rb", ".js", ".py", ".c", ".cpp", ".h", ".txt", ".xml", ".html",
    ".css", ".json", ".yaml", ".yml", ".lua", ".pl", ".php", ".java",
    ".md", ".csv", ".ini", ".cfg", ".conf", ".smt2", ".smt", ".asm",
    ".s", ".rs", ".go", ".swift", ".ts",
}

_SCRIPT_EXTENSIONS = {".sh", ".bash"}

_BINARY_EXTENSIONS = {
    ".mp4", ".avi", ".mkv", ".mov", ".tiff", ".tif", ".bmp", ".gif",
    ".png", ".jpg", ".jpeg", ".webp", ".ico", ".pdf", ".doc", ".dwg",
    ".dxf", ".eps", ".ps", ".svg", ".wav", ".mp3", ".flac", ".ogg",
    ".zip", ".gz", ".bz2", ".tar", ".rar", ".7z", ".bin", ".dat",
    ".pcap", ".elf", ".wasm", ".o", ".so", ".a",
}


def _infer_poc_type(poc_path: str) -> str:
    """Infer PoC type from the file extension.

    ARVO's PoC is always ``/tmp/poc`` with no extension, so this virtually
    always returns "binary" — which is correct: OSS-Fuzz inputs are raw byte
    strings fed to ``LLVMFuzzerTestOneInput``, even for text formats.  The
    caller can override via ``sniff_poc_type`` once the file is readable.
    """
    lower = poc_path.lower()
    for ext in _SCRIPT_EXTENSIONS:
        if lower.endswith(ext):
            return "script"
    for ext in _TEXT_EXTENSIONS:
        if lower.endswith(ext):
            return "text"
    for ext in _BINARY_EXTENSIONS:
        if lower.endswith(ext):
            return "binary"
    return "binary"


def sniff_poc_type(poc_bytes: bytes) -> str:
    """Classify a PoC by content rather than by name.

    ARVO PoCs carry no extension, but many are in fact source text (mruby
    scripts, XML documents).  Telling the Mutator which it is decides whether
    it edits the file as text or patches bytes.
    """
    if not poc_bytes:
        return "binary"
    sample = poc_bytes[:4096]
    if b"\x00" in sample:
        return "binary"
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return "binary"
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return "text" if printable / len(sample) > 0.9 else "binary"


def parse_repro_command(
    wrapper_content: str,
    fuzz_target: str = "",
) -> ReproCommand:
    """Extract the repro command from ``/usr/bin/arvo``'s contents.

    *fuzz_target* is the ``fuzz_target`` column of overview.csv, used when the
    wrapper cannot be parsed.  Both agreed on every probed bug, so the
    fallback is a safety net rather than a routine path.
    """
    binary, poc_path = parse_wrapper_run_command(wrapper_content)
    exports = parse_wrapper_exports(wrapper_content)

    if not binary and fuzz_target:
        binary = f"{OUT_DIR}/{fuzz_target}"
    if not poc_path:
        poc_path = POC_PATH

    cmd_template = (
        f"source <(sed -n '/^export/p' {ARVO_WRAPPER}) && {binary} {{poc}}"
        if binary else ""
    )

    return ReproCommand(
        binary=binary,
        args="",
        poc_path=poc_path,
        poc_type=_infer_poc_type(poc_path),
        exports=exports,
        cmd_template=cmd_template,
    )


_LEGACY_TESTCASE_RE = re.compile(r"/testcase/(\S*)")


def normalize_legacy_path(path: str) -> str:
    """Rewrite a stray SEC-bench ``/testcase/...`` path to ARVO's ``/tmp/...``.

    Agents occasionally echo paths from examples in their prompts.  Rather
    than let the resulting command fail with a confusing ENOENT, rewrite it.
    """
    return _LEGACY_TESTCASE_RE.sub(r"/tmp/\1", path)
