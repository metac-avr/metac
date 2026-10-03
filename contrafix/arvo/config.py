"""Global configuration for the ARVO solver."""

import os

MODEL_NAME = os.environ.get("SECBENCH_MODEL_NAME", "nvidia/Qwen3-Coder-480B-A35B-Instruct-NVFP4")
BASE_URL = os.environ.get("SECBENCH_BASE_URL", "http://localhost:5001/v1")
API_KEY = os.environ.get("SECBENCH_API_KEY", "s")
EMBEDDING_MODEL = os.environ.get("SECBENCH_EMBEDDING_MODEL", "text-embedding-3-small")
ENABLE_EMBEDDING_FALLBACK = os.environ.get("SECBENCH_ENABLE_EMBEDDING_FALLBACK", "1") == "1"
REASONING_EFFORT = os.environ.get("SECBENCH_REASONING_EFFORT", "none")
# Cap on the tokens a single completion may generate (`max_tokens`); 0 leaves it
# to the server.  The agents' answers are edits, commands and reports, so a few
# thousand tokens is plenty, and the cap keeps a runaway generation from
# spending a whole request budget.
MAX_TOKENS = int(os.environ.get("SECBENCH_MAX_TOKENS", "12800"))
# Seconds one completion request may take before the client gives up and retries it.  The
# OpenAI SDK's own default is 600: a request the server silently drops (seen under load,
# 47 times in one mruby run) then costs 10 minutes before the retry.  Normal turns take
# ~5s (99th percentile ~90s, 99.9th ~340s, measured over the rq3 logs), so 300 only
# re-sends the rare very long generation.  Retries are raised to match.
REQUEST_TIMEOUT = float(os.environ.get("SECBENCH_REQUEST_TIMEOUT", "300"))
REQUEST_MAX_RETRIES = int(os.environ.get("SECBENCH_REQUEST_MAX_RETRIES", "5"))


# Adversarial loop parameters.  Env-overridable so a cheap smoke run
# (1 round, 1 patcher, 2 variants) needs no code edit.
MAX_ADVERSARIAL_ROUNDS = int(os.environ.get("ARVO_MAX_ROUNDS", "3"))
MAX_MUTATION_VARIANTS = int(os.environ.get("ARVO_MUTATION_VARIANTS", "3"))
PATCHES_PER_ROUND = int(os.environ.get("ARVO_PATCHES_PER_ROUND", "2"))
PATCHER_TEMPERATURE = float(os.environ.get("ARVO_PATCHER_TEMPERATURE", "1"))
DOCKER_EXEC_TIMEOUT = int(os.environ.get("ARVO_DOCKER_EXEC_TIMEOUT", "300"))

# How long a single Docker API call may take.  docker-py's own default is 60
# seconds, which is fine for starting a container and far too short for
# committing one: prepare_image commits an ARVO container after apt, clang-12
# and a full configure build, and the daemon takes minutes to write that layer
# out.  The 60s default surfaced as a ReadTimeoutError from
# container.commit() -- on the local unix socket, nothing to do with a
# registry -- after the preparation had already succeeded.
DOCKER_API_TIMEOUT = int(os.environ.get("ARVO_DOCKER_API_TIMEOUT", "3600"))

# Timeout for every build after the prepared image's baseline build (pipeline
# gates and agent-triggered builds alike).  These are incremental
# `build.py --skip-configure` runs, but at San2Patch's `-j 1`, so
# the 300s that suited `arvo compile` at -j16 is too tight: a timeout here is
# reported to the agent as a build failure.
BUILD_TIMEOUT = int(os.environ.get("ARVO_BUILD_TIMEOUT", "1800"))

# ---------------------------------------------------------------------------
# MetaC build environment (San2Patch parity)
# ---------------------------------------------------------------------------

# MetaC checkout this package lives in (<root>/contrafix/arvo/config.py).
METAC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ARVO_BENCHMARK_DIR = os.path.join(METAC_ROOT, "benchmarks", "arvo")

# Container setup San2Patch's `arvo-<bug_id>` container gets from
# benchmarks/arvo/scripts/docker.py:checkout (install_dependency=True).
INSTALL_DEPS_SCRIPT = os.path.join(METAC_ROOT, "install-deps.sh")
SETUP_LLVM_SCRIPT = os.path.join(METAC_ROOT, "setup_llvm.py")
# install-deps.sh installs this from tools/ next to itself when present, and downloads
# it otherwise; copying it in keeps preparation off GitHub.
E9PATCH_DEB = os.path.join(METAC_ROOT, "tools", "e9patch_1.0.0_amd64.deb")

# The San2Patch environment is set up once per bug and committed as an image
# (<PREPARED_IMAGE_REPO>:<localId>), which every container of that bug then
# starts from; see docker_tools.prepare_image.  Setup (apt, clang-12, the
# configure build) needs the network, so it gets its own budget.
PREPARED_IMAGE_REPO = os.environ.get("ARVO_PREPARED_IMAGE_REPO", "contrafix-f2r/arvo")
PREPARE_TIMEOUT = int(os.environ.get("ARVO_PREPARE_TIMEOUT", "7200"))

# Remove a bug's prepared image once its instance is finished (whatever the
# outcome), to bound disk use; a later run prepares it again.  ffmpeg images
# add several GB each on top of the shared n132/arvo layers.
REMOVE_PREPARED_IMAGE = os.environ.get("ARVO_REMOVE_PREPARED_IMAGE", "0") == "1"

RESULTS_DIR = os.environ.get("ARVO_RESULTS_DIR", "./results_arvo")
# Wall-clock budget of one instance, in seconds; 0 (the default) means none.  The 7300s
# budget cut php-src runs off before the validation modes could differ.
INSTANCE_TIMEOUT = int(os.environ.get("ARVO_INSTANCE_TIMEOUT", "0"))

# After a patch passes the original PoC, run every PoC variant the Mutator has
# produced so far against it and count the patch as failed if any variant still
# triggers the original vulnerability type.  The failure is fed back to the next
# round like a failed PoC.  Applies to every PATCH_MODE: conv runs the variants
# in the Patcher's container, metapro against the binary-patched build.
# ContraFix as released verifies against the original PoC only; set 0 for that.
VARIANT_GATE = os.environ.get("ARVO_VARIANT_GATE", "1") == "1"

# How a patch is validated, as San2Patch's run-arvo.py --mode does:
#   conv      build the patched source and run the PoC against it (ContraFix's own way)
#   metapro   derive a metapro patch config from the diff, apply it to the instrumented
#             binary and run the PoC against that instead -- no source build
#   dyninst   compile the patched functions into a shared library, swap them into the
#             running target with Dyninst and run the PoC against that -- no source build
#   combined  metapro first, then dyninst when metapro cannot apply the patch, then conv
#             when dyninst cannot either
# metapro and combined need the bug's metapro-source/, metapro-out/ and arvo-<id>
# container; see arvo.metapro.  dyninst and combined need the arvo-<id> container checked
# out with checkout.py --setup-dyninst; see arvo.dyninst.
PATCH_MODE = os.environ.get("ARVO_PATCH_MODE", "conv")

# Budget for one metapro validation (config + binary patch + PoC run), whose PoC run
# alone gets 300s inside the container.
METAPRO_TIMEOUT = int(os.environ.get("ARVO_METAPRO_TIMEOUT", "900"))

# Budget for one dyninst validation: the libpatch build and the PoC run (180s inside
# the container), both twice when the whole-file retry kicks in.
DYNINST_TIMEOUT = int(os.environ.get("ARVO_DYNINST_TIMEOUT", "1200"))
# Budget for a bug's one-time dyninst setup: a full build of contrafix-dyninst-source
# and the PIC archive replaying every compile of it.
DYNINST_SETUP_TIMEOUT = int(os.environ.get("ARVO_DYNINST_SETUP_TIMEOUT", "7200"))

# Closed-loop retry limits
MAX_MUTATION_RETRIES = 0       # Retry mutation if 0 variants crash
MAX_PATCHER_RETRIES = 0        # Retry patcher if empty diff or build failure

# Agent tool-calling iterations (how many tool rounds each agent may take)
MUTATOR_MAX_TOOL_ITERS = 40
PATCHER_MAX_TOOL_ITERS = 40
ANALYZER_MAX_TOOL_ITERS = 60   # Analyzer reads source + inserts probes + builds + runs

# Maximum characters returned by a single tool result before truncation.
# 66000 (the SEC-bench value) is ~16.5k tokens, so a few large tool results
# exhaust a request budget.  Tool results are also what makes the *prompt*
# grow: they stay in the conversation and are re-sent on every later call, and
# measured over a 43-instance php run the prompt reached 121k tokens on one
# call, with 201 of 2447 calls above 50k.  Sanitizer reports — the output that
# actually must survive intact — measured at most ~3k characters, so 10000
# still keeps a 3x margin on those while bounding file and log dumps.
MAX_OUTPUT_LENGTH = int(os.environ.get("ARVO_MAX_OUTPUT_LENGTH", "10000"))

# Memory limit per container.  SEC-bench used 4g; ARVO builds are heavier
# (OSS-Fuzz base images with vendored dependencies).
CONTAINER_MEM_LIMIT = os.environ.get("ARVO_MEM_LIMIT", "16g")

# The agents never need the network: the LLM API is called from the host, and
# leaving the container online lets a Patcher fetch the upstream fix from
# `repo_addr` even after the local history is stripped (porting.md §7.0).
# Only the one-off image preparation runs online, before any agent exists.
CONTAINER_NETWORK_MODE = os.environ.get("ARVO_NETWORK_MODE", "none")

# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

# ARVO ships no HuggingFace dataset; instances come from MetaC's CSV.
OVERVIEW_CSV = os.environ.get(
    "ARVO_OVERVIEW_CSV", os.path.join(ARVO_BENCHMARK_DIR, "overview.csv"),
)

# Filters used by MetaC's own scripts; kept identical so the instance
# set matches the existing benchmark tooling.
ARVO_FILTERS = {
    "submodule_bug": "N",
    "language": "c",
    "patch url available?": "Y",
    "ubuntu version": 20,
}

# No project is excluded.  Builds go through each bug's build.py, which builds
# only that bug's fuzz target, so ffmpeg needs no special handling; its images
# are still 26.8GB each (a 23.6GB prebuilt /out layer).
ARVO_EXCLUDED_PROJECTS = set(
    p for p in os.environ.get("ARVO_EXCLUDED_PROJECTS", "").split(",") if p
)

# Docker image naming lives in arvo.benchmark (get_image_name); these exist
# for parity with the SEC-bench/PatchEval configs.
DOCKER_IMAGE_PREFIX = "n132/arvo"
DOCKER_IMAGE_TAG_VUL = "vul"
DOCKER_IMAGE_TAG_FIX = "fix"

# ============================================================================
# Ablation configuration (identical semantics to the SEC-bench runner)
# ============================================================================
#
#                    差分分析                 经验知识库
#   实验      PoC变异  崩溃分析      补丁修复经验  PoC变异实践经验
#   ─────────────────────────────────────────────────────────────────────────
#   Baseline    ✓        ✓          ✓            ✓          完整系统
#   E1          ✗        ✗          ✗            ✗          纯Patcher（最低基线）
#   E2          ✗        ✓          ✓            ✓          去掉变异
#   E3          ✓        ✗          ✓            ✓          去掉分析
#   E4          ✓        ✓          ✗            ✗          去掉全部经验
#   E5          ✓        ✓          ✗            ✓          只去掉Patcher经验
#   E6          ✓        ✓          ✓            ✗          只去掉Mutation经验
#
ABLATION_SKIP_MUTATOR = os.environ.get("ABLATION_SKIP_MUTATOR", "0") == "1"
ABLATION_SKIP_ANALYZER = os.environ.get("ABLATION_SKIP_ANALYZER", "0") == "1"
ABLATION_SKIP_PATCHER_EXP = os.environ.get("ABLATION_SKIP_PATCHER_EXP", "0") == "1"
ABLATION_SKIP_MUTATION_EXP = os.environ.get("ABLATION_SKIP_MUTATION_EXP", "0") == "1"
