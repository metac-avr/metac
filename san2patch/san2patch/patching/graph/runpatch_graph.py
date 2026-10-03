import os
import shlex
import time
from functools import partial
from typing import Annotated, Tuple

from aim import Run

from langgraph.graph import StateGraph
from langsmith import traceable
from pydantic import BaseModel

from san2patch.consts import (
    FIX_BUILD_ERROR_RETRIES,
    GENPATCH_MAX_LINE,
    GENPATCH_MIN_LINE,
)
from san2patch.context import (
    San2PatchContextManager,
    San2PatchLogger,
    San2PatchTemperatureManager,
)
from san2patch.patching.graph.howtofix_graph import (
    FixStrategyState,
    HowToFixState,
)
from san2patch.patching.graph.wheretofix_graph import (
    LocationState,
)
from san2patch.patching.llm.base_llm_patcher import BaseLLMPatcher, ask
from san2patch.patching.llm.openai_llm_patcher import GPT4oPatcher
from san2patch.patching.prompt.patch_prompts import (
    FixBuildErrorPrompt,
    FixErrorModel,
    PatchCodeBranchPrompt,
)
from san2patch.patching.validator import (
    ArvoValidator,
    FinalTestValidator,
    extract_patched_function_locations,
)
from san2patch.utils.enum import ExperimentResEnum
from san2patch.utils.reducers import *
from san2patch.patching import metapro_patch as metapro


def normalize_no_index_diff(diff: str, original_dir: str, patched_dir: str) -> str:
    """Rewrite the path prefixes of a `git diff --no-index` between two
    directories so the result applies with `git apply -p1`.

    `git diff --no-index a b` embeds the directory names in the prefixes
    (e.g. ``a/<original_dir>/sub/f.c`` / ``b/<patched_dir>/sub/f.c``). This
    strips the directory component back to plain ``a/<relpath>`` /
    ``b/<relpath>``, matching the format produced by `git diff` inside a repo.
    """
    orig_p = original_dir.strip("/")
    patched_p = patched_dir.strip("/")

    lines = []
    for line in diff.splitlines():
        if line.startswith(f"--- a/{orig_p}/"):
            line = "--- a/" + line[len(f"--- a/{orig_p}/") :]
        elif line.startswith(f"+++ b/{patched_p}/"):
            line = "+++ b/" + line[len(f"+++ b/{patched_p}/") :]
        elif line.startswith("diff --git "):
            line = line.replace(f"a/{orig_p}/", "a/").replace(f"b/{patched_p}/", "b/")
        lines.append(line)

    return "\n".join(lines) + ("\n" if diff.endswith("\n") else "")


SOURCE_FILE_EXTENSIONS = (".c", ".cc", ".cpp", ".h")

USE_VERIFIER = False


def filter_diff_by_extension(diff: str, extensions=SOURCE_FILE_EXTENSIONS) -> str:
    """Keep only the per-file sections of a unified git diff that *modify* an
    existing source file whose path ends with one of ``extensions``.

    Sections for non-source files (build files, configs, generated artifacts,
    ...) are dropped, as are pure additions or removals (where one of the
    ``---``/``+++`` headers is ``/dev/null``).

    A git diff is a concatenation of per-file sections that each start with a
    ``diff --git`` line, so we split on that boundary and decide per section
    using its ``---``/``+++`` headers.
    """
    sections = []
    current = []
    for line in diff.splitlines(keepends=True):
        if line.startswith("diff --git ") and current:
            sections.append(current)
            current = []
        current.append(line)
    if current:
        sections.append(current)

    def header_path(line: str) -> str:
        # Strip the "--- "/"+++ " marker and any trailing tab/timestamp.
        return line[4:].split("\t", 1)[0].strip()

    kept = []
    for section in sections:
        old_path = new_path = None
        for line in section:
            # Headers precede the first hunk; stop here so content lines such
            # as "--- foo" (a removed line beginning with "--") aren't mistaken
            # for headers.
            if line.startswith("@@"):
                break
            if line.startswith("--- "):
                old_path = header_path(line)
            elif line.startswith("+++ "):
                new_path = header_path(line)

        # Skip pure additions/removals and any section missing a header.
        if not old_path or not new_path:
            continue
        if old_path == "/dev/null" or new_path == "/dev/null":
            continue

        path = new_path[2:] if new_path.startswith(("a/", "b/")) else new_path
        if path.endswith(extensions):
            kept.append("".join(section))

    return "".join(kept)


class GenPatchState(BaseModel):
    fix_strategy: Annotated[FixStrategyState, fixed_value] = FixStrategyState()
    patch_result: Annotated[str, fixed_value] = ""

    def validate_self(self):
        for loc in self.fix_strategy.fix_location.locations:
            if not loc.original_code:
                raise ValueError("Original code is empty")


class GenPatchCandidateState(BaseModel):
    genpatch_candidate: Annotated[list[GenPatchState], fixed_value] = []


class RunResultState(BaseModel):
    ret_code: Annotated[bool, fixed_value] = False
    err_msg: Annotated[str | bool, fixed_value] = ""


class PatchTestState(RunResultState):
    attempt_id: Annotated[str, fixed_value] = ""


class BuildTestState(RunResultState): ...


class VulnerabilityTestState(RunResultState): ...


class FunctionalityTestState(RunResultState): ...

class VerifyState(RunResultState): ...


class ValidatorState(BaseModel):
    vuln_data: Annotated[dict, fixed_value] = {}
    project: Annotated[str, fixed_value] = ""
    bug_id: Annotated[int, fixed_value] = 0
    binary_path: Annotated[str, fixed_value] = ""
    poc_path: Annotated[str, fixed_value] = ""
    work_dir: Annotated[str, fixed_value] = ""
    san: Annotated[str, fixed_value] = ""
    original_dir: Annotated[str, fixed_value] = ""
    # run-arvo.py --mode. 'conv': apply the patch, rebuild, then run the
    # vulnerability and functionality tests. 'metapro': derive a metapro patch
    # config, apply it at binary level and run the metapro PoC test in place of
    # the rebuild and vulnerability test; the functionality test still runs.
    patch_mode: Annotated[str, fixed_value] = "conv"
    # run-arvo.py -o/--output: name of the per-bug output directory that
    # everything below work_dir is written to.
    output_dir: Annotated[str, fixed_value] = "san2patch"
    patch_success: Annotated[list[str], fixed_value]
    # Wall-clock seconds consumed per step, plus each attempt's outcome under
    # "result". Nested so attempts map to the strategy that produced them:
    #   {"strategy_<idx>": {"generate": <s>,
    #                        "attempts": {"<genpatch_id>_<retry_cnt>":
    #                                     {"patch": <s>, "build": <s>,
    #                                      "vulnerability": <s>,
    #                                      "functionality": <s>,
    #                                      "result": <ExperimentResEnum value>}}}}
    time_records: Annotated[dict, fixed_dict] = {}


class FixBuildState(BaseModel):
    build_ret: Annotated[bool, fixed_value] = False
    build_err_msg: Annotated[str, fixed_value] = ""
    original_functions: Annotated[list[str], fixed_value] = []
    patched_functions: Annotated[list[str], fixed_value] = []


# metapro states
class MetaproPatchGenState(RunResultState):
    metapro_gen_time: Annotated[float, fixed_value] = 0.0
    patch_config: Annotated[list[dict], fixed_value] = []
    metapro_patch_gen_result: Annotated[bool, fixed_value] = False
    patch_template_usage: Annotated[str, fixed_value] = ""

class MetaproBinaryPatchState(RunResultState):
    metapro_patch_result: Annotated[bool, fixed_value] = False
    metapro_patch_time: Annotated[float, fixed_value] = 0.0

class MetaproTestState(RunResultState):
    metapro_test_result: Annotated[bool, fixed_value] = False
    metapro_test_time: Annotated[float, fixed_value] = 0.0

# dyninst states
class DyninstBinaryPatchState(RunResultState):
    dyninst_patch_result: Annotated[bool, fixed_value] = False
    # Timed per step rather than as one number: the first dyninst_patch() of a bug
    # also builds the project-wide PIC archive, which dwarfs everything else (ffmpeg:
    # ~1.8 h against ~26 s for a later call), so a single total hides where the cost
    # actually is. The three sum to what dyninst_patch_time used to hold.
    dyninst_extract_time: Annotated[float, fixed_value] = 0.0
    dyninst_patch_time: Annotated[float, fixed_value] = 0.0
    dyninst_test_time: Annotated[float, fixed_value] = 0.0
    # Whether the rewrite itself went in, independently of what the PoC then did.
    # ret_code folds both together (it is the PoC verdict once the patch applied),
    # so combined mode needs this to tell "try the next approach" from "this patch
    # is wrong" -- only the former is a reason to fall back.
    dyninst_applied: Annotated[bool, fixed_value] = False

# All
class RunPatchState(
    HowToFixState,
    GenPatchState,
    GenPatchCandidateState,
    PatchTestState,
    BuildTestState,
    VulnerabilityTestState,
    FunctionalityTestState,
    VerifyState,
    ValidatorState,
    MetaproPatchGenState,
    MetaproBinaryPatchState,
    MetaproTestState,
    DyninstBinaryPatchState,
): ...


# Input
class InputState(HowToFixState): ...


# Output
class OutputState(GenPatchCandidateState, ValidatorState): ...


# Outcome of one validation step inside RunPatch's retry loop. The step helpers
# return one of these and the caller turns them into control flow: _RETRY re-runs
# the same genpatch (the build-error fix loop), _ABORT gives up on it.
_OK, _RETRY, _ABORT = "ok", "retry", "abort"


def get_code_source(
    fix_location: LocationState,
    src_dir,
    min_line=GENPATCH_MIN_LINE,
    max_line=GENPATCH_MAX_LINE,
):
    cm = San2PatchContextManager("C", src_dir=src_dir)
    code_context = cm.get_code_context(
        file_name=fix_location.file_name,
        line=int(fix_location.fix_line),
        min_line=min_line,
        max_line=max_line,
        sibling=False,
    )
    code_block = code_context.code
    code_line = cm.get_code_lines(
        file_name=fix_location.file_name,
        line_start=int(fix_location.fix_line) - 2,
        line_end=int(fix_location.fix_line) + 2,
    )

    return code_block, code_line, code_context.func_def, code_context.func_ret


def generate_runpatch_graph(
    LLMPatcher: BaseLLMPatcher = GPT4oPatcher, branch_num: int = 3
):
    graph_name = "runpatch"
    runpatch_builder = StateGraph(RunPatchState)
    temperature = San2PatchTemperatureManager()
    llm: BaseLLMPatcher = LLMPatcher(temperature=temperature.default)
    llm_gen: BaseLLMPatcher = LLMPatcher(temperature=temperature.genpatch)
    logger = San2PatchLogger().logger

    def get_original_code(state: RunPatchState, fix_location: LocationState):
        original_code, replace_line, func_def, func_ret = get_code_source(
            fix_location, state.package_location
        )

        # assert replace_line in original_code, f"replace_line: {replace_line} not in original_code: {original_code}"
        if replace_line not in original_code:
            original_code, replace_line, func_def, func_ret = get_code_source(
                fix_location,
                state.package_location,
                min_line=GENPATCH_MIN_LINE // 2,
                max_line=GENPATCH_MAX_LINE // 2,
            )

            if replace_line not in original_code:
                return original_code, original_code, func_def, func_ret

        fixme_replace_line = (
            f"// FIXME: Crash {state.vuln_info_final.type}\n {replace_line}"
        )

        replace_code = original_code.replace(replace_line, fixme_replace_line)

        return original_code, replace_code, func_def, func_ret

    def branch_generate_patch(state: RunPatchState, genpatch_state: GenPatchState):
        # Clear all original code
        for loc in genpatch_state.fix_strategy.fix_location.locations:
            loc.original_code = ""

        # Create new mock genpatch states
        new_genpatch_states = [
            genpatch_state.model_copy(deep=True) for _ in range(branch_num)
        ]

        # For each patch location, generate a new patch
        for loc_idx, loc in enumerate(
            genpatch_state.fix_strategy.fix_location.locations
        ):
            try:
                original_code, replace_code, func_def, func_ret = get_original_code(
                    state, loc
                )
            except Exception as e:
                logger.error(
                    f"Error in getting original code in {loc.file_name}: {e}. skipping fix location..."
                )
                continue

            for patch_idx in range(branch_num):
                loc = new_genpatch_states[
                    patch_idx
                ].fix_strategy.fix_location.locations[loc_idx]
                loc.original_code = original_code
                loc.func_def = func_def
                loc.func_ret = func_ret

            prompt_cls = partial(PatchCodeBranchPrompt, branch_num=branch_num)

            try:
                patches = ask(
                    llm_gen,
                    prompt_cls,
                    {
                        **state.model_dump(),
                        "fix_strategy": genpatch_state.fix_strategy,
                        "original_function": replace_code,
                        "func_def": func_def,
                        "func_ret": func_ret,
                    },
                )
            except Exception as e:
                logger.warning(
                    f"Error in generating patch: {e}. Set patched code to original code."
                )
                for patch_idx in range(branch_num):
                    new_genpatch_states[patch_idx].fix_strategy.fix_location.locations[
                        loc_idx
                    ].patched_code = (
                        new_genpatch_states[patch_idx]
                        .fix_strategy.fix_location.locations[loc_idx]
                        .original_code
                    )
            else:
                for patch_idx in range(branch_num):
                    new_genpatch_states[patch_idx].fix_strategy.fix_location.locations[
                        loc_idx
                    ].patched_code = patches.__getattribute__(
                        f"patched_code_{patch_idx + 1}"
                    )

        # Remove invalid genpatch states
        final_genpatch_states = []
        for new_state in new_genpatch_states:
            try:
                new_state.validate_self()
                final_genpatch_states.append(new_state)
            except Exception as e:
                logger.error(
                    f"Error in validating genpatch state: {e}. skipping genpatch..."
                )
                continue

        return final_genpatch_states

    def genpatch_per_strategy(state: RunPatchState, fix_strategy: FixStrategyState):
        genpatch_state = GenPatchState(fix_strategy=fix_strategy)
        branched_genpatch_states = branch_generate_patch(state, genpatch_state)

        state.genpatch_candidate.extend(branched_genpatch_states)

        return branched_genpatch_states

    @traceable(type="validator")
    def test_patch(
        state: RunPatchState,
        genpatch_state: GenPatchState,
        genpatch_id: int,
        pv: FinalTestValidator | ArvoValidator,
        retry_cnt: int = 0,
    ) -> PatchTestState:
        # Rest repo dir
        if (isinstance(pv, FinalTestValidator)):
            pv.run_cmd("git reset --hard", cwd=state.package_location, quiet=True)

        # Relative paths of the files this attempt actually modifies; used below
        # to diff only those files instead of walking the whole tree.
        patched_rel_files: list[str] = []

        # Post-process for small bug in the code
        for fix_loc in genpatch_state.fix_strategy.fix_location.locations:
            file_name = fix_loc.file_name
            original_function = fix_loc.original_code
            patched_function = fix_loc.patched_code

            # Post-process for small bug in the code
            if San2PatchContextManager().context_mode == "line":
                original_lines = [
                    line.strip() for line in original_function.splitlines()
                ]
                patched_lines = [line.strip() for line in patched_function.splitlines()]

                if (
                    original_lines[0] != patched_lines[0]
                    or original_lines[-1] != patched_lines[-1]
                ):
                    logger.warning(
                        "Original and patched codes do not match. Finding patched codes in the original code..."
                    )

                    try:
                        start_idx = original_lines.index(patched_lines[0])
                        end_idx = (
                            len(original_lines)
                            - 1
                            - original_lines[::-1].index(patched_lines[-1])
                        )

                        original_function = "\n".join(
                            original_function.splitlines()[start_idx : end_idx + 1]
                        )
                    except ValueError:
                        logger.warning("Patched code not found in the original code.")
            else:
                temp_patched_function = patched_function.strip()
                if (original_function.count("{") == original_function.count("}")) and (
                    patched_function.count("{") == patched_function.count("}")
                ):
                    if original_function[0] == "{" and temp_patched_function[0] != "{":
                        patched_function = "{\n" + patched_function + "\n}"

            # patched_function = patched_function.strip()
            if file_name[0] == "/" or file_name[0] == "\\":
                file_name = file_name[1:]

            if file_name not in patched_rel_files:
                patched_rel_files.append(file_name)

            with open(os.path.join(state.package_location, file_name), "r") as f:
                source_code = f.read()

            patched_code = ""
            if source_code.find(original_function):
                patched_code = source_code.replace(original_function, patched_function)

            with open(os.path.join(state.package_location, file_name), "w") as f:
                f.write(patched_code)

        # Unique id for this attempt; retry_cnt distinguishes the intermediate
        # patches produced by the build-error fix retries (each retry mutates
        # genpatch_state's patched_code), so every generated patch is kept.
        attempt_id = f"{genpatch_id}_{retry_cnt}"

        # Generate patch using "git diff"
        if isinstance(pv, FinalTestValidator):
            patch_diff_file = os.path.join(state.diff_stage_dir, state.vuln_id)
            pv.run_cmd(
                f"git diff --patch > {patch_diff_file}_{attempt_id}.diff",
                cwd=state.package_location,
            )
            pv.run_cmd(
                f"git diff --patch > {patch_diff_file}.diff",
                cwd=state.package_location,
            )
        else:
            patch_diff_file = os.path.join(state.diff_stage_dir, 'cur-patch')
            attrs_file = os.path.join(state.diff_stage_dir, '.gitattributes-cpp')
            with open(attrs_file, 'w') as f:
                f.write('* diff=cpp\n')

            diff_parts = []
            for rel in patched_rel_files:
                if not rel.endswith(SOURCE_FILE_EXTENSIONS):
                    continue
                orig_file = os.path.join(state.original_dir, rel)
                patched_file = os.path.join(state.package_location, rel)
                _, part, _ = pv.run_cmd(
                    f"git -c core.attributesFile={shlex.quote(attrs_file)} diff --no-index -U0 --patch {shlex.quote(orig_file)} {shlex.quote(patched_file)}",
                    cwd=state.package_location,
                    pipe=True,
                    expect_error=True,
                )
                if part:
                    diff_parts.append(part)
            diff_out = "".join(diff_parts)
            diff_out = normalize_no_index_diff(
                diff_out, state.original_dir, state.package_location
            )
            # Keep only source files in the diff (drop build/config/etc.).
            diff_out = filter_diff_by_extension(diff_out)
            with open(f"{patch_diff_file}_{attempt_id}.diff", "w") as f:
                f.write(diff_out)
            with open(f"{patch_diff_file}.diff", "w") as f:
                f.write(diff_out)

        # Setup Patch Validator
        if isinstance(pv, FinalTestValidator):
            pv.setup()

        # Apply patch
        ret_code, err_msg = pv.patch()
        if err_msg is None:
            err_msg = ""

        if not ret_code:
            pv.logger.warning("Patch failed.")
            genpatch_state.patch_result = state.patch_success[genpatch_id] = (
                ExperimentResEnum.PATCH_FAILED.value
            )

        return PatchTestState(ret_code=ret_code, err_msg=err_msg, attempt_id=attempt_id)

    @traceable(type='validator')
    def metapro_patch_gen(
        state: RunPatchState,
        pv: FinalTestValidator | ArvoValidator,
    ) -> MetaproPatchGenState:
        # Generate metapro patch config
        pv.logger.info("Generating metapro patch config.")
        patch_diff_file = os.path.join(state.diff_stage_dir, 'cur-patch')
        patch_config, metapro_gen_time, has_replace, has_insert = metapro.gen_patch_config(
            project=state.project,
            bug_id=state.bug_id,
            diff_file_path=f"{patch_diff_file}.diff",
            source_path=os.path.join(pv.work_dir, 'metapro-source'),
            config_output_path=f'{patch_diff_file}_{state.attempt_id}.json',
            prev_location=None,
            output_dir=state.output_dir,
        )
        if has_replace and has_insert:
            patch_usage = 'both'
        elif has_replace:
            patch_usage = 'replace'
        elif has_insert:
            patch_usage = 'insert'
        else:
            patch_usage = '-'

        if patch_config is None:
            pv.logger.warning("Metapro patch generation failed.")
            return MetaproPatchGenState(ret_code=False, metapro_gen_time=metapro_gen_time,
                                        err_msg="Metapro patch config generation failed.",
                                        patch_template_usage=patch_usage)

        return MetaproPatchGenState(ret_code=True, metapro_gen_time=metapro_gen_time,
                                    patch_config=patch_config, err_msg='',
                                    patch_template_usage=patch_usage)

    @traceable(type="validator")
    def test_build(
        state: RunPatchState,
        genpatch_state: GenPatchState,
        genpatch_id: int,
        pv: FinalTestValidator | ArvoValidator,
    ) -> BuildTestState:
        if isinstance(pv, FinalTestValidator):
            ret_code, err_msg = pv.build_test()
        else:
            ret_code, err_msg = pv.build_test(state.san)
        if err_msg is None:
            err_msg = ""

        if not ret_code:
            pv.logger.warning("Build test failed.")
            genpatch_state.patch_result = state.patch_success[genpatch_id] = (
                ExperimentResEnum.BUILD_FAILED.value
            )

            original_functions = [
                loc.original_code
                for loc in genpatch_state.fix_strategy.fix_location.locations
            ]
            patched_functions = [
                loc.patched_code
                for loc in genpatch_state.fix_strategy.fix_location.locations
            ]

            fix_build_state = FixBuildState(
                build_ret=ret_code,
                build_err_msg=err_msg,
                original_functions=original_functions,
                patched_functions=patched_functions,
            )

            try:
                fixed_res: FixErrorModel = ask(
                    llm, FixBuildErrorPrompt, fix_build_state
                )
            except Exception as e:
                logger.warning(f"Error in fixing build error: {e}. skipping...")
            else:
                for idx, patched_function in enumerate(
                    fixed_res.fixed_patched_functions
                ):
                    genpatch_state.fix_strategy.fix_location.locations[
                        idx
                    ].patched_code = patched_function

        return BuildTestState(ret_code=ret_code, err_msg=err_msg)

    @traceable(type='validator')
    def metapro_binary_patch(
        state: RunPatchState,
        pv: FinalTestValidator | ArvoValidator,
    ) -> MetaproBinaryPatchState:
        pv.logger.info("Starting metapro binary patch.")
        result, metapro_patch_time, output = pv.metapro_patch(patch_config_path=state.patch_config)
        if not result:
            pv.logger.warning("Metapro binary patch failed.")
        return MetaproBinaryPatchState(ret_code=result, metapro_patch_time=metapro_patch_time,
                                       err_msg=output)

    @traceable(type="validator")
    def dyninst_binary_patch(
        state: RunPatchState,
        pv: FinalTestValidator | ArvoValidator,
    ) -> DyninstBinaryPatchState:
        """Apply the patch via Dyninst function replacement, then run the PoC
        against the rewritten process -- combines pv.dyninst_patch() and
        pv.dyninst_test() into the single call slot do_dyninst() has (where
        do_metapro() has three: metapro_patch_gen/metapro_binary_patch/
        metapro_test).

        Locations are derived directly from this attempt's cur-patch.diff
        (the LLM-generated patch, same file metapro_patch_gen() reads)
        against pv.source_dir -- unlike metapro, dyninst replaces whole
        functions, so it needs no separate AST-diff config step.
        """
        t0 = time.time()
        diff_path = os.path.join(state.diff_stage_dir, 'cur-patch.diff')
        locations = extract_patched_function_locations(diff_path, pv.source_dir)
        extract_time = time.time() - t0
        if not locations:
            pv.logger.warning("Dyninst: no patched function(s) could be resolved from cur-patch.diff.")
            return DyninstBinaryPatchState(ret_code=False, dyninst_applied=False,
                                           dyninst_extract_time=extract_time,
                                           err_msg="no patched function(s) resolved from cur-patch.diff")

        # The global-data sync wrapper (see _DYN_RUNTIME_C in validator.py, and dyninst_patch()'s own
        # docstring) is off by default now: a raw byte copy of a global whose type holds a heap
        # pointer duplicates that pointer into both copies, and whichever side frees and replaces it,
        # the sync can hand the other side a stale value it later frees again -- confirmed on
        # php-src/42531112 (the wrapper made a call never return) and independently on
        # libxml2/42517254 (an already-verified patch double-freed, in unrelated error-reporting code
        # the patch never touches, only with the wrapper on). Real accuracy loss remains when it's off
        # and a patched function genuinely needs a global initialised at runtime, but a spurious
        # result is worse than that gap.

        def _once(force_whole_file: bool) -> Tuple[bool, bool, float, float, str]:
            """Returns (applied, ok, patch_time, test_time, output). `applied` is False
            only when the rewrite could not be put in place; `ok` is then meaningless
            and no test ran, so its time is 0."""
            patch_ok, patch_time, patch_output = pv.dyninst_patch(
                locations, force_whole_file=force_whole_file)
            if not patch_ok:
                return False, False, patch_time, 0.0, patch_output
            test_ok, test_time, test_output = pv.dyninst_test(locations)
            return True, test_ok, patch_time, test_time, patch_output + '\n' + test_output

        applied, ok, patch_time, test_time, output = _once(force_whole_file=False)
        # Retry once, forcing every location to compile whole-file, if this
        # failed for a MECHANISM reason rather than a genuine test verdict --
        # a clean extraction compile can still be missing something outside
        # its own closure and only fail later, either at dyninst_patch()'s
        # own final link or at dyninst_test()'s loadLibrary()/runtime symbol
        # resolution (see build_libpatch()'s docstring in validator.py). A
        # genuine crash/vuln-test verdict from dyninst_test() never contains
        # either signature, so this never masks or re-rolls a real result --
        # only retries cases that never got one in the first place.
        if not ok and ('FAILED:' in output or 'symbol lookup error:' in output):
            retry_applied, retry_ok, retry_patch, retry_test, retry_output = _once(force_whole_file=True)
            output += '\n[retry: forced whole-file compile for every location]\n' + retry_output
            # Both attempts are real work, so the retry adds to each bucket.
            patch_time += retry_patch
            test_time += retry_test
            applied, ok = retry_applied, retry_ok

        if not applied:
            pv.logger.warning("Dyninst could not apply the patch.")
        elif not ok:
            pv.logger.warning("Dyninst applied the patch but the PoC still crashed.")
        return DyninstBinaryPatchState(ret_code=ok, dyninst_applied=applied,
                                       dyninst_extract_time=extract_time,
                                       dyninst_patch_time=patch_time,
                                       dyninst_test_time=test_time, err_msg=output)

    @traceable(type="validator")
    def test_vulnerability(
        state: RunPatchState,
        genpatch_state: GenPatchState,
        genpatch_id: int,
        pv: FinalTestValidator | ArvoValidator,
    ) -> VulnerabilityTestState:
        ret_code, err_msg = pv.vulnerability_test()
        if err_msg is None:
            err_msg = ""

        if not ret_code:
            pv.logger.warning("Vulnerability test failed.")
            genpatch_state.patch_result = state.patch_success[genpatch_id] = (
                ExperimentResEnum.VULN_FAILED.value
            )

        return VulnerabilityTestState(ret_code=ret_code, err_msg=err_msg)

    @traceable(type="validator")
    def metapro_test(
        state: RunPatchState,
        pv: FinalTestValidator | ArvoValidator,
    ) -> MetaproTestState:
        pv.logger.info("Starting metapro test.")
        result, test_time, output = pv.metapro_test(patch_config_path=state.patch_config)
        if not result:
            pv.logger.warning("Metapro test failed.")
        return MetaproTestState(ret_code=result, metapro_test_time=test_time, err_msg=output)

    @traceable(type="validator")
    def test_functionality(
        state: RunPatchState,
        genpatch_state: GenPatchState,
        genpatch_id: int,
        pv: FinalTestValidator | ArvoValidator,
    ) -> FunctionalityTestState:
        ret_code, err_msg = pv.functionality_test()
        if err_msg is None:
            err_msg = ""

        if not ret_code:
            pv.logger.warning("Functionality test failed.")
            genpatch_state.patch_result = state.patch_success[genpatch_id] = (
                ExperimentResEnum.FUNC_FAILED.value
            )
        elif not USE_VERIFIER:
            pv.logger.critical(
                f"Congratulations! You have successfully patched the {state.vuln_id} vulnerability!"
            )
            genpatch_state.patch_result = state.patch_success[genpatch_id] = (
                ExperimentResEnum.SUCCESS.value
            )

        return FunctionalityTestState(ret_code=ret_code, err_msg=err_msg)
    
    @traceable(type='validator')
    def verify_patch(
        state: RunPatchState,
        genpatch_state: GenPatchState,
        genpatch_id: int,
        pv: FinalTestValidator | ArvoValidator,
    ) -> VerifyState:
        ret_code, err_msg = pv.verify()

        if isinstance(err_msg, bool) and err_msg:
            pv.logger.critical(
                f"Congratulations! You have successfully patched the {state.vuln_id} vulnerability!"
            )
            genpatch_state.patch_result = state.patch_success[genpatch_id] = (
                ExperimentResEnum.SUCCESS.value
            )
        elif isinstance(err_msg, str) and err_msg == 'partial':
            # Partial is also success
            pv.logger.critical(
                f"Congratulations! You have successfully patched the {state.vuln_id} vulnerability!"
            )
            genpatch_state.patch_result = state.patch_success[genpatch_id] = (
                ExperimentResEnum.SUCCESS.value
            )
        else:
            pv.logger.info("Verification failed.")
            genpatch_state.patch_result = state.patch_success[genpatch_id] = (
                ExperimentResEnum.VERIFY_FAILED.value
            )

        return VerifyState(ret_code=ret_code, err_msg=err_msg)

    def RunPatch(state: RunPatchState):
        if state.bug_id == 0:
            pv = FinalTestValidator(
                state.vuln_data,
                state.diff_stage_dir.split("/")[-1],
                state.experiment_name,
            )
        else:
            pv = ArvoValidator(
                state.project,
                state.bug_id,
                state.work_dir,
                state.binary_path,
                state.poc_path,
                state.diff_stage_dir.split("/")[-1],
                output_dir=state.output_dir,
            )

        def record_time(target: dict, step: str, fn):
            # Time a single step and record its wall-clock seconds into the
            # given dict, even if the step raises (e.g. build test errors).
            start = time.perf_counter()
            try:
                return fn()
            finally:
                target[step] = time.perf_counter() - start

        for strat_idx, fix_strategy in enumerate(state.fix_strategy_final):
            # Each strategy owns its generation time and the attempts it
            # produced, so attempt_key -> strategy is recoverable by nesting.
            strat_rec = state.time_records.setdefault(
                f"strategy_{strat_idx}", {"attempts": {}}
            )
            branched_genpatch_states: list[GenPatchState] = record_time(
                strat_rec,
                "generate",
                lambda: genpatch_per_strategy(state, fix_strategy),
            )

            start_id = len(state.patch_success)
            state.patch_success.extend([""] * len(branched_genpatch_states))
            ret_patch = ret_build = ret_vuln = ret_func = None

            for _id, genpatch_state in enumerate(branched_genpatch_states):
                genpatch_id = start_id + _id
                try:
                    genpatch_state.validate_self()
                except Exception as e:
                    logger.error(
                        f"Error in validating genpatch state: {e}. skipping genpatch..."
                    )
                    continue

                for retry_cnt in range(FIX_BUILD_ERROR_RETRIES):
                    pv.logger.debug(f"Trying to patch {retry_cnt + 1} time...")
                    attempt_key = f"{genpatch_id}_{retry_cnt}"
                    attempt_rec = strat_rec["attempts"].setdefault(attempt_key, {})

                    ret_patch: PatchTestState = record_time(
                        attempt_rec,
                        "patch",
                        lambda: test_patch(
                            state, genpatch_state, genpatch_id, pv, retry_cnt
                        ),
                    )
                    if not ret_patch.ret_code:
                        attempt_rec["result"] = ExperimentResEnum.PATCH_FAILED.value
                        pv.revert()
                        break

                    state.attempt_id = ret_patch.attempt_id

                    # Validation steps as small helpers so the four modes can be
                    # composed from them. Each returns _OK / _RETRY / _ABORT and
                    # records its own outcome; the caller does the continue/break.
                    def do_build() -> str:
                        try:
                            ret_build: BuildTestState = record_time(
                                attempt_rec,
                                "build",
                                lambda: test_build(
                                    state, genpatch_state, genpatch_id, pv
                                ),
                            )
                        except Exception as e:
                            logger.error(f"Error in build test: {e}")
                            attempt_rec["result"] = ExperimentResEnum.BUILD_FAILED.value
                            return _ABORT
                        if not ret_build.ret_code:
                            attempt_rec["result"] = ExperimentResEnum.BUILD_FAILED.value
                            return _RETRY
                        return _OK

                    def do_vulnerability() -> str:
                        ret_vuln: VulnerabilityTestState = record_time(
                            attempt_rec,
                            "vulnerability",
                            lambda: test_vulnerability(
                                state, genpatch_state, genpatch_id, pv
                            ),
                        )
                        if not ret_vuln.ret_code:
                            attempt_rec["result"] = ExperimentResEnum.VULN_FAILED.value
                            return _ABORT
                        return _OK

                    def do_metapro() -> Tuple[bool, str]:
                        """metapro config + binary patch, then the PoC test.

                        Returns (applied, outcome). `applied` is False only when the
                        config could not be derived or could not be applied to the
                        binary -- that is the condition `combined` falls back on. A
                        PoC that still crashes means the patch is simply wrong, so it
                        aborts the attempt instead of handing it to another rewriter.
                        """
                        patch_diff_dir = os.path.join(state.diff_stage_dir, 'cur-patch')
                        ret_gen: MetaproPatchGenState = record_time(
                            attempt_rec,
                            "metapro_patch_gen",
                            lambda: metapro_patch_gen(state, pv),
                        )
                        if ret_gen.ret_code:
                            state.patch_config = ret_gen.patch_config
                            state.metapro_gen_time = ret_gen.metapro_gen_time
                            state.metapro_patch_gen_result = ret_gen.ret_code
                        attempt_rec['metapro_patch_gen_result'] = ret_gen.ret_code
                        attempt_rec['patch_template_usage'] = ret_gen.patch_template_usage
                        if not ret_gen.ret_code:
                            return False, _RETRY

                        ret_bin: MetaproBinaryPatchState = record_time(
                            attempt_rec,
                            "metapro_patch",
                            lambda: metapro_binary_patch(state, pv),
                        )
                        with open(f'{patch_diff_dir}-{state.attempt_id}-binary-patch.log', 'w') as f:
                            f.write(ret_bin.err_msg or "")
                        if ret_bin.ret_code:
                            state.metapro_patch_time = ret_bin.metapro_patch_time
                            state.metapro_patch_result = ret_bin.ret_code
                        attempt_rec['metapro_patch_result'] = ret_bin.ret_code
                        if not ret_bin.ret_code:
                            return False, _RETRY

                        ret_test: MetaproTestState = record_time(
                            attempt_rec,
                            "metapro_test",
                            lambda: metapro_test(state, pv),
                        )
                        with open(f'{patch_diff_dir}-{state.attempt_id}-metapro-test.log', 'w') as f:
                            f.write(ret_test.err_msg or "")
                        if ret_test.ret_code:
                            state.metapro_test_time = ret_test.metapro_test_time
                            state.metapro_test_result = ret_test.ret_code
                        attempt_rec['metapro_test_result'] = ret_test.ret_code
                        if not ret_test.ret_code:
                            attempt_rec["result"] = ExperimentResEnum.VULN_FAILED.value
                            return True, _ABORT
                        return True, _OK

                    def do_dyninst() -> Tuple[bool, str]:
                        # Not wrapped in record_time: dyninst_binary_patch() times its
                        # own three steps, and an outer total would double-count them
                        # for any consumer that sums the numbers in a result file.
                        ret_dyn: DyninstBinaryPatchState = dyninst_binary_patch(state, pv)
                        attempt_rec['dyninst_extract'] = ret_dyn.dyninst_extract_time
                        attempt_rec['dyninst_patch'] = ret_dyn.dyninst_patch_time
                        attempt_rec['dyninst_test'] = ret_dyn.dyninst_test_time
                        attempt_rec['dyninst_applied'] = ret_dyn.dyninst_applied
                        attempt_rec['dyninst_patch_result'] = ret_dyn.ret_code
                        state.dyninst_extract_time = ret_dyn.dyninst_extract_time
                        state.dyninst_patch_time = ret_dyn.dyninst_patch_time
                        state.dyninst_test_time = ret_dyn.dyninst_test_time
                        state.dyninst_applied = ret_dyn.dyninst_applied
                        if not ret_dyn.dyninst_applied:
                            # The rewrite never went in -- combined falls through to the
                            # next approach, the single-approach mode ends the attempt.
                            return False, _RETRY
                        state.dyninst_patch_result = ret_dyn.ret_code
                        if not ret_dyn.ret_code:
                            # Rewritten fine, but the PoC still crashes: the patch is wrong,
                            # so no other rewriter would help. Same verdict do_metapro gives.
                            attempt_rec["result"] = ExperimentResEnum.VULN_FAILED.value
                            return True, _ABORT
                        return True, _OK

                    # Binary-rewriting strategies to try, in order, before any
                    # rebuild. 'combined' tries metapro and then dyninst, and falls
                    # back to conv when neither could apply the patch; the
                    # single-approach modes try only their own; conv tries none.
                    strategies = {
                        'metapro': (do_metapro,),
                        'dyninst': (do_dyninst,),
                        'combined': (do_metapro, do_dyninst),
                    }.get(state.patch_mode, ())

                    applied, outcome = False, _OK
                    for strategy in strategies:
                        applied, outcome = strategy()
                        if applied:
                            break

                    if outcome == _ABORT:
                        # A rewriter applied the patch and the PoC still crashed.
                        pv.revert()
                        break

                    if applied:
                        # The rewriter stood in for the vulnerability test, but it only
                        # touched the binary: the source tree is still unbuilt and
                        # test_functionality needs a built tree, so compile it now.
                        outcome = do_build()
                    elif state.patch_mode in ('conv', 'combined'):
                        # conv, or combined with no rewriter able to apply the patch.
                        outcome = do_build()
                        if outcome == _OK:
                            outcome = do_vulnerability()
                    else:
                        # metapro/dyninst mode: the rewriter is the whole approach, so
                        # failing to apply the patch ends the attempt.
                        attempt_rec["result"] = ExperimentResEnum.BUILD_FAILED.value
                        outcome = _RETRY

                    if outcome == _RETRY:
                        pv.revert()
                        continue
                    if outcome == _ABORT:
                        pv.revert()
                        break
                    ret_func: FunctionalityTestState = record_time(
                        attempt_rec,
                        "functionality",
                        lambda: test_functionality(
                            state, genpatch_state, genpatch_id, pv
                        ),
                    )

                    if USE_VERIFIER:
                        if not ret_func.ret_code:
                            attempt_rec["result"] = ExperimentResEnum.FUNC_FAILED.value
                            pv.revert()
                            break
                        # Run verifier if enabled
                        ret_verify: VerifyState = record_time(
                            attempt_rec,
                            "verify",
                            lambda: verify_patch(
                                state, genpatch_state, genpatch_id, pv
                            ),
                        )
                        attempt_rec["result"] = (
                            ExperimentResEnum.SUCCESS.value
                            if ret_verify.err_msg in (True, "partial")
                            else ExperimentResEnum.VERIFY_FAILED.value
                        )
                        if ret_func.ret_code:
                            pv.revert()
                            break
                    # Record the attempt's outcome explicitly so consumers can
                    # identify the successful attempt by result rather than
                    # assuming it is the last/highest retry.
                    else:
                        attempt_rec["result"] = (
                            ExperimentResEnum.SUCCESS.value
                            if ret_func.ret_code
                            else ExperimentResEnum.FUNC_FAILED.value
                        )
                        if ret_func.ret_code:
                            pv.revert()
                            break
                pv.revert()
                if ret_func is not None and ret_func.ret_code:
                    pv.revert()
                    break
            if ret_func is not None and ret_func.ret_code:
                pv.revert()
                break

        if isinstance(pv, FinalTestValidator):
            pv.run_cmd("git reset --hard", cwd=state.package_location, quiet=True)

        return state

    runpatch_builder.add_node("runpatch_run_patch", RunPatch)
    runpatch_builder.add_node(
        "runpatch_end", lambda state: {"last_node": "runpatch_end"}
    )

    runpatch_builder.set_entry_point("runpatch_run_patch")
    runpatch_builder.set_finish_point("runpatch_end")

    runpatch_builder.add_edge("runpatch_run_patch", "runpatch_end")

    return runpatch_builder.compile()
