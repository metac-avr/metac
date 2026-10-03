import datetime
import json
import os
import sys
import shutil
import signal
import traceback
import warnings
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

# Add the san2patch subdirectory to sys.path to make the san2patch package importable
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'san2patch'))

import argparse
import psutil
from aim import Run
from art import text2art
from dotenv import load_dotenv
from langchain.callbacks import tracing_v2_enabled
from langsmith import tracing_context
from rich.progress import track

import san2patch.dataset.test as test_dataset
from san2patch.context import San2PatchLogger
from san2patch.dataset.test.arvo_dataset import ArvoDataset
from san2patch.patching.llm.anthropic_llm_patcher import (
    Claude3HaikuPatcher,
    Claude3OpusPatcher,
    Claude35SonnetPatcher,
    Claude5OpusPatcher,
)
from san2patch.patching.llm.base_llm_patcher import BaseLLMPatcher

# from san2patch.patching.llm.google_llm_patcher import (
from san2patch.patching.llm.google_llm_patcher import (
    Gemini15FlashPatcher,
    Gemini15ProPatcher,
)
from san2patch.patching.llm.openai_llm_patcher import (
    GPT4ominiPatcher as OpenAIGPT4ominiPatcher,
    GPT5_6SolPatcher as OpenAIGPT5_6SolPatcher,
)
from san2patch.patching.llm.huggingface_llm_patcher import (
    DeepSeekV4ProPatcher,
    Qwen3_6_35BPatcher,
    Qwen3CoderNextPatcher,
    DeepSeekV4FlashPatcher,
    Qwen3CoderPatcher,
    GLM4_6Patcher,
)
from san2patch.patching.llm.openrouter_llm_patcher import (
    DeepSeekV4ProPatcher as OpenRouterDeepSeekV4ProPatcher,
    GLM5_3Patcher as OpenRouterGLM5_3Patcher,
    OpenrouterQwen3CoderPatcher,
)
from san2patch.patching.llm.openai_llm_patcher import GPT4oPatcher as OpenAIGPT4oPatcher
from san2patch.patching.llm.openai_llm_patcher import GPT35Patcher as OpenAIGPT35Patcher
from san2patch.patching.patcher import ArvoPatcher, San2Patcher, TestEvalRetCode
from san2patch.utils.enum import (
    MODEL_LIST,
    SELECT_METHODS,
    TEMPERATURE_SETTING,
    VERSION_LIST,
    ExperimentStepEnum,
)

warnings.filterwarnings("ignore", category=UserWarning, module="pydantic")

logger = San2PatchLogger("RUN PATCH").logger


def terminate_process_and_children(pid):
    """
    Terminates the process with the given PID and all its child processes.
    """
    try:
        # Get the parent process using the given PID
        parent = psutil.Process(pid)
        # Find all child processes recursively
        children = parent.children(recursive=True)
        # Terminate all child processes
        for child in children:
            os.kill(child.pid, signal.SIGTERM)
        # Terminate the parent process
        os.kill(pid, signal.SIGTERM)
    except psutil.NoSuchProcess:
        print("The process has already been terminated.")
    except Exception as e:
        print(f"An error occurred: {e}")


def run_patch_one(
    project: str,
    bug_id: int,
    binary_path: str,
    poc_path: str,
    sanitizer:str,
    LLMPatcher: BaseLLMPatcher,
    retry_cnt: int = 5,
    max_retry_cnt: int = 0,
    select_method: SELECT_METHODS = "sample",
    temperature_setting: TEMPERATURE_SETTING = "medium",
    raise_exception: bool = False,
    halt_on_success: bool = True,
    mode: str = "conv",
    output_dir: str = "san2patch",
):
    global args
    vuln_id = f"{project}-{bug_id}"
    # Logger setting
    dataset = ArvoDataset(project, bug_id, output_dir=output_dir)
    if args.remove_previous and os.path.exists(dataset.final_dir):
        shutil.rmtree(dataset.final_dir)
    dataset.setup_directory(dataset.final_dir)

    logger = San2PatchLogger().logger

    logger.info(f"Starting patching in test {dataset.name}...")

    logger.info(f"dataset.final_dir: {dataset.final_dir}")
    logger.info(f"vuln_id_start: {vuln_id}")

    stage_num = 0

    res_file = os.path.join(dataset.gen_diff_dir, "res.txt")

    # Count directory that starts with "stage_" to resume from the last stage
    last_try_cnt = len([x for x in os.listdir(dataset.gen_diff_dir) if x.startswith("stage_")])

    for i in range(last_try_cnt, last_try_cnt + retry_cnt):
        if max_retry_cnt != 0 and i >= max_retry_cnt:
            logger.error(f"Max retry count reached for vuln_id: {vuln_id}. exiting...")
            break

        # Set up aim run
        try:
            aim_run = Run(repo=os.getenv("AIM_SERVER_URL", "http://localhost:53800"))
            aim_run.set_artifacts_uri(os.getenv("AIM_ARTIFACTS_URI", "file://."))
        except Exception:
            logger.warning("Cannot connect to aim server. Turn off aim.")
            aim_run = dict()

        aim_run["vuln_id"] = vuln_id
        aim_run["model"] = LLMPatcher.__name__
        aim_run["retry_cnt"] = retry_cnt
        aim_run["try"] = i
        aim_run["stage"] = stage_num
        aim_run["step"] = ExperimentStepEnum.START.value

        # Set up patcher
        patcher = ArvoPatcher(
            project=project,
            bug_id=bug_id,
            binary_path=binary_path,
            poc_path=poc_path,
            sanitizer=sanitizer,
            mode="test",
            LLMPatcher=LLMPatcher,
            aim_run=aim_run,
            retry_cnt=retry_cnt,
            select_method=select_method,
            temperature_setting=temperature_setting,
            patch_mode=mode,
            output_dir=output_dir,
        )

        logger.info(
            f"Starting patching stage {stage_num} try {i} for vuln_id: {vuln_id}"
        )

        def _run_patch():
            try:
                res = patcher.make_diff(try_cnt=i, stage=stage_num)
                # Store time records individually per iteration so they are not
                # overwritten across stages/tries.
                with open(
                    os.path.join(
                        dataset.final_dir, f"result_stage_{stage_num}_{i}.json"
                    ),
                    "w",
                ) as f:
                    json.dump(res.time_records, f, indent=4)

                # Re-evaluate if the patch is already successful
                if TestEvalRetCode.SUCCESS.value in res.patch_success:
                    # ret_code, err_msg = patcher.test_eval_patch()
                    # ret_code = ret_code.value

                    ret_code = TestEvalRetCode.SUCCESS.value
                    err_msg = ""

                    # genpatch_id of the first successful patch.
                    success_idx = res.patch_success.index(
                        TestEvalRetCode.SUCCESS.value
                    )

                    # Recover the successful attempt's retry_cnt from
                    # time_records, which nests attempts as
                    #   {"strategy_<n>": {"attempts":
                    #        {"<genpatch_id>_<retry_cnt>": {..., "result": <enum>}}}}.
                    # Select by the recorded "result" so this stays correct even
                    # if RunPatch no longer terminates on the first success.
                    attempts = {}
                    for strat_rec in res.time_records.values():
                        attempts.update(strat_rec.get("attempts", {}))
                    success_attempt_keys = [
                        key
                        for key, rec in attempts.items()
                        if key.split("_")[0] == str(success_idx)
                        and rec.get("result") == TestEvalRetCode.SUCCESS.value
                    ]
                    # Latest successful attempt for this genpatch_id.
                    success_attempt_key = max(
                        success_attempt_keys,
                        key=lambda key: int(key.split("_")[1]),
                        default=f"{success_idx}_0",
                    )

                    # Get success diff file from dataset_dir (see
                    # runpatch_graph.py: cur-patch_<genpatch_id>_<retry_cnt>.diff).
                    success_diff_file = os.path.join(
                        dataset.gen_diff_dir,
                        f"stage_{stage_num}_{i}",
                        f"cur-patch_{success_attempt_key}.diff",
                    )

                    success_graph_output = os.path.join(
                        dataset.gen_diff_dir,
                        f"stage_{stage_num}_{i}",
                        f"graph_output.json",
                    )

                    # Copy the success diff file to the vuln directory
                    vuln_dir = os.path.join(dataset.gen_diff_dir, vuln_id)

                    dataset.run_cmd(
                        f"cp {success_diff_file} {dataset.final_dir}/success.diff"
                    )
                    dataset.run_cmd(
                        f"cp {success_graph_output} {dataset.final_dir}/success.artifact"
                    )

                elif TestEvalRetCode.FUNC_FAILED.value in res.patch_success:
                    ret_code = TestEvalRetCode.FUNC_FAILED.value
                    err_msg = ""
                elif not res.patch_success:
                    # No patch ever reached the test loop: every candidate was
                    # dropped during generation (validate_self() rejects a genpatch
                    # whose original_code is empty, which is what happens when the
                    # context manager cannot pull the source for a fix location).
                    # There is no per-patch outcome to take a majority of, and
                    # max() on the empty list used to raise ValueError here.
                    ret_code = TestEvalRetCode.GENPATCH_FAILED.value
                    err_msg = ""
                else:
                    patch_success = res.patch_success
                    ret_code = max(patch_success, key=patch_success.count)
                    err_msg = ""

                if isinstance(aim_run, Run):
                    aim_run["time"] = aim_run.duration

                try:
                    aim_run["cost"] = float(
                        cb.client.read_run(cb.latest_run.id).total_cost
                    )
                    aim_run["langsmith_url"] = cb.get_run_url()
                except Exception:
                    aim_run["cost"] = None
                    aim_run["langsmith_url"] = None

                aim_run["result"] = ret_code
                aim_run["error"] = err_msg
                aim_run["patch_cnt"] = len([x for x in res.patch_success if x])
                aim_run["patch_success"] = res.patch_success

                with open(res_file, "a") as f:
                    try:
                        f.write(
                            f"try: {i}\tstage: {stage_num}\tcode: {ret_code}\trun: {cb.get_run_url()}\n"
                        )
                    except Exception:
                        f.write(f"try: {i}\tstage: {stage_num}\tcode: {ret_code}\n")

                logger.info(
                    f"Ending patching stage {stage_num} try {i} for vuln_id: {vuln_id}"
                )

                if ret_code == TestEvalRetCode.SUCCESS.value:
                    logger.success(f"Patch success for vuln_id: {vuln_id}")
                    if halt_on_success:
                        return True

            except Exception as e:
                if isinstance(aim_run, Run):
                    aim_run["time"] = aim_run.duration
                try:
                    aim_run["cost"] = float(
                        cb.client.read_run(cb.latest_run.id).total_cost
                    )
                    aim_run["langsmith_url"] = cb.get_run_url()
                except Exception:
                    aim_run["cost"] = None
                    aim_run["langsmith_url"] = None

                aim_run["result"] = TestEvalRetCode.EXCEPTION_RAISED.value
                aim_run["error"] = str(e)

                logger.error(f"Exception occurred: {e}. Retrying...")
                traceback.print_exc()
                if raise_exception:
                    raise e

            return False

        if os.getenv("LANGSMITH_API_KEY", "") != "":
            with tracing_v2_enabled() as cb:
                logger.info("Langsmith Tracing enabled")
                res = _run_patch()
                if res:
                    break

        else:
            with tracing_context(enabled=False):
                logger.info("Langsmith Tracing disabled")
                cb = None
                res = _run_patch()
                if res:
                    break

    logger.info(f"vuln_id_end: {vuln_id}")


def main(
    project: str,
    bug_id: int,
    binary_path:str,
    sanitizer:str,
    model: str,
    retry_cnt: int = 5,
    max_retry_cnt: int = 0,
    select_method: SELECT_METHODS = "sample",
    temperature_setting: TEMPERATURE_SETTING = "medium",
    raise_exception: bool = False,
    halt_on_success: bool = True,
    mode: str = "conv",
    output: str = "san2patch",
):
    print(text2art("San2Patch"))

    print("############################################")
    print(f'{project}-{bug_id}')
    print("############################################")

    if model == "gpt-4o":
        model_class = OpenAIGPT4oPatcher
    elif model == "gpt-4o-mini":
        model_class = OpenAIGPT4ominiPatcher
    elif model == "gpt-3.5":
        model_class = OpenAIGPT35Patcher
    elif model == "gpt-5.6-sol":
        model_class = OpenAIGPT5_6SolPatcher
    elif model == "claude-3-opus":
        model_class = Claude3OpusPatcher
    elif model == "claude-3.5-sonnet":
        model_class = Claude35SonnetPatcher
    elif model == "claude-3-haiku":
        model_class = Claude3HaikuPatcher
    elif model == 'claude-opus-5':
        model_class = Claude5OpusPatcher
    elif model == "gemini-1.5-pro":
        model_class = Gemini15ProPatcher
    elif model == "gemini-1.5-flash":
        model_class = Gemini15FlashPatcher
    elif model == 'qwen-3.6':
        model_class = Qwen3_6_35BPatcher
    elif model == 'deepseek-v4-pro':
        model_class = OpenRouterDeepSeekV4ProPatcher
    elif model == 'qwen-3-coder-next':
        model_class = Qwen3CoderNextPatcher
    elif model == 'deepseek-v4-flash':
        model_class = DeepSeekV4FlashPatcher
    elif model == 'qwen-3-coder':
        model_class = Qwen3CoderPatcher
    elif model == 'glm-4.6':
        model_class = GLM4_6Patcher
    elif model == 'glm-5.3':
        model_class = OpenRouterGLM5_3Patcher
    elif model == 'qwen-3-coder-openrouter':
        model_class = OpenrouterQwen3CoderPatcher
    else:
        raise ValueError(f"Model {model} not found")

    try:
        load_dotenv(override=True)
        poc_path = os.path.join(os.getenv("DATASET_DIR"), project, str(bug_id), "poc")
        run_patch_one(
            project,
            bug_id,
            os.path.join(os.getenv("DATASET_DIR"), project, str(bug_id), output, 'output', binary_path),
            poc_path,
            sanitizer,
            model_class,
            retry_cnt,
            max_retry_cnt,
            select_method,
            temperature_setting,
            raise_exception,
            halt_on_success,
            mode,
            output,
        )
    except KeyboardInterrupt:
        logger.error("Keyboard interrupt occurred. Exiting...")
        current_pid = os.getpid()
        terminate_process_and_children(current_pid)
        raise
    finally:
        logger.success("All patching completed. Shutting down executor...")

    logger.info(f"Patching completed for {project}-{bug_id}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run San2Patch on a specific vulnerability.")
    parser.add_argument('project', type=str, help='The project name (e.g., ffmpeg)')
    parser.add_argument('bug_id', type=int, help='The bug ID (e.g., 42501760)')
    parser.add_argument('binary_path', type=str, help='The path to the binary to patch')
    parser.add_argument('sanitizer', type=str, help='The sanitizer used for the vulnerability (e.g., asan, ubsan)')
    parser.add_argument('model', type=str, help='The LLM model to use (e.g., gpt-4o, claude-3-opus)')
    parser.add_argument('--retry-cnt', type=int, default=5, help='Number of retries for patching')
    parser.add_argument('--max-retry-cnt', type=int, default=0, help='Maximum number of retries (0 for unlimited)')
    parser.add_argument('--select-method', choices=['sample', 'greedy'], default='sample', help='Method to select patches (e.g., sample)')
    parser.add_argument('--temperature-setting', choices=['low', 'medium', 'high'], default='medium', help='Temperature setting for LLM')
    parser.add_argument('--raise-exception', action='store_true', help='Whether to raise exceptions during patching')
    parser.add_argument('--halt-on-success', action='store_true', help='Whether to halt on first successful patch')
    parser.add_argument('-r', '--remove-previous', action='store_true', help='Whether to remove previous results and start fresh')
    parser.add_argument('--mode', choices=['conv', 'metapro', 'dyninst', 'combined'], default='conv',
                        help="Validation approach. 'conv' (default): apply the source patch, "
                             "rebuild, then run the vulnerability and functionality tests. "
                             "'metapro': derive a metapro patch config from the patch, apply it "
                             "at binary level and run the metapro PoC test instead of the rebuild "
                             "and vulnerability test; the functionality test still runs. "
                             "'dyninst': apply the patch using Dyninst binary rewriting and run the tests. "
                             "'combined': run the combined approach.")
    parser.add_argument('-o', '--output', type=str, help='The output directory for patched binaries',
                        default='san2patch')
    args = parser.parse_args()

    main(
        project=args.project,
        bug_id=args.bug_id,
        binary_path=args.binary_path,
        sanitizer=args.sanitizer,
        model=args.model,
        retry_cnt=args.retry_cnt,
        max_retry_cnt=args.max_retry_cnt,
        select_method=args.select_method,
        temperature_setting=args.temperature_setting,
        raise_exception=args.raise_exception,
        halt_on_success=args.halt_on_success,
        mode=args.mode,
        output=args.output,
    )
