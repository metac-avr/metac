import json
import os
import shutil
from typing import Literal, NamedTuple

from aim import Run
from dotenv import load_dotenv

from san2patch.context import init_context
from san2patch.dataset.base_dataset import BaseDataset
from san2patch.patching.graph.ablation.cot.patching_graph import (
    CoTPatchState,
    generate_cot_patch_graph,
)
from san2patch.patching.graph.ablation.no_comprehend.patching_graph import (
    NoComprehendPatchState,
    generate_no_comprehend_patch_graph,
)
from san2patch.patching.graph.ablation.no_context.patching_graph import (
    NoContextPatchState,
    generate_no_context_patch_graph,
)
from san2patch.patching.graph.ablation.no_howtofix.patching_graph import (
    NoHowToFixPatchState,
    generate_no_howtofix_patch_graph,
)
from san2patch.patching.graph.ablation.zeroshot.patching_graph import (
    ZeroshotPatchState,
    generate_zeroshot_patch_graph,
)
from san2patch.patching.graph.patching_graph import (
    FullPatchState,
    generate_tot_patch_graph,
)
from san2patch.patching.llm.base_llm_patcher import BaseLLMPatcher
from san2patch.patching.llm.openai_llm_patcher import GPT4oPatcher
from san2patch.patching.validator import ArvoValidator, FinalTestValidator
from san2patch.utils.cmd import BaseCommander
from san2patch.utils.docker import DockerHelper
from san2patch.utils.enum import (
    SELECT_METHODS,
    TEMPERATURE_SETTING,
    VERSION_LIST,
    ExperimentStepEnum,
)
from san2patch.utils.enum import ExperimentResEnum as TestEvalRetCode


def prune_san_output(full_txt: str, logger) -> str:
    """Keep only the sanitizer report from raw program output.

    Program runs can emit large amounts of non-sanitizer output (the target's
    own logging, echoed crash input, etc.) that bloats the prompt and can push
    the LLM request past its token limit. ``BaseDataset.get_only_san_output``
    extracts just the sanitizer block; if no sanitizer markers are found it
    returns ``False``, in which case we fall back to the full text so we never
    silently drop the only diagnostic we have.
    """
    pruned = BaseDataset.get_only_san_output(full_txt)
    if pruned is False:
        logger.warning(
            "No sanitizer markers found in output; using full text without pruning."
        )
        return full_txt
    return pruned


class San2Patcher(BaseCommander):
    def __init__(
        self,
        vuln_id: str,
        data_dir: str,
        mode: Literal["test"] = "test",
        LLMPatcher: BaseLLMPatcher = GPT4oPatcher,
        version: VERSION_LIST = "tot",
        aim_run: Run | None = None,
        experiment_name: str | None = None,
        retry_cnt: int = 1,
        docker_id: str | None = None,
        select_method: SELECT_METHODS = "sample",
        temperature_setting: TEMPERATURE_SETTING = "medium",
        *args,
        **kwargs,
    ):
        load_dotenv(override=True)

        super().__init__(*args, **kwargs)

        self.vuln_id = vuln_id
        self.data_dir = data_dir
        self.retry_cnt = retry_cnt
        self.docker_id = docker_id
        if self.docker_id is None:
            try:
                self.docker_id = DockerHelper().get_benchmark_container_id()
            except Exception as e:
                self.logger.error(f"Error getting docker id: {e}")
                raise ValueError(
                    "Cannot get docker id. Please run the container (san2patch-benchmark) first."
                )

        self.mode = mode
        self.LLMPatcher = LLMPatcher
        self.version = version
        self.aim_run = aim_run
        self.select_method = select_method
        self.temperature_setting = temperature_setting

        vuln_data_file = os.path.join(self.data_dir, "vuln", f"{self.vuln_id}.json")

        if not os.path.exists(vuln_data_file):
            self.logger.error(f"Vulnerability data file not found: {vuln_data_file}")

        with open(vuln_data_file, "r") as f:
            self.vuln_data = json.load(f)

        san_output_file = os.path.join(
            self.data_dir, "sanitizer", f"{self.vuln_id}.san"
        )

        if not os.path.exists(san_output_file):
            self.logger.error(f"Sanitizer output file not found: {san_output_file}")

        with open(san_output_file, "r", errors="ignore") as f:
            self.san_output = prune_san_output(f.read(), self.logger)

        self.output_dir = os.path.join(self.data_dir, "output")

        self.package_name = self.vuln_data["subject"]

        self.experiment_name = experiment_name
        if self.experiment_name is not None:
            self.diff_dir = os.path.join(
                self.data_dir, f"gen_diff_{self.experiment_name}", self.vuln_id
            )
        else:
            self.diff_dir = os.path.join(self.data_dir, "gen_diff", self.vuln_id)

        if not os.path.exists(self.diff_dir):
            os.makedirs(self.diff_dir)

        self.repo_dir = os.path.join(
            self.data_dir, "repo", f"{self.package_name}_{self.vuln_id}"
        )
        self.copy_repo_dir = os.path.join(
            self.data_dir, "repo_copy", f"{self.package_name}_{self.vuln_id}"
        )

        if self.version in ["zeroshot", "cot", "no_context"]:
            self.context_mode = "line"
        else:
            self.context_mode = "ast"

        init_context(
            self.vuln_id,
            self.copy_repo_dir,
            self.context_mode,
            self.temperature_setting,
            self.docker_id,
        )

    def generate_patch(self):
        # Generate patch and save it to self.output_dir as filename {self.vuln_id}.diff
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.GENPATCH.value

        # Generate patch using LLM
        if self.version == "tot":
            patch_graph = generate_tot_patch_graph(
                self.LLMPatcher,
            ).with_config({"run_name": "ToTPatch"})

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    "mode": self.mode,
                    "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    "experiment_name": self.experiment_name,
                    "select_method": self.select_method,
                }
            )
            res = FullPatchState(**res_json)

        elif self.version == "zeroshot":
            patch_graph = generate_zeroshot_patch_graph(self.LLMPatcher).with_config(
                {"run_name": "ZeroshotPatch"}
            )

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    "experiment_name": self.experiment_name,
                }
            )

            res = ZeroshotPatchState(**res_json)

        elif self.version == "cot":
            patch_graph = generate_cot_patch_graph(self.LLMPatcher).with_config(
                {"run_name": "CoTPatch"}
            )

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    "experiment_name": self.experiment_name,
                }
            )
            res = CoTPatchState(**res_json)

        elif self.version == "no_context":
            patch_graph = generate_no_context_patch_graph(
                self.LLMPatcher,
            ).with_config({"run_name": "NoContextPatch"})

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    "experiment_name": self.experiment_name,
                }
            )
            res = NoContextPatchState(**res_json)

        elif self.version == "no_comprehend":
            patch_graph = generate_no_comprehend_patch_graph(
                self.LLMPatcher,
            ).with_config({"run_name": "NoComprehendPatch"})

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    "experiment_name": self.experiment_name,
                }
            )
            res = NoComprehendPatchState(**res_json)

        elif self.version == "no_howtofix":
            patch_graph = generate_no_howtofix_patch_graph(
                self.LLMPatcher,
            ).with_config({"run_name": "NoHowToFixPatch"})

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    "experiment_name": self.experiment_name,
                }
            )
            res = NoHowToFixPatchState(**res_json)

        else:
            raise ValueError(f"Invalid version: {self.version}")

        return res

    def make_diff(self, try_cnt=0, stage=0):
        if not os.path.exists(self.copy_repo_dir):
            self.run_cmd(f"cp -r {self.repo_dir} {self.copy_repo_dir}")
            self.logger.info(f"Repo copy complete {self.copy_repo_dir}")

        self.run_cmd("git reset --hard", cwd=self.copy_repo_dir, quiet=True)

        self.diff_stage_dir = os.path.join(self.diff_dir, f"stage_{stage}_{try_cnt}")
        if not os.path.exists(self.diff_stage_dir):
            self.logger.info(f"create stage_{stage}_{try_cnt} {self.diff_stage_dir}")
            os.makedirs(self.diff_stage_dir)

        res = self.generate_patch()

        res_output = os.path.join(
            self.diff_stage_dir, f"{self.vuln_id}_graph_output.json"
        )
        with open(res_output, "w") as f:
            json.dump(res.model_dump(), f)

        return res

    class TestEvalRet(NamedTuple):
        ret_code: TestEvalRetCode
        err_msg: str

    def test_eval_patch(self) -> TestEvalRet:
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.EVAL.value

        stage_id = self.diff_stage_dir.split("/")[-1]

        pv = FinalTestValidator(
            self.vuln_data,
            stage_id,
            experiment_name=self.experiment_name,
            docker_id=self.docker_id,
        )

        # Setup docker container
        pv.setup()

        # Apply patch
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.PATCH.value

        patch_ret, patch_err_msg = pv.patch()
        if not patch_ret:
            return TestEvalRetCode.PATCH_FAILED, patch_err_msg

        # Build patched project
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.BUILD.value

        build_ret, build_err_msg = pv.build_test()
        if not build_ret:
            return TestEvalRetCode.BUILD_FAILED, build_err_msg

        # Test patched project using original crash input
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.VULN_TEST.value

        vuln_ret, vuln_err_msg = pv.vulnerability_test()
        if not vuln_ret:
            return TestEvalRetCode.VULN_FAILED, vuln_err_msg

        # Test patched project using functionality test
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.FUNC_TEST.value

        func_ret, func_err_msg = pv.functionality_test()
        if not func_ret:
            return TestEvalRetCode.FUNC_FAILED, func_err_msg

        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.END.value

        return TestEvalRetCode.SUCCESS, None


def add_diff_attribute(source_dir: str):
    git_attribute_path = os.path.join(source_dir, ".gitattributes")
    if os.path.exists(git_attribute_path):
        with open(git_attribute_path, "r") as f:
            attributes = f.read()
            if """# .gitattributes
*.c diff=cpp
*.h diff=cpp
*.cpp diff=cpp
*.hpp diff=cpp""" in attributes:
                return # Already added
            
    with open(git_attribute_path, "a") as f:
        f.write(
            """# .gitattributes
*.c diff=cpp
*.h diff=cpp
*.cpp diff=cpp
*.hpp diff=cpp
""")


class ArvoPatcher(BaseCommander):
    def __init__(
        self,
        project: str,
        bug_id: int,
        binary_path:str,
        poc_path:str,
        sanitizer:str,
        mode: Literal["test"] = "test",
        LLMPatcher: BaseLLMPatcher = GPT4oPatcher,
        version: VERSION_LIST = "tot",
        aim_run: Run | None = None,
        retry_cnt: int = 1,
        select_method: SELECT_METHODS = "sample",
        temperature_setting: TEMPERATURE_SETTING = "medium",
        patch_mode: str = "conv",
        output_dir: str = "san2patch",
        *args,
        **kwargs,
    ):
        load_dotenv(override=True)

        super().__init__(*args, **kwargs)

        self.vuln_id = f'{project}-{bug_id}'
        self.project = project
        self.bug_id = bug_id
        # Validation approach (run-arvo.py's --mode): 'conv' rebuilds and runs the
        # vulnerability test, 'metapro' binary-patches and runs the metapro PoC test
        # instead. Also the name of the per-bug output directory (-o/--output).
        self.patch_mode = patch_mode
        self.output_dir_name = output_dir
        self.work_dir = os.path.join(os.getenv('DATASET_DIR'), project, str(bug_id))
        self.data_dir = os.path.join(os.getenv('DATASET_DIR'), project, str(bug_id), output_dir)
        self.retry_cnt = retry_cnt
        self.docker_id = f'arvo-{bug_id}'
        self.binary = binary_path
        self.poc = poc_path
        self.sanitizer = sanitizer
        if self.docker_id is None:
            try:
                self.docker_id = DockerHelper().get_benchmark_container_id()
            except Exception as e:
                self.logger.error(f"Error getting docker id: {e}")
                raise ValueError(
                    "Cannot get docker id. Please run the container (san2patch-benchmark) first."
                )

        self.mode = mode
        self.LLMPatcher = LLMPatcher
        self.version = version
        self.aim_run = aim_run
        self.select_method = select_method
        self.temperature_setting = temperature_setting

        san_output_file = os.path.join(self.work_dir, "test.log")

        if not os.path.exists(san_output_file):
            self.logger.error(f"Sanitizer output file not found: {san_output_file}")

        with open(san_output_file, "r", errors="ignore") as f:
            self.san_output = prune_san_output(f.read(), self.logger)

        self.output_dir = os.path.join(self.data_dir, "output")

        self.package_name = project

        self.diff_dir = os.path.join(self.data_dir, 'gen_diff')

        if not os.path.exists(self.diff_dir):
            os.makedirs(self.diff_dir)

        self.repo_dir = os.path.join(self.work_dir, 'source')
        self.copy_repo_dir = os.path.join(self.work_dir, 'san2patch-source')
        if os.path.exists(self.copy_repo_dir):
            shutil.rmtree(self.copy_repo_dir)
        shutil.copytree(self.repo_dir, self.copy_repo_dir)
        if project == 'gpac':
            self.run_cmd(f'docker exec -w {self.copy_repo_dir} {self.docker_id} bash -c "git submodule update --init"', cwd=self.copy_repo_dir, expect_error=True)
            # Delete tests take too long
            self.run_cmd(f'docker exec -w {self.copy_repo_dir} {self.docker_id} bash -c "rm -f testsuite/scripts/avmix.sh testsuite/scripts/graphics_dump.sh testsuite/scripts/python.sh testsuite/scripts/raw* testsuite/scripts/softstretch.sh testsuite/scripts/thumbs.sh testsuite/scripts/vflip.sh testsuite/scripts/vout.sh testsuite/scripts/xps_inband.sh"', cwd=self.copy_repo_dir, expect_error=True)

        add_diff_attribute(self.repo_dir)
        add_diff_attribute(self.copy_repo_dir)

        if self.version in ["zeroshot", "cot", "no_context"]:
            self.context_mode = "line"
        else:
            self.context_mode = "ast"

        pv = ArvoValidator(
            self.project,
            self.bug_id,
            self.work_dir,
            self.binary,
            self.poc,
            'init-temp',
            output_dir=self.output_dir_name,
        )
        # Setup once before running
        pv.setup(self.sanitizer)
        pv.preprocess_patcher()

        init_context(
            self.vuln_id,
            self.copy_repo_dir,
            self.context_mode,
            self.temperature_setting,
            self.docker_id,
        )

    def generate_patch(self):
        # Generate patch and save it to self.output_dir as filename {self.vuln_id}.diff
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.GENPATCH.value

        # Generate patch using LLM
        if self.version == "tot":
            patch_graph = generate_tot_patch_graph(
                self.LLMPatcher,
            ).with_config({"run_name": "ToTPatch"})

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    "mode": self.mode,
                    # "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    # "experiment_name": self.experiment_name,
                    "select_method": self.select_method,
                    "project": self.project,
                    "bug_id": self.bug_id,
                    "work_dir": self.work_dir,
                    "binary_path": self.binary,
                    "poc_path": self.poc,
                    'san': self.sanitizer,
                    'original_dir': self.repo_dir,
                    'patch_mode': self.patch_mode,
                    'output_dir': self.output_dir_name,
                }
            )
            res = FullPatchState(**res_json)

        elif self.version == "zeroshot":
            patch_graph = generate_zeroshot_patch_graph(self.LLMPatcher).with_config(
                {"run_name": "ZeroshotPatch"}
            )

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    # "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    # "experiment_name": self.experiment_name,
                    "project": self.project,
                    "bug_id": self.bug_id,
                    "work_dir": self.work_dir,
                    "binary_path": self.binary,
                    "poc_path": self.poc,
                    'san': self.sanitizer,
                    'original_dir': self.repo_dir,
                }
            )

            res = ZeroshotPatchState(**res_json)

        elif self.version == "cot":
            patch_graph = generate_cot_patch_graph(self.LLMPatcher).with_config(
                {"run_name": "CoTPatch"}
            )

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    # "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    # "experiment_name": self.experiment_name,
                    "project": self.project,
                    "bug_id": self.bug_id,
                    "work_dir": self.work_dir,
                    "binary_path": self.binary,
                    "poc_path": self.poc,
                    'san': self.sanitizer,
                    'original_dir': self.repo_dir,
                }
            )
            res = CoTPatchState(**res_json)

        elif self.version == "no_context":
            patch_graph = generate_no_context_patch_graph(
                self.LLMPatcher,
            ).with_config({"run_name": "NoContextPatch"})

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    # "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    # "experiment_name": self.experiment_name,
                    "project": self.project,
                    "bug_id": self.bug_id,
                    "work_dir": self.work_dir,
                    "binary_path": self.binary,
                    "poc_path": self.poc,
                    'san': self.sanitizer,
                    'original_dir': self.repo_dir,
                }
            )
            res = NoContextPatchState(**res_json)

        elif self.version == "no_comprehend":
            patch_graph = generate_no_comprehend_patch_graph(
                self.LLMPatcher,
            ).with_config({"run_name": "NoComprehendPatch"})

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    # "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    # "experiment_name": self.experiment_name,
                    "project": self.project,
                    "bug_id": self.bug_id,
                    "work_dir": self.work_dir,
                    "binary_path": self.binary,
                    "poc_path": self.poc,
                    'san': self.sanitizer,
                    'original_dir': self.repo_dir,
                }
            )
            res = NoComprehendPatchState(**res_json)

        elif self.version == "no_howtofix":
            patch_graph = generate_no_howtofix_patch_graph(
                self.LLMPatcher,
            ).with_config({"run_name": "NoHowToFixPatch"})

            res_json = patch_graph.invoke(
                {
                    "vuln_id": self.vuln_id,
                    "sanitizer_output": self.san_output,
                    "package_name": self.package_name,
                    "package_language": "C",
                    "package_location": self.copy_repo_dir,
                    # "vuln_data": self.vuln_data,
                    "diff_stage_dir": self.diff_stage_dir,
                    # "experiment_name": self.experiment_name,
                    "project": self.project,
                    "bug_id": self.bug_id,
                    "work_dir": self.work_dir,
                    "binary_path": self.binary,
                    "poc_path": self.poc,
                    'san': self.sanitizer,
                    'original_dir': self.repo_dir,
                }
            )
            res = NoHowToFixPatchState(**res_json)

        else:
            raise ValueError(f"Invalid version: {self.version}")

        return res

    def make_diff(self, try_cnt=0, stage=0):
        if not os.path.exists(self.copy_repo_dir):
            self.run_cmd(f"cp -r {self.repo_dir} {self.copy_repo_dir}")
            self.logger.info(f"Repo copy complete {self.copy_repo_dir}")

        # self.run_cmd("git reset --hard", cwd=self.copy_repo_dir, quiet=True)

        self.diff_stage_dir = os.path.join(self.diff_dir, f"stage_{stage}_{try_cnt}")
        if not os.path.exists(self.diff_stage_dir):
            self.logger.info(f"create stage_{stage}_{try_cnt} {self.diff_stage_dir}")
            os.makedirs(self.diff_stage_dir)

        res = self.generate_patch()

        res_output = os.path.join(
            self.diff_stage_dir, f"graph_output.json"
        )
        with open(res_output, "w") as f:
            json.dump(res.model_dump(), f)

        return res

    class TestEvalRet(NamedTuple):
        ret_code: TestEvalRetCode
        err_msg: str

    def test_eval_patch(self) -> TestEvalRet:
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.EVAL.value

        stage_id = self.diff_stage_dir.split("/")[-1]

        pv = ArvoValidator(
            self.project,
            self.bug_id,
            self.work_dir,
            self.binary,
            self.poc,
            stage_id,
            output_dir=self.output_dir_name,
        )

        # Setup docker container
        # pv.setup()

        # Apply patch
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.PATCH.value

        patch_ret, patch_err_msg = pv.patch()
        if not patch_ret:
            return TestEvalRetCode.PATCH_FAILED, patch_err_msg

        # Build patched project
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.BUILD.value

        build_ret, build_err_msg = pv.build_test(self.sanitizer)
        if not build_ret:
            return TestEvalRetCode.BUILD_FAILED, build_err_msg

        # Test patched project using original crash input
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.VULN_TEST.value

        vuln_ret, vuln_err_msg = pv.vulnerability_test()
        if not vuln_ret:
            return TestEvalRetCode.VULN_FAILED, vuln_err_msg

        # Test patched project using functionality test
        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.FUNC_TEST.value

        func_ret, func_err_msg = pv.functionality_test()
        if not func_ret:
            return TestEvalRetCode.FUNC_FAILED, func_err_msg
        
        verify_ret, verify_err_msg = pv.verify()
        if not verify_ret or verify_err_msg == False:
            return TestEvalRetCode.VERIFY_FAILED, verify_err_msg

        if self.aim_run:
            self.aim_run["step"] = ExperimentStepEnum.END.value

        pv.revert()

        return TestEvalRetCode.SUCCESS, None


if __name__ == "__main__":
    pass
