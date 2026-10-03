import os

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

from san2patch.consts import DEFAULT_TEMPERATURE
from san2patch.patching.prompt.base_prompts import BasePrompt

from .base_llm_patcher import BaseLLMPatcher


class HuggingFacePatcher(BaseLLMPatcher):
    name = "HuggingFace Endpoint"
    vendor = "HuggingFace"

    def __init__(
        self,
        prompt: BasePrompt | None,
        model_name: str,
        temperature: float = DEFAULT_TEMPERATURE,
        timeout=90,
        port=5001,
        **kwargs,
    ):
        load_dotenv(override=True)

        model = ChatOpenAI(
            openai_api_key='',
            model=model_name,
            temperature=temperature,
            timeout=timeout,
            base_url=f'http://localhost:{port}/v1',
            **kwargs,
        )

        super().__init__(model, prompt)


class Qwen3_6_35BPatcher(HuggingFacePatcher):
    name = "Qwen 3.6 35B"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="Qwen/Qwen3.6-35B-A3B", **kwargs)

class Qwen3CoderNextPatcher(HuggingFacePatcher):
    name = "Qwen 3 Coder Next"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="Qwen/Qwen3-Coder-Next", **kwargs)


class DeepSeekV4ProPatcher(HuggingFacePatcher):
    name = "DeepSeek V4 Pro"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="deepseek-ai/DeepSeek-V4-Pro", port=5002, **kwargs)

class DeepSeekV4FlashPatcher(HuggingFacePatcher):
    name = "DeepSeek V4 Flash"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="deepseek-ai/DeepSeek-V4-Flash", port=5002, **kwargs)

class Qwen3CoderPatcher(HuggingFacePatcher):
    name = "Qwen 3 Coder"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="nvidia/Qwen3-Coder-480B-A35B-Instruct-NVFP4", **kwargs)

class GLM4_6Patcher(HuggingFacePatcher):
    name = "GLM 4.6"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="bullpoint/GLM-4.6-AWQ", **kwargs)