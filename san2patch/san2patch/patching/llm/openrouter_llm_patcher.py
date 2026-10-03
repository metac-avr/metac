import os

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

from san2patch.consts import DEFAULT_TEMPERATURE
from san2patch.patching.prompt.base_prompts import BasePrompt

from .base_llm_patcher import BaseLLMPatcher


class OpenRouterPatcher(BaseLLMPatcher):
    name = "OpenRouter Endpoint"
    vendor = "OpenRouter"

    def __init__(
        self,
        prompt: BasePrompt | None,
        model_name: str,
        temperature: float = DEFAULT_TEMPERATURE,
        timeout=90,
        **kwargs,
    ):
        load_dotenv(override=True)
        self.api_key = os.getenv("OPENROUTER_API_KEY")

        model = ChatOpenAI(
            openai_api_key=self.api_key,
            model=model_name,
            timeout=timeout,
            base_url=f'https://openrouter.ai/api/v1',
            **kwargs,
        )

        super().__init__(model, prompt)


class DeepSeekV4ProPatcher(OpenRouterPatcher):
    name = "DeepSeek V4 Pro 0813"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="deepseek/deepseek-v4-pro-0813", extra_body={
            'reasoning': {'enabled': False},
            'provider': {
                'data_collection': 'deny',
                'require_parameters': True
            },
            'max_tokens': 16000
        }, **kwargs)

class GLM5_3Patcher(OpenRouterPatcher):
    name = "GLM 5.3"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="z-ai/glm-5.3", extra_body={
            'reasoning': {'enabled': False},
            'provider': {
                'data_collection': 'deny',
                'require_parameters': True
            },
            'max_tokens': 16000
        }, **kwargs)

class OpenrouterQwen3CoderPatcher(OpenRouterPatcher):
    name = "OpenRouter Qwen 3 Coder"

    def __init__(self, prompt: BasePrompt | None = None, **kwargs):
        super().__init__(prompt, model_name="qwen/qwen3-coder", extra_body={
            'reasoning': {'enabled': False},
            'provider': {
                'data_collection': 'deny',
            },
            'max_tokens': 16000
        }, **kwargs)