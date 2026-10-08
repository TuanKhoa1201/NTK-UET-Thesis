import os

import ollama
from tqdm.contrib.concurrent import thread_map

from src.models.llm import LLM
from src.utils.mylogger import MyLogger


_model_name_map = {
    "ollama-qwen-coder": "qwen2.5-coder:latest",
    "ollama-qwen-coder-1.5b": "qwen2.5-coder:1.5b",
    "ollama-qwen": "qwen2.5:32b",
    "ollama-llama3": "llama3.2:latest",
    "ollama-deepseek-32b": "deepseek-r1:32b",
    "ollama-deepseek-7b": "deepseek-r1:latest",
}


_OLLAMA_DEFAULT_OPTIONS = {
    "temperature": 0.0,
    "num_predict": -1,
    "stop": None,
    "seed": 0,
}


class OllamaModel(LLM):
    def __init__(self, model_name, logger: MyLogger, **kwargs):
        super().__init__(model_name, logger, _model_name_map, **kwargs)

        host = os.environ.get(
            "OLLAMA_HOST",
            "http://127.0.0.1:11434",
        )

        self.client = ollama.Client(host=host)

        # OLLAMA_KEEPWARM_V1
        #
        # `keep_alive` controls only Ollama model residency/lifecycle.
        # It must not become part of semantic inference options or the
        # exact-request cache identity.
        raw_keep_alive = os.environ.get(
            "IRIS_OLLAMA_KEEP_ALIVE",
            "30m",
        ).strip()

        if raw_keep_alive.lower() in {
            "",
            "none",
            "default",
        }:
            self.keep_alive = None
        else:
            self.keep_alive = raw_keep_alive

        self.options = dict(_OLLAMA_DEFAULT_OPTIONS)

        self.options["temperature"] = kwargs.get(
            "temperature",
            0.0,
        )

        self.options["seed"] = kwargs.get(
            "seed",
            0,
        )

        max_new_tokens = kwargs.get("max_new_tokens")

        if max_new_tokens is not None:
            self.options["num_predict"] = int(max_new_tokens)

        if "num_predict" in kwargs:
            self.options["num_predict"] = int(
                kwargs["num_predict"]
            )

        if "stop" in kwargs:
            self.options["stop"] = kwargs["stop"]

    def predict(
        self,
        prompt,
        batch_size=0,
        no_progress_bar=False,
        expect_json=False,
        json_schema=None,
        **kwargs,
    ):
        if batch_size == 0:
            return self._predict(
                prompt,
                expect_json=expect_json,
            json_schema=json_schema,
            )

        args = range(0, len(prompt))

        responses = thread_map(
            lambda x: self._predict(
                prompt[x],
                expect_json=expect_json,
            json_schema=json_schema,
            ),
            args,
            max_workers=batch_size,
            disable=no_progress_bar,
        )

        return responses

    def _predict(
        self,
        main_prompt,
        expect_json=False,
        json_schema=None,
    ):
        if not isinstance(main_prompt, list):
            raise TypeError(
                "OllamaModel expects a list of chat messages"
            )

        request = {
            "model": self.model_id,
            "messages": main_prompt,
            "options": self.options,
        }

        if json_schema is not None:
            request["format"] = json_schema
        elif expect_json:
            request["format"] = "json"

        if self.keep_alive is not None:
            request["keep_alive"] = self.keep_alive

        try:
            response = self.client.chat(**request)

        except ollama.ResponseError as exc:
            raise RuntimeError(
                f"Ollama response error: {exc.error}"
            ) from exc

        return response.message.content
