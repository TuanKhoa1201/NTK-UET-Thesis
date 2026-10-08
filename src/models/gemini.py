import os
import re
import time
from tqdm.contrib.concurrent import thread_map
from google import genai

from models.llm import LLM
from utils.mylogger import MyLogger


_model_name_map = {
    "gemini-2.5-flash-lite": "gemini-2.5-flash-lite",
    "gemini-2.5-flash": "gemini-2.5-flash",
    "gemini-3.5-flash": "gemini-3.5-flash",
    "gemini-3.1-flash-lite": "gemini-3.1-flash-lite",
}


class GeminiModel(LLM):

    def __init__(self, model_name, logger: MyLogger, **kwargs):

        self.logger = logger
        self.kwargs = kwargs

        self.model_name = model_name
        self.model_id = _model_name_map.get(model_name, model_name)

        api_key = kwargs.get(
            "google_api_key",
            os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"),
        )

        if not api_key:
            raise RuntimeError(
                "Neither GEMINI_API_KEY nor GOOGLE_API_KEY is set."
            )

        self.client = genai.Client(api_key=api_key)

    def log(self, msg):
        if self.logger is not None:
            self.logger.log(msg)

    def predict(
        self,
        prompt,
        expect_json=False,
        batch_size=0,
        no_progress_bar=False,
    ):

        if batch_size == 0:
            return self._predict(prompt, expect_json)

        args = range(len(prompt))

        responses = thread_map(
            lambda i: self._predict(prompt[i], expect_json),
            args,
            max_workers=1,
            disable=no_progress_bar,
        )

        return responses

    def _extract_retry_delay(self, error_msg):
        """
        Parse retryDelay from Gemini error message.

        Example:
            retryDelay': '54s'
        """
        m = re.search(r"retryDelay['\"]?:\s*['\"]?(\d+)s", error_msg)

        if m:
            return int(m.group(1)) + 1

        return None

    def _predict(self, main_prompt, expect_json=False):

        system_prompt = main_prompt[0]["content"]
        user_prompt = main_prompt[1]["content"]

        full_prompt = f"""System:
{system_prompt}

User:
{user_prompt}
"""

        config = {
            "temperature": 0,
        }

        if expect_json:
            config["response_mime_type"] = "application/json"

        last_exception = None

        MAX_RETRY = 10

        for attempt in range(MAX_RETRY):

            try:

                response = self.client.models.generate_content(
                    model=self.model_id,
                    contents=full_prompt,
                    config=config,
                )

                text = getattr(response, "text", None)

                if text is None:
                    raise RuntimeError("Gemini returned empty response.")

                text = text.strip()

                if text == "":
                    raise RuntimeError("Gemini returned blank response.")

                return text

            except Exception as e:

                last_exception = e

                err = str(e)

                self.log(
                    f"[Gemini] Attempt {attempt+1}/{MAX_RETRY} failed: {repr(e)}"
                )

                if attempt == MAX_RETRY - 1:
                    break

                wait = self._extract_retry_delay(err)

                if wait is None:
                    wait = min(2 ** attempt, 60)

                self.log(
                    f"[Gemini] Waiting {wait} seconds before retry..."
                )

                time.sleep(wait)

        raise RuntimeError(
            f"Gemini failed after {MAX_RETRY} attempts.\nLast error: {last_exception}"
        )
