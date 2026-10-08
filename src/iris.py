import random
import os
import sys
import subprocess as sp
import pandas as pd
import shutil
import json
import re
import argparse
import numpy as np
import copy
import math
import random

import requests
from tqdm import tqdm
from tqdm.contrib.concurrent import thread_map

THIS_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
IRIS_ROOT_DIR = os.path.abspath(f"{THIS_SCRIPT_DIR}/../")
sys.path.append(IRIS_ROOT_DIR)

from src.config import CODEQL_DIR, CODEQL_DB_PATH, PACKAGE_MODULES_PATH, OUTPUT_DIR, ALL_METHOD_INFO_DIR, PROJECT_SOURCE_CODE_DIR, CVES_MAPPED_W_COMMITS_DIR, CODEQL_QUERY_VERSION


from src.logger import Logger
from src.queries import QUERIES
from src.prompts import API_LABELLING_SYSTEM_PROMPT, API_LABELLING_USER_PROMPT
from src.prompts import FUNC_PARAM_LABELLING_SYSTEM_PROMPT, FUNC_PARAM_LABELLING_USER_PROMPT

from src.codeql_queries import QL_SOURCE_PREDICATE, QL_STEP_PREDICATE, QL_SINK_PREDICATE
from src.codeql_queries import EXTENSION_YML_TEMPLATE, EXTENSION_SRC_SINK_YML_ENTRY, EXTENSION_SUMMARY_YML_ENTRY
from src.codeql_queries import QL_METHOD_CALL_SOURCE_BODY_ENTRY, QL_FUNC_PARAM_SOURCE_ENTRY, QL_FUNC_PARAM_NAME_ENTRY
from src.codeql_queries import QL_SUMMARY_BODY_ENTRY, QL_BODY_OR_SEPARATOR
from src.codeql_queries import QL_SUBSET_PREDICATE, CALL_QL_SUBSET_PREDICATE
from src.codeql_queries import QL_SINK_BODY_ENTRY, QL_SINK_ARG_NAME_ENTRY, QL_SINK_ARG_THIS_ENTRY

from src.modules.codeql_query_runner import CodeQLQueryRunner
from src.modules.contextual_analysis_pipeline import ContextualAnalysisPipeline
from src.modules.evaluation_pipeline import EvaluationPipeline

from src.models.llm import LLM
import hashlib

CODEQL = f"{CODEQL_DIR}/codeql"

PRIMITIVE_TYPES = set([
    "void",
    "int",
    "boolean",
    "long",
    "Integer",
    "Boolean",
    "Object",
])

MAX_DOC_LENGTH = 50


class SAPipeline:
    def __init__(self,
            project_name: str,
            query: str,
            run_id: str = "default",
            llm: str = "gpt-4",
            label_api_batch_size: int = 10,
            label_func_param_batch_size: int = 10,
            num_threads: int = 3,
            seed: int = 1234,
            no_summary_model: bool = False,
            use_exhaustive_qll: bool = False,
            skip_huge_project: bool = False,
            skip_huge_project_num_apis_threshold: int = 3000,
            skip_posthoc_filter: bool = False,
            skip_evaluation: bool = False,
            filter_by_module: bool = False,
            filter_by_module_large: bool = False,
            posthoc_filtering_skip_fp: bool = False,
            posthoc_filtering_rerun_skipped_fp: bool = False,
            evaluation_only: bool = False,
            overwrite: bool = False,
            overwrite_api_candidates: bool = False,
            overwrite_func_param_candidates: bool = False,
            overwrite_labelled_apis: bool = False,
            overwrite_llm_cache: bool = False,
            overwrite_labelled_func_param: bool = False,
            overwrite_cwe_query_result: bool = False,
            overwrite_postprocess_cwe_query_result: bool = False,
            overwrite_posthoc_filter: bool = False,
            overwrite_debug_info: bool = False,
            debug_source: bool = False,
            debug_sink: bool = False,
            test_run: bool = False,
            no_logger: bool = False,
            use_container: bool = False,
    ):
        # Store basic information
        self.project_name = project_name
        self.query = query
        self.llm = llm
        self.label_api_batch_size = label_api_batch_size
        self.label_func_param_batch_size = label_func_param_batch_size
        self.num_threads = num_threads
        self.seed = seed
        self.run_id = f"{run_id}-docker" if use_container else run_id
        self.no_summary_model = no_summary_model
        self.use_exhaustive_qll = use_exhaustive_qll
        self.skip_huge_project = skip_huge_project
        self.skip_huge_project_num_apis_threshold = skip_huge_project_num_apis_threshold
        self.skip_posthoc_filter = skip_posthoc_filter
        self.skip_evaluation = skip_evaluation
        self.filter_by_module = filter_by_module
        self.filter_by_module_large = filter_by_module_large
        self.posthoc_filtering_skip_fp = posthoc_filtering_skip_fp
        self.posthoc_filtering_rerun_skipped_fp = posthoc_filtering_rerun_skipped_fp
        self.evaluation_only = evaluation_only
        self.overwrite = overwrite
        self.overwrite_api_candidates = overwrite_api_candidates
        self.overwrite_func_param_candidates = overwrite_func_param_candidates
        self.overwrite_labelled_apis = overwrite_labelled_apis
        self.overwrite_llm_cache = overwrite_llm_cache
        self.overwrite_labelled_func_param = overwrite_labelled_func_param
        self.overwrite_cwe_query_result = overwrite_cwe_query_result
        self.overwrite_postprocess_cwe_query_result = overwrite_postprocess_cwe_query_result
        self.overwrite_posthoc_filter = overwrite_posthoc_filter
        self.overwrite_debug_info = overwrite_debug_info
        self.debug_source = debug_source
        self.debug_sink = debug_sink
        self.test_run = test_run
        self.no_logger = no_logger
        self.use_container = use_container

        # Setup logger
        if not self.no_logger:
            self.master_logger = Logger(f"{IRIS_ROOT_DIR}/log")

        # Check if the query is valid
        if self.query in QUERIES:
            if "cwe_id" not in QUERIES[self.query]:
                if not self.no_logger:
                    self.master_logger.info(f"Processing {self.project_name} (Query: {self.query}, Trial: {self.run_id})...")
                    self.master_logger.error(f"==> Query `{self.query}` is not a query for detecting CWE; aborting")
                raise Exception(f"Query `{self.query}` is not a query for detecting CWE; aborting")
        else:
            if not self.no_logger:
                self.master_logger.info(f"Processing {self.project_name} (Query: {self.query}, Trial: {self.run_id})...")
                self.master_logger.error(f"==> Unknown query `{self.query}`; aborting")
            raise Exception(f"Unknown query `{self.query}`; aborting")
        self.cwe_id = QUERIES[self.query]["cwe_id"]

        # Extract the CVE identifier from the project name instead of relying
        # on a fixed underscore-delimited position.
        cve_match = re.search(
            r"CVE-[0-9]{4}-[0-9]+",
            project_name,
            flags=re.IGNORECASE,
        )
        self.cve_id = (
            cve_match.group(0).upper()
            if cve_match is not None
            else None
        )

        # Load some basic information, such as commits and fixes related to the CVE
        self.project_source_code_dir = f"{PROJECT_SOURCE_CODE_DIR}/{self.project_name}"
        self.project_cve_with_commit_info = None
        self.cve_fixing_commits = []

        if self.cve_id is not None and self.cve_id.startswith("CVE-"):
            self.all_cves_with_commit = pd.read_csv(CVES_MAPPED_W_COMMITS_DIR)

            matching_cves = self.all_cves_with_commit[
                self.all_cves_with_commit["cve_id"] == self.cve_id
            ]

            if not matching_cves.empty:
                self.project_cve_with_commit_info = matching_cves.iloc[0]

                raw_fix_commit_ids = self.project_cve_with_commit_info.get(
                    "fix_commit_ids",
                    "",
                )

                if pd.notna(raw_fix_commit_ids):
                    self.cve_fixing_commits = [
                        commit_id.strip()
                        for commit_id in str(raw_fix_commit_ids).split(";")
                        if commit_id.strip()
                    ]
        self.fixed_methods = pd.read_csv(ALL_METHOD_INFO_DIR)
        self.project_fixed_methods = self.fixed_methods[self.fixed_methods["project_slug"] == self.project_name]
        self.project_fixed_modules = self.project_fixed_methods[
            self.project_fixed_methods["file"].str.contains("src/main") &
            self.project_fixed_methods["file"].str.endswith(".java")]
        self.fixed_modules = self.project_fixed_modules \
            .apply(lambda f: \
                pd.Series([
                    f["file"][:f["file"].index("src/main") - 1] if f["file"].index("src/main") > 1 else ""
                ], index=["module"]), axis=1, result_type="expand") \
            .drop_duplicates()

        # Basic path information
        self.project_output_path = f"{OUTPUT_DIR}/{self.project_name}/{self.run_id}"

        # Setup codeql database path
        db_project_name = f"{self.project_name}-docker" if self.use_container else self.project_name
        self.project_codeql_db_path = f"{CODEQL_DB_PATH}/{db_project_name}"
        if not os.path.exists(f"{self.project_codeql_db_path}/db-java"):
            if not self.no_logger:
                self.master_logger.info(f"Processing {self.project_name} (Query: {self.query}, Trial: {self.run_id})...")
                self.master_logger.error(f"==> Cannot find CodeQL database for {self.project_name}; aborting")
            raise Exception(f"Cannot find CodeQL database for {self.project_codeql_db_path}; aborting")

        # Setup consolidated analysis directory with common/ and cwe-{query}/ subdirectories
        self.analysis_output_path = f"{self.project_output_path}/analysis"
        self.analysis_common_path = f"{self.analysis_output_path}/common"
        self.analysis_cwe_path = f"{self.analysis_output_path}/{self.query}"
        os.makedirs(self.analysis_common_path, exist_ok=True)
        os.makedirs(self.analysis_cwe_path, exist_ok=True)

        # Setup custom CodeQL qlpack structure
        self.custom_codeql_root = f"{self.project_output_path}/myqueries"

        # Create qlpack.yml for the custom package
        self._create_custom_qlpack_yml()

        # Path towards external APIs (fetch query results in old structure)
        self.external_apis_csv_path = f"{self.project_output_path}/fetch_external_apis/results.csv"
        self.candidate_apis_csv_path = f"{self.analysis_common_path}/candidate_apis.csv"

        # Path towards function parameters (fetch query results in old structure)
        self.func_param_path = f"{self.project_output_path}/fetch_func_params/results.csv"
        self.source_func_param_candidates_path = f"{self.analysis_common_path}/source_func_param_candidates.csv"

        # Function and Class locations (fetch query results in old structure)
        self.func_locs_path = f"{self.project_output_path}/fetch_func_locs/results.csv"
        self.class_locs_path = f"{self.project_output_path}/fetch_class_locs/results.csv"

        # LLM labelled results (CWE-specific analysis data)
        self.llm_labelled_sink_apis_path = f"{self.analysis_cwe_path}/llm_labelled_sink_apis.json"
        self.llm_labelled_source_apis_path = f"{self.analysis_cwe_path}/llm_labelled_source_apis.json"
        self.llm_labelled_taint_prop_apis_path = f"{self.analysis_cwe_path}/llm_labelled_taint_prop_apis.json"
        self.llm_labelled_source_func_params_path = f"{self.analysis_cwe_path}/llm_labelled_source_func_params.json"

        # LLM related log paths (CWE-specific)
        self.label_api_log_path = f"{self.analysis_cwe_path}/logs/label_apis"
        self.label_func_params_log_path = f"{self.analysis_cwe_path}/logs/label_func_params"
        os.makedirs(self.label_api_log_path, exist_ok=True)
        os.makedirs(self.label_func_params_log_path, exist_ok=True)

        # CodeQL queries paths - generate files directly in final destination
        cwe_query_dir = f"{self.custom_codeql_root}/{self.query}"

        self.source_qll_path = f"{cwe_query_dir}/MySources.qll"
        self.summary_qll_path = f"{cwe_query_dir}/MySummaries.qll"
        self.sink_qll_path = f"{cwe_query_dir}/MySinks.qll"
        self.spec_yml_path = f"{cwe_query_dir}/specs.model.yml"

        # Setup query output path
        self.query_output_path = f"{self.project_output_path}/{self.query}"
        os.makedirs(self.query_output_path, exist_ok=True)
        self.query_output_result_sarif_path = f"{self.query_output_path}/results.sarif"
        self.query_output_result_sarif_pp_path = f"{self.query_output_path}/results_pp.sarif"
        self.query_output_result_csv_path = f"{self.query_output_path}/results.csv"

        # Setup posthoc-filtering output path
        self.posthoc_filtering_output_path = f"{self.project_output_path}/{self.query}-posthoc-filter"
        os.makedirs(self.posthoc_filtering_output_path, exist_ok=True)
        self.posthoc_filtering_output_result_sarif_path = f"{self.posthoc_filtering_output_path}/results.sarif"
        self.posthoc_filtering_output_result_json_path = f"{self.posthoc_filtering_output_path}/results.json"
        self.posthoc_filtering_output_stats_json_path = f"{self.posthoc_filtering_output_path}/stats.json"
        self.posthoc_filtering_output_log_path = f"{self.posthoc_filtering_output_path}/logs"
        os.makedirs(self.posthoc_filtering_output_log_path, exist_ok=True)

        # Setup final output path
        self.final_output_path = f"{self.project_output_path}/{self.query}-final"
        os.makedirs(self.final_output_path, exist_ok=True)
        self.final_output_json_path = f"{self.final_output_path}/results.json"

        # Create logger
        if not self.no_logger:
            self.project_logging_directory = f"{self.project_output_path}/log"
            os.makedirs(self.project_logging_directory, exist_ok=True)
            self.project_logger = Logger(self.project_logging_directory)
            self.project_logger.info(f"Processing {self.project_name} (Query: {self.query}, Trial: {self.run_id})...")
        else:
            self.project_logger = None

        # Setup cache path
        self.common_cache_path = f"{OUTPUT_DIR}/common/{self.run_id}/cwe-{self.cwe_id}"
        if not os.path.exists(self.common_cache_path):
            os.makedirs(self.common_cache_path, exist_ok=True)
        self.api_labels_cache_path = f"{self.common_cache_path}/api_labels_{self.llm}.json"
        self.model = None

    def _create_custom_qlpack_yml(self):
        """Create qlpack.yml for the custom CodeQL package"""
        qlpack_content = f"""
name: iris
version: 1.0.0
dependencies:
  codeql/java-all: "9.1.2"
  codeql/java-queries: "1.11.4"
"""
        qlpack_path = f"{self.custom_codeql_root}/qlpack.yml"
        os.makedirs(self.custom_codeql_root, exist_ok=True)
        with open(qlpack_path, 'w') as f:
            f.write(qlpack_content)

        # CODEQL_LOCAL_LOCK_V1
        # Materialize the frozen dependency graph for this run.
        canonical_lock_path = os.path.join(
            os.path.dirname(__file__),
            "queries",
            "codeql-pack.lock.yml",
        )

        generated_lock_path = os.path.join(
            self.custom_codeql_root,
            "codeql-pack.lock.yml",
        )

        if not os.path.isfile(canonical_lock_path):
            raise RuntimeError(
                "Missing canonical CodeQL lock file: "
                f"{canonical_lock_path}"
            )

        with open(
            canonical_lock_path,
            "rb",
        ) as src_lock:
            lock_bytes = src_lock.read()

        with open(
            generated_lock_path,
            "wb",
        ) as dst_lock:
            dst_lock.write(lock_bytes)
            
    def get_model(self):
        if self.model is None:
            self.model = LLM.get_llm(model_name=self.llm, logger=self.project_logger, kwargs={"seed": self.seed, "max_new_tokens": 2048})
        return self.model

    # STAGE3_EXACT_LLM_CACHE_V1
    #
    # Content-addressed cache for the exact Ollama Stage 3 request.
    # This stores the raw model response, not a derived source/sink verdict.
    # The normal Stage 3 parser/normalizer still runs on cache hits.
    #
    # Fail closed: if the local Ollama model digest cannot be resolved,
    # persistent cross-run caching is disabled for that request.
    def _stage3_exact_cache_model_identity(self, model):
        if getattr(
            self,
            "_stage3_exact_cache_identity_checked",
            False,
        ):
            return getattr(
                self,
                "_stage3_exact_cache_identity_value",
                None,
            )

        self._stage3_exact_cache_identity_checked = True
        identity = None

        if not self.llm.lower().startswith("ollama"):
            self._stage3_exact_cache_identity_value = None
            return None

        model_id = str(
            getattr(model, "model_id", "")
        ).strip()

        try:
            listing = model.client.list()

            if isinstance(listing, dict):
                models = listing.get("models", []) or []
            else:
                models = getattr(
                    listing,
                    "models",
                    [],
                ) or []

            for entry in models:
                if isinstance(entry, dict):
                    entry_name = (
                        entry.get("model")
                        or entry.get("name")
                        or ""
                    )
                    digest = entry.get("digest")
                else:
                    entry_name = (
                        getattr(entry, "model", None)
                        or getattr(entry, "name", None)
                        or ""
                    )
                    digest = getattr(
                        entry,
                        "digest",
                        None,
                    )

                if (
                    str(entry_name).strip() == model_id
                    and digest
                ):
                    identity = {
                        "model_id": model_id,
                        "model_digest": str(digest),
                    }
                    break

        except Exception as e:
            if self.project_logger is not None:
                self.project_logger.info(
                    "  ==> Stage 3 exact cache disabled: "
                    "could not resolve Ollama model digest: "
                    f"{e}"
                )

        if (
            identity is None
            and self.project_logger is not None
        ):
            self.project_logger.info(
                "  ==> Stage 3 exact cache disabled: "
                f"no digest found for model {model_id!r}"
            )

        self._stage3_exact_cache_identity_value = (
            identity
        )

        return identity

    def _stage3_predict_with_exact_cache(
        self,
        prompt,
    ):
        import hashlib

        model = self.get_model()

        # Preserve upstream behavior for non-Ollama backends.
        if not self.llm.lower().startswith("ollama"):
            return (
                model.predict(
                    prompt,
                    expect_json=True,
                ),
                False,
                None,
            )

        identity = (
            self._stage3_exact_cache_model_identity(
                model
            )
        )

        # Fail closed rather than risk a stale cache when model
        # identity cannot be proven.
        if identity is None:
            return (
                model.predict(
                    prompt,
                    expect_json=True,
                ),
                False,
                None,
            )

        options = dict(
            getattr(
                model,
                "options",
                {},
            )
        )

        request_identity = {
            "cache_version": 1,
            "stage": "stage3_api_src_tp_sink",
            "query": self.query,
            "cwe_id": str(self.cwe_id),
            "model_alias": self.llm,
            "model_id": identity["model_id"],
            "model_digest": identity[
                "model_digest"
            ],
            "messages": prompt,
            "options": options,
            "expect_json": True,
            "json_schema": None,
            "format": "json",
        }

        canonical_request = json.dumps(
            request_identity,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

        cache_key = hashlib.sha256(
            canonical_request.encode("utf-8")
        ).hexdigest()

        cache_root = os.environ.get(
            "IRIS_EXACT_LLM_CACHE_DIR"
        )

        if not cache_root:
            cache_root = os.path.join(
                OUTPUT_DIR,
                "common",
                "exact_llm_cache_v1",
            )

        cache_dir = os.path.join(
            cache_root,
            "stage3",
            cache_key[:2],
        )

        cache_path = os.path.join(
            cache_dir,
            f"{cache_key}.json",
        )

        if (
            not self.overwrite_llm_cache
            and os.path.isfile(cache_path)
        ):
            try:
                with open(
                    cache_path,
                    "r",
                    encoding="utf-8",
                ) as f:
                    cached = json.load(f)

                if (
                    cached.get("request")
                    == request_identity
                    and isinstance(
                        cached.get("response"),
                        str,
                    )
                ):
                    return (
                        cached["response"],
                        True,
                        cache_key,
                    )

            except (
                OSError,
                json.JSONDecodeError,
                TypeError,
            ) as e:
                if self.project_logger is not None:
                    self.project_logger.info(
                        "  ==> Ignoring invalid Stage 3 "
                        f"exact-cache entry {cache_key}: "
                        f"{e}"
                    )

        response = model.predict(
            prompt,
            expect_json=True,
        )

        if not self.test_run:
            os.makedirs(
                cache_dir,
                exist_ok=True,
            )

            cache_obj = {
                "request": request_identity,
                "response": response,
            }

            temp_path = (
                f"{cache_path}.tmp."
                f"{os.getpid()}"
            )

            try:
                with open(
                    temp_path,
                    "w",
                    encoding="utf-8",
                ) as f:
                    json.dump(
                        cache_obj,
                        f,
                        ensure_ascii=False,
                        sort_keys=True,
                        indent=2,
                    )

                os.replace(
                    temp_path,
                    cache_path,
                )

            except OSError:
                # Caching must never change Stage 3 semantics.
                # If persistence fails, the freshly generated
                # response is still returned normally.
                try:
                    if os.path.isfile(temp_path):
                        os.unlink(temp_path)
                except OSError:
                    pass

        return (
            response,
            False,
            cache_key,
        )

    # STAGE4_EXACT_LLM_CACHE_V1
    #
    # Cache the RAW response of the exact Ollama request.
    # Contract validation and normalization remain unchanged and
    # are executed again even on cache hits.
    #
    # Stage 4 classification itself is CWE-independent, so query
    # and cwe_id are deliberately NOT part of this exact-request
    # identity. Identical Stage 4 prompts may therefore be reused
    # across CWE jobs.
    def _stage4_predict_with_exact_cache(
        self,
        prompt,
        request_kind,
    ):
        import hashlib

        model = self.get_model()

        if not self.llm.lower().startswith("ollama"):
            return (
                model.predict(
                    prompt,
                    expect_json=True,
                ),
                False,
                None,
            )

        identity = (
            self._stage3_exact_cache_model_identity(
                model
            )
        )

        # Fail closed when exact model identity cannot be proven.
        if identity is None:
            return (
                model.predict(
                    prompt,
                    expect_json=True,
                ),
                False,
                None,
            )

        request_kind = str(request_kind)

        if request_kind not in {
            "initial",
            "retry",
        }:
            raise ValueError(
                "Invalid Stage 4 exact-cache request kind: "
                f"{request_kind!r}"
            )

        options = dict(
            getattr(
                model,
                "options",
                {},
            )
        )

        request_identity = {
            "cache_version": 1,
            "stage": "stage4_func_param_src",
            "request_kind": request_kind,
            "model_alias": self.llm,
            "model_id": identity["model_id"],
            "model_digest": identity[
                "model_digest"
            ],
            "messages": prompt,
            "options": options,
            "expect_json": True,
            "json_schema": None,
            "format": "json",
        }

        canonical_request = json.dumps(
            request_identity,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

        cache_key = hashlib.sha256(
            canonical_request.encode("utf-8")
        ).hexdigest()

        cache_root = os.environ.get(
            "IRIS_EXACT_LLM_CACHE_DIR"
        )

        if not cache_root:
            cache_root = os.path.join(
                OUTPUT_DIR,
                "common",
                "exact_llm_cache_v1",
            )

        cache_dir = os.path.join(
            cache_root,
            "stage4",
            cache_key[:2],
        )

        cache_path = os.path.join(
            cache_dir,
            f"{cache_key}.json",
        )

        if (
            not self.overwrite_llm_cache
            and os.path.isfile(cache_path)
        ):
            try:
                with open(
                    cache_path,
                    "r",
                    encoding="utf-8",
                ) as f:
                    cached = json.load(f)

                if (
                    cached.get("request")
                    == request_identity
                    and isinstance(
                        cached.get("response"),
                        str,
                    )
                ):
                    return (
                        cached["response"],
                        True,
                        cache_key,
                    )

            except (
                OSError,
                json.JSONDecodeError,
                TypeError,
            ) as e:
                if self.project_logger is not None:
                    self.project_logger.info(
                        "  ==> Ignoring invalid Stage 4 "
                        f"exact-cache entry {cache_key}: "
                        f"{e}"
                    )

        response = model.predict(
            prompt,
            expect_json=True,
        )

        if not self.test_run:
            os.makedirs(
                cache_dir,
                exist_ok=True,
            )

            cache_obj = {
                "request": request_identity,
                "response": response,
            }

            temp_path = (
                f"{cache_path}.tmp."
                f"{os.getpid()}"
            )

            try:
                with open(
                    temp_path,
                    "w",
                    encoding="utf-8",
                ) as f:
                    json.dump(
                        cache_obj,
                        f,
                        ensure_ascii=False,
                        sort_keys=True,
                        indent=2,
                    )

                os.replace(
                    temp_path,
                    cache_path,
                )

            except OSError:
                # Cache persistence must never alter Stage 4
                # analysis semantics.
                try:
                    if os.path.isfile(temp_path):
                        os.unlink(temp_path)
                except OSError:
                    pass

        return (
            response,
            False,
            cache_key,
        )

    # STATIC_STAGE12_CACHE_V1
    #
    # Persistent content-addressed cache for deterministic
    # Stage 1/2 extraction + filtering.
    #
    # Invalidation is deliberately conservative.
    def _static_cache_sha256_file(self, path):
        import hashlib

        path = os.path.abspath(str(path))

        try:
            stat = os.stat(path)
        except OSError:
            return None

        memo = getattr(
            self,
            "_static_cache_file_hash_memo",
            None,
        )

        if memo is None:
            memo = {}
            self._static_cache_file_hash_memo = memo

        key = (
            path,
            stat.st_size,
            stat.st_mtime_ns,
        )

        if key in memo:
            return memo[key]

        h = hashlib.sha256()

        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)

                if not chunk:
                    break

                h.update(chunk)

        digest = h.hexdigest()
        memo[key] = digest

        return digest

    def _static_cache_codeql_version(self):
        import subprocess

        cached = getattr(
            self,
            "_static_cache_codeql_version_value",
            None,
        )

        if cached is not None:
            return cached

        try:
            from src.modules.codeql_query_runner import CODEQL

            result = subprocess.run(
                [CODEQL, "version"],
                check=True,
                capture_output=True,
                text=True,
            )

            value = result.stdout.strip()

        except Exception as e:
            if self.project_logger is not None:
                self.project_logger.info(
                    "  ==> Static Stage 1/2 cache disabled: "
                    f"cannot resolve CodeQL version: {e}"
                )

            return None

        self._static_cache_codeql_version_value = value

        return value

    def _static_stage_cache_fingerprint(
        self,
        stage_name,
        query_name,
    ):
        import hashlib
        import sys

        memo = getattr(
            self,
            "_static_stage_cache_fingerprint_memo",
            None,
        )

        if memo is None:
            memo = {}
            self._static_stage_cache_fingerprint_memo = memo

        memo_key = (
            str(stage_name),
            str(query_name),
        )

        if memo_key in memo:
            return memo[memo_key]

        codeql_version = (
            self._static_cache_codeql_version()
        )

        if not codeql_version:
            return None

        iris_dir = os.path.abspath(
            os.path.dirname(__file__)
        )

        package_path = os.path.join(
            PACKAGE_MODULES_PATH,
            f"{self.project_name}.txt",
        )

        required_files = [
            (
                "db/codeql-database.yml",
                os.path.join(
                    self.project_codeql_db_path,
                    "codeql-database.yml",
                ),
            ),
            (
                "db/src.zip",
                os.path.join(
                    self.project_codeql_db_path,
                    "src.zip",
                ),
            ),
            (
                "package_names",
                package_path,
            ),
            (
                "iris.py",
                os.path.abspath(__file__),
            ),
            (
                "config.py",
                os.path.join(
                    iris_dir,
                    "config.py",
                ),
            ),
            (
                "queries.py",
                os.path.join(
                    iris_dir,
                    "queries.py",
                ),
            ),
            (
                "qlpack.yml",
                os.path.join(
                    self.custom_codeql_root,
                    "qlpack.yml",
                ),
            ),
            (
                "codeql-pack.lock.yml",
                os.path.join(
                    self.custom_codeql_root,
                    "codeql-pack.lock.yml",
                ),
            ),
        ]

        if query_name not in QUERIES:
            return None

        for rel in QUERIES[query_name].get(
            "queries",
            [],
        ):
            required_files.append(
                (
                    f"query:{rel}",
                    os.path.join(
                        iris_dir,
                        rel,
                    ),
                )
            )

        file_hashes = {}

        for label, path in required_files:
            digest = self._static_cache_sha256_file(
                path
            )

            if digest is None:
                if self.project_logger is not None:
                    self.project_logger.info(
                        "  ==> Static Stage 1/2 cache disabled: "
                        f"missing fingerprint input {path}"
                    )

                return None

            file_hashes[label] = digest

        try:
            fixed_modules = (
                self.fixed_modules.to_dict(
                    orient="records"
                )
                if hasattr(
                    self.fixed_modules,
                    "to_dict",
                )
                else []
            )
        except Exception:
            fixed_modules = []

        runtime_config = {
            "project_name": self.project_name,
            "filter_by_module": getattr(
                self,
                "filter_by_module",
                None,
            ),
            "filter_by_module_large": getattr(
                self,
                "filter_by_module_large",
                None,
            ),
            "skip_huge_project_num_apis_threshold": getattr(
                self,
                "skip_huge_project_num_apis_threshold",
                None,
            ),
            "use_container": getattr(
                self,
                "use_container",
                None,
            ),
            "fixed_modules": fixed_modules,
            "python_version": sys.version,
            "pandas_version": pd.__version__,
        }

        identity = {
            "cache_version": 1,
            "stage": str(stage_name),
            "query": str(query_name),
            "codeql_version": codeql_version,
            "files": file_hashes,
            "runtime_config": runtime_config,
        }

        canonical = json.dumps(
            identity,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )

        fingerprint = hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()

        memo[memo_key] = (
            fingerprint,
            identity,
        )

        return memo[memo_key]

    def _static_stage_cache_dir(
        self,
        stage_name,
        fingerprint,
    ):
        root = os.environ.get(
            "IRIS_STATIC_CACHE_DIR"
        )

        if not root:
            root = os.path.join(
                OUTPUT_DIR,
                "common",
                "static_stage_cache_v1",
            )

        return os.path.join(
            root,
            str(stage_name),
            fingerprint[:2],
            fingerprint,
        )

    def _restore_static_stage_cache(
        self,
        stage_name,
        query_name,
        artifacts,
    ):
        import shutil

        info = self._static_stage_cache_fingerprint(
            stage_name,
            query_name,
        )

        if info is None:
            return False

        fingerprint, identity = info

        cache_dir = self._static_stage_cache_dir(
            stage_name,
            fingerprint,
        )

        manifest_path = os.path.join(
            cache_dir,
            "manifest.json",
        )

        if not os.path.isfile(manifest_path):
            return False

        try:
            with open(
                manifest_path,
                "r",
                encoding="utf-8",
            ) as f:
                manifest = json.load(f)

        except (
            OSError,
            json.JSONDecodeError,
            TypeError,
        ):
            return False

        if manifest.get("fingerprint") != fingerprint:
            return False

        if manifest.get("identity") != identity:
            return False

        entries = manifest.get("artifacts")

        if not isinstance(entries, dict):
            return False

        validated = []

        for label, destination in artifacts:
            entry = entries.get(label)

            if not isinstance(entry, dict):
                return False

            cache_name = entry.get("cache_name")
            expected_hash = entry.get("sha256")

            if (
                not isinstance(cache_name, str)
                or not isinstance(expected_hash, str)
            ):
                return False

            cache_path = os.path.join(
                cache_dir,
                cache_name,
            )

            if not os.path.isfile(cache_path):
                return False

            actual_hash = (
                self._static_cache_sha256_file(
                    cache_path
                )
            )

            if actual_hash != expected_hash:
                return False

            validated.append(
                (
                    cache_path,
                    destination,
                )
            )

        for cache_path, destination in validated:
            os.makedirs(
                os.path.dirname(destination),
                exist_ok=True,
            )

            tmp = (
                f"{destination}.static-cache-tmp."
                f"{os.getpid()}"
            )

            shutil.copy2(
                cache_path,
                tmp,
            )

            os.replace(
                tmp,
                destination,
            )

        return True

    def _store_static_stage_cache(
        self,
        stage_name,
        query_name,
        artifacts,
    ):
        import shutil

        if self.test_run:
            return None

        info = self._static_stage_cache_fingerprint(
            stage_name,
            query_name,
        )

        if info is None:
            return None

        fingerprint, identity = info

        for _label, source in artifacts:
            if not os.path.isfile(source):
                return None

        cache_dir = self._static_stage_cache_dir(
            stage_name,
            fingerprint,
        )

        os.makedirs(
            cache_dir,
            exist_ok=True,
        )

        artifact_manifest = {}

        for index, (label, source) in enumerate(
            artifacts
        ):
            cache_name = (
                f"{index:02d}_{label}.csv"
            )

            cache_path = os.path.join(
                cache_dir,
                cache_name,
            )

            source_hash = (
                self._static_cache_sha256_file(
                    source
                )
            )

            tmp = (
                f"{cache_path}.tmp."
                f"{os.getpid()}"
            )

            shutil.copy2(
                source,
                tmp,
            )

            os.replace(
                tmp,
                cache_path,
            )

            artifact_manifest[label] = {
                "cache_name": cache_name,
                "sha256": source_hash,
            }

        manifest = {
            "fingerprint": fingerprint,
            "identity": identity,
            "artifacts": artifact_manifest,
        }

        manifest_path = os.path.join(
            cache_dir,
            "manifest.json",
        )

        tmp_manifest = (
            f"{manifest_path}.tmp."
            f"{os.getpid()}"
        )

        with open(
            tmp_manifest,
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(
                manifest,
                f,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
                default=str,
            )

        os.replace(
            tmp_manifest,
            manifest_path,
        )

        return fingerprint

    def run_simple_codeql_query(self, query, target_csv_path=None, suffix=None, dyn_queries={}):
        runner = CodeQLQueryRunner(self.project_output_path, self.project_codeql_db_path, self.project_logger)
        runner.run(query, target_csv_path, suffix, dyn_queries)

    def keep_external_packages(self, api_candidates_df):
        packages = open(f"{PACKAGE_MODULES_PATH}/{self.project_name}.txt").readlines()
        packages = [p.strip() for p in packages]

        return api_candidates_df[
            ~api_candidates_df["package"].apply(
                lambda pkg: any(
                    pkg == p or pkg.startswith(p + ".")
                    for p in packages
                )
            )
        ]

    def keep_internal_packages(self, api_candidates_df):
        packages = open(f"{PACKAGE_MODULES_PATH}/{self.project_name}.txt").readlines()
        packages = [p.strip() for p in packages]

        return api_candidates_df[
            api_candidates_df["package"].apply(
                lambda pkg: any(
                    pkg == p or pkg.startswith(p + ".")
                    for p in packages
                )
            )
        ]

    def api_candidate_is_in_fixed_module(self, external_api_candidate_row):
        if len(self.fixed_modules) > 0:
            return any(f"{s}/src/main" in external_api_candidate_row["location"] for s in self.fixed_modules["module"])
        else:
            return True

    def api_candidate_has_non_trivial_return(self, external_api_candidate_row):
        """
        A candidate has non trivial return if the candidate is a constructor or return non primitive type
        """
        if external_api_candidate_row["callstr"].startswith("new "): return True
        else: return external_api_candidate_row["return_type"] not in PRIMITIVE_TYPES

    def api_candidate_has_non_trivial_parameter(self, row):
        """
        A candidate has non trivial parameter if the candidate is
        1. static method with at least one non-trivial parameter
        2. non-static method
        """
        if row["is_static"]:
            param_types_raw = "" if type(row["parameter_types"]) == float else row["parameter_types"]
            param_types = param_types_raw.split(";")
            return any(param_ty not in PRIMITIVE_TYPES for param_ty in param_types)
        else:
            return True

    def api_candidate_not_on_blacklist(self, external_api_candidate_row):
        row = external_api_candidate_row
        if row["package"] == "java.util" and row["clazz"] == "String": return False
        if row["package"] == "java.util" and row["clazz"] == "EnumSet": return False
        if row["package"] == "java.util" and row["clazz"] == "LinkedList": return False
        if row["package"] == "java.util" and row["clazz"] == "List": return False
        if row["package"] == "java.io" and row["clazz"] == "PrintStream": return False
        else: return True

    def api_is_candidate(self, candidate, num_external_apis):
        if self.api_candidate_not_on_blacklist(candidate):
            if self.filter_by_module and not self.api_candidate_is_in_fixed_module(candidate):
                return False
            elif self.filter_by_module_large and num_external_apis >  self.skip_huge_project_num_apis_threshold and not self.api_candidate_is_in_fixed_module(candidate):
                return False
            return self.api_candidate_has_non_trivial_parameter(candidate) or \
                   self.api_candidate_has_non_trivial_return(candidate)
        else:
            return False

    def collect_invoked_external_apis(self):
        self.project_logger.info("==> Stage 1: Collecting external APIs...")

        stage1_cache_artifacts = [
            ("raw", self.external_apis_csv_path),
            ("filtered", self.candidate_apis_csv_path),
        ]

        if (
            not self.overwrite
            and not self.overwrite_api_candidates
            and self._restore_static_stage_cache(
                "stage1_external_apis",
                "fetch_external_apis",
                stage1_cache_artifacts,
            )
        ):
            self.project_logger.info(
                "  ==> Stage 1 static cache: HIT"
            )
            return

        self.project_logger.info(
            "  ==> Stage 1 static cache: MISS"
        )

        # 1. Invoke CodeQL to extract the external APIs
        if not os.path.exists(self.external_apis_csv_path) or self.overwrite or self.overwrite_api_candidates:
            self.project_logger.info("  ==> Extracting all external APIs by running CodeQL... ", no_new_line=True)
            self.run_simple_codeql_query("fetch_external_apis")
            self.project_logger.print("Done.")
        else:
            self.project_logger.info("  ==> Existing external APIs file found. Skipping running CodeQL...")

        # 2. Load the API candidates
        if not os.path.exists(self.candidate_apis_csv_path) or self.overwrite or self.overwrite_api_candidates:
            external_api_candidates = pd.read_csv(self.external_apis_csv_path)
            num_external_apis = len(external_api_candidates)

            # 3. Filter the APIs by internal/external, and source/sink/taint-prop
            external_api_candidates = self.keep_external_packages(external_api_candidates)
            possible_src_snk_tp = external_api_candidates.apply(lambda row: self.api_is_candidate(row, num_external_apis), axis=1)
            external_api_candidates = external_api_candidates[possible_src_snk_tp]

            # 4. Keep only the core columns (package, class, function, signature) and deduplicate
            external_api_candidates = external_api_candidates[["package", "clazz", "func", "full_signature"]].drop_duplicates()
            num_candidates = len(external_api_candidates)

            # 5. Dump the filtered API candidates
            self.project_logger.info(f"  ==> #Relevant API Calls: {num_external_apis}, #Filtered Candidates: {num_candidates}")
            self.project_logger.info("  ==> Dumping filtered API candidates...")
            external_api_candidates.to_csv(self.candidate_apis_csv_path, index=False, header=True, sep=',', encoding='utf-8')
        else:
            self.project_logger.info("  ==> Existing candidate APIs file found. Skipping filtering candidates...")

        stage1_cache_key = self._store_static_stage_cache(
            "stage1_external_apis",
            "fetch_external_apis",
            stage1_cache_artifacts,
        )

        if stage1_cache_key is not None:
            self.project_logger.info(
                "  ==> Stage 1 static cache: STORED "
                f"{stage1_cache_key}"
            )

    def func_parameter_has_non_trivial_parameter(self, row):
        param_types_raw = "" if type(row["parameter_types"]) == float else row["parameter_types"]
        param_types = param_types_raw.split(";")
        return any(param_ty not in PRIMITIVE_TYPES for param_ty in param_types)

    def func_parameter_not_on_blacklist(self, row):
        if row["func"] == "isEqual" or row["func"] == "toString" or row["func"] == "equals" or row["func"] == "canConvert" or row["func"] == "compareTo" or row["func"] == "compare":
            return False
        elif "src/test" in row["location"]:
            return False
        else:
            return True

    def func_parameter_is_candidate(self, row):
        if self.func_parameter_not_on_blacklist(row):
            if self.filter_by_module and not self.api_candidate_is_in_fixed_module(row):
                return False
            return self.func_parameter_has_non_trivial_parameter(row)
        else:
            return False

    def collect_internal_function_parameters(self):
        self.project_logger.info("==> Stage 2: Collecting internal function parameters...")

        stage2_cache_artifacts = [
            ("raw", self.func_param_path),
            (
                "filtered",
                self.source_func_param_candidates_path,
            ),
        ]

        if (
            not self.overwrite
            and not self.overwrite_func_param_candidates
            and self._restore_static_stage_cache(
                "stage2_func_params",
                "fetch_func_params",
                stage2_cache_artifacts,
            )
        ):
            self.project_logger.info(
                "  ==> Stage 2 static cache: HIT"
            )
            return

        self.project_logger.info(
            "  ==> Stage 2 static cache: MISS"
        )

        # 1. Invoke CodeQL to extract the internal function parameters
        if not os.path.exists(self.func_param_path) or self.overwrite or self.overwrite_func_param_candidates:
            self.project_logger.info("  ==> Extracting all function parameters by running CodeQL... ", no_new_line=True)
            self.run_simple_codeql_query("fetch_func_params")
            self.project_logger.print("Done.")
        else:
            self.project_logger.info("  ==> Existing function parameter file found. Skipping running CodeQL...")

        # 2. Filter it to get function parameter source candidates
        if not os.path.exists(self.source_func_param_candidates_path) or self.overwrite or self.overwrite_func_param_candidates:
            func_param_candidates = pd.read_csv(self.func_param_path, keep_default_na=False)
            num_internal_apis = len(func_param_candidates)

            # 3. Filter the APIs by internal
            func_param_candidates = self.keep_internal_packages(func_param_candidates)
            possible_func_param = func_param_candidates.apply(lambda row: self.func_parameter_is_candidate(row), axis=1)
            func_param_candidates = func_param_candidates[possible_func_param]

            # 4. Keep only the relevant fields for candidates
            func_param_candidates = func_param_candidates[["package", "clazz", "func", "full_signature", "doc"]]
            num_candidates = len(func_param_candidates)

            # 5. Dump the func param candidates
            self.project_logger.info(f"  ==> #Relevant APIs: {num_internal_apis}, #Filtered Candidates: {num_candidates}")
            self.project_logger.info("  ==> Dumping filtered function parameter candidates...")
            func_param_candidates.to_csv(self.source_func_param_candidates_path, index=False, header=True, sep=",", encoding="utf-8")
        else:
            self.project_logger.info("  ==> Existing source function parameter candidates file found. Skipping filtering candidates...")

        stage2_cache_key = self._store_static_stage_cache(
            "stage2_func_params",
            "fetch_func_params",
            stage2_cache_artifacts,
        )

        if stage2_cache_key is not None:
            self.project_logger.info(
                "  ==> Stage 2 static cache: STORED "
                f"{stage2_cache_key}"
            )

    def load_cached_llm_labeled_apis(self):
        if os.path.exists(self.api_labels_cache_path):
            return json.load(open(self.api_labels_cache_path))
        else:
            return []

    def filter_to_query_apis_with_cache(self, candidates):
        """
        :param candidates, a list of the following [(<package>, <class>, <method>, <signature>), ...]
        """
        llm_results = self.load_cached_llm_labeled_apis()
        cached_apis = set([(item["package"], item["class"], item["method"], item["signature"]) for item in llm_results])
        remaining_apis = sorted(list(set(candidates).difference(cached_apis)))
        return remaining_apis

    def merge_llm_labeled_apis_and_cache(self, candidates, new_llm_result):
        cached_result = self.load_cached_llm_labeled_apis()
        cached_mapping = {",".join([item["package"], item["class"], item["method"], item["signature"]]): item for item in cached_result}
        new_llm_mapping = {",".join([item["package"], item["class"], item["method"], item["signature"]]): item for item in new_llm_result}

        result = []
        for item in candidates:
            item_key = ",".join(item)
            if item_key in new_llm_mapping:
                result.append(new_llm_mapping[item_key])
            elif item_key in cached_mapping:
                if cached_mapping[item_key].get("type", "") != "none":
                    copy_of_cached_item = {k: v for (k, v) in cached_mapping[item_key].items()}
                    result.append(copy_of_cached_item)
        return result

    def cache_llm_results(self, candidates, new_llm_result):
        if os.path.exists(self.api_labels_cache_path):
            try:
                cache = json.load(open(self.api_labels_cache_path))
            except json.JSONDecodeError as e:
                self.project_logger.error(f"Error when loading cache: {self.api_labels_cache_path}\n{e}"); exit(1)
        else:
            cache = []
        cached_apis = {(item["package"], item["class"], item["method"], item["signature"]): item for item in cache}
        llm_returned_apis = {(item["package"], item["class"], item["method"], item["signature"]): item for item in new_llm_result}
        for item in candidates:
            if item in cached_apis:
                if item in llm_returned_apis:
                    cached_apis[item]["type"] = llm_returned_apis[item].get("type", "none")
                else:
                    cached_apis[item]["type"] = "none"
            else:
                if item in llm_returned_apis:
                    to_cache_obj = {k: v for (k, v) in llm_returned_apis[item].items()}
                else:
                    to_cache_obj = {"package": item[0], "class": item[1], "method": item[2], "signature": item[3], "type": "none"}
                cached_apis[item] = to_cache_obj
        reload_cache = [cached_apis[item] for item in sorted(cached_apis.keys())]
        json.dump(reload_cache, open(self.api_labels_cache_path, "w"), indent=2)

    def extract_parameter_names_from_signature(self, signature):
        """Extract Java parameter names while respecting nested generics."""
        if not isinstance(signature, str):
            return []

        left = signature.find("(")
        right = signature.rfind(")")

        if left < 0 or right <= left:
            return []

        params_text = signature[left + 1:right].strip()

        if not params_text:
            return []

        parts = []
        current = []

        angle_depth = 0
        paren_depth = 0
        bracket_depth = 0

        for ch in params_text:
            if ch == "<":
                angle_depth += 1
            elif ch == ">" and angle_depth > 0:
                angle_depth -= 1
            elif ch == "(":
                paren_depth += 1
            elif ch == ")" and paren_depth > 0:
                paren_depth -= 1
            elif ch == "[":
                bracket_depth += 1
            elif ch == "]" and bracket_depth > 0:
                bracket_depth -= 1

            if (
                ch == ","
                and angle_depth == 0
                and paren_depth == 0
                and bracket_depth == 0
            ):
                part = "".join(current).strip()
                if part:
                    parts.append(part)
                current = []
            else:
                current.append(ch)

        part = "".join(current).strip()
        if part:
            parts.append(part)

        names = []

        for part in parts:
            match = re.search(
                r"([A-Za-z_$][A-Za-z0-9_$]*)"
                r"\s*(?:\[\s*\])?\s*$",
                part,
            )

            if match:
                names.append(match.group(1))

        return names

    def parse_json(self, json_str):
        try:
            #print("try 1", json_str)
            import re

            # Remove markdown code block markers if present
            json_str = re.sub(r'```json\s*', '', json_str)
            json_str = re.sub(r'```\s*$', '', json_str)

            # Handle escaped single quotes which are invalid in JSON
            json_str = json_str.replace("\\'", "'")

            # Original cleanup
            json_str = json_str.replace("\\n", "").replace("\\\n", "")
            json_str = re.sub("//.*", "", json_str)
            json_str = re.sub("\"\"", "\"", json_str)


            # First parse strict JSON. Some local models return one
            # object even when the prompt asks for a JSON list.
            try:
                parsed = json.loads(json_str)

                if isinstance(parsed, list):
                    return parsed

                if isinstance(parsed, dict):
                    return [parsed]

            except json.JSONDecodeError:
                pass

            # Fallback: extract JSON array from surrounding text
            json_match = re.findall(r"\[[\s\S]*\]", json_str)
            if not json_match:
                self.project_logger.error("Error parsing JSON: No JSON array found in response")
                return []

            json_str = json_match[0]
            #json_str = re.sub(r"\\n", "", json_str)
            result = json.loads(json_str)
            if type(result) == list:
                return result
            else:
                return []
        except Exception as e:
            print(e)
            try:
                self.project_logger.error("Error parsing JSON 1. Trying list parsing")
                results = re.findall(r"{[^}]*}", json_str)
                results = [json.loads(r.strip()) for r in results]
                return results
            except Exception as e:
                print(e)
                self.project_logger.error("Error parsing JSON 2")
                self.project_logger.error(f"Problematic JSON string: {repr(json_str[:500])}")
        return []

    # RESUME_VALIDATION_V1
    #
    # Same-run resume validators.  Existing files are reusable only
    # when the complete stage bundle is structurally valid.
    def _resume_load_json(self, path):
        if not os.path.isfile(path):
            return None

        try:
            with open(
                path,
                "r",
                encoding="utf-8",
            ) as f:
                return json.load(f)
        except (
            OSError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ):
            return None

    def _resume_valid_json_list(self, path):
        return isinstance(
            self._resume_load_json(path),
            list,
        )

    def _resume_valid_sarif(self, path):
        data = self._resume_load_json(path)

        if not isinstance(data, dict):
            return False

        runs = data.get("runs")

        if (
            not isinstance(runs, list)
            or len(runs) == 0
            or not isinstance(runs[0], dict)
        ):
            return False

        return isinstance(
            runs[0].get("results", []),
            list,
        )

    def _resume_valid_stage3_bundle(self):
        return all(
            self._resume_valid_json_list(path)
            for path in (
                self.llm_labelled_source_apis_path,
                self.llm_labelled_sink_apis_path,
                self.llm_labelled_taint_prop_apis_path,
            )
        )

    def _resume_valid_stage4_bundle(self):
        return self._resume_valid_json_list(
            self.llm_labelled_source_func_params_path
        )

    def _resume_valid_stage6_bundle(self):
        if not self._resume_valid_sarif(
            self.query_output_result_sarif_path
        ):
            return False

        if not os.path.isfile(
            self.query_output_result_csv_path
        ):
            return False

        # RESUME_STAGE6_CSV_VALIDATION_V1
        #
        # Validate SARIF and CSV as one structural bundle.
        # CodeQL CSV output has one logical row per SARIF result
        # for these path-problem queries. Zero findings legitimately
        # produce an empty CSV.
        sarif = self._resume_load_json(
            self.query_output_result_sarif_path
        )

        results = (
            sarif.get("runs", [{}])[0]
            .get("results", [])
        )

        try:
            import csv

            with open(
                self.query_output_result_csv_path,
                "r",
                encoding="utf-8",
                newline="",
            ) as f:
                rows = list(csv.reader(f))

        except (
            OSError,
            UnicodeDecodeError,
            csv.Error,
        ):
            return False

        if len(rows) != len(results):
            return False

        if len(rows) == 0:
            return len(results) == 0

        widths = {
            len(row)
            for row in rows
        }

        if len(widths) != 1:
            return False

        if next(iter(widths)) <= 1:
            return False

        return True

    def query_gpt_for_api_src_tp_sink_batched(self):
        self.project_logger.info("==> Stage 3: Querying LLM for source/taint-prop/sink APIs...")

        # Check if there is labelled sink/source/taint-propagator
        if (
            not self._resume_valid_stage3_bundle()
            or self.overwrite
            or self.overwrite_labelled_apis
        ):
            # 1. Load the candidates
            candidates_csv = pd.read_csv(self.candidate_apis_csv_path, keep_default_na=False)
            candidates = [(row["package"], row["clazz"], row["func"], row["full_signature"]) for (_, row) in candidates_csv.iterrows()]

            # 6. If the candidates are too many, exit
            if self.skip_huge_project and len(candidates) > self.skip_huge_project_num_apis_threshold:
                self.project_logger.info("  ==> Skipping project due to it being too large...")
                exit(0)

            # 2. Load the cache (if needed), and eliminate candidates for querying
            if self.overwrite_llm_cache:
                to_query_candidates = candidates
            else:
                to_query_candidates = self.filter_to_query_apis_with_cache(candidates)

            num_not_queried_candidates = (
                len(candidates) - len(to_query_candidates)
            )

            self.project_logger.info(
                f"  ==> Querying LLM... "
                f"#Candidates: {len(candidates)}, "
                f"#To Query APIs: {len(to_query_candidates)}, "
                f"#Not Queried This Run: {num_not_queried_candidates}"
            )

            # 3. Setup LLMs and relevant queries
            #model = LLM.get_llm(model_name=self.llm, logger=self.project_logger, kwargs={"seed": self.seed, "max_new_tokens": 1024})
            system_prompt = API_LABELLING_SYSTEM_PROMPT

            if self.llm.lower().startswith("ollama"):
                system_prompt = """You are a security expert.
You will receive exactly ONE API and must classify it for the requested CWE.

Return exactly ONE JSON object with this format:
{
  "package": "<package name>",
  "class": "<class name>",
  "method": "<method name>",
  "signature": "<signature>",
  "sink_args": [],
  "type": "<source, sink, taint-propagator, or none>"
}

Use:
- source only when the API can introduce attacker-controlled data.
- sink only when the API can directly consume tainted data in a way relevant to the requested CWE.
- taint-propagator only when it propagates tainted data without sanitizing it.
- none when the API does not satisfy any of the above for the requested CWE.

For a sink, sink_args must contain only the argument names/positions that consume tainted data.
For every other type, sink_args must be an empty list.

Do not classify an API merely because it is security-sensitive in some unrelated context.
Do not output anything except the JSON object."""

            cwe_description = QUERIES[self.query]["prompts"]["desc"]
            cwe_long_description = QUERIES[self.query]["prompts"]["long_desc"]
            cwe_examples = json.dumps(QUERIES[self.query]["prompts"]["examples"], indent=2)

            # 4. Setup dispatch function.
            # Small local Ollama models are more reliable when classifying
            # exactly one API per request.
            effective_label_api_batch_size = self.label_api_batch_size

            if self.llm.lower().startswith("ollama"):
                effective_label_api_batch_size = 1
                self.project_logger.info(
                    "  ==> Ollama Stage 3 batch size forced to 1 "
                    "for reliable structured classification"
                )

            def process_candidate_batch(i):
                # 4.1. Get the batch of to query candidates
                batch = to_query_candidates[
                    i:i + effective_label_api_batch_size
                ]
                api_list_text = "\n".join([",".join(row) for row in batch])

                # 4.2. Build the user prompt and dump it
                user_prompt = API_LABELLING_USER_PROMPT.format(
                    cwe_description=cwe_description,
                    cwe_id=self.cwe_id,
                    cwe_long_description=cwe_long_description,
                    cwe_examples=cwe_examples,
                    methods=api_list_text)
                with open(f"{self.label_api_log_path}/raw_user_prompt_{i}.txt", "w") as f:
                    f.write(user_prompt + "\n")

                return [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ]

                # 4.4. Parse the GPT result
                #json_result = self.parse_json(result)
                #return json_result

            # 5. Iterate through all batches and generate result
            args = range(
                0,
                len(to_query_candidates),
                effective_label_api_batch_size,
            )

            indiv_results = []

            stage3_exact_cache_hits = 0
            stage3_exact_cache_misses = 0

            for i in tqdm(args, desc="Querying LLM"):
                prompt = process_candidate_batch(i)

                (
                    response,
                    exact_cache_hit,
                    _exact_cache_key,
                ) = self._stage3_predict_with_exact_cache(
                    prompt
                )

                if exact_cache_hit:
                    stage3_exact_cache_hits += 1
                else:
                    stage3_exact_cache_misses += 1

                json_result = self.parse_json(response)

                if self.llm.lower().startswith("ollama"):
                    batch = to_query_candidates[
                        i:i + effective_label_api_batch_size
                    ]

                    if len(batch) != 1:
                        raise RuntimeError(
                            "Ollama Stage 3 expects exactly one API per request"
                        )

                    allowed_types = {
                        "source",
                        "sink",
                        "taint-propagator",
                        "none",
                    }

                    item = next(
                        (
                            x for x in json_result
                            if isinstance(x, dict)
                            and x.get("type") in allowed_types
                        ),
                        None,
                    )

                    if item is None:
                        json_result = []
                    else:
                        item = dict(item)

                        # Preserve the model's echoed signature temporarily.
                        # It may rename p0 -> sql, p1 -> query, etc.
                        model_signature = item.get("signature", "")
                        model_sink_args = item.get("sink_args", [])

                        if not isinstance(model_sink_args, list):
                            model_sink_args = []

                        (
                            item["package"],
                            item["class"],
                            item["method"],
                            item["signature"],
                        ) = batch[0]

                        # CodeQL sink generation expects canonical argument
                        # identifiers from the candidate signature (p0, p1, ...)
                        # or "this". Map model-renamed arguments back by
                        # parameter position.
                        if item.get("type") == "sink":
                            candidate_params = (
                                self.extract_parameter_names_from_signature(
                                    batch[0][3]
                                )
                            )

                            model_params = (
                                self.extract_parameter_names_from_signature(
                                    model_signature
                                )
                            )

                            normalized_sink_args = []

                            for raw_arg in model_sink_args:
                                sink_arg = str(raw_arg)
                                mapped_arg = None

                                if sink_arg == "this":
                                    mapped_arg = "this"

                                elif sink_arg in candidate_params:
                                    mapped_arg = sink_arg

                                elif sink_arg in model_params:
                                    arg_index = model_params.index(sink_arg)

                                    if arg_index < len(candidate_params):
                                        mapped_arg = candidate_params[arg_index]

                                else:
                                    match = re.fullmatch(
                                        r"p([0-9]+)",
                                        sink_arg,
                                    )

                                    if match:
                                        arg_index = int(match.group(1))

                                        if arg_index < len(candidate_params):
                                            mapped_arg = candidate_params[arg_index]

                                    elif (
                                        len(candidate_params) == 1
                                        and len(model_sink_args) == 1
                                    ):
                                        # The model identified the only
                                        # argument as the sink but renamed it.
                                        mapped_arg = candidate_params[0]

                                if (
                                    mapped_arg is not None
                                    and mapped_arg not in normalized_sink_args
                                ):
                                    normalized_sink_args.append(mapped_arg)

                            item["sink_args"] = normalized_sink_args

                        else:
                            item["sink_args"] = []

                        json_result = [item]

                with open(
                    f"{self.label_api_log_path}/raw_llm_response_{i}.txt",
                    "w"
                ) as f:
                    f.write(str(response) + "\n")

                indiv_results.append(json_result)

            self.project_logger.info(
                "  ==> Stage 3 exact-request cache: "
                f"#Hits: {stage3_exact_cache_hits}, "
                f"#Misses: {stage3_exact_cache_misses}"
            )

            # 6. Merge all the results
            merged_llm_results = []
            for indiv_result in indiv_results:
                merged_llm_results.extend(indiv_result)
            merged_llm_results=self.filter_invalid_entries(merged_llm_results)
            # 7. Save the result for this project
            merged_overall_results = self.merge_llm_labeled_apis_and_cache(candidates, merged_llm_results)
            sources = [r for r in merged_overall_results if r.get("type", "") == "source"]
            taint_props = [r for r in merged_overall_results if r.get("type", "") == "taint-propagator"]
            sinks = [r for r in merged_overall_results if r.get("type", "") == "sink"]
            self.project_logger.info(f"  ==> #APIs Labelled by LLM: {len(merged_overall_results)}, #Source: {len(sources)}, #Sink: {len(sinks)}, #Taint Propagators: {len(taint_props)}")
            if not self.test_run:
                json.dump(sources, open(self.llm_labelled_source_apis_path, "w"), indent=2)
                json.dump(taint_props, open(self.llm_labelled_taint_prop_apis_path, "w"), indent=2)
                json.dump(sinks, open(self.llm_labelled_sink_apis_path, "w"), indent=2)

            # 8. Save the results for common cache
            if not self.test_run:
                self.cache_llm_results(
                    to_query_candidates,
                    merged_llm_results,
                )
        else:
            self.project_logger.info("  ==> Existing labelled source/taint-prop/sink APIs found. Skipping querying GPT...")

    def first_project_description_paragraph(self, readme_lines):
        paragraph_lines = []
        paragraph_started = False

        for line in readme_lines:
            stripped = line.strip()

            if not paragraph_started:
                # Skip headings, badges, images, markup, and blank lines
                # until the first normal prose paragraph begins.
                if not stripped or not stripped[0].isalpha():
                    continue

                paragraph_started = True
                paragraph_lines.append(stripped)
                continue

            # Once the first prose paragraph has started, stop at its
            # first boundary instead of collecting unrelated README text.
            if not stripped or not stripped[0].isalpha():
                break

            paragraph_lines.append(stripped)

        return "\n".join(paragraph_lines)

    def resolve_project_repo_identity(self):
        """Resolve a stable owner/repository identity for Stage 4 prompts."""

        # Prefer IRIS CVE metadata when it is available.
        if self.project_cve_with_commit_info is not None:
            github_username = self.project_cve_with_commit_info.get(
                "github_username"
            )
            github_repo = self.project_cve_with_commit_info.get(
                "github_repository_name"
            )

            if (
                pd.notna(github_username)
                and pd.notna(github_repo)
                and str(github_username).strip()
                and str(github_repo).strip()
            ):
                return (
                    str(github_username).strip(),
                    str(github_repo).strip(),
                )

        # For locally supplied projects that are absent from the IRIS
        # CVE/commit dataset, derive the identity from the Git origin.
        try:
            import subprocess

            result = subprocess.run(
                [
                    "git",
                    "-C",
                    self.project_source_code_dir,
                    "config",
                    "--get",
                    "remote.origin.url",
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            origin_url = result.stdout.strip()
            remote_path = None

            if "github.com/" in origin_url:
                remote_path = origin_url.split(
                    "github.com/",
                    1,
                )[1]

            elif "github.com:" in origin_url:
                remote_path = origin_url.split(
                    "github.com:",
                    1,
                )[1]

            if remote_path:
                remote_path = remote_path.rstrip("/")

                if remote_path.endswith(".git"):
                    remote_path = remote_path[:-4]

                parts = remote_path.split("/")

                if (
                    len(parts) >= 2
                    and parts[0].strip()
                    and parts[1].strip()
                ):
                    return (
                        parts[0].strip(),
                        parts[1].strip(),
                    )

        except Exception as e:
            if hasattr(self, "project_logger"):
                self.project_logger.info(
                    "  ==> Could not resolve project identity "
                    f"from Git origin: {e}"
                )

        # Last-resort fallback: do not pretend that a CVE token is the
        # repository name.
        fallback_owner = self.project_name.split("_")[0]

        return (
            fallback_owner,
            self.project_name,
        )

    def fetch_project_description_from_commit_readme(self, commit_link):
        # Try for each possible readme file
        for possible_readme_file_name in ["README.md", "README.adoc", "README", "readme.md", "readme"]:
            link = commit_link + "/" + possible_readme_file_name
            self.project_logger.info(f"  ==> Attempting to fetch project readme from {link}...")
            try:
                response = requests.get(link)
                if response.status_code == 200:
                    self.project_logger.info(f"  ==> Success!")
                    lines = response.text.split('\n')
                    first_markdown_paragraph = self.first_project_description_paragraph(lines)

                    # Success. Dump the readme and the head
                    with open(f"{self.label_func_params_log_path}/readme.txt", "w") as f:
                        f.write("\n".join(lines))
                    with open(f"{self.label_func_params_log_path}/readme_head.txt", "w") as f:
                        f.write(first_markdown_paragraph)

                    return first_markdown_paragraph
                else:
                    self.project_logger.info(f"  ==> Fail")
            except Exception as e:
                self.project_logger.info(f"  ==> Fail with error: {e}")

    def fetch_project_description_from_readme(self):
        readme_head_txt_path = (
            f"{self.label_func_params_log_path}/readme_head.txt"
        )

        # The analyzed source tree is authoritative for Stage 4 context.
        # This keeps vulnerable/fixed project states isolated and avoids
        # accidentally using README content from a CVE fixing commit.
        local_readme_names = [
            "README.md",
            "README.adoc",
            "README",
            "readme.md",
            "readme",
        ]

        for readme_name in local_readme_names:
            readme_path = os.path.join(
                self.project_source_code_dir,
                readme_name,
            )

            if not os.path.isfile(readme_path):
                continue

            self.project_logger.info(
                f"  ==> Using local project readme: {readme_path}"
            )

            try:
                with open(readme_path, "rb") as f:
                    raw_readme = f.read()

                readme_text = raw_readme.decode(
                    "utf-8",
                    errors="replace",
                )
                lines = readme_text.splitlines()

                paragraph = self.first_project_description_paragraph(
                    lines
                )

                if paragraph:
                    os.makedirs(
                        self.label_func_params_log_path,
                        exist_ok=True,
                    )

                    with open(
                        f"{self.label_func_params_log_path}/readme.txt",
                        "wb",
                    ) as f:
                        f.write(raw_readme)

                    with open(
                        readme_head_txt_path,
                        "w",
                        encoding="utf-8",
                    ) as f:
                        f.write(paragraph)

                    return paragraph

            except Exception as e:
                self.project_logger.info(
                    f"  ==> Failed to read local project readme: {e}"
                )

        # If the analyzed source tree has no usable README, reuse an
        # already-fetched fallback for this run when available.
        if os.path.exists(readme_head_txt_path) and not self.overwrite:
            self.project_logger.info(
                "  ==> Found fetched readme fallback. "
                "Skipping remote fetch..."
            )
            return "".join(
                list(open(readme_head_txt_path, encoding="utf-8"))
            )

        # Preserve the original IRIS remote fallback only when the local
        # source tree does not provide a usable README.
        if (
            len(self.cve_fixing_commits) > 0
            and self.project_cve_with_commit_info is not None
        ):
            github_username = (
                self.project_cve_with_commit_info["github_username"]
            )
            github_repo = (
                self.project_cve_with_commit_info[
                    "github_repository_name"
                ]
            )

            repo_base = (
                f"https://raw.githubusercontent.com/"
                f"{github_username}/{github_repo}"
            )

            for commit_hash in self.cve_fixing_commits:
                base_link = f"{repo_base}/{commit_hash}"

                paragraph = (
                    self.fetch_project_description_from_commit_readme(
                        base_link
                    )
                )

                if paragraph is not None:
                    return paragraph

            base_link = f"{repo_base}/master"

            paragraph = (
                self.fetch_project_description_from_commit_readme(
                    base_link
                )
            )

            if paragraph is not None:
                return paragraph

        self.project_logger.error(
            "  ==> Cannot obtain project readme description."
        )
        return None

    def extract_doc(self, doc_str):
        if doc_str is None:
            return ""
        elif len(doc_str) <= MAX_DOC_LENGTH:
            return doc_str
        else:
            return doc_str[:MAX_DOC_LENGTH] + "..."

    def fetch_func_param_src_candidates(self):
        candidates_csv = pd.read_csv(self.source_func_param_candidates_path, keep_default_na=False)

        # Do deduplication
        dedup_map = {}
        for (_, row) in candidates_csv.iterrows():
            key = (row["package"], row["clazz"], row["func"])
            if key not in dedup_map:
                dedup_map[key] = row
            else:
                if row["doc"] != "":
                    dedup_map[key] = row
                elif len(row["full_signature"]) > len(dedup_map[key]["full_signature"]):
                    dedup_map[key] = row

        # Add doc into the candidates
        candidates = [(key[0], key[1], key[2], row["full_signature"], self.extract_doc(row["doc"])) for (key, row) in dedup_map.items()]

        # Count the number of functions with documentations
        num_with_docs = len([() for cand in candidates if cand[4] != ""])
        self.project_logger.info(f"  ==> #Candidate functions with source param: {len(candidates_csv)}; after deduplication: {len(candidates)}; with documentations: {num_with_docs}. Querying LLM...")

        # Return
        return candidates

    def query_gpt_for_func_param_src(self):
        self.project_logger.info("==> Stage 4: Querying LLM for source function parameters...")
        if (
            not self._resume_valid_stage4_bundle()
            or self.overwrite
            or self.overwrite_labelled_func_param
        ):
            # 1. Get LLM and fetch information used for prompt
            system_prompt = FUNC_PARAM_LABELLING_SYSTEM_PROMPT

            if self.llm.lower().startswith("ollama"):
                system_prompt = """You are a security expert.
You will receive exactly ONE Java method or constructor.

Identify which parameters of that exact candidate can carry malicious,
attacker-controlled end-user input.

Return exactly ONE short JSON object:
{
  "package": "<package name>",
  "class": "<class name>",
  "method": "<method name>",
  "signature": "<signature>",
  "tainted_input": []
}

Rules:
- Analyze only the single candidate provided.
- Do not invent or substitute another method, constructor, or signature.
- tainted_input must contain only exact parameter names present in the
  candidate signature.
- If no parameter is attacker-controlled, return an empty tainted_input list.
- Do not output anything except the JSON object."""

            proj_description = self.fetch_project_description_from_readme()
            proj_username, proj_name = (
                self.resolve_project_repo_identity()
            )

            # 2. Get LLM
            #model = LLM.get_llm(model_name=self.llm, logger=self.project_logger, kwargs={"seed": self.seed, "max_new_tokens": 1024})

            # 3. Load the candidates
            candidates = self.fetch_func_param_src_candidates()

            # 4. Setup dispatch function.
            # Local Ollama models return one object reliably, so classify
            # exactly one project method per request.
            effective_label_func_param_batch_size = (
                self.label_func_param_batch_size
            )

            if self.llm.lower().startswith("ollama"):
                effective_label_func_param_batch_size = 1
                self.project_logger.info(
                    "  ==> Ollama Stage 4 batch size forced to 1 "
                    "for reliable structured classification"
                )

            def process_candidate_batch(i):
                # 4.1. Get the batch of to query candidates
                batch = candidates[
                    i:i + effective_label_func_param_batch_size
                ]
                api_list_text = "\n".join(
                    [
                        ",".join(
                            [
                                row[0],
                                row[1],
                                row[2],
                                row[3],
                                row[4],
                            ]
                        )
                        for row in batch
                    ]
                )

                # 4.2. Build the user prompt and dump it
                user_prompt = FUNC_PARAM_LABELLING_USER_PROMPT.format(
                    project_username=proj_username,
                    project_name=proj_name,
                    project_readme_summary=proj_description,
                    methods=api_list_text)
                with open(f"{self.label_func_params_log_path}/raw_user_prompt_{i}.txt", "w") as f:
                    f.write(user_prompt + "\n")


                return [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ]

            # 5. Actually dispatch the tasks
            # args = range(0, len(candidates), self.label_func_param_batch_size)
            # indiv_results = thread_map(process_candidate_batch, args, max_workers=self.num_threads)

            args = range(
                0,
                len(candidates),
                effective_label_func_param_batch_size,
            )

            model = self.get_model()

            stage4_exact_cache_hits = 0
            stage4_exact_cache_misses = 0
            stage4_retry_cache_hits = 0
            stage4_retry_cache_misses = 0

            def stage4_ollama_contract_error(
                response_text,
                candidate,
                require_identity=True,
            ):
                try:
                    parsed = json.loads(response_text)
                except (TypeError, json.JSONDecodeError) as e:
                    return f"malformed JSON: {e}"

                if isinstance(parsed, dict):
                    item = parsed

                elif (
                    isinstance(parsed, list)
                    and len(parsed) == 1
                    and isinstance(parsed[0], dict)
                ):
                    item = parsed[0]

                else:
                    return (
                        "expected exactly one JSON object "
                        "for the single candidate"
                    )

                (
                    package,
                    clazz,
                    method,
                    signature,
                    _doc,
                ) = candidate

                if require_identity:
                    if item.get("package") != package:
                        return (
                            "package mismatch: "
                            f"{item.get('package')!r} != {package!r}"
                        )

                    if item.get("class") != clazz:
                        return (
                            "class mismatch: "
                            f"{item.get('class')!r} != {clazz!r}"
                        )

                    if item.get("method") != method:
                        return (
                            "method mismatch: "
                            f"{item.get('method')!r} != {method!r}"
                        )

                tainted_input = item.get("tainted_input")

                if not isinstance(tainted_input, list):
                    return "tainted_input is not a list"

                candidate_params = (
                    self.extract_parameter_names_from_signature(
                        signature
                    )
                )

                invalid_args = [
                    arg_name
                    for arg_name in tainted_input
                    if (
                        not isinstance(arg_name, str)
                        or arg_name not in candidate_params
                    )
                ]

                if invalid_args:
                    return (
                        "tainted_input contains parameters not "
                        f"in candidate signature: {invalid_args!r}"
                    )

                return None

            indiv_results = []

            for i in tqdm(args, desc="Querying LLM"):
                prompt = process_candidate_batch(i)

                if self.llm.lower().startswith("ollama"):
                    (
                        response,
                        exact_cache_hit,
                        _exact_cache_key,
                    ) = self._stage4_predict_with_exact_cache(
                        prompt,
                        "initial",
                    )

                    if exact_cache_hit:
                        stage4_exact_cache_hits += 1
                    else:
                        stage4_exact_cache_misses += 1

                    batch = candidates[
                        i:i + effective_label_func_param_batch_size
                    ]

                    if len(batch) != 1:
                        raise RuntimeError(
                            "Ollama Stage 4 expects exactly "
                            "one function"
                        )

                    contract_error = (
                        stage4_ollama_contract_error(
                            response,
                            batch[0],
                        )
                    )

                    if contract_error is not None:
                        self.project_logger.info(
                            "  ==> Retrying Stage 4 candidate "
                            f"{i} due to contract error: "
                            f"{contract_error}"
                        )

                        (
                            package,
                            clazz,
                            method,
                            signature,
                            _doc,
                        ) = batch[0]

                        candidate_params = (
                            self.extract_parameter_names_from_signature(
                                signature
                            )
                        )

                        with open(
                            f"{self.label_func_params_log_path}/"
                            f"retry_initial_response_{i}.txt",
                            "w",
                        ) as f:
                            f.write(response + "\n")

                        retry_system_prompt = """The previous response
violated the required output contract.

Analyze exactly the ONE Java method or constructor provided.

A parameter should be tainted only when it can carry malicious,
attacker-controlled end-user input, including direct HTTP request input or
untrusted input supplied through a public library entry point.

Return exactly ONE short JSON object in this form:
{"tainted_input": []}

tainted_input may contain only exact names from allowed_parameter_names,
or [] if none apply.
Do not invent parameter names.
Do not output any other keys or any text outside the JSON object."""

                        retry_user_prompt = json.dumps(
                            {
                                "package": package,
                                "class": clazz,
                                "method": method,
                                "signature": signature,
                                "allowed_parameter_names": candidate_params,
                            },
                            ensure_ascii=False,
                        )

                        with open(
                            f"{self.label_func_params_log_path}/"
                            f"retry_user_prompt_{i}.txt",
                            "w",
                        ) as f:
                            f.write(retry_user_prompt + "\n")

                        retry_prompt = [
                            {
                                "role": "system",
                                "content": retry_system_prompt,
                            },
                            {
                                "role": "user",
                                "content": retry_user_prompt,
                            },
                        ]

                        (
                            response,
                            retry_cache_hit,
                            _retry_cache_key,
                        ) = self._stage4_predict_with_exact_cache(
                            retry_prompt,
                            "retry",
                        )

                        if retry_cache_hit:
                            stage4_exact_cache_hits += 1
                            stage4_retry_cache_hits += 1
                        else:
                            stage4_exact_cache_misses += 1
                            stage4_retry_cache_misses += 1

                        with open(
                            f"{self.label_func_params_log_path}/"
                            f"retry_response_{i}.txt",
                            "w",
                        ) as f:
                            f.write(response + "\n")

                        retry_contract_error = (
                            stage4_ollama_contract_error(
                                response,
                                batch[0],
                                require_identity=False,
                            )
                        )

                        if retry_contract_error is not None:
                            raise RuntimeError(
                                "Ollama Stage 4 response still violates "
                                "the candidate contract after retry for "
                                f"index {i}: "
                                f"{package}.{clazz}.{method}; "
                                f"{retry_contract_error}"
                            )

                else:
                    response = model.predict(prompt)

                json_result = self.parse_json(response)

                if self.llm.lower().startswith("ollama"):
                    batch = candidates[
                        i:i + effective_label_func_param_batch_size
                    ]

                    if len(batch) != 1:
                        raise RuntimeError(
                            "Ollama Stage 4 expects exactly one "
                            "function per request"
                        )

                    item = next(
                        (
                            x for x in json_result
                            if isinstance(x, dict)
                        ),
                        None,
                    )

                    if item is None:
                        json_result = []

                    else:
                        item = dict(item)

                        (
                            package,
                            clazz,
                            method,
                            signature,
                            _doc,
                        ) = batch[0]

                        # Do not trust identity echoed by the model.
                        item["package"] = package
                        item["class"] = clazz
                        item["method"] = method
                        item["signature"] = signature

                        candidate_params = (
                            self.extract_parameter_names_from_signature(
                                signature
                            )
                        )

                        tainted_input = item.get(
                            "tainted_input",
                            [],
                        )

                        if not isinstance(tainted_input, list):
                            tainted_input = []

                        normalized_tainted_input = []

                        for arg_name in tainted_input:
                            if (
                                isinstance(arg_name, str)
                                and arg_name in candidate_params
                                and arg_name
                                not in normalized_tainted_input
                            ):
                                normalized_tainted_input.append(
                                    arg_name
                                )

                        item["tainted_input"] = (
                            normalized_tainted_input
                        )

                        # Stage 4 artifact contains only functions that
                        # actually have at least one labelled source param.
                        if normalized_tainted_input:
                            json_result = [item]
                        else:
                            json_result = []

                with open(
                    f"{self.label_func_params_log_path}/raw_llm_response_{i}.txt",
                    "w"
                ) as f:
                    f.write(response + "\n")

                indiv_results.append(json_result)

            self.project_logger.info(
                "  ==> Stage 4 exact-request cache: "
                f"#Hits: {stage4_exact_cache_hits}, "
                f"#Misses: {stage4_exact_cache_misses}, "
                f"#RetryHits: {stage4_retry_cache_hits}, "
                f"#RetryMisses: {stage4_retry_cache_misses}"
            )

            # 6. Merge all the results
            merged_llm_results = []
            for indiv_result in indiv_results:
                merged_llm_results.extend(indiv_result)

            # 7. Save the result for this project
            self.project_logger.info(f"  ==> Finished querying LLM. #Function with source param: {len(merged_llm_results)}")
            if not self.test_run:
                json.dump(merged_llm_results, open(self.llm_labelled_source_func_params_path, "w"), indent=2)
        else:
            self.project_logger.info(f"  ==> Found labelled source function parameters. Skipping...")

    def not_none(self, d, keys):
        return isinstance(d, dict) and all([d.get(k, None) for k in keys])

    def filter_cwe_relevant_sink_entries(self, sink_apis):
        """
        Deterministic CWE-specific sink semantic normalization.

        Raw Stage-3 LLM labels remain unchanged on disk.

        CWE-89:
        - JDBC/JPA known SQL-text APIs only.
        - Explicitly SQL-oriented third-party framework packages only.
        - Normalize SQL-text input to p0.

        CWE-78:
        - Runtime.exec(...) command argument is p0.
        - ProcessBuilder constructor / command(...) command input is p0.
        - Reject unrelated SQL, LDAP, file, servlet, crypto, etc. APIs.

        Other CWE queries preserve historical behavior.
        """

        if self.query not in {
            "cwe-089wLLM",
            "cwe-078wLLM",
        }:
            return sink_apis

        kept = []
        rejected = []
        normalized = 0

        # ====================================================
        # CWE-89 policy
        # ====================================================

        standard_sql_methods = {
            "execute",
            "executequery",
            "executeupdate",
            "executelargeupdate",
            "addbatch",
            "preparestatement",
            "preparecall",
        }

        jpa_sql_methods = {
            "createquery",
            "createnativequery",
        }

        third_party_sql_methods = {
            "execute",
            "executequery",
            "executeupdate",
            "executelargeupdate",
            "addbatch",
            "preparestatement",
            "preparecall",
            "query",
            "update",
            "batchupdate",
            "queryforobject",
            "queryforlist",
            "queryformap",
            "queryforrowset",
            "createquery",
            "createnativequery",
            "createsqlquery",
            "fetch",
            "fetchone",
            "resultquery",
        }

        third_party_sql_prefixes = (
            "org.springframework.jdbc.",
            "org.hibernate.",
            "org.jooq.",
            "org.jdbi.",
        )

        # ====================================================
        # Process each LLM-labelled sink
        # ====================================================

        for original in sink_apis:
            if not isinstance(original, dict):
                rejected.append(original)
                continue

            api = dict(original)

            package = str(
                api.get("package", "")
            ).strip()

            clazz = str(
                api.get("class", "")
            ).strip()

            method = str(
                api.get("method", "")
            ).strip()

            signature = str(
                api.get("signature", "")
            ).strip()

            package_lower = package.lower()
            clazz_lower = clazz.lower()
            method_lower = method.lower()

            keep = False

            # =================================================
            # CWE-89
            # =================================================

            if self.query == "cwe-089wLLM":

                if package_lower == "java.sql":
                    keep = (
                        method_lower in standard_sql_methods
                        and "p0" in signature
                    )

                elif package_lower in {
                    "javax.persistence",
                    "jakarta.persistence",
                }:
                    keep = (
                        method_lower in jpa_sql_methods
                        and "p0" in signature
                    )

                elif package_lower.startswith(
                    third_party_sql_prefixes
                ):
                    keep = (
                        method_lower in third_party_sql_methods
                        and "p0" in signature
                    )

            # =================================================
            # CWE-78
            # =================================================

            elif self.query == "cwe-078wLLM":

                # Runtime.exec(String / String[] ...)
                if (
                    package_lower == "java.lang"
                    and clazz_lower == "runtime"
                    and method_lower == "exec"
                    and "p0" in signature
                ):
                    keep = True

                # new ProcessBuilder(List<String> / String...)
                # and ProcessBuilder.command(...)
                elif (
                    package_lower == "java.lang"
                    and clazz_lower == "processbuilder"
                    and method_lower in {
                        "processbuilder",
                        "command",
                    }
                    and "p0" in signature
                ):
                    keep = True

            if keep:
                old_args = api.get(
                    "sink_args",
                    [],
                )

                if old_args != ["p0"]:
                    normalized += 1

                api["sink_args"] = ["p0"]
                kept.append(api)

            else:
                rejected.append(original)

        try:
            cwe_name = (
                "CWE-89"
                if self.query == "cwe-089wLLM"
                else "CWE-78"
            )

            self.project_logger.info(
                f"  ==> {cwe_name} sink semantic guard: "
                f"kept={len(kept)}, "
                f"rejected={len(rejected)}, "
                f"normalized={normalized}"
            )

        except Exception:
            pass

        return kept

    def filter_invalid_entries(self, api_list):
        return [api for api in api_list if self.not_none(api, ["method", "class", "package", "signature"])]

    def build_source_qll_with_enumeration(self):
        # FACTORED_SOURCE_QLL_V1
        #
        # Preserve the original exhaustive source semantics while
        # factoring the repeated AST joins out of thousands of OR
        # branches. Exact duplicate semantic tuples are idempotent
        # under OR and are therefore deduplicated.

        def ql_string(value):
            value = str(value)

            value = value.replace(
                "\\",
                "\\\\",
            )

            value = value.replace(
                '"',
                '\\"',
            )

            value = value.replace(
                "\r",
                "\\r",
            )

            value = value.replace(
                "\n",
                "\\n",
            )

            return (
                '"'
                + value
                + '"'
            )

        def relation_body(rows, names):
            if len(rows) == 0:
                return "  1 = 0"

            blocks = []

            for row in rows:
                terms = [
                    f"{name} = {ql_string(value)}"
                    for name, value
                    in zip(
                        names,
                        row,
                    )
                ]

                blocks.append(
                    "  (\n    "
                    + " and\n    ".join(
                        terms
                    )
                    + "\n  )"
                )

            return "\n  or\n".join(
                blocks
            )

        source_apis = self.filter_invalid_entries(
            json.load(
                open(
                    self.llm_labelled_source_apis_path
                )
            )
        )

        source_api_rows_raw = [
            (
                api["package"],
                api["class"],
                api["method"],
            )
            for api in source_apis
        ]

        source_params = self.filter_invalid_entries(
            json.load(
                open(
                    self.llm_labelled_source_func_params_path
                )
            )
        )

        source_param_rows_raw = []

        for param_func in source_params:
            tainted_input = param_func.get(
                "tainted_input",
                [],
            )

            if (
                not isinstance(
                    tainted_input,
                    list,
                )
                or len(
                    tainted_input
                ) == 0
            ):
                continue

            for arg_name in tainted_input:
                source_param_rows_raw.append(
                    (
                        param_func["package"],
                        param_func["class"],
                        param_func["method"],
                        arg_name,
                    )
                )

        source_api_rows = sorted(
            set(
                source_api_rows_raw
            ),
            key=lambda row: tuple(
                str(value)
                for value in row
            ),
        )

        source_param_rows = sorted(
            set(
                source_param_rows_raw
            ),
            key=lambda row: tuple(
                str(value)
                for value in row
            ),
        )

        source_api_relation = relation_body(
            source_api_rows,
            (
                "packageName",
                "className",
                "methodName",
            ),
        )

        source_param_relation = relation_body(
            source_param_rows,
            (
                "packageName",
                "className",
                "methodName",
                "parameterName",
            ),
        )

        my_source_content = f"""import java
    import semmle.code.java.dataflow.DataFlow
    private import semmle.code.java.dataflow.ExternalFlow

    predicate sourceApiSpec(
      string packageName,
      string className,
      string methodName
    ) {{
    {source_api_relation}
    }}

    predicate sourceParameterSpec(
      string packageName,
      string className,
      string methodName,
      string parameterName
    ) {{
    {source_param_relation}
    }}

    predicate isGPTDetectedSource(DataFlow::Node src) {{
      exists(
        string packageName,
        string className,
        string methodName
      |
        sourceApiSpec(
          packageName,
          className,
          methodName
        )
        and
        src.asExpr().(Call).getCallee().getName() =
          methodName
        and
        src.asExpr().(Call).getCallee()
          .getDeclaringType()
          .getSourceDeclaration()
          .hasQualifiedName(
            packageName,
            className
          )
      )
      or
      exists(
        Parameter p,
        string packageName,
        string className,
        string methodName,
        string parameterName
      |
        sourceParameterSpec(
          packageName,
          className,
          methodName,
          parameterName
        )
        and
        src.asParameter() = p
        and
        p.getCallable().getName() =
          methodName
        and
        p.getCallable()
          .getDeclaringType()
          .getSourceDeclaration()
          .hasQualifiedName(
            packageName,
            className
          )
        and
        p.getName() = parameterName
      )
    }}
    """

        return my_source_content

    def build_and_save_source_qll_with_enumeration(self):
        os.makedirs(os.path.dirname(self.source_qll_path), exist_ok=True)
        with open(self.source_qll_path, "w") as f:
            f.write(self.build_source_qll_with_enumeration())

    def build_and_save_source_qll_with_source_node(self):
        my_source_content = QL_SOURCE_PREDICATE.format(
            body=f"sourceNode(src, \"{self.project_name}\")")
        os.makedirs(os.path.dirname(self.source_qll_path), exist_ok=True)
        with open(self.source_qll_path, "w") as f:
            f.write(my_source_content)

    def build_taint_propagator_qll_with_enumeration(self):
        summary_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_taint_prop_apis_path)))

        if len(summary_apis) == 0 or self.no_summary_model:
            body = "1 = 0"
        else:
            body = QL_BODY_OR_SEPARATOR.join([
                QL_SUMMARY_BODY_ENTRY.format(
                    package=api["package"],
                    clazz=api["class"],
                    method=api["method"],
                ) for api in summary_apis
            ])
        my_summary_content = QL_STEP_PREDICATE.format(body=body)
        return my_summary_content

    def build_and_save_taint_propagator_qll_with_enumeration(self):
        os.makedirs(os.path.dirname(self.summary_qll_path), exist_ok=True)
        with open(self.summary_qll_path, "w") as f:
            f.write(self.build_taint_propagator_qll_with_enumeration())

    def build_sink_qll_with_enumeration(self):
        sink_apis = self.filter_cwe_relevant_sink_entries(self.filter_invalid_entries(json.load(open(self.llm_labelled_sink_apis_path))))
        if len(sink_apis) == 0:
            body = "1 = 0"
            additional = ""
        else:
            def sink_body_entry(api):
                if "sink_args" in api and \
                    any(
                        len(re.findall(r"[\S\s]*p([0-9]+)", str(sink_arg))) > 0 or str(sink_arg) == "this"
                        for sink_arg in api["sink_args"]
                    ):
                    return QL_SINK_BODY_ENTRY.format(
                        method=api["method"],
                        package=api["package"],
                        clazz=api["class"],
                        args=" or ".join([
                            QL_SINK_ARG_THIS_ENTRY if sink_arg == "this" else
                            QL_SINK_ARG_NAME_ENTRY.format(
                                arg_id=int(re.findall(r"[\S\s]*p([0-9]+)", sink_arg)[0]), # sink_arg will be `pX` where X is a number
                            )
                            for sink_arg in api["sink_args"]
                            if len(re.findall(r"[\S\s]*p([0-9]+)", str(sink_arg))) > 0 or str(sink_arg) == "this"
                        ])
                    )
                else:
                    return "1 = 0"

            def sink_body(apis):
                return QL_BODY_OR_SEPARATOR.join([sink_body_entry(api) for api in sink_apis])

            batch_size = 300
            if len(sink_apis) > batch_size:
                num_batches = int(math.ceil(len(sink_apis) / batch_size))
                body = " or\n".join([
                    CALL_QL_SUBSET_PREDICATE.format(part_id=i, kind="Sink", node="snk")
                    for i in range(num_batches)])
                additional = "\n\n".join([
                    QL_SUBSET_PREDICATE.format(
                        part_id=i,
                        kind="Sink",
                        node="snk",
                        body=sink_body(sink_apis[i * batch_size : (i + 1) * batch_size]))
                    for i in range(num_batches)
                ])
            else:
                body = sink_body(sink_apis)
                additional = ""
        my_sink_content = QL_SINK_PREDICATE.format(body=body, additional=additional)
        return my_sink_content

    def build_and_save_sink_qll_with_enumeration(self):
        os.makedirs(os.path.dirname(self.sink_qll_path), exist_ok=True)
        with open(self.sink_qll_path, "w") as f:
            f.write(self.build_sink_qll_with_enumeration())

    def build_and_save_sink_qll_with_sink_node(self):
        my_sink_content = QL_SINK_PREDICATE.format(
            body=f"sinkNode(snk, \"{self.project_name}\")")
        os.makedirs(os.path.dirname(self.sink_qll_path), exist_ok=True)
        with open(self.sink_qll_path, "w") as f:
            f.write(my_sink_content)

    def build_extension_yml(self):
        # First load labelled sources, sinks, and taint-propagators
        source_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_source_apis_path)))
        source_params = self.filter_invalid_entries(json.load(open(self.llm_labelled_source_func_params_path)))
        sink_apis = self.filter_cwe_relevant_sink_entries(self.filter_invalid_entries(json.load(open(self.llm_labelled_sink_apis_path))))
        taint_prop_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_taint_prop_apis_path)))

        # Convert into entries
        source_api_entries = "\n".join([
            EXTENSION_SRC_SINK_YML_ENTRY.format(
                package=source_api["package"],
                clazz=source_api["class"],
                method=source_api["method"],
                access="ReturnValue",
                tag=self.project_name,
            ) for source_api in source_apis if isinstance(source_api, dict)
        ])
        source_params=[k for k in source_params if isinstance(k, dict)]
        source_func_parm_entries = "\n".join([
            EXTENSION_SRC_SINK_YML_ENTRY.format(
                package=source_func_param["package"],
                clazz=source_func_param["class"],
                method=source_func_param["method"],
                access=f"Parameter[{'this' if param_name == 'this' else param_name[1:]}]",
                tag=self.project_name,
            )
            for source_func_param in source_params
            for param_name in source_func_param.get("tainted_input", [])
        ])
        if self.query in {"cwe-089wLLM", "cwe-078wLLM"}:
            # CWE-89 must model only the explicitly identified
            # SQL-text arguments. Never widen a sink to
            # Argument[0..10].
            sink_api_entries = "\n".join([
                EXTENSION_SRC_SINK_YML_ENTRY.format(
                    package=sink_api["package"],
                    clazz=sink_api["class"],
                    method=sink_api["method"],
                    access=f"Argument[{int(str(sink_arg)[1:])}]",
                    tag=self.project_name,
                )
                for sink_api in sink_apis
                if isinstance(sink_api, dict)
                for sink_arg in sink_api.get("sink_args", [])
                if (
                    isinstance(sink_arg, str)
                    and len(sink_arg) >= 2
                    and sink_arg[0] == "p"
                    and sink_arg[1:].isdigit()
                )
            ])
        else:
            # Preserve historical behavior for other CWE queries.
            sink_api_entries = "\n".join([
                EXTENSION_SRC_SINK_YML_ENTRY.format(
                    package=sink_api["package"],
                    clazz=sink_api["class"],
                    method=sink_api["method"],
                    access="Argument[0..10]",
                    tag=self.project_name,
                )
                for sink_api in sink_apis
                if isinstance(sink_api, dict)
            ])

        # Build the final yaml
        yml_content = EXTENSION_YML_TEMPLATE.format(
            sources="\n".join([source_api_entries, source_func_parm_entries]),
            sinks=sink_api_entries)

        return yml_content

    def build_and_save_extension_yml(self):
        os.makedirs(os.path.dirname(self.spec_yml_path), exist_ok=True)
        with open(self.spec_yml_path, "w") as f:
            f.write(self.build_extension_yml())

    def build_project_specific_query(self):
        if self.test_run: return

        self.project_logger.info("==> Stage 5: Building project specific query...")

        self.project_logger.info("  ==> Building source query...")
        if self.use_exhaustive_qll:
            self.build_and_save_source_qll_with_enumeration()
        else:
            self.build_and_save_source_qll_with_source_node()

        self.project_logger.info("  ==> Building taint-propagator query...")
        self.build_and_save_taint_propagator_qll_with_enumeration()

        self.project_logger.info("  ==> Building sink query...")
        if self.use_exhaustive_qll:
            self.build_and_save_sink_qll_with_enumeration()
        else:
            self.build_and_save_sink_qll_with_sink_node()

        # NOT WORKING YAML
        self.project_logger.info("  ==> Building extension yml...")
        self.build_and_save_extension_yml()

    # STAGE6_EXACT_CACHE_V1
    #
    # Persistent exact-input cache for Stage 6 CodeQL analysis.
    # The cache identity deliberately excludes RUN_ID/path.
    #
    # SARIF contains run-specific tool-extension URIs pointing at
    # <run>/myqueries.  Those URIs are normalized before caching
    # and rebound to the current run when restoring.
    def _stage6_exact_cache_file_sha256(self, path):
        return self._static_cache_sha256_file(path)

    def _stage6_exact_cache_identity(
        self,
        codeql_ram_mb,
        codeql_threads,
    ):
        codeql_version = (
            self._static_cache_codeql_version()
        )

        if codeql_version is None:
            return None, None

        db_files = {
            "codeql-database.yml":
                os.path.join(
                    self.project_codeql_db_path,
                    "codeql-database.yml",
                ),
            "src.zip":
                os.path.join(
                    self.project_codeql_db_path,
                    "src.zip",
                ),
        }

        pack_files = {
            "qlpack.yml":
                os.path.join(
                    self.custom_codeql_root,
                    "qlpack.yml",
                ),
            "codeql-pack.lock.yml":
                os.path.join(
                    self.custom_codeql_root,
                    "codeql-pack.lock.yml",
                ),
        }

        query_root = os.path.join(
            self.custom_codeql_root,
            self.query,
        )

        if not os.path.isdir(query_root):
            return None, None

        generated_query_inputs = {}

        for root, dirs, files in os.walk(query_root):
            dirs.sort()
            files.sort()

            for name in files:
                path = os.path.join(
                    root,
                    name,
                )

                rel = os.path.relpath(
                    path,
                    query_root,
                )

                try:
                    generated_query_inputs[rel] = (
                        self._stage6_exact_cache_file_sha256(
                            path
                        )
                    )
                except OSError:
                    return None, None

        if not generated_query_inputs:
            return None, None

        database = {}
        pack = {}

        try:
            for name, path in db_files.items():
                database[name] = (
                    self._stage6_exact_cache_file_sha256(
                        path
                    )
                )

            for name, path in pack_files.items():
                pack[name] = (
                    self._stage6_exact_cache_file_sha256(
                        path
                    )
                )

            iris_py_sha = (
                self._stage6_exact_cache_file_sha256(
                    os.path.abspath(__file__)
                )
            )
        except OSError:
            return None, None

        identity = {
            "cache_version": 1,
            "stage": "stage6_codeql_analysis",
            "query": self.query,
            "cwe_id": self.cwe_id,
            "codeql_version": codeql_version,
            "database": database,
            "pack": pack,
            "generated_query_inputs":
                generated_query_inputs,
            "implementation": {
                "iris_py_sha256":
                    iris_py_sha,
            },
            "analysis_contract": {
                "rerun": True,
                "sarif_format":
                    "sarif-latest",
                "csv_format":
                    "csv",
                "ram_mb":
                    int(codeql_ram_mb),
                "threads":
                    int(codeql_threads),
            },
        }

        canonical = json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        fingerprint = hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()

        return fingerprint, identity

    def _stage6_exact_cache_dir(
        self,
        fingerprint,
    ):
        root = os.getenv(
            "IRIS_STAGE6_CACHE_DIR"
        )

        if not root:
            root = os.path.join(
                OUTPUT_DIR,
                "common",
                "stage6_exact_cache_v1",
            )

        return os.path.join(
            root,
            fingerprint[:2],
            fingerprint,
        )

    def _stage6_sarif_uri_prefix(self):
        return (
            "file://"
            + os.path.abspath(
                self.custom_codeql_root
            ).rstrip("/")
            + "/"
        )

    def _stage6_normalize_sarif_bytes(
        self,
        raw_bytes,
    ):
        current = (
            self._stage6_sarif_uri_prefix()
            .encode("utf-8")
        )

        placeholder = (
            b"file://__IRIS_STAGE6_MYQUERIES__/"
        )

        return raw_bytes.replace(
            current,
            placeholder,
        )

    def _stage6_rebase_sarif_bytes(
        self,
        cached_bytes,
    ):
        placeholder = (
            b"file://__IRIS_STAGE6_MYQUERIES__/"
        )

        current = (
            self._stage6_sarif_uri_prefix()
            .encode("utf-8")
        )

        return cached_bytes.replace(
            placeholder,
            current,
        )

    def _restore_stage6_exact_cache(
        self,
        fingerprint,
        identity,
    ):
        if (
            fingerprint is None
            or identity is None
        ):
            return False

        cache_dir = (
            self._stage6_exact_cache_dir(
                fingerprint
            )
        )

        manifest_path = os.path.join(
            cache_dir,
            "manifest.json",
        )

        csv_cache_path = os.path.join(
            cache_dir,
            "results.csv",
        )

        sarif_cache_path = os.path.join(
            cache_dir,
            "results.normalized.sarif",
        )

        if not (
            os.path.isfile(manifest_path)
            and os.path.isfile(csv_cache_path)
            and os.path.isfile(sarif_cache_path)
        ):
            return False

        try:
            with open(
                manifest_path,
                "r",
                encoding="utf-8",
            ) as f:
                manifest = json.load(f)

            if (
                manifest.get("fingerprint")
                != fingerprint
                or manifest.get("identity")
                != identity
            ):
                return False

            artifacts = manifest.get(
                "artifacts",
                {},
            )

            expected_csv = (
                artifacts
                .get("results.csv", {})
                .get("sha256")
            )

            expected_sarif = (
                artifacts
                .get(
                    "results.normalized.sarif",
                    {},
                )
                .get("sha256")
            )

            if not (
                isinstance(expected_csv, str)
                and isinstance(
                    expected_sarif,
                    str,
                )
            ):
                return False

            actual_csv = (
                self._stage6_exact_cache_file_sha256(
                    csv_cache_path
                )
            )

            actual_sarif = (
                self._stage6_exact_cache_file_sha256(
                    sarif_cache_path
                )
            )

            if (
                actual_csv != expected_csv
                or actual_sarif
                != expected_sarif
            ):
                return False

            with open(
                csv_cache_path,
                "rb",
            ) as f:
                csv_bytes = f.read()

            with open(
                sarif_cache_path,
                "rb",
            ) as f:
                normalized_sarif = f.read()

            restored_sarif = (
                self._stage6_rebase_sarif_bytes(
                    normalized_sarif
                )
            )

            # Validate rebased SARIF before modifying
            # destination files.
            json.loads(
                restored_sarif.decode("utf-8")
            )

            os.makedirs(
                os.path.dirname(
                    self.query_output_result_csv_path
                ),
                exist_ok=True,
            )

            csv_tmp = (
                self.query_output_result_csv_path
                + f".tmp.{os.getpid()}"
            )

            sarif_tmp = (
                self.query_output_result_sarif_path
                + f".tmp.{os.getpid()}"
            )

            with open(
                csv_tmp,
                "wb",
            ) as f:
                f.write(csv_bytes)

            with open(
                sarif_tmp,
                "wb",
            ) as f:
                f.write(restored_sarif)

            os.replace(
                csv_tmp,
                self.query_output_result_csv_path,
            )

            os.replace(
                sarif_tmp,
                self.query_output_result_sarif_path,
            )

            return True

        except Exception:
            return False

    def _store_stage6_exact_cache(
        self,
        fingerprint,
        identity,
    ):
        if (
            self.test_run
            or fingerprint is None
            or identity is None
        ):
            return None

        if not (
            os.path.isfile(
                self.query_output_result_csv_path
            )
            and os.path.isfile(
                self.query_output_result_sarif_path
            )
        ):
            return None

        try:
            with open(
                self.query_output_result_csv_path,
                "rb",
            ) as f:
                csv_bytes = f.read()

            with open(
                self.query_output_result_sarif_path,
                "rb",
            ) as f:
                sarif_bytes = f.read()

            normalized_sarif = (
                self._stage6_normalize_sarif_bytes(
                    sarif_bytes
                )
            )

            # Validate normalized SARIF before storage.
            json.loads(
                normalized_sarif.decode("utf-8")
            )

            cache_dir = (
                self._stage6_exact_cache_dir(
                    fingerprint
                )
            )

            os.makedirs(
                cache_dir,
                exist_ok=True,
            )

            csv_path = os.path.join(
                cache_dir,
                "results.csv",
            )

            sarif_path = os.path.join(
                cache_dir,
                "results.normalized.sarif",
            )

            manifest_path = os.path.join(
                cache_dir,
                "manifest.json",
            )

            csv_tmp = (
                csv_path
                + f".tmp.{os.getpid()}"
            )

            sarif_tmp = (
                sarif_path
                + f".tmp.{os.getpid()}"
            )

            manifest_tmp = (
                manifest_path
                + f".tmp.{os.getpid()}"
            )

            with open(
                csv_tmp,
                "wb",
            ) as f:
                f.write(csv_bytes)

            with open(
                sarif_tmp,
                "wb",
            ) as f:
                f.write(normalized_sarif)

            csv_sha = hashlib.sha256(
                csv_bytes
            ).hexdigest()

            sarif_sha = hashlib.sha256(
                normalized_sarif
            ).hexdigest()

            manifest = {
                "fingerprint":
                    fingerprint,
                "identity":
                    identity,
                "artifacts": {
                    "results.csv": {
                        "cache_name":
                            "results.csv",
                        "sha256":
                            csv_sha,
                    },
                    "results.normalized.sarif": {
                        "cache_name":
                            "results.normalized.sarif",
                        "sha256":
                            sarif_sha,
                    },
                },
            }

            with open(
                manifest_tmp,
                "w",
                encoding="utf-8",
            ) as f:
                json.dump(
                    manifest,
                    f,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )

            os.replace(
                csv_tmp,
                csv_path,
            )

            os.replace(
                sarif_tmp,
                sarif_path,
            )

            os.replace(
                manifest_tmp,
                manifest_path,
            )

            return fingerprint

        except Exception:
            return None

    def find_vulnerability(self):
        self.project_logger.info("==> Stage 6: Finding vulnerabilities with CodeQL...")

        # Step 0: Resume only from a structurally valid result bundle.
        if (
            not self.overwrite
            and not self.overwrite_cwe_query_result
            and self._resume_valid_stage6_bundle()
        ):
            self.project_logger.info(
                f"  ==> Found valid existing {self.query} "
                "SARIF+CSV bundle; skipping..."
            )
            return

        if (
            not self.overwrite
            and not self.overwrite_cwe_query_result
            and (
                os.path.exists(
                    self.query_output_result_sarif_path
                )
                or os.path.exists(
                    self.query_output_result_csv_path
                )
            )
        ):
            self.project_logger.info(
                "  ==> Existing Stage 6 result bundle is "
                "incomplete or invalid; recomputing..."
            )

        if self.test_run:
            self.project_logger.info(f"  ==> Test run; skipping...")
            return

        # Step 1: Copy static query files if needed
        self.project_logger.info("  ==> Copying custom queries...")
        codeql_query_dir = f"{self.custom_codeql_root}/{self.query}"
        os.makedirs(codeql_query_dir, exist_ok=True)
        for q in QUERIES[self.query]["queries"]:
            query_dest_path = f"{codeql_query_dir}/{q.split('/')[-1]}"
            if not os.path.exists(query_dest_path):
                shutil.copy(f"{THIS_SCRIPT_DIR}/{q}", query_dest_path)
            self.project_logger.info(f"  ==> Query {q.split('/')[-1]} ready... Done!")

        # Step 2: Run codeql analyze and produce sarif and csv
        self.project_logger.info("  ==> Running CodeQL analysis...")

        # Stage 6 CodeQL resource control.
        #
        # Large generated source/sink models can make QL compilation
        # substantially more memory-intensive than the simple Stage 1/2
        # extraction queries.  Allow an explicit override, otherwise
        # choose a conservative value from WSL/Linux MemTotal while
        # reserving roughly 3 GiB for Python/Ollama/the OS.
        codeql_ram_override = os.getenv("IRIS_CODEQL_RAM_MB")

        if codeql_ram_override:
            codeql_ram_mb = int(codeql_ram_override)
        else:
            total_mem_mb = None

            try:
                with open(
                    "/proc/meminfo",
                    "r",
                    encoding="utf-8",
                ) as meminfo:
                    for line in meminfo:
                        if line.startswith("MemTotal:"):
                            total_mem_kb = int(
                                line.split()[1]
                            )
                            total_mem_mb = (
                                total_mem_kb // 1024
                            )
                            break
            except (OSError, ValueError):
                total_mem_mb = None

            if total_mem_mb is None:
                codeql_ram_mb = 4096
            else:
                codeql_ram_mb = max(
                    2048,
                    min(
                        8192,
                        total_mem_mb - 1536,
                    ),
                )

        codeql_threads = int(
            os.getenv(
                "IRIS_CODEQL_THREADS",
                "1",
            )
        )

        if codeql_ram_mb < 2048:
            raise RuntimeError(
                "IRIS_CODEQL_RAM_MB must be >= 2048"
            )

        if codeql_threads < 1:
            raise RuntimeError(
                "IRIS_CODEQL_THREADS must be >= 1"
            )

        self.project_logger.info(
            "  ==> Stage 6 CodeQL resources: "
            f"RAM={codeql_ram_mb} MB, "
            f"threads={codeql_threads}"
        )

        # STAGE6_SKIP_PACK_INSTALL_V1
        #
        # Do not invoke `codeql pack install` here. The complete
        # dependency graph is frozen by the canonical lock file and
        # all locked packs must already exist in the local CodeQL
        # package cache. Registry-aware installation would break
        # local-only reproducibility.
        lock_file_path = (
            f"{self.custom_codeql_root}/codeql-pack.lock.yml"
        )

        canonical_lock_path = os.path.join(
            os.path.dirname(__file__),
            "queries",
            "codeql-pack.lock.yml",
        )

        if not os.path.isfile(lock_file_path):
            msg = (
                "  ==> Missing generated frozen CodeQL lock file; "
                "aborting"
            )
            self.project_logger.error(msg)
            raise RuntimeError(msg)

        if not os.path.isfile(canonical_lock_path):
            msg = (
                "  ==> Missing canonical frozen CodeQL lock file; "
                "aborting"
            )
            self.project_logger.error(msg)
            raise RuntimeError(msg)

        with open(lock_file_path, "rb") as f:
            generated_lock = f.read()

        with open(canonical_lock_path, "rb") as f:
            canonical_lock = f.read()

        if generated_lock != canonical_lock:
            msg = (
                "  ==> Generated CodeQL lock differs from canonical "
                "frozen lock; aborting"
            )
            self.project_logger.error(msg)
            raise RuntimeError(msg)

        self.project_logger.info(
            "  ==> Stage 6 frozen CodeQL lock verified; "
            "skipping registry-dependent pack install"
        )

        stage6_cache_fingerprint, stage6_cache_identity = (
            self._stage6_exact_cache_identity(
                codeql_ram_mb,
                codeql_threads,
            )
        )

        stage6_cache_hit = False

        if (
            not self.overwrite
            and not self.overwrite_cwe_query_result
        ):
            stage6_cache_hit = (
                self._restore_stage6_exact_cache(
                    stage6_cache_fingerprint,
                    stage6_cache_identity,
                )
            )

        if stage6_cache_hit:
            self.project_logger.info(
                "  ==> Stage 6 exact cache: HIT "
                f"{stage6_cache_fingerprint}"
            )
            return

        self.project_logger.info(
            "  ==> Stage 6 exact cache: MISS"
        )

        query_filename = QUERIES[self.query]["queries"][0].split("/")[-1]
        to_run_query_full_path = f"{codeql_query_dir}/{query_filename}"

        # Pack dependencies are resolved through the custom qlpack lockfile
        # and the CodeQL package cache; no explicit --search-path is required.

        # Run SARIF analysis
        sarif_cmd = [
            CODEQL,
            "database",
            "analyze",
            "--rerun",
            f"--ram={codeql_ram_mb}",
            f"--threads={codeql_threads}",
            self.project_codeql_db_path,
            "--format=sarif-latest",
            f"--output={self.query_output_result_sarif_path}",
            to_run_query_full_path,
        ]
        sarif_result = sp.run(sarif_cmd)
        if sarif_result.returncode != 0:
            msg = (
                "  ==> CodeQL SARIF analysis failed with exit code "
                f"{sarif_result.returncode}; aborting"
            )
            self.project_logger.error(msg)
            raise RuntimeError(msg)

        if (
            not os.path.isfile(self.query_output_result_sarif_path)
            or os.path.getsize(self.query_output_result_sarif_path) == 0
        ):
            msg = "  ==> Result SARIF not produced or empty; aborting"
            self.project_logger.error(msg)
            raise RuntimeError(msg)

        # Run CSV analysis
        csv_cmd = [
            CODEQL,
            "database",
            "analyze",
            "--rerun",
            f"--ram={codeql_ram_mb}",
            f"--threads={codeql_threads}",
            self.project_codeql_db_path,
            "--format=csv",
            f"--output={self.query_output_result_csv_path}",
            to_run_query_full_path,
        ]
        csv_result = sp.run(csv_cmd)
        if csv_result.returncode != 0:
            msg = (
                "  ==> CodeQL CSV analysis failed with exit code "
                f"{csv_result.returncode}; aborting"
            )
            self.project_logger.error(msg)
            raise RuntimeError(msg)

        if not os.path.isfile(self.query_output_result_csv_path):
            msg = "  ==> Result CSV not produced; aborting"
            self.project_logger.error(msg)
            raise RuntimeError(msg)

        if os.path.getsize(self.query_output_result_csv_path) == 0:
            # CodeQL legitimately emits an empty CSV when a successful
            # vulnerability query returns zero rows.  Distinguish that
            # valid zero-finding case from an inconsistent output state
            # by checking the already-produced SARIF.
            try:
                with open(
                    self.query_output_result_sarif_path,
                    "r",
                    encoding="utf-8",
                ) as f:
                    sarif = json.load(f)

                sarif_results = (
                    sarif.get("runs", [{}])[0]
                    .get("results", [])
                )
            except Exception as e:
                msg = (
                    "  ==> Result CSV is empty and SARIF could not be "
                    f"validated: {e}; aborting"
                )
                self.project_logger.error(msg)
                raise RuntimeError(msg)

            if len(sarif_results) == 0:
                self.project_logger.info(
                    "  ==> CodeQL query returned zero findings; "
                    "empty CSV is valid."
                )
            else:
                msg = (
                    "  ==> Result CSV is empty despite non-empty "
                    "SARIF results; aborting"
                )
                self.project_logger.error(msg)
                raise RuntimeError(msg)

        stage6_cache_key = (
            self._store_stage6_exact_cache(
                stage6_cache_fingerprint,
                stage6_cache_identity,
            )
        )

        if stage6_cache_key is not None:
            self.project_logger.info(
                "  ==> Stage 6 exact cache: STORED "
                f"{stage6_cache_key}"
            )

    def extract_class_locations(self):
        # LOCATION_STATIC_CACHE_V1
        if os.path.exists(self.class_locs_path):
            return

        cache_artifacts = [
            ("raw", self.class_locs_path),
        ]

        if (
            not self.overwrite
            and self._restore_static_stage_cache(
                "location_class_locs",
                "fetch_class_locs",
                cache_artifacts,
            )
        ):
            self.project_logger.info(
                "  ==> Class locations static cache: HIT"
            )
            return

        self.project_logger.info(
            "  ==> Class locations static cache: MISS"
        )
        self.project_logger.info(
            "  ==> Class locations not found; "
            "running CodeQL query to extract..."
        )

        self.run_simple_codeql_query(
            "fetch_class_locs"
        )

        cache_key = self._store_static_stage_cache(
            "location_class_locs",
            "fetch_class_locs",
            cache_artifacts,
        )

        if cache_key is not None:
            self.project_logger.info(
                "  ==> Class locations static cache: STORED "
                f"{cache_key}"
            )

    def extract_func_locations(self):
        # LOCATION_STATIC_CACHE_V1
        if os.path.exists(self.func_locs_path):
            return

        cache_artifacts = [
            ("raw", self.func_locs_path),
        ]

        if (
            not self.overwrite
            and self._restore_static_stage_cache(
                "location_func_locs",
                "fetch_func_locs",
                cache_artifacts,
            )
        ):
            self.project_logger.info(
                "  ==> Function locations static cache: HIT"
            )
            return

        self.project_logger.info(
            "  ==> Function locations static cache: MISS"
        )
        self.project_logger.info(
            "  ==> Function locations not found; "
            "running CodeQL query to extract..."
        )

        self.run_simple_codeql_query(
            "fetch_func_locs"
        )

        cache_key = self._store_static_stage_cache(
            "location_func_locs",
            "fetch_func_locs",
            cache_artifacts,
        )

        if cache_key is not None:
            self.project_logger.info(
                "  ==> Function locations static cache: STORED "
                f"{cache_key}"
            )

    def extract_enclosing_decl_locs_map(self, decl_locs):
        """
        Extract enclosing declaration locations mapping from a pandas DataFrame

        :param decl_locs, a pandas DataFrame containing function or class locations
        :returns a mapping from file name to list of declarations defined in that file.
                 each declaration is a tuple (<decl_name>, <start_line>, <end_line>)
        """
        enclosing_decl_locs = {}
        for (i, row) in decl_locs.iterrows():
            if row["file"] not in enclosing_decl_locs:
                enclosing_decl_locs[row["file"]] = []
            enclosing_decl_locs[row["file"]].append((row["name"], row["start_line"], row["end_line"]))
        return enclosing_decl_locs

    def find_enclosing_declaration(self, start_line, end_line, decl_locs):
        closest_start_end = None
        for decl_loc in decl_locs:
            if decl_loc[1] <= start_line and end_line <= decl_loc[2]:
                if closest_start_end is None:
                    closest_start_end = decl_loc
                else:
                    if decl_loc[1] > closest_start_end[1]:
                        closest_start_end = decl_loc
        return closest_start_end

    def is_valid_alarm(self, alarm):
        if "codeFlows" not in alarm:
            return False
        else:
            return len(alarm["codeFlows"]) > 0

    def get_source_line(self, location):
        relative_file_url = location["location"]["physicalLocation"]["artifactLocation"]["uri"]
        line_num = location["location"]["physicalLocation"]["region"]["startLine"]
        file_dir = f"{self.project_source_code_dir}/{relative_file_url}"
        if not os.path.exists(file_dir):
            print("Not found ", file_dir)
            return ""
        else:
            file_lines = list(open(file_dir, 'r').readlines())
            if line_num > len(file_lines):
                return ""
            else:
                line = file_lines[line_num - 1]
                return line

    def is_valid_code_flow(self, code_flow, source_is_func_param, project_methods):
        thread_flow = code_flow["threadFlows"][0]
        locations = thread_flow["locations"]
    
        # if source_is_func_param:
        #     source_loc = locations[0]
        #     source_file_url = source_loc["location"]["physicalLocation"]["artifactLocation"]["uri"]
        #     source_start_line = source_loc["location"]["physicalLocation"]["region"]["startLine"]
        #     source_enclosing_func = self.find_enclosing_declaration(source_start_line, source_start_line, project_methods[source_file_url])

        snk_line = self.get_source_line(locations[-1])
        if ".println(" in snk_line or ".print(" in snk_line:
            return False

        for loc in locations:
            file_url = loc["location"]["physicalLocation"]["artifactLocation"]["uri"]
            if "src/test" in file_url:
                return False

        return True

    def post_process_cwe_query_result(self):
        self.project_logger.info("==> Stage 7: Post-processing CWE query results...")
        original_result_sarif = json.load(open(self.query_output_result_sarif_path))
        alarms = original_result_sarif["runs"][0]["results"]

        # 1. Extract class and function locations
        self.project_logger.info("  ==> Extracting function and class locations...")
        self.extract_func_locations()
        project_methods = self.extract_enclosing_decl_locs_map(pd.read_csv(self.func_locs_path))

        # 2. Print statistics
        num_alarms = len(alarms)
        num_paths = sum([len(alarm["codeFlows"]) for alarm in alarms if "codeFlows" in alarm])
        self.project_logger.info(f"  ==> Original #alarms: {num_alarms}; Original #paths: {num_paths}")

        # Do a few things
        # 1. remove the paths with node location containing `src/test`
        # 2. if the path starts with a function parameter of `f`, and that the path
        #    contains anything after a `return` statement inside that function `f`
        for alarm in alarms:
            source_is_func_param = "user-provided value as public function parameter" in alarm["message"]["text"]
            if "codeFlows" in alarm:
                alarm["codeFlows"] = [cf for cf in alarm["codeFlows"] if self.is_valid_code_flow(cf, source_is_func_param, project_methods)]

        # 3. Remove the alarms with no code-flows
        alarms = [alarm for alarm in alarms if self.is_valid_alarm(alarm)]
        new_num_alarms = len(alarms)
        new_num_paths = sum([len(alarm["codeFlows"]) for alarm in alarms if "codeFlows" in alarm])
        self.project_logger.info(f"  ==> New #alarms: {new_num_alarms}; New #paths: {new_num_paths}")

        # 4. Save the result back to the sarif
        original_result_sarif["runs"][0]["results"] = alarms
        if not self.test_run:
            json.dump(original_result_sarif, open(self.query_output_result_sarif_pp_path, "w"))

    def query_gpt_for_posthoc_filtering(self):
        self.project_logger.info("==> Stage 8: Querying LLM for posthoc filtering...")
        if self.skip_posthoc_filter:
            self.project_logger.info("  ==> Skipping posthoc filter...")
            return

        # 1. Extract class and function locations
        self.project_logger.info("  ==> Extracting function and class locations...")
        self.extract_class_locations()
        self.extract_func_locations()

        # 2. Create and run the pipeline
        contextual_analysis_pipeline = ContextualAnalysisPipeline(
            self.query,
            self.cwe_id,
            self.llm,
            self.seed,
            self.class_locs_path,
            self.func_locs_path,
            self.project_fixed_methods,
            self.query_output_result_sarif_pp_path,
            self.posthoc_filtering_output_log_path,
            self.posthoc_filtering_output_result_json_path,
            self.posthoc_filtering_output_result_sarif_path,
            self.posthoc_filtering_output_stats_json_path,
            self.project_source_code_dir,
            self.project_logger,
            self.overwrite,
            self.overwrite_posthoc_filter,
            self.test_run,
            posthoc_filtering_skip_fp=self.posthoc_filtering_skip_fp,
            rerun_skipped_fp=self.posthoc_filtering_rerun_skipped_fp,
            overwrite_llm_cache=self.overwrite_llm_cache,
        )
        contextual_analysis_pipeline.run()

    def build_evaluation_pipeline(self):
        return EvaluationPipeline(
            self.project_fixed_methods,
            self.class_locs_path,
            self.func_locs_path,
            self.project_source_code_dir,
            self.external_apis_csv_path,
            self.candidate_apis_csv_path,
            self.llm_labelled_sink_apis_path,
            self.llm_labelled_source_apis_path,
            self.llm_labelled_taint_prop_apis_path,
            self.source_func_param_candidates_path,
            self.llm_labelled_source_func_params_path,
            self.query_output_result_sarif_pp_path,
            self.posthoc_filtering_output_result_sarif_path,
            self.final_output_json_path,
            self.project_logger,
            overwrite=self.overwrite or self.overwrite_posthoc_filter or self.overwrite_cwe_query_result,
            test_run=self.test_run,
            posthoc_filtering_output_stats_json_path=self.posthoc_filtering_output_stats_json_path,
        )

    def evaluate_result(self):
        self.project_logger.info("==> Stage 9: Evaluating results...")
        if self.skip_evaluation:
            self.project_logger.info("  ==> skipping evaluation...")
            return

        # 1. Extract class and function locations
        self.project_logger.info("  ==> Extracting function and class locations...")
        self.extract_class_locations()
        self.extract_func_locations()

        # 2. Build
        eval_pipeline = self.build_evaluation_pipeline()
        eval_pipeline.run()

    def debug_result(self):
        if self.test_run:
            return

        # Debug source information
        if self.debug_source:
            if self.overwrite or self.overwrite_debug_info or not os.path.exists(f"{self.project_output_path}/fetch_sources/cwe-{self.cwe_id}/results.csv"):
                self.project_logger.info("==> Stage 10.1: Debug sources...")
                self.run_simple_codeql_query("fetch_sources", suffix=f"cwe-{self.cwe_id}", dyn_queries={"MySources.qll": self.build_source_qll_with_enumeration()})

        # Debug sink information
        if self.debug_sink:
            if self.overwrite or self.overwrite_debug_info or not os.path.exists(f"{self.project_output_path}/fetch_sinks/cwe-{self.cwe_id}/results.csv"):
                self.project_logger.info("==> Stage 10.1: Debug sinks...")
                self.run_simple_codeql_query("fetch_sinks", suffix=f"cwe-{self.cwe_id}", dyn_queries={"MySinks.qll": self.build_sink_qll_with_enumeration()})

    def run(self):
        # Normal execution now relies on per-stage validated resume
        # contracts rather than an existence-only skip-all shortcut.
        if self.evaluation_only:
            self.master_logger.info(
                "==> Evaluation-only mode"
            )
            self.post_process_cwe_query_result()
            self.evaluate_result()
            self.debug_result()
            return

        # 1. Collect all the invoked external APIs
        self.collect_invoked_external_apis()

        # 2. Collect all the internal function parameters
        self.collect_internal_function_parameters()

        # 3. Query GPT for source/taint-propagator/sink from external APIs
        self.query_gpt_for_api_src_tp_sink_batched()

        # 4. Query GPT for sources among internal function parameters
        self.query_gpt_for_func_param_src()

        # 5. Build local query for this project
        self.build_project_specific_query()

        # 6. Send the local query for vulnerability detection
        self.find_vulnerability()

        # 7. Do a post-processing step for rule-based filtering of paths
        self.post_process_cwe_query_result()

        # 8. Do posthoc filtering
        self.query_gpt_for_posthoc_filtering()

        # 9. Evaluate performance
        self.evaluate_result()

        # 10. Debuggging
        self.debug_result()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("project", type=str)
    parser.add_argument("--query", type=str, default="022", required=True)
    parser.add_argument("--llm", type=str, default="gpt-4")
    parser.add_argument("--run-id", type=str, default="default")
    parser.add_argument("--seed", type=int, default=1234)
    parser.add_argument("--label-api-batch-size", type=int, default=30)
    parser.add_argument("--label-func-param-batch-size", type=int, default=20)
    parser.add_argument("--num-threads", type=int, default=3)
    parser.add_argument("--no-summary-model", action="store_true")
    parser.add_argument("--use-exhaustive-qll", action="store_true")
    parser.add_argument("--filter-by-module", action="store_true")
    parser.add_argument("--filter-by-module-large", action="store_true")
    parser.add_argument("--skip-huge-project", action="store_true")
    parser.add_argument("--skip-huge-project-num-apis-threshold", type=int, default=3000)
    parser.add_argument("--skip-posthoc-filter", action="store_true")
    parser.add_argument("--skip-evaluation", action="store_true")
    parser.add_argument("--posthoc-filtering-skip-fp", action="store_true")
    parser.add_argument("--posthoc-filtering-rerun-skipped-fp", action="store_true")
    parser.add_argument("--evaluation-only", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--overwrite-api-candidates", action="store_true")
    parser.add_argument("--overwrite-func-param-candidates", action="store_true")
    parser.add_argument("--overwrite-labelled-apis", action="store_true")
    parser.add_argument("--overwrite-llm-cache", action="store_true")
    parser.add_argument("--overwrite-labelled-func-param", action="store_true")
    parser.add_argument("--overwrite-cwe-query-result", action="store_true")
    parser.add_argument("--overwrite-postprocess-cwe-query-result", action="store_true")
    parser.add_argument("--overwrite-posthoc-filter", action="store_true")
    parser.add_argument("--overwrite-debug-info", action="store_true")
    parser.add_argument("--debug-source", action="store_true")
    parser.add_argument("--debug-sink", action="store_true")
    parser.add_argument("--test-run", action="store_true")
    parser.add_argument("--use-container", action="store_true", help="Use container-built CodeQL database")
    args = parser.parse_args()

    # Set basic properties
    args.use_exhaustive_qll = True

    pipeline = SAPipeline(
        args.project,
        args.query,
        run_id=args.run_id,
        llm=args.llm,
        label_api_batch_size=args.label_api_batch_size,
        label_func_param_batch_size=args.label_func_param_batch_size,
        num_threads=args.num_threads,
        seed=args.seed,
        no_summary_model=args.no_summary_model,
        use_exhaustive_qll=args.use_exhaustive_qll,
        skip_huge_project=args.skip_huge_project,
        skip_huge_project_num_apis_threshold=args.skip_huge_project_num_apis_threshold,
        skip_posthoc_filter=args.skip_posthoc_filter,
        skip_evaluation=args.skip_evaluation,
        filter_by_module=args.filter_by_module,
        filter_by_module_large=args.filter_by_module_large,
        posthoc_filtering_skip_fp=args.posthoc_filtering_skip_fp,
        posthoc_filtering_rerun_skipped_fp=args.posthoc_filtering_rerun_skipped_fp,
        evaluation_only=args.evaluation_only,
        overwrite=args.overwrite,
        overwrite_api_candidates=args.overwrite_api_candidates,
        overwrite_func_param_candidates=args.overwrite_func_param_candidates,
        overwrite_labelled_apis=args.overwrite_labelled_apis,
        overwrite_llm_cache=args.overwrite_llm_cache,
        overwrite_labelled_func_param=args.overwrite_labelled_func_param,
        overwrite_cwe_query_result=args.overwrite_cwe_query_result,
        overwrite_postprocess_cwe_query_result=args.overwrite_postprocess_cwe_query_result,
        overwrite_posthoc_filter=args.overwrite_posthoc_filter,
        overwrite_debug_info=args.overwrite_debug_info,
        debug_source=args.debug_source,
        debug_sink=args.debug_sink,
        test_run=args.test_run,
        use_container=args.use_container,
    )

    pipeline.run()
