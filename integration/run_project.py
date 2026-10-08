#!/usr/bin/env python3

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
INTEGRATION = ROOT / "integration"

SOURCE_ROOT = ROOT / "data" / "project-sources"
DB_ROOT = ROOT / "data" / "codeql-dbs"
PACKAGE_ROOT = ROOT / "data" / "package-names"

ALL_QUERIES = [
    "cwe-022wLLM",
    "cwe-078wLLM",
    "cwe-079wLLM",
    "cwe-089wLLM",
]

DEFAULT_MODEL = "ollama-qwen-coder-1.5b"


def print_cmd(cmd, cwd=None):
    prefix = ""

    if cwd is not None:
        prefix = f"(cd {shlex.quote(str(cwd))} && "

    text = shlex.join([str(x) for x in cmd])

    if cwd is not None:
        text += ")"

    print("+", prefix + text, flush=True)


def run(cmd, cwd=None, env=None, capture=False):
    cmd = [str(x) for x in cmd]

    print_cmd(cmd, cwd=cwd)

    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=True,
    )


def find_executable(candidates, label):
    for value in candidates:
        if not value:
            continue

        p = Path(str(value)).expanduser()

        if p.is_file():
            return str(p.resolve())

        found = shutil.which(str(value))

        if found:
            return str(Path(found).resolve())

    raise FileNotFoundError(
        f"Cannot find {label}. Checked: "
        + ", ".join(str(x) for x in candidates if x)
    )


def validate_project_name(project):
    if not re.fullmatch(r"[A-Za-z0-9._-]+", project):
        raise ValueError(
            "Project name may contain only letters, numbers, '.', '_' and '-'."
        )

    if project in {".", ".."}:
        raise ValueError("Invalid project name")


def detect_build_command(source):
    if (source / "mvnw").is_file():
        return "./mvnw -DskipTests clean compile"

    if (source / "pom.xml").is_file():
        return "mvn -DskipTests clean compile"

    if (source / "gradlew").is_file():
        return "./gradlew classes -x test"

    if (
        (source / "build.gradle").is_file()
        or (source / "build.gradle.kts").is_file()
    ):
        return "gradle classes -x test"

    return None


def validate_database(codeql, db):
    """
    Validate the database against both CodeQL and IRIS contracts.

    A partially-created CodeQL database may still be resolvable while
    lacking db-java. IRIS explicitly requires <db>/db-java, so a database
    is reusable only when all of the checks below pass.
    """

    if not db.is_dir():
        return False

    metadata_path = (
        db / "codeql-database.yml"
    )

    if not metadata_path.is_file():
        return False

    # IRIS SAPipeline.__init__ requires this directory.
    if not (db / "db-java").is_dir():
        return False

    try:
        metadata = yaml.safe_load(
            metadata_path.read_text(
                encoding="utf-8",
            )
        ) or {}
    except Exception:
        return False

    # A failed CodeQL database create can leave metadata behind.
    if metadata.get("finalised") is not True:
        return False

    result = subprocess.run(
        [
            codeql,
            "resolve",
            "database",
            "--format=json",
            "--",
            str(db),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    return result.returncode == 0



def java_major(java_bin):
    result = subprocess.run(
        [str(java_bin), "-version"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    text = result.stderr + "\n" + result.stdout

    match = re.search(
        r'version\s+"([^"]+)"',
        text,
    )

    if match is None:
        return None

    version = match.group(1)

    if version.startswith("1."):
        match = re.match(
            r"1\.(\d+)",
            version,
        )
    else:
        match = re.match(
            r"(\d+)",
            version,
        )

    if match is None:
        return None

    return int(match.group(1))


def version_major(value):
    value = str(value).strip()

    if value.startswith("1."):
        match = re.match(
            r"1\.(\d+)",
            value,
        )
    else:
        match = re.match(
            r"(\d+)",
            value,
        )

    if match is None:
        return None

    return int(match.group(1))


def detect_required_java_major(source):
    candidates = []

    # Explicit version-manager files.
    for name in (
        ".java-version",
        ".tool-versions",
    ):
        path = source / name

        if not path.is_file():
            continue

        text = path.read_text(
            encoding="utf-8",
            errors="ignore",
        )

        if name == ".tool-versions":
            match = re.search(
                r"(?m)^\s*java\s+([^\s]+)",
                text,
            )

            if match:
                major = version_major(
                    match.group(1)
                )

                if major is not None:
                    candidates.append(major)

        else:
            major = version_major(text)

            if major is not None:
                candidates.append(major)

    # Common Maven Java properties.
    pom = source / "pom.xml"

    if pom.is_file():
        text = pom.read_text(
            encoding="utf-8",
            errors="ignore",
        )

        patterns = (
            r"<java\.version>\s*([^<]+)\s*</java\.version>",
            r"<maven\.compiler\.release>\s*([^<]+)\s*</maven\.compiler\.release>",
            r"<maven\.compiler\.source>\s*([^<]+)\s*</maven\.compiler\.source>",
            r"<maven\.compiler\.target>\s*([^<]+)\s*</maven\.compiler\.target>",
        )

        for pattern in patterns:
            for match in re.finditer(
                pattern,
                text,
                flags=re.IGNORECASE,
            ):
                value = match.group(1).strip()

                # Ignore unresolved Maven properties such as
                # ${some.java.version}.
                if "${" in value:
                    continue

                major = version_major(value)

                if major is not None:
                    candidates.append(major)

    if not candidates:
        return None

    return max(candidates)


def installed_jdks():
    homes = []

    configured = os.environ.get("JAVA_HOME")

    if configured:
        homes.append(
            Path(configured).expanduser()
        )

    jvm_root = Path("/usr/lib/jvm")

    if jvm_root.is_dir():
        homes.extend(
            sorted(jvm_root.iterdir())
        )

    seen = set()
    result = []

    for home in homes:
        try:
            home = home.resolve()
        except OSError:
            continue

        if home in seen:
            continue

        seen.add(home)

        java_bin = home / "bin/java"

        if not java_bin.is_file():
            continue

        major = java_major(java_bin)

        if major is None:
            continue

        result.append(
            (major, home)
        )

    return sorted(
        result,
        key=lambda x: (x[0], str(x[1])),
    )


def select_java_env(
    source,
    java_home_override=None,
):
    required = detect_required_java_major(
        source
    )

    jdks = installed_jdks()

    print()
    print("===== JAVA SELECTION =====")
    print(
        "PROJECT_REQUIRED_JAVA_MAJOR =",
        required,
    )

    if jdks:
        for major, home in jdks:
            print(
                "INSTALLED_JDK =",
                major,
                home,
            )
    else:
        print("INSTALLED_JDK = <none detected>")

    if java_home_override:
        selected_home = (
            Path(java_home_override)
            .expanduser()
            .resolve()
        )

        selected_java = (
            selected_home / "bin/java"
        )

        if not selected_java.is_file():
            raise RuntimeError(
                "Invalid --java-home: "
                f"{selected_home}"
            )

        selected_major = java_major(
            selected_java
        )

        if selected_major is None:
            raise RuntimeError(
                "Cannot determine Java version: "
                f"{selected_java}"
            )

        if (
            required is not None
            and selected_major < required
        ):
            raise RuntimeError(
                f"Selected Java {selected_major} "
                f"is below project requirement "
                f"Java {required}"
            )

    elif required is not None:
        eligible = [
            (major, home)
            for major, home in jdks
            if major >= required
        ]

        if not eligible:
            installed = ", ".join(
                f"Java {major}: {home}"
                for major, home in jdks
            )

            raise RuntimeError(
                f"Project requires Java >= {required}, "
                "but no compatible installed JDK was found. "
                f"Installed: {installed or '<none>'}"
            )

        # Prefer the lowest installed JDK satisfying the project,
        # reducing compatibility surprises on older projects.
        selected_major, selected_home = (
            eligible[0]
        )

    else:
        current_home = os.environ.get(
            "JAVA_HOME"
        )

        selected = None

        if current_home:
            resolved = (
                Path(current_home)
                .expanduser()
                .resolve()
            )

            for major, home in jdks:
                if home == resolved:
                    selected = (
                        major,
                        home,
                    )
                    break

        if selected is None:
            if not jdks:
                print(
                    "JAVA_SELECTION="
                    "inherit current PATH"
                )

                return (
                    os.environ.copy(),
                    None,
                    None,
                    None,
                )

            # No declared project requirement and no valid
            # JAVA_HOME: prefer the highest installed JDK.
            selected = jdks[-1]

        selected_major, selected_home = (
            selected
        )

    env = os.environ.copy()

    env["JAVA_HOME"] = str(
        selected_home
    )

    env["PATH"] = (
        str(selected_home / "bin")
        + os.pathsep
        + env.get("PATH", "")
    )

    print(
        "SELECTED_JAVA_MAJOR =",
        selected_major,
    )

    print(
        "SELECTED_JAVA_HOME =",
        selected_home,
    )

    return (
        env,
        required,
        selected_major,
        selected_home,
    )

def prepare_database(
    project,
    source,
    codeql,
    explicit_build_command=None,
    java_home_override=None,
):
    db = DB_ROOT / project

    print()
    print("===== CODEQL DATABASE =====")
    print("DB =", db)

    if db.exists():
        if validate_database(codeql, db):
            print("CODEQL_DB=REUSE_VALID")
            return db

        quarantine_root = (
            ROOT
            / "data"
            / "codeql-db-quarantine"
        )

        quarantine_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        stamp = dt.datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        quarantine = (
            quarantine_root
            / (
                f"{project}.invalid_"
                f"{stamp}_{os.getpid()}"
            )
        )

        if quarantine.exists():
            raise RuntimeError(
                "CodeQL quarantine target already exists: "
                f"{quarantine}"
            )

        print(
            "CODEQL_DB=INVALID_OR_PARTIAL"
        )

        print(
            "CODEQL_DB_QUARANTINE=",
            quarantine,
        )

        shutil.move(
            str(db),
            str(quarantine),
        )

        print(
            "CODEQL_DB_QUARANTINED=YES"
        )

    (
        java_env,
        required_java_major,
        selected_java_major,
        selected_java_home,
    ) = select_java_env(
        source,
        java_home_override=java_home_override,
    )

    build_command = (
        explicit_build_command
        if explicit_build_command
        else detect_build_command(source)
    )

    DB_ROOT.mkdir(parents=True, exist_ok=True)

    if build_command:
        print("BUILD_COMMAND =", build_command)

        run(
            [
                codeql,
                "database",
                "create",
                str(db),
                "--language=java",
                f"--source-root={source}",
                f"--command={build_command}",
            ],
            env=java_env,
        )
    else:
        print(
            "BUILD_COMMAND = <none detected>; "
            "using CodeQL Java no-build mode"
        )

        run(
            [
                codeql,
                "database",
                "create",
                str(db),
                "--language=java",
                "--build-mode=none",
                f"--source-root={source}",
            ],
            env=java_env,
        )

    if not validate_database(codeql, db):
        raise RuntimeError(
            f"CodeQL database validation failed: {db}"
        )

    print("CODEQL_DB_CREATE=PASS")

    return db


def source_packages(source):
    package_re = re.compile(
        r"^\s*package\s+"
        r"([A-Za-z_][A-Za-z0-9_.]*)\s*;",
        re.MULTILINE,
    )

    packages = set()

    for java_file in source.rglob("*.java"):
        relative = java_file.relative_to(source)

        if any(
            x in relative.parts
            for x in (
                ".git",
                "target",
                "build",
                ".gradle",
                ".idea",
            )
        ):
            continue

        try:
            text = java_file.read_text(
                encoding="utf-8",
                errors="ignore",
            )
        except OSError:
            continue

        match = package_re.search(text)

        if match:
            packages.add(match.group(1))

    return sorted(packages)


def prepare_package_file(project, source):
    package_file = PACKAGE_ROOT / f"{project}.txt"

    print()
    print("===== INTERNAL PACKAGE FILE =====")
    print("PACKAGE_FILE =", package_file)

    if package_file.is_file():
        print("PACKAGE_FILE=REUSE_EXISTING")
        return package_file

    packages = source_packages(source)

    PACKAGE_ROOT.mkdir(
        parents=True,
        exist_ok=True,
    )

    content = ""

    if packages:
        content = "\n".join(packages) + "\n"

    package_file.write_text(
        content,
        encoding="utf-8",
    )

    print("PACKAGE_COUNT =", len(packages))

    if packages:
        print("PACKAGE_ROOTS =", packages[:10])
    else:
        print(
            "WARNING: no Java package declarations found; "
            "created an empty package file"
        )

    print("PACKAGE_FILE_CREATE=PASS")

    return package_file


def build_config(
    project,
    source,
    opengrep,
    opengrep_config,
    opengrep_extra_args,
    queries,
    model,
    dispatch_mode,
    run_tag,
    no_git_ignore,
):
    run_id = f"{project}/{run_tag}"

    relative_base = (
        Path("generated")
        / project
        / run_tag
    )

    cfg = {
        "project": {
            "name": project,
            "source": str(source),
        },
        "opengrep": {
            "executable": opengrep,
            "config": opengrep_config,
            "output": str(
                relative_base
                / "opengrep.sarif"
            ),
        },
        "iris": {
            "executable": sys.executable,
            "script": "src/iris.py",
            "queries": queries,
            "run_id": run_id,
            "llm": model,
            "overwrite_llm_cache": False,
            "overwrite_label_cache": False,
            "dispatch_mode": dispatch_mode,
        },
        "report": {
            "output_dir": str(
                Path("reports")
                / project
                / run_tag
            ),
            "project_name":
                "OpenGrep + IRIS + Local LLM",
            "analyzer_version": "1.0.0",
        },
        "metadata": {
            "description":
                f"Full automated analysis for {project}",
        },
        "paths": {
            "normalized_findings": str(
                relative_base
                / "normalized_findings.json"
            ),
            "iris_jobs": str(
                relative_base
                / "iris_jobs.json"
            ),
        },
        "logging": {
            "log_dir": str(
                Path("logs")
                / project
                / run_tag
            ),
            "level": "INFO",
        },
        "runtime": {
            "save_temp_files": True,
            "generate_json": True,
            "generate_csv": True,
            "generate_html": True,
            "verbose": True,
        },
    }

    # OPENGREP_PINNED_VARIANT_ARGS_V1
    effective_opengrep_args = list(
        opengrep_extra_args
    )

    if no_git_ignore:
        effective_opengrep_args.append(
            "--no-git-ignore"
        )

    if effective_opengrep_args:
        cfg["opengrep"]["extra_args"] = (
            effective_opengrep_args
        )

    config_path = (
        INTEGRATION
        / relative_base
        / "config.yaml"
    )

    config_path.parent.mkdir(
        parents=True,
        exist_ok=False,
    )

    config_path.write_text(
        yaml.safe_dump(
            cfg,
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )

    return config_path, run_id


def verify_stage_contracts(
    project,
    run_id,
    jobs_file,
):
    print()
    print("===== FULL PIPELINE CONTRACT =====")

    jobs = json.loads(
        jobs_file.read_text(encoding="utf-8")
    )

    if not jobs:
        raise RuntimeError(
            "No IRIS jobs were produced"
        )

    out = (
        ROOT
        / "output"
        / project
        / run_id
    )

    shared = [
        out / "fetch_external_apis/results.csv",
        out / "analysis/common/candidate_apis.csv",
        out / "fetch_func_params/results.csv",
        out
        / "analysis/common/source_func_param_candidates.csv",
    ]

    for path in shared:
        if not path.is_file():
            raise RuntimeError(
                f"Missing Stage 1/2 artifact: {path}"
            )

        print("PASS:", path)

    for job in jobs:
        query = job["query"]

        required = [
            # Stage 3
            out
            / "analysis"
            / query
            / "llm_labelled_source_apis.json",

            out
            / "analysis"
            / query
            / "llm_labelled_sink_apis.json",

            out
            / "analysis"
            / query
            / "llm_labelled_taint_prop_apis.json",

            # Stage 4
            out
            / "analysis"
            / query
            / "llm_labelled_source_func_params.json",

            # Stage 5
            out
            / "myqueries"
            / query
            / "MySources.qll",

            out
            / "myqueries"
            / query
            / "MySummaries.qll",

            out
            / "myqueries"
            / query
            / "MySinks.qll",

            # Stage 6
            out
            / query
            / "results.sarif",

            # Stage 7
            out
            / query
            / "results_pp.sarif",

            # Stage 8
            out
            / f"{query}-posthoc-filter"
            / "results.sarif",

            out
            / f"{query}-posthoc-filter"
            / "results.json",

            out
            / f"{query}-posthoc-filter"
            / "stats.json",

            # Stage 9
            out
            / f"{query}-final"
            / "results.json",
        ]

        print()
        print("QUERY =", query)

        for path in required:
            if not path.is_file():
                raise RuntimeError(
                    f"Missing pipeline artifact: {path}"
                )

            print("PASS:", path)

    print()
    print("IRIS_JOB_COUNT =", len(jobs))
    print("FULL_STAGE_1_TO_9_CONTRACT=PASS")



def verify_report_contract(
    project,
    run_id,
    run_tag,
    jobs_file,
):
    """
    Verify that the final report does not lose analyzer findings.

    The report may deduplicate overlapping OpenGrep/IRIS findings, so
    exact source-count equality is not required. However, if either
    OpenGrep or effective IRIS posthoc SARIF contains findings, the
    merged report must not be empty.
    """

    print()
    print("===== REPORT UNION CONTRACT =====")

    report_path = (
        ROOT
        / "reports"
        / project
        / run_tag
        / "report.json"
    )

    opengrep_path = (
        INTEGRATION
        / "generated"
        / project
        / run_tag
        / "opengrep.sarif"
    )

    assert report_path.is_file(), report_path
    assert opengrep_path.is_file(), opengrep_path

    report = json.loads(
        report_path.read_text(
            encoding="utf-8",
        )
    )

    findings = report.get("findings")

    if not isinstance(findings, list):
        raise RuntimeError(
            "report.json findings is not a list"
        )

    opengrep = json.loads(
        opengrep_path.read_text(
            encoding="utf-8",
        )
    )

    opengrep_count = sum(
        len(run.get("results", []) or [])
        for run in opengrep.get("runs", [])
    )

    jobs = json.loads(
        jobs_file.read_text(
            encoding="utf-8",
        )
    )

    out = (
        ROOT
        / "output"
        / project
        / run_id
    )

    # IRIS_POSTHOC_DIAGNOSTIC_V2
    #
    # Keep three separate meanings:
    #
    # 1. RESULT_CONTAINERS:
    #    Every SARIF result object physically present after Stage 8.
    #
    # 2. SURVIVING_RAW:
    #    Result objects that still contain at least one codeFlow.
    #
    # 3. UNIQUE_FINDINGS:
    #    Effective IRIS findings after applying the same per-SARIF
    #    filtering/dedup semantics used by report_generator.py.
    iris_posthoc_container_count = 0
    iris_posthoc_surviving_raw = 0
    iris_posthoc_unique_count = 0

    from report_generator import SarifLoader

    for job in jobs:
        query = job["query"]

        sarif_path = (
            out
            / f"{query}-posthoc-filter"
            / "results.sarif"
        )

        if not sarif_path.is_file():
            raise RuntimeError(
                "Missing posthoc SARIF for report "
                f"contract: {sarif_path}"
            )

        sarif = json.loads(
            sarif_path.read_text(
                encoding="utf-8",
            )
        )

        results = [
            result
            for run in sarif.get("runs", [])
            for result in (run.get("results", []) or [])
            if isinstance(result, dict)
        ]

        iris_posthoc_container_count += len(results)

        iris_posthoc_surviving_raw += sum(
            1
            for result in results
            if result.get("codeFlows") or []
        )

        iris_posthoc_unique_count += len(
            SarifLoader.load(
                sarif_path,
                "IRIS",
            )
        )

    print(
        "OPENGREP_RESULTS =",
        opengrep_count,
    )

    print(
        "IRIS_POSTHOC_RESULT_CONTAINERS =",
        iris_posthoc_container_count,
    )

    print(
        "IRIS_POSTHOC_SURVIVING_RAW =",
        iris_posthoc_surviving_raw,
    )

    print(
        "IRIS_POSTHOC_UNIQUE_FINDINGS =",
        iris_posthoc_unique_count,
    )

    print(
        "REPORT_FINDINGS =",
        len(findings),
    )

    if (
        opengrep_count > 0
        or iris_posthoc_unique_count > 0
    ) and len(findings) == 0:
        raise RuntimeError(
            "Final report lost analyzer findings: "
            f"OpenGrep={opengrep_count}, "
            f"IRIS_unique={iris_posthoc_unique_count}, "
            "report=0"
        )

    if (
        iris_posthoc_surviving_raw
        > iris_posthoc_container_count
    ):
        raise RuntimeError(
            "Invalid IRIS posthoc diagnostic: "
            "surviving result count exceeds "
            "container count"
        )

    if (
        iris_posthoc_unique_count
        > iris_posthoc_surviving_raw
    ):
        raise RuntimeError(
            "Invalid IRIS posthoc diagnostic: "
            "unique finding count exceeds "
            "surviving raw count"
        )

    print("REPORT_UNION_CONTRACT=PASS")

def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "One-command OpenGrep + IRIS + "
            "local LLM Stage 1-9 runner"
        )
    )

    parser.add_argument(
        "project",
        help=(
            "Folder name under "
            "data/project-sources/"
        ),
    )

    parser.add_argument(
        "--queries",
        nargs="+",
        default=["all"],
        help=(
            "IRIS queries, or 'all'. "
            "Default: all supported queries"
        ),
    )

    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
    )

    parser.add_argument(
        "--dispatch-mode",
        choices=[
            "configured",
            "hybrid",
        ],
        default="hybrid",
    )

    parser.add_argument(
        "--run-tag",
        default=None,
        help=(
            "Optional output run tag. "
            "Default: timestamped full run"
        ),
    )

    parser.add_argument(
        "--build-command",
        default=None,
        help=(
            "Override CodeQL build command "
            "for unusual Java projects"
        ),
    )

    parser.add_argument(
        "--java-home",
        default=None,
        help=(
            "Override JAVA_HOME for project build. "
            "Normally auto-detected."
        ),
    )

    parser.add_argument(
        "--opengrep-variant",
        choices=[
            "historical",
            "pinned-20260929",
        ],
        default="pinned-20260929",
        help=(
            "OpenGrep ruleset variant. "
            "'historical' preserves registry alias p/java; "
            "'pinned-20260929' uses the locally vendored "
            "immutable ruleset."
        ),
    )

    parser.add_argument(
        "--no-git-ignore",
        action="store_true",
        help=(
            "Pass --no-git-ignore to OpenGrep. "
            "Use only when required."
        ),
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Generate and validate configuration "
            "without executing OpenGrep/IRIS"
        ),
    )

    return parser.parse_args()


def main():
    args = parse_args()

    # LOCAL_ONLY_MODEL_GUARD
    # This project intentionally uses only local Ollama models.
    # Abort before OpenGrep/IRIS execution if a cloud/backend alias
    # is supplied accidentally.
    requested_model = str(args.model).strip()

    if not requested_model.lower().startswith("ollama-"):
        raise RuntimeError(
            "LOCAL_ONLY_MODEL_GUARD: refusing non-Ollama model "
            f"{requested_model!r}. "
            "Use a local ollama-* model."
        )

    validate_project_name(args.project)

    project = args.project
    source = (
        SOURCE_ROOT
        / project
    ).resolve()

    if not source.is_dir():
        raise FileNotFoundError(
            "Project source directory not found:\n"
            f"{source}"
        )

    queries = args.queries

    if queries == ["all"]:
        queries = list(ALL_QUERIES)

    invalid = [
        q
        for q in queries
        if q not in ALL_QUERIES
    ]

    if invalid:
        raise ValueError(
            f"Unsupported query/queries: {invalid}"
        )

    opengrep = find_executable(
        [
            os.environ.get("OPENGREP"),
            (
                Path.home()
                / ".opengrep/cli/v1.25.0/opengrep"
            ),
            "opengrep",
        ],
        "OpenGrep",
    )

    codeql = find_executable(
        [
            os.environ.get("CODEQL"),
            ROOT / "codeql/codeql",
            "codeql",
        ],
        "CodeQL",
    )

    ollama = find_executable(
        [
            os.environ.get("OLLAMA"),
            "ollama",
        ],
        "Ollama",
    )

    # OPENGREP_PINNED_VARIANT_V1
    if args.opengrep_variant == "historical":
        opengrep_config = "p/java"
        opengrep_extra_args = []
    else:
        pinned_rules = (
            INTEGRATION
            / "rules"
            / "opengrep"
            / "p-java-pinned-20260929"
            / "5e652fa9ac09c9fac36bbadc3562a0c8eed1a47438a9d1f545e021ae3c5648b1"
            / "p-java.yaml"
        ).resolve()

        if not pinned_rules.is_file():
            raise FileNotFoundError(
                "Pinned OpenGrep ruleset missing: "
                f"{pinned_rules}"
            )

        opengrep_config = str(
            pinned_rules
        )

        # Required for exact compatibility with the historical
        # registry-origin rule IDs when this same ruleset is
        # loaded from an explicit local file.
        opengrep_extra_args = [
            "--no-rewrite-rule-ids"
        ]

    print("===== PROJECT =====")
    print("PROJECT =", project)
    print("SOURCE  =", source)
    print("QUERIES =", queries)
    print("MODEL   =", args.model)
    print("MODE    =", args.dispatch_mode)
    print(
        "OPENGREP_VARIANT =",
        args.opengrep_variant,
    )
    print(
        "OPENGREP_CONFIG  =",
        opengrep_config,
    )

    print()
    print("===== TOOLS =====")
    print("OPENGREP =", opengrep)
    print("CODEQL   =", codeql)
    print("OLLAMA   =", ollama)

    print()
    print("===== OLLAMA =====")

    ollama_result = run(
        [ollama, "list"],
        capture=True,
    )

    print(ollama_result.stdout.strip())

    db = DB_ROOT / project
    package_file = (
        PACKAGE_ROOT
        / f"{project}.txt"
    )

    if args.dry_run:
        print()
        print("===== DRY RUN PREREQUISITES =====")
        print(
            "CODEQL_DB_READY =",
            validate_database(
                codeql,
                db,
            ),
        )
        print(
            "PACKAGE_FILE_EXISTS =",
            package_file.is_file(),
        )
    else:
        prepare_database(
            project=project,
            source=source,
            codeql=codeql,
            explicit_build_command=args.build_command,
            java_home_override=args.java_home,
        )

        prepare_package_file(
            project=project,
            source=source,
        )

    stamp = dt.datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    run_tag = (
        args.run_tag
        if args.run_tag
        else f"full_{stamp}_{os.getpid()}"
    )

    config_path, run_id = build_config(
        project=project,
        source=source,
        opengrep=opengrep,
        opengrep_config=opengrep_config,
        opengrep_extra_args=opengrep_extra_args,
        queries=queries,
        model=args.model,
        dispatch_mode=args.dispatch_mode,
        run_tag=run_tag,
        no_git_ignore=args.no_git_ignore,
    )

    print()
    print("===== GENERATED RUN =====")
    print("CONFIG =", config_path)
    print("RUN_ID =", run_id)

    if args.dry_run:
        print()
        print("DRY_RUN=PASS")
        return 0

    print()
    print("===== FULL PIPELINE =====")

    run(
        [
            sys.executable,
            "main.py",
            "--config",
            str(config_path),
            "--verbose",
        ],
        cwd=INTEGRATION,
    )

    jobs_file = (
        INTEGRATION
        / "generated"
        / project
        / run_tag
        / "iris_jobs.json"
    )

    opengrep_sarif = (
        INTEGRATION
        / "generated"
        / project
        / run_tag
        / "opengrep.sarif"
    )

    normalized = (
        INTEGRATION
        / "generated"
        / project
        / run_tag
        / "normalized_findings.json"
    )

    for path in (
        opengrep_sarif,
        normalized,
        jobs_file,
    ):
        if not path.is_file():
            raise RuntimeError(
                f"Missing integration artifact: {path}"
            )

        print("PASS:", path)

    verify_stage_contracts(
        project=project,
        run_id=run_id,
        jobs_file=jobs_file,
    )

    verify_report_contract(
        project=project,
        run_id=run_id,
        run_tag=run_tag,
        jobs_file=jobs_file,
    )

    print()
    print("=" * 72)
    print("FULL PROJECT RUN PASS")
    print("=" * 72)
    print("PROJECT =", project)
    print("RUN_ID  =", run_id)
    print("CONFIG  =", config_path)
    print(
        "OUTPUT  =",
        ROOT / "output" / project / run_id,
    )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        raise SystemExit(130)
    except Exception as exc:
        print()
        print("=" * 72)
        print("FULL PROJECT RUN FAILED")
        print("=" * 72)
        print(type(exc).__name__ + ":", exc)
        raise SystemExit(1)
