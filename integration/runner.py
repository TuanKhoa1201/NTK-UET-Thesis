"""
runner.py

Execute OpenGrep and IRIS.
"""

import json
import os
import subprocess
from pathlib import Path

from logger import Logger

log = Logger()

# ==========================================================
# Project paths
# ==========================================================

# integration/
INTEGRATION_DIR = Path(__file__).resolve().parent

# iris/
PROJECT_ROOT = INTEGRATION_DIR.parent


# ==========================================================
# Helpers
# ==========================================================

def run_command(cmd, cwd=None, env=None):
    """
    Execute a shell command.
    """

    log.command(" ".join(map(str, cmd)))

    result = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode})"
        )

    return result


# ==========================================================
# STEP 1
# OpenGrep
# ==========================================================


# OPENGREP_EXACT_RESULT_CACHE_V1
#
# Exact raw-SARIF cache for local immutable OpenGrep rule files.
# Registry aliases such as p/java are intentionally not cache eligible.

OPENGREP_EXACT_CACHE_SCHEMA = (
    "OPENGREP_EXACT_RESULT_CACHE_V1"
)


def _sha256_file(path):
    import hashlib

    h = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)

            if not chunk:
                break

            h.update(chunk)

    return h.hexdigest()


def _sha256_bytes(data):
    import hashlib

    return hashlib.sha256(
        data
    ).hexdigest()


def _source_tree_identity(root):
    import hashlib

    root = Path(root).resolve()

    h = hashlib.sha256()

    file_count = 0
    symlink_count = 0

    for path in sorted(
        root.rglob("*"),
        key=lambda x: x.as_posix(),
    ):
        rel = path.relative_to(
            root
        )

        # Git internals are represented separately below.
        if ".git" in rel.parts:
            continue

        rel_text = rel.as_posix()

        if path.is_symlink():
            target = os.readlink(path)

            h.update(
                b"L\0"
                + rel_text.encode("utf-8")
                + b"\0"
                + target.encode("utf-8")
                + b"\0"
            )

            symlink_count += 1
            continue

        if not path.is_file():
            continue

        data = path.read_bytes()

        h.update(
            b"F\0"
            + rel_text.encode("utf-8")
            + b"\0"
            + hashlib.sha256(
                data
            ).digest()
            + b"\0"
        )

        file_count += 1

    return {
        "sha256": h.hexdigest(),
        "file_count": file_count,
        "symlink_count": symlink_count,
    }


def _git_capture(root, args):
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            *args,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    return result


def _git_identity(root):
    root = Path(root).resolve()

    probe = _git_capture(
        root,
        [
            "rev-parse",
            "--show-toplevel",
        ],
    )

    if probe.returncode != 0:
        return {
            "is_repository": False,
        }

    git_root = Path(
        probe.stdout.decode(
            "utf-8",
            errors="replace",
        ).strip()
    ).resolve()

    try:
        relative_root = root.relative_to(
            git_root
        )
    except ValueError:
        return {
            "is_repository": False,
        }

    if relative_root == Path("."):
        pathspec = "."
    else:
        pathspec = relative_root.as_posix()

    # ------------------------------------------------------
    # Scope committed identity to this project subtree.
    #
    # If the project lives inside a larger parent repository,
    # unrelated commits elsewhere in that repository must not
    # invalidate the OpenGrep exact-result cache.
    # ------------------------------------------------------

    if pathspec == ".":
        head_args = [
            "rev-parse",
            "HEAD^{tree}",
        ]
    else:
        head_args = [
            "rev-parse",
            f"HEAD:{pathspec}",
        ]

    head = _git_capture(
        git_root,
        head_args,
    )

    # ------------------------------------------------------
    # Scope index/status to the source project only.
    #
    # Previously these commands described the entire Git
    # repository. For fixtures under ~/iris this meant that
    # newly generated integration/temp/report files changed
    # the cache fingerprint even when source code was
    # completely unchanged.
    # ------------------------------------------------------

    index = _git_capture(
        git_root,
        [
            "ls-files",
            "--stage",
            "-z",
            "--",
            pathspec,
        ],
    )

    status = _git_capture(
        git_root,
        [
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--",
            pathspec,
        ],
    )

    if index.returncode != 0:
        raise RuntimeError(
            "Could not fingerprint project-scoped "
            "Git index for OpenGrep exact cache: "
            + index.stderr.decode(
                "utf-8",
                errors="replace",
            )
        )

    if status.returncode != 0:
        raise RuntimeError(
            "Could not fingerprint project-scoped "
            "Git working tree for OpenGrep exact cache: "
            + status.stderr.decode(
                "utf-8",
                errors="replace",
            )
        )

    head_text = None

    if head.returncode == 0:
        head_text = head.stdout.decode(
            "utf-8",
            errors="replace",
        ).strip()

    return {
        "is_repository": True,
        "root": str(git_root),
        "project_subpath": pathspec,
        "head": head_text,
        "index_sha256":
            _sha256_bytes(
                index.stdout
            ),
        "status_sha256":
            _sha256_bytes(
                status.stdout
            ),
    }


def _resolve_opengrep_executable(value):
    import shutil

    raw = str(value)

    candidate = Path(
        raw
    ).expanduser()

    if (
        candidate.is_absolute()
        or candidate.parent
        != Path(".")
    ):
        resolved = candidate.resolve()

        if not resolved.is_file():
            raise FileNotFoundError(
                f"OpenGrep executable not found: {resolved}"
            )

        return resolved

    found = shutil.which(raw)

    if not found:
        raise FileNotFoundError(
            f"OpenGrep executable not found: {raw}"
        )

    return Path(found).resolve()


def _opengrep_version(executable):
    result = subprocess.run(
        [
            str(executable),
            "--version",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Could not obtain OpenGrep version"
        )

    return result.stdout.strip()


def _validate_opengrep_sarif(path):
    path = Path(path)

    if not path.is_file():
        return None

    try:
        data = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except Exception:
        return None

    if not isinstance(
        data,
        dict,
    ):
        return None

    runs = data.get(
        "runs"
    )

    if (
        not isinstance(
            runs,
            list,
        )
        or not runs
    ):
        return None

    result_count = 0
    rule_count = 0

    for run in runs:
        if not isinstance(
            run,
            dict,
        ):
            return None

        results = run.get(
            "results",
            [],
        )

        if not isinstance(
            results,
            list,
        ):
            return None

        result_count += len(
            results
        )

        tool = run.get(
            "tool",
            {},
        )

        if not isinstance(
            tool,
            dict,
        ):
            return None

        driver = tool.get(
            "driver",
            {},
        )

        if not isinstance(
            driver,
            dict,
        ):
            return None

        rules = driver.get(
            "rules",
            [],
        )

        if not isinstance(
            rules,
            list,
        ):
            return None

        rule_count += len(
            rules
        )

    return {
        "result_count":
            result_count,
        "rule_count":
            rule_count,
    }


def _opengrep_cache_root():
    raw = os.environ.get(
        "IRIS_OPENGREP_EXACT_CACHE_DIR"
    )

    if raw:
        return Path(
            raw
        ).expanduser().resolve()

    return (
        Path.home()
        / ".cache"
        / "iris"
        / "opengrep-exact-v1"
    ).resolve()


def _opengrep_cache_context(
    cfg,
    project,
    extra_args,
):
    import hashlib

    config_raw = str(
        cfg.opengrep["config"]
    )

    config_path = Path(
        config_raw
    ).expanduser()

    if not config_path.is_absolute():
        config_path = (
            Path.cwd()
            / config_path
        ).resolve()
    else:
        config_path = (
            config_path.resolve()
        )

    # Registry aliases such as p/java arrive here as a non-existent
    # local path and deliberately bypass the exact cache.
    if not config_path.is_file():
        return None

    executable = (
        _resolve_opengrep_executable(
            cfg.opengrep.get(
                "executable",
                "opengrep",
            )
        )
    )

    environment = {
        key: os.environ[key]
        for key in sorted(
            os.environ
        )
        if (
            key.startswith(
                "OPENGREP_"
            )
            or key.startswith(
                "SEMGREP_"
            )
            or key
            in {
                "LANG",
                "LC_ALL",
                "LC_CTYPE",
            }
        )
    }

    identity = {
        "schema":
            OPENGREP_EXACT_CACHE_SCHEMA,

        "executable": {
            "path":
                str(executable),

            "sha256":
                _sha256_file(
                    executable
                ),

            "version":
                _opengrep_version(
                    executable
                ),
        },

        "config": {
            "path":
                str(config_path),

            "sha256":
                _sha256_file(
                    config_path
                ),
        },

        "source": {
            "root":
                str(
                    Path(
                        project
                    ).resolve()
                ),

            "tree":
                _source_tree_identity(
                    project
                ),

            "git":
                _git_identity(
                    project
                ),
        },

        "extra_args": [
            str(x)
            for x in extra_args
        ],

        "execution_cwd":
            str(
                Path.cwd().resolve()
            ),

        "output_mode":
            "sarif",

        "environment":
            environment,
    }

    payload = json.dumps(
        identity,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    fingerprint = hashlib.sha256(
        payload
    ).hexdigest()

    root = (
        _opengrep_cache_root()
    )

    entry = (
        root
        / fingerprint[:2]
        / fingerprint
    )

    return {
        "root": root,
        "entry": entry,
        "fingerprint":
            fingerprint,
        "identity":
            identity,
    }


def _opengrep_cache_entry_valid(
    context,
):
    entry = context[
        "entry"
    ]

    manifest_path = (
        entry
        / "manifest.json"
    )

    sarif_path = (
        entry
        / "opengrep.sarif"
    )

    if (
        not manifest_path.is_file()
        or not sarif_path.is_file()
    ):
        return False

    try:
        manifest = json.loads(
            manifest_path.read_text(
                encoding="utf-8"
            )
        )
    except Exception:
        return False

    if (
        manifest.get("schema")
        != OPENGREP_EXACT_CACHE_SCHEMA
    ):
        return False

    if (
        manifest.get(
            "fingerprint"
        )
        != context[
            "fingerprint"
        ]
    ):
        return False

    if (
        manifest.get(
            "identity"
        )
        != context[
            "identity"
        ]
    ):
        return False

    artifact = manifest.get(
        "artifact"
    )

    if not isinstance(
        artifact,
        dict,
    ):
        return False

    try:
        expected_size = int(
            artifact[
                "size"
            ]
        )
    except Exception:
        return False

    if (
        sarif_path.stat().st_size
        != expected_size
    ):
        return False

    if (
        _sha256_file(
            sarif_path
        )
        != artifact.get(
            "sha256"
        )
    ):
        return False

    info = (
        _validate_opengrep_sarif(
            sarif_path
        )
    )

    if info is None:
        return False

    if (
        info[
            "result_count"
        ]
        != artifact.get(
            "result_count"
        )
    ):
        return False

    if (
        info[
            "rule_count"
        ]
        != artifact.get(
            "rule_count"
        )
    ):
        return False

    return True


def _remove_cache_entry_guarded(
    path,
    root,
):
    import shutil

    path = Path(path)
    root = Path(root).resolve()

    if not path.exists():
        return

    resolved = path.resolve()

    if (
        resolved == root
        or root
        not in resolved.parents
    ):
        raise RuntimeError(
            "Refusing unsafe OpenGrep "
            f"cache deletion: {resolved}"
        )

    if path.is_dir():
        shutil.rmtree(
            path
        )
    else:
        path.unlink()


def _restore_opengrep_cache(
    context,
    output,
):
    import shutil
    import tempfile

    if not (
        _opengrep_cache_entry_valid(
            context
        )
    ):
        return False

    cached = (
        context[
            "entry"
        ]
        / "opengrep.sarif"
    )

    output = Path(
        output
    )

    fd, tmp_name = (
        tempfile.mkstemp(
            prefix=
                ".opengrep-cache-",
            suffix=".sarif.tmp",
            dir=str(
                output.parent
            ),
        )
    )

    os.close(fd)

    tmp = Path(
        tmp_name
    )

    try:
        shutil.copyfile(
            cached,
            tmp,
        )

        os.replace(
            tmp,
            output,
        )

    finally:
        if tmp.exists():
            tmp.unlink()

    return True


def _store_opengrep_cache(
    context,
    output,
):
    import shutil
    import tempfile

    output = Path(
        output
    )

    info = (
        _validate_opengrep_sarif(
            output
        )
    )

    if info is None:
        raise RuntimeError(
            "OpenGrep produced an invalid "
            "SARIF artifact"
        )

    entry = context[
        "entry"
    ]

    root = context[
        "root"
    ]

    if entry.exists():
        if (
            _opengrep_cache_entry_valid(
                context
            )
        ):
            return

        _remove_cache_entry_guarded(
            entry,
            root,
        )

    entry.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    tmp_dir = Path(
        tempfile.mkdtemp(
            prefix=
                ".opengrep-cache-",
            dir=str(
                entry.parent
            ),
        )
    )

    try:
        cached_sarif = (
            tmp_dir
            / "opengrep.sarif"
        )

        shutil.copyfile(
            output,
            cached_sarif,
        )

        manifest = {
            "schema":
                OPENGREP_EXACT_CACHE_SCHEMA,

            "fingerprint":
                context[
                    "fingerprint"
                ],

            "identity":
                context[
                    "identity"
                ],

            "artifact": {
                "filename":
                    "opengrep.sarif",

                "sha256":
                    _sha256_file(
                        cached_sarif
                    ),

                "size":
                    cached_sarif.stat().st_size,

                "result_count":
                    info[
                        "result_count"
                    ],

                "rule_count":
                    info[
                        "rule_count"
                    ],
            },
        }

        (
            tmp_dir
            / "manifest.json"
        ).write_text(
            json.dumps(
                manifest,
                indent=2,
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        if entry.exists():
            if (
                _opengrep_cache_entry_valid(
                    context
                )
            ):
                return

            _remove_cache_entry_guarded(
                entry,
                root,
            )

        os.replace(
            tmp_dir,
            entry,
        )

    finally:
        if tmp_dir.exists():
            _remove_cache_entry_guarded(
                tmp_dir,
                root,
            )


def run_opengrep(cfg):

    project = Path(
        cfg.project["source"]
    ).resolve()

    if not project.exists():
        raise FileNotFoundError(
            f"Project not found: {project}"
        )

    output = (
        INTEGRATION_DIR
        / cfg.opengrep["output"]
    ).resolve()

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    extra_args = cfg.opengrep.get(
        "extra_args",
        [],
    )

    if not isinstance(
        extra_args,
        list,
    ):
        raise TypeError(
            "opengrep.extra_args must be a list"
        )

    cmd = [
        cfg.opengrep.get(
            "executable",
            "opengrep",
        ),
        *extra_args,
        "--config",
        cfg.opengrep["config"],
        str(project),
        "--sarif",
        "--output",
        str(output),
    ]

    log.start("OpenGrep")

    context = (
        _opengrep_cache_context(
            cfg,
            project,
            extra_args,
        )
    )

    if context is None:
        print(
            "OPENGREP_EXACT_CACHE_BYPASS="
            "NON_LOCAL_CONFIG"
        )

    else:
        fingerprint = context[
            "fingerprint"
        ]

        if (
            _restore_opengrep_cache(
                context,
                output,
            )
        ):
            print(
                "OPENGREP_EXACT_CACHE_HIT="
                f"{fingerprint}"
            )

            log.file(output)
            log.finish("OpenGrep")
            return

        if context[
            "entry"
        ].exists():
            print(
                "OPENGREP_EXACT_CACHE_CORRUPT="
                f"{fingerprint}"
            )

        print(
            "OPENGREP_EXACT_CACHE_MISS="
            f"{fingerprint}"
        )

    run_command(cmd)

    if context is not None:
        _store_opengrep_cache(
            context,
            output,
        )

        print(
            "OPENGREP_EXACT_CACHE_STORED="
            f"{context['fingerprint']}"
        )

    log.file(output)
    log.finish("OpenGrep")


# ==========================================================
# Load jobs
# ==========================================================

def load_jobs(cfg):

    jobs_file = (INTEGRATION_DIR / cfg.paths["iris_jobs"]).resolve()

    if not jobs_file.exists():
        raise FileNotFoundError(jobs_file)

    with open(jobs_file, "r", encoding="utf-8") as f:
        return json.load(f)


# ==========================================================
# STEP 4
# Run IRIS
# ==========================================================

def run_iris(cfg):

    jobs = load_jobs(cfg)

    total = len(jobs)

    success = 0
    failed = 0

    # ------------------------------------------------------
    # IRIS expects project NAME only
    # ------------------------------------------------------

    project_name = Path(cfg.project["source"]).name

    # ------------------------------------------------------
    # Build absolute path of src/iris.py
    # ------------------------------------------------------

    iris_script = (PROJECT_ROOT / cfg.iris["script"]).resolve()

    if not iris_script.exists():
        raise FileNotFoundError(
            f"Cannot find IRIS script:\n{iris_script}"
        )

    env = os.environ.copy()

    env["PYTHONPATH"] = str(PROJECT_ROOT / "src")

    log.start("IRIS")

    for index, job in enumerate(jobs, start=1):

        log.section(f"Job {index}/{total}")

        log.info(
            "Queries CWE : "
            + ", ".join(job.get("cwes", []))
        )

        log.info(
            f"IRIS Query  : {job['query']}"
        )

        cmd = [
            cfg.iris.get("executable", "python"),
            str(iris_script),
            "--query",
            job["query"],
            "--run-id",
            cfg.iris["run_id"],
            "--llm",
            cfg.iris["llm"],
        ]

        if cfg.iris.get("overwrite_llm_cache", False):
            cmd.append("--overwrite-llm-cache")

        if cfg.iris.get("overwrite_label_cache", False):
            cmd.extend([
                "--overwrite-labelled-apis",
                "--overwrite-labelled-func-param",
            ])

        cmd.append(project_name)

        try:

            run_command(
                cmd,
                cwd=str(PROJECT_ROOT),
                env=env,
            )

            success += 1

            log.success(
                f"{job['query']} finished"
            )

        except Exception as ex:

            failed += 1

            log.error(str(ex))

    log.section("IRIS Summary")

    log.info(f"Total Jobs : {total}")
    log.info(f"Success    : {success}")
    log.info(f"Failed     : {failed}")

    log.finish("IRIS")

    return {
        "total": total,
        "success": success,
        "failed": failed,
    }


# ==========================================================
# Standalone test
# ==========================================================

if __name__ == "__main__":

    from config import Config

    cfg = Config()

    run_opengrep(cfg)
