"""B34R2: explicit, fail-closed CodeQL pre-finalize policy for a Java-only demo.

The real Java extractor still traces javac and must emit a nonempty database.
CodeQL's Java pre-finalize also invokes XML extraction, which is not required
for this fixture containing only .java sources and no XML/properties resources.
This exception is NOT suitable for a real Maven/Spring application.
"""
from __future__ import annotations
from pathlib import Path
from ntk_b33.common import Blocker, sha_file

REQUIRED_FILES = frozenset({
    'build.sh', 'expectations.json', 'opengrep_demo_rules.yml',
    'src/ntk/b34/Case01.java', 'src/ntk/b34/Case02.java',
    'src/ntk/b34/Case03.java', 'src/ntk/b34/Case04.java',
})
MODE = 'NO_PRE_FINALIZE_JDK_ONLY_FIXTURE'


def validate_java_only_fixture(root: Path) -> dict:
    """Refuse bypass if even one unexpected file is present or source is missing."""
    if not root.is_dir() or root.is_symlink():
        raise Blocker('NO_PRE_FINALIZE_INVALID_FIXTURE_ROOT')
    observed = {}
    for path in root.rglob('*'):
        if path.is_symlink():
            raise Blocker('NO_PRE_FINALIZE_SYMLINK_IN_FIXTURE: ' + str(path))
        if not path.is_file():
            if not path.is_dir():
                raise Blocker('NO_PRE_FINALIZE_SPECIAL_FILE_IN_FIXTURE: '+str(path))
            continue
        observed[str(path.relative_to(root))] = sha_file(path)
    if set(observed) != REQUIRED_FILES:
        extra = sorted(set(observed) - REQUIRED_FILES)
        missing = sorted(REQUIRED_FILES - set(observed))
        raise Blocker('NO_PRE_FINALIZE_REQUIRES_EXACT_SEVEN_INPUTS: '
                      + 'extra=' + repr(extra) + ', missing=' + repr(missing))
    return {
        'mode': MODE,
        'cli_option': '--no-pre-finalize',
        'scope': 'FOUR_FILE_JDK_ONLY_JAVA_FIXTURE_NO_XML_OR_PROPERTIES_RESOURCES',
        'java_extractor_still_required': True,
        'java_compiler_tracing_still_required': True,
        'codeql_database_must_be_created_and_queried': True,
        'general_jvm_projects_supported': False,
        'reason': 'JAVA_EXTRACTOR_PRE_FINALIZE_INVOKES_OPTIONAL_XML_INDEXING_BUT_NO_XML_INPUTS',
        'input_sha256': dict(sorted(observed.items())),
    }


def database_create_argv(codeql, db, source_root, build_command, cachearg,
                         extractor_options, resources, policy):
    if policy.get('mode') != MODE or policy.get('cli_option') != '--no-pre-finalize':
        raise Blocker('INVALID_NO_PRE_FINALIZE_POLICY')
    return [codeql, 'database', 'create', db, '--language=java',
            '--source-root='+str(source_root), '--command='+build_command,
            '--no-pre-finalize', cachearg, *extractor_options, *resources]
