"""B34R3: fail-closed pinned local CodeQL-pack dependency resolution.

The 2.25.6 CLI does not resolve a locked query pack's dependencies through
--search-path. Do not install/update any QL pack or touch the user's ~/.codeql.
Stage byte-pinned libraries into the isolated run's --common-caches tree and
also pass explicit --additional-packs locations for locked resolution.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re

from ntk_b33.common import Blocker, sha_file, digest


def verify_and_options(pack_report: dict, pins_path: Path, *, run: Path,
                       common_caches: Path) -> tuple[list[str], dict]:
    pins = json.loads(pins_path.read_text(encoding='utf-8'))
    if not isinstance(pack_report, dict) or set(pack_report) != set(pins):
        raise Blocker('B34R3_PACK_SET_DIFFERS_FROM_OBSERVED_B34R2')
    if not pack_report or len(pack_report) != 16:
        raise Blocker('B34R3_PACK_COUNT_NOT_16')
    if common_caches.resolve() != (run.resolve()/'codeql-cache'):
        raise Blocker('B34R3_COMMON_CACHES_NOT_RUN_LOCAL')
    package_root = common_caches.resolve()/'packages'
    directories = []
    proven = {}
    for name in sorted(pins):
        if not re.fullmatch(r'codeql/[a-z][a-z0-9-]*', name):
            raise Blocker('B34R3_INVALID_PACK_NAME')
        expected = pins[name]
        actual = pack_report[name]
        version = expected['version']
        if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){2}', version):
            raise Blocker('B34R3_INVALID_PACK_VERSION')
        packpath = package_root / name / version
        if Path(actual['copy_path']).resolve() != packpath:
            raise Blocker('B34R3_PACK_COPY_NOT_INSIDE_LOCAL_CACHE: ' + name)
        if (actual['version'] != version or
                actual['fingerprint'] != expected['fingerprint'] or
                actual['files'].get('qlpack.yml') != expected['qlpack_sha256']):
            raise Blocker('B34R3_PINNED_PACK_FINGERPRINT_MISMATCH: ' + name)
        if not (packpath / 'qlpack.yml').is_file():
            raise Blocker('B34R3_MISSING_PACK_METADATA: ' + name)
        meta = (packpath / 'qlpack.yml').read_text(encoding='utf-8')
        if not re.search(r'^name:\s*["\']?' + re.escape(name) +
                         r'["\']?\s*$', meta, flags=re.MULTILINE):
            raise Blocker('B34R3_PACK_NAME_MISMATCH: ' + name)
        if not re.search(r'^version:\s*["\']?' + re.escape(version) +
                         r'["\']?\s*$', meta, flags=re.MULTILINE):
            raise Blocker('B34R3_PACK_VERSION_MISMATCH: ' + name)
        # Verify both the observed previous-run fingerprint and fresh bytes,
        # rather than trusting a directory naming convention.
        files = {str(p.relative_to(packpath)): sha_file(p)
                 for p in sorted(packpath.rglob('*')) if p.is_file()}
        if files != actual['files'] or digest(files) != expected['fingerprint']:
            raise Blocker('B34R3_LOCAL_PACK_BYTES_CHANGED: ' + name)
        directories.append(str(packpath))
        proven[name] = {'version': version,
                        'fingerprint': expected['fingerprint'],
                        'path': str(packpath)}
    if len(set(directories)) != len(directories):
        raise Blocker('B34R3_DUPLICATE_ADDITIONAL_PACK_PATH')
    # Each path is a *pack root* (contains qlpack.yml), not the nested
    # qlpacks/codeql/name/version parent tree that CodeQL cannot discover.
    option = '--additional-packs=' + os.pathsep.join(directories)
    return [option], {'mode': 'ISOLATED_CACHE_PLUS_ADDITIONAL_PACKS',
                      'pack_count': len(proven),
                      'observed_previous_run': 'B34R2_USER_UPLOADED_QLPACK_MANIFEST',
                      'cache_root': str(common_caches), 'packs': proven,
                      'codeql_pack_install_executed': False,
                      'query_lock_file_modified': False}
