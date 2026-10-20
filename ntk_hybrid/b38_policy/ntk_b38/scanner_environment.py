"""Private, validated runtime directories for the pinned local scanner.

OpenGrep 1.25.0 checks XDG_CONFIG_HOME with Sys.is_directory at startup.
A declared but absent directory raises before rules are processed. Do not
work around that by leaking the user's real HOME/configuration to a scan.
"""
from __future__ import annotations
import os
from pathlib import Path
import stat
import tempfile
from ntk_b33.common import Blocker, write_json

ENVIRONMENT_REVISION = 'B38R1_PRIVATE_SCANNER_DIRS_V1'
PRIVATE_NAMES = ('.config', '.cache', '.tmp', '.state', '.semgrep', '.config/.semgrep')


def _private_directory(path: Path, root: Path) -> dict:
    try:
        if path.is_symlink():
            raise Blocker('SCANNER_RUNTIME_DIRECTORY_IS_SYMLINK: ' + str(path))
        path.mkdir(mode=0o700, parents=False, exist_ok=True)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise Blocker('SCANNER_RUNTIME_PATH_NOT_DIRECTORY: ' + str(path))
        if not path.resolve().is_relative_to(root):
            raise Blocker('SCANNER_RUNTIME_DIRECTORY_OUTSIDE_WORK: ' + str(path))
        if info.st_uid != os.geteuid():
            raise Blocker('SCANNER_RUNTIME_DIRECTORY_WRONG_OWNER: ' + str(path))
        path.chmod(0o700)
        # Probe actual writes, not merely os.access (which can mislead as root).
        fd, name = tempfile.mkstemp(prefix='.ntk-write-probe-', dir=str(path))
        try:
            os.write(fd, b'private scanner runtime directory\n')
        finally:
            os.close(fd)
            os.unlink(name)
        return {'path': str(path), 'directory': True, 'symlink': False,
                'mode': oct(stat.S_IMODE(path.stat().st_mode)),
                'write_probe': 'PASS', 'inside_scan_workspace': True}
    except Blocker:
        raise
    except OSError as exc:
        raise Blocker('SCANNER_RUNTIME_DIRECTORY_NOT_READY: ' + str(path) + ': ' + str(exc)) from exc


def prepare_environment(work: Path) -> tuple[dict[str, str], dict]:
    """Create every configured HOME/XDG/TMP directory before starting scanner."""
    work = Path(work).absolute()
    if work.is_symlink() or not work.is_dir():
        raise Blocker('SCANNER_WORK_DIRECTORY_INVALID: ' + str(work))
    # The parent is a trusted per-run workspace, never the uploaded project.
    root = work.resolve()
    directories = [_private_directory(root, root)]
    for relative in PRIVATE_NAMES:
        directories.append(_private_directory(root / relative, root))
    env = {key: os.environ[key] for key in ('PATH', 'LD_LIBRARY_PATH') if key in os.environ}
    env.setdefault('PATH', '/usr/bin:/bin')
    env.update({
        'HOME': str(root),
        'XDG_CONFIG_HOME': str(root / '.config'),
        'XDG_CACHE_HOME': str(root / '.cache'),
        'XDG_STATE_HOME': str(root / '.state'),
        'TMPDIR': str(root / '.tmp'),
        'TMP': str(root / '.tmp'),
        'TEMP': str(root / '.tmp'),
        'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'SEMGREP_SEND_METRICS': 'off', 'OPENGREP_SEND_METRICS': 'off',
        'SEMGREP_ENABLE_VERSION_CHECK': '0', 'OPENGREP_ENABLE_VERSION_CHECK': '0',
        'PYTHONDONTWRITEBYTECODE': '1',
    })
    # Store only non-secret runtime settings; never dump the ambient environment.
    proof = {
        'revision': ENVIRONMENT_REVISION,
        'status': 'DIRECTORIES_CREATED_AND_WRITE_TESTED_BEFORE_EXEC',
        'configuration': {key: env[key] for key in (
            'HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME', 'TMPDIR', 'TMP', 'TEMP')},
        'directories': directories,
        'ambient_home_config_credentials_not_inherited': True,
        'network_isolation': 'SEPARATE_INHERITED_SECCOMP_PROOF_REQUIRED',
    }
    write_json(root / 'ENVIRONMENT_PROOF.json', proof)
    return env, proof
