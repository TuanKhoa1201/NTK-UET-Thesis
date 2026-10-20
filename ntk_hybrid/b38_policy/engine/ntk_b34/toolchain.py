"""B34R1: resolve Java before DB creation; recover a pinned CLI outside IRIS.

No model/source/log uploads. Downloading a public tool is opt-in. The query
packs are NOT upgraded by this module. Each command produces local evidence.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from ntk_b33.common import Blocker, sha_file, write_json

VERSION = '2.25.6'
ASSET_URL = 'https://github.com/github/codeql-cli-binaries/releases/download/v2.25.6/codeql-linux64.zip'
ASSET_SHA = 'd7108fe3ab439267f2dbadd5462096aa190c6258e06d90004faef04d65bf4281'
ASSET_SIZE = 539477738
ASSET_METADATA_URL = 'https://api.github.com/repos/github/codeql-cli-binaries/releases/assets/433022414'
ALLOWED_DOWNLOAD_HOSTS = {'github.com', 'release-assets.githubusercontent.com',
                          'objects.githubusercontent.com'}
MAX_UNPACKED = 8 * 1024**3


@dataclass(frozen=True)
class SelectedToolchain:
    executable: Path
    extractor: Path
    mode: str
    archive_sha256: str | None = None

    @property
    def database_options(self) -> list[str]:
        # Extractor search path is separate from the QL library search path.
        return ['--search-path=' + str(self.extractor)]


def allowed_download_url(url: str) -> bool:
    p = urllib.parse.urlparse(url)
    return (p.scheme == 'https' and p.hostname in ALLOWED_DOWNLOAD_HOSTS
            and p.username is None and p.password is None and p.port in (None, 443))


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed_download_url(newurl):
            raise Blocker('CODEQL_DOWNLOAD_REDIRECT_REJECTED')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def probe_command(argv: list, base: Path, *, cwd: Path, timeout: int = 90) -> tuple[int, str]:
    """Separate stdout/stderr; never confuse diagnostic text with JSON."""
    base.parent.mkdir(parents=True, exist_ok=True)
    args = list(map(str, argv))
    write_json(base.with_suffix('.command.json'),
               {'argv': args, 'cwd': str(cwd), 'timeout_seconds': timeout})
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0', PYTHONDONTWRITEBYTECODE='1')
    with base.with_suffix('.stdout.log').open('w') as out, base.with_suffix('.stderr.log').open('w') as err:
        p = subprocess.Popen(args, cwd=cwd, env=env, stdout=out, stderr=err,
                             start_new_session=True)
        try:
            rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
            rc = 124
    text = base.with_suffix('.stdout.log').read_text(errors='replace')
    write_json(base.with_suffix('.result.json'), {'returncode': rc})
    return rc, text


def parse_extractor_path(text: str) -> Path:
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, TypeError) as exc:
        raise Blocker('EXTRACTOR_RESOLVE_INVALID_JSON') from exc
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        raise Blocker('EXTRACTOR_RESOLVE_NOT_ONE_ABSOLUTE_PATH')
    return Path(value).resolve(strict=True)


def probe_java(executable: Path, run: Path, label: str,
               search_path: Path | None = None) -> tuple[SelectedToolchain | None, dict]:
    base = run/'toolchain_probe'/label
    report = {'executable': str(executable), 'search_path': str(search_path) if search_path else None}
    try:
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise Blocker('CODEQL_NOT_EXECUTABLE')
        cachearg = '--common-caches=' + str(run/'codeql-cache')
        rc, text = probe_command([executable, 'version', cachearg], base/'VERSION', cwd=run)
        if rc or not re.search(r'\brelease\s+' + re.escape(VERSION) + r'(?:\.(?=\s|$)|(?=\s|$))', text):
            raise Blocker('CODEQL_EXPECTED_EXACT_VERSION_2_25_6')
        options = [cachearg]
        if search_path is not None:
            options.append('--search-path=' + str(search_path))
        lrc, _ = probe_command([executable, 'resolve', 'languages', '--format=json', *options],
                               base/'LANGUAGES', cwd=run)
        report['languages_returncode'] = lrc
        rc, text = probe_command([executable, 'resolve', 'extractor', '--language=java',
                                  '--format=json', *options], base/'JAVA_EXTRACTOR', cwd=run)
        if rc:
            raise Blocker('JAVA_EXTRACTOR_UNRESOLVED_EXIT_' + str(rc))
        root = parse_extractor_path(text)
        metadata = root/'codeql-extractor.yml'
        if not metadata.is_file() or not (root/'tools').is_dir():
            raise Blocker('RESOLVED_JAVA_EXTRACTOR_INCOMPLETE_LAYOUT')
        if not re.search(r'^name:\s*[\"\x27]?java[\"\x27]?\s*$', metadata.read_text(), re.M):
            raise Blocker('RESOLVED_EXTRACTOR_METADATA_NOT_JAVA')
        # Pin the exact selected directory in database create, rather than
        # depending on implicit discovery a second time.
        report.update({'status': 'RESOLVED_NOT_YET_DATABASE_PROVEN',
                       'extractor_root': str(root),
                       'extractor_metadata_sha256': sha_file(metadata),
                       'launcher_sha256': sha_file(executable),
                       'database_search_path': str(root)})
        return SelectedToolchain(executable, root, label), report
    except (OSError, ValueError, Blocker) as exc:
        report.update({'status': 'UNAVAILABLE', 'reason': str(exc)})
        return None, report


def check_archive(path: Path, expected_sha: str = ASSET_SHA,
                  expected_size: int = ASSET_SIZE) -> None:
    if not path.is_file() or path.stat().st_size != expected_size:
        raise Blocker('CODEQL_ARCHIVE_MISSING_OR_SIZE_MISMATCH: ' + str(path))
    if sha_file(path) != expected_sha:
        raise Blocker('CODEQL_ARCHIVE_SHA256_MISMATCH: ' + str(path))


def download_official(destination: Path, run: Path) -> None:
    """GET only, constant public URL, TLS verified, no GitHub/HF tokens."""
    if destination.exists():
        raise Blocker('REFUSE_OVERWRITE_EXISTING_CODEQL_DOWNLOAD')
    destination.parent.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(destination.parent).free < ASSET_SIZE + 256*1024**2:
        raise Blocker('INSUFFICIENT_DISK_FOR_CODEQL_DOWNLOAD')
    write_json(run/'CODEQL_DOWNLOAD_REQUEST.json', {
        'url': ASSET_URL, 'method': 'GET', 'expected_size': ASSET_SIZE,
        'expected_sha256': ASSET_SHA, 'credentials': 'NONE',
        'source_or_model_upload': False, 'tls_verification': True})
    fd, tmpname = tempfile.mkstemp(prefix='codeql-download-', suffix='.part', dir=destination.parent)
    os.close(fd)
    tmp = Path(tmpname)
    try:
        opener = urllib.request.build_opener(SafeRedirect())
        request = urllib.request.Request(ASSET_URL, headers={'User-Agent': 'NTK-B34R1-tool-recovery'})
        count, next_progress, h = 0, 64*1024**2, hashlib.sha256()
        print('B34R1: downloading pinned PUBLIC CodeQL tool; no project upload.', flush=True)
        with opener.open(request, timeout=90) as response, tmp.open('wb') as out:
            if not allowed_download_url(response.geturl()):
                raise Blocker('CODEQL_DOWNLOAD_FINAL_HOST_REJECTED')
            while True:
                block = response.read(1024*1024)
                if not block:
                    break
                count += len(block)
                if count > ASSET_SIZE:
                    raise Blocker('CODEQL_DOWNLOAD_OVERSIZE')
                h.update(block)
                out.write(block)
                if count >= next_progress:
                    print('CODEQL_DOWNLOAD_BYTES=%d/%d' % (count, ASSET_SIZE), flush=True)
                    next_progress += 64*1024**2
        if count != ASSET_SIZE or h.hexdigest() != ASSET_SHA:
            raise Blocker('CODEQL_DOWNLOAD_SIZE_OR_SHA256_MISMATCH')
        if destination.exists():
            raise Blocker('CODEQL_DOWNLOAD_DESTINATION_CREATED_CONCURRENTLY')
        # Atomic no-overwrite publication on the same filesystem.
        os.link(tmp, destination)
        write_json(run/'CODEQL_DOWNLOAD_VERIFIED.json', {
            'bytes': count, 'sha256': h.hexdigest(), 'path': str(destination)})
    except (OSError, urllib.error.URLError) as exc:
        # Keep credentials, redirect signed URLs and proxy details out of reports.
        raise Blocker('CODEQL_PUBLIC_DOWNLOAD_FAILED: ' + type(exc).__name__ +
                      '; use --codeql-archive with the pinned ZIP for offline recovery') from None
    finally:
        tmp.unlink(missing_ok=True)


def safe_unpack(archive: Path, destination: Path, *, max_size: int = MAX_UNPACKED) -> dict:
    """Preserve POSIX executable bits and safe in-tree symlinks from official ZIP.

    The caller must verify archive SHA first. No extractall permission loss, no
    writing through symlink parents, no overwriting an existing directory.
    """
    if destination.exists():
        raise Blocker('REFUSE_OVERWRITE_TOOLCHAIN_DIRECTORY')
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        total = sum(i.file_size for i in infos)
        if total > max_size or len(infos) > 100000:
            raise Blocker('CODEQL_UNPACK_SIZE_GUARD')
        seen, links, regular = set(), {}, []
        for i in infos:
            p = PurePosixPath(i.filename)
            key = p.as_posix().rstrip('/')
            if (p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0] != 'codeql'
                    or '\\' in i.filename or ':' in i.filename or '\x00' in i.filename or key in seen):
                raise Blocker('UNSAFE_OR_DUPLICATE_CODEQL_ARCHIVE_MEMBER')
            seen.add(key)
            mode = i.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if stat.S_ISLNK(mode):
                target = z.read(i).decode('utf-8')
                if not target or '\\' in target or '\x00' in target or Path(target).is_absolute():
                    raise Blocker('UNSAFE_CODEQL_SYMLINK')
                links[key] = target
            elif i.is_dir() or kind in (0, stat.S_IFREG, stat.S_IFDIR):
                regular.append(i)
            else:
                raise Blocker('SPECIAL_DEVICE_IN_CODEQL_ARCHIVE')
        for key in seen:
            if any(str(a) in links for a in PurePosixPath(key).parents):
                raise Blocker('CODEQL_ARCHIVE_WRITES_THROUGH_SYMLINK')
        anchor = (destination/'codeql').resolve()
        for key, target in links.items():
            resolved = (destination/key).parent.joinpath(target).resolve()
            if not resolved.is_relative_to(anchor):
                raise Blocker('CODEQL_SYMLINK_ESCAPES_DISTRIBUTION')
        if not {'codeql/codeql', 'codeql/java/codeql-extractor.yml'}.issubset(seen):
            raise Blocker('PINNED_ARCHIVE_MISSING_CLI_OR_JAVA_EXTRACTOR')
        destination.parent.mkdir(parents=True, exist_ok=True)
        if shutil.disk_usage(destination.parent).free < total + 256*1024**2:
            raise Blocker('INSUFFICIENT_DISK_FOR_CODEQL_EXTRACTION')
        destination.mkdir(exist_ok=False)
        hashes = {}
        for i in regular:
            p = destination/i.filename
            if i.is_dir():
                p.mkdir(parents=True, exist_ok=True)
                continue
            p.parent.mkdir(parents=True, exist_ok=True)
            h = hashlib.sha256()
            with z.open(i) as src, p.open('xb') as out:
                while True:
                    block = src.read(1024*1024)
                    if not block:
                        break
                    h.update(block)
                    out.write(block)
            mode = (i.external_attr >> 16) & 0o777
            p.chmod(mode or 0o644)
            hashes[i.filename] = {'sha256': h.hexdigest(), 'mode': oct(mode or 0o644)}
        for name, target in links.items():
            p = destination/name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.symlink_to(target)
            if not p.resolve().is_relative_to(anchor):
                raise Blocker('CODEQL_SYMLINK_CHAIN_ESCAPES_DISTRIBUTION')
            hashes[name] = {'symlink': target}
    return {'files': hashes, 'uncompressed_bytes': total,
            'scope': 'VERIFIED_OFFICIAL_CLI_ARCHIVE_NOT_QUERY_PACK_UPGRADE'}


def select_toolchain(original: Path, work: Path, downloads: Path, run: Path, *,
                     allow_download: bool = False, archive_override: Path | None = None) -> SelectedToolchain:
    reports = []
    write_json(run/'CODEQL_RELEASE_PIN.json', {
        'version': VERSION, 'url': ASSET_URL, 'bytes': ASSET_SIZE, 'sha256': ASSET_SHA,
        'official_metadata_url': ASSET_METADATA_URL, 'allow_download': allow_download})
    chosen, report = probe_java(original, run, 'ORIGINAL_DEFAULT')
    reports.append(report)
    write_json(run/'CODEQL_RESOLUTION_ATTEMPTS.json', reports)
    if chosen is None and (original.parent/'java/codeql-extractor.yml').is_file():
        chosen, report = probe_java(original, run, 'ORIGINAL_EXPLICIT_JAVA', original.parent/'java')
        reports.append(report)
        write_json(run/'CODEQL_RESOLUTION_ATTEMPTS.json', reports)
    if chosen is not None:
        write_json(run/'CODEQL_SELECTION.json', {
            **report, 'mode': chosen.mode, 'downloaded': False,
            'engine_changed': False, 'query_packs_changed': False})
        return chosen

    print('B34R1: original CLI cannot resolve Java; trying a verified isolated distribution.', flush=True)
    local = work/'toolchain_downloads'/('codeql-linux64-'+VERSION+'-'+ASSET_SHA[:12]+'.zip')
    candidates = [archive_override] if archive_override else [
        local, downloads/('codeql-linux64-'+VERSION+'.zip'), downloads/'codeql-linux64.zip']
    archive, rejected = None, []
    for path in candidates:
        if path is None or not path.exists():
            continue
        try:
            check_archive(path)
            archive = path
            break
        except Blocker as exc:
            rejected.append({'path': str(path), 'reason': str(exc)})
            if archive_override is not None:
                write_json(run/'CODEQL_ARCHIVES_REJECTED.json', rejected)
                raise
    write_json(run/'CODEQL_ARCHIVES_REJECTED.json', rejected)
    fetched = False
    if archive is None:
        if not allow_download:
            raise Blocker('JAVA_EXTRACTOR_NOT_AVAILABLE_LOCALLY: use --allow-codeql-download '
                          'or --codeql-archive with the SHA-pinned 2.25.6 Linux ZIP; no network attempted')
        if local.exists():
            raise Blocker('CACHED_CODEQL_ZIP_INVALID_NOT_OVERWRITTEN: ' + str(local))
        download_official(local, run)
        archive, fetched = local, True
    check_archive(archive)
    target = run/'toolchain_recovery'
    manifest = safe_unpack(archive, target)
    manifest.update({'archive': str(archive), 'archive_sha256': ASSET_SHA,
                     'downloaded_this_run': fetched})
    write_json(run/'CODEQL_DISTRIBUTION_MANIFEST.json', manifest)
    binary = target/'codeql/codeql'
    chosen, report = probe_java(binary, run, 'ISOLATED_OFFICIAL_2_25_6', target/'codeql/java')
    reports.append(report)
    write_json(run/'CODEQL_RESOLUTION_ATTEMPTS.json', reports)
    if chosen is None:
        raise Blocker('VERIFIED_OFFICIAL_DISTRIBUTION_FAILED_JAVA_PREFLIGHT: '+report['reason'])
    chosen = SelectedToolchain(binary, chosen.extractor, 'ISOLATED_OFFICIAL_2_25_6', ASSET_SHA)
    write_json(run/'CODEQL_SELECTION.json', {
        **report, 'mode': chosen.mode, 'archive_sha256': ASSET_SHA,
        'downloaded': fetched, 'engine_changed': True, 'engine_version_changed': False,
        'query_packs_changed': False, 'original_cli_modified': False})
    return chosen
