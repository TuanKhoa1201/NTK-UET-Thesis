"""Untrusted Java ZIP intake. Java text files only; never execute uploaded builds."""
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import stat
import zipfile

MAX_ZIP = 16 * 1024 * 1024
MAX_FILES = 2000
MAX_TOTAL_UNPACKED = 64 * 1024 * 1024
MAX_SINGLE_JAVA = 2 * 1024 * 1024
MAX_JAVA_FILES = 1000

class IntakeError(ValueError):
    pass


def secure_unpack(blob: bytes, target: Path) -> dict:
    if not isinstance(blob, bytes) or not blob or len(blob) > MAX_ZIP:
        raise IntakeError('UPLOAD_MUST_BE_ZIP_UNDER_16_MIB')
    target = target.resolve()
    target.mkdir(parents=True, exist_ok=False)
    digest = hashlib.sha256(blob).hexdigest()
    total = 0
    count = 0
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        items = z.infolist()
        if len(items) > MAX_FILES:
            raise IntakeError('ZIP_ENTRY_LIMIT_EXCEEDED')
        seen = set()
        for item in items:
            name = item.filename
            if (not name or len(name) > 255 or '\\' in name or '\x00' in name or name.startswith('/')
                    or ':' in name or any(part in ('', '.', '..') for part in name.rstrip('/').split('/'))):
                raise IntakeError('UNSAFE_ZIP_PATH')
            parts = PurePosixPath(name.rstrip('/')).parts
            if len(parts) > 24:
                raise IntakeError('ZIP_PATH_DEPTH_EXCEEDED')
            folded = '/'.join(parts).casefold()
            if folded in seen:
                raise IntakeError('DUPLICATE_ZIP_PATH')
            seen.add(folded)
            fmode = (item.external_attr >> 16) & 0o170000
            if fmode not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise IntakeError('ZIP_SYMLINK_OR_SPECIAL_FILE_FORBIDDEN')
            if item.is_dir():
                continue
            total += item.file_size
            if total > MAX_TOTAL_UNPACKED:
                raise IntakeError('ZIP_TOTAL_UNPACKED_TOO_LARGE')
            if item.file_size > 256 * (item.compress_size + 1):
                raise IntakeError('ZIP_COMPRESSION_RATIO_TOO_HIGH')
            if not name.lower().endswith('.java'):
                continue
            if item.file_size > MAX_SINGLE_JAVA:
                raise IntakeError('JAVA_FILE_TOO_LARGE')
            count += 1
            if count > MAX_JAVA_FILES:
                raise IntakeError('TOO_MANY_JAVA_FILES')
            dst = target.joinpath(*parts)
            if not dst.resolve().is_relative_to(target):
                raise IntakeError('OUTSIDE_WORKSPACE')
            dst.parent.mkdir(parents=True, exist_ok=True)
            with z.open(item) as src, open(dst, 'xb') as fout:
                remaining = item.file_size
                while True:
                    chunk = src.read(min(1024 * 1024, remaining + 1))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise IntakeError('JAVA_ZIP_SIZE_MISMATCH')
                    fout.write(chunk)
                if remaining != 0:
                    raise IntakeError('JAVA_ZIP_SIZE_MISMATCH')
            dst.chmod(0o600)
    if count == 0:
        raise IntakeError('ZIP_CONTAINS_NO_JAVA')
    return {'archive_sha256': digest, 'java_files': count, 'zip_entries': len(items),
            'compressed_bytes': len(blob), 'unpacked_declared_bytes': total,
            'extraction_policy': 'ONLY_JAVA_NO_BUILD_OR_EXECUTION'}
