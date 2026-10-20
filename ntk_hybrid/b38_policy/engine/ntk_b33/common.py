from __future__ import annotations
import ctypes
import ctypes.util
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import socket
from typing import Any

COMMIT = '51c2aafaf2746a6246ab057752791cc397c272d4'
IRIS_BLOB = 'daab36f359efd201cb9d84b10eaff9dfc9162633'
ADAPTER_SHA = {
    'epoch_1': '38a6e7b771853abdb49ae2ec1ad46a6bad6557c38ccc9f73bd0649eff4ce1954',
    'epoch_2': 'a6fd202e3a982d10f677e6351012a50340a9184d1f633c4e0c6925aa6ba5351b',
}
ADAPTER_CONFIG_SHA = 'b6305fec9b9ae3a10043fb7cfdeda6c28839ab0604e5f4e388194b65e5211d7e'
PARSER = 'ntk-strict-six-fields-v33.1'
FIELDS = {'package', 'class', 'method', 'signature', 'sink_args', 'type'}
IDENTITY = ('package', 'class', 'method', 'signature')
ROLES = {'none', 'source', 'sink', 'taint-propagator'}

class Blocker(RuntimeError):
    pass


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def sha_file(path: Path | str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: Path | str, data: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp.' + str(os.getpid()))
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    os.replace(tmp, path)


def normalize_cwe(value: Any) -> str:
    if isinstance(value, bool):
        raise Blocker('Invalid CWE: boolean')
    m = re.fullmatch(r'(?:CWE[-_ ]?)?0*(22|78|79|89)', str(value).strip(), re.I)
    if not m:
        raise Blocker('Unsupported or missing CWE: ' + repr(value))
    return m.group(1)


def walk(value: Any):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def candidate_from_record(record: dict) -> dict:
    """Read explicit identities only; never infer owner or overload from source text."""
    found = {}
    def has_identity(obj):
        return (isinstance(obj, dict) and 'package' in obj and
                ('class' in obj or 'clazz' in obj) and
                ('method' in obj or 'func' in obj) and
                ('signature' in obj or 'full_signature' in obj))
    # An explicit top-level candidate is the request, not a nested model completion.
    # When the record has no explicit canonical container, require an unambiguous identity.
    explicit = [record] if has_identity(record) else []
    if not explicit:
        for key in ('api', 'candidate', 'native_api', 'api_identity', 'native_candidate'):
            item = record.get(key)
            if has_identity(item):
                explicit.append(item)
            elif isinstance(item, list) and len(item) == 4 and all(isinstance(x, str) for x in item):
                explicit.append(dict(zip(IDENTITY, item)))
    for obj in (explicit if explicit else walk(record)):
        if not isinstance(obj, dict):
            continue
        row = {}
        for target, names in {
            'package': ('package',), 'class': ('class', 'clazz'),
            'method': ('method', 'func'), 'signature': ('signature', 'full_signature'),
        }.items():
            vals = [obj[n] for n in names if n in obj and isinstance(obj[n], str)]
            if len(set(vals)) > 1:
                raise Blocker('Conflicting explicit identity aliases: ' + target)
            if vals:
                row[target] = vals[0]
        if set(row) == set(IDENTITY):
            found[digest(row)] = row
    if len(found) != 1:
        raise Blocker('Expected one explicit API identity in record; found %d. Keys=%r' %
                      (len(found), list(record)[:30]))
    cwes = set()
    for obj in walk(record):
        if isinstance(obj, dict):
            for key in ('cwe', 'cwe_id', 'requested_cwe'):
                if key in obj:
                    cwes.add(normalize_cwe(obj[key]))
    if len(cwes) != 1:
        raise Blocker('Missing or ambiguous explicit CWE; record keys=' + repr(list(record)[:30]))
    row = next(iter(found.values()))
    row['cwe'] = next(iter(cwes))
    # Receiver semantics are NOT guessed. Only an explicit false is evidence of an instance API.
    static_flags = {obj['is_static'] for obj in walk(record)
                    if isinstance(obj, dict) and type(obj.get('is_static')) is bool}
    row['is_static'] = next(iter(static_flags)) if len(static_flags) == 1 else None
    row['receiver_policy'] = 'HOLD_THIS_UNTIL_SEMANTIC_REVIEW'
    row['source_record_sha256'] = digest(record)
    messages = record.get('messages')
    if (isinstance(messages, list) and len(messages) == 2 and
            all(isinstance(m, dict) and set(m) == {'role', 'content'} for m in messages) and
            [m['role'] for m in messages] == ['system', 'user']):
        row['historical_b32_messages'] = messages
    return row


def parameter_names(signature: str) -> list[str]:
    if not isinstance(signature, str) or '(' not in signature or not signature.rstrip().endswith(')'):
        raise Blocker('SIGNATURE_NOT_SUPPORTED')
    body = signature[signature.find('(') + 1:signature.rfind(')')].strip()
    if not body:
        return []
    parts, buf = [], []
    depth = {'<': 0, '(': 0, '[': 0}
    closes = {'>': '<', ')': '(', ']': '['}
    for char in body:
        if char in depth:
            depth[char] += 1
        elif char in closes:
            depth[closes[char]] -= 1
            if depth[closes[char]] < 0:
                raise Blocker('UNBALANCED_SIGNATURE')
        if char == ',' and all(n == 0 for n in depth.values()):
            parts.append(''.join(buf).strip())
            buf = []
        else:
            buf.append(char)
    parts.append(''.join(buf).strip())
    if any(depth.values()):
        raise Blocker('UNBALANCED_SIGNATURE')
    names = []
    for part in parts:
        # A name without a preceding type is ambiguous and is not guessed.
        match = re.fullmatch(r'.+\s+([A-Za-z_$][A-Za-z0-9_$]*)(?:\s*\[\s*\])?', part)
        if not match:
            raise Blocker('PARAMETER_NAME_NOT_PROVEN')
        names.append(match.group(1))
    if len(set(names)) != len(names):
        raise Blocker('DUPLICATE_PARAMETER_NAMES')
    return names


def strict_label(raw: Any, candidate: dict, cwe: str, *, receiver_approved: bool = False) -> dict:
    def abstain(reason: str) -> dict:
        return {'status': 'ABSTAIN', 'reason': reason, 'label': None}
    try:
        if normalize_cwe(candidate['cwe']) != normalize_cwe(cwe):
            return abstain('CWE_MISMATCH')
    except (KeyError, Blocker):
        return abstain('CWE_UNPROVEN')
    if not isinstance(raw, str):
        return abstain('NON_TEXT_RESPONSE')
    def unique_pairs(pairs):
        result = {}
        for key, val in pairs:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = val
        return result
    def reject_constant(value):
        raise ValueError('non-finite JSON value: ' + value)
    try:
        obj = json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=reject_constant)
    except (ValueError, TypeError):
        return abstain('INVALID_STRICT_JSON')
    if not isinstance(obj, dict) or set(obj) != FIELDS:
        return abstain('EXACT_SIX_FIELDS_REQUIRED')
    if any(type(obj[k]) is not str or obj[k] != candidate.get(k) for k in IDENTITY):
        return abstain('IDENTITY_OR_OVERLOAD_MISMATCH')
    if not isinstance(obj['type'], str) or obj['type'] not in ROLES:
        return abstain('INVALID_ROLE')
    args = obj['sink_args']
    if not isinstance(args, list) or any(type(a) is not str for a in args):
        return abstain('INVALID_SINK_ARGS_TYPE')
    if len(args) != len(set(args)):
        return abstain('DUPLICATE_SINK_ARGS')
    if obj['type'] != 'sink':
        if args:
            return abstain('NON_SINK_WITH_SINK_ARGS')
    else:
        if not args:
            return abstain('EMPTY_SINK_ARGS')
        try:
            params = parameter_names(candidate['signature'])
        except Blocker as exc:
            return abstain(str(exc))
        for arg in args:
            if arg == 'this':
                if candidate.get('is_static') is not False or not receiver_approved:
                    return abstain('RECEIVER_SEMANTICS_UNPROVEN')
            elif arg not in params:
                return abstain('UNKNOWN_SINK_ARGUMENT')
    return {'status': 'ACCEPTED', 'reason': 'STRICT_CONTRACT_ACCEPTED_NOT_GOLD', 'label': obj}


def deny_inet() -> dict:
    """Linux seccomp, inherited by children/threads. No privileged/network namespace changes."""
    class ArgCmp(ctypes.Structure):
        _fields_ = [('arg', ctypes.c_uint), ('op', ctypes.c_int),
                    ('datum_a', ctypes.c_uint64), ('datum_b', ctypes.c_uint64)]
    name = ctypes.util.find_library('seccomp')
    if not name:
        raise Blocker('libseccomp missing; offline isolation not silently downgraded')
    lib = ctypes.CDLL(name, use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                         ctypes.c_uint, ctypes.POINTER(ArgCmp)]
    lib.seccomp_rule_add_array.restype = ctypes.c_int
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_load.restype = ctypes.c_int
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    ctx = lib.seccomp_init(0x7fff0000)
    if not ctx:
        raise Blocker('seccomp_init failed')
    try:
        for call in ('socket', 'socketpair'):
            nr = lib.seccomp_syscall_resolve_name(call.encode())
            if nr < 0:
                raise Blocker('seccomp syscall unresolved: ' + call)
            for family in (socket.AF_INET, socket.AF_INET6):
                cmp = ArgCmp(0, 4, family, 0)  # SCMP_CMP_EQ
                rc = lib.seccomp_rule_add_array(ctx, 0x00050000 | errno.EPERM, nr, 1, ctypes.byref(cmp))
                if rc != 0:
                    raise Blocker('seccomp rule failed: ' + str(rc))
        if lib.seccomp_load(ctx) != 0:
            raise Blocker('seccomp_load failed')
    finally:
        lib.seccomp_release(ctx)
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
        except OSError as exc:
            if exc.errno != errno.EPERM:
                raise Blocker('Network isolation probe unexpected error: ' + repr(exc))
        else:
            sock.close()
            raise Blocker('NETWORK_ISOLATION_FAILED')
    return {'AF_INET': 'DENIED_EPERM', 'AF_INET6': 'DENIED_EPERM',
            'scope': 'CURRENT_PROCESS_AND_DESCENDANTS', 'AF_UNIX': 'ALLOWED'}
