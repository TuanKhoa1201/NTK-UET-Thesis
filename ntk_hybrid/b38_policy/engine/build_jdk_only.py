#!/usr/bin/env python3
"""Trusted Java-only build command for CodeQL. Does NOT execute project build files.

This is a proof-of-integration workflow for JDK-only projects from trusted users.
-javac -proc:none forbids annotation processors (including processor discovery).
No Maven/Gradle dependency resolution, project shell commands or application runs.
"""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys


def command(root: Path, output: Path) -> list[str]:
    root = root.resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError('INVALID_SOURCE_ROOT')
    files = sorted(root.rglob('*.java'))
    if not files or len(files) > 24:
        raise RuntimeError('JDK_ONLY_REQUIRES_1_TO_24_JAVA_FILES')
    for path in files:
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise RuntimeError('SYMLINK_OR_OUTSIDE_SOURCE')
    output.mkdir(parents=True, exist_ok=True)
    return ['javac','-proc:none','-encoding','UTF-8','-d',str(output),*(str(x) for x in files)]


def main() -> int:
    if len(sys.argv) != 3:
        raise RuntimeError('USAGE: build_jdk_only.py SOURCE_ROOT CLASS_OUTPUT_ROOT')
    cmd = command(Path(sys.argv[1]), Path(sys.argv[2]))
    env = dict(os.environ)
    for name in ('JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','CLASSPATH'):
        env.pop(name, None)
    print('NTK_TRUSTED_JDK_COMPILATION_START count='+str(len(cmd)-6), flush=True)
    p = subprocess.run(cmd, env=env, check=False)
    if p.returncode:
        raise RuntimeError('JAVAC_FAILED_%d; JDK_ONLY_INPUT_NOT_SUPPORTED' % p.returncode)
    classes = sorted(Path(sys.argv[2]).rglob('*.class'))
    if not classes:
        raise RuntimeError('NO_COMPILED_CLASSES')
    print('NTK_TRUSTED_JDK_COMPILATION_PASS classes='+str(len(classes)), flush=True)
    return 0

if __name__=='__main__':
    sys.exit(main())
