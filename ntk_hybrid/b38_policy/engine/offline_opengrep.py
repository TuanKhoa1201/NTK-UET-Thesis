#!/usr/bin/env python3
"""Run pinned OpenGrep under inherited Linux seccomp isolation.

Public scanner binary receives only local paths; no remote network sockets.
"""
import os
from pathlib import Path
import sys
from offline_common import Blocker, deny_inet, write_json

def main():
    if len(sys.argv)<5:
        raise Blocker('OFFLINE_WRAPPER_ARGUMENTS')
    proof, binary, *argv = sys.argv[1:]
    if argv[0]!='scan' or not Path(binary).is_file() or not os.path.isabs(binary):
        raise Blocker('OFFLINE_WRAPPER_INVALID_BINARY')
    info=deny_inet()
    write_json(Path(proof),{'status':'INHERITED_SECCOMP_INSTALLED_BEFORE_EXEC','network':info,
                           'binary':binary,'argv':[binary]+argv})
    os.execv(binary,[binary]+argv)
if __name__=='__main__':
    main()
