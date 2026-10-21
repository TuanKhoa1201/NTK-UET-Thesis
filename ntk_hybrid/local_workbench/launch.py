#!/usr/bin/env python3
from pathlib import Path
import os,sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from store import loads,read,need
from workbench import main
if __name__=='__main__':
    import signal
    def stop(signum,frame):raise KeyboardInterrupt('SIGNAL_'+str(signum))
    signal.signal(signal.SIGTERM,stop)
    try:
        c=loads(read(ROOT/'INSTALL.json'))
        need(os.path.abspath(sys.executable)==os.path.abspath(c['host_python']),'USE_THE_HOST_PYTHON_RECORDED_DURING_INSTALL')
        sys.exit(main(['--state',c['state'],*sys.argv[1:]]))
    except Exception as e:print('WORKBENCH_BLOCKED='+str(e),flush=True);sys.exit(2)
