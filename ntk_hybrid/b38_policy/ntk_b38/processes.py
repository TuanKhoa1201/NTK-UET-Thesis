"""Best-effort Linux process cleanup for this scan, not arbitrary user processes."""
import os
from pathlib import Path
import signal

def descendants(root):
 parents={}
 for p in Path('/proc').iterdir():
  if not p.name.isdecimal():continue
  try:
   # Parent pid is field 4; executable names can contain spaces or parentheses.
   fields=(p/'stat').read_text().rsplit(')',1)[1].strip().split()
   parents[int(p.name)]=int(fields[1])
  except (OSError,ValueError,IndexError):pass
 found=[];front=[root]
 while front:
  children=[pid for pid,ppid in parents.items() if ppid in front and pid not in found]
  found.extend(children);front=children
 return found

def install_cleanup_handler():
 def stop(signum,frame):
  for pid in reversed(descendants(os.getpid())):
   try:os.kill(pid,signal.SIGTERM)
   except ProcessLookupError:pass
  raise RuntimeError('SCAN_CANCELLED_BY_SIGNAL_'+str(signum))
 signal.signal(signal.SIGTERM,stop)
 signal.signal(signal.SIGINT,stop)
