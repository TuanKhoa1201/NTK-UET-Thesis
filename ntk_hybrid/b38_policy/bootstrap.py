"""Use only the bundled B37 engine, never ambient modules with the same name."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent
ENGINE=ROOT/'engine'
if str(ENGINE) not in sys.path:sys.path.insert(0,str(ENGINE))
