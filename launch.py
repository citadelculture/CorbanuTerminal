"""Add only this public packet to isolated Python's import path."""
import pathlib
import runpy
import sys
here=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(here))
runpy.run_path(str(here/'host.py'),run_name='__main__')
