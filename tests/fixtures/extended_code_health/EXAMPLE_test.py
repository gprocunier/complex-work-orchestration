"""Fixed approved measurement driver; no paths are read from a report."""
from pathlib import Path
import runpy

subject = runpy.run_path(str(Path(__file__).with_name("EXAMPLE_subject.py")))
if subject["example"](1) != 2:
    raise AssertionError("EXAMPLE positive case failed")
