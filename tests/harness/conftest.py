import sys
from pathlib import Path

# Make `threatmodel_eval` and `mutate` importable from the harness dir.
sys.path.insert(0, str(Path(__file__).resolve().parent))
