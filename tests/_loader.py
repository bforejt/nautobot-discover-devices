"""Load pure discovery modules without importing Nautobot Job registration."""

import importlib
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"

package = types.ModuleType("jobs")
package.__path__ = [str(ROOT / "jobs")]
sys.modules.setdefault("jobs", package)


def load(name):
    """Load a module under the synthetic jobs package."""
    return importlib.import_module("jobs." + name)


def fixture(name):
    """Read a sanitized structured fixture."""
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))
