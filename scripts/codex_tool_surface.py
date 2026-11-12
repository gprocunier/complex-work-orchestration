"""Compatibility path for ``cwo_core.codex_tool_surface``.

The implementation moved to ``scripts/cwo_core/codex_tool_surface.py`` so core
modules can import it without importing a script. Importing this name returns
that same module object: attribute reads and patches through either name reach
one implementation.
"""

from __future__ import annotations

import sys

from cwo_core import codex_tool_surface as _implementation

sys.modules[__name__] = _implementation
