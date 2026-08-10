"""logcoverage — detection coverage gap analysis for security teams.

Reports the blind spots between three things that are supposed to line up and
usually do not: what your detections require, what your SIEM actually ingests,
and what your critical systems emit.

Read-only by construction. It reads rule files, runs metadata searches that never
touch event content, and has no code path that writes to a SIEM, a rule
repository, or anything else.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
