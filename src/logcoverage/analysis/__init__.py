"""Analysis implementations.

Importing this package registers every built-in analysis. A new analysis should
``@register("name")`` in a module imported here and add its name to
``logcoverage.config.ALL_ANALYSES``; the CI invariants job fails the build if the
two lists disagree, because an analysis an operator can select and no code
implements is a permanently green, permanently blind run — the exact failure this
tool exists to report, applied to itself.

Every analysis here is deterministic: same state in, same findings out. Nothing
in this package consults a model, opens a socket or reads a file, and nothing
here chooses a severity — the band comes from the table in
:mod:`logcoverage.severity`.
"""

from __future__ import annotations

# Imported for their registration side effects.
from . import (  # noqa: F401  (side-effect imports)
    expected_unconfigured,
    field_gaps,
    orphan_ingestion,
    required_absent,
    silent_source,
    technique_coverage,
    volume_collapse,
)
from .base import (
    AnalysisContext,
    SourceState,
    SourceVerdict,
    get_analysis,
    register,
    registered_analyses,
)

__all__ = [
    "AnalysisContext",
    "SourceState",
    "SourceVerdict",
    "get_analysis",
    "register",
    "registered_analyses",
]
