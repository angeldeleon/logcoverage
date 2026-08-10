"""Detection rule inputs: what each rule says it reads.

Two formats, and the difference between how they are treated is deliberate.

:mod:`logcoverage.rules.sigma` reads files somebody else wrote, so it tolerates
unknown keys and degrades a malformed rule into an *indeterminate* one rather
than dropping it. :mod:`logcoverage.rules.mapping` reads a file the operator
wrote, so it rejects unknown keys and fails loudly.

:mod:`logcoverage.rules.loader` does the traversal for both: bounded, sorted, and
refusing symlinks outright.
"""

from __future__ import annotations

from .loader import LoadedFile, LoadResult, RuleLoadError, read_file, walk_rule_tree
from .mapping import parse_mapping_file
from .sigma import parse_sigma_documents

__all__ = [
    "LoadResult",
    "LoadedFile",
    "RuleLoadError",
    "parse_mapping_file",
    "parse_sigma_documents",
    "read_file",
    "walk_rule_tree",
]
