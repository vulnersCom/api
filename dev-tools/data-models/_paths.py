"""Shared filesystem paths for the data-model toolset (see sample_collections.py)."""

from __future__ import annotations

from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]

# Regenerable sampled data — git-ignored (see .gitignore).
TYPE_OUT = HERE / "type_schemas.json"
SCHEMA_OUT = HERE / "family_schemas.json"
COLLECTION_OUT = HERE / "collection_map.json"
REPORT_OUT = HERE / "coverage_report.md"

# Committed generated outputs.
MODELS_DATA = REPO / "src" / "vulners" / "_models" / "_collections_data.py"
DOC_DIR = REPO / "documentation" / "reference"
