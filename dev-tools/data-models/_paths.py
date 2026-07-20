"""Shared filesystem paths for the data-model toolset (see sample_collections.py)."""

from __future__ import annotations

from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]

# Regenerable raw sample records — git-ignored (see .gitignore).
TYPE_OUT = HERE / "type_schemas.json"
COLLECTION_OUT = HERE / "collection_map.json"

# Committed generated outputs.
MODELS_DATA = REPO / "src" / "vulners" / "_models" / "_collections_data.py"
FIELD_DESCRIPTIONS = REPO / "src" / "vulners" / "_models" / "_field_descriptions.py"
DOC_DIR = REPO / "documentation" / "reference"
