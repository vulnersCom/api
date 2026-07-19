"""Guards for the example scripts under samples/.

Samples are not shipped in the distribution, but they are copy-pasted by users.
A sample may show the direct ``api_key="YOUR_API_KEY_HERE"`` form in a comment,
but the executable client it constructs must never pass a literal key — it reads
the key from the VULNERS_API_KEY environment variable.
"""

from __future__ import annotations

import ast
import py_compile
from pathlib import Path

import pytest

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
# Two sets: samples/legacy/ (v3 API) and samples/v4/ (v4 API).
SAMPLE_FILES = sorted(SAMPLES_DIR.rglob("*.py"))


def test_samples_exist():
    assert SAMPLE_FILES, "no sample scripts found"


@pytest.mark.parametrize("path", SAMPLE_FILES, ids=lambda p: p.name)
def test_sample_compiles(path: Path):
    py_compile.compile(str(path), doraise=True)


@pytest.mark.parametrize("path", SAMPLE_FILES, ids=lambda p: p.name)
def test_no_hardcoded_api_key_literal(path: Path):
    source = path.read_text(encoding="utf-8")
    # the old, undocumented "KEY" env name is gone
    assert '"KEY"' not in source and "'KEY'" not in source
    # A literal "YOUR_API_KEY_HERE" may appear only as a comment placeholder,
    # never in executable code. The AST below never sees comments, so any
    # api_key=<constant> it finds is a real hard-coded literal.
    tree = ast.parse(source, filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "api_key":
                    # never a bare string literal in a real client construction
                    assert not isinstance(kw.value, ast.Constant), (
                        f"{path.name} passes a literal api_key"
                    )


@pytest.mark.parametrize("path", SAMPLE_FILES, ids=lambda p: p.name)
def test_sample_reads_key_from_env(path: Path):
    source = path.read_text(encoding="utf-8")
    # every sample constructs the client, so every sample must reference the
    # documented environment variable
    assert 'os.environ["VULNERS_API_KEY"]' in source
