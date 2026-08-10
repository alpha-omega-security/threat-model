"""Citation resolution — the only checks that compare the model to the source.

Every other check reads the document's shape, which is cheap to satisfy without
doing the work. These read the tree the model was written from, so a citation
that is shaped right but points at nothing fails here and nowhere else.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import mutate  # noqa: F401  (puts the harness dir on sys.path via conftest)
from threatmodel_eval import Model
from threatmodel_eval.citations import _classify, _comment_lines, run_citation_checks

_SRC = "src"


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    src = tmp_path / _SRC
    src.mkdir()
    (src / "widget.c").write_text(
        "#include <stdio.h>\n"            # 1
        "/* A block comment whose\n"      # 2
        "   continuation starts with a word, not an asterisk. */\n"   # 3
        "\n"                              # 4
        "int guard(int n) {\n"            # 5
        "    state->wrap &= ~4;\n"        # 6
        "    return n;\n"                 # 7
        "}\n"                             # 8
        "#endif\n"                        # 9
    )
    return tmp_path


def _model(body: str) -> Model:
    return Model.from_text("# T\n\n## 1.1 Header\n\n" + body,
                           Path("docs/threat-model.md"))


def _fail_ids(tree: Path, body: str) -> set[str]:
    report = run_citation_checks(_model(body), tree)
    return {f.check_id for f in report.findings if not f.passed}


def test_statement_citation_resolves(tree):
    assert _fail_ids(tree, "The bit is cleared at `src/widget.c:6`.") == set()


@pytest.mark.parametrize("line,why", [
    (4, "blank line"),
    (9, "bare #endif"),
    (8, "lone closing brace"),
    (2, "comment opener"),
    (3, "comment continuation that does not start with an asterisk"),
])
def test_non_code_citation_is_rejected(tree, line, why):
    assert _fail_ids(tree, f"See `src/widget.c:{line}`.") == {"CITE.resolves"}, why


def test_missing_file_and_overrun_line_are_rejected(tree):
    assert _fail_ids(tree, "See `src/nope.c:1`.") == {"CITE.resolves"}
    assert _fail_ids(tree, "See `src/widget.c:900`.") == {"CITE.resolves"}


def test_basename_falls_back_when_unique(tree):
    # Models cite `widget.c`; the tree may nest it. A unique match still counts.
    assert _fail_ids(tree, "The bit is cleared at `widget.c:6`.") == set()


@pytest.mark.parametrize("citation_path", ["../outside.c", "ABSOLUTE"])
def test_code_citation_cannot_escape_source_root(tmp_path, citation_path):
    root = tmp_path / "checkout"
    root.mkdir()
    outside = tmp_path / "outside.c"
    outside.write_text("int outside(void) { return 1; }\n")
    (root / "outside.c").write_text("int decoy(void) { return 1; }\n")
    if citation_path == "ABSOLUTE":
        citation_path = str(outside)

    assert _fail_ids(root, f"See `{citation_path}:1`.") == {"CITE.resolves"}


def test_code_citation_rejects_symlinks_outside_source_root(tmp_path):
    root = tmp_path / "checkout"
    nested = root / "nested"
    nested.mkdir(parents=True)
    outside = tmp_path / "outside.c"
    outside.write_text("int outside(void) { return 1; }\n")
    try:
        (root / "direct.c").symlink_to(outside)
        (nested / "fallback.c").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available")

    assert _fail_ids(root, "See `direct.c:1`.") == {"CITE.resolves"}
    assert _fail_ids(root, "See `fallback.c:1`.") == {"CITE.resolves"}


def test_quote_must_appear_in_the_file_it_is_attributed_to(tree):
    real = ('"continuation starts with a word, not an asterisk" '
            "*(documented, `src/widget.c`)*")
    fake = ('"this sentence appears nowhere in the source at all, truly" '
            "*(documented, `src/widget.c`)*")
    assert "CITE.quotes" not in _fail_ids(tree, real)
    assert "CITE.quotes" in _fail_ids(tree, fake)


@pytest.mark.parametrize("citation_path", ["../outside.c", "ABSOLUTE"])
def test_attributed_quote_cannot_escape_source_root(tmp_path, citation_path):
    root = tmp_path / "checkout"
    root.mkdir()
    outside = tmp_path / "outside.c"
    quote = "outside quotation must never be read by citation validation"
    outside.write_text(quote + "\n")
    (root / "outside.c").write_text(quote + "\n")
    if citation_path == "ABSOLUTE":
        citation_path = str(outside)
    body = f'"{quote}" *(documented, `{citation_path}`)*'

    assert "CITE.quotes" in _fail_ids(root, body)


def test_attributed_quote_rejects_symlink_outside_source_root(tmp_path):
    root = tmp_path / "checkout"
    nested = root / "nested"
    nested.mkdir(parents=True)
    outside = tmp_path / "outside.c"
    quote = "outside quotation must never be read by citation validation"
    outside.write_text(quote + "\n")
    try:
        (nested / "linked.c").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available")

    body = f'"{quote}" *(documented, `linked.c`)*'
    assert "CITE.quotes" in _fail_ids(root, body)


def test_elided_quote_matches_on_its_longest_fragment(tree):
    body = ('"A block comment whose … continuation starts with a word, not an '
            'asterisk" *(documented, `src/widget.c`)*')
    assert "CITE.quotes" not in _fail_ids(tree, body)


def test_comment_scan_tracks_block_state():
    lines = ["code();", "/* open", "still comment", "*/ tail();", "after();"]
    assert _comment_lines(lines) == {2, 3}
    assert _classify(lines[2], True) == "comment text"
    assert _classify(lines[0], False) == ""


# --------------------------------------------------------------------------- #
# Scope vs build — a directory the build compiles is in scope wherever it lives.
# --------------------------------------------------------------------------- #
from threatmodel_eval.buildscope import run_buildscope_checks  # noqa: E402


@pytest.fixture
def buildtree(tmp_path: Path) -> Path:
    (tmp_path / "contrib" / "accel").mkdir(parents=True)
    (tmp_path / "contrib" / "accel" / "fast.c").write_text("int f(void){return 0;}\n")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "cover.c").write_text("int t(void){return 0;}\n")
    (tmp_path / "Makefile.in").write_text(
        "fast.o: $(SRCDIR)contrib/accel/fast.c\n"          # 1 builds into the lib
        "\t$(CC) -c -o $@ $(SRCDIR)contrib/accel/fast.c\n" # 2
        "cover.o: $(SRCDIR)test/cover.c\n"                 # 3 test binary only
        "\t$(CC) -c -o $@ $(SRCDIR)test/cover.c\n"         # 4
        "clean:\n"                                          # 5
        "\trm -f *.o \\\n"                                  # 6 continuation…
        "\t   contrib/accel/*.o\n"                          # 7 …still the rm
    )
    return tmp_path


def _scope_fail(tree: Path, scope_body: str) -> bool:
    model = Model.from_text(
        "# T\n\n## 1.1 Header\n\nx\n\n## 1.3 Out of scope\n\n" + scope_body,
        Path("docs/threat-model.md"))
    return any(not f.passed for f in run_buildscope_checks(model, tree).findings)


def test_excluded_directory_that_the_build_compiles_is_flagged(buildtree):
    assert _scope_fail(buildtree, "- `contrib/` is samples and is out of scope.")


def test_naming_the_built_path_counts_as_acknowledged(buildtree):
    assert not _scope_fail(
        buildtree,
        "- `contrib/` is out of scope, except `contrib/accel/` which the build "
        "compiles into the library on some platforms.")


def test_test_directories_are_not_flagged(buildtree):
    # test/cover.c is compiled, but into a test binary, not the shipped artifact.
    assert not _scope_fail(buildtree, "- `test/` holds the test suite; out of scope.")


def test_clean_target_is_not_a_build_rule(buildtree):
    # The rm continuation names contrib/accel/*.o; deleting is not shipping.
    model_body = ("- `contrib/` is out of scope, except `contrib/accel/` which "
                  "the build compiles in.")
    assert not _scope_fail(buildtree, model_body)


# --------------------------------------------------------------------------- #
# §1.7 coverage claims — "every public entry point" is a claim about a set.
# --------------------------------------------------------------------------- #
from threatmodel_eval.apisurface import run_api_checks  # noqa: E402


@pytest.fixture
def apitree(tmp_path: Path) -> Path:
    (tmp_path / "api.h").write_text(
        "/* comment mentioning notAFunction( */\n"
        "#define Z_ERRNO (-1)\n"              # constant, not callable
        "#define wrapInit(a) wrapInit_(a)\n"  # function-like macro: counts
        "int alpha(int n);\n"
        "int beta(void);\n"
        "int gamma(char *p);\n"
        "int delta(void);\n"
        "int epsilon(void);\n"
        "int zeta(void);\n"
    )
    return tmp_path


def _api_fail(tree: Path, s7: str) -> list[str]:
    model = Model.from_text(
        "# T\n\n## 1.1 Header\n\nx\n\n## 1.7 Inputs\n\n" + s7,
        Path("docs/threat-model.md"))
    return [f.check_id for f in run_api_checks(model, tree).findings if not f.passed]


def test_export_extraction_skips_constants_and_comments(apitree):
    from threatmodel_eval.apisurface import _exports
    names = _exports(apitree / "api.h")
    assert "Z_ERRNO" not in names and "notAFunction" not in names
    assert {"alpha", "beta", "wrapInit"} <= names


def test_false_completeness_claim_is_caught(apitree):
    body = "Every public entry point in `api.h` is covered. `alpha` and `beta`."
    assert _api_fail(apitree, body) == ["API.coverage-claim"]


def test_true_completeness_claim_passes(apitree):
    body = ("Every public entry point in `api.h` is covered: `alpha`, `beta`, "
            "`gamma`, `delta`, `epsilon`, `zeta`, `wrapInit`.")
    assert _api_fail(apitree, body) == []


def test_a_stated_count_is_not_a_completeness_claim(apitree):
    # The spec asks for a denominator instead of an adjective; partial is fine.
    body = "2 of 7 entry points have rows: `alpha`, `beta`. The rest are accessors."
    assert "API.coverage-claim" not in _api_fail(apitree, body)


def test_unresolvable_header_is_not_guessed_at(apitree):
    body = "Every public entry point in `nosuch.h` is covered."
    assert _api_fail(apitree, body) == []
