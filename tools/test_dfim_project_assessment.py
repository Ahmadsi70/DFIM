"""Unit tests for the DFIM project value assessment tool."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dfim_project_assessment import (
    COMMERCIAL_VALUE_THRESHOLD_PCT,
    PRACTICAL_VALUE_THRESHOLD_PCT,
    DIMENSIONS,
    PROJECT_ROOT,
    AssessmentResult,
    DimensionScore,
    Finding,
    _assess_commercial_readiness,
    _assess_gaps,
    _assess_purpose,
    _assess_security_posture,
    _assess_technical_maturity,
    _detect_project_name,
    _detect_use_case,
    _read_json,
    _safe_read,
    _to_json,
    _to_text,
    run_assessment,
)


# ══════════════════════════════════════════════════════════════════════
# Core data model tests
# ══════════════════════════════════════════════════════════════════════


class DataModelTests(unittest.TestCase):
    """Validation of data classes, serialization, and output formatting."""

    def test_finding_fields_are_correctly_stored(self) -> None:
        f = Finding("deployment", "Test label", "Some detail", "strength")
        self.assertEqual(f.category, "deployment")
        self.assertEqual(f.label, "Test label")
        self.assertEqual(f.detail, "Some detail")
        self.assertEqual(f.verdict, "strength")

    def test_dimension_score_calculates_pct_correctly(self) -> None:
        dim = DimensionScore(
            name="test",
            description="desc",
            score_pct=75.0,
            max_possible=20,
            earned=15,
            findings=[],
        )
        self.assertEqual(dim.score_pct, 75.0)
        self.assertEqual(dim.earned, 15)
        self.assertEqual(dim.max_possible, 20)

    def test_assessment_result_stores_all_fields(self) -> None:
        result = AssessmentResult(
            project_name="TestApp",
            project_summary="A test project",
            use_case="Testing",
            dimensions=[],
            overall_score_pct=82.5,
            has_commercial_value=True,
            has_practical_value=True,
            top_strengths=["strength one"],
            critical_gaps=["gap one"],
            recommendation="Go to production",
        )
        self.assertTrue(result.has_commercial_value)
        self.assertTrue(result.has_practical_value)
        self.assertEqual(result.project_name, "TestApp")
        self.assertEqual(result.overall_score_pct, 82.5)

    def test_to_json_is_valid_and_contains_keys(self) -> None:
        result = AssessmentResult(
            project_name="Foo",
            project_summary="bar",
            use_case="baz",
            dimensions=[],
            overall_score_pct=50.0,
            has_commercial_value=False,
            has_practical_value=True,
            top_strengths=[],
            critical_gaps=[],
            recommendation="fix it",
        )
        raw = _to_json(result)
        data = json.loads(raw)
        self.assertIn("project_name", data)
        self.assertIn("overall_score_pct", data)
        self.assertIn("dimensions", data)
        self.assertIsInstance(data["dimensions"], list)

    def test_to_text_includes_all_sections(self) -> None:
        result = AssessmentResult(
            project_name="Foo",
            project_summary="bar",
            use_case="baz",
            dimensions=[
                DimensionScore(
                    name="test_dim",
                    description="test desc",
                    score_pct=50.0,
                    max_possible=10,
                    earned=5,
                    findings=[
                        Finding("cat", "label", "detail", "strength"),
                        Finding("cat", "label2", "detail2", "gap"),
                    ],
                )
            ],
            overall_score_pct=50.0,
            has_commercial_value=False,
            has_practical_value=True,
            top_strengths=["s1"],
            critical_gaps=["g1"],
            recommendation="fix it",
        )
        text = _to_text(result)
        self.assertIn("Foo", text)
        self.assertIn("test_dim", text)
        self.assertIn("TOP STRENGTHS", text)
        self.assertIn("CRITICAL GAPS", text)
        self.assertIn("RECOMMENDATION", text)


# ══════════════════════════════════════════════════════════════════════
# Dimension scoring tests (structural / threshold)
# ══════════════════════════════════════════════════════════════════════


class DimensionScoringTests(unittest.TestCase):
    """Verify that each dimension returns scores in valid ranges
    and contains expected finding categories."""

    def test_purpose_dimension_returns_valid_score(self) -> None:
        dim = _assess_purpose()
        self.assertGreaterEqual(dim.score_pct, 0.0)
        self.assertLessEqual(dim.score_pct, 100.0)
        self.assertGreater(dim.max_possible, 0)
        self.assertGreaterEqual(len(dim.findings), 1)
        verdicts = {f.verdict for f in dim.findings}
        self.assertTrue({"strength", "gap"}.issuperset(verdicts))

    def test_technical_maturity_returns_valid_score(self) -> None:
        dim = _assess_technical_maturity()
        self.assertGreaterEqual(dim.score_pct, 0.0)
        self.assertLessEqual(dim.score_pct, 100.0)
        self.assertGreater(dim.max_possible, 0)
        self.assertGreaterEqual(len(dim.findings), 1)

    def test_commercial_readiness_returns_valid_score(self) -> None:
        dim = _assess_commercial_readiness()
        self.assertGreaterEqual(dim.score_pct, 0.0)
        self.assertLessEqual(dim.score_pct, 100.0)
        self.assertGreater(dim.max_possible, 0)
        self.assertGreaterEqual(len(dim.findings), 1)

    def test_security_posture_returns_valid_score(self) -> None:
        dim = _assess_security_posture()
        self.assertGreaterEqual(dim.score_pct, 0.0)
        self.assertLessEqual(dim.score_pct, 100.0)
        self.assertGreater(dim.max_possible, 0)
        self.assertGreaterEqual(len(dim.findings), 1)

    def test_gaps_dimension_returns_valid_score(self) -> None:
        dim = _assess_gaps()
        self.assertGreaterEqual(dim.score_pct, 0.0)
        self.assertLessEqual(dim.score_pct, 100.0)
        self.assertGreater(dim.max_possible, 0)
        self.assertEqual(dim.name, "gaps_and_deficiencies")
        # Gap dimension must contain at least one "gap" verdict
        gap_findings = [f for f in dim.findings if f.verdict == "gap"]
        self.assertGreaterEqual(len(gap_findings), 1)

    def test_all_dimension_names_are_covered(self) -> None:
        result = run_assessment()
        dim_names = {d.name for d in result.dimensions}
        self.assertEqual(dim_names, set(DIMENSIONS))


# ══════════════════════════════════════════════════════════════════════
# Full assessment integration tests
# ══════════════════════════════════════════════════════════════════════


class FullAssessmentTests(unittest.TestCase):
    """End-to-end assessment result validation."""

    def test_run_assessment_returns_all_dimensions(self) -> None:
        result = run_assessment()
        self.assertEqual(len(result.dimensions), 5)

    def test_overall_score_is_within_range(self) -> None:
        result = run_assessment()
        self.assertGreaterEqual(result.overall_score_pct, 0.0)
        self.assertLessEqual(result.overall_score_pct, 100.0)

    def test_top_strengths_and_gaps_are_non_empty(self) -> None:
        result = run_assessment()
        self.assertIsInstance(result.top_strengths, list)
        self.assertIsInstance(result.critical_gaps, list)
        self.assertGreater(len(result.top_strengths), 0, "Expected at least one strength")
        self.assertGreater(len(result.critical_gaps), 0, "Expected at least one gap")

    def test_verdict_is_consistent_with_score(self) -> None:
        result = run_assessment()
        if result.overall_score_pct >= COMMERCIAL_VALUE_THRESHOLD_PCT:
            self.assertTrue(result.has_commercial_value)
            self.assertTrue(result.has_practical_value)
        elif result.overall_score_pct >= PRACTICAL_VALUE_THRESHOLD_PCT:
            self.assertFalse(result.has_commercial_value)
            self.assertTrue(result.has_practical_value)
        else:
            self.assertFalse(result.has_commercial_value)
            self.assertFalse(result.has_practical_value)

    def test_recommendation_is_not_empty(self) -> None:
        result = run_assessment()
        self.assertIsInstance(result.recommendation, str)
        self.assertGreater(len(result.recommendation.strip()), 20)

    def test_project_name_is_detected(self) -> None:
        name = _detect_project_name()
        self.assertIsInstance(name, str)
        self.assertGreater(len(name), 0)

    def test_use_case_is_detected(self) -> None:
        uc = _detect_use_case()
        self.assertIsInstance(uc, str)
        self.assertGreater(len(uc), 10)


# ══════════════════════════════════════════════════════════════════════
# Helper function tests
# ══════════════════════════════════════════════════════════════════════


class HelperTests(unittest.TestCase):
    """Tests for utilities and helpers."""

    def test_safe_read_handles_missing_file(self) -> None:
        result = _safe_read(Path("/nonexistent/path/definitely/not/there.txt"))
        self.assertEqual(result, "")

    def test_safe_read_handles_real_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.txt"
            path.write_text("hello world", encoding="utf-8")
            result = _safe_read(path)
            self.assertIn("hello", result)

    def test_thresholds_are_percentage_values(self) -> None:
        self.assertGreater(COMMERCIAL_VALUE_THRESHOLD_PCT, 50.0)
        self.assertLess(COMMERCIAL_VALUE_THRESHOLD_PCT, 100.0)
        self.assertGreater(PRACTICAL_VALUE_THRESHOLD_PCT, 30.0)
        self.assertLess(PRACTICAL_VALUE_THRESHOLD_PCT, 100.0)
        self.assertGreaterEqual(COMMERCIAL_VALUE_THRESHOLD_PCT, PRACTICAL_VALUE_THRESHOLD_PCT)


if __name__ == "__main__":
    unittest.main()
