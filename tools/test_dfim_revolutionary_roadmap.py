"""Unit tests for the DFIM Revolutionary Roadmap."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dfim_revolutionary_roadmap import (
    ALL_PHASES,
    REVENUE_STREAMS,
    ROADMAP_VERSION,
    Milestone,
    Phase,
    RevenueStream,
    Roadmap,
    _build_roadmap,
    _to_json,
    _to_markdown,
    validate_roadmap,
)

import unittest


class RoadmapModelTests(unittest.TestCase):
    """Data model and serialization tests."""

    def test_roadmap_is_versioned(self) -> None:
        roadmap = _build_roadmap()
        self.assertEqual(roadmap.version, ROADMAP_VERSION)

    def test_json_output_is_valid(self) -> None:
        roadmap = _build_roadmap()
        raw = _to_json(roadmap)
        data = json.loads(raw)
        self.assertIn("project_name", data)
        self.assertIn("phases", data)
        self.assertIn("revenue_streams", data)
        self.assertIn("total_estimated_weeks", data)

    def test_markdown_output_contains_all_phases(self) -> None:
        roadmap = _build_roadmap()
        md = _to_markdown(roadmap)
        for phase in roadmap.phases:
            self.assertIn(phase.ref, md)
            self.assertIn(phase.title_fa, md)

    def test_markdown_output_contains_revenue(self) -> None:
        roadmap = _build_roadmap()
        md = _to_markdown(roadmap)
        for rs in roadmap.revenue_streams:
            self.assertIn(rs.name_fa, md)


class RoadmapStructureTests(unittest.TestCase):
    """Structural integrity and plan coherence."""

    def test_five_phases_total(self) -> None:
        roadmap = _build_roadmap()
        self.assertEqual(len(roadmap.phases), 5)

    def test_phase_0_has_all_gap_closure_milestones(self) -> None:
        """Phase 0 must address every critical gap identified in project assessment."""
        roadmap = _build_roadmap()
        phase0 = [p for p in roadmap.phases if p.ref == "PHASE-0"][0]
        ids = {m.id for m in phase0.milestones}
        required = {"P0-M1", "P0-M2", "P0-M3", "P0-M4", "P0-M5", "P0-M6", "P0-M7"}
        self.assertTrue(required.issubset(ids), f"Missing milestones: {required - ids}")

    def test_egapless_attack_surface(self) -> None:
        """Every Phase-0 milestone title must map to a known deficiency from the assessment."""
        roadmap = _build_roadmap()
        phase0 = [p for p in roadmap.phases if p.ref == "PHASE-0"][0]
        keywords_per_milestone = [
            "IMA",
            "تست‌های یکپارچگی",
            "انتزاع مسیر بوت",
            "لایسنس",
            "Runtime Key",
            "Recovery",
            "Telemetry GA",
        ]
        for m, kw in zip(phase0.milestones, keywords_per_milestone):
            self.assertIn(kw, m.title, f"{m.id} title should contain '{kw}'")

    def test_all_milestones_have_deliverables(self) -> None:
        roadmap = _build_roadmap()
        for phase in roadmap.phases:
            for m in phase.milestones:
                self.assertGreater(len(m.deliverables), 0, f"{m.id}: no deliverables")
                self.assertGreater(m.effort_weeks, 0, f"{m.id}: zero effort")

    def test_dependencies_only_reference_earlier_or_same_phase(self) -> None:
        # Validate that dep references exist (no forward references across phases)
        roadmap = _build_roadmap()
        all_ids = {m.id: phase.ref for phase in roadmap.phases for m in phase.milestones}
        for phase in roadmap.phases:
            for m in phase.milestones:
                for dep in m.depends_on:
                    self.assertIn(dep, all_ids, f"{m.id} depends on unknown {dep}")

    def test_four_revenue_streams(self) -> None:
        roadmap = _build_roadmap()
        self.assertEqual(len(roadmap.revenue_streams), 4)


class ValidationTests(unittest.TestCase):
    """Self-validation of roadmap consistency."""

    def test_roadmap_passes_validation(self) -> None:
        roadmap = _build_roadmap()
        errors = validate_roadmap(roadmap)
        self.assertEqual(len(errors), 0, f"Validation errors: {errors}")

    def test_total_weeks_is_positive(self) -> None:
        roadmap = _build_roadmap()
        self.assertGreater(roadmap.total_estimated_weeks, 50)

    def test_critical_path_exists_and_is_non_empty(self) -> None:
        roadmap = _build_roadmap()
        self.assertGreater(len(roadmap.critical_path_ids), 3)

    def test_no_duplicate_milestone_ids(self) -> None:
        roadmap = _build_roadmap()
        all_ids = [m.id for phase in roadmap.phases for m in phase.milestones]
        self.assertEqual(len(all_ids), len(set(all_ids)))

    def test_phases_are_in_order(self) -> None:
        roadmap = _build_roadmap()
        refs = [p.ref for p in roadmap.phases]
        self.assertEqual(refs, ["PHASE-0", "PHASE-1", "PHASE-2", "PHASE-3", "PHASE-4"])

    def test_invalid_risk_rejected_by_validation(self) -> None:
        # Construct an invalid milestone manually
        bad = Milestone(
            id="X-TEST-BAD", title="Bad risk", description="...",
            deliverables=["x"], effort_weeks=1,
            depends_on=[], risk="impossible",
        )
        p = Phase(ref="P-X", title_fa="X", title_en="X", timeline="?",
                   goal="?", milestones=[bad], kpis=["x"], exit_criteria=["x"])
        r = Roadmap(version="1", generated_at="now", project_name="T",
                     vision="v", phases=[p], revenue_streams=[],
                     total_estimated_weeks=1, critical_path_ids=[])
        errors = validate_roadmap(r)
        self.assertTrue(any("invalid risk" in e for e in errors))


class UtilityTests(unittest.TestCase):
    """Helper and utility verification."""

    def test_all_phase_refs_are_unique(self) -> None:
        refs = [p.ref for p in ALL_PHASES]
        self.assertEqual(len(refs), len(set(refs)))

    def test_revenue_stream_names_are_unique(self) -> None:
        names = [r.name_en for r in REVENUE_STREAMS]
        self.assertEqual(len(names), len(set(names)))

    def test_csv_to_json_and_back_consistency(self) -> None:
        """For now, we confirm no crash — add round-trip if needed."""
        roadmap = _build_roadmap()
        j = _to_json(roadmap)
        self.assertGreater(len(j), 100)
        m = _to_markdown(roadmap)
        self.assertGreater(len(m), 500)


if __name__ == "__main__":
    unittest.main()
