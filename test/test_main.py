"""
Unit tests for Kubernetes Security Hardening Pipeline.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.main import assess_workload, risk_level, WorkloadConfig


def safe_config(**overrides):
    """A fully hardened workload config — should score 0."""
    defaults = dict(
        workload_name="test-app",
        namespace="production",
        workload_type="Deployment",
        privileged_container=False,
        run_as_root=False,
        host_network=False,
        host_pid=False,
        writable_root_filesystem=False,
        no_resource_limits=False,
        no_liveness_probe=False,
        no_readiness_probe=False,
        default_service_account=False,
        no_security_context=False,
        latest_image_tag=False,
        no_network_policy=False,
    )
    defaults.update(overrides)
    return WorkloadConfig(**defaults)


class TestWorkloadAssessment:

    def test_fully_hardened_config_scores_zero(self):
        config = safe_config()
        score, violations, _ = assess_workload(config)
        assert score == 0
        assert violations == []

    def test_privileged_container_critical(self):
        config = safe_config(privileged_container=True)
        score, violations, remediations = assess_workload(config)
        assert score >= 40
        assert any("privileged" in v.lower() for v in violations)
        assert any("privileged" in r.lower() for r in remediations)

    def test_run_as_root_flagged(self):
        config = safe_config(run_as_root=True)
        score, violations, _ = assess_workload(config)
        assert any("root" in v.lower() for v in violations)
        assert score >= 35

    def test_host_network_flagged(self):
        config = safe_config(host_network=True)
        score, violations, _ = assess_workload(config)
        assert any("host network" in v.lower() for v in violations)

    def test_writable_filesystem_flagged(self):
        config = safe_config(writable_root_filesystem=True)
        score, violations, _ = assess_workload(config)
        assert any("writable" in v.lower() for v in violations)

    def test_no_resource_limits_flagged(self):
        config = safe_config(no_resource_limits=True)
        score, violations, _ = assess_workload(config)
        assert any("resource limits" in v.lower() for v in violations)

    def test_latest_image_tag_flagged(self):
        config = safe_config(latest_image_tag=True)
        score, violations, _ = assess_workload(config)
        assert any("latest" in v.lower() for v in violations)

    def test_multiple_violations_accumulate(self):
        config = safe_config(
            privileged_container=True,
            run_as_root=True,
            host_network=True,
            no_resource_limits=True,
        )
        score, violations, _ = assess_workload(config)
        assert score >= 70
        assert len(violations) >= 4

    def test_score_capped_at_100(self):
        config = WorkloadConfig(
            workload_name="worst-app",
            namespace="default",
            privileged_container=True,
            run_as_root=True,
            host_network=True,
            host_pid=True,
            writable_root_filesystem=True,
            no_resource_limits=True,
            no_liveness_probe=True,
            no_readiness_probe=True,
            default_service_account=True,
            no_security_context=True,
            latest_image_tag=True,
            no_network_policy=True,
        )
        score, _, _ = assess_workload(config)
        assert score <= 100

    def test_remediations_match_violations(self):
        config = safe_config(privileged_container=True, run_as_root=True)
        _, violations, remediations = assess_workload(config)
        assert len(violations) == len(remediations)


class TestRiskLevel:

    def test_score_0_is_low(self):
        assert risk_level(0) == "LOW"

    def test_score_20_to_39_is_medium(self):
        assert risk_level(20) == "MEDIUM"
        assert risk_level(39) == "MEDIUM"

    def test_score_40_to_69_is_high(self):
        assert risk_level(40) == "HIGH"
        assert risk_level(69) == "HIGH"

    def test_score_70_plus_is_critical(self):
        assert risk_level(70) == "CRITICAL"
        assert risk_level(100) == "CRITICAL"
