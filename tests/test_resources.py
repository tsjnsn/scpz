"""Tests for scpz.optimizations.resources."""

from __future__ import annotations

from scpz.models import Statement
from scpz.optimizations.resources import optimize_resources


class TestResourceOptimization:
    def test_wildcard_absorbs_all(self) -> None:
        stmt = Statement(
            effect="Deny",
            action="s3:*",
            resource=["*", "arn:aws:s3:::mybucket"],
        )
        result = optimize_resources([stmt])
        assert result[0].resource == "*"

    def test_dedup_resources(self) -> None:
        stmt = Statement(
            effect="Deny",
            action="s3:*",
            resource=[
                "arn:aws:s3:::mybucket",
                "arn:aws:s3:::mybucket",
                "arn:aws:s3:::otherbucket",
            ],
        )
        result = optimize_resources([stmt])
        resources = result[0].resource_list
        assert len(resources) == 2

    def test_no_collapse_unrelated_names(self) -> None:
        """Roles with no shared name prefix must stay explicit."""
        stmt = Statement(
            effect="Deny",
            action="iam:*",
            resource=[
                "arn:aws:iam::123456789012:role/Admin",
                "arn:aws:iam::123456789012:role/ReadOnly",
                "arn:aws:iam::123456789012:role/Developer",
            ],
        )
        result = optimize_resources([stmt])
        resources = result[0].resource_list
        assert "arn:aws:iam::123456789012:role/*" not in resources
        assert len(resources) == 3

    def test_collapse_shared_prefix_names(self) -> None:
        """Roles sharing a name prefix collapse to that prefix wildcard."""
        stmt = Statement(
            effect="Deny",
            action="iam:*",
            resource=[
                "arn:aws:iam::123456789012:role/app-prod-1",
                "arn:aws:iam::123456789012:role/app-prod-2",
                "arn:aws:iam::123456789012:role/app-prod-3",
            ],
        )
        result = optimize_resources([stmt])
        resources = result[0].resource_list
        assert "arn:aws:iam::123456789012:role/app-prod-*" in resources
        assert len(resources) == 1

    def test_no_collapse_security_roles(self) -> None:
        """The security_guardrails example must not collapse to role/*."""
        stmt = Statement(
            effect="Deny",
            action="iam:*",
            resource=[
                "arn:aws:iam::123456789012:role/SecurityAdmin",
                "arn:aws:iam::123456789012:role/SecurityAudit",
                "arn:aws:iam::123456789012:role/SecurityReadOnly",
                "arn:aws:iam::123456789012:role/IncidentResponse",
                "arn:aws:iam::123456789012:role/OrganizationAdmin",
            ],
        )
        result = optimize_resources([stmt])
        resources = result[0].resource_list
        assert "arn:aws:iam::123456789012:role/*" not in resources
        assert len(resources) == 5

    def test_single_resource_unchanged(self) -> None:
        stmt = Statement(
            effect="Deny",
            action="s3:*",
            resource="arn:aws:s3:::mybucket",
        )
        result = optimize_resources([stmt])
        assert result[0].resource == "arn:aws:s3:::mybucket"

    def test_mixed_types_no_broad_wildcard(self) -> None:
        """Unrelated names in each type stay explicit, not collapsed to type/*."""
        stmt = Statement(
            effect="Deny",
            action="iam:*",
            resource=[
                "arn:aws:iam::123456789012:user/Admin",
                "arn:aws:iam::123456789012:user/ReadOnly",
                "arn:aws:iam::123456789012:role/Admin",
                "arn:aws:iam::123456789012:role/ReadOnly",
            ],
        )
        result = optimize_resources([stmt])
        resources = result[0].resource_list
        assert "arn:aws:iam::123456789012:user/*" not in resources
        assert "arn:aws:iam::123456789012:role/*" not in resources
        assert len(resources) == 4

    def test_mixed_types_shared_prefix_collapses(self) -> None:
        """Within a type, shared-prefix names do collapse."""
        stmt = Statement(
            effect="Deny",
            action="iam:*",
            resource=[
                "arn:aws:iam::123456789012:role/prod-app-1",
                "arn:aws:iam::123456789012:role/prod-app-2",
                "arn:aws:iam::123456789012:user/svc-deploy",
                "arn:aws:iam::123456789012:user/svc-runner",
            ],
        )
        result = optimize_resources([stmt])
        resources = result[0].resource_list
        assert "arn:aws:iam::123456789012:role/prod-app-*" in resources
        assert "arn:aws:iam::123456789012:user/svc-*" in resources
