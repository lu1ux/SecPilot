from fakes import (
    build_finding,
)
from secpilot.core.finding import (
    FindingSeverity,
    FindingStatus,
)
from secpilot.risk.engine import (
    RiskEngine,
)


def test_confirmed_high_confidence_keeps_base():

    finding = build_finding(
        status=(
            FindingStatus.CONFIRMED
        ),

        confidence=0.9,
    )

    RiskEngine().rate(
        finding
    )

    assert (
        finding.severity
        == FindingSeverity.HIGH
    )

    assert (
        finding.metadata[
            "risk_rationale"
        ]
    )

    assert (
        finding.metadata[
            "risk_rule"
        ]
        == "base_severity"
    )


def test_suspected_downgrades_one_level():

    finding = build_finding(
        status=(
            FindingStatus.SUSPECTED
        ),

        confidence=0.9,
    )

    RiskEngine().rate(
        finding
    )

    assert (
        finding.severity
        == FindingSeverity.MEDIUM
    )

    assert (
        finding.metadata[
            "risk_rule"
        ]
        == "suspected_downgrade"
    )


def test_confirmed_low_confidence_downgrades():

    finding = build_finding(
        status=(
            FindingStatus.CONFIRMED
        ),

        confidence=0.4,
    )

    RiskEngine().rate(
        finding
    )

    assert (
        finding.severity
        == FindingSeverity.MEDIUM
    )

    assert (
        finding.metadata[
            "risk_rule"
        ]
        == "confirmed_low_confidence"
    )


def test_rejected_becomes_info():

    finding = build_finding(
        status=(
            FindingStatus.REJECTED
        ),
    )

    RiskEngine().rate(
        finding
    )

    assert (
        finding.severity
        == FindingSeverity.INFO
    )

    assert (
        "否定"
        in finding.metadata[
            "risk_rationale"
        ]
    )

    assert (
        finding.metadata[
            "risk_rule"
        ]
        == "rejected"
    )


def test_unknown_vulnerability_type_defaults_low():

    finding = build_finding(
        vulnerability_type=(
            "mystery_bug"
        ),
    )

    RiskEngine().rate(
        finding
    )

    assert (
        finding.severity
        == FindingSeverity.LOW
    )

    assert (
        finding.metadata[
            "risk_rule"
        ]
        == "unknown_type_default"
    )


def test_already_rated_is_skipped():

    finding = build_finding(
        severity=(
            FindingSeverity.HIGH
        ),
    )

    RiskEngine().rate(
        finding
    )

    assert (
        finding.severity
        == FindingSeverity.HIGH
    )

    assert (
        finding.metadata[
            "risk_rule"
        ]
        == "already_rated"
    )


def test_rate_all_rates_every_finding():

    findings = [
        build_finding(),

        build_finding(
            status=(
                FindingStatus.REJECTED
            ),
        ),
    ]

    result = (
        RiskEngine()
        .rate_all(findings)
    )

    assert (
        result is findings
    )

    assert (
        findings[0].severity
        == FindingSeverity.HIGH
    )

    assert (
        findings[1].severity
        == FindingSeverity.INFO
    )
