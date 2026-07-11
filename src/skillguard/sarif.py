"""
SARIF 2.1.0 output for skillguard.

Converts SkillScanResult and BatchScanReport objects into a valid SARIF log
suitable for uploading to GitHub Advanced Security / the Security tab.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from typing import Any

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
_SARIF_VERSION = "2.1.0"
_TOOL_NAME = "skillguard"
_TOOL_VERSION = "1.0.0"
_TOOL_URI = "https://github.com/obielin/skillguard"

# Map skillguard Severity → SARIF level
_SEVERITY_TO_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _rule_to_sarif(rule: Any) -> dict[str, Any]:
    """Convert a skillguard Rule to a SARIF reportingDescriptor."""
    return {
        "id": rule.id,
        "name": rule.name,
        "shortDescription": {"text": rule.name},
        "fullDescription": {"text": rule.description},
        "help": {"text": rule.remediation, "markdown": rule.remediation},
        "properties": {
            "tags": list(rule.tags),
            "severity": rule.severity.value,
        },
    }


def _finding_to_results(finding: Any, artifact_uri: str) -> list[dict[str, Any]]:
    """
    Convert a Finding to one or more SARIF result objects.

    Each line number in finding.line_numbers becomes its own result location.
    If there are no line numbers a single result without a region is emitted.
    """
    level = _SEVERITY_TO_LEVEL.get(finding.severity.value, "warning")
    base: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": level,
        "message": {"text": finding.rule.description},
    }

    artifact_location: dict[str, Any] = {"uri": artifact_uri, "uriBaseId": "%SRCROOT%"}

    if finding.line_numbers:
        results = []
        for line_no in finding.line_numbers:
            result = dict(base)
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": artifact_location,
                        "region": {"startLine": line_no},
                    }
                }
            ]
            results.append(result)
        return results

    # No line number information — emit a single result pointing at line 1
    base["locations"] = [
        {
            "physicalLocation": {
                "artifactLocation": artifact_location,
                "region": {"startLine": 1},
            }
        }
    ]
    return [base]


def _skill_result_to_sarif_results(
    skill_result: Any,
) -> tuple[list[dict[str, Any]], list[Any]]:
    """
    Return (sarif_results, rules_used) for a single SkillScanResult.

    rules_used is a list of Rule objects (deduplicated by id) seen in this result.
    """
    # Use the skill_name as the artifact URI (relative path friendly)
    uri = skill_result.skill_name.replace("\\", "/")

    sarif_results: list[dict[str, Any]] = []
    rules_seen: dict[str, Any] = {}

    for finding in skill_result.findings:
        sarif_results.extend(_finding_to_results(finding, uri))
        if finding.rule_id not in rules_seen:
            rules_seen[finding.rule_id] = finding.rule

    return sarif_results, list(rules_seen.values())


def results_to_sarif(results: list[Any]) -> dict[str, Any]:
    """
    Convert a list of SkillScanResult objects to a SARIF 2.1.0 log dict.

    Parameters
    ----------
    results:
        One or more SkillScanResult objects (from scanner.scan_file / scan_text /
        scan_directory).

    Returns
    -------
    dict
        A SARIF log object ready for json.dumps().
    """
    all_sarif_results: list[dict[str, Any]] = []
    rules_by_id: dict[str, Any] = {}

    for skill_result in results:
        sarif_results, rules = _skill_result_to_sarif_results(skill_result)
        all_sarif_results.extend(sarif_results)
        for rule in rules:
            if rule.id not in rules_by_id:
                rules_by_id[rule.id] = rule

    driver_rules = [_rule_to_sarif(r) for r in rules_by_id.values()]

    sarif_log: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": _TOOL_VERSION,
                        "informationUri": _TOOL_URI,
                        "rules": driver_rules,
                    }
                },
                "results": all_sarif_results,
            }
        ],
    }
    return sarif_log


def batch_report_to_sarif(report: Any) -> dict[str, Any]:
    """
    Convert a BatchScanReport to a SARIF 2.1.0 log dict.

    Parameters
    ----------
    report:
        A BatchScanReport returned by scanner.scan_directory / scan_texts.

    Returns
    -------
    dict
        A SARIF log object ready for json.dumps().
    """
    return results_to_sarif(report.results)


def to_sarif_string(sarif_log: dict[str, Any], indent: int = 2) -> str:
    """Serialise a SARIF log dict to a JSON string."""
    return json.dumps(sarif_log, indent=indent)
