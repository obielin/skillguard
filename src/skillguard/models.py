"""Data models for skillguard scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from skillguard.rules import Rule, Severity


@dataclass
class Finding:
    """A single security finding from a rule match."""

    rule: Rule
    snippets: list[str]
    line_numbers: list[int] = field(default_factory=list)

    @property
    def rule_id(self) -> str:
        return self.rule.id

    @property
    def severity(self) -> Severity:
        return self.rule.severity

    @property
    def name(self) -> str:
        return self.rule.name

    def __repr__(self) -> str:
        return f"Finding({self.rule_id}, {self.severity.value}: {self.name})"


@dataclass
class SkillScanResult:
    """
    Scan result for a single skill file or text blob.

    Attributes:
        skill_name:    Name of the skill (filename or provided name)
        findings:      All security findings detected
        risk_score:    0-100 composite risk score
        risk_level:    CRITICAL / HIGH / MEDIUM / LOW / SAFE
        scan_time_ms:  Time taken to scan
        line_count:    Total lines in the skill
        char_count:    Total characters in the skill
        error:         Any error encountered during scanning
    """

    skill_name: str
    findings: list[Finding]
    risk_score: float
    risk_level: str
    scan_time_ms: float = 0.0
    line_count: int = 0
    char_count: int = 0
    error: str = ""

    @property
    def is_safe(self) -> bool:
        return self.risk_level == "SAFE"

    @property
    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def summary_line(self) -> str:
        icon = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "SAFE": "SAFE",
        }.get(self.risk_level, "?")
        return (
            f"[{icon}] {self.skill_name} "
            f"(score={self.risk_score:.0f}/100, "
            f"{self.finding_count} finding(s))"
        )

    def __repr__(self) -> str:
        return (
            f"SkillScanResult({self.skill_name!r}, "
            f"{self.risk_level}, "
            f"score={self.risk_score:.0f}, "
            f"findings={self.finding_count})"
        )


@dataclass
class BatchScanReport:
    """
    Report for scanning multiple skills at once.

    Attributes:
        results:        Per-skill scan results
        total_scanned:  Total number of skills scanned
        safe_count:     Skills with no findings
        flagged_count:  Skills with at least one finding
        critical_count: Skills with critical findings
    """

    results: list[SkillScanResult]
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_scanned(self) -> int:
        return len(self.results)

    @property
    def safe_count(self) -> int:
        return sum(1 for r in self.results if r.is_safe)

    @property
    def flagged_count(self) -> int:
        return sum(1 for r in self.results if not r.is_safe)

    @property
    def critical_count(self) -> int:
        return sum(1 for r in self.results if r.risk_level == "CRITICAL")

    @property
    def flag_rate(self) -> float:
        return round(self.flagged_count / self.total_scanned, 4) if self.total_scanned else 0.0

    @property
    def critical_findings_total(self) -> list[Finding]:
        findings = []
        for r in self.results:
            findings.extend(r.critical_findings)
        return findings

    def summary(self) -> str:
        lines = [
            "",
            "=" * 64,
            "  SKILLGUARD -- BATCH SCAN REPORT",
            "=" * 64,
            f"  Skills scanned:   {self.total_scanned}",
            f"  Safe:             {self.safe_count}",
            f"  Flagged:          {self.flagged_count}",
            f"  Critical:         {self.critical_count}",
            f"  Flag rate:        {self.flag_rate:.0%}",
            "-" * 64,
        ]
        by_level: dict[str, list[SkillScanResult]] = {}
        for r in self.results:
            by_level.setdefault(r.risk_level, []).append(r)

        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if level in by_level:
                lines.append(f"  {level} RISK ({len(by_level[level])})")
                for r in by_level[level][:5]:
                    lines.append(f"    [{r.risk_score:.0f}] {r.skill_name}")
                    for f in r.findings[:2]:
                        lines.append(f"         -> {f.rule_id}: {f.name}")
                if len(by_level.get(level, [])) > 5:
                    lines.append(f"    ... and {len(by_level[level]) - 5} more")

        lines += ["=" * 64, ""]
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"BatchScanReport({self.total_scanned} skills, "
            f"{self.flagged_count} flagged, "
            f"{self.critical_count} critical)"
        )
