"""Dependency analyzer: OSV-Scanner against lockfiles/manifests, offline, in the sandbox.

One finding per (manifest, package, advisory group). OSV-Scanner groups advisories
that describe the same vulnerability (e.g. PYSEC + GHSA + CVE), so each group is
reported once.
"""

import dataclasses
import json
import logging
import re
from datetime import timedelta
from pathlib import Path
from typing import Any

from app.config import Settings, get_settings
from app.models import Severity
from app.services.analyzers.base import Analyzer, AnalyzerResult, FindingData, ScanContext
from app.services.analyzers.osv_db import detect_ecosystems, ensure_databases
from app.services.analyzers.sandbox import (
    OUTPUT_FILENAME,
    OUTPUT_MOUNT,
    AnalyzerOutputError,
    SandboxLimits,
    SandboxMount,
    run_tool,
)
from app.services.analyzers.snippets import normalize_path, strip_nul

logger = logging.getLogger(__name__)

ANALYZER_NAME = "dependency"
DB_MOUNT = "/db"

# 0 = no vulnerabilities, 1 = vulnerabilities found, 128 = no packages found.
_OK_EXIT_CODES = frozenset({0, 1, 128})

_DB_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.ERROR,
    "MODERATE": Severity.WARNING,
    "MEDIUM": Severity.WARNING,
    "LOW": Severity.INFO,
}
_SEVERITY_ORDER = list(Severity)
_MISSING_DB_PATTERN = re.compile(r"could not load db for (\S+) ecosystem")
_SUMMARY_MAX_CHARS = 200


def normalize_severity(
    cvss_score: object, database_severities: list[object] | None = None
) -> Severity:
    """CVSS base score -> severity (>=9 critical, >=7 error, >=4 warning, else info).

    Falls back to the advisory database's own label (GHSA's CRITICAL/HIGH/MODERATE/LOW),
    then to warning: a known vulnerability without a score is never "info".
    """
    try:
        score = float(str(cvss_score))
    except ValueError:
        score = None
    if score is not None and score > 0:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.ERROR
        if score >= 4.0:
            return Severity.WARNING
        return Severity.INFO

    labelled = [
        _DB_SEVERITY_MAP[label]
        for value in database_severities or []
        if (label := str(value).upper()) in _DB_SEVERITY_MAP
    ]
    if labelled:
        return max(labelled, key=_SEVERITY_ORDER.index)
    return Severity.WARNING


def _version_key(version: str) -> tuple[tuple[int, int | str], ...]:
    """Loose cross-ecosystem ordering: numeric parts numerically, others lexically."""
    key: list[tuple[int, int | str]] = []
    for part in re.findall(r"\d+|[A-Za-z]+", version):
        key.append((1, int(part)) if part.isdigit() else (0, part.lower()))
    return tuple(key)


def _normalize_package_name(name: str, ecosystem: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def fixed_versions(vulnerability: dict[str, Any], package: dict[str, Any]) -> list[str]:
    """Versions that fix `vulnerability` for this package, from ranges that include it."""
    name = _normalize_package_name(str(package.get("name", "")), str(package.get("ecosystem")))
    installed = _version_key(str(package.get("version", "")))
    fixes: list[str] = []
    for affected in vulnerability.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != package.get("ecosystem"):
            continue
        if _normalize_package_name(str(pkg.get("name", "")), str(pkg.get("ecosystem"))) != name:
            continue
        for version_range in affected.get("ranges") or []:
            if version_range.get("type") == "GIT":
                continue
            introduced: str | None = None
            for event in version_range.get("events") or []:
                if "introduced" in event:
                    introduced = str(event["introduced"])
                elif "fixed" in event and introduced is not None:
                    fixed = str(event["fixed"])
                    if (introduced == "0" or _version_key(introduced) <= installed) and (
                        installed < _version_key(fixed)
                    ):
                        fixes.append(fixed)
                    introduced = None
    return sorted(set(fixes), key=_version_key)


def _summary(vulnerabilities: list[dict[str, Any]]) -> str:
    for vuln in vulnerabilities:
        if summary := str(vuln.get("summary") or "").strip():
            return summary
    for vuln in vulnerabilities:
        if details := " ".join(str(vuln.get("details") or "").split()):
            first_sentence = details.split(". ")[0].rstrip(".")
            return first_sentence[:_SUMMARY_MAX_CHARS]
    return "Known vulnerability"


def _advisory_id(group: dict[str, Any]) -> str:
    """The most recognisable id: a CVE, else a GHSA, else OSV's first id."""
    ids = [str(i) for i in group.get("ids") or []]
    aliases = [str(a) for a in group.get("aliases") or []]
    for candidates, prefix in ((aliases, "CVE-"), (ids + aliases, "GHSA-")):
        matching = sorted(c for c in candidates if c.startswith(prefix))
        if matching:
            return matching[0]
    return ids[0] if ids else "unknown-advisory"


def _trim_vulnerability(vuln: dict[str, Any], package: dict[str, Any]) -> dict[str, Any]:
    """Keep what explains the finding; full OSV records (version lists, details) are huge."""
    return {
        "id": vuln.get("id"),
        "aliases": vuln.get("aliases"),
        "summary": vuln.get("summary"),
        "severity": vuln.get("severity"),
        "database_specific": {"severity": (vuln.get("database_specific") or {}).get("severity")},
        "fixed_versions": fixed_versions(vuln, package),
        "published": vuln.get("published"),
        "modified": vuln.get("modified"),
    }


def parse_osv_output(payload: dict[str, Any]) -> list[FindingData]:
    results = payload.get("results")
    if results is None:  # no package sources found
        return []
    if not isinstance(results, list):
        raise AnalyzerOutputError("OSV-Scanner output has an invalid results list.")

    findings: list[FindingData] = []
    for result in results:
        try:
            source_path = normalize_path(str(result["source"]["path"]))
            packages = result.get("packages") or []
        except (KeyError, TypeError) as exc:
            logger.warning("skipping malformed osv-scanner result: %r", exc)
            continue

        for entry in packages:
            package = entry.get("package") or {}
            name, version = str(package.get("name", "")), str(package.get("version", ""))
            ecosystem = str(package.get("ecosystem", ""))
            vulns_by_id = {str(v.get("id")): v for v in entry.get("vulnerabilities") or []}

            for group in entry.get("groups") or []:
                group_vulns = [vulns_by_id[i] for i in group.get("ids") or [] if i in vulns_by_id]
                if not group_vulns:
                    continue
                per_vuln_fixes = [fixed_versions(v, package) for v in group_vulns]
                # Upgrading must fix every advisory in the group: take the highest
                # of each advisory's lowest fixing version.
                fixed = (
                    max((fixes[0] for fixes in per_vuln_fixes), key=_version_key)
                    if all(per_vuln_fixes)
                    else None
                )
                all_fixes = sorted({v for fixes in per_vuln_fixes for v in fixes}, key=_version_key)
                advisory_id = _advisory_id(group)
                summary = _summary(group_vulns)
                fix_text = (
                    f"Upgrade to {fixed} or later." if fixed else "No fixed version is known."
                )

                findings.append(
                    FindingData(
                        analyzer=ANALYZER_NAME,
                        rule_id=strip_nul(advisory_id)[:512],
                        severity=normalize_severity(
                            group.get("max_severity"),
                            [
                                (v.get("database_specific") or {}).get("severity")
                                for v in group_vulns
                            ],
                        ),
                        file_path=strip_nul(source_path),
                        start_line=1,
                        end_line=1,
                        message=strip_nul(f"{name} {version}: {summary}. {fix_text}"),
                        category=f"vulnerable-dependency:{ecosystem}:{name}:{advisory_id}",
                        dependency=strip_nul(
                            {
                                "ecosystem": ecosystem,
                                "package": name,
                                "installed_version": version,
                                "advisory_id": advisory_id,
                                "aliases": sorted(
                                    {
                                        *map(str, group.get("ids") or []),
                                        *map(str, group.get("aliases") or []),
                                    }
                                ),
                                "fixed_version": fixed,
                                "fixed_versions": all_fixes,
                                "cvss_score": group.get("max_severity") or None,
                            }
                        ),
                        raw=strip_nul(
                            {
                                "source": result.get("source"),
                                "package": package,
                                "group": group,
                                "vulnerabilities": [
                                    _trim_vulnerability(v, package) for v in group_vulns
                                ],
                            }
                        ),
                    )
                )
    return findings


def locate_package_line(repo_path: Path, rel_path: str, package: str) -> int | None:
    """Line declaring `package` in a manifest/lockfile, for a useful location and snippet."""
    root = repo_path.resolve()
    path = (root / rel_path).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        return None
    escaped = re.escape(package)
    if path.name.startswith("requirements") or path.suffix in {".txt", ".in"}:
        flexible = re.sub(r"(\\[-_.])+", "[-_.]+", escaped)
        pattern = re.compile(rf"^\s*{flexible}\s*(\[|[=<>!~;@]|$)", re.IGNORECASE)
    elif path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
        # The installed package entry, not the root manifest's version range.
        pattern = re.compile(rf'"(\S*/)?node_modules/{escaped}"\s*:')
    else:
        # package-lock "node_modules/<name>", Cargo/poetry `name = "<name>"`, go.mod paths...
        pattern = re.compile(rf"""(["'/\s]|^){escaped}(["'@\s:]|$)""")
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, start=1):
                if pattern.search(line):
                    return lineno
    except OSError:
        return None
    return None


class DependencyAnalyzer(Analyzer):
    name = ANALYZER_NAME
    display_name = "OSV-Scanner"
    supported_languages = frozenset()  # lockfiles of any ecosystem

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self.docker_image = self._settings.osv_scanner_image
        self.timeout_seconds = self._settings.osv_scanner_timeout_seconds

    def run(self, repo_path: Path, context: ScanContext) -> AnalyzerResult:
        settings = self._settings
        db_root = Path(settings.scan_workspace_dir) / "_vulndb" / "osv"
        ecosystems = detect_ecosystems(repo_path)
        warnings = ensure_databases(
            ecosystems, db_root, timedelta(hours=settings.osv_db_max_age_hours)
        )
        db_root.mkdir(parents=True, exist_ok=True)

        logger.info("running osv-scanner for scan %s (%s)", context.scan_id, sorted(ecosystems))
        output = run_tool(
            display_name=self.display_name,
            image=settings.osv_scanner_image,
            entrypoint=["/osv-scanner"],
            command=[
                "scan",
                "source",
                "--recursive",
                "--offline",  # vulnerabilities from the mounted databases only
                "--no-resolve",  # transitive resolution would need a package registry
                "--no-call-analysis=all",  # Rust call analysis runs build scripts
                "--allow-no-lockfiles",
                "--format",
                "json",
                "--output",
                f"{OUTPUT_MOUNT}/{OUTPUT_FILENAME}",
                ".",
            ],
            environment={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": DB_MOUNT},
            repo_path=repo_path,
            output_dir=context.work_dir / f"{self.name}-out",
            extra_mounts=[SandboxMount(db_root, DB_MOUNT, read_only=True)],
            limits=SandboxLimits(
                cpus=settings.osv_scanner_cpus,
                memory=settings.osv_scanner_memory_limit,
                timeout_seconds=self.timeout_seconds,
            ),
            ok_exit_codes=_OK_EXIT_CODES,
            labels={"codeaudit.scan_id": context.scan_id, "codeaudit.analyzer": self.name},
        )

        for ecosystem in sorted(set(_MISSING_DB_PATTERN.findall(output.stderr))):
            warnings.append(
                f"No vulnerability database for {ecosystem}; its dependencies were not checked."
            )

        findings = []
        for finding in self.parse(output.raw_output):
            package = (finding.dependency or {}).get("package")
            line = locate_package_line(repo_path, finding.file_path, package) if package else None
            findings.append(
                dataclasses.replace(finding, start_line=line, end_line=line) if line else finding
            )
        return AnalyzerResult(
            analyzer=self.name,
            success=True,
            findings=findings,
            raw_output=output.raw_output,
            duration_ms=int(output.duration_seconds * 1000),
            warnings=tuple(warnings),
        )

    def parse(self, raw_output: str) -> list[FindingData]:
        if not raw_output.strip():
            return []
        try:
            payload = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise AnalyzerOutputError("OSV-Scanner produced invalid JSON output.") from exc
        if not isinstance(payload, dict):
            raise AnalyzerOutputError("OSV-Scanner output is not a JSON object.")
        return parse_osv_output(payload)
