"""Rank correlation between rubric scores and the pre-registered labels.

Rescores the findings snapshot with the rubric in the working tree (so a rubric
change can be evaluated against the same scans), then reports:

- Spearman rho per category and overall, with bootstrap 95% intervals
- rho within each group (vulnerable / tutorial / mature)
- inversions: pairs whose labels differ by >= 2 but whose scores disagree
- sensitivity of rho to every rubric parameter, varied one at a time

    cd backend && uv run python ../validation/rubric/report.py \\
        ../validation/rubric/results/20260918/findings.jsonl --out ../validation/rubric/results/20260918

Snapshot fidelity is checked: rescoring with the unmodified rubric must reproduce
the score the API stored (scans.jsonl next to the snapshot), or the report aborts.
"""

import argparse
import csv
import json
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from itertools import combinations
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.models import Severity
from app.services.scoring import rubric

HERE = Path(__file__).resolve().parent
DIMENSIONS = ("security", "dependencies", "architecture", "code_health", "overall")
BOOTSTRAP = 5000
SEED = 20260918


@dataclass(frozen=True)
class F:
    id: int
    analyzer: str
    rule_id: str
    severity: Severity
    file_path: str
    corroborated_by: list[str]


# ---------------------------------------------------------------- statistics


def _ranks(values: np.ndarray) -> np.ndarray:
    order = values.argsort(kind="mergesort")
    ranks = np.empty(len(values))
    sorted_values = values[order]
    i = 0
    while i < len(values):
        j = i
        while j + 1 < len(values) and sorted_values[j + 1] == sorted_values[i]:
            j += 1
        ranks[order[i : j + 1]] = (i + j) / 2 + 1
        i = j + 1
    return ranks


def spearman(x: list[float], y: list[float]) -> float | None:
    a, b = np.asarray(x, float), np.asarray(y, float)
    if len(a) < 3:
        return None
    ra, rb = _ranks(a), _ranks(b)
    if ra.std() == 0 or rb.std() == 0:
        return None
    return float(np.corrcoef(ra, rb)[0, 1])


def bootstrap_ci(x: list[float], y: list[float]) -> tuple[float, float] | None:
    rng = np.random.default_rng(SEED)
    a, b = np.asarray(x, float), np.asarray(y, float)
    values = []
    for _ in range(BOOTSTRAP):
        idx = rng.integers(0, len(a), len(a))
        rho = spearman(list(a[idx]), list(b[idx]))
        if rho is not None:
            values.append(rho)
    if len(values) < BOOTSTRAP * 0.9:
        return None
    return float(np.percentile(values, 2.5)), float(np.percentile(values, 97.5))


def permutation_p(x: list[float], y: list[float], observed: float) -> float:
    """One-sided p-value for rho >= observed under random label order."""
    rng = np.random.default_rng(SEED)
    b = np.asarray(y, float)
    hits = sum(
        1 for _ in range(BOOTSTRAP) if (spearman(x, list(rng.permutation(b))) or -1) >= observed - 1e-12
    )
    return (hits + 1) / (BOOTSTRAP + 1)


# ---------------------------------------------------------------- scoring


@contextmanager
def patched(**changes: object) -> Iterator[None]:
    saved = {name: getattr(rubric, name) for name in changes}
    try:
        for name, value in changes.items():
            setattr(rubric, name, value)
        if "CATEGORIES" in changes:
            rubric.CATEGORY_BY_ANALYZER = {
                a: spec for spec in rubric.CATEGORIES for a in spec.analyzers  # type: ignore[attr-defined]
            }
        yield
    finally:
        for name, value in saved.items():
            setattr(rubric, name, value)
        rubric.CATEGORY_BY_ANALYZER = {a: spec for spec in rubric.CATEGORIES for a in spec.analyzers}


def score_all(snapshot: list[dict]) -> dict[str, dict[str, float | None]]:
    out = {}
    for scan in snapshot:
        c = scan["context"]
        context = rubric.ScoreContext(
            source_loc=c["source_loc"],
            module_count=c["module_count"],
            analyzers_run=frozenset(c["analyzers_run"]),
            analyzers_failed=frozenset(c["analyzers_failed"]),
        )
        findings = [F(i, a, r, Severity(s), p, cb) for i, a, r, s, p, cb in scan["findings"]]
        report = rubric.score(findings, context)
        values: dict[str, float | None] = {c.category: c.score for c in report.categories}
        values["overall"] = report.overall
        values["incomplete"] = report.incomplete  # type: ignore[assignment]
        out[scan["repo"]] = values
    return out


def correlations(scores: dict, labels: dict, repos: list[str] | None = None) -> dict[str, dict]:
    result = {}
    for dim in DIMENSIONS:
        pairs = [
            (float(labels[r][dim]), scores[r][dim])
            for r in (repos or scores)
            if r in labels and scores[r].get(dim) is not None
        ]
        x, y = [p[0] for p in pairs], [p[1] for p in pairs]
        rho = spearman(x, y)
        result[dim] = {"n": len(pairs), "rho": rho}
    return result


# ---------------------------------------------------------------- sensitivity


def variants() -> list[tuple[str, Callable[[], object]]]:
    out: list[tuple[str, Callable[[], object]]] = []

    def cat_change(name: str, **fields: object) -> Callable[[], object]:
        cats = tuple(replace(c, **fields) if c.name == name else c for c in rubric.CATEGORIES)
        return lambda: patched(CATEGORIES=cats)

    for spec in rubric.CATEGORIES:
        for factor in (0.5, 1.5):
            out.append((f"{spec.name} weight ×{factor}", cat_change(spec.name, weight=spec.weight * factor)))
            out.append(
                (f"{spec.name} half-life ×{factor}", cat_change(spec.name, half_life=spec.half_life * factor))
            )
    for exponent in (0.5, 1.0):
        out.append((f"repeat damping exponent {exponent}", lambda e=exponent: patched(RULE_DAMPING_EXPONENT=e)))
    out.append(("no repeat damping (exponent 0)", lambda: patched(RULE_DAMPING_EXPONENT=0.0)))
    for factor in (0.05, 1.0):
        out.append((f"test-path factor {factor}", lambda f=factor: patched(TEST_PATH_FACTOR=f)))
    out.append(("corroboration factor 1.0", lambda: patched(CORROBORATION_FACTOR=1.0)))
    out.append(("equal category weights", lambda: patched(
        CATEGORIES=tuple(replace(c, weight=0.25) for c in rubric.CATEGORIES))))
    flat = {s: 1.0 for s in Severity}
    out.append(("flat severity weights", lambda: patched(
        CATEGORIES=tuple(replace(c, severity_weights=flat) for c in rubric.CATEGORIES))))
    out.append(("no size normalisation", lambda: patched(
        CATEGORIES=tuple(replace(c, size_normalized="none") for c in rubric.CATEGORIES))))
    return out


# ---------------------------------------------------------------- counterfactual experiments
# Candidate rubric changes, each motivated by a diagnosed inversion. They transform the
# snapshot (or patch the rubric) and are NOT what CodeAudit ships; see docs/validation.md.

import copy
import re

NON_PRODUCTION = re.compile(
    rubric._TEST_PATH.pattern + r"|(^|/)(examples?|docs?|demos?|samples?)(/|$)"
)


def exp_unpinned_not_assessed(snapshot: list[dict], lockfiles: dict) -> list[dict]:
    """E1: no lockfile / no pinned requirement -> dependencies not assessed (instead of 100)."""
    out = copy.deepcopy(snapshot)
    for scan in out:
        if not lockfiles.get(scan["repo"], {}).get("pinned", True):
            scan["context"]["analyzers_run"] = [a for a in scan["context"]["analyzers_run"] if a != "dependency"]
    return out


def exp_group_by_package(snapshot: list[dict]) -> list[dict]:
    """E2: advisories for one package form one rule (one upgrade fixes them), so repeats are damped."""
    out = copy.deepcopy(snapshot)
    for scan in out:
        packages = scan.get("dependency_packages", {})
        for f in scan["findings"]:
            if f[1] == "dependency" and str(f[0]) in packages:
                f[2] = packages[str(f[0])]
    return out


def exp_cycles_per_component(snapshot: list[dict]) -> list[dict]:
    """E4: one cycle finding per strongly connected component instead of one per enumerated cycle."""
    out = copy.deepcopy(snapshot)
    for scan in out:
        cycles = [f for f in scan["findings"] if f[1] == "architecture" and f[2].endswith("circular_dependency")]
        if not cycles:
            continue
        rest = [f for f in scan["findings"] if f not in cycles]
        next_id = max(f[0] for f in scan["findings"]) + 1
        synthetic = [
            [next_id + i, "architecture", "architecture/circular_dependency", c["severity"], f"component-{i}", []]
            for i, c in enumerate(scan.get("cycle_components", []))
        ]
        scan["findings"] = rest + synthetic
    return out


def experiments(snapshot: list[dict], lockfiles: dict) -> list[tuple[str, list[dict], dict]]:
    """(name, snapshot, rubric patches)."""
    e1 = exp_unpinned_not_assessed(snapshot, lockfiles)
    e2 = exp_group_by_package(snapshot)
    e4 = exp_cycles_per_component(snapshot)
    combined = exp_cycles_per_component(exp_group_by_package(exp_unpinned_not_assessed(snapshot, lockfiles)))
    return [
        ("E1 unpinned dependencies not assessed", e1, {}),
        ("E2 advisories grouped per package", e2, {}),
        ("E3 examples/docs weighted like tests", snapshot, {"_TEST_PATH": NON_PRODUCTION}),
        ("E4 cycles counted per component", e4, {}),
        ("E1–E4 combined", combined, {"_TEST_PATH": NON_PRODUCTION}),
    ]


# ---------------------------------------------------------------- report


def fmt(v: float | None, digits: int = 2) -> str:
    return "n/a" if v is None else f"{v:.{digits}f}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot")
    parser.add_argument("--labels", default=str(HERE / "labels.csv"))
    parser.add_argument("--corrections", default=str(HERE / "label_corrections.csv"))
    parser.add_argument("--out", required=True)
    parser.add_argument("--skip-fidelity-check", action="store_true",
                        help="use after a rubric change: stored API scores were produced by the old rubric")
    args = parser.parse_args()

    snapshot = [json.loads(line) for line in Path(args.snapshot).read_text().splitlines() if line.strip()]
    with open(args.labels, newline="") as handle:
        label_rows = {row["repo"]: row for row in csv.DictReader(handle)}
    corrections_used: list[dict] = []
    if Path(args.corrections).exists():
        with open(args.corrections, newline="") as handle:
            corrections_used = list(csv.DictReader(handle))
    groups = {repo: row["group"] for repo, row in label_rows.items()}

    scores = score_all(snapshot)

    # Fidelity: the snapshot must reproduce what the API stored.
    scans_file = Path(args.snapshot).with_name("scans.jsonl")
    if scans_file.exists() and not args.skip_fidelity_check:
        api = {
            r["repo"]: r["score"]["overall"]
            for r in map(json.loads, scans_file.read_text().splitlines())
            if r.get("score")
        }
        mismatched = {r: (api[r], scores[r]["overall"]) for r in api if abs((api[r] or 0) - (scores[r]["overall"] or 0)) > 0.01}
        if mismatched:
            sys.exit(f"snapshot does not reproduce the API scores: {mismatched}")

    def corrected(apply: bool) -> dict:
        labels = {r: dict(row) for r, row in label_rows.items()}
        if apply:
            for c in corrections_used:
                labels[c["repo"]][c["dimension"]] = c["new_label"]
        return labels

    labels = corrected(False)
    main_corr = correlations(scores, labels)
    for dim in DIMENSIONS:
        pairs = [(float(labels[r][dim]), scores[r][dim]) for r in scores if scores[r].get(dim) is not None]
        x, y = [p[0] for p in pairs], [p[1] for p in pairs]
        main_corr[dim]["ci95"] = bootstrap_ci(x, y)
        main_corr[dim]["p_one_sided"] = permutation_p(x, y, main_corr[dim]["rho"]) if main_corr[dim]["rho"] is not None else None

    by_group = {
        g: correlations(scores, labels, [r for r in scores if groups.get(r) == g])
        for g in ("vulnerable", "tutorial", "mature")
    }
    medians = {
        g: {dim: (float(np.median(v)) if (v := [scores[r][dim] for r in scores if groups.get(r) == g and scores[r].get(dim) is not None]) else None) for dim in DIMENSIONS}
        for g in ("vulnerable", "tutorial", "mature")
    }

    inversions = []
    for dim in DIMENSIONS:
        repos = [r for r in scores if scores[r].get(dim) is not None]
        for a, b in combinations(repos, 2):
            la, lb = float(labels[a][dim]), float(labels[b][dim])
            if abs(la - lb) < 2:
                continue
            hi, lo = (a, b) if la > lb else (b, a)
            if scores[hi][dim] < scores[lo][dim]:
                inversions.append({
                    "dimension": dim, "higher_label": hi, "lower_label": lo,
                    "labels": [float(labels[hi][dim]), float(labels[lo][dim])],
                    "scores": [round(scores[hi][dim], 1), round(scores[lo][dim], 1)],
                })

    sensitivity = []
    for name, make in variants():
        with make():  # type: ignore[attr-defined]
            s = score_all(snapshot)
        corr = correlations(s, labels)
        sensitivity.append({"variant": name, **{d: corr[d]["rho"] for d in DIMENSIONS}})

    corrected_corr = correlations(scores, corrected(True)) if corrections_used else None

    lockfiles_path = Path(args.snapshot).with_name("lockfiles.json")
    lockfiles = json.loads(lockfiles_path.read_text()) if lockfiles_path.exists() else {}
    experiment_rows = []
    experiment_scores = {}
    for name, variant, patches in experiments(snapshot, lockfiles):
        with patched(**patches):
            s = score_all(variant)
        corr = correlations(s, labels)
        row = {"experiment": name, **{d: corr[d]["rho"] for d in DIMENSIONS}, "n": {d: corr[d]["n"] for d in DIMENSIONS}}
        if name.startswith("E1–E4"):
            row["ci95"] = {}
            for d in DIMENSIONS:
                pairs = [(float(labels[r][d]), s[r][d]) for r in s if s[r].get(d) is not None]
                row["ci95"][d] = bootstrap_ci([p[0] for p in pairs], [p[1] for p in pairs])
            row["within_group"] = {
                g: correlations(s, labels, [r for r in s if groups.get(r) == g]) for g in ("vulnerable", "tutorial", "mature")
            }
            n_inv = 0
            for d in DIMENSIONS:
                repos = [r for r in s if s[r].get(d) is not None]
                for a, b in combinations(repos, 2):
                    la, lb = float(labels[a][d]), float(labels[b][d])
                    if abs(la - lb) >= 2 and ((la > lb) != (s[a][d] > s[b][d])) and s[a][d] != s[b][d]:
                        n_inv += 1
            row["inversions"] = n_inv
        experiment_rows.append(row)
        experiment_scores[name] = s

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    metrics = {
        "rubric_version": rubric.RUBRIC_VERSION,
        "n_scans": len(scores),
        "correlations": main_corr,
        "by_group": by_group,
        "group_medians": medians,
        "inversions": inversions,
        "sensitivity": sensitivity,
        "label_corrections": corrections_used,
        "correlations_with_corrections": corrected_corr,
        "experiments": experiment_rows,
        "experiment_scores": experiment_scores,
        "scores": scores,
    }
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n")

    lines = [
        f"# Rubric validation (rubric v{rubric.RUBRIC_VERSION})",
        "",
        f"{len(scores)} repositories scored; labels from `labels.csv` (pre-registered). "
        f"Bootstrap: {BOOTSTRAP} resamples, seed {SEED}. p: one-sided permutation test.",
        "",
        "## Spearman ρ, label vs score",
        "",
        "| Dimension | n | ρ | 95% CI | p |",
        "|---|---|---|---|---|",
    ]
    for dim in DIMENSIONS:
        c = main_corr[dim]
        ci = c.get("ci95")
        lines.append(
            f"| {dim} | {c['n']} | **{fmt(c['rho'])}** | "
            f"{'n/a' if not ci else f'{ci[0]:.2f} – {ci[1]:.2f}'} | {fmt(c.get('p_one_sided'), 4)} |"
        )
    lines += ["", "## Within groups (the stricter test)", "", "| Group | " + " | ".join(DIMENSIONS) + " |",
              "|---|" + "---|" * len(DIMENSIONS)]
    for g, corr in by_group.items():
        lines.append(f"| {g} | " + " | ".join(f"{fmt(corr[d]['rho'])} (n={corr[d]['n']})" for d in DIMENSIONS) + " |")
    lines += ["", "## Median score per group", "", "| Group | " + " | ".join(DIMENSIONS) + " |",
              "|---|" + "---|" * len(DIMENSIONS)]
    for g, med in medians.items():
        lines.append(f"| {g} | " + " | ".join(fmt(med[d], 1) for d in DIMENSIONS) + " |")
    lines += ["", "## Scores", "", "| Repository | Group | " + " | ".join(DIMENSIONS) + " | labels |",
              "|---|---|" + "---|" * (len(DIMENSIONS) + 1)]
    for repo in sorted(scores, key=lambda r: -(scores[r]["overall"] or 0)):
        s = scores[repo]
        lab = "/".join(labels[repo][d] for d in DIMENSIONS)
        lines.append(f"| {repo} | {groups[repo]} | " + " | ".join(fmt(s[d], 1) for d in DIMENSIONS) + f" | {lab} |")
    lines += ["", f"Labels column order: {', '.join(DIMENSIONS)}.", "",
              f"## Inversions (labels differ by ≥ 2, scores disagree): {len(inversions)}", ""]
    for inv in inversions:
        lines.append(
            f"- **{inv['dimension']}**: {inv['higher_label']} (label {inv['labels'][0]:g}, score {inv['scores'][0]}) "
            f"< {inv['lower_label']} (label {inv['labels'][1]:g}, score {inv['scores'][1]})"
        )
    lines += ["", "## Sensitivity (ρ with one parameter changed)", "",
              "| Variant | " + " | ".join(DIMENSIONS) + " |", "|---|" + "---|" * len(DIMENSIONS),
              "| **as shipped** | " + " | ".join(fmt(main_corr[d]["rho"]) for d in DIMENSIONS) + " |"]
    for row in sensitivity:
        lines.append(f"| {row['variant']} | " + " | ".join(fmt(row[d]) for d in DIMENSIONS) + " |")
    if experiment_rows:
        lines += ["", "## Counterfactual experiments (not shipped; same labels, same snapshot)", "",
                  "| Experiment | " + " | ".join(DIMENSIONS) + " |", "|---|" + "---|" * len(DIMENSIONS),
                  "| **as shipped (v" + rubric.RUBRIC_VERSION + ")** | " + " | ".join(fmt(main_corr[d]["rho"]) for d in DIMENSIONS) + " |"]
        for row in experiment_rows:
            lines.append(f"| {row['experiment']} | " + " | ".join(
                f"{fmt(row[d])}" + (f" (n={row['n'][d]})" if row["n"][d] != main_corr[d]["n"] else "") for d in DIMENSIONS) + " |")
        combined = experiment_rows[-1]
        lines += ["", "Combined, with 95% bootstrap CIs: " + "; ".join(
            f"{d} {fmt(combined[d])} [{'n/a' if not combined['ci95'][d] else f'{combined['ci95'][d][0]:.2f}, {combined['ci95'][d][1]:.2f}'}]"
            for d in DIMENSIONS) + f". Inversions: {combined['inversions']} (as shipped: {len(inversions)}).", "",
            "Combined, within groups: " + "; ".join(
                f"{g}: overall {fmt(c['overall']['rho'])}, security {fmt(c['security']['rho'])}" for g, c in combined["within_group"].items()) + "."]
    if corrected_corr:
        lines += ["", "## With label corrections", "", "| Dimension | ρ (original labels) | ρ (corrected) |", "|---|---|---|"]
        for d in DIMENSIONS:
            lines.append(f"| {d} | {fmt(main_corr[d]['rho'])} | {fmt(corrected_corr[d]['rho'])} |")
    resolution = {
        scan["repo"]: scan.get("import_resolution") or {} for scan in snapshot if scan.get("import_resolution")
    }
    if resolution:
        coverages = sorted((r.get("coverage"), repo) for repo, r in resolution.items() if r.get("coverage") is not None)
        values = [c for c, _ in coverages]
        metrics["import_resolution"] = {
            "median": float(np.median(values)), "min": min(values), "per_repo": {r: c for c, r in coverages},
            "unresolved_by_reason": {repo: r.get("unresolved_by_reason") for repo, r in resolution.items()},
        }
        (out / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n")
        lines += ["", "## Import resolution coverage (architecture analyzer)", "",
                  f"Median {np.median(values):.1%}, lowest {min(values):.1%}.", "",
                  "| Repository | Coverage | Unresolved by reason |", "|---|---|---|"]
        for c, repo in coverages:
            lines.append(f"| {repo} | {c:.1%} | {json.dumps(resolution[repo].get('unresolved_by_reason') or {})} |")
    (out / "report.md").write_text("\n".join(lines) + "\n")
    print((out / "report.md").read_text())


if __name__ == "__main__":
    main()
