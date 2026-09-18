"""Rubric 1.1 signal experiment: does each experimental signal improve rank correlation?

Rescores a findings snapshot that includes the stored experimental signals
(export.py, scans run with EXPERIMENTAL_SIGNALS_ENABLED=true) under many rubric
configurations and reports, against the same pre-registered labels:

1. baseline (no signals, identical to rubric 1.0), each signal alone, all signals,
   the process-dimension and dependency-health-target variants, and the best subset
   found by exhaustive search;
2. how many repositories each signal actually applied to;
3. an honest estimate of the best-subset search: the subset is re-selected inside
   bootstrap resamples and evaluated on the out-of-bag repositories;
4. collinearity: Spearman matrix across category scores and signal scores;
5. dimension weights fitted by non-negative least squares against the overall label,
   compared with the hand-picked weights, in sample and leave-one-out.

    cd backend && uv run python ../validation/rubric/signals_experiment.py \\
        ../validation/rubric/results/<date>-v1.1/findings.jsonl --out ../validation/rubric/results/<date>-v1.1
"""

import argparse
import csv
import json
import sys
from itertools import combinations
from pathlib import Path

import numpy as np
from scipy.optimize import nnls

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "backend"))

from report import DIMENSIONS, SEED, F, bootstrap_ci, spearman  # noqa: E402

from app.models import Severity  # noqa: E402
from app.services.scoring import rubric  # noqa: E402
from app.services.scoring.rubric import RubricConfig, ScoreContext  # noqa: E402

SIGNALS = ("error_handling", "dep_health", "git_history", "ci_quality", "test_quality")
GROUPS = ("vulnerable", "tutorial", "mature")
OOB_BOOTSTRAPS = 300


# ------------------------------------------------------------------ scoring


def score_all(snapshot: list[dict], config: RubricConfig) -> dict[str, dict]:
    out = {}
    for scan in snapshot:
        c = scan["context"]
        context = ScoreContext(
            source_loc=c["source_loc"],
            module_count=c["module_count"],
            analyzers_run=frozenset(c["analyzers_run"]),
            analyzers_failed=frozenset(c["analyzers_failed"]),
            signals=scan.get("signals") or {},
        )
        findings = [F(i, a, r, Severity(s), p, cb) for i, a, r, s, p, cb in scan["findings"]]
        report = rubric.score(findings, context, config=config)
        values: dict = {cat.category: cat.score for cat in report.categories}
        values["overall"] = report.overall
        out[scan["repo"]] = values
    return out


def correlations(scores: dict, labels: dict, repos: list[str] | None = None) -> dict[str, dict]:
    result = {}
    for dim in DIMENSIONS:
        pairs = [
            (float(labels[r][dim]), scores[r][dim])
            for r in (repos if repos is not None else scores)
            if scores[r].get(dim) is not None
        ]
        result[dim] = {"n": len(pairs), "rho": spearman([p[0] for p in pairs], [p[1] for p in pairs])}
    return result


def cliffs_delta(better: list[float], worse: list[float]) -> float | None:
    """P(better > worse) − P(better < worse): +1 = perfect separation in the right direction."""
    if not better or not worse:
        return None
    gt = sum(1 for b in better for w in worse if b > w)
    lt = sum(1 for b in better for w in worse if b < w)
    return (gt - lt) / (len(better) * len(worse))


def separation(scores: dict, groups: dict) -> dict:
    overall = {g: [scores[r]["overall"] for r in scores if groups[r] == g] for g in GROUPS}
    return {
        "median": {g: float(np.median(v)) if v else None for g, v in overall.items()},
        "delta_mature_vs_vulnerable": cliffs_delta(overall["mature"], overall["vulnerable"]),
        "delta_mature_vs_tutorial": cliffs_delta(overall["mature"], overall["tutorial"]),
        "delta_tutorial_vs_vulnerable": cliffs_delta(overall["tutorial"], overall["vulnerable"]),
    }


def configurations() -> list[tuple[str, RubricConfig]]:
    configs = [("baseline (no signals = rubric 1.0)", RubricConfig())]
    for signal in SIGNALS:
        configs.append((f"+ {signal}", RubricConfig(signals=frozenset({signal}))))
    configs.append(("+ dep_health → security", RubricConfig(signals=frozenset({"dep_health"}), dep_health_target="security")))
    for signal in ("git_history", "ci_quality"):
        configs.append(
            (f"+ {signal} (process dimension)", RubricConfig(signals=frozenset({signal}), process_dimension=True))
        )
    configs.append(("+ git_history + ci_quality (process dimension)",
                    RubricConfig(signals=frozenset({"git_history", "ci_quality"}), process_dimension=True)))
    configs.append(("+ git_history + ci_quality (in architecture)",
                    RubricConfig(signals=frozenset({"git_history", "ci_quality"}))))
    configs.append(("all signals (git/CI in architecture)", RubricConfig(signals=frozenset(SIGNALS))))
    configs.append(("all signals (process dimension)", RubricConfig(signals=frozenset(SIGNALS), process_dimension=True)))
    return configs


def all_subsets() -> list[RubricConfig]:
    out = []
    for size in range(0, len(SIGNALS) + 1):
        for subset in combinations(SIGNALS, size):
            for process in (False, True):
                if process and not {"git_history", "ci_quality"} & set(subset):
                    continue
                for target in ("dependencies", "security") if "dep_health" in subset else ("dependencies",):
                    out.append(RubricConfig(signals=frozenset(subset), process_dimension=process, dep_health_target=target))
    return out


# Components that measure how recently/actively a project is maintained. The
# pre-registered `dependencies` label was *defined* by last-commit date, so these
# leak the labelling criterion into the score; the leak-free variant drops them.
LEAKY_GIT = ("recency", "activity")


def without_git_recency(snapshot: list[dict]) -> list[dict]:
    out = json.loads(json.dumps(snapshot))
    for scan in out:
        git = (scan.get("signals") or {}).get("git_history")
        if git and git.get("applicable"):
            kept = [v for k, v in git["components"].items() if k not in LEAKY_GIT and v is not None]
            git["score"] = sum(kept) / len(kept) if kept else None
            git["components"] = {k: v for k, v in git["components"].items() if k not in LEAKY_GIT}
    return out


def overall_rho(scores: dict, labels: dict, repos: list[str]) -> float | None:
    return spearman([float(labels[r]["overall"]) for r in repos], [scores[r]["overall"] for r in repos])


# ------------------------------------------------------------------ main


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot")
    parser.add_argument("--labels", default=str(HERE / "labels.csv"))
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    snapshot = [json.loads(line) for line in Path(args.snapshot).read_text().splitlines() if line.strip()]
    with open(args.labels, newline="") as handle:
        labels = {row["repo"]: row for row in csv.DictReader(handle)}
    groups = {r: labels[r]["group"] for r in labels}
    repos = [s["repo"] for s in snapshot]

    snapshot_norec = without_git_recency(snapshot)
    python_repos = [
        scan["repo"] for scan in snapshot if "ruff" in scan["context"]["analyzers_run"]
    ]

    # 1. Configurations
    rows = []
    leak_free = [
        ("+ git_history without recency/activity", RubricConfig(signals=frozenset({"git_history"}))),
        ("+ git_history without recency/activity (process dimension)",
         RubricConfig(signals=frozenset({"git_history"}), process_dimension=True)),
    ]
    for name, config, snap in [
        *((n, c, snapshot) for n, c in configurations()),
        *((n, c, snapshot_norec) for n, c in leak_free),
    ]:
        scores = score_all(snap, config)
        corr = correlations(scores, labels)
        pairs = [(float(labels[r]["overall"]), scores[r]["overall"]) for r in repos]
        rows.append({
            "configuration": name,
            "config_key": config.key(),
            **{d: corr[d]["rho"] for d in DIMENSIONS},
            "n": {d: corr[d]["n"] for d in DIMENSIONS},
            "code_health_python_only": correlations(scores, labels, python_repos)["code_health"]["rho"],
            "overall_ci95": bootstrap_ci([p[0] for p in pairs], [p[1] for p in pairs]),
            "separation": separation(scores, groups),
        })

    # Paired bootstrap of Δρ (configuration − baseline) on the overall label.
    baseline_scores = score_all(snapshot, RubricConfig())
    all_configs = [*((n, c, snapshot) for n, c in configurations()), *((n, c, snapshot_norec) for n, c in leak_free)]
    rng_delta = np.random.default_rng(SEED)
    samples = [list(rng_delta.choice(repos, size=len(repos), replace=True)) for _ in range(2000)]
    for row, (_, config, snap) in zip(rows, all_configs, strict=True):
        scores = score_all(snap, config)
        deltas = []
        for sample in samples:
            a_ = overall_rho(scores, labels, sample)
            b_ = overall_rho(baseline_scores, labels, sample)
            if a_ is not None and b_ is not None:
                deltas.append(a_ - b_)
        row["delta_overall"] = {
            "point": (row["overall"] or 0) - (rows[0]["overall"] or 0),
            "ci95": [float(np.percentile(deltas, 2.5)), float(np.percentile(deltas, 97.5))],
            "p_improves": float(np.mean(np.array(deltas) > 0)),
        }

    # 2. Coverage: repos each signal applied to
    coverage = {
        s: {
            "applicable": sum(1 for scan in snapshot if (scan.get("signals") or {}).get(s, {}).get("applicable")),
            "collected": sum(1 for scan in snapshot if s in (scan.get("signals") or {})),
            "reasons": sorted({(scan.get("signals") or {}).get(s, {}).get("reason") or "" for scan in snapshot
                               if not (scan.get("signals") or {}).get(s, {}).get("applicable")} - {""}),
        }
        for s in (*SIGNALS, "advisory")
    }
    for scan in snapshot:
        adv = scan.get("advisory_metrics")
        if adv and adv.get("applicable"):
            coverage["advisory"]["applicable"] += 1

    # Raw signal score vs labels (does the signal itself rank repos?)
    signal_label_rho = {}
    for s in SIGNALS:
        present = [(r, scan["signals"][s]["score"]) for scan in snapshot for r in [scan["repo"]]
                   if (scan.get("signals") or {}).get(s, {}).get("applicable") and scan["signals"][s].get("score") is not None]
        signal_label_rho[s] = {
            dim: spearman([float(labels[r][dim]) for r, _ in present], [v for _, v in present])
            for dim in DIMENSIONS
        } | {"n": len(present)}

    # 3. Best subset, in sample and with out-of-bag re-selection
    subsets = all_subsets()
    subset_scores = {c.key(): score_all(snapshot, c) for c in subsets}
    # Ties go to the smaller configuration: a signal that doesn't change the ranking isn't kept.
    ranked = sorted(
        subsets,
        key=lambda c: (-(overall_rho(subset_scores[c.key()], labels, repos) or -1), len(c.signals), c.process_dimension, c.key()),
    )
    in_sample = [(overall_rho(subset_scores[c.key()], labels, repos) or -1, c.key()) for c in ranked]
    best_rho, best_key = in_sample[0]
    rng = np.random.default_rng(SEED)
    oob_selected, oob_baseline = [], []
    for _ in range(OOB_BOOTSTRAPS):
        bag = list(rng.choice(repos, size=len(repos), replace=True))
        out_of_bag = sorted(set(repos) - set(bag))
        if len(out_of_bag) < 4:
            continue
        chosen = min(
            subsets,
            key=lambda c: (-(overall_rho(subset_scores[c.key()], labels, bag) or -1), len(c.signals), c.key()),
        )
        selected = overall_rho(subset_scores[chosen.key()], labels, out_of_bag)
        baseline = overall_rho(subset_scores["base"], labels, out_of_bag)
        if selected is not None and baseline is not None:
            oob_selected.append(selected)
            oob_baseline.append(baseline)
    best_subset = {
        "in_sample": {"config": best_key, "overall_rho": best_rho},
        "top5_in_sample": [{"config": k, "overall_rho": v} for v, k in in_sample[:5]],
        "out_of_bag": {
            "bootstraps": len(oob_selected),
            "selected_mean_rho": float(np.mean(oob_selected)),
            "baseline_mean_rho": float(np.mean(oob_baseline)),
            "mean_improvement": float(np.mean(np.array(oob_selected) - np.array(oob_baseline))),
            "share_improved": float(np.mean(np.array(oob_selected) > np.array(oob_baseline))),
        },
    }
    norec_scores = {c.key(): score_all(snapshot_norec, c) for c in subsets}
    norec_ranked = sorted(
        subsets,
        key=lambda c: (-(overall_rho(norec_scores[c.key()], labels, repos) or -1), len(c.signals), c.process_dimension, c.key()),
    )
    rng2 = np.random.default_rng(SEED)
    sel2, base2 = [], []
    for _ in range(OOB_BOOTSTRAPS):
        bag = list(rng2.choice(repos, size=len(repos), replace=True))
        out_of_bag = sorted(set(repos) - set(bag))
        if len(out_of_bag) < 4:
            continue
        chosen = min(subsets, key=lambda c: (-(overall_rho(norec_scores[c.key()], labels, bag) or -1), len(c.signals), c.key()))
        a_, b_ = overall_rho(norec_scores[chosen.key()], labels, out_of_bag), overall_rho(norec_scores["base"], labels, out_of_bag)
        if a_ is not None and b_ is not None:
            sel2.append(a_)
            base2.append(b_)
    best_subset["leak_free"] = {
        "in_sample": {"config": norec_ranked[0].key(), "overall_rho": overall_rho(norec_scores[norec_ranked[0].key()], labels, repos)},
        "top5_in_sample": [{"config": c.key(), "overall_rho": overall_rho(norec_scores[c.key()], labels, repos)} for c in norec_ranked[:5]],
        "out_of_bag": {
            "bootstraps": len(sel2),
            "selected_mean_rho": float(np.mean(sel2)),
            "baseline_mean_rho": float(np.mean(base2)),
            "mean_improvement": float(np.mean(np.array(sel2) - np.array(base2))),
            "share_improved": float(np.mean(np.array(sel2) > np.array(base2))),
        },
    }
    best_config = next(c for c in subsets if c.key() == best_key)
    best_scores = subset_scores[best_key]
    best_corr = correlations(best_scores, labels)
    pairs = [(float(labels[r]["overall"]), best_scores[r]["overall"]) for r in repos]
    rows.append({
        "configuration": f"best subset (in-sample search): {best_key}",
        "config_key": best_key,
        **{d: best_corr[d]["rho"] for d in DIMENSIONS},
        "n": {d: best_corr[d]["n"] for d in DIMENSIONS},
        "code_health_python_only": correlations(best_scores, labels, python_repos)["code_health"]["rho"],
        "overall_ci95": bootstrap_ci([p[0] for p in pairs], [p[1] for p in pairs]),
        "separation": separation(best_scores, groups),
    })

    deltas = []
    for sample in samples:
        a_, b_ = overall_rho(best_scores, labels, sample), overall_rho(baseline_scores, labels, sample)
        if a_ is not None and b_ is not None:
            deltas.append(a_ - b_)
    rows[-1]["delta_overall"] = {
        "point": (rows[-1]["overall"] or 0) - (rows[0]["overall"] or 0),
        "ci95": [float(np.percentile(deltas, 2.5)), float(np.percentile(deltas, 97.5))],
        "p_improves": float(np.mean(np.array(deltas) > 0)),
        "note": "in-sample selection: optimistic, see out-of-bag check",
    }

    # 4. Collinearity
    base = subset_scores["base"]
    series: dict[str, dict[str, float]] = {
        f"category:{d}": {r: base[r][d] for r in repos if base[r].get(d) is not None}
        for d in ("security", "dependencies", "architecture", "code_health")
    }
    for s in SIGNALS:
        series[f"signal:{s}"] = {
            scan["repo"]: scan["signals"][s]["score"] for scan in snapshot
            if (scan.get("signals") or {}).get(s, {}).get("applicable") and scan["signals"][s].get("score") is not None
        }
    for part, keys in (("dep_health.supply", ("direct_count", "freshness", "transitive", "trivial")),
                       ("dep_health.hygiene", ("unused", "phantom"))):
        values = {}
        for scan in snapshot:
            comp = ((scan.get("signals") or {}).get("dep_health") or {}).get("components") or {}
            present = [comp[k] for k in keys if comp.get(k) is not None]
            if present:
                values[scan["repo"]] = sum(present) / len(present)
        series[f"signal:{part}"] = values
    names = list(series)
    matrix: dict[str, dict[str, dict]] = {}
    flagged = []
    for a in names:
        matrix[a] = {}
        for b in names:
            common = sorted(set(series[a]) & set(series[b]))
            rho = spearman([series[a][r] for r in common], [series[b][r] for r in common]) if len(common) >= 5 else None
            matrix[a][b] = {"rho": rho, "n": len(common)}
            own_part = a.startswith("signal:dep_health") and b.startswith("signal:dep_health")
            if a < b and rho is not None and abs(rho) > 0.8 and not own_part:
                flagged.append({"a": a, "b": b, "rho": rho, "n": len(common)})

    # 5. Weight fitting (NNLS on category scores against the overall label)
    def fit(feature_repos: list[str], dims: list[str], scores: dict) -> np.ndarray:
        X, y = [], []
        for r in feature_repos:
            present = [scores[r][d] for d in dims if scores[r].get(d) is not None]
            row_mean = sum(present) / len(present)
            X.append([(scores[r][d] if scores[r].get(d) is not None else row_mean) / 100 for d in dims])
            y.append(float(labels[r]["overall"]))
        X = np.hstack([np.array(X), np.ones((len(X), 1))])  # intercept column (unconstrained sign via shift)
        coef, _ = nnls(X, np.array(y) - min(y) + 1)
        weights = coef[:-1]
        return weights / weights.sum() if weights.sum() > 0 else np.full(len(dims), 1 / len(dims))

    def weighted(scores: dict, dims: list[str], weights: np.ndarray, repo: str) -> float:
        parts = [(scores[repo][d], w) for d, w in zip(dims, weights, strict=True) if scores[repo].get(d) is not None]
        total = sum(w for _, w in parts)
        return sum(v * w for v, w in parts) / total if total else 0.0

    def weight_comparison(scores: dict, dims: list[str], hand: dict[str, float]) -> dict:
        learned = fit(repos, dims, scores)
        hand_w = np.array([hand[d] for d in dims])
        loo = {}
        for r in repos:
            w = fit([x for x in repos if x != r], dims, scores)
            loo[r] = weighted(scores, dims, w, r)
        y = [float(labels[r]["overall"]) for r in repos]
        return {
            "dimensions": dims,
            "hand_picked": dict(zip(dims, hand_w.round(3).tolist(), strict=True)),
            "learned": dict(zip(dims, learned.round(3).tolist(), strict=True)),
            "rho_hand_picked": spearman(y, [weighted(scores, dims, hand_w, r) for r in repos]),
            "rho_learned_in_sample": spearman(y, [weighted(scores, dims, learned, r) for r in repos]),
            "rho_learned_leave_one_out": spearman(y, [loo[r] for r in repos]),
        }

    base_dims = ["security", "dependencies", "architecture", "code_health"]
    hand = {s.name: s.weight for s in rubric.CATEGORIES} | {"process": rubric.PROCESS_SPEC.weight}
    weights = {"baseline": weight_comparison(base, base_dims, hand)}
    if best_config.process_dimension:
        weights["best_subset"] = weight_comparison(best_scores, [*base_dims, "process"], hand)
    elif best_config.signals:
        weights["best_subset"] = weight_comparison(best_scores, base_dims, hand)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    result = {
        "configurations": rows,
        "coverage": coverage,
        "signal_vs_labels": signal_label_rho,
        "best_subset": best_subset,
        "collinearity": {"matrix": matrix, "flagged_over_0_8": flagged},
        "weights": weights,
    }
    (out / "signals-experiment.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    (out / "signals-experiment.md").write_text(render(result) + "\n")
    print(render(result))


def fmt(v: float | None, d: int = 2) -> str:
    return "n/a" if v is None else f"{v:.{d}f}"


def render(r: dict) -> str:
    lines = ["# Rubric 1.1 signal experiment", "", "## Configurations (Spearman ρ vs pre-registered labels)", "",
             "| Configuration | overall [95% CI] | Δ overall vs baseline [paired 95% CI] · P(Δ>0) | security | dependencies | architecture | code_health | code_health, same 13 Python repos | median vuln / tut / mature | Cliff's δ mature>vuln | mature>tut |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for row in r["configurations"]:
        ci = row["overall_ci95"]
        sep = row["separation"]
        med = sep["median"]
        lines.append(
            f"| {row['configuration']} | **{fmt(row['overall'])}** [{fmt(ci[0]) if ci else 'n/a'}, {fmt(ci[1]) if ci else 'n/a'}] | "
            + (f"{row['delta_overall']['point']:+.2f} [{row['delta_overall']['ci95'][0]:+.2f}, {row['delta_overall']['ci95'][1]:+.2f}] · {row['delta_overall']['p_improves']:.0%} | " if row.get("delta_overall") else "— | ")
            + " | ".join(f"{fmt(row[d])} (n={row['n'][d]})" for d in ("security", "dependencies", "architecture", "code_health"))
            + f" | {fmt(row.get('code_health_python_only'))}"
            + f" | {fmt(med['vulnerable'], 1)} / {fmt(med['tutorial'], 1)} / {fmt(med['mature'], 1)}"
            + f" | {fmt(sep['delta_mature_vs_vulnerable'])} | {fmt(sep['delta_mature_vs_tutorial'])} |"
        )
    lines += ["", "## Coverage: repositories each signal applied to", "", "| Signal | applicable | collected | reasons when not applicable |", "|---|---|---|---|"]
    for s, c in r["coverage"].items():
        lines.append(f"| {s} | {c['applicable']} | {c['collected']} | {'; '.join(c['reasons'])[:200]} |")
    lines += ["", "## Raw signal score vs labels (ρ, repos where applicable)", "", "| Signal | n | " + " | ".join(DIMENSIONS) + " |", "|---|---|" + "---|" * len(DIMENSIONS)]
    for s, v in r["signal_vs_labels"].items():
        lines.append(f"| {s} | {v['n']} | " + " | ".join(fmt(v[d]) for d in DIMENSIONS) + " |")
    b = r["best_subset"]
    lines += ["", "## Best subset", "",
              f"In-sample best: `{b['in_sample']['config']}` (overall ρ {fmt(b['in_sample']['overall_rho'])}).", "",
              "Top 5 in sample: " + "; ".join(f"`{t['config']}` {fmt(t['overall_rho'])}" for t in b["top5_in_sample"]), "",
              f"Out-of-bag check ({b['out_of_bag']['bootstraps']} bootstraps: select the best subset on the resample, evaluate on the left-out repos): "
              f"selected ρ {fmt(b['out_of_bag']['selected_mean_rho'])} vs baseline ρ {fmt(b['out_of_bag']['baseline_mean_rho'])}, "
              f"mean improvement {fmt(b['out_of_bag']['mean_improvement'])}, improved in {b['out_of_bag']['share_improved']:.0%} of resamples."]
    lf = b["leak_free"]
    lines += ["", "Same search with git_history's recency/activity removed (leak-free): "
              f"in-sample best `{lf['in_sample']['config']}` ({fmt(lf['in_sample']['overall_rho'])}); "
              "top 5: " + "; ".join(f"`{t['config']}` {fmt(t['overall_rho'])}" for t in lf["top5_in_sample"]) + ". "
              f"Out-of-bag: selected ρ {fmt(lf['out_of_bag']['selected_mean_rho'])} vs baseline {fmt(lf['out_of_bag']['baseline_mean_rho'])}, "
              f"mean improvement {fmt(lf['out_of_bag']['mean_improvement'])}, improved in {lf['out_of_bag']['share_improved']:.0%} of resamples."]
    m = r["collinearity"]["matrix"]
    names = list(m)
    short = [n.split(":", 1)[1] for n in names]
    lines += ["", "## Collinearity (Spearman ρ between signals; n = repos where both exist)", "",
              "| | " + " | ".join(short) + " |", "|---|" + "---|" * len(names)]
    for a, sa in zip(names, short, strict=True):
        lines.append(f"| {sa} | " + " | ".join(
            "—" if a == b_ else (f"**{fmt(m[a][b_]['rho'])}**" if m[a][b_]["rho"] is not None and abs(m[a][b_]["rho"]) > 0.8 else fmt(m[a][b_]["rho"]))
            for b_ in names) + " |")
    flagged = r["collinearity"]["flagged_over_0_8"]
    lines += ["", "Pairs above |0.8|: " + ("; ".join(f"{f['a']} × {f['b']} = {fmt(f['rho'])} (n={f['n']})" for f in flagged) or "none") + "."]
    lines += ["", "## Weights: hand-picked vs fitted (NNLS against the overall label)", ""]
    for name, w in r["weights"].items():
        lines += [f"**{name}**", "", "| Dimension | hand-picked | learned |", "|---|---|---|"]
        for d in w["dimensions"]:
            lines.append(f"| {d} | {w['hand_picked'][d]:.2f} | {w['learned'][d]:.2f} |")
        lines += ["", f"ρ with hand-picked weights {fmt(w['rho_hand_picked'])}; learned, in sample {fmt(w['rho_learned_in_sample'])}; "
                  f"learned, leave-one-out {fmt(w['rho_learned_leave_one_out'])}.", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
