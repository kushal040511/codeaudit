"""Metrics for a validation run: precision/recall/F1, ROC, per-signal weight, false positives.

    python validation/phishing/report.py validation/phishing/data/dataset-20260917.results.jsonl \\
        --out validation/phishing/results/20260917

Only rows in state `ok` are scored; every other state is counted and reported.

Label leakage: positives come from OpenPhish, which is also a reputation signal, and
many are listed by Safe Browsing too. Headline metrics therefore EXCLUDE reputation
signals ("without reputation"); the full score is reported separately and says little
about detecting phishing that isn't listed yet.

URLs are defanged (hxxps://evil[.]example) in everything written.
"""

import argparse
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np

LEVEL_THRESHOLDS = {"moderate": 20, "high": 45, "very_high": 70}


def defang(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").replace(".", "[.]")
    scheme = parts.scheme.replace("http", "hxxp")
    path = parts.path if len(parts.path) < 60 else parts.path[:57] + "..."
    return f"{scheme}://{host}{path}"


def score_without_reputation(record: dict) -> int:
    total = sum(e["points"] for e in record["evidence"] if e["category"] != "reputation")
    return int(round(max(0.0, min(100.0, total))))


def confusion(scores: list[int], labels: list[int], threshold: float) -> dict:
    tp = sum(1 for s, y in zip(scores, labels, strict=True) if s >= threshold and y == 1)
    fp = sum(1 for s, y in zip(scores, labels, strict=True) if s >= threshold and y == 0)
    fn = sum(1 for s, y in zip(scores, labels, strict=True) if s < threshold and y == 1)
    tn = sum(1 for s, y in zip(scores, labels, strict=True) if s < threshold and y == 0)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else None
    return {"threshold": threshold, "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall, "f1": f1, "fpr": fpr}


def roc(scores: list[int], labels: list[int]) -> tuple[list[dict], float]:
    points = [confusion(scores, labels, t) for t in range(0, 102)]
    curve = sorted(((p["fpr"] or 0.0, p["recall"] or 0.0) for p in points))
    curve = [(0.0, 0.0), *curve, (1.0, 1.0)]
    auc = sum((x2 - x1) * (y1 + y2) / 2 for (x1, y1), (x2, y2) in zip(curve, curve[1:], strict=False))
    return points, auc


def roc_svg(curves: dict[str, list[dict]], path: Path) -> None:
    size, pad = 360, 40
    colors = ["#2563eb", "#dc2626"]
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size + 2 * pad}" height="{size + 2 * pad}" font-family="sans-serif" font-size="11">',
        f'<rect x="{pad}" y="{pad}" width="{size}" height="{size}" fill="white" stroke="#999"/>',
        f'<line x1="{pad}" y1="{pad + size}" x2="{pad + size}" y2="{pad}" stroke="#ccc" stroke-dasharray="4 3"/>',
        f'<text x="{pad + size / 2}" y="{pad + size + 28}" text-anchor="middle">False positive rate</text>',
        f'<text x="12" y="{pad + size / 2}" text-anchor="middle" transform="rotate(-90 12 {pad + size / 2})">True positive rate (recall)</text>',
    ]
    for index, (name, points) in enumerate(curves.items()):
        coords = sorted({((p["fpr"] or 0.0), (p["recall"] or 0.0)) for p in points})
        coords = [(0.0, 0.0), *coords, (1.0, 1.0)]
        polyline = " ".join(f"{pad + x * size:.1f},{pad + size - y * size:.1f}" for x, y in coords)
        lines.append(f'<polyline fill="none" stroke="{colors[index % 2]}" stroke-width="2" points="{polyline}"/>')
        lines.append(f'<text x="{pad + 10}" y="{pad + 18 + index * 16}" fill="{colors[index % 2]}">{name}</text>')
    lines.append("</svg>")
    path.write_text("\n".join(lines))


def logistic_weights(records: list[dict], signals: list[str], l2: float = 1.0) -> dict[str, float]:
    x = np.array([[1.0 if any(e["signal"] == s and e["status"] == "fired" for e in r["evidence"]) else 0.0 for s in signals] for r in records])
    y = np.array([r["label"] for r in records], dtype=float)
    weights = np.zeros(len(signals))
    bias = 0.0
    for _ in range(4000):
        z = x @ weights + bias
        p = 1 / (1 + np.exp(-z))
        gradient = x.T @ (p - y) / len(y) + l2 * weights / len(y)
        weights -= 0.5 * gradient
        bias -= 0.5 * float(np.mean(p - y))
    return {s: round(float(w), 3) for s, w in zip(signals, weights, strict=True)} | {"(intercept)": round(bias, 3)}


def signal_table(records: list[dict]) -> list[dict]:
    positives = [r for r in records if r["label"] == 1]
    negatives = [r for r in records if r["label"] == 0]
    fired_signals = sorted({e["signal"] for r in records for e in r["evidence"] if e["status"] == "fired"})
    base_scores = [score_without_reputation(r) for r in records]
    labels = [r["label"] for r in records]
    _, base_auc = roc(base_scores, labels)
    coefficients = logistic_weights(records, fired_signals)
    table = []
    for signal in fired_signals:
        def fires(r: dict, signal: str = signal) -> bool:
            return any(e["signal"] == signal and e["status"] == "fired" for e in r["evidence"])

        in_pos = sum(fires(r) for r in positives)
        in_neg = sum(fires(r) for r in negatives)
        pos_rate = in_pos / len(positives) if positives else 0.0
        neg_rate = in_neg / len(negatives) if negatives else 0.0
        category = next(e["category"] for r in records for e in r["evidence"] if e["signal"] == signal)
        points = next(e["points"] for r in records for e in r["evidence"] if e["signal"] == signal and e["status"] == "fired")
        # Ablation: AUC of the (non-reputation) score without this signal's points.
        ablated = [
            int(round(max(0.0, min(100.0, sum(e["points"] for e in r["evidence"] if e["category"] != "reputation" and e["signal"] != signal)))))
            for r in records
        ]
        _, ablated_auc = roc(ablated, labels)
        precision = in_pos / (in_pos + in_neg) if in_pos + in_neg else None
        if category == "reputation":
            verdict = "leaks labels (excluded from headline metrics)"
        elif in_pos + in_neg < 3:
            verdict = "too rare to judge"
        elif points < 0 and pos_rate < neg_rate:
            verdict = "predictive (trust signal)" if base_auc - ablated_auc >= 0.005 else "weak trust signal"
        elif points < 0:
            verdict = "harmful (a trust signal that fires as often on phishing)"
        elif neg_rate >= pos_rate:
            verdict = "noise or harmful (fires at least as often on legitimate sites)"
        elif base_auc - ablated_auc >= 0.005:
            verdict = "predictive"
        elif pos_rate / max(neg_rate, 1e-9) >= 3:
            verdict = "discriminative but redundant with other signals"
        else:
            verdict = "weak"
        table.append({
            "signal": signal,
            "category": category,
            "points": points,
            "fires_on_phishing": round(pos_rate, 3),
            "fires_on_legitimate": round(neg_rate, 3),
            "precision_when_fired": None if precision is None else round(precision, 3),
            "auc_drop_without_signal": round(base_auc - ablated_auc, 4),
            "logistic_coefficient": coefficients.get(signal),
            "verdict": verdict,
        })
    return sorted(table, key=lambda row: -row["auc_drop_without_signal"])


def fmt(value: float | None, digits: int = 3) -> str:
    return "n/a" if value is None or (isinstance(value, float) and math.isnan(value)) else f"{value:.{digits}f}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    records = [json.loads(line) for line in args.results.read_text().splitlines() if line.strip()]
    states: dict[int, Counter[str]] = defaultdict(Counter)
    reasons: Counter[str] = Counter()
    for r in records:
        states[r["label"]][r["state"]] += 1
        if r["state"] != "ok":
            reasons[f"{r['state']}: {(r.get('reason') or '')[:70]}"] += 1
    ok = [r for r in records if r["state"] == "ok"]
    labels = [r["label"] for r in ok]
    variants = {
        "without reputation": [score_without_reputation(r) for r in ok],
        "full score": [r["score"] for r in ok],
    }
    metrics: dict = {"counts": {str(k): dict(v) for k, v in states.items()}, "variants": {}}
    curves = {}
    for name, scores in variants.items():
        points, auc = roc(scores, labels)
        best = max(points, key=lambda p: p["f1"])
        metrics["variants"][name] = {
            "auc": round(auc, 4),
            "best_f1": best,
            "at_levels": {level: confusion(scores, labels, t) for level, t in LEVEL_THRESHOLDS.items()},
        }
        curves[name] = points
        with (args.out / f"roc-{name.replace(' ', '_')}.csv").open("w") as fh:
            fh.write("threshold,tpr,fpr,precision,f1\n")
            for p in points:
                fh.write(f"{p['threshold']},{fmt(p['recall'])},{fmt(p['fpr'])},{fmt(p['precision'])},{fmt(p['f1'])}\n")
    roc_svg(curves, args.out / "roc.svg")
    signals = signal_table(ok)
    metrics["signals"] = signals

    headline = variants["without reputation"]
    fp_threshold = LEVEL_THRESHOLDS["high"]
    best_threshold = metrics["variants"]["without reputation"]["best_f1"]["threshold"]
    false_positives = sorted(
        (r for r, s in zip(ok, headline, strict=True) if r["label"] == 0 and s >= min(fp_threshold, best_threshold)),
        key=lambda r: -score_without_reputation(r),
    )
    false_negatives = [r for r, s in zip(ok, headline, strict=True) if r["label"] == 1 and s < fp_threshold]
    metrics["false_positives"] = [
        {"url": defang(r["url"]), "source": r["source"], "score": score_without_reputation(r), "signals": [f"{e['label']} ({e['points']:+g})" for e in r["evidence"] if e["status"] == "fired" and e["category"] != "reputation"]}
        for r in false_positives
    ]
    (args.out / "metrics.json").write_text(json.dumps(metrics, indent=2, default=str))

    total = len(records)
    lines = [
        f"# Phishing risk validation — {args.results.name}",
        "",
        f"Model version: {records[0].get('model_version') if records else 'n/a'}. {total} URLs evaluated; {len(ok)} scored "
        f"({sum(labels)} phishing, {len(labels) - sum(labels)} legitimate).",
        "",
        "## Reachability",
        "",
        "| State | Phishing | Legitimate |",
        "|---|---|---|",
    ]
    for state in ("ok", "unreachable", "dead_http", "taken_down", "blocked", "error"):
        lines.append(f"| {state} | {states[1][state]} | {states[0][state]} |")
    phish_total = sum(states[1].values())
    if phish_total:
        dead = phish_total - states[1]["ok"]
        lines += ["", f"{dead} of {phish_total} phishing URLs ({dead / phish_total:.0%}) were no longer serving a phishing page when checked."]
    lines += ["", "Most common non-ok reasons:", ""] + [f"- {reason} ×{count}" for reason, count in reasons.most_common(8)]

    for name, data in metrics["variants"].items():
        best = data["best_f1"]
        lines += [
            "",
            f"## Metrics: {name}" + (" (headline)" if name == "without reputation" else " (inflated: labels come from the same feeds)"),
            "",
            f"ROC AUC **{data['auc']:.3f}**. Best F1 {best['f1']:.3f} at score ≥ {best['threshold']} (precision {fmt(best['precision'])}, recall {fmt(best['recall'])}, false positive rate {fmt(best['fpr'])}).",
            "",
            "| Threshold | Precision | Recall | F1 | FPR | TP | FP | FN | TN |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for level, c in data["at_levels"].items():
            lines.append(f"| ≥{c['threshold']} ({level}) | {fmt(c['precision'])} | {fmt(c['recall'])} | {fmt(c['f1'])} | {fmt(c['fpr'])} | {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} |")
    lines += ["", "ROC curves: `roc.svg`; per-threshold values: `roc-*.csv`.", "", "## Signals", "",
              "Fire rates, precision when fired, AUC lost when the signal's points are removed (headline score), and a regularised logistic-regression coefficient fitted on these labels (log-odds; larger = more predictive).", "",
              "| Signal | Points | On phishing | On legitimate | Precision | AUC drop | Logistic coef. | Verdict |", "|---|---|---|---|---|---|---|---|"]
    for row in signals:
        lines.append(f"| {row['signal']} | {row['points']:+g} | {row['fires_on_phishing']:.0%} | {row['fires_on_legitimate']:.0%} | {fmt(row['precision_when_fired'], 2)} | {row['auc_drop_without_signal']:+.4f} | {row['logistic_coefficient']} | {row['verdict']} |")
    lines += ["", f"## False positives (legitimate sites scoring ≥ {min(fp_threshold, best_threshold)}, without reputation)", ""]
    if not false_positives:
        lines.append("None.")
    for fp in metrics["false_positives"]:
        lines.append(f"- **{fp['score']}** `{fp['url']}` ({fp['source']}): " + "; ".join(fp["signals"]))
    lines += ["", f"## False negatives (phishing scoring < {fp_threshold}, without reputation): {len(false_negatives)}", ""]
    for r in sorted(false_negatives, key=lambda r: score_without_reputation(r))[:25]:
        fired = [f"{e['signal']} ({e['points']:+g})" for e in r["evidence"] if e["status"] == "fired" and e["category"] != "reputation"]
        lines.append(f"- {score_without_reputation(r)} `{defang(r['url'])}`: {', '.join(fired) or 'no signals fired'}")
    (args.out / "report.md").write_text("\n".join(lines) + "\n")
    print(args.out / "report.md")


if __name__ == "__main__":
    main()
