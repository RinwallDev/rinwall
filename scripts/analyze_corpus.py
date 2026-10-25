"""Aggregate a blastradius fleet scan into the numbers the research post reports.

    python scripts/analyze_corpus.py research/corpus.json \
        --registry-summary research/registry_summary.json \
        --out research/analysis.json

Reads the JSON that `blastradius --targets ... --json --save-catalogs` writes, prints a
plain-text summary, and writes three files:

  analysis.json               every figure below, with 95% Wilson intervals where a
                              proportion is reported, plus the September 2026 baseline
  validation_sample.full.json a seeded, stratified sample of classifications for a human to
                              check against each tool's real description, so the precision
                              table in the post is measured rather than asserted. It carries
                              each tool's server and description for the reviewer, so it is
                              gitignored and never published.
  validation_sample.json      the same sample and verdicts without the server or the
                              description. This is the published one: the write-up reports
                              aggregates and the method, never a list of named third-party
                              servers labelled by what they can break. Anyone re-running the
                              pipeline gets the same servers from public data, and each
                              item's `id` lets them match their sample to ours.

It never touches the network. Re-running it on the same corpus gives the same output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from urllib.parse import urlsplit

# The first public scan, so the post can say what moved. Figures are the
# post-classifier-fix numbers from that run.
BASELINE_2026_09 = {
    "label": "September 2026",
    "registry_active": 29724,
    "registry_streamable_http": 17032,
    "registry_hosts": 11835,
    "targets": 800,
    "outcomes": {"ok": 421, "auth_required": 257, "protocol_error": 66, "unreachable": 55},
    "tools": 4746,
    "by_class": {"C": 300, "A": 371, "B": 2547, "unknown": 1528},
    "servers_any_c_pct": 32.5,
    "servers_all_b_pct": 23.8,
    "servers_read_and_c_pct": 30.9,
    "top_decile_share_of_c_pct": 66.0,
    "servers_three_plus_c": 30,
    "c_flagged_by_description": 38,
    "description_coverage_pct": 99.9,
    "median_tools": 6,
    "max_tools": 133,
}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (round(100 * (centre - half), 1), round(100 * (centre + half), 1))


def pct(k: int, n: int) -> float:
    return round(100 * k / n, 1) if n else 0.0


def host_of(url: str) -> str:
    return urlsplit(url).hostname or url


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--registry-summary")
    ap.add_argument("--out", default="research/analysis.json")
    ap.add_argument("--validation-sample", default="research/validation_sample.full.json",
                    help="private working copy with servers and descriptions (gitignored)")
    ap.add_argument("--validation-public", default="research/validation_sample.json",
                    help="published copy, without servers or descriptions")
    ap.add_argument("--sample-seed", type=int, default=20261021)
    ap.add_argument("--sample-per-class", default="C=20,A=20,B=20,unknown=15")
    args = ap.parse_args()

    with open(args.corpus, encoding="utf-8") as f:
        corpus = json.load(f)
    records = corpus["records"]

    # --- reachability -----------------------------------------------------
    outcomes = Counter(r["outcome"] for r in records)
    n_targets = len(records)
    ok = [r for r in records if r.get("report")]
    ok_hosts = {host_of(r["source"]) for r in ok}

    # --- tools ------------------------------------------------------------
    by_class: Counter[str] = Counter()
    per_server_counts: list[int] = []
    per_server_c: list[tuple[str, int]] = []
    servers_any_c = servers_all_b = servers_read_and_c = servers_three_plus_c = 0
    c_flagged_by_description = 0
    tools_with_description = total_catalog_tools = 0
    all_results: list[dict] = []

    for r in ok:
        rep = r["report"]
        bc = rep.get("by_class", {})
        for k, v in bc.items():
            by_class[k] += v
        n = rep["total_tools"]
        per_server_counts.append(n)
        c = bc.get("C", 0)
        per_server_c.append((r["source"], c))
        if c > 0:
            servers_any_c += 1
        if c >= 3:
            servers_three_plus_c += 1
        if c == 0 and bc.get("A", 0) == 0 and bc.get("unknown", 0) == 0 and n > 0:
            servers_all_b += 1
        if c > 0 and bc.get("B", 0) > 0:
            servers_read_and_c += 1

        descriptions = {t["name"]: t.get("description", "") for t in r.get("catalog", [])}
        total_catalog_tools += len(descriptions)
        tools_with_description += sum(1 for d in descriptions.values() if d and d.strip())

        for res in rep.get("results", []):
            cls = res.get("class") or ("unknown" if res.get("unclassified") else "")
            if cls == "C" and any(s.get("rule") == "description-phrase" for s in res.get("signals", [])):
                c_flagged_by_description += 1
            all_results.append(
                {
                    "server": r["source"],
                    "tool": res["tool"],
                    "class": cls,
                    "confidence": res.get("confidence"),
                    "rationale": res.get("rationale"),
                    "signals": res.get("signals", []),
                    "description": descriptions.get(res["tool"], ""),
                }
            )

    total_tools = sum(by_class.values())
    n_servers = len(ok)

    # Concentration: what share of every irreversible tool sits on the worst 10% of servers.
    per_server_c.sort(key=lambda x: -x[1])
    decile = max(1, math.ceil(n_servers / 10))
    total_c = by_class.get("C", 0)
    top_decile_c = sum(c for _, c in per_server_c[:decile])

    # Sensitivity: the 3-per-host cap bounds servers per operator, not tools
    # per server, so one very large catalog can still move the tool-level
    # shares. Report them again without the largest catalog.
    largest = max(ok, key=lambda r: r["report"]["total_tools"]) if ok else None
    without_largest: Counter[str] = Counter()
    for r in ok:
        if r is largest:
            continue
        for k, v in r["report"].get("by_class", {}).items():
            without_largest[k] += v
    wl_total = sum(without_largest.values())

    analysis = {
        "targets": n_targets,
        "largest_catalog": {
            "tools": largest["report"]["total_tools"] if largest else 0,
            "by_class": largest["report"].get("by_class", {}) if largest else {},
        },
        "by_class_excluding_largest": {
            k: {"n": v, "pct": pct(v, wl_total)} for k, v in sorted(without_largest.items())
        },
        "outcomes": {k: {"n": v, "pct": pct(v, n_targets)} for k, v in sorted(outcomes.items())},
        "servers_with_catalog": n_servers,
        "distinct_hosts_with_catalog": len(ok_hosts),
        "tools": total_tools,
        "by_class": {
            k: {"n": v, "pct": pct(v, total_tools), "ci95": wilson(v, total_tools)}
            for k, v in sorted(by_class.items())
        },
        "median_tools_per_server": int(statistics.median(per_server_counts)) if per_server_counts else 0,
        "max_tools_per_server": max(per_server_counts) if per_server_counts else 0,
        "servers_any_c": {"n": servers_any_c, "pct": pct(servers_any_c, n_servers), "ci95": wilson(servers_any_c, n_servers)},
        "servers_all_b": {"n": servers_all_b, "pct": pct(servers_all_b, n_servers), "ci95": wilson(servers_all_b, n_servers)},
        "servers_read_and_c": {
            "n": servers_read_and_c,
            "pct": pct(servers_read_and_c, n_servers),
            "ci95": wilson(servers_read_and_c, n_servers),
        },
        "servers_three_plus_c": servers_three_plus_c,
        "servers_by_c_count": {
            "0": sum(1 for _, c in per_server_c if c == 0),
            "1": sum(1 for _, c in per_server_c if c == 1),
            "2": sum(1 for _, c in per_server_c if c == 2),
            "3+": servers_three_plus_c,
        },
        "top_decile_servers": decile,
        "top_decile_share_of_c_pct": pct(top_decile_c, total_c),
        "c_flagged_by_description": c_flagged_by_description,
        "description_coverage": {
            "with": tools_with_description,
            "of": total_catalog_tools,
            "pct": pct(tools_with_description, total_catalog_tools),
        },
        "baseline": BASELINE_2026_09,
    }
    if args.registry_summary:
        with open(args.registry_summary, encoding="utf-8") as f:
            analysis["registry_funnel"] = json.load(f)
        analysis["sampled_at"] = analysis["registry_funnel"].get("fetched_at")

    # --- stratified validation sample ------------------------------------
    # Verdicts already recorded for the same (server, tool, class) are carried
    # forward, so re-running after a classifier change only asks a human to
    # look at classifications that are actually new.
    prior: dict[tuple, tuple] = {}
    prior_meta = {}
    try:
        with open(args.validation_sample, encoding="utf-8") as f:
            old = json.load(f)
        prior_meta = {k: v for k, v in old.items() if k != "items"}
        for x in old.get("items", []):
            if x.get("human_verdict"):
                prior[(x["server"], x["tool"], x["class"])] = (x["human_verdict"], x.get("human_note", ""))
    except FileNotFoundError:
        pass

    # Each item gets a rank from a hash of (seed, server, tool); a class's
    # sample is its lowest-ranked items. Unlike a shuffle, an item's rank
    # does not depend on what else is in the pool, so when a classifier
    # change moves a few tools between classes the rest of the sample
    # stays put and the before/after is a comparison, not a re-draw.
    def rank(x: dict) -> str:
        return hashlib.sha1(f"{args.sample_seed}:{x['server']}:{x['tool']}".encode()).hexdigest()

    quotas = dict(kv.split("=") for kv in args.sample_per_class.split(","))
    sample = []
    carried = 0
    for cls, q in quotas.items():
        pool = sorted((x for x in all_results if x["class"] == cls), key=rank)
        for x in pool[: int(q)]:
            verdict, note = prior.get((x["server"], x["tool"], x["class"]), ("", ""))
            carried += bool(verdict)
            sample.append({**x, "human_verdict": verdict, "human_note": note})
    out = {**prior_meta, "seed": args.sample_seed, "quotas": quotas, "items": sample}
    with open(args.validation_sample, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    # The published copy: same items and verdicts, without the server or the
    # tool's description (a description is distinctive enough to find its
    # server by search). Allowlisted fields, so a new field added to the
    # sample later is withheld by default rather than leaked by default.
    public_keys = ("class", "tool", "confidence", "rationale", "signals", "human_verdict", "human_note")
    public = {
        **prior_meta,
        "seed": args.sample_seed,
        "quotas": quotas,
        "note": "Servers and tool descriptions are withheld on purpose; re-run the pipeline to "
                "reproduce the sample. id is the first 12 hex digits of sha1(seed:server:tool).",
        "items": [{"id": rank(x)[:12], **{k: x[k] for k in public_keys if k in x}} for x in sample],
    }
    with open(args.validation_public, "w", encoding="utf-8") as f:
        json.dump(public, f, indent=2, ensure_ascii=False)

    # Precision from the recorded verdicts. "over" = classified more dangerous
    # than it is, "under" = classified safer than it is; for the unknown
    # stratum the verdict is the class a human assigned.
    validation = {}
    for cls in ("C", "A", "B"):
        items = [x for x in sample if x["class"] == cls and x["human_verdict"]]
        if items:
            correct = sum(1 for x in items if x["human_verdict"] == "correct")
            validation[cls] = {
                "reviewed": len(items),
                "correct": correct,
                "over": sum(1 for x in items if x["human_verdict"] == "over"),
                "under": sum(1 for x in items if x["human_verdict"] == "under"),
                "precision_pct": pct(correct, len(items)),
            }
    unk = [x for x in sample if x["class"] == "unknown" and x["human_verdict"]]
    if unk:
        validation["unknown_is_really"] = dict(Counter(x["human_verdict"] for x in unk))
    analysis["validation"] = validation

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2)

    # --- human-readable ---------------------------------------------------
    b = BASELINE_2026_09
    print(f"targets {n_targets}; catalogs {n_servers} from {len(ok_hosts)} distinct hosts")
    print("outcomes:")
    for k, v in sorted(outcomes.items(), key=lambda kv: -kv[1]):
        print(f"  {k:16s} {v:4d}  {pct(v, n_targets):5.1f}%   (Sept: {b['outcomes'].get(k, 0)})")
    print(f"tools {total_tools} (Sept {b['tools']}); median/server {analysis['median_tools_per_server']}, max {analysis['max_tools_per_server']}")
    for k in ("C", "A", "B", "unknown"):
        v = by_class.get(k, 0)
        lo, hi = wilson(v, total_tools)
        print(f"  {k:8s} {v:5d}  {pct(v, total_tools):5.1f}%  CI {lo}-{hi}   (Sept {b['by_class'][k]}, {pct(b['by_class'][k], b['tools'])}%)")
    print(f"servers with >=1 irreversible tool: {servers_any_c} ({pct(servers_any_c, n_servers)}%; Sept {b['servers_any_c_pct']}%)")
    print(f"servers entirely read-only:         {servers_all_b} ({pct(servers_all_b, n_servers)}%; Sept {b['servers_all_b_pct']}%)")
    print(f"servers with reads AND irreversible: {servers_read_and_c} ({pct(servers_read_and_c, n_servers)}%; Sept {b['servers_read_and_c_pct']}%)")
    print(f"servers with 3+ irreversible: {servers_three_plus_c} (Sept {b['servers_three_plus_c']})")
    print(f"top {decile} servers hold {pct(top_decile_c, total_c)}% of irreversible tools (Sept {b['top_decile_share_of_c_pct']}%)")
    print(f"irreversible flagged by the author's own description: {c_flagged_by_description} (Sept {b['c_flagged_by_description']})")
    print(f"description coverage: {tools_with_description}/{total_catalog_tools} = {pct(tools_with_description, total_catalog_tools)}%")
    if largest:
        lb = largest["report"].get("by_class", {})
        print(f"largest catalog: {largest['report']['total_tools']} tools ({lb}); shares without it: "
              + ", ".join(f"{k} {pct(v, wl_total)}%" for k, v in sorted(without_largest.items())))
    for cls, v in validation.items():
        print(f"validation {cls}: {v}")
    print(f"wrote {args.out}, {args.validation_sample} and {args.validation_public} ({len(sample)} items, {carried} verdicts carried forward, {len(sample) - carried} to hand-check)")


if __name__ == "__main__":
    main()
