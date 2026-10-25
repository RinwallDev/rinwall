#!/usr/bin/env python3
"""Sample public MCP servers from the official registry for the blast-radius scan.

This is the first half of the pipeline behind the "N public MCP servers" research;
`blastradius --targets` is the second. It pages the registry's public API, keeps active
servers that advertise a Streamable HTTP endpoint, caps endpoints per host so a few
aggregators can't dominate what is meant to be an ecosystem-wide measurement, and draws a
seeded random sample. Output is a targets file for the scanner plus a JSON summary of the
funnel, so the numbers in the write-up can be reproduced from this script alone.

Polite by construction: sequential paging with a pause, an honest User-Agent, and this
script never contacts any listed server. The scanner does that, and only ever sends
initialize + tools/list.

Reproducibility: given the same registry snapshot and seed, the sample is identical
(everything is sorted before being shuffled or sampled). The registry changes daily, so
the summary records when it was fetched.

    python scripts/sample_registry.py                    # research/servers.txt, 800 servers
    go run ./cmd/blastradius --targets research/servers.txt --json --save-catalogs > research/corpus.json
    go run ./cmd/blastradius --reanalyze research/corpus.json
"""
import argparse
import json
import os
import random
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
USER_AGENT = "rinwall-sampler/0.1 (research: initialize+tools/list only; github.com/RinwallDev/rinwall)"


def fetch_page(cursor, limit):
    query = {"limit": limit, "version": "latest"}
    if cursor:
        query["cursor"] = cursor
    req = urllib.request.Request(REGISTRY + "?" + urllib.parse.urlencode(query), headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="research/servers.txt", help="targets file for blastradius --targets")
    ap.add_argument("--summary", default="research/registry_summary.json", help="funnel counts, for the write-up")
    ap.add_argument("--sample", type=int, default=800)
    ap.add_argument("--per-host", type=int, default=3, help="max endpoints kept per hostname before sampling")
    ap.add_argument("--seed", type=int, default=20260909)
    ap.add_argument("--limit", type=int, default=100, help="registry page size")
    ap.add_argument("--delay", type=float, default=0.2, help="seconds between registry pages")
    args = ap.parse_args()

    fetched_at = datetime.now(timezone.utc).isoformat()
    total = active = 0
    endpoints_by_host = defaultdict(list)
    seen = set()
    cursor = None
    pages = 0
    while True:
        page = fetch_page(cursor, args.limit)
        pages += 1
        for entry in page.get("servers", []):
            total += 1
            server = entry.get("server", {})
            official = entry.get("_meta", {}).get("io.modelcontextprotocol.registry/official", {})
            if official.get("status") != "active":
                continue
            active += 1
            for remote in server.get("remotes") or []:
                if remote.get("type") != "streamable-http":
                    continue
                url = (remote.get("url") or "").strip()
                if not url.startswith(("https://", "http://")) or url in seen:
                    continue
                seen.add(url)
                host = urllib.parse.urlparse(url).hostname or ""
                endpoints_by_host[host].append(url)
        cursor = page.get("metadata", {}).get("nextCursor")
        print(f"page {pages}: {total} listed, {active} active, {len(seen)} http endpoints, {len(endpoints_by_host)} hosts",
              file=sys.stderr)
        if not cursor:
            break
        time.sleep(args.delay)

    rng = random.Random(args.seed)
    capped = []
    for host in sorted(endpoints_by_host):
        urls = sorted(endpoints_by_host[host])
        rng.shuffle(urls)
        capped.extend(urls[: args.per_host])
    capped.sort()
    sample = sorted(random.Random(args.seed).sample(capped, min(args.sample, len(capped))))

    summary = {
        "fetched_at": fetched_at,
        "registry": REGISTRY,
        "listed_latest_versions": total,
        "active": active,
        "streamable_http_endpoints": len(seen),
        "distinct_hosts": len(endpoints_by_host),
        "after_per_host_cap": len(capped),
        "per_host_cap": args.per_host,
        "sampled": len(sample),
        "seed": args.seed,
    }

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# {len(sample)} public MCP servers sampled from {REGISTRY} on {fetched_at}\n")
        f.write(f"# {total} listed (latest versions) -> {active} active -> {len(seen)} streamable-http endpoints on "
                f"{len(endpoints_by_host)} hosts -> {len(capped)} after capping {args.per_host}/host -> seed {args.seed}\n")
        for url in sample:
            f.write(url + "\n")
    with open(args.summary, "w", encoding="utf-8", newline="\n") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    print(json.dumps(summary, indent=2), file=sys.stderr)
    print(f"wrote {args.out} and {args.summary}", file=sys.stderr)


if __name__ == "__main__":
    main()
