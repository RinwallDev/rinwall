"""Render the research write-up's charts as static SVG from research/analysis.json.

    python scripts/render_charts.py research/analysis.json research/charts

Static SVG so the files embed in Markdown on GitHub, where no script runs. Each mark
carries a <title> so a browser still shows the value on hover. Colors are the
validated reference palette: one blue for magnitude, two blue steps (#5598e7 September,
#1c5cab October) for the before/after dumbbell, text in ink tokens, never series color.
"""

from __future__ import annotations

import json
import os
import sys
from xml.sax.saxutils import escape

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK2 = "#52514e"
GRID = "#e6e5e1"
BLUE = "#2a78d6"
BLUE_LIGHT = "#5598e7"
BLUE_DARK = "#1c5cab"
FONT = "'IBM Plex Sans', 'Segoe UI', system-ui, sans-serif"
MONO = "'IBM Plex Mono', Consolas, monospace"


def svg_open(w: int, h: int, title: str) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
        f'role="img" aria-label="{escape(title)}" font-family="{FONT}">',
        f'<title>{escape(title)}</title>',
        f'<rect width="{w}" height="{h}" fill="{SURFACE}"/>',
    ]


def text(x: float, y: float, s: str, size=13, fill=INK, anchor="start", weight="normal", mono=False) -> str:
    ff = f' font-family="{MONO}"' if mono else ""
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{fill}" text-anchor="{anchor}" '
            f'font-weight="{weight}"{ff}>{escape(s)}</text>')


def hbar(x0: float, y0: float, length: float, thick: float, fill: str, r: float = 4) -> str:
    # Square at the baseline (left), 4px rounded at the data end (right).
    x1 = x0 + max(length, r)
    return (f'<path d="M{x0:.1f},{y0:.1f} H{x1 - r:.1f} a{r},{r} 0 0 1 {r},{r} V{y0 + thick - r:.1f} '
            f'a{r},{r} 0 0 1 -{r},{r} H{x0:.1f} Z" fill="{fill}"/>')


def vbar(x0: float, ybase: float, height: float, thick: float, fill: str, r: float = 4) -> str:
    y1 = ybase - max(height, r)
    return (f'<path d="M{x0:.1f},{ybase:.1f} V{y1 + r:.1f} a{r},{r} 0 0 1 {r},-{r} H{x0 + thick - r:.1f} '
            f'a{r},{r} 0 0 1 {r},{r} V{ybase:.1f} Z" fill="{fill}"/>')


def reachability(a: dict) -> str:
    rows = [
        ("Catalog retrieved", a["outcomes"]["ok"]),
        ("Authentication required", a["outcomes"]["auth_required"]),
        ("Protocol error", a["outcomes"]["protocol_error"]),
        ("Unreachable", a["outcomes"]["unreachable"]),
    ]
    total = a["targets"]
    w, h = 720, 60 + 44 * len(rows) + 30
    out = svg_open(w, h, f"Reachability of {total} sampled MCP servers")
    out.append(text(24, 30, f"What {total} sampled servers did when asked for their tool list", 15, INK, weight="600"))
    out.append(text(24, 50, "initialize, then tools/list; nothing was called", 12, INK2))
    label_w, x0, xmax = 190, 24 + 190, w - 24 - 110
    scale = (xmax - x0) / max(n["n"] for _, n in rows)
    y = 70
    for name, n in rows:
        out.append(text(x0 - 12, y + 16, name, 13, INK, anchor="end"))
        pct, count = n["pct"], n["n"]
        out.append(f'<g><title>{escape(name)}: {count} of {total} ({pct}%)</title>')
        out.append(hbar(x0, y, count * scale, 22, BLUE))
        out.append("</g>")
        out.append(text(x0 + count * scale + 10, y + 16, f"{count}", 13, INK, mono=True))
        out.append(text(x0 + count * scale + 10 + 36, y + 16, f"{pct}%", 12, INK2, mono=True))
        y += 44
    return "\n".join(out + ["</svg>"])


def class_shares(a: dict) -> str:
    b = a["baseline"]
    order = [("C", "Irreversible"), ("A", "Compensable"), ("B", "Read-only"), ("unknown", "Unclassifiable")]
    rows = []
    for key, name in order:
        sept = round(100 * b["by_class"][key] / b["tools"], 1)
        octo = a["by_class"][key]["pct"]
        rows.append((name, sept, octo))
    w, h = 720, 60 + 48 * len(rows) + 56
    out = svg_open(w, h, "Share of tools by reversibility class, October 2026 against the unpublished September run")
    out.append(text(24, 30, "Share of tools by what they can undo", 15, INK, weight="600"))
    out.append(text(24, 50, f"{b['tools']:,} tools in September, {a['tools']:,} in October; the dot is the share, the bar the move", 12, INK2))
    x0, xmax, label_w = 24 + 150, w - 24 - 60, 150
    vmax = 60
    scale = (xmax - x0) / vmax
    # recessive grid
    ytop, ybot = 68, 68 + 48 * len(rows)
    for v in range(0, vmax + 1, 10):
        x = x0 + v * scale
        out.append(f'<line x1="{x:.1f}" y1="{ytop}" x2="{x:.1f}" y2="{ybot}" stroke="{GRID}" stroke-width="1"/>')
        out.append(text(x, ybot + 16, f"{v}%", 11, INK2, anchor="middle", mono=True))
    y = 68 + 12
    for name, sept, octo in rows:
        cy = y + 12
        out.append(text(x0 - 12, cy + 4, name, 13, INK, anchor="end"))
        xs, xo = x0 + sept * scale, x0 + octo * scale
        out.append(f'<line x1="{xs:.1f}" y1="{cy}" x2="{xo:.1f}" y2="{cy}" stroke="{GRID}" stroke-width="3" stroke-linecap="round"/>')
        out.append(f'<g><title>{escape(name)}: September {sept}%, October {octo}%</title>')
        out.append(f'<circle cx="{xs:.1f}" cy="{cy}" r="7" fill="{BLUE_LIGHT}" stroke="{SURFACE}" stroke-width="2"/>')
        out.append(f'<circle cx="{xo:.1f}" cy="{cy}" r="7" fill="{BLUE_DARK}" stroke="{SURFACE}" stroke-width="2"/>')
        out.append("</g>")
        # direct labels: the lower value to the left, the higher to the right, so they never collide
        lo, hi = sorted([(sept, xs), (octo, xo)])
        if abs(hi[1] - lo[1]) < 40:
            out.append(text(lo[1] - 12, cy + 4, f"{lo[0]}%", 12, INK, anchor="end", mono=True))
            out.append(text(hi[1] + 12, cy + 4, f"{hi[0]}%", 12, INK, mono=True))
        else:
            out.append(text(lo[1] - 12, cy + 4, f"{lo[0]}%", 12, INK, anchor="end", mono=True))
            out.append(text(hi[1] + 12, cy + 4, f"{hi[0]}%", 12, INK, mono=True))
        y += 48
    ly = h - 16
    out.append(f'<circle cx="{x0 + 6}" cy="{ly - 4}" r="6" fill="{BLUE_LIGHT}"/>')
    out.append(text(x0 + 18, ly, "September 2026 (unpublished run)", 12, INK2))
    out.append(f'<circle cx="{x0 + 236}" cy="{ly - 4}" r="6" fill="{BLUE_DARK}"/>')
    out.append(text(x0 + 248, ly, "October 2026 (after the classifier fix)", 12, INK2))
    return "\n".join(out + ["</svg>"])


def concentration(a: dict) -> str:
    dist = a["servers_by_c_count"]
    cats = [("0", "none"), ("1", "one"), ("2", "two"), ("3+", "three or more")]
    n_servers = a["servers_with_catalog"]
    w, h = 720, 300
    out = svg_open(w, h, "Servers by number of irreversible tools")
    out.append(text(24, 30, "How many irreversible tools a server exposes", 15, INK, weight="600"))
    out.append(text(24, 50, f"{n_servers} servers with a catalog; the top 10% of servers hold {a['top_decile_share_of_c_pct']}% of all irreversible tools", 12, INK2))
    x0, ybase, plot_h = 24 + 40, h - 50, 160
    slot = (w - 48 - 40) / len(cats)
    vmax = max(dist.values())
    scale = plot_h / vmax
    for i, (key, label) in enumerate(cats):
        n = dist[key]
        cx = x0 + i * slot + slot / 2
        bx = cx - 12
        out.append(f'<g><title>{escape(label)}: {n} servers ({round(100 * n / n_servers, 1)}%)</title>')
        out.append(vbar(bx, ybase, n * scale, 24, BLUE))
        out.append("</g>")
        out.append(text(cx, ybase - n * scale - 8, f"{n}", 13, INK, anchor="middle", mono=True))
        out.append(text(cx, ybase + 18, f"{label}", 12, INK, anchor="middle"))
        out.append(text(cx, ybase + 34, f"{round(100 * n / n_servers, 1)}% of servers", 11, INK2, anchor="middle", mono=True))
    out.append(f'<line x1="{x0}" y1="{ybase}" x2="{w - 24}" y2="{ybase}" stroke="{GRID}" stroke-width="1"/>')
    return "\n".join(out + ["</svg>"])


def main() -> None:
    src = sys.argv[1] if len(sys.argv) > 1 else "research/analysis.json"
    dst = sys.argv[2] if len(sys.argv) > 2 else "research/charts"
    with open(src, encoding="utf-8") as f:
        a = json.load(f)
    os.makedirs(dst, exist_ok=True)
    for name, fn in (("reachability", reachability), ("class-shares", class_shares), ("concentration", concentration)):
        path = os.path.join(dst, f"{name}.svg")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(fn(a))
        print("wrote", path)


if __name__ == "__main__":
    main()
