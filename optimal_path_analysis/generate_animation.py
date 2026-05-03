#!/usr/bin/env python3
"""
Trajectory Animation

Renders a side-by-side animated MP4 showing the LLM's actual attack
trajectory (left) progressing alongside the oracle-optimal path (right).
Each step lights up a node/edge with the color of its taxonomy label.

Requires ffmpeg on PATH. If ffmpeg is missing, the script prints a clear
message and exits without crashing the rest of the pipeline.

Usage:
    python generate_animation.py [classified_trace.json] [-o attack_trajectory.mp4]
                                 [--fps 5] [--seed 42]
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.animation import FFMpegWriter, FuncAnimation


# Match the colors used in generate_graph.py for consistency
COLOR_MAP = {
    "PRODUCTIVE": "#2ca02c",             # green
    "SUBOPTIMAL_EXPLORATION": "#d62728", # red
    "FAILED_EXECUTION": "#ff7f0e",       # orange
    "REDUNDANT": "#9467bd",              # purple
}
DEFAULT_COLOR = "gray"
UNVISITED_COLOR = "#4a4a6a"
UNVISITED_EDGE = "#3a3a5a"
BG_COLOR = "#1a1a2e"
OPTIMAL_COLOR = "#2ca02c"


def has_ffmpeg() -> bool:
    """True if `ffmpeg` is on PATH. Used by main.py to decide whether to
    invoke the animation stage."""
    return shutil.which("ffmpeg") is not None


def _is_valid_target(tgt) -> bool:
    """Filter out parser fallback values that shouldn't appear as graph nodes."""
    return bool(tgt) and tgt not in ("unknown", "?")


def build_animation(classified_path: str, output_path: str,
                    analysis_path: str = None,
                    fps: int = 5, seed: int = 42):
    """Build the side-by-side animation MP4.

    classified_path:  path to classified_trace.json (drives left panel)
    output_path:      where to write the MP4
    analysis_path:    optional path to analysis_report.json. When provided,
                      the right panel shows the TRUE oracle optimal path
                      (from the solver), walked in optimal order. When
                      omitted, the right panel falls back to using the
                      productive steps from the classified trace — which
                      is correct only for runs that completed all goals.
    fps:              animation frame rate
    seed:             layout seed for reproducible node positions
    """
    with open(classified_path) as f:
        trace = json.load(f)

    if not trace:
        print(f"Empty classified trace at {classified_path}", file=sys.stderr)
        return False

    # The "actual" timeline is every step (left panel).
    actual_timeline = trace

    # The "optimal" timeline (right panel) prefers the true oracle path
    # from analysis_report.json. This is important for incomplete runs:
    # a run that stopped halfway has only some PRODUCTIVE steps, and
    # using just those would misrepresent the optimal path. Falling
    # back to productive-only is a last resort.
    optimal_timeline = None
    if analysis_path:
        try:
            with open(analysis_path) as f:
                analysis = json.load(f)
            optimal_timeline = analysis.get("optimal_path", {}).get("steps") or None
        except Exception as e:
            print(f"Warning: could not load optimal path from "
                  f"{analysis_path}: {e}", file=sys.stderr)
    if optimal_timeline is None:
        optimal_timeline = sorted(
            [s for s in trace
             if s.get("taxonomy_label") == "PRODUCTIVE"
             and s.get("optimal_step")],
            key=lambda s: s["optimal_step"],
        )

    # Collect edges from each timeline. We treat src->tgt where both are
    # valid nodes; otherwise we add the source as a standalone node.
    actual_edges = [(s["source"], s["target"]) for s in actual_timeline
                    if _is_valid_target(s.get("target"))
                    and s.get("source") and s["source"] != s["target"]]
    optimal_edges = [(s["source"], s["target"]) for s in optimal_timeline
                     if _is_valid_target(s.get("target"))
                     and s.get("source") and s["source"] != s["target"]]

    # Build a combined layout so shared nodes render at the same position
    # in both panels.
    G_combined = nx.DiGraph()
    G_combined.add_edges_from(actual_edges)
    G_combined.add_edges_from(optimal_edges)
    if len(G_combined) == 0:
        print("No graph-renderable edges found; nothing to animate.",
              file=sys.stderr)
        return False
    pos = nx.spring_layout(G_combined, seed=seed, k=2)

    # Per-panel graphs (used so each panel's edge set is right)
    G_actual = nx.DiGraph(actual_edges)
    G_optimal = nx.DiGraph(optimal_edges)
    # Make sure standalone nodes (e.g. self-targets, parse fallbacks)
    # appear in the layout for completeness.
    for s in actual_timeline:
        if s.get("source") and s["source"] in pos:
            G_actual.add_node(s["source"])
    for s in optimal_timeline:
        if s.get("source") and s["source"] in pos:
            G_optimal.add_node(s["source"])

    fig, (ax_a, ax_o) = plt.subplots(1, 2, figsize=(20, 9))
    fig.patch.set_facecolor(BG_COLOR)
    for ax in (ax_a, ax_o):
        ax.set_facecolor(BG_COLOR)
        ax.set_xticks([])
        ax.set_yticks([])
        for spine in ax.spines.values():
            spine.set_visible(False)

    legend_handles = [
        mpatches.Patch(color=COLOR_MAP["PRODUCTIVE"], label="PRODUCTIVE"),
        mpatches.Patch(color=COLOR_MAP["SUBOPTIMAL_EXPLORATION"],
                       label="SUBOPTIMAL_EXPLORATION"),
        mpatches.Patch(color=COLOR_MAP["FAILED_EXECUTION"],
                       label="FAILED_EXECUTION"),
        mpatches.Patch(color=COLOR_MAP["REDUNDANT"],
                       label="REDUNDANT (frontier decay)"),
        mpatches.Patch(color=UNVISITED_COLOR, label="Not yet visited"),
    ]
    fig.legend(handles=legend_handles, loc="lower center", ncol=5,
               fontsize=9, facecolor="#2c2c54", labelcolor="white",
               framealpha=0.8, bbox_to_anchor=(0.5, 0.01))
    plt.suptitle("LLM Attack Trajectory vs. Optimal Path",
                 color="white", fontsize=16, y=1.01)

    # Per-frame mutable state
    actual_node_colors = {}
    actual_edge_colors = {}
    optimal_node_colors = {}
    optimal_edge_colors = {}

    def draw_panel(ax, G, edge_colors, node_colors, title, step_label):
        ax.clear()
        ax.set_facecolor(BG_COLOR)
        ax.set_xticks([])
        ax.set_yticks([])
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.set_title(title, color="white", fontsize=14, pad=12)

        nodes = list(G.nodes())
        nc = [node_colors.get(n, UNVISITED_COLOR) for n in nodes]
        nx.draw_networkx_nodes(G, pos, ax=ax, nodelist=nodes,
                               node_color=nc, node_size=600, alpha=0.95)
        nx.draw_networkx_labels(G, pos, ax=ax, font_size=5,
                                font_color="white")

        edges = list(G.edges())
        ec = [edge_colors.get(e, UNVISITED_EDGE) for e in edges]
        nx.draw_networkx_edges(G, pos, ax=ax, edgelist=edges,
                               edge_color=ec, arrows=True, arrowsize=15,
                               width=2, connectionstyle="arc3,rad=0.1")
        ax.text(0.02, 0.97, step_label, transform=ax.transAxes,
                color="white", fontsize=10, verticalalignment="top")

    n_actual = len(actual_timeline)
    n_optimal = len(optimal_timeline)
    total_frames = max(n_actual, n_optimal)

    def update(frame):
        # Actual panel: use the taxonomy label of the current step
        if frame < n_actual:
            step = actual_timeline[frame]
            src = step.get("source")
            tgt = step.get("target")
            label = step.get("taxonomy_label", "UNKNOWN")
            color = COLOR_MAP.get(label, DEFAULT_COLOR)
            if src and src in pos:
                actual_node_colors[src] = color
            if _is_valid_target(tgt) and tgt in pos and src != tgt:
                actual_edge_colors[(src, tgt)] = color
                actual_node_colors[tgt] = color

        draw_panel(ax_a, G_actual, actual_edge_colors, actual_node_colors,
                   "LLM Actual Path",
                   f"Step {min(frame + 1, n_actual)} / {n_actual}")

        # Optimal panel: always green
        if frame < n_optimal:
            step = optimal_timeline[frame]
            src = step.get("source")
            tgt = step.get("target")
            if src and src in pos:
                optimal_node_colors[src] = OPTIMAL_COLOR
            if _is_valid_target(tgt) and tgt in pos and src != tgt:
                optimal_edge_colors[(src, tgt)] = OPTIMAL_COLOR
                optimal_node_colors[tgt] = OPTIMAL_COLOR

        draw_panel(ax_o, G_optimal, optimal_edge_colors, optimal_node_colors,
                   "Optimal Path",
                   f"Step {min(frame + 1, n_optimal)} / {n_optimal}")

    anim = FuncAnimation(fig, update, frames=total_frames,
                         interval=int(1000 / fps), repeat=False)
    plt.tight_layout()

    writer = FFMpegWriter(
        fps=fps,
        metadata=dict(title="Attack Trajectory"),
        bitrate=1800,
    )
    try:
        anim.save(output_path, writer=writer)
        print(f"Saved {output_path}")
        return True
    finally:
        plt.close(fig)


def main():
    parser = argparse.ArgumentParser(
        description="Render a side-by-side trajectory animation MP4.")
    parser.add_argument("classified_trace", nargs="?",
                        default="classified_trace.json")
    parser.add_argument("analysis_report", nargs="?",
                        default="analysis_report.json",
                        help="Optional. When provided, the right panel "
                             "shows the true oracle optimal path. Without "
                             "it, falls back to the productive subset of "
                             "the classified trace.")
    parser.add_argument("-o", "--output", default="attack_trajectory.mp4")
    parser.add_argument("--fps", type=int, default=5,
                        help="Animation frame rate (default: 5).")
    parser.add_argument("--seed", type=int, default=42,
                        help="Layout seed for reproducible node positions.")
    args = parser.parse_args()

    if not has_ffmpeg():
        print("ffmpeg not found on PATH; skipping animation. "
              "Install ffmpeg to enable this output.", file=sys.stderr)
        sys.exit(2)

    if not Path(args.classified_trace).exists():
        print(f"Classified trace not found: {args.classified_trace}",
              file=sys.stderr)
        sys.exit(1)

    analysis_arg = (args.analysis_report
                    if Path(args.analysis_report).exists() else None)

    ok = build_animation(args.classified_trace, args.output,
                         analysis_path=analysis_arg,
                         fps=args.fps, seed=args.seed)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
