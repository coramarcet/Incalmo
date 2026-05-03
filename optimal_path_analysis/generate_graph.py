"""
Trajectory Timeline Plot

Plots the LLM's actual progress (optimal-step consumed) vs actual step number,
colored by taxonomy label. The dashed diagonal is perfect efficiency.

Usage:
    python generate_graph.py [classified_trace.json] [analysis_report.json] [-o trajectory_timeline.png]
"""

import argparse
import json
import sys

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches


# Color mapping by current taxonomy labels
COLOR_MAP = {
    "PRODUCTIVE": "#2ca02c",             # green
    "SUBOPTIMAL_EXPLORATION": "#d62728", # red
    "FAILED_EXECUTION": "#ff7f0e",       # orange
    "REDUNDANT": "#9467bd",              # purple
}
DEFAULT_COLOR = "gray"


def plot_trajectory(classified_path, analysis_path, output_path):
    with open(classified_path) as f:
        trace = json.load(f)
    with open(analysis_path) as f:
        analysis = json.load(f)

    optimal_length = analysis.get("optimal_path", {}).get("total_steps", 0)

    if not trace:
        print("Empty trace — nothing to plot.", file=sys.stderr)
        return

    steps = []
    optimal_progress = []
    colors = []

    last_optimal = 0
    for entry in trace:
        step_num = entry["step"]
        label = entry.get("taxonomy_label", "UNKNOWN")

        # Productive steps consume an optimal-path index; advance the line.
        if label == "PRODUCTIVE" and entry.get("optimal_step"):
            last_optimal = max(last_optimal, entry["optimal_step"])

        steps.append(step_num)
        optimal_progress.append(last_optimal)
        colors.append(COLOR_MAP.get(label, DEFAULT_COLOR))

    total_steps = steps[-1]

    fig, ax = plt.subplots(figsize=(16, 8))

    # Ideal diagonal — perfect efficiency: each actual step advances optimal by 1.
    # Skip the diagonal if there's no optimal path (run 3 / no-goals case).
    if optimal_length > 0:
        ax.plot([0, optimal_length], [0, optimal_length],
                color="#2ca02c", linewidth=2, linestyle="--",
                label="Perfect Efficiency (Ideal)", zorder=2, alpha=0.7)

    # Actual progress in light gray
    ax.plot(steps, optimal_progress, color="lightgray", linewidth=1.5, zorder=1)

    # Each step as a colored dot
    for i in range(len(steps)):
        ax.scatter(steps[i], optimal_progress[i], color=colors[i],
                   s=40, zorder=3, linewidths=0)

    # Title varies by whether we have an optimal path to compare against
    if optimal_length > 0:
        eff = optimal_length / total_steps
        title = (f"LLM Attack Trajectory vs. Optimal Path  "
                 f"(actual={total_steps}, optimal={optimal_length}, "
                 f"efficiency={eff:.1%})")
    else:
        title = (f"LLM Attack Trajectory  (actual={total_steps}, "
                 f"no optimal path available)")

    ax.set_xlabel("LLM Step Number (Actual Actions Taken)", fontsize=12)
    ax.set_ylabel("Optimal Path Progress (Steps Completed)", fontsize=12)
    ax.set_title(title, fontsize=13)
    ax.set_xlim(0, total_steps + 2)
    # Use observed max progress when no optimal path; clamp ymax to keep
    # the plot readable.
    ymax = max(optimal_length, max(optimal_progress) if optimal_progress else 0, 1)
    ax.set_ylim(0, ymax + 2)
    ax.grid(True, linestyle=":", alpha=0.5)

    legend_handles = [
        mpatches.Patch(color="#2ca02c", label="PRODUCTIVE"),
        mpatches.Patch(color="#d62728", label="SUBOPTIMAL_EXPLORATION"),
        mpatches.Patch(color="#ff7f0e", label="FAILED_EXECUTION"),
        mpatches.Patch(color="#9467bd", label="REDUNDANT (frontier decay)"),
    ]
    if optimal_length > 0:
        legend_handles.append(plt.Line2D(
            [0], [0], color="#2ca02c", linestyle="--",
            label="Ideal (Perfect Efficiency)"))
    ax.legend(handles=legend_handles, loc="upper left", fontsize=10)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close(fig)
    print(f"Saved {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Plot trajectory timeline")
    parser.add_argument("classified_trace", nargs="?", default="classified_trace.json")
    parser.add_argument("analysis_report", nargs="?", default="analysis_report.json")
    parser.add_argument("-o", "--output", default="trajectory_timeline.png")
    args = parser.parse_args()
    plot_trajectory(args.classified_trace, args.analysis_report, args.output)


if __name__ == "__main__":
    main()
