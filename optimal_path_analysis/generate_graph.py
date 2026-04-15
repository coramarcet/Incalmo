import json
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# Load file
with open("classified_trace.json") as f:
    trace = json.load(f)

# Color mapping by taxonomy label
color_map = {
    "PRODUCTIVE": "green",
    "IRRELEVANT_DEAD_END": "red",
    "FAILED_EXECUTION": "orange",
    "REDUNDANT_FRONTIER_DECAY": "purple",
}
default_color = "gray"

# Build the x (step) and y (optimal progress) arrays
# For MATCH steps, y = optimal_step
# For non-MATCH steps, y = last known optimal_step (progress is flat)
steps = []
optimal_progress = []
colors = []

last_optimal = 0
for entry in trace:
    step_num = entry["step"]
    label = entry.get("taxonomy_label", "UNKNOWN")

    if entry.get("status") == "MATCH" and entry.get("optimal_step"):
        last_optimal = entry["optimal_step"]

    steps.append(step_num)
    optimal_progress.append(last_optimal)
    colors.append(color_map.get(label, default_color))

# Compute the ideal diagonal
total_steps = steps[-1]
optimal_length = max(s["optimal_step"] for s in trace if s.get("status") == "MATCH" and s.get("optimal_step"))
ideal_x = [0, optimal_length]
ideal_y = [0, optimal_length]

# Plot
fig, ax = plt.subplots(figsize=(16, 8))

# Draw ideal diagonal
ax.plot(ideal_x, ideal_y, color="green", linewidth=2,
        linestyle="--", label="Perfect Efficiency (Ideal)", zorder=2)

# Draw the LLM's actual progress line in light gray as background
ax.plot(steps, optimal_progress, color="lightgray", linewidth=1.5, zorder=1)

# Scatter plot each step colored by taxonomy label
for i in range(len(steps)):
    ax.scatter(steps[i], optimal_progress[i], color=colors[i],
               s=40, zorder=3, linewidths=0)

# Labels and formatting
ax.set_xlabel("LLM Step Number (Actual Actions Taken)", fontsize=12)
ax.set_ylabel("Optimal Path Progress (Steps Completed)", fontsize=12)
ax.set_title("LLM Attack Trajectory vs. Optimal Path", fontsize=14)
ax.set_xlim(0, total_steps + 2)
ax.set_ylim(0, optimal_length + 2)

# Grid
ax.grid(True, linestyle=":", alpha=0.5)

# Legend
legend_handles = [
    mpatches.Patch(color="green", label="PRODUCTIVE"),
    mpatches.Patch(color="red", label="IRRELEVANT_DEAD_END"),
    mpatches.Patch(color="orange", label="FAILED_EXECUTION"),
    mpatches.Patch(color="purple", label="REDUNDANT_FRONTIER_DECAY"),
    plt.Line2D([0], [0], color="green", linestyle="--", label="Ideal (Perfect Efficiency)"),
]
ax.legend(handles=legend_handles, loc="upper left", fontsize=10)

plt.tight_layout()
plt.savefig("trajectory_timeline.png", dpi=150)
print("Saved trajectory_timeline.png")