import json
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.animation import FuncAnimation, FFMpegWriter

# --- Load trace ---
with open("classified_trace.json") as f:
    trace = json.load(f)

# --- Color mapping ---
color_map = {
    "PRODUCTIVE": "#2ecc71",
    "IRRELEVANT_DEAD_END": "#e74c3c",
    "FAILED_EXECUTION": "#e67e22",
    "REDUNDANT_FRONTIER_DECAY": "#9b59b6",
}
default_color = "gray"

# --- Separate actual and optimal steps ---
actual_steps = trace  # all 156 steps

optimal_steps = [s for s in trace if s.get("status") == "MATCH"]

# Build optimal path as explicit edges using optimal_target where available
# For MATCH steps, source->target is the correct move
optimal_edges_ordered = []
for s in optimal_steps:
    src = s.get("source")
    tgt = s.get("target")
    if src and tgt and tgt != "unknown":
        optimal_edges_ordered.append((src, tgt, s))

actual_edges_ordered = []
for s in actual_steps:
    src = s.get("source")
    tgt = s.get("target")
    if src and tgt and tgt != "unknown":
        actual_edges_ordered.append((src, tgt, s))

# --- Build full graphs for layout ---
G_actual = nx.DiGraph()
for src, tgt, _ in actual_edges_ordered:
    G_actual.add_edge(src, tgt)

optimal_steps_ordered = [s for s in trace if s.get("status") == "MATCH"]
print(len(optimal_steps_ordered))
G_optimal = nx.DiGraph()
for s in optimal_steps_ordered:
    src = s.get("source")
    tgt = s.get("target")
    if src and tgt and tgt != "unknown":
        G_optimal.add_edge(src, tgt)
    elif src:  # self-loop or unknown target — still add the node
        G_optimal.add_node(src)

# Build a combined graph for layout so shared nodes appear in same position
G_combined = nx.DiGraph()
for src, tgt, _ in actual_edges_ordered:
    G_combined.add_edge(src, tgt)
for src, tgt, _ in optimal_edges_ordered:
    G_combined.add_edge(src, tgt)

# Single layout used by both panels
shared_pos = nx.spring_layout(G_combined, seed=42, k=2)

# Both panels use the same positions
pos_actual = shared_pos
pos_optimal = shared_pos

# --- Setup figure with two side-by-side panels ---
fig, (ax_actual, ax_optimal) = plt.subplots(1, 2, figsize=(20, 9))
fig.patch.set_facecolor("#1a1a2e")  # dark background

for ax in (ax_actual, ax_optimal):
    ax.set_facecolor("#1a1a2e")
    ax.set_xticks([])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_visible(False)

ax_actual.set_title("LLM Actual Path", color="white", fontsize=14, pad=12)
ax_optimal.set_title("Optimal Path", color="white", fontsize=14, pad=12)

# Step counter text
step_text_actual = ax_actual.text(
    0.02, 0.97, "", transform=ax_actual.transAxes,
    color="white", fontsize=10, verticalalignment="top"
)
step_text_optimal = ax_optimal.text(
    0.02, 0.97, "", transform=ax_optimal.transAxes,
    color="white", fontsize=10, verticalalignment="top"
)

# Legend
legend_handles = [
    mpatches.Patch(color="#2ecc71", label="PRODUCTIVE"),
    mpatches.Patch(color="#e74c3c", label="IRRELEVANT_DEAD_END"),
    mpatches.Patch(color="#e67e22", label="FAILED_EXECUTION"),
    mpatches.Patch(color="#9b59b6", label="REDUNDANT_FRONTIER_DECAY"),
    mpatches.Patch(color="gray", label="Not yet visited"),
]
fig.legend(handles=legend_handles, loc="lower center", ncol=5,
           fontsize=9, facecolor="#2c2c54", labelcolor="white",
           framealpha=0.8, bbox_to_anchor=(0.5, 0.01))

plt.suptitle("LLM Attack Trajectory vs. Optimal Path",
             color="white", fontsize=16, y=1.01)

# --- Track state across frames ---
actual_edge_colors = {}   # edge -> color
optimal_edge_colors = {}
actual_node_colors = {}   # node -> color
optimal_node_colors = {}

#total_frames = max(len(actual_edges_ordered), len(optimal_edges_ordered))

def draw_panel(ax, G, pos, edge_colors, node_colors, step_text, frame_label):
    ax.clear()
    ax.set_facecolor("#1a1a2e")
    ax.set_xticks([])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.set_title(frame_label, color="white", fontsize=14, pad=12)

    # Node colors
    nc = [node_colors.get(n, "#4a4a6a") for n in G.nodes()]
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=nc,
                           node_size=600, alpha=0.95)
    nx.draw_networkx_labels(G, pos, ax=ax, font_size=5,
                            font_color="white")

    # Edge colors
    edges = list(G.edges())
    ec = [edge_colors.get(e, "#3a3a5a") for e in edges]
    nx.draw_networkx_edges(G, pos, ax=ax, edgelist=edges,
                           edge_color=ec, arrows=True,
                           arrowsize=15, width=2,
                           connectionstyle="arc3,rad=0.1")

actual_steps_ordered = trace  # all 156

total_frames = max(len(actual_steps_ordered), len(optimal_steps_ordered))

def update(frame):
    # --- Actual panel ---
    if frame < len(actual_steps_ordered):
        step = actual_steps_ordered[frame]
        src = step.get("source")
        tgt = step.get("target")
        label = step.get("taxonomy_label", "UNKNOWN")
        color = color_map.get(label, default_color)

        # Always color the source node
        if src:
            actual_node_colors[src] = color

        # Only add edge if target is valid and different from source
        if tgt and tgt != "unknown":
            actual_edge_colors[(src, tgt)] = color
            actual_node_colors[tgt] = color

    draw_panel(ax_actual, G_actual, pos_actual,
               actual_edge_colors, actual_node_colors,
               step_text_actual, "LLM Actual Path")

    ax_actual.text(0.02, 0.97,
                   f"Step {min(frame + 1, len(actual_steps_ordered))} / {len(actual_steps_ordered)}",
                   transform=ax_actual.transAxes, color="white",
                   fontsize=10, verticalalignment="top")

    # --- Optimal panel ---
    if frame < len(optimal_steps_ordered):
        step = optimal_steps_ordered[frame]
        src = step.get("source")
        tgt = step.get("target")
        color = "#2ecc71"

        if src:
            optimal_node_colors[src] = color

        if tgt and tgt != "unknown":
            optimal_edge_colors[(src, tgt)] = color
            optimal_node_colors[tgt] = color

    draw_panel(ax_optimal, G_optimal, pos_optimal,
               optimal_edge_colors, optimal_node_colors,
               step_text_optimal, "Optimal Path")

    ax_optimal.text(0.02, 0.97,
                    f"Step {min(frame + 1, len(optimal_steps_ordered))} / {len(optimal_steps_ordered)}",
                    transform=ax_optimal.transAxes, color="white",
                    fontsize=10, verticalalignment="top")

# --- Animate ---
# interval = milliseconds per frame (lower = faster)
anim = FuncAnimation(fig, update, frames=total_frames,
                     interval=300, repeat=False)

plt.tight_layout()

writer = FFMpegWriter(fps=5, metadata=dict(title="Attack Trajectory"), bitrate=1800)
anim.save("attack_trajectory.mp4", writer=writer)
print("Saved attack_trajectory.mp4")