import json
from collections import Counter

# Load file
with open("classified_trace.json") as f:
    trace = json.load(f)

total_steps = len(trace)

# Count taxonomy labels
label_counts = Counter(step["taxonomy_label"] for step in trace)

# Count productive vs non-productive
productive = label_counts.get("PRODUCTIVE", 0) + label_counts.get("MATCH", 0)
non_productive = total_steps - productive

# Find the optimal path length (highest optimal_step among MATCH steps)
match_steps = [s["optimal_step"] for s in trace if s.get("status") == "MATCH" and s.get("optimal_step")]
optimal_length = len(match_steps)

# Path efficiency
match_rate = round(optimal_length / total_steps, 4) if optimal_length else None

# What fraction of steps made ANY forward progress (productive)
productive_count = label_counts.get("PRODUCTIVE", 0)
productive_rate = round(productive_count / total_steps, 4)  # ~0.936

# Waste ratio
waste_ratio = round(non_productive / total_steps, 4)

# Excess actions by type (count actual vs what optimal would have been)
from collections import defaultdict
actual_action_counts = Counter(s["action"] for s in trace)
optimal_action_counts = Counter(s["action"] for s in trace if s.get("status") == "MATCH")
excess_by_action = {
    action: actual_action_counts[action] - optimal_action_counts.get(action, 0)
    for action in actual_action_counts
    if actual_action_counts[action] - optimal_action_counts.get(action, 0) > 0
}

# Deviation blocks (consecutive non-MATCH steps)
deviation_blocks = []
current_block = []
for step in trace:
    if step.get("status") != "MATCH":
        current_block.append(step["step"])
    else:
        if current_block:
            deviation_blocks.append({"steps": current_block, "length": len(current_block)})
            current_block = []
if current_block:
    deviation_blocks.append({"steps": current_block, "length": len(current_block)})

# Build the report
report = {
    "summary": {
        "total_steps": total_steps,
        "optimal_path_length": optimal_length,
        "path_efficiency": productive_rate,
        "waste_ratio": waste_ratio,
    },
    "category_breakdown": dict(label_counts),
    "excess_actions_by_type": excess_by_action,
    "deviation_blocks": deviation_blocks,
}

with open("summary_report.json", "w") as f:
    json.dump(report, f, indent=2)

#print("Report written to summary_report.json")
#print(json.dumps(report, indent=2))