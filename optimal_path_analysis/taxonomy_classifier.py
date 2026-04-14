#!/usr/bin/env python3
"""
Failure Taxonomy & Frontier Decay Classifier

Reads the aligned trace and breaks down "DEVIATION" actions into specific 
cognitive failures: Redundant (Frontier Decay), Irrelevant, or Dead-End.

Run it using: python3 taxonomy_classifier.py aligned_trace.json
"""

import json
import argparse
import sys
from pathlib import Path

def classify_trace(aligned_trace):
    # The LLM's Simulated "Memory" to track Frontier Decay
    memory = {
        "scanned_targets": set(),
        "infected_hosts": set(),
        "searched_hosts": set()
    }
    
    classified_trace = []
    taxonomy_counts = {
        "PRODUCTIVE": 0,
        "FAILED_EXECUTION": 0,
        "REDUNDANT_FRONTIER_DECAY": 0,
        "IRRELEVANT_DEAD_END": 0
    }

    for step in aligned_trace:
        action = step["action"]
        target = step["target"]
        status = step["status"]
        success = step.get("success", False)
        
        # 1. Handle Productive Actions
        if status in ["MATCH", "SUBOPTIMAL_ORDERING"]:
            step["taxonomy_label"] = "PRODUCTIVE"
            taxonomy_counts["PRODUCTIVE"] += 1
            
            # Update memory because it learned something useful
            if action == "Scan": memory["scanned_targets"].add(target)
            if action == "LateralMoveToHost": memory["infected_hosts"].add(target)
            if action == "FindInformationOnAHost": memory["searched_hosts"].add(target)
            
        # 2. Handle Failed Actions
        elif status == "FAILED_EXECUTION" or not success:
            step["taxonomy_label"] = "FAILED_EXECUTION"
            taxonomy_counts["FAILED_EXECUTION"] += 1
            
        # 3. Handle Deviations
        elif status == "DEVIATION":
            is_redundant = False
            
            # FRONTIER DECAY HEURISTIC: Did it forget it already did this?
            if action == "Scan" and target in memory["scanned_targets"]:
                is_redundant = True
            elif action == "LateralMoveToHost" and target in memory["infected_hosts"]:
                is_redundant = True
            elif action == "FindInformationOnAHost" and target in memory["searched_hosts"]:
                is_redundant = True
                
            if is_redundant:
                step["taxonomy_label"] = "REDUNDANT_FRONTIER_DECAY"
                taxonomy_counts["REDUNDANT_FRONTIER_DECAY"] += 1
            else:
                step["taxonomy_label"] = "IRRELEVANT_DEAD_END"
                taxonomy_counts["IRRELEVANT_DEAD_END"] += 1
                
                # Even if it's a dead-end, if it succeeded, it goes into memory
                # so we can catch if it loops back to this dead-end later
                if success:
                    if action == "Scan": memory["scanned_targets"].add(target)
                    if action == "LateralMoveToHost": memory["infected_hosts"].add(target)
                    if action == "FindInformationOnAHost": memory["searched_hosts"].add(target)

        classified_trace.append(step)

    return classified_trace, taxonomy_counts

def main():
    parser = argparse.ArgumentParser(description="Classify deviations into taxonomy categories.")
    parser.add_argument("aligned_trace", help="Path to aligned_trace.json from Trace Alignment tool")
    parser.add_argument("--output", "-o", default="classified_trace.json", help="Output JSON file")
    args = parser.parse_args()

    try:
        with open(args.aligned_trace, 'r') as f:
            aligned_trace = json.load(f)
    except FileNotFoundError:
        print(f"Error: Could not find {args.aligned_trace}", file=sys.stderr)
        sys.exit(1)

    classified_trace, counts = classify_trace(aligned_trace)

    # Output the newly labeled trace
    Path(args.output).write_text(json.dumps(classified_trace, indent=2))

    # Print Report to Terminal
    total_waste = counts["FAILED_EXECUTION"] + counts["REDUNDANT_FRONTIER_DECAY"] + counts["IRRELEVANT_DEAD_END"]
    
    print("\n" + "="*50)
    print("COGNITIVE FAILURE TAXONOMY REPORT")
    print("="*50)
    print(f"  Total Productive Steps:     {counts['PRODUCTIVE']}")
    print(f"  Total Wasted Steps:         {total_waste}")
    print("-" * 50)
    print("  Waste Breakdown:")
    print(f"    - Failed Executions:      {counts['FAILED_EXECUTION']}")
    print(f"    - Irrelevant/Dead-Ends:   {counts['IRRELEVANT_DEAD_END']}  (Explored wrong path)")
    print(f"    - Frontier Decay:         {counts['REDUNDANT_FRONTIER_DECAY']}  (Forgot/Repeated actions)")
    print("="*50 + "\n")
    print(f"Detailed trace saved to: {args.output}")

if __name__ == "__main__":
    main()
