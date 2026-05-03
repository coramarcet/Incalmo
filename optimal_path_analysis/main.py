#!/usr/bin/env python3
"""
Pipeline driver for the Incalmo post-hoc analysis.

Takes a single Incalmo action log and runs the full pipeline end-to-end:
    1. Replay events to reconstruct the oracle network state
    2. Compute the optimal attack path
    3. Parse the actual trace and align against optimal
    4. Classify each step into the failure taxonomy
    5. Generate the summary report
    6. Plot the static trajectory timeline (PNG)
    7. Render the side-by-side trajectory animation (MP4, if ffmpeg present)

All outputs land in ./output/{log_stem}_{timestamp}/.

Usage:
    python main.py path/to/action_log.jsonl
    python main.py path/to/action_log.jsonl --verbose
    python main.py path/to/action_log.jsonl --output-dir custom/dir
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import optimal_path_solver as ops
import trace_alignment_diff as tad
import taxonomy_classifier as tc
import generate_report as gr
import generate_graph as gg
import generate_animation as ga


# Filenames produced inside the per-run output folder
ANALYSIS_REPORT = "analysis_report.json"
ALIGNED_TRACE = "aligned_trace.json"
CLASSIFIED_TRACE = "classified_trace.json"
SUMMARY_REPORT = "summary_report.json"
TRAJECTORY_PNG = "trajectory_timeline.png"
TRAJECTORY_MP4 = "attack_trajectory.mp4"


def _say(msg, verbose):
    if verbose:
        print(msg, file=sys.stderr)


def _make_run_dir(action_log_path: Path, base_output_dir: Path) -> Path:
    """Per-run subfolder named {log_stem}_{YYYYMMDD_HHMMSS}."""
    stem = action_log_path.stem  # filename without extension
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = base_output_dir / f"{stem}_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def run_pipeline(action_log: Path, output_root: Path, verbose: bool = False) -> Path:
    """Run all six stages on a single action log. Returns the run dir.
    Stage 6 (animation) is skipped if ffmpeg is not on PATH.
    """
    if not action_log.exists():
        raise FileNotFoundError(f"Action log not found: {action_log}")

    run_dir = _make_run_dir(action_log, output_root)
    _say(f"\n[main] Output directory: {run_dir}\n", verbose)

    # ----- Stage 1: solver — replay + optimal path -----
    _say("[1/6] Replaying events and computing optimal path...", verbose)
    network = ops.replay_events(str(action_log))
    optimal_steps = ops.compute_optimal_path(network)
    analysis = ops.build_analysis_report(network, optimal_steps)
    analysis_path = run_dir / ANALYSIS_REPORT
    analysis_path.write_text(json.dumps(analysis, indent=2, default=str))
    _say(f"      hosts={analysis['environment']['total_hosts']}  "
         f"goals={analysis['environment']['goal_hosts']}  "
         f"optimal_steps={analysis['optimal_path']['total_steps']}", verbose)

    # ----- Stage 2: parse actual trace + align -----
    _say("[2/6] Parsing actual trace and aligning...", verbose)
    actual = tad.parse_actual_trace(str(action_log))
    optimal_normalized = tad.load_optimal_path(str(analysis_path))
    aligned = tad.align_traces(optimal_normalized, actual, verbose=False)
    aligned_path = run_dir / ALIGNED_TRACE
    aligned_path.write_text(json.dumps(aligned, indent=2))
    _say(f"      actual_steps={len(actual)}  aligned={len(aligned)}", verbose)

    # ----- Stage 3: taxonomy classifier -----
    _say("[3/6] Classifying failures...", verbose)
    classified, counts = tc.classify_trace(
        aligned, attack_graph=analysis.get("attack_graph"))
    classified_path = run_dir / CLASSIFIED_TRACE
    classified_path.write_text(json.dumps(classified, indent=2))
    # Build a verbose summary string from the (possibly extended) counts
    parts = [f"productive={counts.get('PRODUCTIVE', 0)}"]
    for k in ("FAILED_EXECUTION", "REDUNDANT", "IRRELEVANT",
              "DEAD_END", "SUBOPTIMAL_ORDERING", "SUBOPTIMAL_EXPLORATION"):
        if counts.get(k):
            parts.append(f"{k.lower()}={counts[k]}")
    _say("      " + "  ".join(parts), verbose)

    # ----- Stage 4: summary report -----
    _say("[4/6] Building summary report...", verbose)
    summary = gr.build_summary(
        classified,
        analysis["optimal_path"]["steps"],
        attack_graph=analysis.get("attack_graph"),
        goal_host_labels=analysis.get("environment", {}).get("goal_host_labels"),
    )
    summary_path = run_dir / SUMMARY_REPORT
    summary_path.write_text(json.dumps(summary, indent=2))
    s = summary["summary"]
    _say(f"      total={s['total_steps']}  "
         f"optimal={s['optimal_path_length']}  "
         f"efficiency={s['path_efficiency']}", verbose)
    for w in s.get("warnings", []):
        _say(f"      WARNING: {w}", verbose)

    # ----- Stage 5: trajectory plot -----
    _say("[5/6] Plotting trajectory timeline...", verbose)
    plot_path = run_dir / TRAJECTORY_PNG
    gg.plot_trajectory(str(classified_path), str(analysis_path), str(plot_path))

    # ----- Stage 6: trajectory animation (optional, requires ffmpeg) -----
    _say("[6/6] Rendering trajectory animation...", verbose)
    if ga.has_ffmpeg():
        anim_path = run_dir / TRAJECTORY_MP4
        try:
            ga.build_animation(str(classified_path), str(anim_path),
                               analysis_path=str(analysis_path))
        except Exception as e:
            # Animation is non-critical; don't let it break the pipeline.
            _say(f"      WARNING: animation failed: {e}", verbose)
    else:
        _say("      Skipped (ffmpeg not on PATH).", verbose)

    return run_dir


def main():
    parser = argparse.ArgumentParser(
        description="Run the full Incalmo post-hoc analysis pipeline.")
    parser.add_argument("action_log",
                        help="Path to an Incalmo action log (.jsonl).")
    parser.add_argument("--output-dir", "-o", default=None,
                        help="Base output directory (default: ./output/ "
                             "next to this script).")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print stage-by-stage progress.")
    args = parser.parse_args()

    if args.output_dir:
        output_root = Path(args.output_dir)
    else:
        # Default to ./output/ in the same directory as this script.
        output_root = Path(__file__).resolve().parent / "output"

    action_log = Path(args.action_log)

    try:
        run_dir = run_pipeline(action_log, output_root, verbose=args.verbose)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Always print the run dir on success — useful for shell scripting.
    print(run_dir)


if __name__ == "__main__":
    main()
