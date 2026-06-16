# secdat Agent Instructions

This file applies to the whole repository.

Follow `.github/copilot-instructions.md` as the shared repository instruction source.

For problem-solving work, use `.codex/agents/rca-shortest-path-solver.toml` before choosing an implementation path. The expected default is shortest-path resolution: trace symptoms back to the cause that keeps producing adjacent failures, then fix the smallest point that cuts that causal chain. Do not default to the shortest-looking local patch when a root-cause fix is likely faster overall.
