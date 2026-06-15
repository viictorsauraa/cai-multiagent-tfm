"""
Multi-model Red Team Pattern

Runs the same red team agent in parallel with different model sizes.
Useful for comparing how model size affects tool-calling reliability,
autonomy, and overall pentest performance on the same target.
"""
from cai.repl.commands.parallel import ParallelConfig

multi_model_redteam_pattern = {
    "name": "multi_model_redteam_pattern",
    "type": "parallel",
    "description": (
        "Red team agents with different model sizes running in parallel "
        "for direct comparison of tool-calling reliability and autonomy"
    ),
    "configs": [
        ParallelConfig("redteam_agent", model="qwen2.5:7b"),
        ParallelConfig("redteam_agent", model="llama3.3:latest"),
    ],
    "unified_context": False,
}
