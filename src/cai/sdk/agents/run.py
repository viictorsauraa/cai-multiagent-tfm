from __future__ import annotations

import asyncio
import copy
import json
import os
import logging
from dataclasses import dataclass, field
from typing import Any, cast

from openai.types.responses import ResponseCompletedEvent

logger = logging.getLogger(__name__)

_HANDOFF_CONTEXT_MESSAGES = int(os.getenv("CAI_HANDOFF_CONTEXT_MESSAGES", "10"))
_HANDOFF_MSG_TRUNCATE = int(os.getenv("CAI_HANDOFF_MSG_TRUNCATE", "500"))
_TOOL_OUTPUT_TRUNCATE = 800       # Max chars per tool output in briefing
_MAX_COMMANDS_IN_BRIEFING = 15    # Max commands to list in briefing
_MAX_FINDINGS_IN_BRIEFING = 1500  # Max chars from state.txt in briefing
_MAX_BRIEFINGS_PER_AGENT = 3      # Max briefings from different sources

# Tools whose calls/results are excluded from briefing (shown via state.txt instead)
_FINDINGS_TOOLS = frozenset({"write_key_findings", "read_key_findings", "thought", "think"})

from .repetition_detector import RepetitionDetector, extract_last_commands

from ._run_impl import (
    AgentToolUseTracker,
    NextStepFinalOutput,
    NextStepHandoff,
    NextStepRunAgain,
    QueueCompleteSentinel,
    RunImpl,
    SingleStepResult,
    TraceCtxManager,
    get_model_tracing_impl,
)
from .agent import Agent
from .agent_output import AgentOutputSchema
from .exceptions import (
    AgentsException,
    InputGuardrailTripwireTriggered,
    MaxTurnsExceeded,
    ModelBehaviorError,
    OutputGuardrailTripwireTriggered,
)
from .guardrail import InputGuardrail, InputGuardrailResult, OutputGuardrail, OutputGuardrailResult
from .handoffs import Handoff, HandoffInputFilter, handoff
from .items import ItemHelpers, ModelResponse, RunItem, TResponseInputItem
from .lifecycle import RunHooks
from .logger import logger
from .model_settings import ModelSettings
from .models.interface import Model, ModelProvider
from .models.openai_provider import OpenAIProvider
from .result import RunResult, RunResultStreaming
from .run_context import RunContextWrapper, TContext
from .stream_events import AgentUpdatedStreamEvent, RawResponsesStreamEvent
from .tool import Tool
from .tracing import Span, SpanError, agent_span, get_current_trace, trace
from .tracing.span_data import AgentSpanData
from .usage import Usage
from .util import _coro, _error_tracing

# CAI_MAX_TURNS must be converted to an int to avoid type mismatch error when comparing.
max_turns_env = os.getenv("CAI_MAX_TURNS")
if max_turns_env is not None:
    try:
        DEFAULT_MAX_TURNS = int(max_turns_env)
    except ValueError:
        try:
            DEFAULT_MAX_TURNS = float(max_turns_env)
        except ValueError:
            DEFAULT_MAX_TURNS = float("inf")
else:
    DEFAULT_MAX_TURNS = float("inf")

price_limit_env = os.getenv("CAI_PRICE_LIMIT")
if price_limit_env is not None:
    try:
        DEFAULT_PRICE_LIMIT = float(price_limit_env)
    except ValueError:
        DEFAULT_PRICE_LIMIT = float("inf")
else:
    DEFAULT_PRICE_LIMIT = float("inf")


@dataclass
class RunConfig:
    """Configures settings for the entire agent run."""

    model: str | Model | None = None
    """The model to use for the entire agent run. If set, will override the model set on every
    agent. The model_provider passed in below must be able to resolve this model name.
    """

    model_provider: ModelProvider = field(default_factory=OpenAIProvider)
    """The model provider to use when looking up string model names. Defaults to OpenAI."""

    model_settings: ModelSettings | None = None
    """Configure global model settings. Any non-null values will override the agent-specific model
    settings.
    """

    handoff_input_filter: HandoffInputFilter | None = None
    """A global input filter to apply to all handoffs. If `Handoff.input_filter` is set, then that
    will take precedence. The input filter allows you to edit the inputs that are sent to the new
    agent. See the documentation in `Handoff.input_filter` for more details.
    """

    input_guardrails: list[InputGuardrail[Any]] | None = None
    """A list of input guardrails to run on the initial run input."""

    output_guardrails: list[OutputGuardrail[Any]] | None = None
    """A list of output guardrails to run on the final output of the run."""

    tracing_disabled: bool = False
    """Whether tracing is disabled for the agent run. If disabled, we will not trace the agent run.
    """

    trace_include_sensitive_data: bool = True
    """Whether we include potentially sensitive data (for example: inputs/outputs of tool calls or
    LLM generations) in traces. If False, we'll still create spans for these events, but the
    sensitive data will not be included.
    """

    workflow_name: str = "Agent workflow"
    """The name of the run, used for tracing. Should be a logical name for the run, like
    "Code generation workflow" or "Customer support agent".
    """

    trace_id: str | None = None
    """A custom trace ID to use for tracing. If not provided, we will generate a new trace ID."""

    group_id: str | None = None
    """
    A grouping identifier to use for tracing, to link multiple traces from the same conversation
    or process. For example, you might use a chat thread ID.
    """

    trace_metadata: dict[str, Any] | None = None
    """
    An optional dictionary of additional metadata to include with the trace.
    """


def _read_state_for_briefing() -> str:
    """Read state.txt for inclusion in handoff briefing. Returns '' if not found."""
    try:
        from cai.tools.misc.reasoning import _state_file_path
        with open(_state_file_path(), encoding="utf-8") as f:
            content = f.read().strip()
        if not content:
            return ""
        if len(content) > _MAX_FINDINGS_IN_BRIEFING:
            content = "...\n" + content[-_MAX_FINDINGS_IN_BRIEFING:]
        return content
    except (FileNotFoundError, OSError, ImportError):
        return ""


def _inject_handoff_context(from_agent: Agent[Any], to_agent: Agent[Any], current_items_len: int = 0) -> None:
    """Extract structured context from from_agent and inject into to_agent's history.

    Builds a template-based briefing with semantic sections instead of copying
    raw messages. Findings-related tool calls (write/read_key_findings, thought,
    think) are excluded from the briefing body — their data appears only in the
    ``## Current Findings`` section read from state.txt.
    """
    from_history = getattr(from_agent.model, 'message_history', None)
    if not from_history:
        to_agent._isolated_items_offset = current_items_len
        return

    # Filter out system messages
    relevant = [m for m in from_history if m.get("role") != "system"]

    # Extract the original user objective (first non-empty user message
    # that is NOT a briefing or the generic "Continue with your task" nudge).
    # This ensures the target IP / goal always reaches specialist agents.
    user_objective = ""
    for m in relevant:
        if m.get("role") == "user":
            text = str(m.get("content", "")).strip()
            if (text
                and not text.startswith("[Handoff from ")
                and not text.startswith("WARNING: ")
                and text != "Continue with your task based on the context provided."):
                user_objective = text
                break
    if len(user_objective) > _HANDOFF_MSG_TRUNCATE:
        user_objective = user_objective[:_HANDOFF_MSG_TRUNCATE] + "..."

    # Extract user instructions that came AFTER the last received briefing.
    # This prevents duplication: if A→B→A→C, instructions from before B's
    # briefing are already embedded in B's briefing and should not be re-extracted.
    user_instructions: list[str] = []
    last_briefing_idx = -1
    for idx, m in enumerate(relevant):
        if m.get("role") == "user" and str(m.get("content", "")).startswith("[Handoff from "):
            last_briefing_idx = idx

    found_objective = False
    for idx, m in enumerate(relevant):
        if m.get("role") != "user":
            continue
        text = str(m.get("content", "")).strip()
        if not text:
            continue
        if text.startswith("[Handoff from "):
            continue
        if text.startswith("WARNING: "):
            continue
        if text == "Continue with your task based on the context provided.":
            continue
        if text == "Continue working on the task based on your previous findings.":
            continue
        if not found_objective:
            found_objective = True  # Skip first one (already extracted as objective)
            continue
        # Only include instructions that came AFTER the last briefing
        if idx <= last_briefing_idx:
            continue
        truncated = text[:_HANDOFF_MSG_TRUNCATE] + "..." if len(text) > _HANDOFF_MSG_TRUNCATE else text
        if truncated not in user_instructions:  # dedup safety
            user_instructions.append(truncated)

    # --- Parse message history into structured sections ---
    commands_executed: list[str] = []
    tool_outputs: list[str] = []
    conclusion = ""
    call_id_to_name: dict[str, str] = {}

    for msg in relevant:
        role = msg.get("role")

        if role == "assistant":
            # Extract tool call names and args
            for tc in msg.get("tool_calls", []):
                func = tc.get("function", {})
                name = func.get("name", "")
                args_raw = func.get("arguments", "{}")
                call_id = tc.get("id", "")
                if call_id:
                    call_id_to_name[call_id] = name
                # Skip findings tools — their data goes in state.txt section
                if name in _FINDINGS_TOOLS:
                    continue
                try:
                    args = json.loads(args_raw)
                    if name == "generic_linux_command":
                        cmd = args.get("command", args_raw)
                        commands_executed.append(str(cmd))
                    else:
                        args_str = ", ".join(f"{k}={v!r}" for k, v in args.items())
                        commands_executed.append(f"{name}({args_str})")
                except (json.JSONDecodeError, AttributeError, TypeError):
                    commands_executed.append(f"{name}(...)")

            # Last assistant content with text = conclusion
            content = msg.get("content")
            if content and str(content).strip():
                conclusion = str(content).strip()

        elif role == "tool":
            call_id = msg.get("tool_call_id", "")
            name = call_id_to_name.get(call_id, "unknown")
            # Skip findings-related tool results
            if name in _FINDINGS_TOOLS:
                continue
            content = str(msg.get("content", ""))
            if not content.strip():
                continue
            if len(content) > _TOOL_OUTPUT_TRUNCATE:
                content = content[:_TOOL_OUTPUT_TRUNCATE] + f"... [{len(content)} chars total]"
            tool_outputs.append(f"[{name}]: {content}")

    # Limit commands to last N
    if len(commands_executed) > _MAX_COMMANDS_IN_BRIEFING:
        commands_executed = commands_executed[-_MAX_COMMANDS_IN_BRIEFING:]

    # Truncate conclusion
    if len(conclusion) > _HANDOFF_MSG_TRUNCATE:
        conclusion = conclusion[:_HANDOFF_MSG_TRUNCATE] + "..."

    # Read state.txt for findings section
    findings = _read_state_for_briefing()

    # --- Build structured briefing ---
    sections: list[str] = []
    if user_objective:
        sections.append("## Objective\n" + user_objective)
    if user_instructions:
        sections.append("## User Instructions (HIGH PRIORITY)\n" + "\n".join(user_instructions))
    if commands_executed:
        sections.append("## Commands Executed\n" + "\n".join(f"- {c}" for c in commands_executed))
    if tool_outputs:
        sections.append("## Key Tool Outputs\n" + "\n".join(tool_outputs))
    if conclusion:
        sections.append("## Agent Conclusion\n" + conclusion)
    if findings:
        sections.append("## Current Findings (state.txt)\n" + findings)

    # Ensure to_agent has its own history list (not shared)
    if not hasattr(to_agent.model, 'message_history') or to_agent.model.message_history is from_history:
        to_agent.model.message_history = []

    if not sections:
        to_agent._isolated_items_offset = current_items_len
        return

    context_msg = {
        "role": "user",
        "content": f"[Handoff from {from_agent.name}]\n\n" + "\n\n".join(sections),
    }

    # Remove previous briefings from the same source agent
    handoff_prefix = f"[Handoff from {from_agent.name}]"
    to_agent.model.message_history = [
        m for m in to_agent.model.message_history
        if not (m.get("role") == "user" and str(m.get("content", "")).startswith(handoff_prefix))
    ]

    # Limit total briefings from different sources
    briefing_msgs = [
        m for m in to_agent.model.message_history
        if m.get("role") == "user" and str(m.get("content", "")).startswith("[Handoff from ")
    ]
    while len(briefing_msgs) >= _MAX_BRIEFINGS_PER_AGENT:
        oldest = briefing_msgs.pop(0)
        to_agent.model.message_history.remove(oldest)

    to_agent.model.message_history.append(context_msg)

    # Set offset to current generated_items length so next turn
    # only processes items created AFTER this handoff.
    # Prevents duplication on round-trip handoffs (A→B→A).
    to_agent._isolated_items_offset = current_items_len


class Runner:
    @classmethod
    async def run(
        cls,
        starting_agent: Agent[TContext],
        input: str | list[TResponseInputItem],
        *,
        context: TContext | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,
        hooks: RunHooks[TContext] | None = None,
        run_config: RunConfig | None = None,
    ) -> RunResult:
        """Run a workflow starting at the given agent. The agent will run in a loop until a final
        output is generated. The loop runs like so:
        1. The agent is invoked with the given input.
        2. If there is a final output (i.e. the agent produces something of type
            `agent.output_type`, the loop terminates.
        3. If there's a handoff, we run the loop again, with the new agent.
        4. Else, we run tool calls (if any), and re-run the loop.

        In two cases, the agent may raise an exception:
        1. If the max_turns is exceeded, a MaxTurnsExceeded exception is raised.
        2. If a guardrail tripwire is triggered, a GuardrailTripwireTriggered exception is raised.

        Note that only the first agent's input guardrails are run.

        Args:
            starting_agent: The starting agent to run.
            input: The initial input to the agent. You can pass a single string for a user message,
                or a list of input items.
            context: The context to run the agent with.
            max_turns: The maximum number of turns to run the agent for. A turn is defined as one
                AI invocation (including any tool calls that might occur).
            hooks: An object that receives callbacks on various lifecycle events.
            run_config: Global settings for the entire agent run.

        Returns:
            A run result containing all the inputs, guardrail results and the output of the last
            agent. Agents may perform handoffs, so we don't know the specific type of the output.
        """
        if hooks is None:
            hooks = RunHooks[Any]()
        if run_config is None:
            run_config = RunConfig()

        tool_use_tracker = AgentToolUseTracker()

        with TraceCtxManager(
            workflow_name=run_config.workflow_name,
            trace_id=run_config.trace_id,
            group_id=run_config.group_id,
            metadata=run_config.trace_metadata,
            disabled=run_config.tracing_disabled,
        ):
            current_turn = 0
            original_input: str | list[TResponseInputItem] = copy.deepcopy(input)
            generated_items: list[RunItem] = []
            model_responses: list[ModelResponse] = []
            repetition_detector = RepetitionDetector()

            context_wrapper: RunContextWrapper[TContext] = RunContextWrapper(
                context=context,  # type: ignore
            )

            input_guardrail_results: list[InputGuardrailResult] = []

            current_span: Span[AgentSpanData] | None = None
            current_agent = starting_agent
            should_run_agent_start_hooks = True

            try:
                while True:
                    # Start an agent span if we don't have one. This span is ended if the current
                    # agent changes, or if the agent loop ends.
                    if current_span is None:
                        handoff_names = [h.agent_name for h in cls._get_handoffs(current_agent)]
                        if output_schema := cls._get_output_schema(current_agent):
                            output_type_name = output_schema.output_type_name()
                        else:
                            output_type_name = "str"

                        current_span = agent_span(
                            name=current_agent.name,
                            handoffs=handoff_names,
                            output_type=output_type_name,
                        )
                        current_span.start(mark_as_current=True)

                        all_tools = await cls._get_all_tools(current_agent)
                        current_span.span_data.tools = [t.name for t in all_tools]

                    current_turn += 1
                    if current_turn > max_turns:
                        _error_tracing.attach_error_to_span(
                            current_span,
                            SpanError(
                                message="Max turns exceeded",
                                data={"max_turns": max_turns},
                            ),
                        )
                        raise MaxTurnsExceeded(f"Max turns ({max_turns}) exceeded")

                    logger.debug(
                        f"Running agent {current_agent.name} (turn {current_turn})",
                    )

                    if current_turn == 1:
                        input_guardrail_results, turn_result = await asyncio.gather(
                            cls._run_input_guardrails(
                                starting_agent,
                                starting_agent.input_guardrails
                                + (run_config.input_guardrails or []),
                                copy.deepcopy(input),
                                context_wrapper,
                            ),
                            cls._run_single_turn(
                                agent=current_agent,
                                all_tools=all_tools,
                                original_input=original_input,
                                generated_items=generated_items,
                                hooks=hooks,
                                context_wrapper=context_wrapper,
                                run_config=run_config,
                                should_run_agent_start_hooks=should_run_agent_start_hooks,
                                tool_use_tracker=tool_use_tracker,
                            ),
                        )
                    else:
                        turn_result = await cls._run_single_turn(
                            agent=current_agent,
                            all_tools=all_tools,
                            original_input=original_input,
                            generated_items=generated_items,
                            hooks=hooks,
                            context_wrapper=context_wrapper,
                            run_config=run_config,
                            should_run_agent_start_hooks=should_run_agent_start_hooks,
                            tool_use_tracker=tool_use_tracker,
                        )
                    should_run_agent_start_hooks = False

                    model_responses.append(turn_result.model_response)
                    original_input = turn_result.original_input
                    generated_items = turn_result.generated_items

                    if isinstance(turn_result.next_step, NextStepFinalOutput):
                        output_guardrail_results = await cls._run_output_guardrails(
                            current_agent.output_guardrails + (run_config.output_guardrails or []),
                            current_agent,
                            turn_result.next_step.output,
                            context_wrapper,
                        )
                        return RunResult(
                            input=original_input,
                            new_items=generated_items,
                            raw_responses=model_responses,
                            final_output=turn_result.next_step.output,
                            _last_agent=current_agent,
                            input_guardrail_results=input_guardrail_results,
                            output_guardrail_results=output_guardrail_results,
                        )
                    elif isinstance(turn_result.next_step, NextStepHandoff):
                        # Get the previous agent before switching
                        previous_agent = current_agent
                        current_agent = cast(Agent[TContext], turn_result.next_step.new_agent)
                        logger.info(
                            "Handoff: %s → %s (model: %s)",
                            previous_agent.name,
                            current_agent.name,
                            getattr(current_agent.model, 'model', 'unknown'),
                        )

                        # Transfer message history for swarm patterns
                        # Check if both agents have models with message_history
                        if (hasattr(previous_agent, 'model') and hasattr(previous_agent.model, 'message_history') and
                            hasattr(current_agent, 'model') and hasattr(current_agent.model, 'message_history')):
                            # Check if either agent uses isolated context
                            use_isolation = (
                                getattr(current_agent, 'isolated_context', False) or
                                getattr(previous_agent, 'isolated_context', False)
                            )
                            # Import the is_swarm_pattern function from patterns utils
                            try:
                                from cai.agents.patterns.utils import is_swarm_pattern
                                # Check if either agent is part of a swarm pattern
                                if is_swarm_pattern(previous_agent) or is_swarm_pattern(current_agent):
                                    if use_isolation:
                                        # Per-agent context: inject summary instead of sharing
                                        _inject_handoff_context(previous_agent, current_agent, len(generated_items))
                                        logger.info(
                                            "Isolated context: injected %d msgs from %s → %s",
                                            _HANDOFF_CONTEXT_MESSAGES,
                                            previous_agent.name,
                                            current_agent.name,
                                        )
                                    else:
                                        # Original behavior: share history reference
                                        current_agent.model.message_history = previous_agent.model.message_history
                                        # Also share history in AGENT_MANAGER
                                        if hasattr(previous_agent, 'name') and hasattr(current_agent, 'name'):
                                            from cai.sdk.agents.simple_agent_manager import AGENT_MANAGER
                                            AGENT_MANAGER.share_swarm_history(previous_agent.name, current_agent.name)
                            except ImportError:
                                # If we can't import, check if agents have bidirectional handoffs
                                # by looking if the new agent can handoff back to the previous agent
                                if hasattr(current_agent, 'handoffs'):
                                    for handoff_item in current_agent.handoffs:
                                        if hasattr(handoff_item, 'agent_name') and handoff_item.agent_name == previous_agent.name:
                                            # Bidirectional handoff detected, share history
                                            current_agent.model.message_history = previous_agent.model.message_history
                                            break

                        # Register the handoff agent with AGENT_MANAGER for tracking
                        # This ensures patterns/swarms work with commands like /history and /graph
                        from cai.sdk.agents.simple_agent_manager import AGENT_MANAGER
                        if hasattr(current_agent, 'name'):
                            # For non-parallel patterns, use set_active_agent which will handle it as single agent
                            # This maintains compatibility with single agent commands
                            AGENT_MANAGER.set_active_agent(current_agent, current_agent.name)
                        
                        current_span.finish(reset_current=True)
                        current_span = None
                        should_run_agent_start_hooks = True
                        repetition_detector.reset()
                    elif isinstance(turn_result.next_step, NextStepRunAgain):
                        # Check for repeated commands
                        if hasattr(current_agent, 'model') and hasattr(current_agent.model, 'message_history'):
                            for cmd in extract_last_commands(current_agent.model.message_history):
                                repetition_detector.record(cmd)
                            if repetition_detector.should_warn():
                                repetition_detector.mark_warned()
                                current_agent.model.message_history.append({
                                    "role": "user",
                                    "content": (
                                        "WARNING: You have executed very similar commands "
                                        f"{repetition_detector.threshold} times consecutively. "
                                        "The approach is NOT working. You MUST either: "
                                        "(1) try a completely different tool or approach, "
                                        "(2) call write_key_findings with what you have learned so far, "
                                        "(3) hand off back to the orchestrator. "
                                        "Do NOT repeat the same command with minor variations."
                                    ),
                                })
                                logger.warning(
                                    "Repetition detected for agent %s: %d similar commands",
                                    current_agent.name, len(repetition_detector._history),
                                )
                    else:
                        raise AgentsException(
                            f"Unknown next step type: {type(turn_result.next_step)}"
                        )
            finally:
                if current_span:
                    current_span.finish(reset_current=True)

    @classmethod
    def run_sync(
        cls,
        starting_agent: Agent[TContext],
        input: str | list[TResponseInputItem],
        *,
        context: TContext | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,
        hooks: RunHooks[TContext] | None = None,
        run_config: RunConfig | None = None,
    ) -> RunResult:
        """Run a workflow synchronously, starting at the given agent. Note that this just wraps the
        `run` method, so it will not work if there's already an event loop (e.g. inside an async
        function, or in a Jupyter notebook or async context like FastAPI). For those cases, use
        the `run` method instead.

        The agent will run in a loop until a final output is generated. The loop runs like so:
        1. The agent is invoked with the given input.
        2. If there is a final output (i.e. the agent produces something of type
            `agent.output_type`, the loop terminates.
        3. If there's a handoff, we run the loop again, with the new agent.
        4. Else, we run tool calls (if any), and re-run the loop.

        In two cases, the agent may raise an exception:
        1. If the max_turns is exceeded, a MaxTurnsExceeded exception is raised.
        2. If a guardrail tripwire is triggered, a GuardrailTripwireTriggered exception is raised.

        Note that only the first agent's input guardrails are run.

        Args:
            starting_agent: The starting agent to run.
            input: The initial input to the agent. You can pass a single string for a user message,
                or a list of input items.
            context: The context to run the agent with.
            max_turns: The maximum number of turns to run the agent for. A turn is defined as one
                AI invocation (including any tool calls that might occur).
            hooks: An object that receives callbacks on various lifecycle events.
            run_config: Global settings for the entire agent run.

        Returns:
            A run result containing all the inputs, guardrail results and the output of the last
            agent. Agents may perform handoffs, so we don't know the specific type of the output.
        """
        return asyncio.get_event_loop().run_until_complete(
            cls.run(
                starting_agent,
                input,
                context=context,
                max_turns=max_turns,
                hooks=hooks,
                run_config=run_config,
            )
        )

    @classmethod
    def run_streamed(
        cls,
        starting_agent: Agent[TContext],
        input: str | list[TResponseInputItem],
        context: TContext | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,
        hooks: RunHooks[TContext] | None = None,
        run_config: RunConfig | None = None,
    ) -> RunResultStreaming:
        """Run a workflow starting at the given agent in streaming mode. The returned result object
        contains a method you can use to stream semantic events as they are generated.

        The agent will run in a loop until a final output is generated. The loop runs like so:
        1. The agent is invoked with the given input.
        2. If there is a final output (i.e. the agent produces something of type
            `agent.output_type`, the loop terminates.
        3. If there's a handoff, we run the loop again, with the new agent.
        4. Else, we run tool calls (if any), and re-run the loop.

        In two cases, the agent may raise an exception:
        1. If the max_turns is exceeded, a MaxTurnsExceeded exception is raised.
        2. If a guardrail tripwire is triggered, a GuardrailTripwireTriggered exception is raised.

        Note that only the first agent's input guardrails are run.

        Args:
            starting_agent: The starting agent to run.
            input: The initial input to the agent. You can pass a single string for a user message,
                or a list of input items.
            context: The context to run the agent with.
            max_turns: The maximum number of turns to run the agent for. A turn is defined as one
                AI invocation (including any tool calls that might occur).
            hooks: An object that receives callbacks on various lifecycle events.
            run_config: Global settings for the entire agent run.

        Returns:
            A result object that contains data about the run, as well as a method to stream events.
        """
        if hooks is None:
            hooks = RunHooks[Any]()
        if run_config is None:
            run_config = RunConfig()

        # If there's already a trace, we don't create a new one. In addition, we can't end the
        # trace here, because the actual work is done in `stream_events` and this method ends
        # before that.
        new_trace = (
            None
            if get_current_trace()
            else trace(
                workflow_name=run_config.workflow_name,
                trace_id=run_config.trace_id,
                group_id=run_config.group_id,
                metadata=run_config.trace_metadata,
                disabled=run_config.tracing_disabled,
            )
        )
        # Need to start the trace here, because the current trace contextvar is captured at
        # asyncio.create_task time
        if new_trace:
            new_trace.start(mark_as_current=True)

        output_schema = cls._get_output_schema(starting_agent)
        context_wrapper: RunContextWrapper[TContext] = RunContextWrapper(
            context=context  # type: ignore
        )

        streamed_result = RunResultStreaming(
            input=copy.deepcopy(input),
            new_items=[],
            current_agent=starting_agent,
            raw_responses=[],
            final_output=None,
            is_complete=False,
            current_turn=0,
            max_turns=max_turns,
            input_guardrail_results=[],
            output_guardrail_results=[],
            _current_agent_output_schema=output_schema,
            _trace=new_trace,
        )

        # Kick off the actual agent loop in the background and return the streamed result object.
        streamed_result._run_impl_task = asyncio.create_task(
            cls._run_streamed_impl(
                starting_input=input,
                streamed_result=streamed_result,
                starting_agent=starting_agent,
                max_turns=max_turns,
                hooks=hooks,
                context_wrapper=context_wrapper,
                run_config=run_config,
            )
        )
        return streamed_result

    @classmethod
    async def _run_input_guardrails_with_queue(
        cls,
        agent: Agent[Any],
        guardrails: list[InputGuardrail[TContext]],
        input: str | list[TResponseInputItem],
        context: RunContextWrapper[TContext],
        streamed_result: RunResultStreaming,
        parent_span: Span[Any],
    ):
        queue = streamed_result._input_guardrail_queue

        # We'll run the guardrails and push them onto the queue as they complete
        guardrail_tasks = [
            asyncio.create_task(
                RunImpl.run_single_input_guardrail(agent, guardrail, input, context)
            )
            for guardrail in guardrails
        ]
        guardrail_results = []
        try:
            for done in asyncio.as_completed(guardrail_tasks):
                result = await done
                if result.output.tripwire_triggered:
                    _error_tracing.attach_error_to_span(
                        parent_span,
                        SpanError(
                            message="Guardrail tripwire triggered",
                            data={
                                "guardrail": result.guardrail.get_name(),
                                "type": "input_guardrail",
                            },
                        ),
                    )
                queue.put_nowait(result)
                guardrail_results.append(result)
        except Exception:
            for t in guardrail_tasks:
                t.cancel()
            raise

        streamed_result.input_guardrail_results = guardrail_results

    @classmethod
    async def _run_streamed_impl(
        cls,
        starting_input: str | list[TResponseInputItem],
        streamed_result: RunResultStreaming,
        starting_agent: Agent[TContext],
        max_turns: int,
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
    ):
        current_span: Span[AgentSpanData] | None = None
        current_agent = starting_agent
        current_turn = 0
        should_run_agent_start_hooks = True
        tool_use_tracker = AgentToolUseTracker()

        streamed_result._event_queue.put_nowait(AgentUpdatedStreamEvent(new_agent=current_agent))

        try:
            while True:
                if streamed_result.is_complete:
                    break

                # Start an agent span if we don't have one. This span is ended if the current
                # agent changes, or if the agent loop ends.
                if current_span is None:
                    handoff_names = [h.agent_name for h in cls._get_handoffs(current_agent)]
                    if output_schema := cls._get_output_schema(current_agent):
                        output_type_name = output_schema.output_type_name()
                    else:
                        output_type_name = "str"

                    current_span = agent_span(
                        name=current_agent.name,
                        handoffs=handoff_names,
                        output_type=output_type_name,
                    )
                    current_span.start(mark_as_current=True)

                    all_tools = await cls._get_all_tools(current_agent)
                    tool_names = [t.name for t in all_tools]
                    current_span.span_data.tools = tool_names
                current_turn += 1
                streamed_result.current_turn = current_turn

                if current_turn > max_turns:
                    _error_tracing.attach_error_to_span(
                        current_span,
                        SpanError(
                            message="Max turns exceeded",
                            data={"max_turns": max_turns},
                        ),
                    )
                    streamed_result._event_queue.put_nowait(QueueCompleteSentinel())
                    break

                if current_turn == 1:
                    # Run the input guardrails in the background and put the results on the queue
                    streamed_result._input_guardrails_task = asyncio.create_task(
                        cls._run_input_guardrails_with_queue(
                            starting_agent,
                            starting_agent.input_guardrails + (run_config.input_guardrails or []),
                            copy.deepcopy(ItemHelpers.input_to_new_input_list(starting_input)),
                            context_wrapper,
                            streamed_result,
                            current_span,
                        )
                    )
                try:
                    turn_result = await cls._run_single_turn_streamed(
                        streamed_result,
                        current_agent,
                        hooks,
                        context_wrapper,
                        run_config,
                        should_run_agent_start_hooks,
                        tool_use_tracker,
                        all_tools,
                    )
                    should_run_agent_start_hooks = False
                    
                    # Process the turn result
                    streamed_result.raw_responses = streamed_result.raw_responses + [
                        turn_result.model_response
                    ]
                    streamed_result.input = turn_result.original_input
                    streamed_result.new_items = turn_result.generated_items

                    if isinstance(turn_result.next_step, NextStepHandoff):
                        # Get the previous agent before switching
                        previous_agent = current_agent
                        current_agent = turn_result.next_step.new_agent

                        # Transfer message history for swarm patterns
                        # Check if both agents have models with message_history
                        if (hasattr(previous_agent, 'model') and hasattr(previous_agent.model, 'message_history') and
                            hasattr(current_agent, 'model') and hasattr(current_agent.model, 'message_history')):
                            # Check if either agent uses isolated context
                            use_isolation = (
                                getattr(current_agent, 'isolated_context', False) or
                                getattr(previous_agent, 'isolated_context', False)
                            )
                            # Import the is_swarm_pattern function from patterns utils
                            try:
                                from cai.agents.patterns.utils import is_swarm_pattern
                                # Check if either agent is part of a swarm pattern
                                if is_swarm_pattern(previous_agent) or is_swarm_pattern(current_agent):
                                    if use_isolation:
                                        # Per-agent context: inject summary instead of sharing
                                        _inject_handoff_context(previous_agent, current_agent, len(streamed_result.new_items))
                                        logger.info(
                                            "Isolated context: injected %d msgs from %s → %s",
                                            _HANDOFF_CONTEXT_MESSAGES,
                                            previous_agent.name,
                                            current_agent.name,
                                        )
                                    else:
                                        # Original behavior: share history reference
                                        current_agent.model.message_history = previous_agent.model.message_history
                                        # Also share history in AGENT_MANAGER
                                        if hasattr(previous_agent, 'name') and hasattr(current_agent, 'name'):
                                            from cai.sdk.agents.simple_agent_manager import AGENT_MANAGER
                                            AGENT_MANAGER.share_swarm_history(previous_agent.name, current_agent.name)
                            except ImportError:
                                # If we can't import, check if agents have bidirectional handoffs
                                # by looking if the new agent can handoff back to the previous agent
                                if hasattr(current_agent, 'handoffs'):
                                    for handoff_item in current_agent.handoffs:
                                        if hasattr(handoff_item, 'agent_name') and handoff_item.agent_name == previous_agent.name:
                                            # Bidirectional handoff detected, share history
                                            current_agent.model.message_history = previous_agent.model.message_history
                                            break

                        current_span.finish(reset_current=True)
                        current_span = None
                        should_run_agent_start_hooks = True
                        streamed_result._event_queue.put_nowait(
                            AgentUpdatedStreamEvent(new_agent=current_agent)
                        )
                    elif isinstance(turn_result.next_step, NextStepFinalOutput):
                        streamed_result._output_guardrails_task = asyncio.create_task(
                            cls._run_output_guardrails(
                                current_agent.output_guardrails
                                + (run_config.output_guardrails or []),
                                current_agent,
                                turn_result.next_step.output,
                                context_wrapper,
                            )
                        )

                        try:
                            output_guardrail_results = await streamed_result._output_guardrails_task
                        except Exception:
                            # Exceptions will be checked in the stream_events loop
                            output_guardrail_results = []

                        streamed_result.output_guardrail_results = output_guardrail_results
                        streamed_result.final_output = turn_result.next_step.output
                        streamed_result.is_complete = True
                        streamed_result._event_queue.put_nowait(QueueCompleteSentinel())
                    elif isinstance(turn_result.next_step, NextStepRunAgain):
                        pass
                except (KeyboardInterrupt, asyncio.CancelledError) as e:
                    # Re-raise to propagate the interruption
                    raise e
                except Exception as e:
                    if current_span:
                        _error_tracing.attach_error_to_span(
                            current_span,
                            SpanError(
                                message="Error in agent run",
                                data={"error": str(e)},
                            ),
                        )
                    streamed_result.is_complete = True
                    streamed_result._event_queue.put_nowait(QueueCompleteSentinel())
                    raise

            streamed_result.is_complete = True
        finally:
            if current_span:
                current_span.finish(reset_current=True)

    @classmethod
    async def _run_single_turn_streamed(
        cls,
        streamed_result: RunResultStreaming,
        agent: Agent[TContext],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        should_run_agent_start_hooks: bool,
        tool_use_tracker: AgentToolUseTracker,
        all_tools: list[Tool],
    ) -> SingleStepResult:
        if should_run_agent_start_hooks:
            await asyncio.gather(
                hooks.on_agent_start(context_wrapper, agent),
                (
                    agent.hooks.on_start(context_wrapper, agent)
                    if agent.hooks
                    else _coro.noop_coroutine()
                ),
            )

        output_schema = cls._get_output_schema(agent)

        streamed_result.current_agent = agent
        streamed_result._current_agent_output_schema = output_schema

        system_prompt = await agent.get_system_prompt(context_wrapper)

        handoffs = cls._get_handoffs(agent)
        model = cls._get_model(agent, run_config)
        model_settings = agent.model_settings.resolve(run_config.model_settings)
        model_settings = RunImpl.maybe_reset_tool_choice(agent, tool_use_tracker, model_settings)

        # Ensure agent model is set in model_settings for streaming mode
        if not hasattr(model_settings, "agent_model") or not model_settings.agent_model:
            if isinstance(agent.model, str):
                model_settings.agent_model = agent.model
            elif isinstance(run_config.model, str):
                model_settings.agent_model = run_config.model

        final_response: ModelResponse | None = None

        if getattr(agent, 'isolated_context', False) and hasattr(agent.model, 'message_history') and agent.model.message_history:
            # Skip original_input (already in history as briefing).
            # Include only NEW items from this agent since last processed.
            offset = getattr(agent, '_isolated_items_offset', 0)
            input: list[TResponseInputItem] = []
            for item in streamed_result.new_items[offset:]:
                if item.agent.name == agent.name:
                    input.append(item.to_input_item())
            agent._isolated_items_offset = len(streamed_result.new_items)
        else:
            input = ItemHelpers.input_to_new_input_list(streamed_result.input)
            input.extend([item.to_input_item() for item in streamed_result.new_items])

        # 1. Stream the output events
        async for event in model.stream_response(
            system_prompt,
            input,
            model_settings,
            all_tools,
            output_schema,
            handoffs,
            get_model_tracing_impl(
                run_config.tracing_disabled, run_config.trace_include_sensitive_data
            ),
        ):
            if isinstance(event, ResponseCompletedEvent):
                usage = (
                    Usage(
                        requests=1,
                        input_tokens=event.response.usage.input_tokens,
                        output_tokens=event.response.usage.output_tokens,
                        total_tokens=event.response.usage.total_tokens,
                    )
                    if event.response.usage
                    else Usage()
                )
                final_response = ModelResponse(
                    output=event.response.output,
                    usage=usage,
                    referenceable_id=event.response.id,
                )

            streamed_result._event_queue.put_nowait(RawResponsesStreamEvent(data=event))

        # 2. At this point, the streaming is complete for this turn of the agent loop.
        if not final_response:
            raise ModelBehaviorError("Model did not produce a final response!")

        # 3. Now, we can process the turn as we do in the non-streaming case
        single_step_result = None
        try:
            single_step_result = await cls._get_single_step_result_from_response(
                agent=agent,
                original_input=streamed_result.input,
                pre_step_items=streamed_result.new_items,
                new_response=final_response,
                output_schema=output_schema,
                all_tools=all_tools,
                handoffs=handoffs,
                hooks=hooks,
                context_wrapper=context_wrapper,
                run_config=run_config,
                tool_use_tracker=tool_use_tracker,
            )

            RunImpl.stream_step_result_to_queue(single_step_result, streamed_result._event_queue)
            return single_step_result
        except (KeyboardInterrupt, asyncio.CancelledError) as e:
            # When interrupted, we need to ensure the message history is consistent
            # The tool calls were already added during streaming, but results were not
            # If we have a partial result, stream it before re-raising
            if single_step_result:
                RunImpl.stream_step_result_to_queue(single_step_result, streamed_result._event_queue)
            raise e

    @classmethod
    async def _run_single_turn(
        cls,
        *,
        agent: Agent[TContext],
        all_tools: list[Tool],
        original_input: str | list[TResponseInputItem],
        generated_items: list[RunItem],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        should_run_agent_start_hooks: bool,
        tool_use_tracker: AgentToolUseTracker,
    ) -> SingleStepResult:
        # Ensure we run the hooks before anything else
        if should_run_agent_start_hooks:
            await asyncio.gather(
                hooks.on_agent_start(context_wrapper, agent),
                (
                    agent.hooks.on_start(context_wrapper, agent)
                    if agent.hooks
                    else _coro.noop_coroutine()
                ),
            )

        system_prompt = await agent.get_system_prompt(context_wrapper)

        output_schema = cls._get_output_schema(agent)
        handoffs = cls._get_handoffs(agent)
        if getattr(agent, 'isolated_context', False) and hasattr(agent.model, 'message_history') and agent.model.message_history:
            # Isolated context: skip original_input (already in history as briefing).
            # But first, check if original_input contains a NEW user instruction
            # (e.g. from Ctrl+C → user types at prompt). These must be preserved.
            _SYSTEM_MSGS = frozenset({
                "Continue with your task based on the context provided.",
                "Continue working on the task based on your previous findings.",
                "User input is empty, maybe wants to continue",
            })
            if isinstance(original_input, list):
                # Extract the last user message from original_input
                for msg in reversed(original_input):
                    if isinstance(msg, dict) and msg.get("role") == "user" and not msg.get("_hitl_logged"):
                        text = str(msg.get("content", "")).strip()
                        if (text
                            and text not in _SYSTEM_MSGS
                            and not text.startswith("[Handoff from ")
                            and not text.startswith("WARNING: ")):
                            # Check it's not already the last user message in history
                            last_user_in_history = ""
                            for h in reversed(agent.model.message_history):
                                if h.get("role") == "user":
                                    last_user_in_history = str(h.get("content", "")).strip()
                                    break
                            if text != last_user_in_history:
                                agent.model.message_history.append({
                                    "role": "user",
                                    "content": text,
                                })
                                # Log user_message event only once (not per-agent re-injection)
                                if hasattr(agent.model, 'logger'):
                                    agent.model.logger.log_user_message(text)
                                    msg["_hitl_logged"] = True
                                logger.info("HITL instruction injected into %s: %s",
                                            agent.name, text[:80])
                        break  # Only check the last user message

            # Include only NEW items from this agent since last processed.
            offset = getattr(agent, '_isolated_items_offset', 0)
            input: list[TResponseInputItem] = []
            for item in generated_items[offset:]:
                if item.agent.name == agent.name:
                    input.append(item.to_input_item())
            agent._isolated_items_offset = len(generated_items)
            # Ensure at least one user message for model compatibility
            if not input:
                if not getattr(agent, 'can_finish', True):
                    # Agent cannot finish — nudge it to continue working
                    input.append({"role": "user", "content": "Continue with your task based on the context provided."})
                # else: can_finish=True — no nudge, let the agent's message_history
                # speak for itself. The model will see the last handoff briefing
                # and can decide to produce final output (text, no tools) to end.
        else:
            input = ItemHelpers.input_to_new_input_list(original_input)
            input.extend([generated_item.to_input_item() for generated_item in generated_items])

        new_response = await cls._get_new_response(
            agent,
            system_prompt,
            input,
            output_schema,
            all_tools,
            handoffs,
            context_wrapper,
            run_config,
            tool_use_tracker,
        )

        return await cls._get_single_step_result_from_response(
            agent=agent,
            original_input=original_input,
            pre_step_items=generated_items,
            new_response=new_response,
            output_schema=output_schema,
            all_tools=all_tools,
            handoffs=handoffs,
            hooks=hooks,
            context_wrapper=context_wrapper,
            run_config=run_config,
            tool_use_tracker=tool_use_tracker,
        )

    @classmethod
    async def _get_single_step_result_from_response(
        cls,
        *,
        agent: Agent[TContext],
        all_tools: list[Tool],
        original_input: str | list[TResponseInputItem],
        pre_step_items: list[RunItem],
        new_response: ModelResponse,
        output_schema: AgentOutputSchema | None,
        handoffs: list[Handoff],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        tool_use_tracker: AgentToolUseTracker,
    ) -> SingleStepResult:
        processed_response = RunImpl.process_model_response(
            agent=agent,
            all_tools=all_tools,
            response=new_response,
            output_schema=output_schema,
            handoffs=handoffs,
        )

        # Log tools used with robust type checking
        if hasattr(processed_response, "tools_used") and processed_response.tools_used:
            for i, tool_call in enumerate(processed_response.tools_used):
                try:
                    # Safely extract tool name with multiple fallbacks
                    tool_name = "Unknown"
                    try:
                        if hasattr(tool_call, "tool"):
                            if isinstance(tool_call.tool, str):
                                tool_name = tool_call.tool
                            elif hasattr(tool_call.tool, "name"):
                                tool_name = tool_call.tool.name
                            else:
                                tool_name = str(tool_call.tool)
                    except Exception:
                        pass

                    # Safely extract call_id
                    call_id = "Unknown"
                    try:
                        if hasattr(tool_call, "call_id"):
                            call_id = str(tool_call.call_id)
                    except Exception:
                        pass

                    # Safely extract parsed_args
                    parsed_args = "Unknown"
                    try:
                        if hasattr(tool_call, "parsed_args"):
                            parsed_args = str(tool_call.parsed_args)
                    except Exception:
                        pass
                except Exception:
                    pass

        tool_use_tracker.add_tool_use(agent, processed_response.tools_used)

        return await RunImpl.execute_tools_and_side_effects(
            agent=agent,
            original_input=original_input,
            pre_step_items=pre_step_items,
            new_response=new_response,
            processed_response=processed_response,
            output_schema=output_schema,
            hooks=hooks,
            context_wrapper=context_wrapper,
            run_config=run_config,
        )

    @classmethod
    async def _run_input_guardrails(
        cls,
        agent: Agent[Any],
        guardrails: list[InputGuardrail[TContext]],
        input: str | list[TResponseInputItem],
        context: RunContextWrapper[TContext],
    ) -> list[InputGuardrailResult]:
        if not guardrails:
            return []

        guardrail_tasks = [
            asyncio.create_task(
                RunImpl.run_single_input_guardrail(agent, guardrail, input, context)
            )
            for guardrail in guardrails
        ]

        guardrail_results = []

        for done in asyncio.as_completed(guardrail_tasks):
            result = await done
            if result.output.tripwire_triggered:
                # Cancel all guardrail tasks if a tripwire is triggered.
                for t in guardrail_tasks:
                    t.cancel()
                _error_tracing.attach_error_to_current_span(
                    SpanError(
                        message="Guardrail tripwire triggered",
                        data={"guardrail": result.guardrail.get_name()},
                    )
                )
                raise InputGuardrailTripwireTriggered(result)
            else:
                guardrail_results.append(result)

        return guardrail_results

    @classmethod
    async def _run_output_guardrails(
        cls,
        guardrails: list[OutputGuardrail[TContext]],
        agent: Agent[TContext],
        agent_output: Any,
        context: RunContextWrapper[TContext],
    ) -> list[OutputGuardrailResult]:
        if not guardrails:
            return []

        guardrail_tasks = [
            asyncio.create_task(
                RunImpl.run_single_output_guardrail(guardrail, agent, agent_output, context)
            )
            for guardrail in guardrails
        ]

        guardrail_results = []

        for done in asyncio.as_completed(guardrail_tasks):
            result = await done
            if result.output.tripwire_triggered:
                # Cancel all guardrail tasks if a tripwire is triggered.
                for t in guardrail_tasks:
                    t.cancel()
                _error_tracing.attach_error_to_current_span(
                    SpanError(
                        message="Guardrail tripwire triggered",
                        data={"guardrail": result.guardrail.get_name()},
                    )
                )
                raise OutputGuardrailTripwireTriggered(result)
            else:
                guardrail_results.append(result)

        return guardrail_results

    @classmethod
    async def _get_new_response(
        cls,
        agent: Agent[TContext],
        system_prompt: str | None,
        input: list[TResponseInputItem],
        output_schema: AgentOutputSchema | None,
        all_tools: list[Tool],
        handoffs: list[Handoff],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        tool_use_tracker: AgentToolUseTracker,
    ) -> ModelResponse:
        model = cls._get_model(agent, run_config)
        model_settings = agent.model_settings.resolve(run_config.model_settings)
        model_settings = RunImpl.maybe_reset_tool_choice(agent, tool_use_tracker, model_settings)

        # Ensure agent model is set in model_settings
        if not hasattr(model_settings, "agent_model") or not model_settings.agent_model:
            if isinstance(agent.model, str):
                model_settings.agent_model = agent.model
            elif isinstance(run_config.model, str):
                model_settings.agent_model = run_config.model

        # Propagate can_finish to model so empty-response nudge respects it
        model._agent_can_finish = getattr(agent, 'can_finish', True)

        new_response = await model.get_response(
            system_instructions=system_prompt,
            input=input,
            model_settings=model_settings,
            tools=all_tools,
            output_schema=output_schema,
            handoffs=handoffs,
            tracing=get_model_tracing_impl(
                run_config.tracing_disabled, run_config.trace_include_sensitive_data
            ),
        )

        context_wrapper.usage.add(new_response.usage)

        return new_response

    @classmethod
    def _get_output_schema(cls, agent: Agent[Any]) -> AgentOutputSchema | None:
        if agent.output_type is None or agent.output_type is str:
            return None

        return AgentOutputSchema(agent.output_type)

    @classmethod
    def _get_handoffs(cls, agent: Agent[Any]) -> list[Handoff]:
        handoffs = []
        for handoff_item in agent.handoffs:
            if isinstance(handoff_item, Handoff):
                handoffs.append(handoff_item)
            elif isinstance(handoff_item, Agent):
                handoffs.append(handoff(handoff_item))
        return handoffs

    @classmethod
    async def _get_all_tools(cls, agent: Agent[Any]) -> list[Tool]:
        return await agent.get_all_tools()

    @classmethod
    def _get_model(cls, agent: Agent[Any], run_config: RunConfig) -> Model:
        model = None
        agent_model = None
        if isinstance(run_config.model, Model):
            model = run_config.model
        elif isinstance(run_config.model, str):
            model = run_config.model_provider.get_model(run_config.model)
            agent_model = run_config.model
        elif isinstance(agent.model, Model):
            model = agent.model
        else:
            model = run_config.model_provider.get_model(agent.model)
            agent_model = agent.model

        # Store the original agent model in model_settings for later use
        if agent_model and hasattr(agent, "model_settings"):
            agent.model_settings.agent_model = agent_model

        # Set agent name if the model supports it (for CLI display)
        if hasattr(model, "set_agent_name"):
            model.set_agent_name(agent.name)

        return model
