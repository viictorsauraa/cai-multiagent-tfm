from __future__ import annotations

import asyncio
import dataclasses
import inspect
import json
import re
import uuid
from collections.abc import Awaitable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

from openai.types.responses import (
    ResponseComputerToolCall,
    ResponseFileSearchToolCall,
    ResponseFunctionToolCall,
    ResponseFunctionWebSearch,
    ResponseOutputMessage,
)
from openai.types.responses.response_computer_tool_call import (
    ActionClick,
    ActionDoubleClick,
    ActionDrag,
    ActionKeypress,
    ActionMove,
    ActionScreenshot,
    ActionScroll,
    ActionType,
    ActionWait,
)
from openai.types.responses.response_input_param import ComputerCallOutput
from openai.types.responses.response_reasoning_item import ResponseReasoningItem

from .agent import Agent, ToolsToFinalOutputResult
from .agent_output import AgentOutputSchema
from .computer import AsyncComputer, Computer
from .exceptions import AgentsException, ModelBehaviorError, UserError
from .guardrail import InputGuardrail, InputGuardrailResult, OutputGuardrail, OutputGuardrailResult
from .handoffs import Handoff, HandoffInputData
from .items import (
    HandoffCallItem,
    HandoffOutputItem,
    ItemHelpers,
    MessageOutputItem,
    ModelResponse,
    ReasoningItem,
    RunItem,
    ToolCallItem,
    ToolCallOutputItem,
    TResponseInputItem,
)
from .lifecycle import RunHooks
from .logger import logger
from .model_settings import ModelSettings
from .models.interface import ModelTracing
from .run_context import RunContextWrapper, TContext
from .stream_events import RunItemStreamEvent, StreamEvent
from .tool import ComputerTool, FunctionTool, FunctionToolResult, Tool
from .tracing import (
    SpanError,
    Trace,
    function_span,
    get_current_trace,
    guardrail_span,
    handoff_span,
    trace,
)
from .util import _coro, _error_tracing

if TYPE_CHECKING:
    from .run import RunConfig


class QueueCompleteSentinel:
    pass


QUEUE_COMPLETE_SENTINEL = QueueCompleteSentinel()

_NOT_FINAL_OUTPUT = ToolsToFinalOutputResult(is_final_output=False, final_output=None)


# ── Text-based tool call detection ───────────────────────────────────
# Smaller models (qwen3:8b, llama3.3) sometimes write tool calls as plain
# text instead of using function calling.  The helpers below detect these
# patterns and convert them to real tool calls.

_LLM_SPECIAL_TOKENS = ["<|python_tag|>", "<|im_start|>", "<|im_end|>"]
_PYTHON_KWARGS_RE = re.compile(r'(\w+)\s*=\s*(?:["\']([^"\']*)["\']|(\S+?)(?:\s*[,)]|$))')
_CODE_BLOCK_RE = re.compile(r'```\w*\s*\n(.+?)\n```', re.DOTALL)
_PROSE_STARTERS_RE = re.compile(
    r"^(?:And|But|The|Then|This|That|These|Those|Here|There|"
    r"Let'?s?|First|Second|Third|Next|Finally|However|"
    r"Also|For|In|On|At|To|From|With|If|When|While|"
    r"Note|Now|So|We|You|I |It |As|Or)\s",
    re.IGNORECASE,
)
# Patterns that look like shell control-flow, not English prose.
# Checked *before* _PROSE_STARTERS_RE so "for i in ..." is accepted.
_SHELL_CONSTRUCT_RE = re.compile(
    r"^(?:"
    r"for\s+\w+\s+in\s|"               # for VAR in ...
    r"if\s+[\[!(]|"                     # if [ / if [[ / if ! / if (
    r"if\s+\w+\s*;|"                    # if command;
    r"while\s+[\[!(]|"                  # while [ / while [[ / while !
    r"while\s+(?:true|read|:)|"         # while true / while read / while :
    r"until\s+[\[!]|"                   # until [ / until !
    r"case\s+.+\s+in|"                  # case VAR in
    r"select\s+\w+\s+in\s"             # select VAR in ...
    r")",
    re.IGNORECASE,
)
_SHELL_OPERATORS_RE = re.compile(r"[|><;&]|&&|\|\|")


def _looks_like_command(text: str) -> bool:
    """Return True if *text* plausibly looks like shell command(s), not prose.

    Used by ``_try_code_block`` to avoid executing natural-language reasoning
    that a model accidentally placed inside a markdown code block.
    """
    lines = [
        l.strip()
        for l in text.strip().splitlines()
        if l.strip() and not l.strip().startswith("#")
    ]
    if not lines:
        return False
    first_line = lines[0]

    # Shell constructs (for/if/while/case) take priority over prose detection
    if _SHELL_CONSTRUCT_RE.match(first_line):
        return True

    # Reject if the first meaningful line starts with a common English word
    if _PROSE_STARTERS_RE.match(first_line):
        return False

    # Reject lines ending with period (prose sentences) unless they have shell operators
    for line in lines:
        if line.startswith("\\") or line.startswith("-"):
            continue
        if line.endswith(".") and not _SHELL_OPERATORS_RE.search(line):
            last_word = line.rstrip(".").rsplit(None, 1)[-1] if line.rstrip(".") else ""
            if "/" not in last_word and "." not in last_word:
                return False

    # First token must look like a command name
    first_token = first_line.split()[0] if first_line.split() else ""
    if not re.match(r"^[a-zA-Z0-9_./$~]", first_token):
        return False

    return True


def _build_name_maps(
    function_map: dict, handoff_map: dict
) -> tuple[dict[str, str], dict[str, str]]:
    """Build name→kind lookup and agent_name→tool_name reverse lookup."""
    all_names = {n: "function" for n in function_map}
    all_names.update({n: "handoff" for n in handoff_map})
    agent_to_handoff = {
        ho.agent_name.lower(): tool_name
        for tool_name, ho in handoff_map.items()
    }
    return all_names, agent_to_handoff


def _extract_balanced_parens(text: str, open_idx: int) -> str:
    """Return the content between balanced parentheses starting at *open_idx*.

    ``open_idx`` must point to the opening ``(``.  Returns the inner text
    (without the surrounding parens), or ``""`` if no balanced close is found.
    """
    depth = 0
    i = open_idx
    while i < len(text):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i].strip()
        i += 1
    return ""


def _parse_args(args_str: str) -> dict:
    """Parse function arguments from JSON or Python kwargs format."""
    if not args_str:
        return {}
    try:
        parsed = json.loads(args_str)
        return parsed if isinstance(parsed, dict) else {}
    except (json.JSONDecodeError, ValueError):
        return {
            m.group(1): (m.group(2) if m.group(2) is not None else m.group(3))
            for m in _PYTHON_KWARGS_RE.finditer(args_str)
        }


def _iter_json_candidates(text: str):
    """Yield balanced ``{…}`` substrings from *text* (handles nesting)."""
    i = 0
    while i < len(text):
        start = text.find("{", i)
        if start == -1:
            break
        depth = 0
        j = start
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    yield text[start : j + 1]
                    break
            j += 1
        i = start + 1


def _try_python_style(
    text: str, all_names: dict[str, str]
) -> tuple[str, dict, str] | None:
    """Detect a ``tool_name(key="val")`` pattern in *text*.

    The agent contract is ONE command per response (system prompts state
    this). Returning multiple calls would normalise that violation, so we
    still emit at most one tool call. Heuristic for picking which one
    when the model emits several:

    - If any match is a handoff (``transfer_to_*``), return the LAST
      handoff. Handoffs express the model's operational intent; they
      win over reflective preamble like ``think(...)`` placed before.
    - Otherwise, return the FIRST match (preserves prior behaviour for
      single-call and function-only responses).
    """
    clean = text
    for token in _LLM_SPECIAL_TOKENS:
        clean = clean.replace(token, "")
    clean = clean.strip()
    clean_lower = clean.lower()

    matches: list[tuple[int, str, dict, str]] = []
    for name, kind in all_names.items():
        needle = name + "("
        start = 0
        while True:
            idx = clean_lower.find(needle, start)
            if idx == -1:
                break
            # Word boundary: char before match must not be alnum or '_'.
            if idx > 0 and (clean_lower[idx - 1].isalnum() or clean_lower[idx - 1] == '_'):
                start = idx + 1
                continue
            args_str = _extract_balanced_parens(clean, idx + len(name))
            params = _parse_args(args_str)
            matches.append((idx, name, params, kind))
            start = idx + len(needle)

    if not matches:
        return None

    matches.sort(key=lambda m: m[0])
    handoffs = [m for m in matches if m[3] == "handoff"]
    chosen = handoffs[-1] if handoffs else matches[0]
    _, name, params, kind = chosen
    return name, params, kind


def _try_json_object(
    text: str,
    function_map: dict,
    handoff_map: dict,
    agent_to_handoff: dict[str, str],
) -> tuple[str, dict, str] | None:
    """Detect ``{"name": "tool", "parameters": {…}}`` patterns."""
    for candidate in _iter_json_candidates(text):
        try:
            obj = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict) or "name" not in obj:
            continue

        name = obj["name"]
        params = obj.get("parameters") or obj.get("arguments") or {}
        if not isinstance(params, dict):
            continue

        if name in function_map:
            return name, params, "function"
        if name in handoff_map:
            return name, params, "handoff"

        # Fuzzy: model invented a name like "delegate" with an agent field
        agent_ref = (
            params.get("agent")
            or params.get("agent_name")
            or obj.get("agent")
        )
        if agent_ref and isinstance(agent_ref, str):
            matched = agent_to_handoff.get(agent_ref.lower())
            if matched:
                return matched, {}, "handoff"
    return None


def _try_code_block(text: str, function_map: dict) -> tuple[str, dict, str] | None:
    """Detect raw commands in markdown code blocks and wrap as generic_linux_command.

    When context grows large, smaller models sometimes write commands directly
    in ```bash blocks instead of calling generic_linux_command().  This function
    catches those and converts them to real tool calls.
    """
    if "generic_linux_command" not in function_map:
        return None
    # Clean special tokens first
    clean = text
    for token in _LLM_SPECIAL_TOKENS:
        clean = clean.replace(token, "")
    for m in _CODE_BLOCK_RE.finditer(clean):
        cmd = m.group(1).strip()
        if cmd and not cmd.startswith("{") and _looks_like_command(cmd):
            return "generic_linux_command", {"command": cmd}, "function"
    return None


def _try_extract_text_tool_call(
    text: str, function_map: dict, handoff_map: dict | None = None
) -> tuple[str, dict, str] | None:
    """Detect tool calls written as text by the LLM instead of via function calling.

    Returns ``(tool_name, args_dict, kind)`` where *kind* is ``"function"``
    or ``"handoff"``, or ``None`` if nothing matched.

    Supported patterns::

        JSON:    {"name": "generic_linux_command", "parameters": {"command": "ls"}}
        JSON:    {"name": "transfer_to_recon_agent", "parameters": {}}
        JSON:    {"name": "delegate", "parameters": {"agent": "Recon Agent"}}
        Python:  transfer_to_recon_agent()
        Python:  <|python_tag|>transfer_to_recon_agent(target_ip="172.17.0.2")
    """
    if not text or (not function_map and not handoff_map):
        return None
    if handoff_map is None:
        handoff_map = {}

    all_names, agent_to_handoff = _build_name_maps(function_map, handoff_map)

    # Python-style has priority (more specific match)
    result = _try_python_style(text, all_names)
    if result:
        return result

    result = _try_json_object(text, function_map, handoff_map, agent_to_handoff)
    if result:
        return result

    # Last resort: detect raw commands in markdown code blocks
    return _try_code_block(text, function_map)


def truncate_output(output: Any, max_length: int = 10000) -> str:
    """Truncate tool output if it exceeds max_length characters.
    
    Shows first 5000 and last 5000 characters with TRUNCATED in the middle.
    """
    output_str = str(output)
    if len(output_str) <= max_length:
        return output_str
    
    # Show first 5000 and last 5000 characters
    first_part = output_str[:5000]
    last_part = output_str[-5000:]
    return f"{first_part}\n\n... TRUNCATED ...\n\n{last_part}"


@dataclass
class AgentToolUseTracker:
    agent_to_tools: list[tuple[Agent, list[str]]] = field(default_factory=list)
    """Tuple of (agent, list of tools used). Can't use a dict because agents aren't hashable."""

    def add_tool_use(self, agent: Agent[Any], tool_names: list[str]) -> None:
        existing_data = next((item for item in self.agent_to_tools if item[0] == agent), None)
        if existing_data:
            existing_data[1].extend(tool_names)
        else:
            self.agent_to_tools.append((agent, tool_names))

    def has_used_tools(self, agent: Agent[Any]) -> bool:
        existing_data = next((item for item in self.agent_to_tools if item[0] == agent), None)
        return existing_data is not None and len(existing_data[1]) > 0


@dataclass
class ToolRunHandoff:
    handoff: Handoff
    tool_call: ResponseFunctionToolCall


@dataclass
class ToolRunFunction:
    tool_call: ResponseFunctionToolCall
    function_tool: FunctionTool


@dataclass
class ToolRunComputerAction:
    tool_call: ResponseComputerToolCall
    computer_tool: ComputerTool


@dataclass
class ProcessedResponse:
    new_items: list[RunItem]
    handoffs: list[ToolRunHandoff]
    functions: list[ToolRunFunction]
    computer_actions: list[ToolRunComputerAction]
    tools_used: list[str]  # Names of all tools used, including hosted tools

    def has_tools_to_run(self) -> bool:
        # Handoffs, functions and computer actions need local processing
        # Hosted tools have already run, so there's nothing to do.
        return any(
            [
                self.handoffs,
                self.functions,
                self.computer_actions,
            ]
        )


@dataclass
class NextStepHandoff:
    new_agent: Agent[Any]


@dataclass
class NextStepFinalOutput:
    output: Any


@dataclass
class NextStepRunAgain:
    pass


@dataclass
class SingleStepResult:
    original_input: str | list[TResponseInputItem]
    """The input items i.e. the items before run() was called. May be mutated by handoff input
    filters."""

    model_response: ModelResponse
    """The model response for the current step."""

    pre_step_items: list[RunItem]
    """Items generated before the current step."""

    new_step_items: list[RunItem]
    """Items generated during this current step."""

    next_step: NextStepHandoff | NextStepFinalOutput | NextStepRunAgain
    """The next step to take."""

    @property
    def generated_items(self) -> list[RunItem]:
        """Items generated during the agent run (i.e. everything generated after
        `original_input`)."""
        return self.pre_step_items + self.new_step_items


def get_model_tracing_impl(
    tracing_disabled: bool, trace_include_sensitive_data: bool
) -> ModelTracing:
    if tracing_disabled:
        return ModelTracing.DISABLED
    elif trace_include_sensitive_data:
        return ModelTracing.ENABLED
    else:
        return ModelTracing.ENABLED_WITHOUT_DATA


class RunImpl:
    @classmethod
    async def execute_tools_and_side_effects(
        cls,
        *,
        agent: Agent[TContext],
        # The original input to the Runner
        original_input: str | list[TResponseInputItem],
        # Everything generated by Runner since the original input, but before the current step
        pre_step_items: list[RunItem],
        new_response: ModelResponse,
        processed_response: ProcessedResponse,
        output_schema: AgentOutputSchema | None,
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
    ) -> SingleStepResult:
        # Make a copy of the generated items
        pre_step_items = list(pre_step_items)

        new_step_items: list[RunItem] = []
        new_step_items.extend(processed_response.new_items)

        # First, lets run the tool calls - function tools and computer actions
        # Create tasks separately so we can handle partial results
        function_task = asyncio.create_task(
            cls.execute_function_tool_calls(
                agent=agent,
                tool_runs=processed_response.functions,
                hooks=hooks,
                context_wrapper=context_wrapper,
                config=run_config,
            )
        )
        computer_task = asyncio.create_task(
            cls.execute_computer_actions(
                agent=agent,
                actions=processed_response.computer_actions,
                hooks=hooks,
                context_wrapper=context_wrapper,
                config=run_config,
            )
        )
        
        function_results = []
        computer_results = []
        interrupt_exception = None
        
        try:
            function_results, computer_results = await asyncio.gather(
                function_task, computer_task
            )
        except (KeyboardInterrupt, asyncio.CancelledError) as e:
            interrupt_exception = e
            
            # Try to get partial results from the tasks
            if function_task.done() and not function_task.cancelled():
                try:
                    function_results = function_task.result()
                except Exception:
                    # If the task failed, create synthetic results
                    function_results = []
                    for tool_run in processed_response.functions:
                        result = FunctionToolResult(
                            tool=tool_run.function_tool,
                            output="Tool execution interrupted",
                            run_item=ToolCallOutputItem(
                                output="Tool execution interrupted",
                                raw_item=ItemHelpers.tool_call_output_item(
                                    tool_run.tool_call, "Tool execution interrupted"
                                ),
                                agent=agent,
                            ),
                        )
                        function_results.append(result)
            else:
                # Task was cancelled or not done, create synthetic results
                function_results = []
                for tool_run in processed_response.functions:
                    result = FunctionToolResult(
                        tool=tool_run.function_tool,
                        output="Tool execution interrupted",
                        run_item=ToolCallOutputItem(
                            output="Tool execution interrupted",
                            raw_item=ItemHelpers.tool_call_output_item(
                                tool_run.tool_call, "Tool execution interrupted"
                            ),
                            agent=agent,
                        ),
                    )
                    function_results.append(result)
                    
            if computer_task.done() and not computer_task.cancelled():
                try:
                    computer_results = computer_task.result()
                except Exception:
                    computer_results = []
            else:
                computer_results = []
            
        new_step_items.extend([result.run_item for result in function_results])
        new_step_items.extend(computer_results)
        
        # Re-raise the interruption after ensuring results are added
        if interrupt_exception:
            raise interrupt_exception

        # Second, check if there are any handoffs
        if run_handoffs := processed_response.handoffs:
            return await cls.execute_handoffs(
                agent=agent,
                original_input=original_input,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                new_response=new_response,
                run_handoffs=run_handoffs,
                hooks=hooks,
                context_wrapper=context_wrapper,
                run_config=run_config,
            )

        # Third, we'll check if the tool use should result in a final output
        check_tool_use = await cls._check_for_final_output_from_tools(
            agent=agent,
            tool_results=function_results,
            context_wrapper=context_wrapper,
            config=run_config,
        )

        if check_tool_use.is_final_output:
            # If the output type is str, then let's just stringify it
            if not agent.output_type or agent.output_type is str:
                check_tool_use.final_output = str(check_tool_use.final_output)

            if check_tool_use.final_output is None:
                logger.error(
                    "Model returned a final output of None. Not raising an error because we assume"
                    "you know what you're doing."
                )

            return await cls.execute_final_output(
                agent=agent,
                original_input=original_input,
                new_response=new_response,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                final_output=check_tool_use.final_output,
                hooks=hooks,
                context_wrapper=context_wrapper,
            )

        # Now we can check if the model also produced a final output
        message_items = [item for item in new_step_items if isinstance(item, MessageOutputItem)]

        # We'll use the last content output as the final output
        potential_final_output_text = (
            ItemHelpers.extract_last_text(message_items[-1].raw_item) if message_items else None
        )

        # There are two possibilities that lead to a final output:
        # 1. Structured output schema => always leads to a final output
        # 2. Plain text output schema => only leads to a final output if there are no tool calls
        if output_schema and not output_schema.is_plain_text() and potential_final_output_text:
            forced = await cls._maybe_force_handoff(
                agent, original_input, new_response, pre_step_items,
                new_step_items, context_wrapper)
            if forced:
                return forced
            final_output = output_schema.validate_json(potential_final_output_text)
            return await cls.execute_final_output(
                agent=agent,
                original_input=original_input,
                new_response=new_response,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                final_output=final_output,
                hooks=hooks,
                context_wrapper=context_wrapper,
            )
        elif (
            not output_schema or output_schema.is_plain_text()
        ) and not processed_response.has_tools_to_run():
            forced = await cls._maybe_force_handoff(
                agent, original_input, new_response, pre_step_items,
                new_step_items, context_wrapper)
            if forced:
                return forced
            return await cls.execute_final_output(
                agent=agent,
                original_input=original_input,
                new_response=new_response,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                final_output=potential_final_output_text or "",
                hooks=hooks,
                context_wrapper=context_wrapper,
            )
        else:
            # If there's no final output, we can just run again
            return SingleStepResult(
                original_input=original_input,
                model_response=new_response,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                next_step=NextStepRunAgain(),
            )

    @classmethod
    async def _maybe_force_handoff(
        cls,
        agent: Agent[Any],
        original_input: str | list[TResponseInputItem],
        new_response: ModelResponse,
        pre_step_items: list[RunItem],
        new_step_items: list[RunItem],
        context_wrapper: RunContextWrapper[Any],
    ) -> SingleStepResult | None:
        """If agent.can_finish is False and it has handoffs, force a handoff
        instead of ending the session."""
        if not getattr(agent, 'can_finish', True) and agent.handoffs:
            first_handoff = agent.handoffs[0]
            if isinstance(first_handoff, Handoff):
                target_agent = await first_handoff.on_invoke_handoff(context_wrapper, "")
            else:
                target_agent = first_handoff
            logger.info(
                "Agent %s (can_finish=False) tried to end session; "
                "forcing handoff to %s",
                agent.name, target_agent.name,
            )
            return SingleStepResult(
                original_input=original_input,
                model_response=new_response,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                next_step=NextStepHandoff(target_agent),
            )
        if not getattr(agent, 'can_finish', True) and not agent.handoffs:
            logger.warning(
                "Agent %s has can_finish=False but no handoffs defined — "
                "can_finish constraint will be ignored",
                agent.name,
            )
        return None

    @classmethod
    def maybe_reset_tool_choice(
        cls, agent: Agent[Any], tool_use_tracker: AgentToolUseTracker, model_settings: ModelSettings
    ) -> ModelSettings:
        """Resets tool choice to None if the agent has used tools and the agent's reset_tool_choice
        flag is True."""

        if agent.reset_tool_choice is True and tool_use_tracker.has_used_tools(agent):
            return dataclasses.replace(model_settings, tool_choice=None)

        return model_settings

    @classmethod
    def process_model_response(
        cls,
        *,
        agent: Agent[Any],
        all_tools: list[Tool],
        response: ModelResponse,
        output_schema: AgentOutputSchema | None,
        handoffs: list[Handoff],
    ) -> ProcessedResponse:
        items: list[RunItem] = []

        run_handoffs = []
        functions = []
        computer_actions = []
        tools_used: list[str] = []
        handoff_map = {handoff.tool_name: handoff for handoff in handoffs}
        function_map = {tool.name: tool for tool in all_tools if isinstance(tool, FunctionTool)}
        computer_tool = next((tool for tool in all_tools if isinstance(tool, ComputerTool)), None)

        for output in response.output:
            if isinstance(output, ResponseOutputMessage):
                items.append(MessageOutputItem(raw_item=output, agent=agent))

                # Detect tool calls or handoffs written as JSON text by the LLM.
                # Some models write {"name": "tool", "parameters": {...}} in plain text
                # instead of using the function-calling mechanism.  When detected, convert
                # them to real ToolRunFunction/ToolRunHandoff entries so they execute.
                text_content = ItemHelpers.extract_last_text(output)
                if text_content:
                    extracted = _try_extract_text_tool_call(
                        text_content, function_map, handoff_map
                    )
                    if extracted:
                        tool_name, params, kind = extracted
                        fake_id = f"text_call_{uuid.uuid4().hex[:8]}"
                        synthetic_call = ResponseFunctionToolCall(
                            id=fake_id,
                            call_id=fake_id,
                            name=tool_name,
                            arguments=json.dumps(params),
                            type="function_call",
                        )
                        tools_used.append(tool_name)
                        if kind == "handoff":
                            items.append(
                                HandoffCallItem(raw_item=synthetic_call, agent=agent)
                            )
                            run_handoffs.append(
                                ToolRunHandoff(
                                    tool_call=synthetic_call,
                                    handoff=handoff_map[tool_name],
                                )
                            )
                        else:
                            items.append(
                                ToolCallItem(raw_item=synthetic_call, agent=agent)
                            )
                            functions.append(
                                ToolRunFunction(
                                    tool_call=synthetic_call,
                                    function_tool=function_map[tool_name],
                                )
                            )
            elif isinstance(output, ResponseFileSearchToolCall):
                items.append(ToolCallItem(raw_item=output, agent=agent))
                tools_used.append("file_search")
            elif isinstance(output, ResponseFunctionWebSearch):
                items.append(ToolCallItem(raw_item=output, agent=agent))
                tools_used.append("web_search")
            elif isinstance(output, ResponseReasoningItem):
                items.append(ReasoningItem(raw_item=output, agent=agent))
            elif isinstance(output, ResponseComputerToolCall):
                items.append(ToolCallItem(raw_item=output, agent=agent))
                tools_used.append("computer_use")
                if not computer_tool:
                    _error_tracing.attach_error_to_current_span(
                        SpanError(
                            message="Computer tool not found",
                            data={},
                        )
                    )
                    raise ModelBehaviorError(
                        "Model produced computer action without a computer tool."
                    )
                computer_actions.append(
                    ToolRunComputerAction(tool_call=output, computer_tool=computer_tool)
                )
            elif not isinstance(output, ResponseFunctionToolCall):
                logger.warning(f"Unexpected output type, ignoring: {type(output)}")
                continue

            # At this point we know it's a function tool call
            if not isinstance(output, ResponseFunctionToolCall):
                continue

            tools_used.append(output.name)

            # Handoffs
            if output.name in handoff_map:
                items.append(HandoffCallItem(raw_item=output, agent=agent))
                handoff = ToolRunHandoff(
                    tool_call=output,
                    handoff=handoff_map[output.name],
                )
                run_handoffs.append(handoff)
            # Regular function tool call
            else:
                if output.name not in function_map:
                    _error_tracing.attach_error_to_current_span(
                        SpanError(
                            message="Tool not found",
                            data={"tool_name": output.name},
                        )
                    )
                    raise ModelBehaviorError(f"Tool {output.name} not found in agent {agent.name}")
                items.append(ToolCallItem(raw_item=output, agent=agent))
                functions.append(
                    ToolRunFunction(
                        tool_call=output,
                        function_tool=function_map[output.name],
                    )
                )

        return ProcessedResponse(
            new_items=items,
            handoffs=run_handoffs,
            functions=functions,
            computer_actions=computer_actions,
            tools_used=tools_used,
        )

    @classmethod
    async def execute_function_tool_calls(
        cls,
        *,
        agent: Agent[TContext],
        tool_runs: list[ToolRunFunction],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        config: RunConfig,
    ) -> list[FunctionToolResult]:
        async def run_single_tool(
            func_tool: FunctionTool, tool_call: ResponseFunctionToolCall
        ) -> Any:
            with function_span(func_tool.name) as span_fn:
                if config.trace_include_sensitive_data:
                    span_fn.span_data.input = tool_call.arguments
                try:
                    _, _, result = await asyncio.gather(
                        hooks.on_tool_start(context_wrapper, agent, func_tool),
                        (
                            agent.hooks.on_tool_start(context_wrapper, agent, func_tool)
                            if agent.hooks
                            else _coro.noop_coroutine()
                        ),
                        func_tool.on_invoke_tool(context_wrapper, tool_call.arguments),
                    )

                    await asyncio.gather(
                        hooks.on_tool_end(context_wrapper, agent, func_tool, result),
                        (
                            agent.hooks.on_tool_end(context_wrapper, agent, func_tool, result)
                            if agent.hooks
                            else _coro.noop_coroutine()
                        ),
                    )
                except Exception as e:
                    _error_tracing.attach_error_to_current_span(
                        SpanError(
                            message="Error running tool",
                            data={"tool_name": func_tool.name, "error": str(e)},
                        )
                    )
                    if isinstance(e, AgentsException):
                        raise e
                    raise UserError(f"Error running tool {func_tool.name}: {e}") from e

                if config.trace_include_sensitive_data:
                    span_fn.span_data.output = result
            return result

        tasks = []
        for tool_run in tool_runs:
            function_tool = tool_run.function_tool
            tasks.append(asyncio.create_task(run_single_tool(function_tool, tool_run.tool_call)))

        try:
            results = await asyncio.gather(*tasks)
        except (KeyboardInterrupt, asyncio.CancelledError) as e:
            # When interrupted, return partial results with error messages
            results = []
            for i, task in enumerate(tasks):
                if task.done() and not task.cancelled():
                    try:
                        results.append(task.result())
                    except Exception:
                        results.append("Tool execution interrupted")
                else:
                    results.append("Tool execution interrupted")
            
            # Re-raise the exception after collecting results
            raise e

        return [
            FunctionToolResult(
                tool=tool_run.function_tool,
                output=result,
                run_item=ToolCallOutputItem(
                    output=result,
                    raw_item=ItemHelpers.tool_call_output_item(tool_run.tool_call, truncate_output(result)),
                    agent=agent,
                ),
            )
            for tool_run, result in zip(tool_runs, results)
        ]

    @classmethod
    async def execute_computer_actions(
        cls,
        *,
        agent: Agent[TContext],
        actions: list[ToolRunComputerAction],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        config: RunConfig,
    ) -> list[RunItem]:
        results: list[RunItem] = []
        # Need to run these serially, because each action can affect the computer state
        for action in actions:
            results.append(
                await ComputerAction.execute(
                    agent=agent,
                    action=action,
                    hooks=hooks,
                    context_wrapper=context_wrapper,
                    config=config,
                )
            )

        return results

    @classmethod
    async def execute_handoffs(
        cls,
        *,
        agent: Agent[TContext],
        original_input: str | list[TResponseInputItem],
        pre_step_items: list[RunItem],
        new_step_items: list[RunItem],
        new_response: ModelResponse,
        run_handoffs: list[ToolRunHandoff],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
    ) -> SingleStepResult:
        # If there is more than one handoff, add tool responses that reject those handoffs
        multiple_handoffs = len(run_handoffs) > 1
        if multiple_handoffs:
            output_message = "Multiple handoffs detected, ignoring this one."
            new_step_items.extend(
                [
                    ToolCallOutputItem(
                        output=output_message,
                        raw_item=ItemHelpers.tool_call_output_item(
                            handoff.tool_call, output_message
                        ),
                        agent=agent,
                    )
                    for handoff in run_handoffs[1:]
                ]
            )

        actual_handoff = run_handoffs[0]
        with handoff_span(from_agent=agent.name) as span_handoff:
            handoff = actual_handoff.handoff
            new_agent: Agent[Any] = await handoff.on_invoke_handoff(
                context_wrapper, actual_handoff.tool_call.arguments
            )
            span_handoff.span_data.to_agent = new_agent.name
            if multiple_handoffs:
                requested_agents = [handoff.handoff.agent_name for handoff in run_handoffs]
                span_handoff.set_error(
                    SpanError(
                        message="Multiple handoffs requested",
                        data={
                            "requested_agents": requested_agents,
                        },
                    )
                )

            # Append a tool output item for the handoff
            new_step_items.append(
                HandoffOutputItem(
                    agent=agent,
                    raw_item=ItemHelpers.tool_call_output_item(
                        actual_handoff.tool_call,
                        handoff.get_transfer_message(new_agent),
                    ),
                    source_agent=agent,
                    target_agent=new_agent,
                )
            )

            # Execute handoff hooks
            await asyncio.gather(
                hooks.on_handoff(
                    context=context_wrapper,
                    from_agent=agent,
                    to_agent=new_agent,
                ),
                (
                    agent.hooks.on_handoff(
                        context_wrapper,
                        agent=new_agent,
                        source=agent,
                    )
                    if agent.hooks
                    else _coro.noop_coroutine()
                ),
            )

            # If there's an input filter, filter the input for the next agent
            input_filter = handoff.input_filter or (
                run_config.handoff_input_filter if run_config else None
            )
            if input_filter:
                logger.debug("Filtering inputs for handoff")
                handoff_input_data = HandoffInputData(
                    input_history=tuple(original_input)
                    if isinstance(original_input, list)
                    else original_input,
                    pre_handoff_items=tuple(pre_step_items),
                    new_items=tuple(new_step_items),
                )
                if not callable(input_filter):
                    _error_tracing.attach_error_to_span(
                        span_handoff,
                        SpanError(
                            message="Invalid input filter",
                            data={"details": "not callable()"},
                        ),
                    )
                    raise UserError(f"Invalid input filter: {input_filter}")
                filtered = input_filter(handoff_input_data)
                if not isinstance(filtered, HandoffInputData):
                    _error_tracing.attach_error_to_span(
                        span_handoff,
                        SpanError(
                            message="Invalid input filter result",
                            data={"details": "not a HandoffInputData"},
                        ),
                    )
                    raise UserError(f"Invalid input filter result: {filtered}")

                original_input = (
                    filtered.input_history
                    if isinstance(filtered.input_history, str)
                    else list(filtered.input_history)
                )
                pre_step_items = list(filtered.pre_handoff_items)
                new_step_items = list(filtered.new_items)

        return SingleStepResult(
            original_input=original_input,
            model_response=new_response,
            pre_step_items=pre_step_items,
            new_step_items=new_step_items,
            next_step=NextStepHandoff(new_agent),
        )

    @classmethod
    async def execute_final_output(
        cls,
        *,
        agent: Agent[TContext],
        original_input: str | list[TResponseInputItem],
        new_response: ModelResponse,
        pre_step_items: list[RunItem],
        new_step_items: list[RunItem],
        final_output: Any,
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
    ) -> SingleStepResult:
        # Run the on_end hooks
        await cls.run_final_output_hooks(agent, hooks, context_wrapper, final_output)

        return SingleStepResult(
            original_input=original_input,
            model_response=new_response,
            pre_step_items=pre_step_items,
            new_step_items=new_step_items,
            next_step=NextStepFinalOutput(final_output),
        )

    @classmethod
    async def run_final_output_hooks(
        cls,
        agent: Agent[TContext],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        final_output: Any,
    ):
        await asyncio.gather(
            hooks.on_agent_end(context_wrapper, agent, final_output),
            agent.hooks.on_end(context_wrapper, agent, final_output)
            if agent.hooks
            else _coro.noop_coroutine(),
        )

    @classmethod
    async def run_single_input_guardrail(
        cls,
        agent: Agent[Any],
        guardrail: InputGuardrail[TContext],
        input: str | list[TResponseInputItem],
        context: RunContextWrapper[TContext],
    ) -> InputGuardrailResult:
        with guardrail_span(guardrail.get_name()) as span_guardrail:
            result = await guardrail.run(agent, input, context)
            span_guardrail.span_data.triggered = result.output.tripwire_triggered
            return result

    @classmethod
    async def run_single_output_guardrail(
        cls,
        guardrail: OutputGuardrail[TContext],
        agent: Agent[Any],
        agent_output: Any,
        context: RunContextWrapper[TContext],
    ) -> OutputGuardrailResult:
        with guardrail_span(guardrail.get_name()) as span_guardrail:
            result = await guardrail.run(agent=agent, agent_output=agent_output, context=context)
            span_guardrail.span_data.triggered = result.output.tripwire_triggered
            return result

    @classmethod
    def stream_step_result_to_queue(
        cls,
        step_result: SingleStepResult,
        queue: asyncio.Queue[StreamEvent | QueueCompleteSentinel],
    ):
        for item in step_result.new_step_items:
            if isinstance(item, MessageOutputItem):
                event = RunItemStreamEvent(item=item, name="message_output_created")
            elif isinstance(item, HandoffCallItem):
                event = RunItemStreamEvent(item=item, name="handoff_requested")
            elif isinstance(item, HandoffOutputItem):
                event = RunItemStreamEvent(item=item, name="handoff_occured")
            elif isinstance(item, ToolCallItem):
                event = RunItemStreamEvent(item=item, name="tool_called")
            elif isinstance(item, ToolCallOutputItem):
                event = RunItemStreamEvent(item=item, name="tool_output")
            elif isinstance(item, ReasoningItem):
                event = RunItemStreamEvent(item=item, name="reasoning_item_created")
            else:
                logger.warning(f"Unexpected item type: {type(item)}")
                event = None

            if event:
                queue.put_nowait(event)

    @classmethod
    async def _check_for_final_output_from_tools(
        cls,
        *,
        agent: Agent[TContext],
        tool_results: list[FunctionToolResult],
        context_wrapper: RunContextWrapper[TContext],
        config: RunConfig,
    ) -> ToolsToFinalOutputResult:
        """Returns (i, final_output)."""
        if not tool_results:
            return _NOT_FINAL_OUTPUT

        if agent.tool_use_behavior == "run_llm_again":
            return _NOT_FINAL_OUTPUT
        elif agent.tool_use_behavior == "stop_on_first_tool":
            return ToolsToFinalOutputResult(
                is_final_output=True, final_output=tool_results[0].output
            )
        elif isinstance(agent.tool_use_behavior, dict):
            names = agent.tool_use_behavior.get("stop_at_tool_names", [])
            for tool_result in tool_results:
                if tool_result.tool.name in names:
                    return ToolsToFinalOutputResult(
                        is_final_output=True, final_output=tool_result.output
                    )
            return ToolsToFinalOutputResult(is_final_output=False, final_output=None)
        elif callable(agent.tool_use_behavior):
            if inspect.iscoroutinefunction(agent.tool_use_behavior):
                return await cast(
                    Awaitable[ToolsToFinalOutputResult],
                    agent.tool_use_behavior(context_wrapper, tool_results),
                )
            else:
                return cast(
                    ToolsToFinalOutputResult, agent.tool_use_behavior(context_wrapper, tool_results)
                )

        logger.error(f"Invalid tool_use_behavior: {agent.tool_use_behavior}")
        raise UserError(f"Invalid tool_use_behavior: {agent.tool_use_behavior}")


class TraceCtxManager:
    """Creates a trace only if there is no current trace, and manages the trace lifecycle."""

    def __init__(
        self,
        workflow_name: str,
        trace_id: str | None,
        group_id: str | None,
        metadata: dict[str, Any] | None,
        disabled: bool,
    ):
        self.trace: Trace | None = None
        self.workflow_name = workflow_name
        self.trace_id = trace_id
        self.group_id = group_id
        self.metadata = metadata
        self.disabled = disabled

    def __enter__(self) -> TraceCtxManager:
        current_trace = get_current_trace()
        if not current_trace:
            self.trace = trace(
                workflow_name=self.workflow_name,
                trace_id=self.trace_id,
                group_id=self.group_id,
                metadata=self.metadata,
                disabled=self.disabled,
            )
            self.trace.start(mark_as_current=True)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.trace:
            self.trace.finish(reset_current=True)


class ComputerAction:
    @classmethod
    async def execute(
        cls,
        *,
        agent: Agent[TContext],
        action: ToolRunComputerAction,
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        config: RunConfig,
    ) -> RunItem:
        output_func = (
            cls._get_screenshot_async(action.computer_tool.computer, action.tool_call)
            if isinstance(action.computer_tool.computer, AsyncComputer)
            else cls._get_screenshot_sync(action.computer_tool.computer, action.tool_call)
        )

        _, _, output = await asyncio.gather(
            hooks.on_tool_start(context_wrapper, agent, action.computer_tool),
            (
                agent.hooks.on_tool_start(context_wrapper, agent, action.computer_tool)
                if agent.hooks
                else _coro.noop_coroutine()
            ),
            output_func,
        )

        await asyncio.gather(
            hooks.on_tool_end(context_wrapper, agent, action.computer_tool, output),
            (
                agent.hooks.on_tool_end(context_wrapper, agent, action.computer_tool, output)
                if agent.hooks
                else _coro.noop_coroutine()
            ),
        )

        # TODO: don't send a screenshot every single time, use references
        image_url = f"data:image/png;base64,{output}"
        return ToolCallOutputItem(
            agent=agent,
            output=image_url,
            raw_item=ComputerCallOutput(
                call_id=action.tool_call.call_id,
                output={
                    "type": "computer_screenshot",
                    "image_url": image_url,
                },
                type="computer_call_output",
            ),
        )

    @classmethod
    async def _get_screenshot_sync(
        cls,
        computer: Computer,
        tool_call: ResponseComputerToolCall,
    ) -> str:
        action = tool_call.action
        if isinstance(action, ActionClick):
            computer.click(action.x, action.y, action.button)
        elif isinstance(action, ActionDoubleClick):
            computer.double_click(action.x, action.y)
        elif isinstance(action, ActionDrag):
            computer.drag([(p.x, p.y) for p in action.path])
        elif isinstance(action, ActionKeypress):
            computer.keypress(action.keys)
        elif isinstance(action, ActionMove):
            computer.move(action.x, action.y)
        elif isinstance(action, ActionScreenshot):
            computer.screenshot()
        elif isinstance(action, ActionScroll):
            computer.scroll(action.x, action.y, action.scroll_x, action.scroll_y)
        elif isinstance(action, ActionType):
            computer.type(action.text)
        elif isinstance(action, ActionWait):
            computer.wait()

        return computer.screenshot()

    @classmethod
    async def _get_screenshot_async(
        cls,
        computer: AsyncComputer,
        tool_call: ResponseComputerToolCall,
    ) -> str:
        action = tool_call.action
        if isinstance(action, ActionClick):
            await computer.click(action.x, action.y, action.button)
        elif isinstance(action, ActionDoubleClick):
            await computer.double_click(action.x, action.y)
        elif isinstance(action, ActionDrag):
            await computer.drag([(p.x, p.y) for p in action.path])
        elif isinstance(action, ActionKeypress):
            await computer.keypress(action.keys)
        elif isinstance(action, ActionMove):
            await computer.move(action.x, action.y)
        elif isinstance(action, ActionScreenshot):
            await computer.screenshot()
        elif isinstance(action, ActionScroll):
            await computer.scroll(action.x, action.y, action.scroll_x, action.scroll_y)
        elif isinstance(action, ActionType):
            await computer.type(action.text)
        elif isinstance(action, ActionWait):
            await computer.wait()

        return await computer.screenshot()
