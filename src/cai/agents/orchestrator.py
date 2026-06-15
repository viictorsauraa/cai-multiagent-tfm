"""Red Team Orchestrator Agent — coordinates the full assessment."""
import os
from dotenv import load_dotenv
from openai import AsyncOpenAI
from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from cai.tools.misc.reasoning import think, read_key_findings
from cai.util import load_prompt_template, create_system_prompt_renderer
from cai.agents.guardrails import get_security_guardrails

load_dotenv()
model_name = os.getenv("CAI_MODEL", "alias1")
api_key = os.getenv("ALIAS_API_KEY", os.getenv("OPENAI_API_KEY", "sk-alias-1234567890"))

orchestrator_system_prompt = load_prompt_template("prompts/system_orchestrator_agent.md")

input_guardrails, output_guardrails = get_security_guardrails()

orchestrator_agent = Agent(
    name="Red Team Orchestrator",
    description="Coordinates the full red team assessment, delegating to specialists.",
    instructions=create_system_prompt_renderer(orchestrator_system_prompt),
    tools=[think, read_key_findings],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=AsyncOpenAI(api_key=api_key),
    ),
)
