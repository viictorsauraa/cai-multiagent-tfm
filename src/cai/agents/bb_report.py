"""Bug Bounty Report & Triage Agent — findings documentation."""
import os
from dotenv import load_dotenv
from openai import AsyncOpenAI
from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from cai.tools.reconnaissance.generic_linux_command import generic_linux_command
from cai.tools.misc.reasoning import read_key_findings
from cai.util import load_prompt_template, create_system_prompt_renderer
from cai.agents.guardrails import get_security_guardrails

load_dotenv()
model_name = os.getenv("CAI_MODEL", "alias1")
api_key = os.getenv("ALIAS_API_KEY", os.getenv("OPENAI_API_KEY", "sk-alias-1234567890"))

bb_report_system_prompt = load_prompt_template("prompts/system_bb_report_agent.md")

input_guardrails, output_guardrails = get_security_guardrails()

bb_report_agent = Agent(
    name="BB Report and Triage",
    description="Documents findings with severity, reproduction steps, and generates platform-ready reports.",
    instructions=create_system_prompt_renderer(bb_report_system_prompt),
    tools=[generic_linux_command, read_key_findings],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=AsyncOpenAI(api_key=api_key),
    ),
)
