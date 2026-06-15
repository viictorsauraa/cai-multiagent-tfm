"""Bug Bounty Recon & Scope Agent — asset discovery and enumeration."""
import os
from dotenv import load_dotenv
from openai import AsyncOpenAI
from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from cai.tools.reconnaissance.generic_linux_command import generic_linux_command
from cai.tools.misc.reasoning import write_key_findings, read_key_findings
from cai.util import load_prompt_template, create_system_prompt_renderer
from cai.agents.guardrails import get_security_guardrails

load_dotenv()
model_name = os.getenv("CAI_MODEL", "alias1")
api_key = os.getenv("ALIAS_API_KEY", os.getenv("OPENAI_API_KEY", "sk-alias-1234567890"))

bb_recon_system_prompt = load_prompt_template("prompts/system_bb_recon_agent.md")

input_guardrails, output_guardrails = get_security_guardrails()

bb_recon_agent = Agent(
    name="BB Recon Agent",
    description="Performs reconnaissance: subdomain enumeration, port scanning, directory fuzzing.",
    instructions=create_system_prompt_renderer(bb_recon_system_prompt),
    tools=[generic_linux_command, write_key_findings, read_key_findings],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=AsyncOpenAI(api_key=api_key),
    ),
)
