"""Strategy Agent — analysis and attack planning."""
import os
from dotenv import load_dotenv
from openai import AsyncOpenAI
from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from cai.tools.misc.reasoning import think, thought, write_key_findings, read_key_findings
from cai.util import load_prompt_template, create_system_prompt_renderer
from cai.agents.guardrails import get_security_guardrails

load_dotenv()
model_name = os.getenv("CAI_MODEL", "alias1")
api_key = os.getenv("ALIAS_API_KEY", os.getenv("OPENAI_API_KEY", "sk-alias-1234567890"))

strategy_system_prompt = load_prompt_template("prompts/system_strategy_agent.md")

input_guardrails, output_guardrails = get_security_guardrails()

strategy_agent = Agent(
    name="Strategy Agent",
    description="Analyzes findings and defines the attack strategy.",
    instructions=create_system_prompt_renderer(strategy_system_prompt),
    tools=[think, thought, write_key_findings, read_key_findings],
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=AsyncOpenAI(api_key=api_key),
    ),
)
