<%
    # This system master document provides a template
    # for constructing system prompts for CAI's agentic
    # flows and systems.
    #
    # The structure of the prompts include the following
    # sections:
    #
    # 1. Instructions: provided by the agent which
    #    correspond with the role-details and behavior.
    #
    # 2. Compacted Summary (optional): AI-generated summary
    #    from previous conversations to reduce context usage
    #
    # 3. Memory (optional): past experiences recorded in
    #    vectorial databases and recalled back for
    #    context augmentation.
    #
    # 4. Reasoning (optional): Leverage reasoning-type
    #    LLM models (which could be different from selected)
    #    to further augment the context with additional
    #    thought processes
    #
    # 5. Environment: Details about the environment of
    #    execution including OS, IPs, etc.
    #

    import os
    from cai.util import cli_print_tool_call
    try:
        from cai.rag.vector_db import get_previous_memory
    except Exception as e:
        # Silently ignore if RAG module is not available
        pass
    from cai import is_caiextensions_memory_available
    
    # Import compact summary function
    try:
        from cai.repl.commands.memory import get_compacted_summary
        # Get agent name from the agent object
        agent_name = getattr(agent, 'name', None)
        compacted_summary = get_compacted_summary(agent_name)
    except Exception as e:
        compacted_summary = None

    # Get system prompt from the base instructions passed to the template
    # The base instructions are passed as 'ctf_instructions' in the render context
    # We use the pre-set system_prompt variable which equals base_instructions
    # Do NOT call agent.instructions here as that would create infinite recursion!

    # Get CTF_INSIDE environment variable
    ctf_inside = os.getenv('CTF_INSIDE')
    env_context = os.getenv('CAI_ENV_CONTEXT', 'true').lower()
    # Get memory from vector db if RAG is enabled
    rag_enabled = os.getenv("CAI_MEMORY", "?").lower() in ["episodic", "semantic", "all"]
    memory = ""
    if rag_enabled:
        if os.getenv("CAI_MEMORY", "?").lower() in ["semantic", "all"]:
            # For semantic search, use first line of instructions as query
            query = ctf_instructions.split('\n')[0].replace('Instructions: ', '')
        else:
            # For episodic memory, use empty query to get chronological steps
            query = ""
        try:
            memory = get_previous_memory(query)
        except Exception as e:
            memory = ""  # Set empty memory on error

        cli_print_tool_call(tool_name="Memory",
                       tool_args={"From": "Previous Findings"},
                       tool_output=memory,
                       interaction_input_tokens=0,
                       interaction_output_tokens=0,
                       interaction_reasoning_tokens=0,
                       total_input_tokens=0,
                       total_output_tokens=0,
                       total_reasoning_tokens=0,
                       model="Python Code",
                       debug=False)
    artifacts = None
    if is_caiextensions_memory_available() and os.getenv('CTF_NAME'):
        from caiextensions.memory import get_artifacts
        artifacts = get_artifacts(os.getenv('CTF_NAME').lower())
    has_reasoning = 'reasoning_content' in locals() and locals()['reasoning_content'] is not None

%>
${system_prompt}
% if compacted_summary:

<compacted_context>
This is a summary of previous conversation context that has been compacted to save tokens:

${compacted_summary}

Use this summary to understand the context and continue from where the conversation left off.
</compacted_context>
% endif
% if rag_enabled:

<memory>
${memory}
</memory>

Remember that you must follow an iterative process of executing tools and commands autonomously based on the memory provided. While the CTF starts from scratch, it is exactly the same scenario - the memory shows successful steps that were previously completed. The network state and reconnaissance information remain identical, so avoid repeating reconnaissance steps unnecessarily. Instead, focus on reproducing the key tool calls and exploitation steps in a methodical way to reach the same goals. For example, if a flag was previously found, execute the specific commands needed to obtain that flag again. Always use the flag discriminator to validate flags. Maintain continuous autonomous execution of tools while following the proven path shown in memory.
% endif

% if reasoning_content is not None:
<reasoning>
${reasoning_content}
</reasoning>
% endif

% if env_context.lower() == 'true':
<%
    import platform
    import socket
    import os

    from pathlib import Path

    # Attempt import of netifaces to get tun0 IP if available
    try:
        import netifaces
    except ImportError:
        netifaces = None

    # Gather system info
    try:
        hostname = socket.gethostname()
        ip_addr = socket.gethostbyname(hostname)
        os_name = platform.system()
    except:
        hostname = "local0"
        ip_addr = "127.0.0.1"
        os_name = "Linux"   

    # Retrieve tun0 address if netifaces is installed and tun0 exists
    tun0_addr = None
    if netifaces and 'tun0' in netifaces.interfaces():
        addrs = netifaces.ifaddresses('tun0')
        if netifaces.AF_INET in addrs:
            tun0_addr = addrs[netifaces.AF_INET][0].get('addr', None)

    # Get wordlist directories — check common locations
    wordlist_path = Path('/usr/share/wordlists')
    wordlist_entries = []
    if wordlist_path.exists():
        wordlist_entries = sorted([
            f"{e.name}/" if e.is_dir() else e.name
            for e in wordlist_path.iterdir()
        ])

    # Also check /usr/share/dirb/wordlists (standalone dirb install)
    dirb_path = Path('/usr/share/dirb/wordlists')
    dirb_files = []
    if dirb_path.exists():
        dirb_files = sorted([f.name for f in dirb_path.iterdir() if f.is_file()])
%>
Attacker machine information:
├── OS: ${os_name}
├── Hostname: ${hostname}
├── IP Attacker (default): ${ip_addr}
% if tun0_addr:
├── IP tun0: ${tun0_addr}
% endif
└── Role: Attacker

% if wordlist_entries:
Available wordlists in /usr/share/wordlists/:
% for entry in wordlist_entries:
├── ${entry}
% endfor
% endif
% if dirb_files:
Available wordlists in /usr/share/dirb/wordlists/:
% for f in dirb_files:
├── ${f}
% endfor
% endif

IMPORTANT: Do NOT assume or guess file paths for wordlists, tools, or any other resources.
Use ONLY the paths listed above. If you need a wordlist or resource not listed, run
`find /usr/share -name "filename" 2>/dev/null` or `ls` to locate it first.
% endif

% if artifacts:
Useful information: ${artifacts}
% endif
