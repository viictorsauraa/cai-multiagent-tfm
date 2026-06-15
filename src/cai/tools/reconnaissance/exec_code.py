"""
Tool for executing code via LLM tool calls.
"""
import os
import re
import shlex
import uuid

from cai.tools.common import run_command, _get_workspace_dir  # pylint: disable=import-error
from cai.sdk.agents import function_tool


# Per-language lint commands. Run BEFORE execution so syntax errors surface
# as a structured message instead of being buried in runtime stderr.
# Skipped for languages whose compile/build step (line 111+) already lints.
_SYNTAX_CHECK = {
    "bash": "bash -n {f}",
    "sh": "bash -n {f}",
    "shell": "bash -n {f}",
    "ruby": "ruby -c {f}",
    "rb": "ruby -c {f}",
    "perl": "perl -c {f}",
    "pl": "perl -c {f}",
    "php": "php -l {f}",
    "javascript": "node --check {f}",
    "js": "node --check {f}",
}


@function_tool
def execute_code(code: str = "", language: str = "python",
                filename: str = "exploit", timeout: int = 100, ctf=None) -> str:
    """
    Create a file code store it and execute it

    This tool allows for executing code provided in different
    programming languages. It creates a permanent file with the provided code
    and executes it using the appropriate interpreter. You can exec this
    code as many times as you want using `generic_linux_command` tool.

    Priorize: Python and Perl

    Args:
        code: The code snippet to execute
        language: Programming language to use (default: python)
        filename: Base name for the file without extension (default: exploit)
        timeout: Timeout for the execution (default: 100 seconds)
                Use high timeout for long running code 
                Use low timeout for short running code
    Returns:
        Command output or error message from execution
    """

    if not code:
        return "No code provided to execute"

    # Map file extensions
    extensions = {
        "python": "py",
        "py": "py",       # alias for python
        "php": "php",
        "bash": "sh",
        "sh": "sh",       # alias for bash
        "shell": "sh",    # alias for bash
        "ruby": "rb",
        "rb": "rb",       # alias for ruby
        "perl": "pl",
        "pl": "pl",       # alias for perl
        "golang": "go",
        "go": "go",       # alias for golang
        "javascript": "js",
        "js": "js",       # alias for javascript
        "typescript": "ts",
        "ts": "ts",       # alias for typescript
        "rust": "rs",
        "rs": "rs",       # alias for rust
        "csharp": "cs",
        "cs": "cs",       # alias for csharp
        "java": "java",
        "kotlin": "kt",
        "kt": "kt",       # alias for kotlin
        "c": "c",
        "cpp": "cpp",
        "c++": "cpp",     # alias for cpp
    }
    # Normalize language to lowercase
    language = language.lower()
    ext = extensions.get(language, "txt")

    # Sanitize filename to prevent command injection
    filename = os.path.basename(filename)
    if not re.match(r'^[a-zA-Z0-9_\-]+$', filename):
        return (f"Invalid filename: '{filename}'. "
                "Only alphanumeric characters, hyphens, and underscores allowed.")

    full_filename = f"{filename}.{ext}"
    safe_full = shlex.quote(full_filename)
    safe_name = shlex.quote(filename)

    # Create code file with content using unique delimiter to avoid collisions
    delimiter = f"CAI_CODE_BLOCK_{uuid.uuid4().hex[:8]}"
    create_cmd = f"cat << '{delimiter}' > {safe_full}\n{code}\n{delimiter}"
    # Don't stream the file creation and suppress output display
    result = run_command(create_cmd, ctf=ctf, stream=False, tool_name="_internal_file_creation")
    if result.strip() and (
        "No such file" in result
        or "Permission denied" in result
        or ("Command exited with code" in result and "code 0" not in result)
    ):
        return f"Failed to create code file: {result}"

    # Resolve the path the model should use to reference this file in
    # subsequent generic_linux_command calls. Echoing it eliminates the
    # common failure mode where the model invents a path (typically /tmp/)
    # that doesn't match where CAI actually wrote the file.
    saved_path = os.path.join(_get_workspace_dir(), full_filename)
    path_banner = f"[execute_code] saved: {saved_path}\n"

    # Python: in-process syntax check before launching the interpreter.
    # Catches errors like unterminated strings that would otherwise surface
    # as confusing runtime stderr.
    if language in ("python", "py"):
        try:
            compile(code, full_filename, "exec")
        except SyntaxError as e:
            return (f"{path_banner}[execute_code] SyntaxError: {e.msg} "
                    f"at line {e.lineno}, column {e.offset}. File saved but "
                    f"NOT executed. Fix the syntax and re-emit.")

    # Other interpreted languages: run the interpreter's check flag.
    check_tpl = _SYNTAX_CHECK.get(language)
    if check_tpl:
        check_out = run_command(check_tpl.format(f=safe_full), ctf=ctf,
                                stream=False, tool_name="_internal_syntax_check")
        if "Command exited with code" in check_out and "code 0" not in check_out:
            return (f"{path_banner}[execute_code] Syntax check failed:\n"
                    f"{check_out}\nFile saved but NOT executed.")

    # Prepare execution command based on language
    if language in ["python", "py"]:
        exec_cmd = f"python3 {safe_full}"
    elif language in ["php"]:
        exec_cmd = f"php {safe_full}"
    elif language in ["bash", "sh", "shell"]:
        exec_cmd = f"bash {safe_full}"
    elif language in ["ruby", "rb"]:
        exec_cmd = f"ruby {safe_full}"
    elif language in ["perl", "pl"]:
        exec_cmd = f"perl {safe_full}"
    elif language in ["golang", "go"]:
        temp_dir = f"/tmp/go_exec_{filename}"
        safe_temp = shlex.quote(temp_dir)
        run_command(f"mkdir -p {safe_temp}", ctf=ctf, stream=False, tool_name="_internal_setup")
        run_command(f"cp {safe_full} {safe_temp}/main.go", ctf=ctf, stream=False, tool_name="_internal_setup")
        compile_result = run_command(f"cd {safe_temp} && go mod init temp && go build -o main main.go", ctf=ctf, stream=False, tool_name="_internal_setup")
        if "error" in compile_result.lower():
            return f"Compilation failed:\n{compile_result}"
        exec_cmd = f"cd {safe_temp} && ./main"
    elif language in ["javascript", "js"]:
        exec_cmd = f"node {safe_full}"
    elif language in ["typescript", "ts"]:
        exec_cmd = f"ts-node {safe_full}"
    elif language in ["rust", "rs"]:
        compile_result = run_command(f"rustc {safe_full} -o {safe_name}", ctf=ctf, stream=False, tool_name="_internal_setup")
        if "error" in compile_result.lower():
            return f"Compilation failed:\n{compile_result}"
        exec_cmd = f"./{safe_name}"
    elif language in ["csharp", "cs"]:
        compile_result = run_command(f"dotnet build {safe_full}", ctf=ctf, stream=False, tool_name="_internal_setup")
        if "error" in compile_result.lower():
            return f"Compilation failed:\n{compile_result}"
        exec_cmd = f"dotnet run {safe_full}"
    elif language in ["java"]:
        compile_result = run_command(f"javac {safe_full}", ctf=ctf, stream=False, tool_name="_internal_setup")
        if "error" in compile_result.lower():
            return f"Compilation failed:\n{compile_result}"
        exec_cmd = f"java {safe_name}"
    elif language in ["kotlin", "kt"]:
        safe_jar = shlex.quote(f"{filename}.jar")
        compile_result = run_command(f"kotlinc {safe_full} -include-runtime -d {safe_jar}", ctf=ctf, stream=False, tool_name="_internal_setup")
        if "error" in compile_result.lower():
            return f"Compilation failed:\n{compile_result}"
        exec_cmd = f"java -jar {safe_jar}"
    elif language in ["c"]:
        compile_result = run_command(f"gcc {safe_full} -o {safe_name}", ctf=ctf, stream=False, tool_name="_internal_setup")
        if "error" in compile_result.lower():
            return f"Compilation failed:\n{compile_result}"
        exec_cmd = f"./{safe_name}"
    elif language in ["cpp", "c++"]:
        compile_result = run_command(f"g++ {safe_full} -o {safe_name}", ctf=ctf, stream=False, tool_name="_internal_setup")
        if "error" in compile_result.lower():
            return f"Compilation failed:\n{compile_result}"
        exec_cmd = f"./{safe_name}"
    else:
        return f"Unsupported language: {language}"

    # Execute the code with syntax-highlighted output
    # Create a custom tool args dictionary to send language and code info to the tool output function
    tool_args = {
        "command": "execute",
        "language": language,
        "filename": filename,
        "code": code,  # Include the code for syntax highlighting
        "timeout": timeout
    }
    
    # Run the command with streaming to get syntax highlighting
    output = run_command(
        exec_cmd,
        ctf=ctf,
        timeout=timeout,
        stream=True,  # ALWAYS use streaming
        tool_name="execute_code",
        args=tool_args
    )

    return path_banner + output
