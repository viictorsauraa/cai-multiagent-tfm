"""Tests for the /state command."""

import os
import pytest
from cai.repl.commands.state import StateCommand, _state_path


@pytest.fixture
def state_cmd():
    return StateCommand()


@pytest.fixture
def tmp_cwd(tmp_path, monkeypatch):
    """Change cwd to a temp dir so state.txt doesn't pollute the project."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestStateShow:
    def test_show_no_file(self, state_cmd, tmp_cwd):
        assert state_cmd.handle_show([]) is True

    def test_show_with_file(self, state_cmd, tmp_cwd):
        (tmp_cwd / "state.txt").write_text("credentials: admin:pass123\n")
        assert state_cmd.handle_show([]) is True

    def test_show_empty_file(self, state_cmd, tmp_cwd):
        (tmp_cwd / "state.txt").write_text("")
        assert state_cmd.handle_show([]) is True


class TestStateClear:
    def test_clear_removes_file(self, state_cmd, tmp_cwd):
        (tmp_cwd / "state.txt").write_text("some findings\n")
        assert state_cmd.handle_clear([]) is True
        assert not (tmp_cwd / "state.txt").exists()

    def test_clear_no_file(self, state_cmd, tmp_cwd):
        assert state_cmd.handle_clear([]) is True


class TestStateWrite:
    def test_write_creates_file(self, state_cmd, tmp_cwd):
        assert state_cmd.handle_write(["hello", "world"]) is True
        assert (tmp_cwd / "state.txt").read_text() == "hello world\n"

    def test_write_overwrites(self, state_cmd, tmp_cwd):
        (tmp_cwd / "state.txt").write_text("old content\n")
        assert state_cmd.handle_write(["new", "content"]) is True
        assert (tmp_cwd / "state.txt").read_text() == "new content\n"

    def test_write_no_args(self, state_cmd, tmp_cwd):
        assert state_cmd.handle_write([]) is False


class TestStatePath:
    def test_path_shows(self, state_cmd, tmp_cwd):
        assert state_cmd.handle_path([]) is True


class TestStateHandle:
    def test_default_is_show(self, state_cmd, tmp_cwd):
        assert state_cmd.handle() is True

    def test_subcommand_dispatch(self, state_cmd, tmp_cwd):
        (tmp_cwd / "state.txt").write_text("data\n")
        assert state_cmd.handle(["clear"]) is True
        assert not (tmp_cwd / "state.txt").exists()

    def test_unknown_subcommand_falls_to_show(self, state_cmd, tmp_cwd):
        assert state_cmd.handle(["unknown"]) is True


class TestStateWorkspaceResolution:
    """state.txt path should respect workspace resolution via _get_workspace_dir."""

    def test_uses_workspace_dir_with_name(self, tmp_path, monkeypatch):
        """CAI_WORKSPACE_DIR + CAI_WORKSPACE → base/name/state.txt"""
        monkeypatch.setenv("CAI_WORKSPACE_DIR", str(tmp_path))
        monkeypatch.setenv("CAI_WORKSPACE", "myws")
        from cai.tools.misc.reasoning import _state_file_path
        assert _state_file_path() == str(tmp_path / "myws" / "state.txt")

    def test_uses_workspace_dir_only(self, tmp_path, monkeypatch):
        """CAI_WORKSPACE_DIR alone (no name) → base/state.txt"""
        monkeypatch.delenv("CAI_WORKSPACE", raising=False)
        monkeypatch.setenv("CAI_WORKSPACE_DIR", str(tmp_path))
        from cai.tools.misc.reasoning import _state_file_path
        assert _state_file_path() == str(tmp_path / "state.txt")

    def test_workspace_name_uses_workspaces_subdir(self, tmp_path, monkeypatch):
        """CAI_WORKSPACE alone (no DIR) → cwd/workspaces/name/state.txt"""
        monkeypatch.delenv("CAI_WORKSPACE_DIR", raising=False)
        monkeypatch.setenv("CAI_WORKSPACE", "test")
        monkeypatch.chdir(tmp_path)
        from cai.tools.misc.reasoning import _state_file_path
        assert _state_file_path() == str(tmp_path / "workspaces" / "test" / "state.txt")

    def test_falls_back_to_cwd(self, tmp_path, monkeypatch):
        monkeypatch.delenv("CAI_WORKSPACE", raising=False)
        monkeypatch.delenv("CAI_WORKSPACE_DIR", raising=False)
        monkeypatch.chdir(tmp_path)
        from cai.tools.misc.reasoning import _state_file_path
        assert _state_file_path() == str(tmp_path / "state.txt")


class TestWriteKeyFindingsDedup:
    """write_key_findings should not duplicate content in state.txt."""

    def test_write_key_findings_no_duplicate(self, tmp_path, monkeypatch):
        """Writing the same finding twice should only store it once."""
        monkeypatch.delenv("CAI_WORKSPACE", raising=False)
        monkeypatch.setenv("CAI_WORKSPACE_DIR", str(tmp_path))
        from cai.tools.misc.reasoning import write_key_findings
        import asyncio
        import json

        async def _invoke(findings):
            return await write_key_findings.on_invoke_tool(None, json.dumps({"findings": findings}))

        result1 = asyncio.get_event_loop().run_until_complete(_invoke("admin:password123"))
        result2 = asyncio.get_event_loop().run_until_complete(_invoke("admin:password123"))

        assert "Successfully wrote" in result1
        assert "skipped duplicate" in result2

        content = (tmp_path / "state.txt").read_text()
        assert content.count("admin:password123") == 1

    def test_write_key_findings_different_content_appends(self, tmp_path, monkeypatch):
        """Different findings should both be stored."""
        monkeypatch.delenv("CAI_WORKSPACE", raising=False)
        monkeypatch.setenv("CAI_WORKSPACE_DIR", str(tmp_path))
        from cai.tools.misc.reasoning import write_key_findings
        import asyncio
        import json

        async def _invoke(findings):
            return await write_key_findings.on_invoke_tool(None, json.dumps({"findings": findings}))

        asyncio.get_event_loop().run_until_complete(_invoke("Found SSH on port 22"))
        asyncio.get_event_loop().run_until_complete(_invoke("Found HTTP on port 80"))

        content = (tmp_path / "state.txt").read_text()
        assert "Found SSH on port 22" in content
        assert "Found HTTP on port 80" in content
