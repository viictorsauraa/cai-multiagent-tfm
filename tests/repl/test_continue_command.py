"""Tests for the /continue command."""
import pytest

from cai.repl.commands.continue_cmd import ContinueCommand, CONTINUE_STATE


@pytest.fixture(autouse=True)
def reset_state():
    """Reset CONTINUE_STATE before and after each test."""
    CONTINUE_STATE.enabled = False
    CONTINUE_STATE.pending_input = None
    yield
    CONTINUE_STATE.enabled = False
    CONTINUE_STATE.pending_input = None


@pytest.fixture
def cmd():
    return ContinueCommand()


class TestContinueOn:
    def test_on_enables(self, cmd):
        assert cmd.handle_on([]) is True
        assert CONTINUE_STATE.enabled is True

    def test_on_idempotent(self, cmd):
        CONTINUE_STATE.enabled = True
        assert cmd.handle_on([]) is True
        assert CONTINUE_STATE.enabled is True


class TestContinueOff:
    def test_off_disables(self, cmd):
        CONTINUE_STATE.enabled = True
        assert cmd.handle_off([]) is True
        assert CONTINUE_STATE.enabled is False

    def test_off_clears_pending(self, cmd):
        CONTINUE_STATE.pending_input = "something"
        cmd.handle_off([])
        assert CONTINUE_STATE.pending_input is None


class TestContinueToggle:
    def test_toggle_on(self, cmd):
        assert cmd.handle_toggle() is True
        assert CONTINUE_STATE.enabled is True

    def test_toggle_off(self, cmd):
        CONTINUE_STATE.enabled = True
        assert cmd.handle_toggle() is True
        assert CONTINUE_STATE.enabled is False

    def test_toggle_clears_pending_when_off(self, cmd):
        CONTINUE_STATE.enabled = True
        CONTINUE_STATE.pending_input = "something"
        cmd.handle_toggle()
        assert CONTINUE_STATE.pending_input is None


class TestContinueStatus:
    def test_status_returns_true(self, cmd):
        assert cmd.handle_status([]) is True


class TestContinueHandle:
    def test_no_args_toggles(self, cmd):
        cmd.handle()
        assert CONTINUE_STATE.enabled is True

    def test_subcommand_dispatch(self, cmd):
        cmd.handle(["on"])
        assert CONTINUE_STATE.enabled is True
        cmd.handle(["off"])
        assert CONTINUE_STATE.enabled is False

    def test_unknown_subcommand(self, cmd):
        result = cmd.handle(["bogus"])
        assert result is False
