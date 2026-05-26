"""Hardened execution context for Axon MCP.

Provides ``running_guard`` v2 — a context manager that auto-resumes x64dbg
when events pause the process, with support for:
- Nested guards
- Catch-all untracked-pause detection
- Configurable resume policies
- State-machine integration
"""

from __future__ import annotations

import dataclasses
import enum
import threading
import time
from contextlib import contextmanager
from typing import Callable

from x64dbg_automate.events import EventType
from x64dbg_automate.api_runtime.debugger_state import DebuggerState, DebuggerStateMachine


class ResumePolicy(enum.StrEnum):
    """How aggressively the guard should resume x64dbg."""
    NEVER = "never"                       # Don't auto-resume
    TRACKED_EVENTS = "tracked_events"     # Only resume on explicitly listed events
    ALL_NON_BREAKPOINT = "all_non_bp"     # Resume on any event except breakpoints
    FORCE = "force"                       # Always resume on any pause


@dataclasses.dataclass
class GuardContext:
    """Snapshot of the guard's state at a point in time."""
    policy: ResumePolicy
    tracked_events: set[EventType]
    entered_at: float
    resumes_triggered: int = 0
    untracked_pauses: list[str] = dataclasses.field(default_factory=list)


class ExecutionContextManager:
    """Manages nested running_guard contexts and tracks pause history."""

    def __init__(self, client, state_machine: DebuggerStateMachine | None = None):
        self._client = client
        self._sm = state_machine or DebuggerStateMachine()
        self._guard_stack: list[GuardContext] = []
        self._stack_lock = threading.Lock()

    @property
    def state_machine(self) -> DebuggerStateMachine:
        return self._sm

    @contextmanager
    def running_guard(
        self,
        tracked_events: set[EventType] | None = None,
        policy: ResumePolicy = ResumePolicy.TRACKED_EVENTS,
        timeout: float = 30.0,
        on_untracked_pause: Callable[[str], None] | None = None,
    ):
        """Enter a hardened execution context.

        Args:
            tracked_events: Event types that trigger auto-resume under
                ``TRACKED_EVENTS`` policy.
            policy: Resume aggressiveness (see ``ResumePolicy``).
            timeout: Max seconds for the guarded block; if exceeded, the guard
                raises ``TimeoutError`` on exit.
            on_untracked_pause: Optional callback invoked when the debugger
                pauses on an event NOT in *tracked_events*.

        Raises:
            TimeoutError: If the guarded block exceeds *timeout*.
        """
        if tracked_events is None:
            tracked_events = set()

        ctx = GuardContext(
            policy=policy,
            tracked_events=set(tracked_events),
            entered_at=time.time(),
        )

        with self._stack_lock:
            self._guard_stack.append(ctx)
            depth = len(self._guard_stack)

        # Set up auto-resume hook on the client
        original_events = getattr(self._client, "_auto_resume_events", set()).copy()
        original_fn = getattr(self._client, "_auto_resume_fn", None)

        def _handler(event):
            self._handle_pause_event(event, ctx, on_untracked_pause)

        # If nested, merge tracked events from all active guards
        merged_events = self._merged_tracked_events()
        self._client._auto_resume_events = merged_events
        self._client._auto_resume_fn = _handler

        try:
            yield ctx
        finally:
            elapsed = time.time() - ctx.entered_at
            with self._stack_lock:
                if self._guard_stack and self._guard_stack[-1] is ctx:
                    self._guard_stack.pop()

            # Restore outer guard's hooks if any remain, else clear
            if self._guard_stack:
                outer = self._guard_stack[-1]
                merged = self._merged_tracked_events()
                self._client._auto_resume_events = merged
                # Re-bind outer handler — but we can't easily recover the closure.
                # Instead, we use a single stable handler that delegates to the top guard.
                self._client._auto_resume_fn = self._make_top_guard_handler()
            else:
                self._client._auto_resume_events = original_events
                self._client._auto_resume_fn = original_fn

            if elapsed > timeout:
                raise TimeoutError(
                    f"running_guard timed out after {elapsed:.2f}s (limit {timeout}s). "
                    f"Resumes triggered: {ctx.resumes_triggered}. "
                    f"Untracked pauses: {ctx.untracked_pauses}"
                )

    def _merged_tracked_events(self) -> set[EventType]:
        merged: set[EventType] = set()
        for ctx in self._guard_stack:
            merged |= ctx.tracked_events
        return merged

    def _make_top_guard_handler(self) -> Callable:
        """Return a handler that delegates to whichever guard is currently on top."""
        def handler(event):
            with self._stack_lock:
                if not self._guard_stack:
                    return
                top = self._guard_stack[-1]
            self._handle_pause_event(event, top, None)
        return handler

    def _handle_pause_event(self, event, ctx: GuardContext, on_untracked_pause: Callable | None) -> None:
        event_str = str(event.event_type)
        should_resume = False

        if ctx.policy == ResumePolicy.NEVER:
            should_resume = False
        elif ctx.policy == ResumePolicy.FORCE:
            should_resume = True
        elif ctx.policy == ResumePolicy.TRACKED_EVENTS:
            should_resume = event.event_type in ctx.tracked_events
        elif ctx.policy == ResumePolicy.ALL_NON_BREAKPOINT:
            should_resume = event.event_type != EventType.EVENT_BREAKPOINT

        if should_resume:
            ctx.resumes_triggered += 1
            # Update state machine
            if self._sm.current_state == DebuggerState.RUNNING:
                self._sm.transition(DebuggerState.PAUSED_EVENT, reason=f"Auto-resume on {event_str}")
            # Fire-and-forget resume
            def _do_resume():
                try:
                    self._client.go()
                except Exception:
                    pass
            threading.Thread(target=_do_resume, daemon=True).start()
        else:
            ctx.untracked_pauses.append(event_str)
            if on_untracked_pause is not None:
                try:
                    on_untracked_pause(event_str)
                except Exception:
                    pass
            # Notify state machine of untracked pause
            self._sm.transition(DebuggerState.PAUSED_EVENT, reason=f"Untracked pause on {event_str}")
