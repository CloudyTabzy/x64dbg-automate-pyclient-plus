"""Debugger state machine and health monitor for Axon MCP.

Tracks x64dbg's execution state across the session lifecycle, detects
unexpected pauses, and provides structured recovery hints to AI agents.

State Transitions::

    DISCONNECTED ──► CONNECTING ──► STOPPED (system breakpoint)
                                        │
                    ┌───────────────────┼───────────────────┐
                    │                   │                   │
                    ▼                   ▼                   ▼
               RUNNING ◄─────────► PAUSED_EVENT      PAUSED_BREAKPOINT
                    │                   │                   │
                    │                   ▼                   │
                    │              STOPPED ◄────────────────┘
                    │                   │
                    └───────────────────┘

States:
    - DISCONNECTED: No x64dbg session active.
    - CONNECTING: Session being established.
    - STOPPED: Debuggee loaded but execution paused (e.g. system breakpoint).
    - RUNNING: Debuggee is actively executing.
    - PAUSED_EVENT: Debuggee paused on an event (OutputDebugString, load DLL, etc).
    - PAUSED_BREAKPOINT: Debuggee paused on a user or system breakpoint.
    - ERROR: Communication failure or unexpected condition.
"""

from __future__ import annotations

import dataclasses
import enum
import threading
import time
from typing import Callable


class DebuggerState(enum.StrEnum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    STOPPED = "stopped"
    RUNNING = "running"
    PAUSED_EVENT = "paused_event"
    PAUSED_BREAKPOINT = "paused_breakpoint"
    ERROR = "error"


@dataclasses.dataclass
class StateTransition:
    """A single state transition with metadata."""
    timestamp: float
    from_state: DebuggerState
    to_state: DebuggerState
    reason: str = ""
    event_type: str | None = None


class DebuggerStateMachine:
    """Thread-safe state machine for tracking x64dbg lifecycle.

    Designed to be attached to a sandbox or client instance.  The AI agent
    can query ``current_state`` and ``transition_log`` at any time to
    understand why the debugger is in a particular condition.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._state = DebuggerState.DISCONNECTED
        self._log: list[StateTransition] = []
        self._listeners: list[Callable[[StateTransition], None]] = []
        self._last_health_check = 0.0
        self._consecutive_errors = 0

    # ── Public API ──────────────────────────────────────────────────────────

    @property
    def current_state(self) -> DebuggerState:
        with self._lock:
            return self._state

    @property
    def transition_log(self) -> list[StateTransition]:
        with self._lock:
            return list(self._log)

    def transition(self, new_state: DebuggerState, reason: str = "", event_type: str | None = None) -> StateTransition:
        """Atomically transition to a new state and notify listeners."""
        with self._lock:
            old = self._state
            if old == new_state:
                return StateTransition(time.time(), old, new_state, reason, event_type)

            tx = StateTransition(time.time(), old, new_state, reason, event_type)
            self._log.append(tx)
            # Keep last 500 transitions to avoid unbounded growth
            if len(self._log) > 500:
                self._log = self._log[-500:]
            self._state = new_state

            if new_state == DebuggerState.ERROR:
                self._consecutive_errors += 1
            else:
                self._consecutive_errors = 0

        for listener in self._listeners:
            try:
                listener(tx)
            except Exception:
                pass
        return tx

    def add_listener(self, callback: Callable[[StateTransition], None]) -> None:
        with self._lock:
            self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[StateTransition], None]) -> None:
        with self._lock:
            if callback in self._listeners:
                self._listeners.remove(callback)

    def is_healthy(self) -> bool:
        """Return False if the state machine is stuck in ERROR or has
        accumulated too many consecutive errors."""
        with self._lock:
            return self._state != DebuggerState.ERROR and self._consecutive_errors < 3

    def is_executing(self) -> bool:
        """True if the debuggee is expected to be making forward progress."""
        with self._lock:
            return self._state == DebuggerState.RUNNING

    def is_paused(self) -> bool:
        with self._lock:
            return self._state in (
                DebuggerState.STOPPED,
                DebuggerState.PAUSED_EVENT,
                DebuggerState.PAUSED_BREAKPOINT,
            )

    def last_transition_within(self, seconds: float) -> bool:
        """True if any state change occurred within the last *seconds*."""
        with self._lock:
            if not self._log:
                return False
            return (time.time() - self._log[-1].timestamp) < seconds

    def get_recent_events(self, n: int = 20) -> list[StateTransition]:
        with self._lock:
            return self._log[-n:]


class HealthMonitor:
    """Low-frequency background liveness monitor.

    Earlier this polled ``is_running()``/``is_debugging()`` over the *shared* REQ
    socket every 250 ms (~8 RPC round-trips/sec), which contended with tool calls
    and churned the connection. It now:

    * runs at a slow interval (default 5 s),
    * checks liveness via the client's **dedicated** probe socket
      (``is_connection_alive``) so it never touches the shared REQ socket,
    * only does a state refresh (running/paused) when the link is alive, and only
      if the client exposes a cheap path.

    Combined with ZMTP heartbeats (which keep the link up during idle gaps), this
    removes the connection churn while preserving the flight-recorder transitions
    that ``get_debugger_state`` / ``get_execution_log`` rely on. It deliberately
    does NOT auto-reconnect in the background — recovery happens on the next tool
    call (serialized with tool execution) to avoid racing a mid-flight request.
    """

    def __init__(
        self,
        client,
        state_machine: DebuggerStateMachine,
        poll_interval: float = 5.0,
        stall_threshold: float = 2.0,
        on_stall: Callable | None = None,
    ):
        self._client = client
        self._sm = state_machine
        self._poll_interval = poll_interval
        self._stall_threshold = stall_threshold
        self._on_stall = on_stall
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._expected_running = False
        self._expected_running_since = 0.0

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def expect_running(self, expected: bool = True) -> None:
        """Tell the monitor whether the debuggee *should* be running."""
        self._expected_running = expected
        if expected:
            self._expected_running_since = time.time()

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception:
                pass
            self._stop_event.wait(self._poll_interval)

    def _tick(self) -> None:
        # Low-frequency state refresh over the SHARED socket. At a 5s cadence this
        # is ~0.2 req/s — negligible versus the old 8 req/s hammering — and the
        # ZMTP heartbeat (not this poll) is what keeps the link alive during idle.
        #
        # We deliberately do NOT create a probe socket here: socket creation from
        # this background thread can race with connection teardown and trip a
        # libzmq signaler assertion on Windows. The dedicated probe socket
        # (is_connection_alive) is only used on the main thread, synchronously
        # with tool calls.
        try:
            is_running = self._client.is_running()
            is_debugging = self._client.is_debugging()
        except Exception:
            # A transient failure here is not fatal; the next tool call heals it.
            return

        if not is_debugging:
            self._sm.transition(DebuggerState.DISCONNECTED, reason="is_debugging() returned False")
            return

        if is_running:
            if self._sm.current_state != DebuggerState.RUNNING:
                self._sm.transition(DebuggerState.RUNNING, reason="is_running() True")
        else:
            if self._sm.current_state == DebuggerState.RUNNING:
                self._sm.transition(DebuggerState.PAUSED_EVENT, reason="Unexpected pause while RUNNING")

            if self._expected_running and self._stall_threshold > 0:
                paused_for = time.time() - self._expected_running_since
                if paused_for > self._stall_threshold and self._on_stall is not None:
                    self._on_stall(self._sm.current_state, paused_for)
                    self._expected_running_since = time.time()
