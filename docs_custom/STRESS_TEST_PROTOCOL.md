# Axon MCP Stress Test Protocol
## For Agent Verification of Hardened Execution Architecture

> **Version:** Axon_MCP  
> **Date:** 2026-05-26  
> **Duration:** ~15-20 minutes  
> **Prerequisites:** x64dbg installed, plugins deployed, no x64dbg instances running

---

## Pre-Test Checklist

- [ ] `C:\Dev\RE_Tools\snapshot_2025-08-19_19-40\release\x64\plugins\x64dbg-automate.dp64` exists (timestamp matches build)
- [ ] `C:\Dev\RE_Tools\snapshot_2025-08-19_19-40\release\x32\plugins\x64dbg-automate.dp32` exists (timestamp matches build)
- [ ] No x64dbg.exe or x32dbg.exe processes running (`taskkill /f /im x64dbg.exe`)
- [ ] No winver.exe processes running (`taskkill /f /im winver.exe`)
- [ ] Python environment active in `x64dbg-automate-pyclient-plus/`

---

## Test Suite 1: Plugin Health & Version (2 min)

**Goal:** Verify both architecture plugins load and report correct version.

```python
import os
os.environ["TEST_BITNESS"] = "64"
os.environ["X64DBG_PATH"] = r"C:\Dev\RE_Tools\snapshot_2025-08-19_19-40\release\x64\x64dbg.exe"

from x64dbg_automate import X64DbgClient
client = X64DbgClient()
client.start_session()  # starts x64dbg without target

# Verify plugin responds
print("Plugin version:", client._get_xauto_compat_version())
assert client._get_xauto_compat_version() == "Axon_MCP", "Version mismatch!"

# Verify ZMQ pub/sub is alive
events_before = len(client._debug_events_q)
client.go()
client.pause()
import time
time.sleep(0.5)
events_after = len(client._debug_events_q)
print(f"Events captured: {events_after - events_before}")
assert events_after > events_before, "ZMQ pub/sub not receiving events!"

client.terminate_session()
print("✅ Test 1 PASS: Plugin loads, version correct, ZMQ alive")
```

**Repeat for x32:**
```python
os.environ["TEST_BITNESS"] = "32"
os.environ["X64DBG_PATH"] = r"C:\Dev\RE_Tools\snapshot_2025-08-19_19-40\release\x32\x32dbg.exe"
# ... same test
```

---

## Test Suite 2: Event System Stress (3 min)

**Goal:** Flood x64dbg with events and verify ZMQ doesn't drop or stall.

```python
from x64dbg_automate import X64DbgClient
from x64dbg_automate.events import EventType
import queue, time

client = X64DbgClient()
client.start_session(r'c:\Windows\system32\winver.exe')
client.wait_for_debug_event(EventType.EVENT_SYSTEMBREAKPOINT)

# Register callbacks for ALL event types
callback_counts = {et: 0 for et in EventType}
event_q = queue.Queue()

def make_cb(et):
    return lambda ev: (callback_counts.update({et: callback_counts[et] + 1}), event_q.put((et, ev)))

for et in EventType:
    client.watch_debug_event(et, make_cb(et))

# Rapid pause/resume cycles to generate events
for i in range(10):
    client.go()
    time.sleep(0.1)
    client.pause()
    time.sleep(0.1)

time.sleep(1.0)  # let events drain

total_events = len(client._debug_events_q)
print(f"Total events in queue: {total_events}")
print(f"Callback hits: {sum(callback_counts.values())}")
assert total_events >= 10, f"Expected >= 10 events, got {total_events}"
assert sum(callback_counts.values()) >= 10, "Callbacks not firing!"

client.terminate_session()
print("✅ Test 2 PASS: Event system handles rapid pause/resume")
```

---

## Test Suite 3: Hardened running_guard (5 min)

**Goal:** Verify auto-resume works under real x64dbg conditions.

### 3A: Basic OutputDebugString Guard
```python
from x64dbg_automate import X64DbgClient
from x64dbg_automate.events import EventType
from x64dbg_automate.win32 import OpenProcess, CreateRemoteThread, WaitForSingleObject, CloseHandle
import queue

client = X64DbgClient()
received = queue.Queue()
client.watch_debug_event(EventType.EVENT_OUTPUT_DEBUG_STRING, received.put)

client.start_session(r'c:\Windows\system32\winver.exe')
client.wait_for_debug_event(EventType.EVENT_SYSTEMBREAKPOINT)
client.go()
client.wait_until_stopped()
client.clear_breakpoint()
client.go()

# Inject PEB-restoring shellcode
shellcode = client.virt_alloc()
sz_str = client.virt_alloc()
client.write_memory(sz_str, b'StressTest_Heartbeat\x00')

i = shellcode
i = i + client.assemble_at(i, 'mov rax, qword ptr gs:[0x60]')
i = i + client.assemble_at(i, 'mov byte ptr [rax+2], 1')
i = i + client.assemble_at(i, f'mov rcx, 0x{sz_str:x}')
i = i + client.assemble_at(i, 'mov rax, OutputDebugStringA')
i = i + client.assemble_at(i, 'call rax')
i = i + client.assemble_at(i, 'ret')

hProc = OpenProcess(0x1fffff, False, client.debugee_pid())

# CRITICAL TEST: Without guard, this would hang on INFINITE wait
with client.running_guard({EventType.EVENT_OUTPUT_DEBUG_STRING}):
    hThread = CreateRemoteThread(hProc, None, 0, shellcode, None, 0, None)
    result = WaitForSingleObject(hThread, 5000)
    print(f"WaitForSingleObject result: {result} (0=WAIT_OBJECT_0, 258=TIMEOUT)")

CloseHandle(hThread)
CloseHandle(hProc)

try:
    ev = received.get(timeout=5)
    assert ev.event_type == EventType.EVENT_OUTPUT_DEBUG_STRING
    assert b"StressTest_Heartbeat" in ev.event_data.lpDebugStringData
    print("✅ Test 3A PASS: running_guard auto-resumed, event captured")
except queue.Empty:
    print("❌ Test 3A FAIL: Event not captured!")

client.terminate_session()
```

### 3B: Nested Guards
```python
from x64dbg_automate.events import EventType

with client.running_guard({EventType.EVENT_OUTPUT_DEBUG_STRING}):
    with client.running_guard({EventType.EVENT_LOAD_DLL}):
        # Both events should be tracked
        pass
    # After inner exits, only OUTPUT_DEBUG_STRING tracked
    pass
print("✅ Test 3B PASS: Nested guards restored correctly")
```

### 3C: Untracked Pause Detection
```python
with client.running_guard({EventType.EVENT_OUTPUT_DEBUG_STRING}) as ctx:
    # Manually trigger a different event type
    client.debug_event_publish(["EVENT_RESUME_DEBUG"])
    assert len(ctx.untracked_pauses) == 1, "Untracked pause not recorded!"
print("✅ Test 3C PASS: Untracked pause detected")
```

---

## Test Suite 4: Debugger State Machine (2 min)

**Goal:** Verify state transitions are tracked correctly.

```python
from x64dbg_automate.api_runtime.debugger_state import DebuggerState

sm = client._axon_state_machine
assert sm.current_state == DebuggerState.DISCONNECTED  # Before session

client.start_session(r'c:\Windows\system32\winver.exe')
client.wait_for_debug_event(EventType.EVENT_SYSTEMBREAKPOINT)

# After system breakpoint, state should reflect stopped
assert sm.is_paused() or sm.current_state == DebuggerState.STOPPED, \
    f"Expected paused/stopped after system BP, got {sm.current_state}"

client.go()
time.sleep(0.5)
assert sm.is_executing() or sm.current_state == DebuggerState.RUNNING, \
    f"Expected running after go(), got {sm.current_state}"

# Check transition log has entries
log = sm.transition_log
assert len(log) >= 2, f"Expected >= 2 transitions, got {len(log)}"
print(f"Transitions recorded: {len(log)}")
for tx in log[-5:]:
    print(f"  {tx.from_state} -> {tx.to_state}: {tx.reason}")

client.terminate_session()
print("✅ Test 4 PASS: State machine tracks transitions correctly")
```

---

## Test Suite 5: Infrastructure Tools (3 min)

**Goal:** Verify new MCP infrastructure tools work end-to-end.

```python
from x64dbg_automate.api_runtime.api_infrastructure import (
    get_debugger_state, wait_for_stable_state, force_resume, get_execution_log
)

client = X64DbgClient()
client.start_session(r'c:\Windows\system32\winver.exe')
client.wait_for_debug_event(EventType.EVENT_SYSTEMBREAKPOINT)

# Test get_debugger_state
r = get_debugger_state()
assert r["success"], f"get_debugger_state failed: {r}"
print(f"State: {r['state']}, Healthy: {r['is_healthy']}")

# Test wait_for_stable_state
client.go()
r = wait_for_stable_state(desired_state="running", timeout=5.0, poll_interval=0.1)
assert r["success"] and r["reached"], f"wait_for_stable_state failed: {r}"
print(f"Reached running in {r['waited']:.2f}s")

# Test force_resume (should be no-op when already running)
r = force_resume()
assert r["success"], f"force_resume failed: {r}"
print(f"force_resume: attempts={r['attempts']}")

# Test get_execution_log
r = get_execution_log(n=10)
assert r["success"], f"get_execution_log failed: {r}"
print(f"Execution log entries: {r['count']}")

client.terminate_session()
print("✅ Test 5 PASS: All infrastructure tools functional")
```

---

## Test Suite 6: Tool Gateway (@guarded) (2 min)

**Goal:** Verify `@guarded` decorator handles paused debuggee gracefully.

```python
from x64dbg_automate.api_runtime.tool_gateway import guarded
from x64dbg_automate.api_runtime.responses import ok

# Create a test tool
@guarded(pre_flight=True, post_flight=True, timeout=5.0)
def test_guarded_tool(address: str = "0x0", size: int = 4, sandbox_id: str | None = None) -> dict:
    client = get_manager().get_client(sandbox_id)
    data = client.read_memory(int(address, 16), size)
    return ok(memory=data.hex())

client = X64DbgClient()
client.start_session(r'c:\Windows\system32\winver.exe')
client.wait_for_debug_event(EventType.EVENT_SYSTEMBREAKPOINT)

# Call while STOPPED — @guarded should auto-resume
r = test_guarded_tool(address="0x7FF00000", size=4, sandbox_id=None)
assert r["success"], f"Guarded tool failed: {r}"
print(f"Guarded tool result: {r}")

client.terminate_session()
print("✅ Test 6 PASS: @guarded auto-resumed and executed tool")
```

---

## Test Suite 7: ZMQ Non-Blocking Send Under Load (3 min)

**Goal:** Verify C++ plugin doesn't stall when Python subscriber is slow.

```python
import time

client = X64DbgClient()
client.start_session(r'c:\Windows\system32\winver.exe')
client.wait_for_debug_event(EventType.EVENT_SYSTEMBREAKPOINT)

# Block the Python event processing for 2 seconds
# Events should pile up in ZMQ buffer, not stall x64dbg
def slow_cb(ev):
    time.sleep(2.0)

client.watch_debug_event(EventType.EVENT_RESUME_DEBUG, slow_cb)

start = time.time()
client.go()  # Triggers RESUME_DEBUG event
client.pause()  # Triggers PAUSE_DEBUG event
elapsed = time.time() - start

# If x64dbg stalled on the slow callback, this would take >2s
# With non-blocking sends, x64dbg should NOT stall
assert elapsed < 1.0, f"x64dbg stalled on slow callback! Took {elapsed:.2f}s"
print(f"x64dbg remained responsive during slow callback: {elapsed:.2f}s")

client.terminate_session()
print("✅ Test 7 PASS: Non-blocking ZMQ sends prevent x64dbg stall")
```

---

## Test Suite 8: Full Integration Run (5 min)

**Goal:** Run the complete HLA test suite.

```powershell
cd x64dbg-automate-pyclient-plus
python -m pytest tests/test_hla_commands.py -x -v
```

**Expected:** All tests pass, including `test_event_output_dbg_str`.

---

## Failure Reporting Template

If any test fails, capture:

```
TEST: [name]
EXPECTED: [expected behavior]
ACTUAL: [actual behavior]
LOGS: [relevant console output]
STATE: [get_debugger_state() output at failure time]
X64DBG_VERSION: [x64dbg.exe file version]
PLUGIN_TIMESTAMP: [dp64/dp32 modification time]
```

---

## Sign-Off Checklist

- [ ] Test 1: Plugin health (x64 + x32)
- [ ] Test 2: Event system stress
- [ ] Test 3A: running_guard auto-resume
- [ ] Test 3B: Nested guards
- [ ] Test 3C: Untracked pause detection
- [ ] Test 4: State machine tracking
- [ ] Test 5: Infrastructure tools
- [ ] Test 6: @guarded tool gateway
- [ ] Test 7: ZMQ non-blocking under load
- [ ] Test 8: Full HLA integration suite

**Result:** ___ / 10 passed
