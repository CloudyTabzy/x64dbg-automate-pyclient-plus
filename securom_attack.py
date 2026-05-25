"""SecuROM extraction via x32dbg — the proper way using our tools.

This launches x32dbg with SecuROM anti-debug countermeasures:
- ScyllaHide configured via our tools
- Memory write breakpoint on Stext (0xA7A000)
- Triggers when user navigates to activation/serial dialog
- Dumps Stext the moment it's decrypted
"""
import sys, os, time

sys.path.insert(0, r"C:\Dev\x64dbg_MCP_Automate_Plus\x64dbg-automate-pyclient-plus")

# ------------------------------------------------------------------
# Step 1: Launch x32dbg with BoneCrafterModKit.exe
# ------------------------------------------------------------------
X32DBG_PATH = r"C:\Dev\RE_Tools\snapshot_2025-08-19_19-40\release\x32\x32dbg.exe"
TARGET_EXE = r"C:\Dev\BoneCrafterModKit\BoneCraft\BoneCrafterModKit.exe"
STEXT_VA = 0x00A7A000       # 32-bit loaded address = 0x400000 + 0x67A000
STEXT_SIZE = 0x00A18DF0

print("=" * 60)
print("x32dbg SecuROM Bypass — Automated Cold Dump")
print("=" * 60)

# Start x32dbg with target loaded
print(f"\n[1/6] Starting x32dbg with {TARGET_EXE}...")
import subprocess
proc = subprocess.Popen([X32DBG_PATH, TARGET_EXE], cwd=os.path.dirname(X32DBG_PATH))
print(f"    x32dbg PID: {proc.pid}")
time.sleep(3)  # Give x32dbg time to initialize

# ------------------------------------------------------------------
# Step 2: Connect via Python client and configure
# ------------------------------------------------------------------
print("\n[2/6] Connecting via Python client...")
os.environ["X64DBG_PATH"] = X32DBG_PATH
from x64dbg_automate import X64DbgClient

client = X64DbgClient()
client.connect_to_session(proc.pid)
client.wait_until_debugging(timeout=30)
print(f"    Connected. PID={client.get_process_info().pid}")

# ------------------------------------------------------------------
# Step 3: Configure ScyllaHide
# ------------------------------------------------------------------
print("\n[3/6] Configuring ScyllaHide for SecuROM...")
# x64dbg SDK uses the cmd interface for settings
# These set ScyllaHide's anti-anti-debug options
client.set_setting("ScyllaHide", "PEBBeingDebugged", 0)
client.set_setting("ScyllaHide", "PEBHeapFlags", 0)
client.set_setting("ScyllaHide", "NtQueryInformationProcess", 1)
client.set_setting("ScyllaHide", "NtSetInformationThread", 1)
client.set_setting("ScyllaHide", "NtQuerySystemInformation", 1)
client.set_setting("ScyllaHide", "GetTickCount", 1)
client.set_setting("ScyllaHide", "NtClose", 1)
print("    ScyllaHide configured")

# ------------------------------------------------------------------
# Step 4: Verify the PEB looks clean
# ------------------------------------------------------------------
print("\n[4/6] Verifying PEB state...")
peb = client.get_peb()
print(f"    BeingDebugged: {peb.being_debugged}")
print(f"    NtGlobalFlag:  0x{peb.nt_global_flag:08X}")
print(f"    HeapFlags:     0x{peb.heap_flags:08X}")
print(f"    HeapForceFlags: 0x{peb.heap_force_flags:08X}")

# ------------------------------------------------------------------
# Step 5: Set memory write breakpoint on Stext
# ------------------------------------------------------------------
print(f"\n[5/6] Setting memory write breakpoint on Stext ({hex(STEXT_VA)})...")
client.set_breakpoint(hex(STEXT_VA), "memory", mode="w")
print("    Memory breakpoint set (write). Waiting for SecuROM decryption...")

# ------------------------------------------------------------------
# Step 6: Run the debuggee
# ------------------------------------------------------------------
print("\n[6/6] Resuming execution...")
print()
print("=" * 60)
print("ACTION REQUIRED: In the BoneCrafterModKit window,")
print("navigate to the Activation / Serial / Registration dialog.")
print("The breakpoint will fire when Stext is decrypted.")
print("=" * 60)
client.go(pass_exceptions=True)

# Wait for breakpoint
from x64dbg_automate.events import EventType
event = client.wait_for_event("EVENT_BREAKPOINT", timeout=300)
if event:
    print(f"\n    Breakpoint hit! Dumping Stext...")
    # Now read Stext from process memory
    stext_data = client.read_memory(STEXT_VA, min(STEXT_SIZE, 4096))
    print(f"    First 4KB of Stext: entropy={__import__('x64dbg_automate').external.entropy.shannon_entropy(stext_data):.2f}")
    
    # Dump via standalone tool
    dump_path = os.path.join(r"C:\Dev\BoneCrafterModKit\extracted", "stext_decrypted.bin")
    os.makedirs(os.path.dirname(dump_path), exist_ok=True)
    data = client.read_memory(STEXT_VA, STEXT_SIZE)
    with open(dump_path, "wb") as f:
        f.write(data)
    print(f"    Stext dumped: {dump_path} ({len(data):,} bytes)")
else:
    print("\n    Breakpoint timeout. Trying alternate approach...")
    # Try reading it anyway
    print(f"    Reading Stext from running process...")
    stext_data = client.read_memory(STEXT_VA, min(STEXT_SIZE, 4096))
    ent = __import__('x64dbg_automate').external.entropy.shannon_entropy(stext_data)
    print(f"    Entropy: {ent:.2f} {'(DECRYPTED)' if 4.5 < ent < 6.5 else '(still encrypted)'}")
