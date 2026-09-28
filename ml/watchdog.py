"""
Stall watchdog for the long GPU jobs. If a laptop GPU drops off the bus ("GPU is lost" - power management or heat),
CUDA calls block forever and the job silently hangs all night. The watchdog ends the process with a clear message
when no progress has been reported for `limit_seconds`; the jobs are resumable, so a re-run continues where it stopped.
"""
import os
import subprocess
import sys
import threading
import time

_last_beat = time.monotonic()


def gpu_temperature():
    """Current GPU temperature in °C from nvidia-smi, or None if it can't be read."""
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"],
                             capture_output=True, text=True, timeout=10)
        return int(out.stdout.strip().splitlines()[0])
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        return None


def cool_down(pause_at=75, resume_at=65, breather=1.0):
    """
    Thermal guard for laptops. Sustained full load made this laptop's GPU overheat and drop off the bus twice
    ("GPU is lost"); a job that pauses when hot finishes more slowly but finishes. Call between batches.
    A short breather after every batch also keeps the average load (and heat) down.
    """
    time.sleep(breather)
    temp = gpu_temperature()
    if temp is None or temp < pause_at:
        return
    print(f"  GPU at {temp} C - pausing until it cools to {resume_at} C ...", flush=True)
    while (temp := gpu_temperature()) is not None and temp > resume_at:
        beat()  # cooling is deliberate, not a stall
        time.sleep(15)
    print(f"  resumed at {temp} C", flush=True)


def beat():
    """Call whenever real progress has been made (e.g. after each written batch)."""
    global _last_beat
    _last_beat = time.monotonic()


def start(limit_seconds=600):
    def watch():
        while True:
            time.sleep(30)
            stalled = time.monotonic() - _last_beat
            if stalled > limit_seconds:
                print(f"\nWATCHDOG: no progress for {int(stalled // 60)} min - the GPU has probably stopped responding "
                      f"(check `nvidia-smi`; 'GPU is lost' needs a restart). Work so far is saved; re-run to resume.",
                      file=sys.stderr, flush=True)
                os._exit(3)
    threading.Thread(target=watch, daemon=True).start()
