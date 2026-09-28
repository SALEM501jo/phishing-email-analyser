"""
Stall watchdog for the long GPU jobs. If a laptop GPU drops off the bus ("GPU is lost" - power management or heat),
CUDA calls block forever and the job silently hangs all night. The watchdog ends the process with a clear message
when no progress has been reported for `limit_seconds`; the jobs are resumable, so a re-run continues where it stopped.
"""
import os
import sys
import threading
import time

_last_beat = time.monotonic()


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
