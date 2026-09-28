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


def cpu_temperature():
    """
    Hottest ACPI thermal zone in °C (Windows performance counter - readable without admin rights, unlike the
    per-core sensors). It measures around the processor, so it usually reads a few degrees below the core
    temperature monitoring apps show. None if unavailable.
    """
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation | Measure-Object Temperature -Maximum).Maximum"],
            capture_output=True, text=True, timeout=15)
        return round(int(out.stdout.strip()) - 273.15)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


# Limits (°C). CPU limit chosen by the owner of this laptop; overridable without code changes.
GPU_PAUSE, GPU_RESUME = int(os.environ.get("ML_GPU_MAX", 75)), int(os.environ.get("ML_GPU_RESUME", 65))
CPU_PAUSE, CPU_RESUME = int(os.environ.get("ML_CPU_MAX", 82)), int(os.environ.get("ML_CPU_RESUME", 72))


def _too_hot(gpu, cpu, gpu_limit, cpu_limit):
    return (gpu is not None and gpu >= gpu_limit) or (cpu is not None and cpu >= cpu_limit)


def cool_down(breather=1.0):
    """
    Thermal guard for laptops. Sustained full load made this laptop's GPU overheat and drop off the bus twice
    ("GPU is lost"); a job that pauses when hot finishes more slowly but finishes. Call between batches.
    Pauses when the GPU or CPU passes its limit and resumes only when BOTH are back under their resume points
    (the CPU and GPU share one cooler in a laptop). A short breather after every batch lowers the average heat.
    """
    time.sleep(breather)
    gpu, cpu = gpu_temperature(), cpu_temperature()
    if not _too_hot(gpu, cpu, GPU_PAUSE, CPU_PAUSE):
        return
    print(f"  hot (GPU {gpu} C, CPU {cpu} C) - pausing until GPU <= {GPU_RESUME} C and CPU <= {CPU_RESUME} C ...", flush=True)
    while True:
        beat()  # cooling is deliberate, not a stall
        time.sleep(15)
        gpu, cpu = gpu_temperature(), cpu_temperature()
        if not _too_hot(gpu, cpu, GPU_RESUME + 1, CPU_RESUME + 1):
            break
    print(f"  resumed (GPU {gpu} C, CPU {cpu} C)", flush=True)


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
