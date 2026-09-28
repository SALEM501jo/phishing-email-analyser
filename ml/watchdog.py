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


LHM_URL = os.environ.get("ML_LHM_URL", "http://localhost:8085/data.json")
# The ACPI thermal zone read 92 C while MSI Center (real CPU package sensor) read 81 C at the same moment.
ACPI_OFFSET = int(os.environ.get("ML_ACPI_OFFSET", 11))


def _lhm_cpu_temperature():
    """CPU Package temperature from LibreHardwareMonitor's local web server (the same sensor MSI Center shows)."""
    import json
    import urllib.request
    try:
        with urllib.request.urlopen(LHM_URL, timeout=3) as response:
            tree = json.load(response)
    except (OSError, ValueError):
        return None

    readings = {}
    def walk(node):
        sensor = node.get("SensorId", "")
        if ("/intelcpu/" in sensor or "/amdcpu/" in sensor) and "/temperature/" in sensor:
            try:
                readings[node.get("Text", "")] = float(str(node.get("Value", "")).split()[0].replace(",", "."))
            except (ValueError, IndexError):
                pass
        for child in node.get("Children", []):
            walk(child)
    walk(tree)
    for preferred in ("CPU Package", "Core Max", "Core Average"):
        if preferred in readings:
            return round(readings[preferred])
    return round(max(readings.values())) if readings else None


def _acpi_cpu_temperature():
    """Hottest ACPI thermal zone (no admin rights needed), corrected by the offset measured against MSI Center."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation | Measure-Object Temperature -Maximum).Maximum"],
            capture_output=True, text=True, timeout=15)
        return round(int(out.stdout.strip()) - 273.15) - ACPI_OFFSET
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def cpu_temperature():
    """
    Real CPU temperature in °C. Preferred source: LibreHardwareMonitor (reads the CPU package sensor; run it as
    administrator with Options > Remote Web Server enabled). Fallback: the ACPI thermal zone, which reads ~11 C
    high on this laptop and is corrected for that. None if neither is available.
    """
    return _lhm_cpu_temperature() or _acpi_cpu_temperature()


def cpu_temperature_source():
    return "LibreHardwareMonitor (CPU Package)" if _lhm_cpu_temperature() is not None else f"ACPI thermal zone - {ACPI_OFFSET} C"


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
    print(f"thermal guard: GPU pause {GPU_PAUSE}/resume {GPU_RESUME} C, CPU pause {CPU_PAUSE}/resume {CPU_RESUME} C "
          f"(CPU source: {cpu_temperature_source()})", flush=True)
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
