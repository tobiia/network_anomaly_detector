import os
import sys
import shutil
import subprocess
from pathlib import Path


def get_path(process_name = "zeek"):
    if sys.platform.startswith("win"):
        raise RuntimeError("This resolver is for Linux/macOS only. Use WSL for Zeek on Windows.")

    # PATH lookup
    found = shutil.which(process_name)
    if found:
        return str(Path(found).resolve())

    # fallbacks
    candidates = [
        Path("/opt/zeek/bin") / process_name,       # linux
        Path("/usr/local/bin") / process_name,      # homebrew/manual installs
        Path("/usr/bin") / process_name,
        Path("/usr/sbin") / process_name,
        Path("/opt/homebrew/bin") / process_name,   # Apple Silicon Homebrew
        Path("/usr/local/sbin") / process_name,
    ]

    for p in candidates:
        if p.is_file() and os.access(p, os.X_OK): # access = executable
            return str(p.resolve())

    raise FileNotFoundError(
        "Could not find Zeek executable. Install Zeek and ensure `zeek` is on PATH"
    )

def run(arg, out_dir):
    parameters = [get_path(), arg.split()]
    try:
        output = subprocess.run(parameters,
                                cwd=out_dir.resolve(),
                                capture_output=True,
                                text=True,
                                check=True)
        return output
    except subprocess.CalledProcessError as e:
        print("Zeek command could not be ran.")
        print(e.output)

def generate_logs(pcap_path, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    cmd = f"-r {str(Path(pcap_path).resolve())} LogAscii::use_json=T"
    run(cmd, out)