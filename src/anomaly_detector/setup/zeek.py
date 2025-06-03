import os
import sys
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from config import Config


def get_path(process_name = "zeek"):
    if sys.platform.startswith("win"):
        raise RuntimeError("This resolver is for Linux/macOS only. Use WSL for Zeek on Windows.")

    # PATH lookup
    found = shutil.which(process_name)
    if found:
        return Path(found).resolve()

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
            return p.resolve()

    raise FileNotFoundError(
        "Could not find Zeek executable. Install Zeek and ensure `zeek` is on PATH"
    )

def run(arg, out_dir):
    parameters = [str(get_path()), arg.split()]
    try:
        output = subprocess.run(parameters,
                                cwd=out_dir,
                                capture_output=True,
                                text=True,
                                check=True)
        return output
    except subprocess.CalledProcessError as e:
        print("Zeek command could not be ran.")
        print(e.output)

def generate_logs(pcap_path):
    now = datetime.now().strftime("%d%m%y_%H%M%S")
    out = Config.RUN_DIR / now
    out.mkdir(parents=True, exist_ok=True)
    out = out.resolve()

    cmd = f"-r {str(pcap_path)} LogAscii::use_json=T"
    run(cmd, out)


def process_pcap(pcap_path):
    generate_logs(pcap_path)
